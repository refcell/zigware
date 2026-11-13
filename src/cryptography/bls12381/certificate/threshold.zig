//! The BLS12-381 threshold certificate scheme (commonware
//! `bls12381::certificate::threshold`): participants sign with key shares, and a quorum of
//! partial signatures recovers one group signature, verified against the group public key.
//! Certificates are a single signature, so they are not attributable.
//!
//! commonware's `impl_certificate_bls12381_threshold!(Subject, Namespace, Faults)` and its
//! `Generic` are one type here: `Scheme(Subject, Faults, P, V)`. Its three roles are a
//! signer (participants, sharing, and share), a verifier (participants and sharing), and a
//! certificate verifier (only the group public key, which can verify certificates but not
//! attestations).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const base = @import("../../certificate.zig");
const ed25519_mocks = @import("../../ed25519/certificate/mocks.zig");
const primitives = @import("../primitives/root.zig");
const dkg = @import("../dkg/root.zig").feldman_desmedt;

const Participant = utils.Participant;
const Set = utils.ordered.Set;
const ops = primitives.ops;
const batch = ops.batch;
const threshold = ops.threshold;
const Share = primitives.group.Share;
const Sharing = primitives.sharing.Sharing;
const PartialSignature = primitives.variant.PartialSignature;

/// A threshold certificate: the recovered group signature.
pub fn Certificate(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const fixed_size: usize = V.Signature.fixed_size;

        signature: base.Deferred(V.Signature),

        pub fn init(signature: V.Signature) Self {
            return .{ .signature = .init(signature) };
        }

        /// The signature, or null when its encoding is not a valid point.
        pub fn get(self: *const Self) ?V.Signature {
            return self.signature.get();
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            _ = gpa;
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            _ = gpa;
            return self.*;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.signature.eql(b.signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.signature.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{ .signature = try .read(gpa, reader, {}) };
        }
    };
}

/// A threshold certificate scheme over subjects `Sub`, with quorums from the fault model
/// `F`, identity keys `P`, and BLS variant `V`.
pub fn Scheme(comptime Sub: type, comptime F: type, comptime P: type, comptime V: type) type {
    base.assert_subject(Sub);
    return struct {
        const Self = @This();
        pub const Subject = Sub;
        pub const Faults = F;
        pub const Namespace = Subject.Namespace;
        pub const PublicKey = P;
        pub const Signature = V.Signature;
        pub const Variant = V;
        pub const Certificate = certificate_of(V);
        pub const Attestation = base.Attestation(Self);
        pub const Verification = base.Verification(Self);
        pub const Assembled = base.Assembled(Self);
        pub const Item = base.CertificateItem(Self);
        pub const Participants = Set(P);

        /// Present for signers and verifiers.
        committee: ?Committee,
        /// Present for signers.
        signing_share: ?Share,
        /// The group public key.
        group_public: V.Public,
        member_index: ?Participant,
        namespace: Namespace,

        const Committee = struct { participants: Participants, polynomial: Sharing(V) };

        /// Checks commonware's constructor preconditions and precomputes partial keys.
        fn committee_of(set: Participants, polynomial: Sharing(V)) Committee {
            if (polynomial.total != set.len()) {
                @panic("polynomial total must equal participant len");
            }
            if (polynomial.required() != set.quorum(Faults)) {
                @panic("polynomial threshold must equal quorum");
            }
            polynomial.precompute_partial_publics();
            return .{ .participants = set, .polynomial = polynomial };
        }

        /// A signing scheme, or null when `share` does not match `polynomial`. Takes
        /// ownership of `participants` and `polynomial` (released when the result is null).
        /// Panics when the polynomial does not fit the participant set.
        pub fn signer(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            polynomial: Sharing(V),
            key_share: Share,
        ) Allocator.Error!?Self {
            var committee = committee_of(set, polynomial);
            const expected = committee.polynomial.partial_public(key_share.index) catch
                @panic("share index must match participant indices");
            if (!expected.eql(key_share.public(V))) {
                committee.participants.deinit(gpa);
                committee.polynomial.deinit(gpa);
                return null;
            }
            errdefer committee.participants.deinit(gpa);
            errdefer committee.polynomial.deinit(gpa);
            return .{
                .committee = committee,
                .signing_share = key_share,
                .group_public = committee.polynomial.public(),
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        /// A scheme that verifies attestations and certificates but cannot sign. Takes
        /// ownership of `participants` and `polynomial`.
        pub fn verifier(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            polynomial: Sharing(V),
        ) Allocator.Error!Self {
            var committee = committee_of(set, polynomial);
            errdefer committee.participants.deinit(gpa);
            errdefer committee.polynomial.deinit(gpa);
            return .{
                .committee = committee,
                .signing_share = null,
                .group_public = committee.polynomial.public(),
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        /// A verifier that knows its index, or null when `public_key` is not a participant.
        /// Takes ownership of `participants` and `polynomial`.
        pub fn member(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            polynomial: Sharing(V),
            public_key: P,
        ) Allocator.Error!?Self {
            const index = set.index(public_key) orelse {
                var owned = set;
                owned.deinit(gpa);
                var sharing = polynomial;
                sharing.deinit(gpa);
                return null;
            };
            var result = try verifier(gpa, namespace, set, polynomial);
            result.member_index = index;
            return result;
        }

        /// A scheme that verifies certificates against the group public key `identity`.
        pub fn certificate_verifier(
            gpa: Allocator,
            namespace: []const u8,
            group_public: V.Public,
        ) Allocator.Error!Self {
            return .{
                .committee = null,
                .signing_share = null,
                .group_public = group_public,
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var committee: ?Committee = null;
            if (self.committee) |c| {
                var set = try c.participants.clone(gpa);
                errdefer set.deinit(gpa);
                committee = .{
                    .participants = set,
                    .polynomial = try c.polynomial.clone(gpa),
                };
            }
            errdefer if (committee) |*c| {
                c.participants.deinit(gpa);
                c.polynomial.deinit(gpa);
            };
            return .{
                .committee = committee,
                .signing_share = self.signing_share,
                .group_public = self.group_public,
                .member_index = self.member_index,
                .namespace = try self.namespace.clone(gpa),
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.committee) |*c| {
                c.participants.deinit(gpa);
                c.polynomial.deinit(gpa);
            }
            if (self.signing_share) |*key_share| key_share.private.zeroize();
            self.namespace.deinit(gpa);
            self.* = undefined;
        }

        fn committee_or_panic(self: *const Self) *const Committee {
            if (self.committee) |*c| return c;
            @panic("can only be called for signer and verifier");
        }

        pub fn me(self: *const Self) ?base.Membership {
            if (self.signing_share) |key_share| return .{ .signer = key_share.index };
            if (self.member_index) |index| return .{ .member = index };
            return null;
        }

        /// The participants; panics for a certificate verifier.
        pub fn participants(self: *const Self) *const Participants {
            return &self.committee_or_panic().participants;
        }

        /// The group public key.
        pub fn identity(self: *const Self) V.Public {
            return self.group_public;
        }

        /// The key share, for signers.
        pub fn share(self: *const Self) ?Share {
            return self.signing_share;
        }

        /// Signs `subject` with the key share, or returns null when this instance cannot
        /// sign.
        pub fn sign(
            self: *const Self,
            gpa: Allocator,
            subject: Subject,
        ) Allocator.Error!?Attestation {
            const key_share = self.signing_share orelse return null;
            const message = try subject.message(gpa);
            defer gpa.free(message);
            const namespace = subject.namespace(&self.namespace);
            const partial = threshold.sign_message(V, key_share, namespace, message);
            return Attestation.init(key_share.index, partial.value);
        }

        /// Verifies one partial signature; panics for a certificate verifier.
        pub fn verify_attestation(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestation: *const Attestation,
            strategy: anytype,
        ) Allocator.Error!bool {
            _ = rng;
            _ = strategy;
            const polynomial = self.committee_or_panic().polynomial;
            const public_key = polynomial.partial_public(attestation.signer) catch return false;
            const signature = attestation.signature.get() orelse return false;
            const message = try subject.message(gpa);
            defer gpa.free(message);
            const namespace = subject.namespace(&self.namespace);
            ops.verify_message(V, public_key, namespace, message, signature) catch return false;
            return true;
        }

        /// Batch-verifies partial signatures and returns the verified ones and the sorted
        /// invalid signers. Every attestation of a signer with an invalid one is rejected.
        pub fn verify_attestations(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestations: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Verification {
            _ = strategy;
            const polynomial = self.committee_or_panic().polynomial;
            var invalid: std.ArrayList(Participant) = .empty;
            defer invalid.deinit(gpa);
            var partials: std.ArrayList(PartialSignature(V)) =
                try .initCapacity(gpa, attestations.len);
            defer partials.deinit(gpa);
            for (attestations) |attestation| {
                if (attestation.signature.get()) |value| {
                    partials.appendAssumeCapacity(.{ .index = attestation.signer, .value = value });
                } else try invalid.append(gpa, attestation.signer);
            }
            if (partials.items.len > 0) {
                const message = try subject.message(gpa);
                defer gpa.free(message);
                const bad = try threshold.batch_verify_same_message(
                    V,
                    gpa,
                    rng,
                    polynomial,
                    subject.namespace(&self.namespace),
                    message,
                    partials.items,
                );
                defer gpa.free(bad);
                for (bad) |position| try invalid.append(gpa, partials.items[position].index);
            }
            return collect(gpa, partials.items, invalid.items);
        }

        fn collect(
            gpa: Allocator,
            partials: []const PartialSignature(V),
            invalid_unsorted: []Participant,
        ) Allocator.Error!Verification {
            const invalid_sorted = base.sort_unique(invalid_unsorted);
            var verified: std.ArrayList(Attestation) = try .initCapacity(gpa, partials.len);
            errdefer verified.deinit(gpa);
            for (partials) |partial| {
                if (contains(invalid_sorted, partial.index)) continue;
                verified.appendAssumeCapacity(.init(partial.index, partial.value));
            }
            const invalid = try gpa.dupe(Participant, invalid_sorted);
            errdefer gpa.free(invalid);
            return .{ .verified = try verified.toOwnedSlice(gpa), .invalid = invalid };
        }

        fn contains(sorted: []const Participant, participant: Participant) bool {
            for (sorted) |item| {
                if (item.get() == participant.get()) return true;
            }
            return false;
        }

        pub fn optimistic_assemble(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            pending: []const Attestation,
            verified: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Assembled {
            return base.optimistic_assemble(self, gpa, rng, subject, pending, verified, strategy);
        }

        /// Recovers a certificate from a non-empty list of partial signatures, which need
        /// not be verified. Signers must be in range, unique, and reach the threshold.
        pub fn assemble(
            self: *const Self,
            gpa: Allocator,
            attestations: []const Attestation,
            strategy: anytype,
        ) (base.AssemblyError || Allocator.Error)!Self.Certificate {
            _ = strategy;
            assert(attestations.len > 0);
            const polynomial = self.committee_or_panic().polynomial;
            const partials = try gpa.alloc(PartialSignature(V), attestations.len);
            defer gpa.free(partials);
            const indices = try gpa.alloc(Participant, attestations.len);
            defer gpa.free(indices);
            for (attestations, partials, indices) |attestation, *partial, *index| {
                const value = attestation.signature.get() orelse return error.MalformedSignature;
                partial.* = .{ .index = attestation.signer, .value = value };
                index.* = attestation.signer;
            }
            var signers = try base.Signers.init(gpa, polynomial.total, indices);
            defer signers.deinit(gpa);
            try signers.require(polynomial.required());
            const signature = threshold.recover(V, gpa, polynomial, partials) catch |err|
                switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.RecoveryFailed,
                };
            return .init(signature);
        }

        /// Verifies a certificate against the group public key.
        pub fn verify_certificate(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            cert: *const Self.Certificate,
            strategy: anytype,
        ) Allocator.Error!bool {
            _ = rng;
            _ = strategy;
            const signature = cert.get() orelse return false;
            const message = try subject.message(gpa);
            defer gpa.free(message);
            const namespace = subject.namespace(&self.namespace);
            ops.verify_message(V, self.group_public, namespace, message, signature) catch
                return false;
            return true;
        }

        /// Verifies certificates (all signed by the group key) with one batch verification.
        pub fn verify_certificates(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            items: []const Item,
            strategy: anytype,
        ) Allocator.Error!bool {
            _ = strategy;
            assert(items.len > 0);
            const entries = try gpa.alloc(batch.SignerEntry(V), items.len);
            defer gpa.free(entries);
            var built: usize = 0;
            defer for (entries[0..built]) |entry| gpa.free(entry.message);
            for (items, entries) |item, *entry| {
                const signature = item.certificate.get() orelse return false;
                entry.* = .{
                    .namespace = item.subject.namespace(&self.namespace),
                    .message = try item.subject.message(gpa),
                    .signature = signature,
                };
                built += 1;
            }
            batch.verify_same_signer(V, rng, self.group_public, entries) catch return false;
            return true;
        }

        pub fn is_attributable() bool {
            return false;
        }

        pub fn is_batchable() bool {
            return true;
        }

        pub fn max_certificate_size(count: u32) usize {
            _ = count;
            return Self.Certificate.fixed_size;
        }

        pub fn certificate_codec_config(self: *const Self) void {
            _ = self;
        }

        pub fn certificate_codec_config_unbounded() void {}

        comptime {
            base.assert_scheme(Self);
        }
    };
}

const certificate_of = Certificate;

/// Builds `n` ed25519 identities, deals them threshold shares with a trusted dealer, and
/// returns one signing scheme `S` per identity and a verifier (commonware
/// `threshold::mocks::fixture`). `S` is a `Scheme(Subject, Faults, ed25519.PublicKey, V)`.
pub fn fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!base.mocks.Fixture(S) {
    assert(n > 0);
    const public_keys, const private_keys = try ed25519_mocks.participants(gpa, rng, n);
    errdefer gpa.free(public_keys);
    errdefer gpa.free(private_keys);
    var set = S.Participants.init(gpa, public_keys) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Proof: `participants` returns strictly increasing keys.
        else => unreachable,
    };
    defer set.deinit(gpa);
    // The trusted dealer draws as commonware's `deal` does; shares follow the key order.
    var dealing = try dkg.deal_anonymous(S.Variant, S.Faults, gpa, rng, .non_zero_counter, n);
    defer dealing.deinit(gpa);
    const schemes = try gpa.alloc(S, n);
    errdefer gpa.free(schemes);
    var built: usize = 0;
    errdefer for (schemes[0..built]) |*scheme| scheme.deinit(gpa);
    for (dealing.shares, schemes) |share, *scheme| {
        const copy = try set.clone(gpa);
        const polynomial = try dealing.sharing.clone(gpa);
        scheme.* = (try S.signer(gpa, namespace, copy, polynomial, share)).?;
        built += 1;
    }
    const polynomial = try dealing.sharing.clone(gpa);
    return .{
        .participants = public_keys,
        .private_keys = private_keys,
        .schemes = schemes,
        .verifier = try S.verifier(gpa, namespace, try set.clone(gpa), polynomial),
    };
}

test {
    _ = @import("threshold_tests.zig");
}
