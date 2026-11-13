//! The BLS12-381 multi-signature certificate scheme (commonware
//! `bls12381::certificate::multisig`): attributable individual BLS signatures that a quorum
//! aggregates into one signature plus the signer bitmap.
//!
//! Every BLS public key in the participant map must have a verified proof of possession
//! (`ops.verify_proof_of_possession`) before a scheme is built from it; otherwise aggregate
//! verification is open to rogue-key attacks. The constructors do not check this.
//!
//! commonware's `impl_certificate_bls12381_multisig!(Subject, Namespace, Faults)` and its
//! `Generic` are one type here: `Scheme(Subject, Faults, P, V)`, with the namespace type
//! taken from `Subject.Namespace`, identity keys `P`, and BLS variant `V`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const base = @import("../../certificate.zig");
const ed25519_mocks = @import("../../ed25519/certificate/mocks.zig");
const primitives = @import("../primitives/root.zig");

const Participant = utils.Participant;
const ops = primitives.ops;
const aggregate = ops.aggregate;
const batch = ops.batch;
const Private = primitives.group.Private;

/// A multisig certificate: the signer bitmap and the aggregate of their signatures.
pub fn Certificate(comptime V: type) type {
    return struct {
        const Self = @This();
        const context = "cryptography::bls12381::certificate::multisig::Certificate";
        pub const Signature = base.Deferred(aggregate.Signature(V));
        /// The participant count bounding the bitmap.
        pub const Cfg = usize;

        signers: base.Signers,
        signature: Signature,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.signers.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return .{ .signers = try self.signers.clone(gpa), .signature = self.signature };
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.signers.eql(&b.signers) and a.signature.eql(b.signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.signers.write(writer);
            self.signature.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.signers.encode_size() + Signature.fixed_size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, participants: usize) codec.Error!Self {
            var signers = try base.Signers.read(gpa, reader, participants);
            errdefer signers.deinit(gpa);
            if (signers.count() == 0) {
                return reader.invalid(context, "Certificate contains no signers");
            }
            return .{ .signers = signers, .signature = try Signature.read(gpa, reader, {}) };
        }
    };
}

/// A multisig certificate scheme over subjects `Sub`, with quorums from the fault model
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
        pub const Certificate = certificate_of(V);
        pub const Variant = V;
        pub const Attestation = base.Attestation(Self);
        pub const Verification = base.Verification(Self);
        pub const Assembled = base.Assembled(Self);
        pub const Item = base.CertificateItem(Self);
        /// Identity keys, ordered, each mapped to its BLS signing key.
        pub const Participants = utils.ordered.BiMap(P, V.Public);

        participants_map: Participants,
        signing: ?Signing,
        member_index: ?Participant,
        namespace: Namespace,

        const Signing = struct { index: Participant, key: Private };

        /// A signing scheme, or null when `private_key`'s public key is not in `map`.
        /// Takes ownership of `map` (released when the result is null).
        pub fn signer(
            gpa: Allocator,
            namespace: []const u8,
            map: Participants,
            private_key: Private,
        ) Allocator.Error!?Self {
            var owned = map;
            const public_key = ops.compute_public(V, private_key);
            const position = for (owned.values(), 0..) |value, i| {
                if (value.eql(public_key)) break i;
            } else {
                owned.deinit(gpa);
                return null;
            };
            errdefer owned.deinit(gpa);
            return .{
                .participants_map = owned,
                .signing = .{ .index = .from_usize(position), .key = private_key },
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        /// A scheme that verifies but cannot sign. Takes ownership of `map`.
        pub fn verifier(
            gpa: Allocator,
            namespace: []const u8,
            map: Participants,
        ) Allocator.Error!Self {
            var owned = map;
            errdefer owned.deinit(gpa);
            return .{
                .participants_map = owned,
                .signing = null,
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        /// A verifier that knows its index, or null when `public_key` is not a participant.
        /// Takes ownership of `map`.
        pub fn member(
            gpa: Allocator,
            namespace: []const u8,
            map: Participants,
            public_key: P,
        ) Allocator.Error!?Self {
            var owned = map;
            const index = owned.keys().index(public_key) orelse {
                owned.deinit(gpa);
                return null;
            };
            var result = try verifier(gpa, namespace, owned);
            result.member_index = index;
            return result;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var map = try clone_participants(gpa, &self.participants_map);
            errdefer map.deinit(gpa);
            return .{
                .participants_map = map,
                .signing = self.signing,
                .member_index = self.member_index,
                .namespace = try self.namespace.clone(gpa),
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.participants_map.deinit(gpa);
            self.namespace.deinit(gpa);
            if (self.signing) |*signing| signing.key.zeroize();
            self.* = undefined;
        }

        pub fn me(self: *const Self) ?base.Membership {
            if (self.signing) |signing| return .{ .signer = signing.index };
            if (self.member_index) |index| return .{ .member = index };
            return null;
        }

        pub fn participants(self: *const Self) *const utils.ordered.Set(P) {
            return self.participants_map.keys();
        }

        fn signing_key(self: *const Self, index: Participant) ?V.Public {
            const value = self.participants_map.value(index.get()) orelse return null;
            return value.*;
        }

        /// Signs `subject`, or returns null when this instance cannot sign.
        pub fn sign(
            self: *const Self,
            gpa: Allocator,
            subject: Subject,
        ) Allocator.Error!?Attestation {
            const signing = self.signing orelse return null;
            const message = try subject.message(gpa);
            defer gpa.free(message);
            const namespace = subject.namespace(&self.namespace);
            const signature = ops.sign_message(V, signing.key, namespace, message);
            return Attestation.init(signing.index, signature);
        }

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
            const public_key = self.signing_key(attestation.signer) orelse return false;
            const signature = attestation.signature.get() orelse return false;
            const message = try subject.message(gpa);
            defer gpa.free(message);
            const namespace = subject.namespace(&self.namespace);
            ops.verify_message(V, public_key, namespace, message, signature) catch return false;
            return true;
        }

        /// Batch-verifies `attestations` (bisecting to find invalid signatures) and returns
        /// the verified ones and the sorted invalid signers. Every attestation of a signer
        /// with an invalid one is rejected.
        pub fn verify_attestations(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestations: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Verification {
            _ = strategy;
            var invalid: std.ArrayList(Participant) = .empty;
            defer invalid.deinit(gpa);
            var candidates: std.ArrayList(Attestation) = try .initCapacity(gpa, attestations.len);
            defer candidates.deinit(gpa);
            var entries: std.ArrayList(batch.Entry(V)) = try .initCapacity(gpa, attestations.len);
            defer entries.deinit(gpa);
            for (attestations) |attestation| {
                const public_key = self.signing_key(attestation.signer);
                const signature = attestation.signature.get();
                if (public_key == null or signature == null) {
                    try invalid.append(gpa, attestation.signer);
                    continue;
                }
                candidates.appendAssumeCapacity(attestation);
                entries.appendAssumeCapacity(.{
                    .public = public_key.?,
                    .signature = signature.?,
                });
            }
            if (candidates.items.len > 0) {
                const message = try subject.message(gpa);
                defer gpa.free(message);
                const namespace = subject.namespace(&self.namespace);
                const bad = try batch.verify_same_message(
                    V,
                    gpa,
                    rng,
                    namespace,
                    message,
                    entries.items,
                );
                defer gpa.free(bad);
                for (bad) |index| try invalid.append(gpa, candidates.items[index].signer);
            }
            return collect(gpa, candidates.items, invalid.items);
        }

        fn collect(
            gpa: Allocator,
            candidates: []const Attestation,
            invalid_unsorted: []Participant,
        ) Allocator.Error!Verification {
            const invalid_sorted = base.sort_unique(invalid_unsorted);
            var verified: std.ArrayList(Attestation) = try .initCapacity(gpa, candidates.len);
            errdefer verified.deinit(gpa);
            for (candidates) |candidate| {
                if (contains(invalid_sorted, candidate.signer)) continue;
                verified.appendAssumeCapacity(candidate);
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

        /// Aggregates a non-empty list of attestations, which need not be verified, into
        /// a certificate.
        pub fn assemble(
            self: *const Self,
            gpa: Allocator,
            attestations: []const Attestation,
            strategy: anytype,
        ) (base.AssemblyError || Allocator.Error)!Self.Certificate {
            _ = strategy;
            assert(attestations.len > 0);
            const signer_indices = try gpa.alloc(Participant, attestations.len);
            defer gpa.free(signer_indices);
            const signatures = try gpa.alloc(V.Signature, attestations.len);
            defer gpa.free(signatures);
            for (attestations, signer_indices, signatures) |attestation, *index, *signature| {
                if (self.signing_key(attestation.signer) == null) return error.UnknownSigner;
                signature.* = attestation.signature.get() orelse return error.MalformedSignature;
                index.* = attestation.signer;
            }
            const keys = self.participants_map.keys();
            var signers = try base.Signers.from_set(gpa, keys, signer_indices);
            errdefer signers.deinit(gpa);
            try signers.require(keys.quorum(Faults));
            const signature = aggregate.combine_signatures(V, signatures);
            return .{ .signers = signers, .signature = .init(signature) };
        }

        /// Verifies a certificate against the aggregate of its signers' keys.
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
            const keys = self.participants_map.keys();
            if (cert.signers.len() != keys.len()) return false;
            if (cert.signers.count() < keys.quorum(Faults)) return false;
            // Malformed signatures skip the per-signer group operations.
            const signature = cert.signature.get() orelse return false;
            var public: aggregate.PublicKey(V) = .zero;
            var signers = cert.signers.iter();
            while (signers.next()) |index| {
                public.add(self.signing_key(index) orelse return false);
            }
            const message = try subject.message(gpa);
            defer gpa.free(message);
            const namespace = subject.namespace(&self.namespace);
            aggregate.verify_same_message(V, public, namespace, message, signature) catch
                return false;
            return true;
        }

        /// Verifies certificates one at a time (multisig has no cross-certificate batching).
        pub fn verify_certificates(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            items: []const Item,
            strategy: anytype,
        ) Allocator.Error!bool {
            assert(items.len > 0);
            for (items) |item| {
                const valid = try self.verify_certificate(
                    gpa,
                    rng,
                    item.subject,
                    item.certificate,
                    strategy,
                );
                if (!valid) return false;
            }
            return true;
        }

        pub fn is_attributable() bool {
            return true;
        }

        pub fn is_batchable() bool {
            return true;
        }

        /// The encoded size of a certificate over at most `count` participants.
        pub fn max_certificate_size(count: u32) usize {
            return base.Signers.max_encode_size(count) + V.Signature.fixed_size;
        }

        pub fn certificate_codec_config(self: *const Self) usize {
            return self.participants_map.len();
        }

        /// For trusted local storage only: never decode network input with it.
        pub fn certificate_codec_config_unbounded() usize {
            return std.math.maxInt(u32);
        }

        comptime {
            base.assert_scheme(Self);
        }
    };
}

/// A copy of `map` (its keys and values own no memory).
pub fn clone_participants(gpa: Allocator, map: anytype) Allocator.Error!@TypeOf(map.*) {
    const Map = @TypeOf(map.*);
    const pairs = try gpa.alloc(Map.Pair, map.len());
    defer gpa.free(pairs);
    for (pairs, map.keys().items, map.values()) |*pair, key, value| pair.* = .{ key, value };
    return Map.init(gpa, pairs) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Proof: `map` already has unique keys and values.
        else => unreachable,
    };
}

/// Builds `n` ed25519 identities with fresh BLS keys, one signing scheme `S` per identity,
/// and a verifier (commonware `multisig::mocks::fixture`). `S` is a
/// `Scheme(Subject, Faults, ed25519.PublicKey, V)`.
pub fn fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!base.mocks.Fixture(S) {
    assert(n > 0);
    const V = S.Variant;
    const public_keys, const private_keys = try ed25519_mocks.participants(gpa, rng, n);
    errdefer gpa.free(public_keys);
    errdefer gpa.free(private_keys);
    const bls_privates = try gpa.alloc(Private, n);
    defer gpa.free(bls_privates);
    const pairs = try gpa.alloc(S.Participants.Pair, n);
    defer gpa.free(pairs);
    for (bls_privates, pairs, public_keys) |*private, *pair, identity| {
        private.* = Private.random(rng);
        pair.* = .{ identity, ops.compute_public(V, private.*) };
    }
    var map = S.Participants.init(gpa, pairs) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Proof: distinct identities and (with overwhelming probability) distinct BLS keys.
        else => unreachable,
    };
    defer map.deinit(gpa);
    const schemes = try gpa.alloc(S, n);
    errdefer gpa.free(schemes);
    var built: usize = 0;
    errdefer for (schemes[0..built]) |*scheme| scheme.deinit(gpa);
    for (bls_privates, schemes) |private, *scheme| {
        const copy = try clone_participants(gpa, &map);
        scheme.* = (try S.signer(gpa, namespace, copy, private)) orelse unreachable;
        built += 1;
    }
    return .{
        .participants = public_keys,
        .private_keys = private_keys,
        .schemes = schemes,
        .verifier = try S.verifier(gpa, namespace, try clone_participants(gpa, &map)),
    };
}

const certificate_of = Certificate;

test {
    _ = @import("multisig_tests.zig");
}
