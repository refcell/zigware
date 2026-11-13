//! The secp256r1 certificate scheme (commonware `secp256r1/certificate/mod.rs`): attributable
//! individual signatures, each checked on its own. A certificate is the signer bitmap and
//! every signature in signer order.
//!
//! Participants are identified by an identity key of type `P` (an ed25519 key in
//! commonware's fixtures) and sign with the secp256r1 key paired with it in a `BiMap`.
//! commonware's `impl_certificate_secp256r1!(Subject, Namespace, Faults)` macro and its
//! `Generic<P, N>` are one type here: `Scheme(Subject, Faults, P)`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const certificate = @import("../certificate.zig");
const standard = @import("standard.zig");

pub const mocks = @import("certificate/mocks.zig");
pub const fixture = mocks.fixture;

const Participant = utils.Participant;
const PrivateKey = standard.PrivateKey;

/// A secp256r1 certificate: the signer bitmap and the signatures in signer order.
pub const Certificate = certificate.Individual(
    standard.Signature,
    "cryptography::secp256r1::certificate::Certificate",
);

/// A secp256r1 certificate scheme over `Subject` for participants identified by keys of type
/// `P`, with quorums from the fault model `Faults`.
pub fn Scheme(comptime SubjectType: type, comptime FaultsType: type, comptime P: type) type {
    certificate.assert_subject(SubjectType);
    return struct {
        const Self = @This();
        pub const Subject = SubjectType;
        pub const Faults = FaultsType;
        pub const Namespace = Subject.Namespace;
        pub const PublicKey = P;
        pub const Signature = standard.Signature;
        pub const Certificate = certificate_type;
        pub const Attestation = certificate.Attestation(Self);
        pub const Verification = certificate.Verification(Self);
        pub const Assembled = certificate.Assembled(Self);
        pub const Item = certificate.CertificateItem(Self);
        /// Identity keys, sorted, paired with each participant's signing key.
        pub const Participants = utils.ordered.BiMap(P, standard.PublicKey);

        committee: Participants,
        signing: ?Signing,
        member_index: ?Participant,
        namespace: Namespace,

        const Signing = struct { index: Participant, key: PrivateKey };

        /// A signing scheme, or null when `private_key` signs for no participant. Takes
        /// ownership of `set` (released when the result is null).
        pub fn signer(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            private_key: PrivateKey,
        ) Allocator.Error!?Self {
            var committee = set;
            const public_key = private_key.public_key();
            const position = for (committee.values(), 0..) |value, index| {
                if (value.eql(public_key)) break index;
            } else {
                committee.deinit(gpa);
                return null;
            };
            errdefer committee.deinit(gpa);
            return .{
                .committee = committee,
                .signing = .{ .index = .from_usize(position), .key = private_key },
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        /// A scheme that verifies but cannot sign. Takes ownership of `set`.
        pub fn verifier(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
        ) Allocator.Error!Self {
            var committee = set;
            errdefer committee.deinit(gpa);
            return .{
                .committee = committee,
                .signing = null,
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        /// A verifier that knows its own index, or null when `identity` is not a
        /// participant. Takes ownership of `set`.
        pub fn member(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            identity: P,
        ) Allocator.Error!?Self {
            var committee = set;
            const index = committee.keys().index(identity) orelse {
                committee.deinit(gpa);
                return null;
            };
            var result = try verifier(gpa, namespace, committee);
            result.member_index = index;
            return result;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var committee = try clone_participants(gpa, &self.committee);
            errdefer committee.deinit(gpa);
            return .{
                .committee = committee,
                .signing = self.signing,
                .member_index = self.member_index,
                .namespace = try self.namespace.clone(gpa),
            };
        }

        fn clone_participants(
            gpa: Allocator,
            set: *const Participants,
        ) Allocator.Error!Participants {
            const pairs = try gpa.alloc(Participants.Pair, set.len());
            defer gpa.free(pairs);
            const keys = set.keys().as_slice();
            for (pairs, keys, set.values()) |*pair, key, value| pair.* = .{ key, value };
            return Participants.init(gpa, pairs) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // Proof: the keys come from a valid map, so they are sorted and unique.
                else => unreachable,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.committee.deinit(gpa);
            self.namespace.deinit(gpa);
            if (self.signing) |*signing| signing.key.zeroize();
            self.* = undefined;
        }

        pub fn me(self: *const Self) ?certificate.Membership {
            if (self.signing) |signing| return .{ .signer = signing.index };
            if (self.member_index) |index| return .{ .member = index };
            return null;
        }

        /// The participants' identity keys.
        pub fn participants(self: *const Self) *const utils.ordered.Set(P) {
            return self.committee.keys();
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
            const signature = signing.key.sign(subject.namespace(&self.namespace), message);
            return Attestation.init(signing.index, signature);
        }

        fn verify_one(
            self: *const Self,
            namespace: []const u8,
            message: []const u8,
            attestation: *const Attestation,
        ) bool {
            const public_key = self.committee.value(attestation.signer.get()) orelse return false;
            const signature = attestation.signature.get() orelse return false;
            return public_key.verify(namespace, message, &signature);
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
            const message = try subject.message(gpa);
            defer gpa.free(message);
            return self.verify_one(subject.namespace(&self.namespace), message, attestation);
        }

        /// Verifies each attestation on its own; secp256r1 has no batch verification.
        pub fn verify_attestations(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestations: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Verification {
            _ = rng;
            _ = strategy;
            const namespace = subject.namespace(&self.namespace);
            const message = try subject.message(gpa);
            defer gpa.free(message);
            var verified: std.ArrayList(Attestation) = try .initCapacity(gpa, attestations.len);
            errdefer verified.deinit(gpa);
            var invalid: std.ArrayList(Participant) = .empty;
            defer invalid.deinit(gpa);
            for (attestations) |*attestation| {
                if (self.verify_one(namespace, message, attestation)) {
                    verified.appendAssumeCapacity(attestation.*);
                } else {
                    try invalid.append(gpa, attestation.signer);
                }
            }
            const invalid_owned = try gpa.dupe(Participant, certificate.sort_unique(invalid.items));
            errdefer gpa.free(invalid_owned);
            return .{ .verified = try verified.toOwnedSlice(gpa), .invalid = invalid_owned };
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
            return certificate.verify_then_assemble(
                self,
                gpa,
                rng,
                subject,
                pending,
                verified,
                strategy,
            );
        }

        /// Assembles a non-empty list of attestations, which need not be verified, into a
        /// certificate with the signatures in signer order.
        pub fn assemble(
            self: *const Self,
            gpa: Allocator,
            attestations: []const Attestation,
            strategy: anytype,
        ) (certificate.AssemblyError || Allocator.Error)!certificate_type {
            _ = strategy;
            const quorum = self.committee.keys().quorum(Faults);
            return certificate_type.assemble(gpa, self.committee.len(), quorum, attestations);
        }

        /// Verifies every signature of a certificate, one at a time.
        pub fn verify_certificate(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            cert: *const certificate_type,
            strategy: anytype,
        ) Allocator.Error!bool {
            _ = rng;
            _ = strategy;
            const count = cert.signers.count();
            if (cert.signers.len() != self.committee.len()) return false;
            if (count != cert.signatures.len) return false;
            if (count < self.committee.keys().quorum(Faults)) return false;
            const namespace = subject.namespace(&self.namespace);
            const message = try subject.message(gpa);
            defer gpa.free(message);
            var signers = cert.signers.iter();
            for (cert.signatures) |deferred| {
                const index = signers.next().?;
                const public_key = self.committee.value(index.get()) orelse return false;
                const signature = deferred.get() orelse return false;
                if (!public_key.verify(namespace, message, &signature)) return false;
            }
            assert(signers.next() == null);
            return true;
        }

        /// Verifies a non-empty list of certificates, one after another.
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
            return false;
        }

        /// An upper bound on the encoding of a certificate over at most `count` participants.
        pub fn max_certificate_size(count: u32) usize {
            const size = standard.Signature.fixed_size;
            return certificate.max_individual_certificate_size(count, size);
        }

        pub fn certificate_codec_config(self: *const Self) usize {
            return self.committee.len();
        }

        /// For trusted local storage only: never decode network input with it.
        pub fn certificate_codec_config_unbounded() usize {
            return std.math.maxInt(u32);
        }

        comptime {
            certificate.assert_scheme(Self);
        }
    };
}

const certificate_type = Certificate;

test {
    _ = @import("certificate_test.zig");
}
