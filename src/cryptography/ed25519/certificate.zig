//! The ed25519 certificate scheme (commonware `ed25519/certificate/mod.rs`): attributable
//! individual signatures, checked with batch verification. A certificate is the signer
//! bitmap and every signature in signer order.
//!
//! commonware's `impl_certificate_ed25519!(Subject, Namespace, Faults)` macro and its
//! `Generic` are one type here: `Scheme(Subject, Faults)`, with the namespace type taken
//! from `Subject.Namespace`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const certificate = @import("../certificate.zig");
const scheme_module = @import("scheme.zig");

pub const mocks = @import("certificate/mocks.zig");
pub const fixture = mocks.fixture;

const Participant = utils.Participant;
const PrivateKey = scheme_module.PrivateKey;
const PublicKey = scheme_module.PublicKey;
const Signature = scheme_module.Signature;

/// An ed25519 certificate: the signer bitmap and the signatures in signer order.
pub const Certificate = certificate.Individual(
    Signature,
    "cryptography::ed25519::certificate::Certificate",
);

/// An ed25519 certificate scheme over `Subject`, with quorums from the fault model `Faults`.
pub fn Scheme(comptime SubjectType: type, comptime FaultsType: type) type {
    certificate.assert_subject(SubjectType);
    return struct {
        const Self = @This();
        pub const Subject = SubjectType;
        pub const Faults = FaultsType;
        pub const Namespace = Subject.Namespace;
        pub const PublicKey = scheme_module.PublicKey;
        pub const Signature = scheme_module.Signature;
        pub const Certificate = certificate_type;
        pub const Attestation = certificate.Attestation(Self);
        pub const Verification = certificate.Verification(Self);
        pub const Assembled = certificate.Assembled(Self);
        pub const Item = certificate.CertificateItem(Self);
        pub const Participants = utils.ordered.Set(scheme_module.PublicKey);

        /// The committee, ordered by public key.
        committee: Participants,
        /// The key this instance signs with, and its index.
        signing: ?Signing,
        /// A member's index when it holds no signing key.
        member_index: ?Participant,
        namespace: Namespace,

        const Signing = struct { index: Participant, key: PrivateKey };

        /// A signing scheme, or null when `private_key` is not in `set`. Takes
        /// ownership of `set` (released when the result is null).
        pub fn signer(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            private_key: PrivateKey,
        ) Allocator.Error!?Self {
            var committee = set;
            const index = committee.index(private_key.public_key()) orelse {
                committee.deinit(gpa);
                return null;
            };
            errdefer committee.deinit(gpa);
            return .{
                .committee = committee,
                .signing = .{ .index = index, .key = private_key },
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

        /// A verifier that knows its own index, or null when `public_key` is not in
        /// `set`. Takes ownership of `set`.
        pub fn member(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            public_key: scheme_module.PublicKey,
        ) Allocator.Error!?Self {
            var committee = set;
            const index = committee.index(public_key) orelse {
                committee.deinit(gpa);
                return null;
            };
            var result = try verifier(gpa, namespace, committee);
            result.member_index = index;
            return result;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var committee = try self.committee.clone(gpa);
            errdefer committee.deinit(gpa);
            return .{
                .committee = committee,
                .signing = self.signing,
                .member_index = self.member_index,
                .namespace = try self.namespace.clone(gpa),
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

        pub fn participants(self: *const Self) *const Participants {
            return &self.committee;
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
            const public_key = self.committee.key(attestation.signer) orelse return false;
            const signature = attestation.signature.get() orelse return false;
            const message = try subject.message(gpa);
            defer gpa.free(message);
            return public_key.verify(subject.namespace(&self.namespace), message, &signature);
        }

        const Candidate = struct {
            attestation: Attestation,
            public_key: *const scheme_module.PublicKey,
            signature: scheme_module.Signature,
        };

        /// Projects candidates onto batch entries over one message.
        const CandidateProjector = struct {
            namespace: []const u8,
            message: []const u8,

            pub fn project(self: @This(), _: usize, item: *const Candidate) Entry {
                return .{
                    .namespace = self.namespace,
                    .message = self.message,
                    .public_key = item.public_key,
                    .signature = &item.signature,
                };
            }
        };

        /// Batch-verifies `attestations`, then checks each one alone when the batch fails.
        pub fn verify_attestations(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestations: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Verification {
            const namespace = subject.namespace(&self.namespace);
            const message = try subject.message(gpa);
            defer gpa.free(message);
            var invalid: std.ArrayList(Participant) = .empty;
            defer invalid.deinit(gpa);
            var candidates: std.ArrayList(Candidate) = try .initCapacity(gpa, attestations.len);
            defer candidates.deinit(gpa);
            for (attestations) |attestation| {
                const public_key = self.committee.key(attestation.signer);
                const signature = attestation.signature.get();
                if (public_key == null or signature == null) {
                    try invalid.append(gpa, attestation.signer);
                    continue;
                }
                candidates.appendAssumeCapacity(.{
                    .attestation = attestation,
                    .public_key = public_key.?,
                    .signature = signature.?,
                });
            }
            const projector: CandidateProjector = .{ .namespace = namespace, .message = message };
            const items = candidates.items;
            if (items.len > 0 and
                !scheme_module.PublicKey.verify_batch(rng, items, projector, strategy))
            {
                // The batch failed: check each signer to isolate the faulty attestations.
                for (items) |*item| {
                    if (!item.public_key.verify(namespace, message, &item.signature)) {
                        try invalid.append(gpa, item.attestation.signer);
                    }
                }
            }
            return collect(gpa, items, invalid.items);
        }

        fn collect(
            gpa: Allocator,
            candidates: []const Candidate,
            invalid_unsorted: []Participant,
        ) Allocator.Error!Verification {
            const invalid_sorted = certificate.sort_unique(invalid_unsorted);
            var verified: std.ArrayList(Attestation) = try .initCapacity(gpa, candidates.len);
            errdefer verified.deinit(gpa);
            for (candidates) |candidate| {
                if (contains(invalid_sorted, candidate.attestation.signer)) continue;
                verified.appendAssumeCapacity(candidate.attestation);
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

        const Entry = scheme_module.PublicKey.Entry;

        /// Assembles a non-empty list of attestations, which need not be verified, into a
        /// certificate with the signatures in signer order.
        pub fn assemble(
            self: *const Self,
            gpa: Allocator,
            attestations: []const Attestation,
            strategy: anytype,
        ) (certificate.AssemblyError || Allocator.Error)!certificate_type {
            _ = strategy;
            const quorum = self.committee.quorum(Faults);
            return certificate_type.assemble(gpa, self.committee.len(), quorum, attestations);
        }

        const Staged = struct {
            message: usize,
            public_key: *const scheme_module.PublicKey,
            signature: scheme_module.Signature,
        };

        /// Projects staged signatures onto batch entries over several messages.
        const StagedProjector = struct {
            namespaces: []const []const u8,
            messages: []const []u8,

            pub fn project(self: @This(), _: usize, item: *const Staged) Entry {
                return .{
                    .namespace = self.namespaces[item.message],
                    .message = self.messages[item.message],
                    .public_key = item.public_key,
                    .signature = &item.signature,
                };
            }
        };

        /// Checks the certificate's structure and appends its signatures to `staged`;
        /// false when the structure or a signature encoding is invalid.
        fn stage(
            self: *const Self,
            gpa: Allocator,
            cert: *const certificate_type,
            message: usize,
            staged: *std.ArrayList(Staged),
        ) Allocator.Error!bool {
            const count = cert.signers.count();
            if (cert.signers.len() != self.committee.len()) return false;
            if (count != cert.signatures.len) return false;
            if (count < self.committee.quorum(Faults)) return false;
            try staged.ensureUnusedCapacity(gpa, count);
            var signers = cert.signers.iter();
            for (cert.signatures) |deferred| {
                const index = signers.next().?;
                const public_key = self.committee.key(index) orelse return false;
                const signature = deferred.get() orelse return false;
                staged.appendAssumeCapacity(.{
                    .message = message,
                    .public_key = public_key,
                    .signature = signature,
                });
            }
            assert(signers.next() == null);
            return true;
        }

        /// Verifies a certificate with one batch verification.
        pub fn verify_certificate(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            cert: *const certificate_type,
            strategy: anytype,
        ) Allocator.Error!bool {
            const item: Item = .{ .subject = subject, .certificate = cert };
            return self.verify_certificates(gpa, rng, &.{item}, strategy);
        }

        /// Verifies a non-empty list of certificates with one batch verification.
        pub fn verify_certificates(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            items: []const Item,
            strategy: anytype,
        ) Allocator.Error!bool {
            assert(items.len > 0);
            const namespaces = try gpa.alloc([]const u8, items.len);
            defer gpa.free(namespaces);
            const messages = try gpa.alloc([]u8, items.len);
            var built: usize = 0;
            defer {
                for (messages[0..built]) |message| gpa.free(message);
                gpa.free(messages);
            }
            var staged: std.ArrayList(Staged) = .empty;
            defer staged.deinit(gpa);
            for (items, 0..) |item, index| {
                if (!try self.stage(gpa, item.certificate, index, &staged)) return false;
                namespaces[index] = item.subject.namespace(&self.namespace);
                messages[index] = try item.subject.message(gpa);
                built += 1;
            }
            const projector: StagedProjector = .{ .namespaces = namespaces, .messages = messages };
            return scheme_module.PublicKey.verify_batch(rng, staged.items, projector, strategy);
        }

        pub fn is_attributable() bool {
            return true;
        }

        pub fn is_batchable() bool {
            return true;
        }

        /// An upper bound on the encoding of a certificate over at most `count` participants.
        pub fn max_certificate_size(count: u32) usize {
            const size = scheme_module.Signature.fixed_size;
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
