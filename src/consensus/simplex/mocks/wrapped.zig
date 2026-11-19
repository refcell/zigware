//! A certificate scheme wrapper that can misbehave (commonware `simplex/mocks/wrapped.rs`):
//! `corrupt_signature` signs with a single flipped bit that still decodes but fails
//! verification, and `recovery_failure` fails every assembly. Verification always uses the
//! wrapped scheme, so honest validators judge a misbehaving one correctly.
//!
//! The wrapper copies the inner scheme by value (a shallow, borrowed copy, like the inner
//! schemes themselves); the inner scheme's owner frees it. Electors need no wrapper: an
//! elector built for the inner scheme serves the wrapper unchanged.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");

const certificate = cryptography.certificate;
const Participant = utils.Participant;
const Sha256 = cryptography.Sha256;

pub const Behavior = enum { honest, corrupt_signature, recovery_failure };

pub fn Scheme(comptime Inner: type) type {
    certificate.assert_scheme(Inner);
    return struct {
        const Self = @This();
        pub const Subject = Inner.Subject;
        pub const Faults = Inner.Faults;
        pub const PublicKey = Inner.PublicKey;
        pub const Signature = Inner.Signature;
        pub const Certificate = Inner.Certificate;
        pub const Participants = Inner.Participants;
        pub const Attestation = certificate.Attestation(Self);
        pub const Verification = certificate.Verification(Self);
        pub const Assembled = certificate.Assembled(Self);
        pub const Item = certificate.CertificateItem(Self);
        const InnerAttestation = certificate.Attestation(Inner);
        const signature_size = codec.fixed_size(Signature).?;

        inner: Inner,
        behavior: Behavior,

        pub fn init(inner: Inner, behavior: Behavior) Self {
            return .{ .inner = inner, .behavior = behavior };
        }

        pub fn me(self: *const Self) ?certificate.Membership {
            return self.inner.me();
        }

        pub fn participants(self: *const Self) *const utils.ordered.Set(PublicKey) {
            return self.inner.participants();
        }

        pub fn sign(
            self: *const Self,
            gpa: Allocator,
            subject: Subject,
        ) Allocator.Error!?Attestation {
            const signed = try self.inner.sign(gpa, subject) orelse return null;
            var result: Attestation = .{ .signer = signed.signer, .signature = signed.signature };
            switch (self.behavior) {
                .honest, .recovery_failure => {},
                .corrupt_signature => {
                    result.signature = try self.corrupt(gpa, subject, signed);
                },
            }
            assert(result.signer.get() == signed.signer.get());
            return result;
        }

        /// Searches the single-bit flips of `signed`'s signature, starting at a bit derived
        /// from the signer and signature, for one that decodes but fails verification.
        fn corrupt(
            self: *const Self,
            gpa: Allocator,
            subject: Subject,
            signed: InnerAttestation,
        ) Allocator.Error!certificate.Deferred(Signature) {
            const encoded = signed.signature.bytes;
            const bit_len: u64 = signature_size * 8;
            var signer_bytes: [codec.max_encode_size(Participant).?]u8 = undefined;
            var writer: codec.Writer = .init(&signer_bytes);
            signed.signer.write(&writer);
            const digest = Sha256.hash(&.{ writer.written(), &encoded });
            const start = utils.modulo(&digest.bytes, bit_len);
            var rng = utils.rng.test_rng();
            for (0..bit_len) |offset| {
                const flip = (start + offset) % bit_len;
                var candidate: InnerAttestation = signed;
                candidate.signature.bytes[flip / 8] ^= @as(u8, 1) << @intCast(flip % 8);
                if (candidate.signature.get() == null) continue;
                const strategy = parallel.sequential;
                if (try self.inner.verify_attestation(gpa, &rng, subject, &candidate, strategy)) {
                    continue;
                }
                assert(!candidate.signature.eql(signed.signature));
                return .{ .bytes = candidate.signature.bytes };
            }
            @panic("expected at least one invalid but decodable signature mutation");
        }

        pub fn verify_attestation(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestation: *const Attestation,
            strategy: anytype,
        ) Allocator.Error!bool {
            const inner: InnerAttestation = .{
                .signer = attestation.signer,
                .signature = .{ .bytes = attestation.signature.bytes },
            };
            return self.inner.verify_attestation(gpa, rng, subject, &inner, strategy);
        }

        pub fn verify_attestations(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestations: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Verification {
            const inner = try to_inner(gpa, attestations);
            defer gpa.free(inner);
            const verification =
                try self.inner.verify_attestations(gpa, rng, subject, inner, strategy);
            defer gpa.free(verification.verified);
            const verified = gpa.alloc(Attestation, verification.verified.len) catch |err| {
                gpa.free(verification.invalid);
                return err;
            };
            for (verified, verification.verified) |*outer, attestation| {
                outer.* = .{ .signer = attestation.signer, .signature = .{
                    .bytes = attestation.signature.bytes,
                } };
            }
            assert(verified.len + verification.invalid.len <= attestations.len);
            return .{ .verified = verified, .invalid = verification.invalid };
        }

        fn to_inner(gpa: Allocator, attestations: []const Attestation) ![]InnerAttestation {
            const inner = try gpa.alloc(InnerAttestation, attestations.len);
            for (inner, attestations) |*copy, attestation| {
                copy.* = .{ .signer = attestation.signer, .signature = .{
                    .bytes = attestation.signature.bytes,
                } };
            }
            assert(inner.len == attestations.len);
            return inner;
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
            return certificate.optimistic_assemble(
                self,
                gpa,
                rng,
                subject,
                pending,
                verified,
                strategy,
            );
        }

        pub fn assemble(
            self: *const Self,
            gpa: Allocator,
            attestations: []const Attestation,
            strategy: anytype,
        ) (certificate.AssemblyError || Allocator.Error)!Certificate {
            assert(attestations.len > 0);
            const inner = try to_inner(gpa, attestations);
            defer gpa.free(inner);
            var result = try self.inner.assemble(gpa, inner, strategy);
            if (self.behavior == .recovery_failure) {
                certificate.deinit_certificate(Certificate, gpa, &result);
                return error.RecoveryFailed;
            }
            return result;
        }

        pub fn verify_certificate(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            cert: *const Certificate,
            strategy: anytype,
        ) Allocator.Error!bool {
            return self.inner.verify_certificate(gpa, rng, subject, cert, strategy);
        }

        pub fn verify_certificates(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            items: []const Item,
            strategy: anytype,
        ) Allocator.Error!bool {
            assert(items.len > 0);
            const inner = try gpa.alloc(certificate.CertificateItem(Inner), items.len);
            defer gpa.free(inner);
            for (inner, items) |*copy, item| {
                copy.* = .{ .subject = item.subject, .certificate = item.certificate };
            }
            return self.inner.verify_certificates(gpa, rng, inner, strategy);
        }

        pub fn is_attributable() bool {
            return Inner.is_attributable();
        }

        pub fn is_batchable() bool {
            return Inner.is_batchable();
        }

        pub fn max_certificate_size(count: u32) usize {
            return Inner.max_certificate_size(count);
        }

        pub fn certificate_codec_config(self: *const Self) codec.Cfg(Certificate) {
            return self.inner.certificate_codec_config();
        }

        pub fn certificate_codec_config_unbounded() codec.Cfg(Certificate) {
            return Inner.certificate_codec_config_unbounded();
        }
    };
}
