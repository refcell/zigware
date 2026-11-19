//! Tests for the mock certificate scheme (commonware `certificate/mocks.rs`). The
//! truncated-signature case has no counterpart (see `mocks.zig`); the should-panic cases are
//! death tests (`utils.death`).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const parallel = @import("parallel");
const certificate = @import("../certificate.zig");
const ed25519 = @import("../ed25519.zig");
const mocks = @import("mocks.zig");

const Participant = utils.Participant;
const U64 = utils.sequence.U64;
const sequential = parallel.sequential;
const gpa = testing.allocator;

const TestSubject = struct {
    pub const Namespace = certificate.BytesNamespace;

    bytes: []const u8,

    pub fn namespace(_: TestSubject, derived: *const Namespace) []const u8 {
        return derived.bytes;
    }

    pub fn message(self: TestSubject, allocator: Allocator) Allocator.Error![]u8 {
        return allocator.dupe(u8, self.bytes);
    }
};

fn MockScheme(comptime options: mocks.Options) type {
    return mocks.Scheme(TestSubject, utils.N3f1, ed25519.PublicKey, options);
}

const Scheme = MockScheme(.{});
const Attestation = Scheme.Attestation;
const namespace = "mock-scheme";
const vote_1: TestSubject = .{ .bytes = "vote-1" };
const vote_2: TestSubject = .{ .bytes = "vote-2" };

fn setup(comptime S: type, rng: anytype) !mocks.Fixture(S) {
    return mocks.fixture(S, gpa, rng, namespace, 4);
}

fn sign_all(fixture: anytype, subject: TestSubject, count: usize) ![]Attestation {
    const attestations = try gpa.alloc(Attestation, count);
    for (fixture.schemes[0..count], attestations) |*scheme, *attestation| {
        attestation.* = (try scheme.sign(gpa, subject)).?;
    }
    return attestations;
}

fn verify_attestation(scheme: *const Scheme, subject: TestSubject, value: Attestation) !bool {
    var rng = utils.rng.test_rng();
    return scheme.verify_attestation(gpa, &rng, subject, &value, sequential);
}

fn verify_certificate(scheme: *const Scheme, subject: TestSubject, value: U64) !bool {
    var rng = utils.rng.test_rng();
    return scheme.verify_certificate(gpa, &rng, subject, &value, sequential);
}

test "mock certificate attestation round trip and reused signatures" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(Scheme, &rng);
    defer fixture.deinit(gpa);
    const first = (try fixture.schemes[0].sign(gpa, vote_1)).?;
    try testing.expect(try verify_attestation(&fixture.verifier, vote_1, first));
    try testing.expect(!try verify_attestation(&fixture.verifier, vote_2, first));

    // Re-signing a subject reuses its signature; another subject gets a new one.
    const second = (try fixture.schemes[0].sign(gpa, vote_1)).?;
    const other = (try fixture.schemes[0].sign(gpa, vote_2)).?;
    try testing.expect(first.eql(second));
    try testing.expect(!first.eql(other));
}

test "mock certificate properties follow the flags" {
    try testing.expect(Scheme.is_attributable());
    try testing.expect(Scheme.is_batchable());
    const Plain = MockScheme(.{ .attributable = false, .batchable = false });
    try testing.expect(!Plain.is_attributable());
    try testing.expect(!Plain.is_batchable());
}

test "mock certificate signer and verifier metadata" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(Scheme, &rng);
    defer fixture.deinit(gpa);
    var cloned = try fixture.schemes[0].clone(gpa);
    defer cloned.deinit(gpa);
    const verifier = &fixture.verifier;
    try testing.expectEqual(null, verifier.me());
    try testing.expect(cloned.me().?.eql(.{ .signer = .init(0) }));
    try testing.expectEqual(4, verifier.participants().len());
    try testing.expectEqual({}, verifier.certificate_codec_config());
    const set = try verifier.participants().clone(gpa);
    try testing.expectEqual(
        null,
        try Scheme.signer(gpa, namespace, set, .init(99), verifier.shared),
    );
    try testing.expectEqual(null, try verifier.sign(gpa, vote_1));
    try testing.expect(try cloned.sign(gpa, vote_1) != null);
}

test "mock certificate rejects foreign and signer-swapped attestations" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(Scheme, &rng);
    defer fixture.deinit(gpa);
    var foreign_fixture = try setup(Scheme, &rng);
    defer foreign_fixture.deinit(gpa);
    const attestation = (try fixture.schemes[0].sign(gpa, vote_1)).?;
    var invalid_signer = attestation;
    invalid_signer.signer = .init(99);
    const foreign = (try foreign_fixture.schemes[3].sign(gpa, vote_1)).?;
    try testing.expect(!try verify_attestation(&fixture.verifier, vote_1, invalid_signer));
    try testing.expect(!try verify_attestation(&fixture.verifier, vote_1, foreign));

    // Different signers of one subject get distinct IDs, so swapping the signer fails.
    const attestation_b = (try fixture.schemes[1].sign(gpa, vote_1)).?;
    try testing.expect(!attestation.signature.eql(attestation_b.signature));
    var forged = attestation;
    forged.signer = .init(1);
    try testing.expect(!try verify_attestation(&fixture.verifier, vote_1, forged));
}

test "mock certificate verify attestations partitions inputs" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(Scheme, &rng);
    defer fixture.deinit(gpa);
    var foreign_fixture = try setup(Scheme, &rng);
    defer foreign_fixture.deinit(gpa);
    const valid_a = (try fixture.schemes[0].sign(gpa, vote_1)).?;
    const valid_b = (try fixture.schemes[1].sign(gpa, vote_1)).?;
    const foreign = (try foreign_fixture.schemes[3].sign(gpa, vote_1)).?;
    const verifier = &fixture.verifier;
    const inputs = [_]Attestation{ valid_a, foreign, valid_b };
    var result = try verifier.verify_attestations(gpa, &rng, vote_1, &inputs, sequential);
    defer result.deinit(gpa);
    try testing.expectEqual(2, result.verified.len);
    try testing.expect(result.verified[0].eql(valid_a));
    try testing.expect(result.verified[1].eql(valid_b));
    try testing.expectEqualSlices(Participant, &.{.init(3)}, result.invalid);

    var empty = try verifier.verify_attestations(gpa, &rng, vote_1, &.{}, sequential);
    defer empty.deinit(gpa);
    try testing.expectEqual(0, empty.verified.len);
    try testing.expectEqual(0, empty.invalid.len);
}

test "mock certificate round trip, reuse, and unit config" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(Scheme, &rng);
    defer fixture.deinit(gpa);
    const subject: TestSubject = .{ .bytes = "certificate-subject" };
    const attestations = try sign_all(&fixture, subject, 3);
    defer gpa.free(attestations);
    const verifier = &fixture.verifier;
    const first = try verifier.assemble(gpa, attestations, sequential);
    const encoded = try codec.encode(U64, gpa, first);
    defer gpa.free(encoded);
    try testing.expectEqual(Scheme.max_certificate_size(4), encoded.len);
    const decoded = try codec.decode_cfg(U64, gpa, encoded, verifier.certificate_codec_config());
    try testing.expect(try verify_certificate(verifier, subject, decoded));
    const other: TestSubject = .{ .bytes = "other-subject" };
    try testing.expect(!try verify_certificate(verifier, other, decoded));

    // Assembling the same attestations in another order reuses the certificate.
    std.mem.reverse(Attestation, attestations);
    try testing.expect(first.eql(try verifier.assemble(gpa, attestations, sequential)));
}

test "mock certificate member reports membership without signing" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(Scheme, &rng);
    defer fixture.deinit(gpa);
    const participants = fixture.verifier.participants();
    const shared = fixture.verifier.shared;
    const subject: TestSubject = .{ .bytes = "certificate-subject" };

    // A key outside the committee yields no member.
    const outsiders, const outsider_keys = try mocks_participants(&rng);
    defer gpa.free(outsiders);
    defer gpa.free(outsider_keys);
    const set = try participants.clone(gpa);
    try testing.expectEqual(null, try Scheme.member(gpa, namespace, set, outsiders[0], shared));

    const index = Participant.init(2);
    const key = participants.key(index).?.*;
    const member_set = try participants.clone(gpa);
    var member = (try Scheme.member(gpa, namespace, member_set, key, shared)).?;
    defer member.deinit(gpa);
    try testing.expect(member.me().?.eql(.{ .member = index }));
    try testing.expectEqual(null, member.me().?.signer_index());
    try testing.expectEqual(null, try member.sign(gpa, subject));
    for (fixture.schemes, 0..) |*scheme, position| {
        try testing.expect(scheme.me().?.eql(.{ .signer = .from_usize(position) }));
    }

    const attestations = try sign_all(&fixture, subject, 3);
    defer gpa.free(attestations);
    const cert = try fixture.schemes[0].assemble(gpa, attestations, sequential);
    var member_rng = utils.rng.test_rng();
    try testing.expect(try member.verify_certificate(gpa, &member_rng, subject, &cert, sequential));
}

fn mocks_participants(rng: anytype) !struct { []ed25519.PublicKey, []ed25519.PrivateKey } {
    return ed25519.certificate.mocks.participants(gpa, rng, 1);
}

test "mock certificate assembly requires matching subjects, quorum, and distinct signers" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(Scheme, &rng);
    defer fixture.deinit(gpa);
    const verifier = &fixture.verifier;
    const attestations = try sign_all(&fixture, vote_1, 3);
    defer gpa.free(attestations);
    const short = verifier.assemble(gpa, attestations[0..2], sequential);
    try testing.expectError(error.InsufficientAttestations, short);

    const mixed = [_]Attestation{
        attestations[0],
        attestations[1],
        (try fixture.schemes[2].sign(gpa, vote_2)).?,
    };
    const mismatched = verifier.assemble(gpa, &mixed, sequential);
    try testing.expectError(error.MalformedSignature, mismatched);

    const duplicated = [_]Attestation{ attestations[0], attestations[0], attestations[1] };
    const duplicate = verifier.assemble(gpa, &duplicated, sequential);
    try testing.expectError(error.DuplicateSigner, duplicate);

    // A strict scheme still reports a sub-quorum instead of panicking.
    var strict = try setup(Strict, &rng);
    defer strict.deinit(gpa);
    var strict_attestations: [2]Strict.Attestation = undefined;
    for (strict.schemes[0..2], &strict_attestations) |*scheme, *attestation| {
        attestation.* = (try scheme.sign(gpa, vote_1)).?;
    }
    const strict_short = strict.verifier.assemble(gpa, &strict_attestations, sequential);
    try testing.expectError(error.InsufficientAttestations, strict_short);
}

test "mock certificate verification rejects mismatched subjects and batch failures" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(Scheme, &rng);
    defer fixture.deinit(gpa);
    const verifier = &fixture.verifier;
    const subject_a: TestSubject = .{ .bytes = "vote-a" };
    const subject_b: TestSubject = .{ .bytes = "vote-b" };
    const signed_a = try sign_all(&fixture, subject_a, 3);
    defer gpa.free(signed_a);
    const signed_b = try sign_all(&fixture, subject_b, 3);
    defer gpa.free(signed_b);
    const cert_a = try verifier.assemble(gpa, signed_a, sequential);
    const cert_b = try verifier.assemble(gpa, signed_b, sequential);
    const missing = U64.init(std.math.maxInt(u64));
    try testing.expect(!try verify_certificate(verifier, subject_a, cert_b));
    try testing.expect(!try verify_certificate(verifier, subject_b, missing));
    const valid = [_]Scheme.Item{
        .{ .subject = subject_a, .certificate = &cert_a },
        .{ .subject = subject_b, .certificate = &cert_b },
    };
    try testing.expect(try verifier.verify_certificates(gpa, &rng, &valid, sequential));
    const invalid = [_]Scheme.Item{
        .{ .subject = subject_a, .certificate = &cert_a },
        .{ .subject = subject_b, .certificate = &missing },
    };
    try testing.expect(!try verifier.verify_certificates(gpa, &rng, &invalid, sequential));
}

test "mock certificate optimistic assemble" {
    var rng = utils.rng.test_rng();
    var fixture = try setup(Scheme, &rng);
    defer fixture.deinit(gpa);
    const verifier = &fixture.verifier;
    const pending = try sign_all(&fixture, vote_1, 4);
    defer gpa.free(pending);
    var certified = try verifier.optimistic_assemble(gpa, &rng, vote_1, pending, &.{}, sequential);
    defer certified.deinit(gpa);
    try testing.expect(try verify_certificate(verifier, vote_1, certified.certificate));

    // A vote over another subject is reported and the others verify.
    pending[1] = (try fixture.schemes[1].sign(gpa, vote_2)).?;
    var result = try verifier.optimistic_assemble(gpa, &rng, vote_1, pending, &.{}, sequential);
    defer result.deinit(gpa);
    try testing.expectEqualSlices(Participant, &.{.init(1)}, result.verification.invalid);
    try testing.expectEqual(3, result.verification.verified.len);
}

const death = utils.death;

// commonware `signature_overflow_panics`: a ledger whose next signature ID is u64::MAX panics
// when it records a new signature.
test "mock certificate signature overflow panics" {
    try death.expect_panic(@src(), "signature overflow", struct {
        fn body() !void {
            var rng = utils.rng.test_rng();
            var fixture = try setup(Scheme, &rng);
            defer fixture.deinit(gpa);
            fixture.schemes[0].shared.signature_next = std.math.maxInt(u64);
            _ = try fixture.schemes[0].sign(gpa, vote_1);
        }
    }.body);
}

// commonware `certificate_overflow_panics`: the same for a new certificate.
test "mock certificate certificate overflow panics" {
    try death.expect_panic(@src(), "certificate overflow", struct {
        fn body() !void {
            var rng = utils.rng.test_rng();
            var fixture = try setup(Scheme, &rng);
            defer fixture.deinit(gpa);
            const attestations = try sign_all(&fixture, vote_1, 3);
            defer gpa.free(attestations);
            fixture.verifier.shared.certificate_next = std.math.maxInt(u64);
            _ = try fixture.verifier.assemble(gpa, attestations, sequential);
        }
    }.body);
}

const Strict = MockScheme(.{ .allow_invalid = false });

// commonware `strict_invalid_requests_panic`: a strict scheme panics on verifying an
// attestation against the wrong subject instead of rejecting it.
test "mock certificate strict scheme panics on an invalid request" {
    try death.expect_panic(@src(), "invalid mock certificate request", struct {
        fn body() !void {
            var rng = utils.rng.test_rng();
            var fixture = try setup(Strict, &rng);
            defer fixture.deinit(gpa);
            const attestation = (try fixture.schemes[0].sign(gpa, vote_1)).?;
            const verifier = &fixture.verifier;
            _ = try verifier.verify_attestation(gpa, &rng, vote_2, &attestation, sequential);
        }
    }.body);
}

// commonware `strict_invalid_assembly_requests_panic`: a strict scheme panics on assembling
// attestations over mixed subjects instead of returning the error.
test "mock certificate strict scheme panics on an invalid assembly" {
    try death.expect_panic(@src(), "invalid mock certificate request", struct {
        fn body() !void {
            var rng = utils.rng.test_rng();
            var fixture = try setup(Strict, &rng);
            defer fixture.deinit(gpa);
            const mixed = [_]Strict.Attestation{
                (try fixture.schemes[0].sign(gpa, vote_1)).?,
                (try fixture.schemes[1].sign(gpa, vote_2)).?,
                (try fixture.schemes[2].sign(gpa, vote_1)).?,
            };
            _ = try fixture.verifier.assemble(gpa, &mixed, sequential);
        }
    }.body);
}
