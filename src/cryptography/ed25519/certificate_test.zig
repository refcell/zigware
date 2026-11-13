//! Tests for the ed25519 certificate scheme (commonware `ed25519/certificate/mod.rs`).
//!
//! commonware's malformed-signature cases build a `Lazy` from three bytes; every 64-byte
//! string decodes as an ed25519 signature and attestations keep their signature inline, so
//! an ed25519 attestation is never malformed here and those cases are covered by the
//! secp256r1 scheme instead.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const parallel = @import("parallel");
const base = @import("../certificate.zig");
const ed25519 = @import("../ed25519.zig");

const Participant = utils.Participant;
const N3f1 = utils.N3f1;
const TestRng = utils.rng.TestRng;
const PrivateKey = ed25519.PrivateKey;
const PublicKey = ed25519.PublicKey;
const Certificate = ed25519.certificate.Certificate;
const Signers = base.Signers;
const sequential = parallel.sequential;
const gpa = testing.allocator;

const namespace = "test-ed25519";
const message = "test message";

/// commonware's `TestSubject`: a message signed under the base namespace.
pub const TestSubject = struct {
    pub const Namespace = base.BytesNamespace;

    bytes: []const u8,

    pub fn namespace(_: TestSubject, derived: *const Namespace) []const u8 {
        return derived.bytes;
    }

    pub fn message(self: TestSubject, allocator: Allocator) Allocator.Error![]u8 {
        return allocator.dupe(u8, self.bytes);
    }
};

const Scheme = ed25519.certificate.Scheme(TestSubject, N3f1);
const Attestation = Scheme.Attestation;
const subject: TestSubject = .{ .bytes = message };

const Fixture = struct {
    schemes: []Scheme,
    verifier: Scheme,

    /// `setup_signers`: `n` signers in key-generation order and a verifier.
    fn init(rng: anytype, n: u32) !Fixture {
        const keys = try gpa.alloc(PrivateKey, n);
        defer gpa.free(keys);
        const public_keys = try gpa.alloc(PublicKey, n);
        defer gpa.free(public_keys);
        for (keys, public_keys) |*key, *public_key| {
            key.* = PrivateKey.random(rng);
            public_key.* = key.public_key();
        }
        var participants = try Scheme.Participants.init(gpa, public_keys);
        defer participants.deinit(gpa);
        const schemes = try gpa.alloc(Scheme, n);
        for (keys, schemes) |key, *scheme| {
            const set = try participants.clone(gpa);
            scheme.* = (try Scheme.signer(gpa, namespace, set, key)).?;
        }
        const verifier = try Scheme.verifier(gpa, namespace, try participants.clone(gpa));
        return .{ .schemes = schemes, .verifier = verifier };
    }

    fn deinit(self: *Fixture) void {
        for (self.schemes) |*scheme| scheme.deinit(gpa);
        gpa.free(self.schemes);
        self.verifier.deinit(gpa);
    }

    /// Attestations over `item` from the first `count` signers.
    fn sign(self: *const Fixture, item: TestSubject, count: usize) ![]Attestation {
        const attestations = try gpa.alloc(Attestation, count);
        for (self.schemes[0..count], attestations) |*scheme, *attestation| {
            attestation.* = (try scheme.sign(gpa, item)).?;
        }
        return attestations;
    }

    /// A certificate over `item` from the first `count` signers.
    fn certify(self: *const Fixture, item: TestSubject, count: usize) !Certificate {
        const attestations = try self.sign(item, count);
        defer gpa.free(attestations);
        return self.schemes[0].assemble(gpa, attestations, sequential);
    }

    fn quorum(self: *const Fixture) u32 {
        return N3f1.quorum(self.schemes.len);
    }
};

/// A certificate with the given signer bitmap and signatures (both copied).
fn certificate_from(
    participants: u32,
    signers: []const Participant,
    signatures: []const Deferred,
) !Certificate {
    var bitmap = try Signers.init(gpa, participants, signers);
    errdefer bitmap.deinit(gpa);
    return .{ .signers = bitmap, .signatures = try gpa.dupe(Deferred, signatures) };
}

const Deferred = base.Deferred(ed25519.Signature);

fn signer_list(cert: *const Certificate) ![]Participant {
    var list: std.ArrayList(Participant) = .empty;
    var iter = cert.signers.iter();
    while (iter.next()) |signer| try list.append(gpa, signer);
    return list.toOwnedSlice(gpa);
}

fn verify(scheme: *const Scheme, rng: anytype, item: TestSubject, cert: *const Certificate) !bool {
    return scheme.verify_certificate(gpa, rng, item, cert, sequential);
}

test "ed25519 certificate is attributable and batchable" {
    try testing.expect(Scheme.is_attributable());
    try testing.expect(Scheme.is_batchable());
}

test "ed25519 certificate optimistic assemble reuses verified attestations" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 5);
    defer fixture.deinit();
    const quorum = fixture.quorum();
    const attestations = try fixture.sign(subject, quorum);
    defer gpa.free(attestations);

    // One seed per signature makes RNG consumption expose the size of the verification
    // batch, even when the single worker executes it serially.
    const pool = try parallel.ThreadPool.create(gpa, testing.io, .{ .threads = 1 });
    defer pool.destroy();
    const strategy = parallel.Rayon.init(pool).with_parallelism(quorum);
    for ([_]usize{ quorum, 1, 0 }) |pending_len| {
        const prior = attestations[0 .. quorum - pending_len];
        const pending = attestations[quorum - pending_len ..];
        const verifier = &fixture.verifier;
        var verified = try verifier.verify_attestations(gpa, &rng, subject, prior, sequential);
        defer verified.deinit(gpa);
        try testing.expectEqual(0, verified.invalid.len);

        // Construction does only the verification needed for fresh votes, including when
        // every vote was already authenticated.
        var expected_rng = TestRng.init(0);
        var expected = try fixture.verifier.verify_attestations(
            gpa,
            &expected_rng,
            subject,
            pending,
            strategy,
        );
        defer expected.deinit(gpa);
        try testing.expectEqual(0, expected.invalid.len);
        var actual_rng = TestRng.init(0);
        var result = try fixture.verifier.optimistic_assemble(
            gpa,
            &actual_rng,
            subject,
            pending,
            verified.verified,
            strategy,
        );
        defer result.deinit(gpa);
        try testing.expectEqual(expected_rng.next_u64(), actual_rng.next_u64());
        try testing.expect(try verify(&fixture.verifier, &rng, subject, &result.certificate));
    }
}

test "ed25519 certificate sign and verify an attestation" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    const scheme = &fixture.schemes[0];
    const attestation = (try scheme.sign(gpa, subject)).?;
    try testing.expect(try scheme.verify_attestation(gpa, &rng, subject, &attestation, sequential));
    const other: TestSubject = .{ .bytes = "other message" };
    try testing.expect(!try scheme.verify_attestation(gpa, &rng, other, &attestation, sequential));
}

test "ed25519 certificate verifier cannot sign" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    try testing.expectEqual(null, try fixture.verifier.sign(gpa, subject));

    // A clone of a signer still signs.
    var clone = try fixture.schemes[0].clone(gpa);
    defer clone.deinit(gpa);
    try testing.expect(try clone.sign(gpa, subject) != null);
}

test "ed25519 certificate member reports membership without signing" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    const participants = fixture.verifier.participants();

    // A key outside the committee yields no member.
    const outsider = PrivateKey.random(&rng).public_key();
    try testing.expectEqual(
        null,
        try Scheme.member(gpa, namespace, try participants.clone(gpa), outsider),
    );

    // A member reports its membership but cannot sign. Verifiers report no membership, and
    // each signer reports the index it signs at.
    const index = Participant.init(2);
    const key = participants.key(index).?.*;
    var member = (try Scheme.member(gpa, namespace, try participants.clone(gpa), key)).?;
    defer member.deinit(gpa);
    try testing.expect(member.me().?.eql(.{ .member = index }));
    try testing.expectEqual(null, member.me().?.signer_index());
    try testing.expectEqual(null, try member.sign(gpa, subject));
    try testing.expectEqual(null, fixture.verifier.me());
    for (fixture.schemes) |*scheme| {
        const signer = scheme.me().?.signer_index().?;
        const attestation = (try scheme.sign(gpa, subject)).?;
        try testing.expectEqual(signer, attestation.signer);
    }

    // A member verifies a certificate assembled by a quorum of signers.
    var cert = try fixture.certify(subject, fixture.quorum());
    defer cert.deinit(gpa);
    try testing.expect(try verify(&member, &rng, subject, &cert));
}

test "ed25519 certificate verify attestations filters invalid" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 5);
    defer fixture.deinit();
    const quorum = fixture.quorum();
    const scheme = &fixture.schemes[0];
    const attestations = try fixture.sign(subject, quorum);
    defer gpa.free(attestations);

    var result = try scheme.verify_attestations(gpa, &rng, subject, attestations, sequential);
    try testing.expectEqual(0, result.invalid.len);
    try testing.expectEqual(quorum, result.verified.len);
    result.deinit(gpa);

    // An unknown signer index invalidates only that attestation.
    const corrupted = try gpa.dupe(Attestation, attestations);
    defer gpa.free(corrupted);
    corrupted[0].signer = .init(999);
    result = try scheme.verify_attestations(gpa, &rng, subject, corrupted, sequential);
    try testing.expectEqualSlices(Participant, &.{.init(999)}, result.invalid);
    try testing.expectEqual(quorum - 1, result.verified.len);
    result.deinit(gpa);

    // Copying another signer's signature invalidates exactly one attestation.
    @memcpy(corrupted, attestations);
    corrupted[0].signature = corrupted[1].signature;
    result = try scheme.verify_attestations(gpa, &rng, subject, corrupted, sequential);
    try testing.expectEqualSlices(Participant, &.{attestations[0].signer}, result.invalid);
    try testing.expectEqual(quorum - 1, result.verified.len);
    result.deinit(gpa);

    // When no attestation reaches batch verification, the caller's RNG is untouched.
    var unknown = attestations[1];
    unknown.signer = .init(999);
    for ([_][]const Attestation{ &.{}, &.{unknown} }) |list| {
        var actual_rng = TestRng.init(0);
        var expected_rng = TestRng.init(0);
        result = try scheme.verify_attestations(gpa, &actual_rng, subject, list, sequential);
        defer result.deinit(gpa);
        try testing.expectEqual(0, result.verified.len);
        try testing.expectEqual(list.len, result.invalid.len);
        try testing.expectEqual(expected_rng.next_u64(), actual_rng.next_u64());
    }
}

test "ed25519 certificate assemble" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    const quorum = fixture.quorum();
    var cert = try fixture.certify(subject, quorum);
    defer cert.deinit(gpa);
    try testing.expectEqual(quorum, cert.signers.count());
    try testing.expectEqual(quorum, cert.signatures.len);
}

test "ed25519 certificate assemble sorts signers" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    const attestations = try fixture.sign(subject, 3);
    defer gpa.free(attestations);
    std.mem.sort(Attestation, attestations, {}, struct {
        fn greater(_: void, a: Attestation, b: Attestation) bool {
            return a.signer.get() > b.signer.get();
        }
    }.greater);
    var cert = try fixture.schemes[0].assemble(gpa, attestations, sequential);
    defer cert.deinit(gpa);
    const signers = try signer_list(&cert);
    defer gpa.free(signers);
    for (signers, 0..) |signer, position| {
        const attestation = attestations[attestations.len - 1 - position];
        try testing.expectEqual(attestation.signer, signer);
        try testing.expect(cert.signatures[position].eql(attestation.signature));
    }
}

test "ed25519 certificate verify and detect corruption" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    var cert = try fixture.certify(subject, fixture.quorum());
    defer cert.deinit(gpa);
    try testing.expect(try verify(&fixture.verifier, &rng, subject, &cert));
    const other: TestSubject = .{ .bytes = "other message" };
    try testing.expect(!try verify(&fixture.verifier, &rng, other, &cert));

    cert.signatures[0] = cert.signatures[1];
    try testing.expect(!try verify(&fixture.verifier, &rng, subject, &cert));
}

test "ed25519 certificate codec round trip" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    var cert = try fixture.certify(subject, fixture.quorum());
    defer cert.deinit(gpa);
    const encoded = try codec.encode(Certificate, gpa, cert);
    defer gpa.free(encoded);
    try testing.expect(encoded.len <= Scheme.max_certificate_size(4));
    var decoded = try codec.decode_cfg(Certificate, gpa, encoded, 4);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&cert));
}

test "ed25519 certificate max size" {
    // The bound reserves the signature-list prefix at its type's maximum width.
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 128);
    defer fixture.deinit();
    var cert = try fixture.certify(subject, 128);
    defer cert.deinit(gpa);
    const prefix_slack = codec.varint.max_u32_varint_size - codec.encode_size(usize, 128);
    try testing.expectEqual(
        Scheme.max_certificate_size(128),
        codec.encode_size(Certificate, cert) + prefix_slack,
    );
}

test "ed25519 certificate assembly rejects sub-quorum, unknown, and duplicate signers" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    const scheme = &fixture.schemes[0];
    const quorum = fixture.quorum();
    const attestations = try fixture.sign(subject, quorum);
    defer gpa.free(attestations);
    const short = attestations[0 .. quorum - 1];
    const insufficient = scheme.assemble(gpa, short, sequential);
    try testing.expectError(error.InsufficientAttestations, insufficient);

    var unknown = try gpa.dupe(Attestation, attestations);
    defer gpa.free(unknown);
    unknown[0].signer = .init(999);
    try testing.expectError(error.UnknownSigner, scheme.assemble(gpa, unknown, sequential));

    const duplicated = try std.mem.concat(gpa, Attestation, &.{ attestations, attestations[2..] });
    defer gpa.free(duplicated);
    try testing.expectError(error.DuplicateSigner, scheme.assemble(gpa, duplicated, sequential));
}

test "ed25519 certificate verification rejects malformed certificates" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    var cert = try fixture.certify(subject, 3);
    defer cert.deinit(gpa);
    const signers = try signer_list(&cert);
    defer gpa.free(signers);
    try testing.expect(try verify(&fixture.verifier, &rng, subject, &cert));

    // Truncated below quorum, and a signature count that disagrees with the bitmap.
    var sub_quorum = try certificate_from(4, signers[0..2], cert.signatures[0..2]);
    defer sub_quorum.deinit(gpa);
    try testing.expect(!try verify(&fixture.verifier, &rng, subject, &sub_quorum));
    var mismatched = try certificate_from(4, signers, cert.signatures[0..2]);
    defer mismatched.deinit(gpa);
    try testing.expect(!try verify(&fixture.verifier, &rng, subject, &mismatched));

    // A bitmap wider than the committee, with and without an unknown signer.
    var wider = try certificate_from(5, signers, cert.signatures);
    defer wider.deinit(gpa);
    try testing.expect(!try verify(&fixture.verifier, &rng, subject, &wider));
    const extended_signers = try std.mem.concat(gpa, Participant, &.{ signers, &.{.init(4)} });
    defer gpa.free(extended_signers);
    const extended_signatures = try std.mem.concat(
        gpa,
        Deferred,
        &.{ cert.signatures, cert.signatures[0..1] },
    );
    defer gpa.free(extended_signatures);
    var unknown = try certificate_from(5, extended_signers, extended_signatures);
    defer unknown.deinit(gpa);
    try testing.expect(!try verify(&fixture.verifier, &rng, subject, &unknown));
}

test "ed25519 certificate batch verification" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    const subjects = [_]TestSubject{
        .{ .bytes = "msg1" },
        .{ .bytes = "msg2" },
        .{ .bytes = "msg3" },
    };
    var certs: [3]Certificate = undefined;
    for (&certs, subjects) |*cert, item| cert.* = try fixture.certify(item, fixture.quorum());
    defer for (&certs) |*cert| cert.deinit(gpa);
    var items: [3]Scheme.Item = undefined;
    for (&items, subjects, &certs) |*item, value, *cert| {
        item.* = .{ .subject = value, .certificate = cert };
    }

    // Verifying several certificates consumes the same randomness as verifying one.
    var actual_rng = TestRng.init(0);
    var expected_rng = TestRng.init(0);
    try testing.expect(try verify(&fixture.verifier, &expected_rng, subjects[0], &certs[0]));
    try testing.expect(
        try fixture.verifier.verify_certificates(gpa, &actual_rng, &items, sequential),
    );
    try testing.expectEqual(expected_rng.next_u64(), actual_rng.next_u64());

    // One corrupted certificate fails the batch.
    certs[1].signatures[0] = certs[1].signatures[1];
    try testing.expect(!try fixture.verifier.verify_certificates(gpa, &rng, &items, sequential));
}

test "ed25519 certificate decode validation" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    var cert = try fixture.certify(subject, 3);
    defer cert.deinit(gpa);
    try expect_decode(&cert, true);

    // No signers, a signature count that disagrees with the bitmap, and more signers than
    // the participant set are rejected.
    var empty = try certificate_from(4, &.{}, &.{});
    defer empty.deinit(gpa);
    try expect_decode(&empty, false);
    var mismatched = try certificate_from(4, &.{ .init(0), .init(1) }, cert.signatures[0..1]);
    defer mismatched.deinit(gpa);
    try expect_decode(&mismatched, false);
    const signers = try signer_list(&cert);
    defer gpa.free(signers);
    const extended_signers = try std.mem.concat(gpa, Participant, &.{ signers, &.{.init(4)} });
    defer gpa.free(extended_signers);
    const extended_signatures = try std.mem.concat(
        gpa,
        Deferred,
        &.{ cert.signatures, cert.signatures[0..1] },
    );
    defer gpa.free(extended_signatures);
    var extended = try certificate_from(5, extended_signers, extended_signatures);
    defer extended.deinit(gpa);
    try expect_decode(&extended, false);
}

fn expect_decode(cert: *const Certificate, valid: bool) !void {
    const encoded = try codec.encode(Certificate, gpa, cert.*);
    defer gpa.free(encoded);
    if (codec.decode_cfg(Certificate, gpa, encoded, 4)) |value| {
        var decoded = value;
        defer decoded.deinit(gpa);
        try testing.expect(valid);
        try testing.expect(decoded.eql(cert));
    } else |_| {
        try testing.expect(!valid);
    }
}
