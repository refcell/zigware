//! Tests for the secp256r1 certificate scheme (commonware `secp256r1/certificate/mod.rs`).
//! As in commonware, most tests use secp256r1 keys as both identity and signing keys.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const parallel = @import("parallel");
const base = @import("../certificate.zig");
const ed25519 = @import("../ed25519.zig");
const secp256r1 = @import("../secp256r1.zig");

const Participant = utils.Participant;
const N3f1 = utils.N3f1;
const PrivateKey = secp256r1.standard.PrivateKey;
const PublicKey = secp256r1.standard.PublicKey;
const Certificate = secp256r1.certificate.Certificate;
const Signers = base.Signers;
const Deferred = base.Deferred(secp256r1.standard.Signature);
const sequential = parallel.sequential;
const gpa = testing.allocator;

const namespace = "test-secp256r1";
const message = "test message";

/// commonware's `TestSubject`, counting message preparation when `calls` is set (the
/// `CountingSubject` of `test_optimistic_assemble_verifies_pending_once`).
const TestSubject = struct {
    pub const Namespace = base.BytesNamespace;

    bytes: []const u8,
    calls: ?*usize = null,

    pub fn namespace(_: TestSubject, derived: *const Namespace) []const u8 {
        return derived.bytes;
    }

    pub fn message(self: TestSubject, allocator: Allocator) Allocator.Error![]u8 {
        if (self.calls) |calls| calls.* += 1;
        return allocator.dupe(u8, self.bytes);
    }
};

const Scheme = secp256r1.certificate.Scheme(TestSubject, N3f1, PublicKey);
const Attestation = Scheme.Attestation;
const subject: TestSubject = .{ .bytes = message };
const other: TestSubject = .{ .bytes = "other subject" };

/// `setup_keys`: `n` signing keys, each its own identity.
fn setup_keys(rng: anytype, keys: []PrivateKey) !Scheme.Participants {
    const pairs = try gpa.alloc(Scheme.Participants.Pair, keys.len);
    defer gpa.free(pairs);
    for (keys, pairs) |*key, *pair| {
        key.* = PrivateKey.random(rng);
        pair.* = .{ key.public_key(), key.public_key() };
    }
    return Scheme.Participants.init(gpa, pairs);
}

fn clone(set: *const Scheme.Participants) !Scheme.Participants {
    const pairs = try gpa.alloc(Scheme.Participants.Pair, set.len());
    defer gpa.free(pairs);
    for (pairs, set.keys().as_slice(), set.values()) |*pair, key, value| pair.* = .{ key, value };
    return Scheme.Participants.init(gpa, pairs);
}

const Fixture = struct {
    schemes: []Scheme,
    verifier: Scheme,

    /// `setup_signers`: `n` signers in key-generation order and a verifier.
    fn init(rng: anytype, n: u32) !Fixture {
        const keys = try gpa.alloc(PrivateKey, n);
        defer gpa.free(keys);
        var participants = try setup_keys(rng, keys);
        defer participants.deinit(gpa);
        const schemes = try gpa.alloc(Scheme, n);
        for (keys, schemes) |key, *scheme| {
            scheme.* = (try Scheme.signer(gpa, namespace, try clone(&participants), key)).?;
        }
        const verifier = try Scheme.verifier(gpa, namespace, try clone(&participants));
        return .{ .schemes = schemes, .verifier = verifier };
    }

    fn deinit(self: *Fixture) void {
        for (self.schemes) |*scheme| scheme.deinit(gpa);
        gpa.free(self.schemes);
        self.verifier.deinit(gpa);
    }

    fn sign(self: *const Fixture, item: TestSubject, count: usize) ![]Attestation {
        const attestations = try gpa.alloc(Attestation, count);
        for (self.schemes[0..count], attestations) |*scheme, *attestation| {
            attestation.* = (try scheme.sign(gpa, item)).?;
        }
        return attestations;
    }

    fn certify(self: *const Fixture, item: TestSubject, count: usize) !Certificate {
        const attestations = try self.sign(item, count);
        defer gpa.free(attestations);
        return self.schemes[0].assemble(gpa, attestations, sequential);
    }

    fn quorum(self: *const Fixture) u32 {
        return N3f1.quorum(self.schemes.len);
    }
};

fn certificate_from(
    participants: u32,
    signers: []const Participant,
    signatures: []const Deferred,
) !Certificate {
    var bitmap = try Signers.init(gpa, participants, signers);
    errdefer bitmap.deinit(gpa);
    return .{ .signers = bitmap, .signatures = try gpa.dupe(Deferred, signatures) };
}

fn signer_list(cert: *const Certificate) ![]Participant {
    var list: std.ArrayList(Participant) = .empty;
    var iter = cert.signers.iter();
    while (iter.next()) |signer| try list.append(gpa, signer);
    return list.toOwnedSlice(gpa);
}

fn verify(scheme: *const Scheme, item: TestSubject, cert: *const Certificate) !bool {
    var rng = utils.rng.test_rng();
    return scheme.verify_certificate(gpa, &rng, item, cert, sequential);
}

/// A signature that does not decode (commonware's truncated `Lazy`).
const malformed: Deferred = .{ .bytes = @splat(0) };

test "secp256r1 certificate is attributable and not batchable" {
    try testing.expect(Scheme.is_attributable());
    try testing.expect(!Scheme.is_batchable());
    try testing.expectEqual(null, malformed.get());
}

test "secp256r1 certificate member reports membership without signing" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    const participants = &fixture.verifier.committee;

    // A key outside the committee yields no member.
    const outsider = PrivateKey.random(&rng).public_key();
    try testing.expectEqual(
        null,
        try Scheme.member(gpa, namespace, try clone(participants), outsider),
    );

    const index = Participant.init(2);
    const key = participants.keys().key(index).?.*;
    var member = (try Scheme.member(gpa, namespace, try clone(participants), key)).?;
    defer member.deinit(gpa);
    try testing.expect(member.me().?.eql(.{ .member = index }));
    try testing.expectEqual(null, member.me().?.signer_index());
    try testing.expectEqual(null, try member.sign(gpa, subject));
    try testing.expectEqual(null, fixture.verifier.me());
    for (fixture.schemes) |*scheme| {
        const signer = scheme.me().?.signer_index().?;
        try testing.expectEqual(signer, (try scheme.sign(gpa, subject)).?.signer);
    }

    // A member verifies a certificate assembled by a quorum of signers.
    var cert = try fixture.certify(subject, fixture.quorum());
    defer cert.deinit(gpa);
    try testing.expect(try verify(&member, subject, &cert));
}

test "secp256r1 certificate member uses identity keys" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();

    // A committee whose signing keys differ from its identity keys.
    const identities = fixture.verifier.participants().as_slice();
    var signing_keys: [4]PublicKey = undefined;
    var pairs: [4]Scheme.Participants.Pair = undefined;
    for (&signing_keys, &pairs, identities) |*key, *pair, identity| {
        key.* = PrivateKey.random(&rng).public_key();
        pair.* = .{ identity, key.* };
    }
    var participants = try Scheme.Participants.init(gpa, &pairs);
    defer participants.deinit(gpa);

    // Each identity key yields a member at its position; no signing key yields a member.
    for (identities, 0..) |identity, position| {
        var member = (try Scheme.member(gpa, namespace, try clone(&participants), identity)).?;
        defer member.deinit(gpa);
        try testing.expect(member.me().?.eql(.{ .member = .from_usize(position) }));
    }
    for (signing_keys) |key| {
        const set = try clone(&participants);
        try testing.expectEqual(null, try Scheme.member(gpa, namespace, set, key));
    }
}

test "secp256r1 certificate optimistic assemble verifies pending once" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 5);
    defer fixture.deinit();
    std.mem.sort(Scheme, fixture.schemes, {}, struct {
        fn less(_: void, a: Scheme, b: Scheme) bool {
            return a.me().?.index().get() < b.me().?.index().get();
        }
    }.less);
    const quorum = fixture.quorum();
    const verifier = &fixture.verifier;
    var calls: usize = 0;
    const counting: TestSubject = .{ .bytes = message, .calls = &calls };

    // Retained votes passed verification for this configuration and subject before the
    // final candidate arrives.
    const signed = try fixture.sign(subject, quorum);
    defer gpa.free(signed);
    const retained = signed[0 .. quorum - 1];
    var prior = try verifier.verify_attestations(gpa, &rng, counting, retained, sequential);
    defer prior.deinit(gpa);
    try testing.expectEqual(0, prior.invalid.len);
    try testing.expectEqual(quorum - 1, prior.verified.len);

    // A rejected candidate verifies the new vote once and returns its signer without
    // repeating certificate verification over retained votes.
    const rejected = (try fixture.schemes[fixture.schemes.len - 1].sign(gpa, other)).?;
    calls = 0;
    var result = try verifier.optimistic_assemble(
        gpa,
        &rng,
        counting,
        &.{rejected},
        prior.verified,
        sequential,
    );
    defer result.deinit(gpa);
    try testing.expectEqual(0, result.verification.verified.len);
    try testing.expectEqualSlices(Participant, &.{rejected.signer}, result.verification.invalid);
    try testing.expectEqual(1, calls);

    // A fresh valid replacement completes the same retained quorum.
    const replacement = signed[quorum - 1];
    var certified = try verifier.optimistic_assemble(
        gpa,
        &rng,
        counting,
        &.{replacement},
        prior.verified,
        sequential,
    );
    defer certified.deinit(gpa);
    try testing.expect(try verify(verifier, subject, &certified.certificate));

    // A verified quorum assembles without preparing the subject again.
    calls = 0;
    var assembled = try verifier.optimistic_assemble(gpa, &rng, counting, &.{}, signed, sequential);
    defer assembled.deinit(gpa);
    try testing.expectEqual(0, calls);
    try testing.expect(try verify(verifier, subject, &assembled.certificate));
    try testing.expect(!try verify(verifier, other, &assembled.certificate));
}

test "secp256r1 certificate sign, verify, and filter attestations" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 5);
    defer fixture.deinit();
    const scheme = &fixture.schemes[0];
    const quorum = fixture.quorum();
    const attestations = try fixture.sign(subject, quorum);
    defer gpa.free(attestations);
    const first = &attestations[0];
    try testing.expect(try scheme.verify_attestation(gpa, &rng, subject, first, sequential));
    try testing.expect(!try scheme.verify_attestation(gpa, &rng, other, first, sequential));
    try testing.expectEqual(null, try fixture.verifier.sign(gpa, subject));

    var result = try scheme.verify_attestations(gpa, &rng, subject, attestations, sequential);
    try testing.expectEqual(0, result.invalid.len);
    try testing.expectEqual(quorum, result.verified.len);
    result.deinit(gpa);

    // An unknown signer, a copied signature, and a malformed signature each invalidate
    // exactly their own attestation.
    const corrupted = try gpa.dupe(Attestation, attestations);
    defer gpa.free(corrupted);
    corrupted[0].signer = .init(999);
    corrupted[1].signature = corrupted[2].signature;
    corrupted[3].signature = malformed;
    result = try scheme.verify_attestations(gpa, &rng, subject, corrupted, sequential);
    defer result.deinit(gpa);
    const expected = [_]Participant{ attestations[1].signer, attestations[3].signer, .init(999) };
    var sorted = expected;
    std.mem.sort(Participant, &sorted, {}, struct {
        fn less(_: void, a: Participant, b: Participant) bool {
            return a.get() < b.get();
        }
    }.less);
    try testing.expectEqualSlices(Participant, &sorted, result.invalid);
    try testing.expectEqual(quorum - 3, result.verified.len);
}

test "secp256r1 certificate assemble, sort, verify, and detect corruption" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    const attestations = try fixture.sign(subject, 3);
    defer gpa.free(attestations);
    std.mem.reverse(Attestation, attestations);
    var cert = try fixture.schemes[0].assemble(gpa, attestations, sequential);
    defer cert.deinit(gpa);
    try testing.expectEqual(3, cert.signers.count());
    const signers = try signer_list(&cert);
    defer gpa.free(signers);
    for (signers[1..], signers[0 .. signers.len - 1]) |later, earlier| {
        try testing.expect(earlier.get() < later.get());
    }
    try testing.expect(try verify(&fixture.verifier, subject, &cert));
    try testing.expect(!try verify(&fixture.verifier, other, &cert));
    cert.signatures[0] = cert.signatures[1];
    try testing.expect(!try verify(&fixture.verifier, subject, &cert));
    cert.signatures[0] = malformed;
    try testing.expect(!try verify(&fixture.verifier, subject, &cert));
}

test "secp256r1 certificate codec round trip and max size" {
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

    // The bound reserves the signature-list prefix at its type's maximum width.
    var large = try Fixture.init(&rng, 128);
    defer large.deinit();
    var full = try large.certify(subject, 128);
    defer full.deinit(gpa);
    const prefix_slack = codec.varint.max_u32_varint_size - codec.encode_size(usize, 128);
    try testing.expectEqual(
        Scheme.max_certificate_size(128),
        codec.encode_size(Certificate, full) + prefix_slack,
    );
}

test "secp256r1 certificate assembly rejects invalid attestations" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    const scheme = &fixture.schemes[0];
    const quorum = fixture.quorum();
    const attestations = try fixture.sign(subject, quorum);
    defer gpa.free(attestations);
    const short = scheme.assemble(gpa, attestations[0 .. quorum - 1], sequential);
    try testing.expectError(error.InsufficientAttestations, short);

    const corrupted = try gpa.dupe(Attestation, attestations);
    defer gpa.free(corrupted);
    corrupted[0].signer = .init(999);
    try testing.expectError(error.UnknownSigner, scheme.assemble(gpa, corrupted, sequential));
    @memcpy(corrupted, attestations);
    corrupted[0].signature = malformed;
    try testing.expectError(error.MalformedSignature, scheme.assemble(gpa, corrupted, sequential));

    const duplicated = try std.mem.concat(gpa, Attestation, &.{ attestations, attestations[2..] });
    defer gpa.free(duplicated);
    try testing.expectError(error.DuplicateSigner, scheme.assemble(gpa, duplicated, sequential));
}

test "secp256r1 certificate verification rejects malformed certificates" {
    var rng = utils.rng.test_rng();
    var fixture = try Fixture.init(&rng, 4);
    defer fixture.deinit();
    var cert = try fixture.certify(subject, 3);
    defer cert.deinit(gpa);
    const signers = try signer_list(&cert);
    defer gpa.free(signers);
    const verifier = &fixture.verifier;

    var sub_quorum = try certificate_from(4, signers[0..2], cert.signatures[0..2]);
    defer sub_quorum.deinit(gpa);
    try testing.expect(!try verify(verifier, subject, &sub_quorum));
    var mismatched = try certificate_from(4, signers, cert.signatures[0..2]);
    defer mismatched.deinit(gpa);
    try testing.expect(!try verify(verifier, subject, &mismatched));
    var wider = try certificate_from(5, signers, cert.signatures);
    defer wider.deinit(gpa);
    try testing.expect(!try verify(verifier, subject, &wider));
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
    try testing.expect(!try verify(verifier, subject, &unknown));

    // Decoding rejects no signers, mismatched counts, and too many signers.
    var empty = try certificate_from(4, &.{}, &.{});
    defer empty.deinit(gpa);
    for ([_]*const Certificate{ &empty, &mismatched, &unknown }) |invalid| {
        const encoded = try codec.encode(Certificate, gpa, invalid.*);
        defer gpa.free(encoded);
        try testing.expect(std.meta.isError(codec.decode_cfg(Certificate, gpa, encoded, 4)));
    }
}

test "secp256r1 certificate verifies certificates one by one" {
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
    const verifier = &fixture.verifier;
    try testing.expect(try verifier.verify_certificates(gpa, &rng, &items, sequential));
    certs[1].signatures[0] = certs[1].signatures[1];
    try testing.expect(!try verifier.verify_certificates(gpa, &rng, &items, sequential));
}

test "secp256r1 certificate fixture over ed25519 identities" {
    var rng = utils.rng.test_rng();
    const Ed25519Identified = secp256r1.certificate.Scheme(TestSubject, N3f1, ed25519.PublicKey);
    var fixture = try secp256r1.certificate.fixture(Ed25519Identified, gpa, &rng, namespace, 4);
    defer fixture.deinit(gpa);
    for (fixture.schemes, fixture.participants, 0..) |*scheme, identity, position| {
        try testing.expectEqual(position, scheme.me().?.index().get());
        try testing.expect(scheme.participants().key(.from_usize(position)).?.eql(identity));
    }
    const attestations = try gpa.alloc(Ed25519Identified.Attestation, 3);
    defer gpa.free(attestations);
    for (fixture.schemes[0..3], attestations) |*scheme, *attestation| {
        attestation.* = (try scheme.sign(gpa, subject)).?;
    }
    var cert = try fixture.verifier.assemble(gpa, attestations, sequential);
    defer cert.deinit(gpa);
    const verifier = &fixture.verifier;
    try testing.expect(try verifier.verify_certificate(gpa, &rng, subject, &cert, sequential));
}
