//! Tests for the BLS12-381 multisig certificate scheme (commonware
//! `bls12381/certificate/multisig/mod.rs` tests).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const parallel = @import("parallel");
const base = @import("../../certificate.zig");
const ed25519 = @import("../../ed25519.zig");
const primitives = @import("../primitives/root.zig");
const multisig = @import("multisig.zig");

const Participant = utils.Participant;
const N3f1 = utils.N3f1;
const Private = primitives.group.Private;
const Scalar = primitives.group.Scalar;
const MinPk = primitives.MinPk;
const MinSig = primitives.MinSig;
const Signers = base.Signers;
const sequential = parallel.sequential;
const gpa = testing.allocator;

const namespace = "test-bls12381-multisig";
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

fn Scheme(comptime V: type) type {
    return multisig.Scheme(TestSubject, N3f1, ed25519.PublicKey, V);
}

const subject: TestSubject = .{ .bytes = message };

fn Fixture(comptime V: type) type {
    return struct {
        const Self = @This();
        schemes: []Scheme(V),
        verifier: Scheme(V),
        participants: Scheme(V).Participants,
        consensus_keys: []Private,

        /// `setup_keys` and `setup_signers`: `n` identity keys, then `n` BLS keys, with
        /// signers in BLS key order.
        fn init(rng: anytype, n: u32) !Self {
            const pairs = try gpa.alloc(Scheme(V).Participants.Pair, n);
            defer gpa.free(pairs);
            for (pairs) |*pair| pair[0] = ed25519.PrivateKey.random(rng).public_key();
            const consensus_keys = try gpa.alloc(Private, n);
            for (consensus_keys, pairs) |*key, *pair| {
                key.* = Private.random(rng);
                pair[1] = primitives.ops.compute_public(V, key.*);
            }
            var participants = try Scheme(V).Participants.init(gpa, pairs);
            const schemes = try gpa.alloc(Scheme(V), n);
            for (consensus_keys, schemes) |key, *scheme| {
                const map = try multisig.clone_participants(gpa, &participants);
                scheme.* = (try Scheme(V).signer(gpa, namespace, map, key)).?;
            }
            const map = try multisig.clone_participants(gpa, &participants);
            return .{
                .schemes = schemes,
                .verifier = try Scheme(V).verifier(gpa, namespace, map),
                .participants = participants,
                .consensus_keys = consensus_keys,
            };
        }

        fn deinit(self: *Self) void {
            for (self.schemes) |*scheme| scheme.deinit(gpa);
            gpa.free(self.schemes);
            self.verifier.deinit(gpa);
            self.participants.deinit(gpa);
            gpa.free(self.consensus_keys);
        }

        /// Attestations over `item` from the first `count` signers.
        fn attest(self: *const Self, item: TestSubject, count: usize) ![]Scheme(V).Attestation {
            const out = try gpa.alloc(Scheme(V).Attestation, count);
            for (out, self.schemes[0..count]) |*attestation, *scheme| {
                attestation.* = (try scheme.sign(gpa, item)).?;
            }
            return out;
        }

        fn quorum(self: *const Self) usize {
            return N3f1.quorum(@as(u32, @intCast(self.schemes.len)));
        }

        fn certificate(self: *const Self, item: TestSubject, count: usize) !Scheme(V).Certificate {
            const attestations = try self.attest(item, count);
            defer gpa.free(attestations);
            return self.schemes[0].assemble(gpa, attestations, sequential);
        }
    };
}

test "multisig: attributable and batchable" {
    inline for (.{ MinPk, MinSig }) |V| {
        try testing.expect(Scheme(V).is_attributable());
        try testing.expect(Scheme(V).is_batchable());
    }
}

test "multisig: sign and verify an attestation; a verifier cannot sign" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const attestation = (try fixture.schemes[0].sign(gpa, subject)).?;
        try testing.expect(try fixture.schemes[0].verify_attestation(
            gpa,
            &rng,
            subject,
            &attestation,
            sequential,
        ));
        try testing.expect(try fixture.verifier.sign(gpa, subject) == null);
        try testing.expect(fixture.verifier.me() == null);

        // A clone keeps its signing key.
        var clone = try fixture.schemes[0].clone(gpa);
        defer clone.deinit(gpa);
        try testing.expect(try clone.sign(gpa, subject) != null);
    }
}

test "multisig: a member reports membership without signing" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const outsider = ed25519.PrivateKey.random(&rng).public_key();
        const map = try multisig.clone_participants(gpa, &fixture.participants);
        try testing.expect(try Scheme(V).member(gpa, namespace, map, outsider) == null);

        const index = Participant.init(2);
        const key = fixture.participants.keys().key(index).?.*;
        const member_map = try multisig.clone_participants(gpa, &fixture.participants);
        var member = (try Scheme(V).member(gpa, namespace, member_map, key)).?;
        defer member.deinit(gpa);
        try testing.expect(member.me().?.eql(.{ .member = index }));
        try testing.expect(member.me().?.signer_index() == null);
        try testing.expect(try member.sign(gpa, subject) == null);
        for (fixture.schemes) |*scheme| {
            const signer = scheme.me().?.signer_index().?;
            const attestation = (try scheme.sign(gpa, subject)).?;
            try testing.expectEqual(signer.get(), attestation.signer.get());
        }
        var cert = try fixture.certificate(subject, fixture.quorum());
        defer cert.deinit(gpa);
        try testing.expect(try member.verify_certificate(gpa, &rng, subject, &cert, sequential));
    }
}

test "multisig: verify attestations filters invalid ones" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 5);
        defer fixture.deinit();
        const quorum = fixture.quorum();
        const attestations = try fixture.attest(subject, quorum);
        defer gpa.free(attestations);
        const scheme = &fixture.schemes[0];

        var all = try scheme.verify_attestations(gpa, &rng, subject, attestations, sequential);
        defer all.deinit(gpa);
        try testing.expectEqual(@as(usize, 0), all.invalid.len);
        try testing.expectEqual(quorum, all.verified.len);

        const unknown = try gpa.dupe(Scheme(V).Attestation, attestations);
        defer gpa.free(unknown);
        unknown[0].signer = .init(999);
        var result = try scheme.verify_attestations(gpa, &rng, subject, unknown, sequential);
        defer result.deinit(gpa);
        try testing.expectEqual(@as(usize, 1), result.invalid.len);
        try testing.expectEqual(@as(u32, 999), result.invalid[0].get());
        try testing.expectEqual(quorum - 1, result.verified.len);

        const swapped = try gpa.dupe(Scheme(V).Attestation, attestations);
        defer gpa.free(swapped);
        swapped[0].signature = swapped[1].signature;
        var bad = try scheme.verify_attestations(gpa, &rng, subject, swapped, sequential);
        defer bad.deinit(gpa);
        try testing.expectEqual(@as(usize, 1), bad.invalid.len);
        try testing.expectEqual(quorum - 1, bad.verified.len);
    }
}

test "multisig: assemble and verify a certificate" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        var cert = try fixture.certificate(subject, fixture.quorum());
        defer cert.deinit(gpa);
        try testing.expectEqual(fixture.quorum(), cert.signers.count());
        const verifier = &fixture.verifier;
        try testing.expect(try verifier.verify_certificate(gpa, &rng, subject, &cert, sequential));

        // An identity aggregate signature fails.
        var corrupted = try cert.clone(gpa);
        defer corrupted.deinit(gpa);
        corrupted.signature = .init(.zero);
        try testing.expect(!try verifier.verify_certificate(
            gpa,
            &rng,
            subject,
            &corrupted,
            sequential,
        ));
    }
}

test "multisig: assemble sorts signers" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        var indices: [3]u32 = undefined;
        for (&indices, fixture.schemes[0..3]) |*index, *scheme| {
            index.* = scheme.me().?.index().get();
        }
        std.mem.sort(u32, &indices, {}, std.sort.asc(u32));
        var attestations: [3]Scheme(V).Attestation = undefined;
        for (&attestations, 0..) |*attestation, i| {
            const wanted = indices[2 - i];
            for (fixture.schemes) |*scheme| {
                if (scheme.me().?.index().get() == wanted) {
                    attestation.* = (try scheme.sign(gpa, subject)).?;
                }
            }
        }
        var cert = try fixture.schemes[0].assemble(gpa, &attestations, sequential);
        defer cert.deinit(gpa);
        var signers = cert.signers.iter();
        for (indices) |expected| try testing.expectEqual(expected, signers.next().?.get());
        try testing.expect(signers.next() == null);
    }
}

test "multisig: certificate codec round trip and decode validation" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const C = Scheme(V).Certificate;
        var cert = try fixture.certificate(subject, 3);
        defer cert.deinit(gpa);
        const encoded = try codec.encode(C, gpa, cert);
        defer gpa.free(encoded);
        try testing.expectEqual(Scheme(V).max_certificate_size(4), encoded.len);
        var decoded = try codec.decode_cfg(C, gpa, encoded, 4);
        defer decoded.deinit(gpa);
        try testing.expect(decoded.eql(&cert));

        var empty: C = .{ .signers = try Signers.init(gpa, 4, &.{}), .signature = cert.signature };
        defer empty.deinit(gpa);
        const empty_bytes = try codec.encode(C, gpa, empty);
        defer gpa.free(empty_bytes);
        try testing.expectError(error.Invalid, codec.decode_cfg(C, gpa, empty_bytes, 4));

        var extended = try with_extra_signer(V, &cert, 4);
        defer extended.deinit(gpa);
        const extended_bytes = try codec.encode(C, gpa, extended);
        defer gpa.free(extended_bytes);
        try testing.expect(std.meta.isError(codec.decode_cfg(C, gpa, extended_bytes, 4)));
    }
}

/// A copy of `cert` whose bitmap covers `participants + 1` and adds the last index.
fn with_extra_signer(
    comptime V: type,
    cert: *const Scheme(V).Certificate,
    participants: u32,
) !Scheme(V).Certificate {
    var indices: [16]Participant = undefined;
    var count: usize = 0;
    var signers = cert.signers.iter();
    while (signers.next()) |index| : (count += 1) indices[count] = index;
    indices[count] = .init(participants);
    count += 1;
    const extended = try Signers.init(gpa, participants + 1, indices[0..count]);
    return .{ .signers = extended, .signature = cert.signature };
}

test "multisig: assemble rejects sub-quorum, unknown, malformed, and duplicate signers" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const scheme = &fixture.schemes[0];
        const quorum = fixture.quorum();
        const attestations = try fixture.attest(subject, quorum);
        defer gpa.free(attestations);
        try testing.expectError(
            error.InsufficientAttestations,
            scheme.assemble(gpa, attestations[0 .. quorum - 1], sequential),
        );

        const unknown = try gpa.dupe(Scheme(V).Attestation, attestations);
        defer gpa.free(unknown);
        unknown[0].signer = .init(999);
        try testing.expectError(error.UnknownSigner, scheme.assemble(gpa, unknown, sequential));

        const malformed = try gpa.dupe(Scheme(V).Attestation, attestations);
        defer gpa.free(malformed);
        @memset(&malformed[0].signature.bytes, 0xff);
        try testing.expectError(
            error.MalformedSignature,
            scheme.assemble(gpa, malformed, sequential),
        );

        var duplicate: [4]Scheme(V).Attestation = undefined;
        @memcpy(duplicate[0..3], attestations[0..3]);
        duplicate[3] = attestations[2];
        try testing.expectError(
            error.DuplicateSigner,
            scheme.assemble(gpa, &duplicate, sequential),
        );
    }
}

test "multisig: verify rejects sub-quorum, resized, and unknown-signer certificates" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const verifier = &fixture.verifier;
        var cert = try fixture.certificate(subject, 3);
        defer cert.deinit(gpa);

        var indices: [3]Participant = undefined;
        var signers = cert.signers.iter();
        for (&indices) |*index| index.* = signers.next().?;
        var truncated: Scheme(V).Certificate = .{
            .signers = try Signers.init(gpa, 4, indices[0..2]),
            .signature = cert.signature,
        };
        defer truncated.deinit(gpa);
        try testing.expect(!try verifier.verify_certificate(
            gpa,
            &rng,
            subject,
            &truncated,
            sequential,
        ));

        var resized: Scheme(V).Certificate = .{
            .signers = try Signers.init(gpa, 5, &indices),
            .signature = cert.signature,
        };
        defer resized.deinit(gpa);
        try testing.expect(!try verifier.verify_certificate(
            gpa,
            &rng,
            subject,
            &resized,
            sequential,
        ));

        var unknown = try with_extra_signer(V, &cert, 4);
        defer unknown.deinit(gpa);
        try testing.expect(!try verifier.verify_certificate(
            gpa,
            &rng,
            subject,
            &unknown,
            sequential,
        ));
    }
}

test "multisig: verify certificates in a batch and detect a failure" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const subjects = [_]TestSubject{
            .{ .bytes = "msg1" },
            .{ .bytes = "msg2" },
            .{ .bytes = "msg3" },
        };
        var certs: [3]Scheme(V).Certificate = undefined;
        var built: usize = 0;
        defer for (certs[0..built]) |*cert| cert.deinit(gpa);
        var items: [3]Scheme(V).Item = undefined;
        for (&certs, &items, subjects) |*cert, *item, s| {
            cert.* = try fixture.certificate(s, fixture.quorum());
            built += 1;
            item.* = .{ .subject = s, .certificate = cert };
        }
        const verifier = &fixture.verifier;
        try testing.expect(try verifier.verify_certificates(gpa, &rng, &items, sequential));
        certs[1].signature = .init(.zero);
        try testing.expect(!try verifier.verify_certificates(gpa, &rng, items[0..2], sequential));
    }
}

test "multisig: verify attestations rejects malleability" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const scheme = &fixture.schemes[0];
        const valid = try fixture.attest(subject, 2);
        defer gpa.free(valid);
        var verification = try scheme.verify_attestations(gpa, &rng, subject, valid, sequential);
        defer verification.deinit(gpa);
        try testing.expectEqual(@as(usize, 0), verification.invalid.len);
        try testing.expectEqual(@as(usize, 2), verification.verified.len);

        const delta = V.Signature.generator.mul(Scalar.random(&rng));
        const first = valid[0].signature.get().?;
        const second = valid[1].signature.get().?;
        const forged = [_]Scheme(V).Attestation{
            .init(valid[0].signer, first.sub(delta)),
            .init(valid[1].signer, second.add(delta)),
        };
        const forged_sum = forged[0].signature.get().?.add(forged[1].signature.get().?);
        try testing.expect(forged_sum.eql(first.add(second)));
        var result = try scheme.verify_attestations(gpa, &rng, subject, &forged, sequential);
        defer result.deinit(gpa);
        try testing.expect(result.invalid.len > 0);
    }
}

test "multisig: optimistic assembly" {
    var rng = utils.test_rng();
    var fixture = try Fixture(MinSig).init(&rng, 4);
    defer fixture.deinit();
    const attestations = try fixture.attest(subject, 4);
    defer gpa.free(attestations);
    const scheme = &fixture.schemes[0];
    var good = try scheme.optimistic_assemble(gpa, &rng, subject, attestations, &.{}, sequential);
    defer good.deinit(gpa);
    try testing.expect(good == .certificate);

    attestations[1].signature = attestations[2].signature;
    var bad = try scheme.optimistic_assemble(gpa, &rng, subject, attestations, &.{}, sequential);
    defer bad.deinit(gpa);
    try testing.expect(bad == .verification);
    try testing.expectEqual(@as(usize, 1), bad.verification.invalid.len);
}

test "multisig: mocks fixture" {
    var rng = utils.test_rng();
    const S = Scheme(MinSig);
    var fixture = try multisig.fixture(S, gpa, &rng, namespace, 4);
    defer fixture.deinit(gpa);
    var attestations: [3]S.Attestation = undefined;
    for (&attestations, fixture.schemes[0..3]) |*a, *s| a.* = (try s.sign(gpa, subject)).?;
    var cert = try fixture.schemes[3].assemble(gpa, &attestations, sequential);
    defer cert.deinit(gpa);
    const verifier = &fixture.verifier;
    try testing.expect(try verifier.verify_certificate(gpa, &rng, subject, &cert, sequential));
    for (fixture.participants, fixture.schemes) |key, *s| {
        try testing.expect(s.participants().items[s.me().?.index().get()].eql(key));
    }
}
