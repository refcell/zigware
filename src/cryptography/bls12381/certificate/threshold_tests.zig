//! Tests for the BLS12-381 threshold certificate scheme (commonware
//! `bls12381/certificate/threshold/mod.rs` tests).
//!
//! commonware's `#[should_panic]` cases (a certificate verifier verifying an attestation, a
//! share index outside the sharing, and a sharing that does not fit the participant set) are
//! death tests (`utils.death.expect_panic`), one per variant.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const parallel = @import("parallel");
const base = @import("../../certificate.zig");
const ed25519 = @import("../../ed25519.zig");
const primitives = @import("../primitives/root.zig");
const dkg = @import("../dkg/root.zig").feldman_desmedt;
const threshold = @import("threshold.zig");

const Participant = utils.Participant;
const N3f1 = utils.N3f1;
const N5f1 = utils.N5f1;
const death = utils.death;
const MinPk = primitives.MinPk;
const MinSig = primitives.MinSig;
const sequential = parallel.sequential;
const gpa = testing.allocator;

const namespace = "test-bls12381-threshold";
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
    return threshold.Scheme(TestSubject, N3f1, ed25519.PublicKey, V);
}

const subject: TestSubject = .{ .bytes = message };

fn Fixture(comptime V: type) type {
    return struct {
        const Self = @This();
        schemes: []Scheme(V),
        verifier: Scheme(V),
        participants: Scheme(V).Participants,
        polynomial: primitives.Sharing(V),

        /// `setup_signers`: `n` identity keys, then a trusted dealing over `n` players.
        fn init(rng: anytype, n: u32) !Self {
            const keys = try gpa.alloc(ed25519.PublicKey, n);
            defer gpa.free(keys);
            for (keys) |*key| key.* = ed25519.PrivateKey.random(rng).public_key();
            var participants = try Scheme(V).Participants.init(gpa, keys);
            errdefer participants.deinit(gpa);
            var dealing = try dkg.deal_anonymous(V, N3f1, gpa, rng, .non_zero_counter, n);
            defer dealing.deinit(gpa);
            const schemes = try gpa.alloc(Scheme(V), n);
            for (dealing.shares, schemes) |share, *scheme| {
                const set = try participants.clone(gpa);
                const polynomial = try dealing.sharing.clone(gpa);
                scheme.* = (try Scheme(V).signer(gpa, namespace, set, polynomial, share)).?;
            }
            const set = try participants.clone(gpa);
            const polynomial = try dealing.sharing.clone(gpa);
            return .{
                .schemes = schemes,
                .verifier = try Scheme(V).verifier(gpa, namespace, set, polynomial),
                .participants = participants,
                .polynomial = try dealing.sharing.clone(gpa),
            };
        }

        fn deinit(self: *Self) void {
            for (self.schemes) |*scheme| scheme.deinit(gpa);
            gpa.free(self.schemes);
            self.verifier.deinit(gpa);
            self.participants.deinit(gpa);
            self.polynomial.deinit(gpa);
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

test "threshold certificate: not attributable, batchable" {
    inline for (.{ MinPk, MinSig }) |V| {
        try testing.expect(!Scheme(V).is_attributable());
        try testing.expect(Scheme(V).is_batchable());
    }
}

test "threshold certificate: sign, verify, and match the share's partial signature" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const scheme = &fixture.schemes[0];
        const attestation = (try scheme.sign(gpa, subject)).?;
        try testing.expect(try scheme.verify_attestation(
            gpa,
            &rng,
            subject,
            &attestation,
            sequential,
        ));
        // A verifier accepts votes but cannot sign.
        try testing.expect(try fixture.verifier.verify_attestation(
            gpa,
            &rng,
            subject,
            &attestation,
            sequential,
        ));
        try testing.expect(try fixture.verifier.sign(gpa, subject) == null);

        const share = scheme.share().?;
        const expected = primitives.ops.threshold.sign_message(V, share, namespace, message);
        try testing.expectEqual(share.index.get(), attestation.signer.get());
        try testing.expect(attestation.signature.get().?.eql(expected.value));

        var clone = try scheme.clone(gpa);
        defer clone.deinit(gpa);
        try testing.expect(try clone.sign(gpa, subject) != null);
    }
}

test "threshold certificate: a member reports membership without signing" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const outsider = ed25519.PrivateKey.random(&rng).public_key();
        const none = try Scheme(V).member(
            gpa,
            namespace,
            try fixture.participants.clone(gpa),
            try fixture.polynomial.clone(gpa),
            outsider,
        );
        try testing.expect(none == null);

        const index = Participant.init(2);
        const key = fixture.participants.key(index).?.*;
        var member = (try Scheme(V).member(
            gpa,
            namespace,
            try fixture.participants.clone(gpa),
            try fixture.polynomial.clone(gpa),
            key,
        )).?;
        defer member.deinit(gpa);
        try testing.expect(member.me().?.eql(.{ .member = index }));
        try testing.expect(member.me().?.signer_index() == null);
        try testing.expect(try member.sign(gpa, subject) == null);
        try testing.expect(fixture.verifier.me() == null);
        var cert_verifier = try Scheme(V).certificate_verifier(
            gpa,
            namespace,
            fixture.polynomial.public(),
        );
        defer cert_verifier.deinit(gpa);
        try testing.expect(cert_verifier.me() == null);
        for (fixture.schemes) |*scheme| {
            const signer = scheme.me().?.signer_index().?;
            const attestation = (try scheme.sign(gpa, subject)).?;
            try testing.expectEqual(signer.get(), attestation.signer.get());
        }
        var cert = try fixture.certificate(subject, fixture.quorum());
        try testing.expect(try member.verify_certificate(gpa, &rng, subject, &cert, sequential));
    }
}

test "threshold certificate: verify attestations filters invalid ones" {
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

test "threshold certificate: assemble, verify, and detect corruption" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const verifier = &fixture.verifier;
        var cert = try fixture.certificate(subject, fixture.quorum());
        try testing.expect(try verifier.verify_certificate(gpa, &rng, subject, &cert, sequential));

        // Every quorum recovers the same signature.
        const shifted = try fixture.attest(subject, 4);
        defer gpa.free(shifted);
        var other = try fixture.schemes[0].assemble(gpa, shifted[1..], sequential);
        try testing.expect(other.eql(&cert));

        var corrupted: Scheme(V).Certificate = .init(.zero);
        try testing.expect(!try verifier.verify_certificate(
            gpa,
            &rng,
            subject,
            &corrupted,
            sequential,
        ));
        const wrong: TestSubject = .{ .bytes = "other message" };
        try testing.expect(!try verifier.verify_certificate(gpa, &rng, wrong, &cert, sequential));
    }
}

test "threshold certificate: codec round trip and length mismatch" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const C = Scheme(V).Certificate;
        const cert = try fixture.certificate(subject, fixture.quorum());
        const encoded = try codec.encode(C, gpa, cert);
        defer gpa.free(encoded);
        try testing.expectEqual(Scheme(V).max_certificate_size(4), encoded.len);
        const decoded = try codec.decode(C, gpa, encoded);
        try testing.expect(decoded.eql(&cert));
        const short = encoded[0 .. encoded.len - 1];
        try testing.expect(std.meta.isError(codec.decode(V.Signature, gpa, short)));
    }
}

test "threshold certificate: assemble rejects sub-quorum, duplicate, unknown, malformed" {
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

        var duplicate: [4]Scheme(V).Attestation = undefined;
        @memcpy(duplicate[0..3], attestations[0..3]);
        duplicate[3] = attestations[2];
        try testing.expectError(
            error.DuplicateSigner,
            scheme.assemble(gpa, &duplicate, sequential),
        );

        const unknown = try gpa.dupe(Scheme(V).Attestation, attestations);
        defer gpa.free(unknown);
        unknown[0].signer = .init(999);
        try testing.expectError(error.UnknownSigner, scheme.assemble(gpa, unknown, sequential));

        const malformed = try gpa.dupe(Scheme(V).Attestation, attestations);
        defer gpa.free(malformed);
        malformed[0].signature = .from_bytes(@splat(0xff));
        try testing.expectError(
            error.MalformedSignature,
            scheme.assemble(gpa, malformed, sequential),
        );
    }
}

test "threshold certificate: verify certificates in a batch and detect a failure" {
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
        var items: [3]Scheme(V).Item = undefined;
        for (&certs, &items, subjects) |*cert, *item, s| {
            cert.* = try fixture.certificate(s, fixture.quorum());
            item.* = .{ .subject = s, .certificate = cert };
        }
        const verifier = &fixture.verifier;
        try testing.expect(try verifier.verify_certificates(gpa, &rng, &items, sequential));
        certs[1] = .init(.zero);
        try testing.expect(!try verifier.verify_certificates(gpa, &rng, items[0..2], sequential));
    }
}

test "threshold certificate: a certificate verifier verifies but cannot sign" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var fixture = try Fixture(V).init(&rng, 4);
        defer fixture.deinit();
        const cert = try fixture.certificate(subject, fixture.quorum());
        var verifier = try Scheme(V).certificate_verifier(
            gpa,
            namespace,
            fixture.polynomial.public(),
        );
        defer verifier.deinit(gpa);
        try testing.expect(verifier.identity().eql(fixture.schemes[0].identity()));
        try testing.expect(try verifier.verify_certificate(gpa, &rng, subject, &cert, sequential));
        try testing.expect(try verifier.sign(gpa, subject) == null);
    }
}

test "threshold certificate: a share that does not match the sharing is rejected" {
    var rng = utils.test_rng();
    var fixture = try Fixture(MinSig).init(&rng, 4);
    defer fixture.deinit();
    var share = fixture.schemes[1].share().?;
    share.private = .random(&rng);
    const result = try Scheme(MinSig).signer(
        gpa,
        namespace,
        try fixture.participants.clone(gpa),
        try fixture.polynomial.clone(gpa),
        share,
    );
    try testing.expect(result == null);
}

test "threshold certificate: optimistic assembly" {
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

test "threshold certificate: mocks fixture" {
    var rng = utils.test_rng();
    const S = Scheme(MinSig);
    var fixture = try threshold.fixture(S, gpa, &rng, namespace, 4);
    defer fixture.deinit(gpa);
    var attestations: [3]S.Attestation = undefined;
    for (&attestations, fixture.schemes[0..3]) |*a, *s| a.* = (try s.sign(gpa, subject)).?;
    var cert = try fixture.schemes[3].assemble(gpa, &attestations, sequential);
    defer cert.deinit(gpa);
    const verifier = &fixture.verifier;
    try testing.expect(try verifier.verify_certificate(gpa, &rng, subject, &cert, sequential));
}

/// The bodies of commonware's `#[should_panic]` tests; each panics at a constructor or
/// verifier precondition.
fn Panics(comptime V: type) type {
    return struct {
        /// commonware `make_participants`.
        fn participants(rng: anytype, n: u32) !Scheme(V).Participants {
            var keys: [8]ed25519.PublicKey = undefined;
            for (keys[0..n]) |*key| key.* = ed25519.PrivateKey.random(rng).public_key();
            return Scheme(V).Participants.init(gpa, keys[0..n]);
        }

        /// commonware `certificate_verifier_panics_on_vote`.
        fn verifier_on_vote() !void {
            var rng = utils.test_rng();
            var fixture = try Fixture(V).init(&rng, 4);
            defer fixture.deinit();
            var verifier = try Scheme(V).certificate_verifier(
                gpa,
                namespace,
                fixture.polynomial.public(),
            );
            defer verifier.deinit(gpa);
            const vote = (try fixture.schemes[1].sign(gpa, subject)).?;
            _ = try verifier.verify_attestation(gpa, &rng, subject, &vote, sequential);
        }

        /// commonware `signer_shares_must_match_participant_indices`.
        fn share_index() !void {
            var rng = utils.test_rng();
            const set = try participants(&rng, 4);
            var dealing = try dkg.deal_anonymous(V, N3f1, gpa, &rng, .non_zero_counter, 4);
            defer dealing.deinit(gpa);
            var share = dealing.shares[0];
            share.index = .init(999);
            const polynomial = try dealing.sharing.clone(gpa);
            var scheme = try Scheme(V).signer(gpa, namespace, set, polynomial, share);
            if (scheme) |*value| value.deinit(gpa);
        }

        /// A signer, or a verifier when `signer` is false, over `n` participants and a dealing
        /// whose fault model `M` and player count `players` may not fit them.
        fn construct(comptime M: type, n: u32, players: u32, signer: bool) !void {
            var rng = utils.test_rng();
            const set = try participants(&rng, n);
            var dealing = try dkg.deal_anonymous(V, M, gpa, &rng, .non_zero_counter, players);
            defer dealing.deinit(gpa);
            const polynomial = try dealing.sharing.clone(gpa);
            var scheme = if (signer)
                try Scheme(V).signer(gpa, namespace, set, polynomial, dealing.shares[0])
            else
                try Scheme(V).verifier(gpa, namespace, set, polynomial);
            if (scheme) |*value| value.deinit(gpa);
        }

        /// commonware `signer_validates_polynomial_degree`: N5f1 over four players deals a
        /// degree-3 polynomial where N3f1 needs degree 2.
        fn signer_degree() !void {
            try construct(N5f1, 4, 4, true);
        }

        /// commonware `verifier_validates_polynomial_degree`.
        fn verifier_degree() !void {
            try construct(N5f1, 4, 4, false);
        }

        /// commonware `signer_polynomial_threshold_must_equal_quorum`: two players for five
        /// participants.
        fn signer_total() !void {
            try construct(N3f1, 5, 2, true);
        }

        /// commonware `verifier_polynomial_threshold_must_equal_quorum`.
        fn verifier_total() !void {
            try construct(N3f1, 5, 2, false);
        }
    };
}

const on_vote = "can only be called for signer and verifier";
const index_mismatch = "share index must match participant indices";
const degree = "polynomial threshold must equal quorum";
const total = "polynomial total must equal participant len";

test "threshold certificate: a certificate verifier panics on a vote (MinPk)" {
    try death.expect_panic(@src(), on_vote, Panics(MinPk).verifier_on_vote);
}

test "threshold certificate: a certificate verifier panics on a vote (MinSig)" {
    try death.expect_panic(@src(), on_vote, Panics(MinSig).verifier_on_vote);
}

test "threshold certificate: a signer's share must match a participant index (MinPk)" {
    try death.expect_panic(@src(), index_mismatch, Panics(MinPk).share_index);
}

test "threshold certificate: a signer's share must match a participant index (MinSig)" {
    try death.expect_panic(@src(), index_mismatch, Panics(MinSig).share_index);
}

test "threshold certificate: a signer validates the polynomial degree (MinPk)" {
    try death.expect_panic(@src(), degree, Panics(MinPk).signer_degree);
}

test "threshold certificate: a signer validates the polynomial degree (MinSig)" {
    try death.expect_panic(@src(), degree, Panics(MinSig).signer_degree);
}

test "threshold certificate: a verifier validates the polynomial degree (MinPk)" {
    try death.expect_panic(@src(), degree, Panics(MinPk).verifier_degree);
}

test "threshold certificate: a verifier validates the polynomial degree (MinSig)" {
    try death.expect_panic(@src(), degree, Panics(MinSig).verifier_degree);
}

test "threshold certificate: a signer's polynomial total must equal the participants (MinPk)" {
    try death.expect_panic(@src(), total, Panics(MinPk).signer_total);
}

test "threshold certificate: a signer's polynomial total must equal the participants (MinSig)" {
    try death.expect_panic(@src(), total, Panics(MinSig).signer_total);
}

test "threshold certificate: a verifier's polynomial total must equal the participants (MinPk)" {
    try death.expect_panic(@src(), total, Panics(MinPk).verifier_total);
}

test "threshold certificate: a verifier's polynomial total must equal the participants (MinSig)" {
    try death.expect_panic(@src(), total, Panics(MinSig).verifier_total);
}
