//! commonware `bls12381_threshold::vrf` tests: votes carry a vote and a seed partial, a
//! quorum recovers both, and a certificate or seed verifies only for its own round.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const vrf = @import("vrf.zig");

const primitives = cryptography.bls12381.primitives;
const tle = cryptography.bls12381.tle;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Round = consensus_types.Round;
const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const Participant = utils.Participant;
const N3f1 = utils.N3f1;
const sequential = parallel.sequential;
/// Debug runs without `-Dslow-tests` cover MinPk only, to keep the suite fast; ReleaseSafe
/// covers both variants.
const variants = if (builtin.mode == .debug and !build_options.slow_tests)
    .{primitives.MinPk}
else
    .{ primitives.MinPk, primitives.MinSig };
const namespace = "bls-threshold-signing-scheme";

fn SchemeOf(comptime V: type) type {
    return vrf.Scheme(Digest, cryptography.ed25519.PublicKey, V);
}

fn setup(comptime V: type, n: u32, seed: u64) !cryptography.certificate.mocks.Fixture(SchemeOf(V)) {
    var rng = utils.rng.TestRng.init(seed);
    return vrf.fixture(SchemeOf(V), testing.allocator, &rng, namespace, n);
}

fn sample_proposal(epoch: u64, view: u64, tag: u8) types.Proposal(Digest) {
    const round: Round = .new(.new(epoch), .new(view));
    return .init(round, round.view.previous().?, Sha256.hash(&.{&.{tag}}));
}

/// Signs `subject` with each scheme in `schemes` into `out`.
fn sign_each(
    comptime S: type,
    schemes: []const S,
    subject: S.Subject,
    out: []S.Attestation,
) !void {
    for (schemes, out) |*scheme, *vote| vote.* = (try scheme.sign(testing.allocator, subject)).?;
}

/// A certificate over `subject` from a quorum of `schemes`, starting at `first`.
fn quorum_certificate(
    comptime S: type,
    schemes: []const S,
    first: usize,
    subject: S.Subject,
) !S.Certificate {
    const quorum = N3f1.quorum(schemes.len);
    var votes: [16]S.Attestation = undefined;
    try sign_each(S, schemes[first..][0..quorum], subject, votes[0..quorum]);
    return schemes[0].assemble(testing.allocator, votes[0..quorum], sequential);
}

/// `scheme.verify_certificate` with the test allocator and a sequential strategy.
fn certifies(scheme: anytype, rng: anytype, subject: anytype, certificate: anytype) !bool {
    return scheme.verify_certificate(testing.allocator, rng, subject, certificate, sequential);
}

test "vrf: sign and verify a vote for each subject" {
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 7);
        defer fixture.deinit(testing.allocator);
        var rng = utils.rng.test_rng();
        const proposal = sample_proposal(0, 2, 1);
        const subjects = [_]S.Subject{
            .{ .notarize = &proposal },
            .{ .nullify = proposal.round },
            .{ .finalize = &proposal },
        };
        const scheme = &fixture.schemes[0];
        for (subjects) |subject| {
            const vote = (try scheme.sign(testing.allocator, subject)).?;
            try testing.expect(try scheme.verify_attestation(
                testing.allocator,
                &rng,
                subject,
                &vote,
                sequential,
            ));
            // The vote does not verify for another subject kind.
            const other: S.Subject = if (subject == .nullify)
                .{ .notarize = &proposal }
            else
                .{ .nullify = proposal.round };
            try testing.expect(!try scheme.verify_attestation(
                testing.allocator,
                &rng,
                other,
                &vote,
                sequential,
            ));
        }
    }
}

test "vrf: verifiers and certificate verifiers cannot sign" {
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 31);
        defer fixture.deinit(testing.allocator);
        const proposal = sample_proposal(0, 21, 9);
        const subject: S.Subject = .{ .notarize = &proposal };
        var signer = try fixture.schemes[0].clone(testing.allocator);
        defer signer.deinit(testing.allocator);
        try testing.expect(try signer.sign(testing.allocator, subject) != null);
        try testing.expect(try fixture.verifier.sign(testing.allocator, subject) == null);
        try testing.expect(fixture.verifier.me() == null);
        var certificate_verifier =
            try S.certificate_verifier(testing.allocator, namespace, signer.identity());
        defer certificate_verifier.deinit(testing.allocator);
        try testing.expect(try certificate_verifier.sign(testing.allocator, subject) == null);
        try testing.expect(certificate_verifier.me() == null);
    }
}

test "vrf: a member reports membership, cannot sign, and verifies certificates" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 12);
        defer fixture.deinit(gpa);
        const verifier = &fixture.verifier;
        const proposal = sample_proposal(0, 3, 2);
        const outsider = cryptography.ed25519.PrivateKey.from_seed(std.math.maxInt(u64));
        const set = try verifier.participants().clone(gpa);
        const sharing = try verifier.polynomial().clone(gpa);
        try testing.expect(try S.member(gpa, namespace, set, sharing, outsider.public_key()) ==
            null);
        const index = Participant.init(2);
        const key = verifier.participants().key(index).?.*;
        var member = (try S.member(
            gpa,
            namespace,
            try verifier.participants().clone(gpa),
            try verifier.polynomial().clone(gpa),
            key,
        )).?;
        defer member.deinit(gpa);
        try testing.expectEqual(index, member.me().?.member);
        try testing.expect(try member.sign(gpa, .{ .notarize = &proposal }) == null);
        for (fixture.schemes) |*scheme| {
            const vote = (try scheme.sign(gpa, .{ .notarize = &proposal })).?;
            try testing.expectEqual(scheme.me().?.signer, vote.signer);
        }
        const subject: S.Subject = .{ .finalize = &proposal };
        const certificate = try quorum_certificate(S, fixture.schemes, 0, subject);
        var rng = utils.rng.test_rng();
        try testing.expect(try certifies(member, &rng, subject, &certificate));
    }
}

test "vrf: verify_attestations filters bad signers" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 5, 13);
        defer fixture.deinit(gpa);
        var rng = utils.rng.test_rng();
        const quorum = N3f1.quorum(5);
        const proposal = sample_proposal(0, 5, 3);
        const subject: S.Subject = .{ .notarize = &proposal };
        var votes: [4]S.Attestation = undefined;
        try sign_each(S, fixture.schemes[0..quorum], subject, votes[0..quorum]);
        const scheme = &fixture.schemes[0];
        var all = try scheme.verify_attestations(gpa, &rng, subject, votes[0..quorum], sequential);
        defer all.deinit(gpa);
        try testing.expectEqual(0, all.invalid.len);
        try testing.expectEqual(quorum, all.verified.len);
        votes[0].signer = .init(999);
        var some = try scheme.verify_attestations(gpa, &rng, subject, votes[0..quorum], sequential);
        defer some.deinit(gpa);
        try testing.expectEqualSlices(Participant, &.{.init(999)}, some.invalid);
        try testing.expectEqual(quorum - 1, some.verified.len);
        // A seed partial from another round invalidates only its signer.
        votes[0].signer = .init(0);
        const other = sample_proposal(0, 6, 3);
        var mixed = votes[1].signature.get().?;
        const forged = (try fixture.schemes[1].sign(gpa, .{ .notarize = &other })).?;
        mixed.seed_signature = forged.signature.get().?.seed_signature;
        votes[1] = .init(votes[1].signer, mixed);
        var seeded =
            try scheme.verify_attestations(gpa, &rng, subject, votes[0..quorum], sequential);
        defer seeded.deinit(gpa);
        try testing.expectEqualSlices(Participant, &.{.init(1)}, seeded.invalid);
        try testing.expectEqual(quorum - 1, seeded.verified.len);
    }
}

test "vrf: assemble rejects too few, duplicate, unknown, and malformed attestations" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 17);
        defer fixture.deinit(gpa);
        const proposal = sample_proposal(0, 7, 4);
        const subject: S.Subject = .{ .notarize = &proposal };
        var votes: [3]S.Attestation = undefined;
        try sign_each(S, fixture.schemes[0..3], subject, &votes);
        const scheme = &fixture.schemes[0];
        try testing.expectError(
            error.InsufficientAttestations,
            scheme.assemble(gpa, votes[0..2], sequential),
        );
        var duplicate = votes;
        duplicate[2] = duplicate[1];
        try testing.expectError(
            error.DuplicateSigner,
            scheme.assemble(gpa, &duplicate, sequential),
        );
        var unknown = votes;
        unknown[2].signer = .init(4);
        try testing.expectError(error.UnknownSigner, scheme.assemble(gpa, &unknown, sequential));
        var malformed = votes;
        malformed[1].signature = .from_bytes(@splat(0xff));
        try testing.expectError(
            error.MalformedSignature,
            scheme.assemble(gpa, &malformed, sequential),
        );
        _ = try scheme.assemble(gpa, &votes, sequential);
    }
}

test "vrf: verify_certificate detects vote and seed corruption" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 23);
        defer fixture.deinit(gpa);
        var rng = utils.rng.test_rng();
        const proposal = sample_proposal(0, 11, 6);
        const subjects = [_]S.Subject{ .{ .notarize = &proposal }, .{ .nullify = proposal.round } };
        for (subjects) |subject| {
            const certificate = try quorum_certificate(S, fixture.schemes, 0, subject);
            const verifier = &fixture.verifier;
            try testing.expect(try certifies(verifier, &rng, subject, &certificate));
            const pair = certificate.get().?;
            const corrupt = [_]S.Signature{
                .{ .vote_signature = pair.seed_signature, .seed_signature = pair.seed_signature },
                .{ .vote_signature = pair.vote_signature, .seed_signature = pair.vote_signature },
                .{ .vote_signature = V.Signature.zero, .seed_signature = pair.seed_signature },
                .{ .vote_signature = pair.vote_signature, .seed_signature = V.Signature.zero },
            };
            for (corrupt) |signature| {
                const forged: S.Certificate = .init(signature);
                try testing.expect(!try certifies(verifier, &rng, subject, &forged));
            }
        }
    }
}

test "vrf: a certificate verifier accepts certificates" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 37);
        defer fixture.deinit(gpa);
        const proposal = sample_proposal(0, 15, 8);
        const subject: S.Subject = .{ .finalize = &proposal };
        const certificate = try quorum_certificate(S, fixture.schemes, 0, subject);
        var verifier =
            try S.certificate_verifier(gpa, namespace, fixture.schemes[0].identity());
        defer verifier.deinit(gpa);
        var rng = utils.rng.test_rng();
        try testing.expect(try certifies(verifier, &rng, subject, &certificate));
    }
}

test "vrf: certificate and seed codec round trips" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 5, 29);
        defer fixture.deinit(gpa);
        const proposal = sample_proposal(0, 13, 7);
        const certificate =
            try quorum_certificate(S, fixture.schemes, 0, .{ .notarize = &proposal });
        const encoded = try codec.encode(S.Certificate, gpa, certificate);
        defer gpa.free(encoded);
        try testing.expectEqual(S.max_certificate_size(5), encoded.len);
        const decoded = try codec.decode(S.Certificate, gpa, encoded);
        try testing.expect(decoded.eql(&certificate));
        try testing.expectError(
            error.EndOfBuffer,
            codec.decode(S.Signature, gpa, encoded[0 .. encoded.len - 1]),
        );
        const seed: vrf.Seed(V) = .{
            .round = proposal.round,
            .signature = certificate.get().?.seed_signature,
        };
        const seed_bytes = try codec.encode(vrf.Seed(V), gpa, seed);
        defer gpa.free(seed_bytes);
        try testing.expect((try codec.decode(vrf.Seed(V), gpa, seed_bytes)).eql(seed));
    }
}

test "vrf: seeds verify only for their own round, and certificates carry them" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 5);
        defer fixture.deinit(gpa);
        const proposal = sample_proposal(0, 1, 0);
        const quorum = N3f1.quorum(4);
        var notarizes: [3]types.Notarize(S, Digest) = undefined;
        var finalizes: [3]types.Finalize(S, Digest) = undefined;
        for (fixture.schemes[0..quorum], &notarizes, &finalizes) |*scheme, *n, *f| {
            n.* = (try types.Notarize(S, Digest).sign(gpa, scheme, proposal)).?;
            f.* = (try types.Finalize(S, Digest).sign(gpa, scheme, proposal)).?;
        }
        const Notarization = types.Notarization(S, Digest);
        const Finalization = types.Finalization(S, Digest);
        const leader = &fixture.schemes[0];
        var notarization = try Notarization.from_votes(gpa, leader, &notarizes, sequential);
        defer notarization.deinit(gpa);
        var finalization = try Finalization.from_votes(gpa, leader, &finalizes, sequential);
        defer finalization.deinit(gpa);
        const seed = vrf.seed(V, &notarization);
        try testing.expect(seed.eql(vrf.seed(V, &finalization)));
        try testing.expect(seed.verify(&fixture.schemes[0]));
        try testing.expect(seed.verify(&fixture.verifier));
        const next: vrf.Seed(V) = .{
            .round = .new(proposal.round.epoch, proposal.round.view.next()),
            .signature = seed.signature,
        };
        try testing.expect(!next.verify(&fixture.schemes[0]));
    }
}

test "vrf: a vote's partials are the share's signatures over vote and round" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 53);
        defer fixture.deinit(gpa);
        const scheme = &fixture.schemes[0];
        const share = scheme.share().?;
        const proposal = sample_proposal(0, 23, 12);
        const vote = (try scheme.sign(gpa, .{ .notarize = &proposal })).?;
        const message = try codec.encode(types.Proposal(Digest), gpa, proposal);
        defer gpa.free(message);
        const round = try codec.encode(Round, gpa, proposal.round);
        defer gpa.free(round);
        const threshold = primitives.ops.threshold;
        const expected_vote = threshold.sign_message(V, share, namespace ++ "_NOTARIZE", message);
        const expected_seed = threshold.sign_message(V, share, namespace ++ "_SEED", round);
        const signature: S.Signature = vote.signature.get().?;
        try testing.expectEqual(share.index, vote.signer);
        try testing.expect(signature.vote_signature.eql(expected_vote.value));
        try testing.expect(signature.seed_signature.eql(expected_seed.value));
    }
}

test "vrf: forged partials that keep the signature sum are rejected" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 67);
        defer fixture.deinit(gpa);
        var rng = utils.rng.test_rng();
        const proposal = sample_proposal(0, 27, 14);
        const subject: S.Subject = .{ .notarize = &proposal };
        const scheme = &fixture.schemes[0];
        const vote = (try scheme.sign(gpa, subject)).?;
        try testing.expect(try scheme.verify_attestation(gpa, &rng, subject, &vote, sequential));
        const delta = V.Signature.generator.mul(primitives.group.Scalar.random(&rng));
        const pair = vote.signature.get().?;
        const forged: S.Attestation = .init(vote.signer, .{
            .vote_signature = pair.vote_signature.sub(delta),
            .seed_signature = pair.seed_signature.add(delta),
        });
        try testing.expect(!try scheme.verify_attestation(gpa, &rng, subject, &forged, sequential));
        var verification =
            try scheme.verify_attestations(gpa, &rng, subject, &.{forged}, sequential);
        defer verification.deinit(gpa);
        try testing.expectEqualSlices(Participant, &.{vote.signer}, verification.invalid);
    }
}

test "vrf: verify_certificates shares a round's seed and rejects a replayed seed" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 83);
        defer fixture.deinit(gpa);
        var rng = utils.rng.test_rng();
        const verifier = &fixture.verifier;
        const shared = sample_proposal(1, 35, 19);
        const notarize: S.Subject = .{ .notarize = &shared };
        const finalize: S.Subject = .{ .finalize = &shared };
        const notarized = try quorum_certificate(S, fixture.schemes, 0, notarize);
        const finalized = try quorum_certificate(S, fixture.schemes, 1, finalize);
        const same_round = [_]S.Item{
            .{ .subject = notarize, .certificate = &notarized },
            .{ .subject = finalize, .certificate = &finalized },
        };
        try testing.expect(try verifier.verify_certificates(gpa, &rng, &same_round, sequential));
        const later = sample_proposal(2, 35, 20);
        const later_subject: S.Subject = .{ .notarize = &later };
        const later_certificate = try quorum_certificate(S, fixture.schemes, 0, later_subject);
        const epochs = [_]S.Item{
            same_round[0],
            .{ .subject = later_subject, .certificate = &later_certificate },
        };
        try testing.expect(try verifier.verify_certificates(gpa, &rng, &epochs, sequential));
        const replayed: S.Certificate = .init(.{
            .vote_signature = later_certificate.get().?.vote_signature,
            .seed_signature = notarized.get().?.seed_signature,
        });
        try testing.expect(!try certifies(verifier, &rng, later_subject, &replayed));
        const forged = [_]S.Item{
            same_round[0],
            .{ .subject = later_subject, .certificate = &replayed },
        };
        try testing.expect(!try verifier.verify_certificates(gpa, &rng, &forged, sequential));
        var results: [2]bool = undefined;
        const bisect = cryptography.certificate.verify_certificates_bisect;
        try bisect(verifier, gpa, &rng, &forged, &results, sequential);
        try testing.expectEqualSlices(bool, &.{ true, false }, &results);
        // Two certificates for one round with different seed signatures fail together.
        const mismatched: S.Certificate = .init(.{
            .vote_signature = finalized.get().?.vote_signature,
            .seed_signature = later_certificate.get().?.seed_signature,
        });
        const split = [_]S.Item{
            same_round[0],
            .{ .subject = finalize, .certificate = &mismatched },
        };
        try testing.expect(!try verifier.verify_certificates(gpa, &rng, &split, sequential));
    }
}

test "vrf: a ciphertext to a round decrypts with that round's seed" {
    const gpa = testing.allocator;
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 61);
        defer fixture.deinit(gpa);
        var rng = utils.rng.test_rng();
        const message: tle.Block = "Secret message for future view10".*;
        const target: Round = .new(.new(333), .new(10));
        const from_signer = try fixture.schemes[0].encrypt(&rng, target, &message);
        const from_verifier = try fixture.verifier.encrypt(&rng, target, &message);
        const identity = fixture.verifier.identity();
        const from_identity = try vrf.encrypt(V, gpa, &rng, identity, namespace, target, &message);
        const proposal = sample_proposal(333, 10, 14);
        const certificate =
            try quorum_certificate(S, fixture.schemes, 0, .{ .notarize = &proposal });
        const seed: vrf.Seed(V) = .{
            .round = target,
            .signature = certificate.get().?.seed_signature,
        };
        for ([_]tle.Ciphertext(V){ from_signer, from_verifier, from_identity }) |ciphertext| {
            try testing.expectEqualSlices(u8, &message, &seed.decrypt(ciphertext).?);
        }
        // Another round's seed does not decrypt it.
        const other = sample_proposal(333, 11, 14);
        const later = try quorum_certificate(S, fixture.schemes, 0, .{ .notarize = &other });
        const wrong: vrf.Seed(V) = .{
            .round = other.round,
            .signature = later.get().?.seed_signature,
        };
        try testing.expect(wrong.decrypt(from_signer) == null);
        var at_identity = try S.certificate_verifier(gpa, namespace, V.Public.zero);
        defer at_identity.deinit(gpa);
        const zeros: tle.Block = @splat(0);
        try testing.expectError(error.InvalidPublicKey, at_identity.encrypt(&rng, target, &zeros));
    }
}

// commonware `test_is_not_attributable` and `test_is_batchable`: threshold partials prove no
// single signer's fault, and votes verify in batches.
test "vrf: the scheme is batchable but not attributable" {
    inline for (variants) |V| {
        try testing.expect(!SchemeOf(V).is_attributable());
        try testing.expect(SchemeOf(V).is_batchable());
    }
}

// commonware `test_verifier_accepts_votes`: a verifier that holds no share still verifies a
// signer's vote, and rejects it for another subject.
test "vrf: a verifier without a share verifies signers' votes" {
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 11);
        defer fixture.deinit(testing.allocator);
        var rng = utils.rng.test_rng();
        const proposal = sample_proposal(0, 3, 4);
        const subject: S.Subject = .{ .notarize = &proposal };
        const vote = (try fixture.schemes[1].sign(testing.allocator, subject)).?;
        const verifier = &fixture.verifier;
        try testing.expect(verifier.me() == null);
        const a = testing.allocator;
        try testing.expect(try verifier.verify_attestation(a, &rng, subject, &vote, sequential));
        const other: S.Subject = .{ .nullify = proposal.round };
        try testing.expect(!try verifier.verify_attestation(a, &rng, other, &vote, sequential));
    }
}

const MinPk = primitives.MinPk;
const MinSig = primitives.MinSig;
const deal_anonymous = cryptography.bls12381.dkg.feldman_desmedt.deal_anonymous;

/// Builds a scheme over `n` participants from a dealing of `dealt` shares with faults model
/// `M`: a signer from share 0 (its index replaced by `share_index` when set), or a verifier.
/// Every misfit below panics inside `signer` or `verifier`.
fn build_misfit(
    comptime V: type,
    comptime M: type,
    n: u32,
    dealt: u32,
    role: enum { signer, verifier },
    share_index: ?u32,
) !void {
    const gpa = testing.allocator;
    const S = SchemeOf(V);
    var fixture = try setup(V, n, 11);
    var rng = utils.rng.test_rng();
    const dealing = try deal_anonymous(V, M, gpa, &rng, .non_zero_counter, dealt);
    const set = try S.Participants.init(gpa, fixture.participants);
    var share = dealing.shares[0];
    if (share_index) |index| share.index = .init(index);
    var scheme = switch (role) {
        .signer => (try S.signer(gpa, namespace, set, dealing.sharing, share)).?,
        .verifier => try S.verifier(gpa, namespace, set, dealing.sharing),
    };
    scheme.deinit(gpa);
    gpa.free(dealing.shares);
    fixture.deinit(gpa);
}

/// commonware certificate_verifier_panics_on_vote: a certificate verifier has no committee,
/// so verifying a vote panics.
fn certificate_verifier_on_vote(comptime V: type) !void {
    const gpa = testing.allocator;
    const S = SchemeOf(V);
    var fixture = try setup(V, 4, 37);
    var verifier = try S.certificate_verifier(gpa, namespace, fixture.schemes[0].identity());
    const proposal = sample_proposal(0, 15, 8);
    const subject: S.Subject = .{ .finalize = &proposal };
    const vote = (try fixture.schemes[1].sign(gpa, subject)).?;
    var rng = utils.rng.test_rng();
    _ = try verifier.verify_attestation(gpa, &rng, subject, &vote, sequential);
    verifier.deinit(gpa);
    fixture.deinit(gpa);
}

const share_index_panic = "share index must match participant indices";
const total_panic = "polynomial total must equal participant len";
const threshold_panic = "polynomial threshold must equal quorum";
const committee_panic = "can only be called for signer and verifier";

// commonware test_signer_shares_must_match_participant_indices_min_pk (should_panic).
test "vrf: a signer panics on a share index outside the participants (min_pk)" {
    try utils.death.expect_panic(@src(), share_index_panic, struct {
        fn body() !void {
            try build_misfit(MinPk, N3f1, 4, 4, .signer, 999);
        }
    }.body);
}

// commonware test_signer_shares_must_match_participant_indices_min_sig (should_panic).
test "vrf: a signer panics on a share index outside the participants (min_sig)" {
    try utils.death.expect_panic(@src(), share_index_panic, struct {
        fn body() !void {
            try build_misfit(MinSig, N3f1, 4, 4, .signer, 999);
        }
    }.body);
}

// commonware test_scheme_polynomial_threshold_must_equal_quorum_min_pk (should_panic): five
// participants, a polynomial dealt to four.
test "vrf: a signer panics when the polynomial total differs (min_pk)" {
    try utils.death.expect_panic(@src(), total_panic, struct {
        fn body() !void {
            try build_misfit(MinPk, N3f1, 5, 4, .signer, null);
        }
    }.body);
}

// commonware test_scheme_polynomial_threshold_must_equal_quorum_min_sig (should_panic).
test "vrf: a signer panics when the polynomial total differs (min_sig)" {
    try utils.death.expect_panic(@src(), total_panic, struct {
        fn body() !void {
            try build_misfit(MinSig, N3f1, 5, 4, .signer, null);
        }
    }.body);
}

// commonware test_verifier_polynomial_threshold_must_equal_quorum_min_pk (should_panic).
test "vrf: a verifier panics when the polynomial total differs (min_pk)" {
    try utils.death.expect_panic(@src(), total_panic, struct {
        fn body() !void {
            try build_misfit(MinPk, N3f1, 5, 4, .verifier, null);
        }
    }.body);
}

// commonware test_verifier_polynomial_threshold_must_equal_quorum_min_sig (should_panic).
test "vrf: a verifier panics when the polynomial total differs (min_sig)" {
    try utils.death.expect_panic(@src(), total_panic, struct {
        fn body() !void {
            try build_misfit(MinSig, N3f1, 5, 4, .verifier, null);
        }
    }.body);
}

// commonware test_signer_validates_polynomial_degree_min_pk (should_panic): for four
// participants N5f1 deals a degree-3 polynomial where this N3f1 scheme needs degree 2.
test "vrf: a signer panics when the polynomial threshold differs (min_pk)" {
    try utils.death.expect_panic(@src(), threshold_panic, struct {
        fn body() !void {
            try build_misfit(MinPk, utils.N5f1, 4, 4, .signer, null);
        }
    }.body);
}

// commonware test_signer_validates_polynomial_degree_min_sig (should_panic).
test "vrf: a signer panics when the polynomial threshold differs (min_sig)" {
    try utils.death.expect_panic(@src(), threshold_panic, struct {
        fn body() !void {
            try build_misfit(MinSig, utils.N5f1, 4, 4, .signer, null);
        }
    }.body);
}

// commonware test_verifier_validates_polynomial_degree_min_pk (should_panic).
test "vrf: a verifier panics when the polynomial threshold differs (min_pk)" {
    try utils.death.expect_panic(@src(), threshold_panic, struct {
        fn body() !void {
            try build_misfit(MinPk, utils.N5f1, 4, 4, .verifier, null);
        }
    }.body);
}

// commonware test_verifier_validates_polynomial_degree_min_sig (should_panic).
test "vrf: a verifier panics when the polynomial threshold differs (min_sig)" {
    try utils.death.expect_panic(@src(), threshold_panic, struct {
        fn body() !void {
            try build_misfit(MinSig, utils.N5f1, 4, 4, .verifier, null);
        }
    }.body);
}

// commonware test_certificate_verifier_panics_on_vote_min_pk (should_panic).
test "vrf: a certificate verifier panics on a vote (min_pk)" {
    try utils.death.expect_panic(@src(), committee_panic, struct {
        fn body() !void {
            try certificate_verifier_on_vote(MinPk);
        }
    }.body);
}

// commonware test_certificate_verifier_panics_on_vote_min_sig (should_panic).
test "vrf: a certificate verifier panics on a vote (min_sig)" {
    try utils.death.expect_panic(@src(), committee_panic, struct {
        fn body() !void {
            try certificate_verifier_on_vote(MinSig);
        }
    }.body);
}
