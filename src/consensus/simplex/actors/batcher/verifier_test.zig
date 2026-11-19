//! commonware `actors/batcher/verifier.rs` tests, run for each simplex scheme.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const multisig = @import("../../scheme/bls12381_multisig.zig");
const threshold = @import("../../scheme/bls12381_threshold/standard.zig");
const secp256r1 = @import("../../scheme/secp256r1.zig");
const verifier_mod = @import("verifier.zig");

const Digest = cryptography.Sha256.Digest;
const MinSig = cryptography.bls12381.primitives.MinSig;
const MinPk = cryptography.bls12381.primitives.MinPk;
const PublicKey = cryptography.ed25519.PublicKey;
const Round = consensus_types.Round;
const View = consensus_types.View;
const sequential = parallel.sequential;
const namespace = "test";

/// A scheme under test and its fixture constructor.
fn Case(comptime S: type, comptime build: anytype) type {
    return struct {
        pub const Scheme = S;
        pub fn fixture(gpa: Allocator, rng: anytype, n: u32) !Fixture(S) {
            return build(S, gpa, rng, namespace, n);
        }
    };
}

fn Fixture(comptime S: type) type {
    return cryptography.certificate.mocks.Fixture(S);
}

fn ed25519_fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    ns: []const u8,
    n: u32,
) !Fixture(S) {
    return ed25519.fixture(Digest, gpa, rng, ns, n);
}

const cases = .{
    Case(ed25519.Scheme(Digest), ed25519_fixture),
    Case(secp256r1.Scheme(Digest, PublicKey), secp256r1.fixture),
    Case(multisig.Scheme(Digest, PublicKey, MinSig), multisig.fixture),
    Case(multisig.Scheme(Digest, PublicKey, MinPk), multisig.fixture),
    Case(threshold.Scheme(Digest, PublicKey, MinSig), threshold.fixture),
};

fn notarize(
    comptime S: type,
    scheme: *const S,
    round: Round,
    parent: u64,
    payload: u8,
) !types.Notarize(S, Digest) {
    const proposal: types.Proposal(Digest) = .init(round, .new(parent), .fill(payload));
    return (try types.Notarize(S, Digest).sign(testing.allocator, scheme, proposal)).?;
}

const round_one: Round = .new(.new(0), .new(1));

fn add_notarize(comptime C: type) !void {
    const S = C.Scheme;
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try C.fixture(gpa, &rng, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    const quorum = utils.N3f1.quorum(@as(u32, 5));
    var verifier = verifier_mod.Verifier(S, Digest).init(round_one, &schemes[0], quorum);
    defer verifier.deinit(gpa);

    const leader_notarize = try notarize(S, &schemes[0], round_one, 0, 1);
    try verifier.add(gpa, .{ .notarize = leader_notarize }, false);
    try testing.expectEqual(1, verifier.notarize.pending.items.len);
    try verifier.add(gpa, .{ .notarize = try notarize(S, &schemes[1], round_one, 0, 1) }, true);
    try testing.expectEqual(1, verifier.notarize.verified.items.len);
    verifier.set_leader(leader_notarize.signer(), &leader_notarize);
    try testing.expectEqual(leader_notarize.signer(), verifier.leader().?);
    try testing.expect(verifier.proposal().?.eql(leader_notarize.proposal));
    try verifier.add(gpa, .{ .notarize = try notarize(S, &schemes[2], round_one, 0, 1) }, false);
    try testing.expectEqual(2, verifier.notarize.pending.items.len);
    // A vote for another proposal is dropped once the leader's proposal is known.
    try verifier.add(gpa, .{ .notarize = try notarize(S, &schemes[3], round_one, 0, 2) }, false);
    try testing.expectEqual(2, verifier.notarize.pending.items.len);

    // Votes buffered before the leader's vote are filtered when it arrives.
    const round_two: Round = .new(.new(0), .new(2));
    var second = verifier_mod.Verifier(S, Digest).init(round_two, &schemes[0], quorum);
    defer second.deinit(gpa);
    const late_leader = try notarize(S, &schemes[0], round_two, 1, 3);
    second.set_leader(late_leader.signer(), null);
    try second.add(gpa, .{ .notarize = try notarize(S, &schemes[1], round_two, 1, 3) }, false);
    try testing.expectEqual(null, second.proposal());
    try second.add(gpa, .{ .notarize = late_leader }, false);
    try testing.expect(second.proposal().?.eql(late_leader.proposal));
    try testing.expectEqual(2, second.notarize.pending.items.len);
}

test "add notarize" {
    inline for (cases) |C| try add_notarize(C);
}

fn set_leader(comptime C: type) !void {
    const S = C.Scheme;
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try C.fixture(gpa, &rng, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    const quorum = utils.N3f1.quorum(@as(u32, 5));
    const leader_notarize = try notarize(S, &schemes[0], round_one, 0, 1);
    var verifier = verifier_mod.Verifier(S, Digest).init(round_one, &schemes[0], quorum);
    defer verifier.deinit(gpa);
    try verifier.add(gpa, .{ .notarize = leader_notarize }, true);
    verifier.set_leader(leader_notarize.signer(), &leader_notarize);
    try testing.expect(verifier.proposal().?.eql(leader_notarize.proposal));

    // A certificate's proposal supersedes the leader's, and then stays authoritative.
    const notarized: types.Proposal(Digest) = .init(round_one, .zero(), .fill(2));
    try testing.expect(verifier.set_proposal(.{ .certificate = notarized }).changed);
    try testing.expect(verifier.proposal().?.eql(notarized));
    try testing.expect(!verifier.set_proposal(.{ .certificate = notarized }).changed);
    const conflicting: types.Proposal(Digest) = .init(round_one, .zero(), .fill(3));
    try testing.expect(!verifier.set_proposal(.{ .certificate = conflicting }).changed);
    try testing.expect(verifier.proposal().?.eql(notarized));
    // The leader's own vote was for another proposal, so it was dropped.
    try testing.expectEqual(0, verifier.notarize.verified.items.len);

    // A notarization that arrives first is not replaced by a buffered leader vote.
    var later = verifier_mod.Verifier(S, Digest).init(round_one, &schemes[0], quorum);
    defer later.deinit(gpa);
    try testing.expect(later.set_proposal(.{ .certificate = notarized }).changed);
    later.set_leader(leader_notarize.signer(), &leader_notarize);
    try testing.expect(later.proposal().?.eql(notarized));
}

test "set leader" {
    inline for (cases) |C| try set_leader(C);
}

fn construct_nullification(comptime C: type) !void {
    const S = C.Scheme;
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try C.fixture(gpa, &rng, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    const quorum = utils.N3f1.quorum(@as(u32, 5));
    var verifier = verifier_mod.Verifier(S, Digest).init(round_one, &schemes[0], quorum);
    defer verifier.deinit(gpa);
    const Nullify = types.Nullify(S);

    // Below quorum (batchable schemes) nothing is attempted.
    for (schemes[0 .. quorum - 1]) |*scheme| {
        try verifier.add(gpa, .{ .nullify = (try Nullify.sign(gpa, scheme, round_one)).? }, false);
    }
    if (S.is_batchable()) {
        const early = try verifier.try_construct_nullification(gpa, &rng, sequential);
        try testing.expectEqual(null, early);
    }
    // A vote signed for another round fails; the batch falls back and isolates it.
    const other_round: Round = .new(.new(0), .new(9));
    var bad = (try Nullify.sign(gpa, &schemes[quorum - 1], other_round)).?;
    bad.round = round_one;
    try verifier.add(gpa, .{ .nullify = bad }, false);
    var attempts: usize = 0;
    var invalid_seen = false;
    while (try verifier.try_construct_nullification(gpa, &rng, sequential)) |batch_const| {
        var batch = batch_const;
        defer batch.deinit(gpa);
        attempts += 1;
        try testing.expect(batch.certificate == null);
        for (batch.invalid) |signer| {
            try testing.expectEqual(bad.signer(), signer);
            invalid_seen = true;
        }
    }
    try testing.expect(attempts > 0 and invalid_seen);
    try testing.expect(!verifier.has_certificate(.nullification));

    // One more valid vote reaches the quorum and assembles.
    const last = (try Nullify.sign(gpa, &schemes[quorum], round_one)).?;
    try verifier.add(gpa, .{ .nullify = last }, false);
    var batch = (try verifier.try_construct_nullification(gpa, &rng, sequential)).?;
    defer batch.deinit(gpa);
    const certificate = &batch.certificate.?;
    try testing.expect(try certificate.verify(gpa, &rng, &fixture.verifier, sequential));
    try testing.expect(verifier.has_certificate(.nullification));
    try testing.expectEqual(null, try verifier.try_construct_nullification(gpa, &rng, sequential));
}

test "construct nullification isolates an invalid vote" {
    inline for (cases) |C| try construct_nullification(C);
}

fn construct_finalization(comptime C: type) !void {
    const S = C.Scheme;
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try C.fixture(gpa, &rng, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    const quorum = utils.N3f1.quorum(@as(u32, 5));
    var verifier = verifier_mod.Verifier(S, Digest).init(round_one, &schemes[0], quorum);
    defer verifier.deinit(gpa);
    const proposal: types.Proposal(Digest) = .init(round_one, .zero(), .fill(1));
    const Finalize = types.Finalize(S, Digest);

    // Without a known proposal and without a verified quorum, nothing is constructed.
    for (schemes[0..quorum]) |*scheme| {
        try verifier.add(gpa, .{ .finalize = (try Finalize.sign(gpa, scheme, proposal)).? }, false);
    }
    try testing.expectEqual(null, try verifier.try_construct_finalization(gpa, &rng, sequential));
    _ = verifier.set_proposal(.{ .certificate = proposal });
    var batch = (try verifier.try_construct_finalization(gpa, &rng, sequential)).?;
    defer batch.deinit(gpa);
    try testing.expectEqual(quorum, batch.processed);
    try testing.expect(!batch.fallback);
    try testing.expect(batch.certificate.? == .finalization);

    // A quorum of verified votes constructs even with no proposal, ignoring pending votes.
    var verified = verifier_mod.Verifier(S, Digest).init(round_one, &schemes[0], quorum);
    defer verified.deinit(gpa);
    for (schemes, 0..) |*scheme, index| {
        const vote = (try Finalize.sign(gpa, scheme, proposal)).?;
        try verified.add(gpa, .{ .finalize = vote }, index < quorum);
    }
    var direct = (try verified.try_construct_finalization(gpa, &rng, sequential)).?;
    defer direct.deinit(gpa);
    try testing.expectEqual(0, direct.processed);
    const certificate = &direct.certificate.?;
    try testing.expect(try certificate.verify(gpa, &rng, &fixture.verifier, sequential));
}

test "construct finalization" {
    inline for (cases) |C| try construct_finalization(C);
}

fn reservations(comptime C: type) !void {
    const S = C.Scheme;
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try C.fixture(gpa, &rng, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    const quorum = utils.N3f1.quorum(@as(u32, 5));
    var verifier = verifier_mod.Verifier(S, Digest).init(round_one, &schemes[0], quorum);
    defer verifier.deinit(gpa);
    // No phase holds vote storage until a vote of its kind arrives.
    try testing.expectEqual(0, verifier.notarize.pending.capacity);
    try testing.expectEqual(0, verifier.nullify.pending.capacity);
    try testing.expectEqual(0, verifier.finalize.pending.capacity);
    const Nullify = types.Nullify(S);
    try verifier.add(gpa, .{ .nullify = (try Nullify.sign(gpa, &schemes[0], round_one)).? }, true);
    try testing.expectEqual(quorum, verifier.nullify.verified.capacity);
    try testing.expectEqual(0, verifier.notarize.pending.capacity);
    try testing.expectEqual(0, verifier.finalize.verified.capacity);
    // Pending storage reserves only the remaining quorum, or one slot when votes verify
    // one at a time.
    try verifier.add(gpa, .{ .nullify = (try Nullify.sign(gpa, &schemes[1], round_one)).? }, false);
    const expected: usize = if (S.is_batchable()) quorum - 1 else 1;
    try testing.expectEqual(expected, verifier.nullify.pending.capacity);
}

// commonware `test_verifier_allocates_vote_buffers_lazily`,
// `test_batchable_certification_reserves_only_remaining_quorum`, and
// `test_non_batchable_certification_avoids_repeated_quorum_reservations`.
test "vote storage is reserved lazily and only for the remaining quorum" {
    inline for (cases) |C| try reservations(C);
}

fn notarize_readiness(comptime C: type) !void {
    const S = C.Scheme;
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try C.fixture(gpa, &rng, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    const quorum = utils.N3f1.quorum(@as(u32, 5));
    var verifier = verifier_mod.Verifier(S, Digest).init(round_one, &schemes[0], quorum);
    defer verifier.deinit(gpa);
    // Nothing pending: no phase constructs.
    try testing.expectEqual(null, try verifier.try_construct_notarization(gpa, &rng, sequential));
    try testing.expectEqual(null, try verifier.try_construct_nullification(gpa, &rng, sequential));
    try testing.expectEqual(null, try verifier.try_construct_finalization(gpa, &rng, sequential));
    // A quorum of unverified notarizes waits for the leader's proposal.
    for (schemes[1 .. quorum + 1]) |*scheme| {
        try verifier.add(gpa, .{ .notarize = try notarize(S, scheme, round_one, 0, 1) }, false);
    }
    try testing.expectEqual(null, try verifier.try_construct_notarization(gpa, &rng, sequential));
    const leader = try notarize(S, &schemes[0], round_one, 0, 1);
    verifier.set_leader(leader.signer(), &leader);
    // The same leader again changes nothing.
    verifier.set_leader(leader.signer(), &leader);
    try testing.expectEqual(leader.signer(), verifier.leader().?);
    var batch = (try verifier.try_construct_notarization(gpa, &rng, sequential)).?;
    defer batch.deinit(gpa);
    try testing.expectEqual(quorum, batch.processed);
    const certificate = &batch.certificate.?;
    try testing.expect(try certificate.verify(gpa, &rng, &fixture.verifier, sequential));
    // A late leader vote after the certificate still records nothing, and nullifies keep
    // accumulating.
    try verifier.add(gpa, .{ .notarize = leader }, false);
    try testing.expectEqual(0, verifier.notarize.pending.items.len);
    const Nullify = types.Nullify(S);
    try verifier.add(gpa, .{ .nullify = (try Nullify.sign(gpa, &schemes[1], round_one)).? }, false);
    try testing.expectEqual(1, verifier.nullify.pending.items.len);
}

// commonware `test_ready_notarizes_without_leader_or_proposal`,
// `test_notarizes_wait_for_quorum`, `test_verify_{notarizes,nullifies,finalizes}_empty_pending`,
// `test_set_leader_twice_same_value_is_noop`, `test_ready_notarizes_exact_quorum`, and
// `test_late_leader_vote_after_certification`.
test "notarizes wait for a leader and a quorum, then assemble once" {
    inline for (cases) |C| try notarize_readiness(C);
}

fn verified_quorum(comptime C: type) !void {
    const S = C.Scheme;
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try C.fixture(gpa, &rng, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    const quorum = utils.N3f1.quorum(@as(u32, 5));
    var verifier = verifier_mod.Verifier(S, Digest).init(round_one, &schemes[0], quorum);
    defer verifier.deinit(gpa);
    const Nullify = types.Nullify(S);
    for (schemes, 0..) |*scheme, index| {
        const verified = index < quorum;
        try verifier.add(gpa, .{ .notarize = try notarize(S, scheme, round_one, 0, 1) }, verified);
        const nullify = (try Nullify.sign(gpa, scheme, round_one)).?;
        try verifier.add(gpa, .{ .nullify = nullify }, verified);
    }
    // Verified votes already meet the quorum: the pending ones are not verified.
    inline for (.{ "try_construct_notarization", "try_construct_nullification" }) |name| {
        var batch = (try @field(@TypeOf(verifier), name)(&verifier, gpa, &rng, sequential)).?;
        defer batch.deinit(gpa);
        try testing.expectEqual(0, batch.processed);
        const certificate = &batch.certificate.?;
        try testing.expect(try certificate.verify(gpa, &rng, &fixture.verifier, sequential));
    }
}

// commonware `test_ready_notarizes_quorum_already_met_by_verified` and
// `test_ready_nullifies_quorum_already_met_by_verified`.
test "a verified quorum assembles without verifying pending votes" {
    inline for (cases) |C| try verified_quorum(C);
}

// commonware `test_nonbatchable_finalize_accounting_tracks_proposal_override`: a scheme that
// verifies votes one at a time checks each finalize as it arrives, and a certificate for
// another proposal drops the finalizes already verified for the leader's.
test "non-batchable finalize accounting follows a proposal override" {
    const S = secp256r1.Scheme(Digest, PublicKey);
    comptime std.debug.assert(!S.is_batchable());
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try secp256r1.fixture(S, gpa, &rng, namespace, 5);
    defer fixture.deinit(gpa);
    const schemes = fixture.schemes;
    const quorum = utils.N3f1.quorum(@as(u32, 5));
    const round: Round = .new(.new(333), .new(7));
    var verifier = verifier_mod.Verifier(S, Digest).init(round, &schemes[0], quorum);
    defer verifier.deinit(gpa);
    const a: types.Proposal(Digest) = .init(round, .new(6), .fill(1));
    const b: types.Proposal(Digest) = .init(round, .new(6), .fill(2));
    const Finalize = types.Finalize(S, Digest);
    verifier.set_leader(.init(0), null);
    const leader = (try types.Notarize(S, Digest).sign(gpa, &schemes[0], a)).?;
    try verifier.add(gpa, .{ .notarize = leader }, false);
    try verifier.add(gpa, .{ .finalize = (try Finalize.sign(gpa, &schemes[0], a)).? }, false);
    try expect_one_valid(S, &verifier, &rng);
    try testing.expectEqual(1, verifier.finalize.verified.items.len);
    // The override drops the verified finalize for the old proposal.
    _ = verifier.set_proposal(.{ .certificate = b });
    try testing.expectEqual(0, verifier.finalize.verified.items.len);
    for (schemes[1..quorum]) |*scheme| {
        try verifier.add(gpa, .{ .finalize = (try Finalize.sign(gpa, scheme, b)).? }, false);
        try expect_one_valid(S, &verifier, &rng);
    }
    try testing.expectEqual(quorum - 1, verifier.finalize.verified.items.len);
    const last = (try Finalize.sign(gpa, &schemes[quorum], b)).?;
    try verifier.add(gpa, .{ .finalize = last }, false);
    var batch = (try verifier.try_construct_finalization(gpa, &rng, sequential)).?;
    defer batch.deinit(gpa);
    try testing.expectEqual(1, batch.processed);
    try testing.expect(batch.certificate != null);
    try testing.expect(verifier.has_certificate(.finalization));
}

/// One finalize verified eagerly, valid, and no certificate yet.
fn expect_one_valid(comptime S: type, verifier: anytype, rng: anytype) !void {
    const gpa = testing.allocator;
    var batch = (try verifier.try_construct_finalization(gpa, rng, sequential)).?;
    defer batch.deinit(gpa);
    try testing.expectEqual(1, batch.processed);
    try testing.expectEqual(0, batch.invalid.len);
    try testing.expect(batch.certificate == null);
    _ = S;
}
