//! commonware `actors/batcher/mod.rs` Round tests that need a scheme other than ed25519:
//! optimistic assembly over trusted and pending votes, its fallback to per-vote
//! verification on an invalid share, and VRF seed corruption. BLS signing is slow in Debug,
//! so Debug without `-Dslow-tests` runs the ed25519 and secp256r1 cases only.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const assert = std.debug.assert;
const actor = @import("actor");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const round_mod = @import("round.zig");
const types_scheme_test = @import("../../types_scheme_test.zig");

const gpa = testing.allocator;
const Digest = cryptography.Sha256.Digest;
const Key = cryptography.ed25519.PublicKey;
const Participant = consensus_types.Participant;
const sequential = parallel.sequential;
const schemes = types_scheme_test.schemes;
/// Whether BLS schemes run: always outside Debug, and in Debug only with `-Dslow-tests`.
const bls = builtin.mode != .debug or build_options.slow_tests;

const Blocker = struct {
    pub const PublicKey = Key;
    pub fn block(_: Blocker, _: Key) actor.Feedback {
        return .ok;
    }
};

fn Reporter(comptime S: type) type {
    return struct {
        pub const Activity = types.Activity(S, Digest);
        pub fn report(_: @This(), _: Activity) actor.Feedback {
            return .ok;
        }
    };
}

fn RoundOf(comptime S: type) type {
    return round_mod.Round(S, Blocker, Digest, Reporter(S));
}

fn Setup(comptime entry: anytype) type {
    return struct {
        const S = entry[0];
        const Round = RoundOf(S);
        const Vote = types.Vote(S, Digest);
        const Kind = Round.Kind;
        const kinds = [_]Kind{ .notarization, .nullification, .finalization };

        fn fixture(namespace: []const u8, n: u32) !cryptography.certificate.mocks.Fixture(S) {
            var rng = utils.rng.test_rng();
            return entry[1](S, gpa, &rng, namespace, n);
        }

        /// commonware `sign_vote`: a vote of `kind` over `round` or `value`.
        fn sign(scheme: *const S, kind: Kind, value: types.Proposal(Digest)) !Vote {
            return switch (kind) {
                .notarization => .{
                    .notarize = (try types.Notarize(S, Digest).sign(gpa, scheme, value)).?,
                },
                .nullification => .{
                    .nullify = (try types.Nullify(S).sign(gpa, scheme, value.round)).?,
                },
                .finalization => .{
                    .finalize = (try types.Finalize(S, Digest).sign(gpa, scheme, value)).?,
                },
            };
        }

        fn signature(vote: *Vote) *@TypeOf(vote.nullify.attestation.signature) {
            return switch (vote.*) {
                inline else => |*inner| &inner.attestation.signature,
            };
        }

        /// A certificate of `kind` (notarization or finalization) over `value` from the
        /// first `count` signers.
        fn certificate(
            fixture_value: anytype,
            kind: Kind,
            value: types.Proposal(Digest),
            count: usize,
        ) !types.Certificate(S, Digest) {
            assert(kind != .nullification);
            assert(count <= 8);
            const scheme = &fixture_value.schemes[0];
            if (kind == .notarization) {
                var votes: [8]types.Notarize(S, Digest) = undefined;
                for (votes[0..count], fixture_value.schemes[0..count]) |*vote, *signer| {
                    vote.* = (try types.Notarize(S, Digest).sign(gpa, signer, value)).?;
                }
                const signed = votes[0..count];
                return .{ .notarization = try .from_votes(gpa, scheme, signed, sequential) };
            }
            var votes: [8]types.Finalize(S, Digest) = undefined;
            for (votes[0..count], fixture_value.schemes[0..count]) |*vote, *signer| {
                vote.* = (try types.Finalize(S, Digest).sign(gpa, signer, value)).?;
            }
            const signed = votes[0..count];
            return .{ .finalization = try .from_votes(gpa, scheme, signed, sequential) };
        }
    };
}

fn quorum_of(n: u32) u32 {
    assert(n > 0);
    return n - (n - 1) / 3;
}

fn proposal_at(epoch: u64, view: u64, fill: u8) types.Proposal(Digest) {
    assert(view > 0);
    return .init(.new(.new(epoch), .new(view)), .new(view - 1), .fill(fill));
}

/// commonware `certify_mixed_votes`: our trusted vote and pending network votes certify
/// each kind together without fallback; the certificate fixes the proposal against a
/// conflicting certificate, and a late vote cannot reopen certification.
fn certify_mixed_votes(comptime entry: anytype) !void {
    const T = Setup(entry);
    for (T.kinds) |kind| {
        var fixture = try T.fixture("batcher_optimistic_recovery", 5);
        defer fixture.deinit(gpa);
        const quorum = quorum_of(5);
        const value = proposal_at(9, 7, 0x0e);
        var round = T.Round.init(value.round, &fixture.schemes[0], .{}, .{}, false);
        defer round.deinit(gpa);
        if (kind == .notarization) round.set_leader(.init(0));
        const ours = try T.sign(&fixture.schemes[0], kind, value);
        const outcome = try round.accept_vote(gpa, ours, true);
        try testing.expect(outcome == .added and outcome.added.retained);
        for (1..quorum) |signer| {
            const vote = try T.sign(&fixture.schemes[signer], kind, value);
            try testing.expect(try round.add_network(gpa, fixture.participants[signer], vote));
        }
        var rng = utils.rng.test_rng();
        var batch = (try round.try_construct(gpa, &rng, sequential)).?;
        defer batch.deinit(gpa);
        try testing.expectEqual(quorum - 1, batch.processed);
        try testing.expectEqual(0, batch.invalid.len);
        try testing.expect(!batch.fallback);
        try testing.expectEqual(kind, std.meta.activeTag(batch.certificate.?));
        const certificate = &batch.certificate.?;
        try testing.expect(try certificate.verify(gpa, &rng, &fixture.schemes[0], sequential));
        try testing.expect(round.has_certificate(kind));
        if (kind != .nullification) {
            const other: T.Kind = if (kind == .notarization) .finalization else .notarization;
            const conflicting = proposal_at(9, 7, 0x0c);
            var rival = try T.certificate(&fixture, other, conflicting, quorum);
            defer rival.deinit(gpa);
            try testing.expect(!try round.record_certificate(gpa, &rival));
            try testing.expect(round.try_forward_proposal(.init(1)).?.eql(value));
        }
        const late = try T.sign(&fixture.schemes[quorum], kind, value);
        try testing.expect(try round.add_network(gpa, fixture.participants[quorum], late));
        try testing.expectEqual(null, try round.try_construct(gpa, &rng, sequential));
    }
}

// commonware `test_threshold_certifies_mixed_votes` (threshold standard and VRF).
test "batcher round certifies mixed trusted and pending votes on threshold schemes" {
    if (!bls) return;
    inline for (.{ 6, 7, 4, 5 }) |index| try certify_mixed_votes(schemes[index]);
}

/// commonware `optimistic_assembly_fallback`: an invalid share forces fallback, which keeps
/// the valid votes; with a spare valid vote the fallback certifies at once, otherwise an
/// invalid replacement falls back again and a valid one completes the quorum.
fn optimistic_assembly_fallback(comptime entry: anytype, valid_quorum: bool) !void {
    const T = Setup(entry);
    for (T.kinds) |kind| {
        const n = 7;
        var fixture = try T.fixture("batcher_optimistic_fallback", n);
        defer fixture.deinit(gpa);
        const quorum = quorum_of(n);
        const value = proposal_at(10, 8, 0xfa);
        var votes: [n]T.Vote = undefined;
        for (&votes, fixture.schemes) |*vote, *scheme| vote.* = try T.sign(scheme, kind, value);
        // Keep the claimed signers in range while using another participant's signature.
        const replacement = T.signature(&votes[n - 1]).*;
        const invalid: []const usize = if (valid_quorum) &.{0} else &.{ 0, quorum };
        for (invalid) |index| T.signature(&votes[index]).* = replacement;
        var round = T.Round.init(value.round, &fixture.schemes[0], .{}, .{}, false);
        defer round.deinit(gpa);
        if (kind == .notarization) round.set_leader(.init(0));
        if (kind == .finalization) {
            var notarization = try T.certificate(&fixture, .notarization, value, quorum);
            defer notarization.deinit(gpa);
            _ = try round.record_certificate(gpa, &notarization);
        }
        const batch_size = quorum + @intFromBool(valid_quorum);
        for (votes[0..batch_size], fixture.participants[0..batch_size]) |vote, peer| {
            try testing.expect(try round.add_network(gpa, peer, vote));
        }
        var rng = utils.rng.test_rng();
        var batch = (try round.try_construct(gpa, &rng, sequential)).?;
        defer batch.deinit(gpa);
        try testing.expectEqual(batch_size, batch.processed);
        try testing.expectEqualSlices(Participant, &.{.init(0)}, batch.invalid);
        try testing.expect(batch.fallback);
        try testing.expectEqual(valid_quorum, round.has_certificate(kind));
        if (!valid_quorum) {
            try testing.expectEqual(null, batch.certificate);
            for (quorum..n) |index| {
                try testing.expectEqual(null, try round.try_construct(gpa, &rng, sequential));
                const peer = fixture.participants[index];
                try testing.expect(try round.add_network(gpa, peer, votes[index]));
                batch.deinit(gpa);
                batch = (try round.try_construct(gpa, &rng, sequential)).?;
                try testing.expectEqual(1, batch.processed);
                try testing.expectEqual(index == quorum, batch.fallback);
                if (index == quorum) {
                    const expected: []const Participant = &.{.init(@intCast(index))};
                    try testing.expectEqualSlices(Participant, expected, batch.invalid);
                    try testing.expectEqual(null, batch.certificate);
                    try testing.expect(!round.has_certificate(kind));
                } else try testing.expectEqual(0, batch.invalid.len);
            }
        }
        const certificate = &batch.certificate.?;
        try testing.expectEqual(kind, std.meta.activeTag(certificate.*));
        try testing.expect(try certificate.verify(gpa, &rng, &fixture.schemes[0], sequential));
    }
}

// commonware `test_optimistic_assembly_fallback`, on every scheme.
test "batcher round falls back from optimistic assembly on an invalid share" {
    inline for (schemes, 0..) |entry, index| {
        if (bls or index < 2) {
            try optimistic_assembly_fallback(entry, false);
            try optimistic_assembly_fallback(entry, true);
        }
    }
}

// commonware `test_optimistic_assembly_after_other_kind_fails`: a failed notarization
// attempt (one invalid share) does not consume the ready nullify quorum.
test "batcher round assembles one kind after another kind's attempt fails" {
    if (!bls) return;
    const T = Setup(schemes[6]);
    var fixture = try T.fixture("batcher_optimistic_per_kind", 5);
    defer fixture.deinit(gpa);
    const quorum = quorum_of(5);
    const value = proposal_at(10, 9, 0x9a);
    var notarizes: [5]T.Vote = undefined;
    for (&notarizes, fixture.schemes) |*vote, *scheme| {
        vote.* = try T.sign(scheme, .notarization, value);
    }
    T.signature(&notarizes[0]).* = T.signature(&notarizes[quorum]).*;
    var round = T.Round.init(value.round, &fixture.schemes[0], .{}, .{}, false);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    for (0..quorum) |index| {
        const peer = fixture.participants[index];
        try testing.expect(try round.add_network(gpa, peer, notarizes[index]));
        const nullify = try T.sign(&fixture.schemes[index], .nullification, value);
        try testing.expect(try round.add_network(gpa, peer, nullify));
    }
    var rng = utils.rng.test_rng();
    var notarize = (try round.try_construct(gpa, &rng, sequential)).?;
    defer notarize.deinit(gpa);
    try testing.expect(notarize.fallback);
    try testing.expectEqual(null, notarize.certificate);
    try testing.expectEqualSlices(Participant, &.{.init(0)}, notarize.invalid);
    try testing.expect(!round.has_certificate(.notarization));
    var nullify = (try round.try_construct(gpa, &rng, sequential)).?;
    defer nullify.deinit(gpa);
    try testing.expect(nullify.certificate.? == .nullification);
    try testing.expect(round.has_certificate(.nullification));
}

/// commonware `vrf_seed_only_corruption`: a vote whose vote signature is valid but whose
/// seed signature comes from another round still fails, and fallback names its signer.
fn vrf_seed_only_corruption(comptime entry: anytype) !void {
    const T = Setup(entry);
    var fixture = try T.fixture("batcher_vrf_seed_corruption", 5);
    defer fixture.deinit(gpa);
    const quorum = quorum_of(5);
    const value = proposal_at(11, 9, 0x5e);
    var votes: [5]T.Vote = undefined;
    for (votes[0..quorum], fixture.schemes[0..quorum]) |*vote, *scheme| {
        vote.* = try T.sign(scheme, .notarization, value);
    }
    const other = try T.sign(&fixture.schemes[0], .notarization, proposal_at(11, 10, 0x07));
    var corrupted = T.signature(&votes[0]).get().?;
    corrupted.seed_signature = other.notarize.attestation.signature.get().?.seed_signature;
    T.signature(&votes[0]).* = .init(corrupted);
    var round = T.Round.init(value.round, &fixture.schemes[0], .{}, .{}, false);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    for (votes[0..quorum], fixture.participants[0..quorum]) |vote, peer| {
        try testing.expect(try round.add_network(gpa, peer, vote));
    }
    var rng = utils.rng.test_rng();
    var batch = (try round.try_construct(gpa, &rng, sequential)).?;
    defer batch.deinit(gpa);
    try testing.expect(batch.fallback);
    try testing.expectEqualSlices(Participant, &.{.init(0)}, batch.invalid);
}

// commonware `test_vrf_seed_only_corruption_triggers_fallback`.
test "batcher round falls back on a VRF seed-only corruption" {
    if (!bls) return;
    try vrf_seed_only_corruption(schemes[4]);
    try vrf_seed_only_corruption(schemes[5]);
}

/// commonware `constructed_quorum_without_leader`: in a one-participant committee our
/// vote is a quorum, which certifies before any leader update and then fixes the proposal.
fn constructed_quorum_without_leader(comptime entry: anytype) !void {
    const T = Setup(entry);
    var fixture = try T.fixture("batcher_test", 1);
    defer fixture.deinit(gpa);
    const value = proposal_at(0, 2, 0xc0);
    var round = T.Round.init(value.round, &fixture.schemes[0], .{}, .{}, false);
    defer round.deinit(gpa);
    _ = try round.accept_vote(gpa, try T.sign(&fixture.schemes[0], .notarization, value), true);
    try testing.expectEqual(null, round.try_forward_proposal(.init(0)));
    var rng = utils.rng.test_rng();
    var batch = (try round.try_construct(gpa, &rng, sequential)).?;
    defer batch.deinit(gpa);
    try testing.expectEqual(0, batch.processed);
    try testing.expectEqual(0, batch.invalid.len);
    try testing.expect(!batch.fallback);
    const certificate = &batch.certificate.?;
    try testing.expect(certificate.notarization.proposal.eql(value));
    try testing.expect(try certificate.verify(gpa, &rng, &fixture.schemes[0], sequential));
    try testing.expect(round.try_forward_proposal(.init(0)).?.eql(value));
    try testing.expect(round.has_certificate(.notarization));
    try testing.expectEqual(null, try round.try_construct(gpa, &rng, sequential));
}

// commonware `test_constructed_quorum_completes_before_leader_update` (ed25519 and
// threshold standard MinPk).
test "batcher round certifies a constructed quorum before the leader update" {
    try constructed_quorum_without_leader(schemes[0]);
    if (bls) try constructed_quorum_without_leader(schemes[6]);
}

// commonware `test_constructed_leader_notarize_is_not_reverified`: our trusted leader
// notarize and its network copy count once; the quorum completes with one more signer.
test "batcher round counts a constructed leader notarize once" {
    const T = Setup(schemes[0]);
    var fixture = try T.fixture("batcher_test", 5);
    defer fixture.deinit(gpa);
    const quorum = quorum_of(5);
    const value = proposal_at(0, 1, 0x1d);
    var round = T.Round.init(value.round, &fixture.schemes[0], .{}, .{}, false);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    const ours = try T.sign(&fixture.schemes[0], .notarization, value);
    const outcome = try round.accept_vote(gpa, ours, true);
    try testing.expect(outcome == .added and outcome.added.retained);
    try testing.expect(!try round.add_network(gpa, fixture.participants[0], ours));
    for (1..quorum - 1) |signer| {
        const vote = try T.sign(&fixture.schemes[signer], .notarization, value);
        try testing.expect(try round.add_network(gpa, fixture.participants[signer], vote));
    }
    var rng = utils.rng.test_rng();
    try testing.expectEqual(null, try round.try_construct(gpa, &rng, sequential));
    const last = try T.sign(&fixture.schemes[quorum - 1], .notarization, value);
    try testing.expect(try round.add_network(gpa, fixture.participants[quorum - 1], last));
    var batch = (try round.try_construct(gpa, &rng, sequential)).?;
    defer batch.deinit(gpa);
    try testing.expectEqual(quorum - 1, batch.processed);
    try testing.expectEqual(0, batch.invalid.len);
    try testing.expect(!batch.fallback);
    try testing.expect(batch.certificate.? == .notarization);
}

/// commonware `verify_and_construct`: a notarize from every participant verifies on
/// `strategy` and certifies without fallback; the certificate verifies under the
/// non-signing verifier, and the completed kind constructs nothing more.
fn verify_and_construct(comptime entry: anytype, strategy: anytype) !void {
    const T = Setup(entry);
    var fixture = try T.fixture("batcher_test", 5);
    defer fixture.deinit(gpa);
    const value = proposal_at(0, 1, 0x0f);
    var round = T.Round.init(value.round, &fixture.schemes[0], .{}, .{}, false);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    for (fixture.schemes, fixture.participants) |*scheme, peer| {
        const vote = try T.sign(scheme, .notarization, value);
        try testing.expect(try round.add_network(gpa, peer, vote));
    }
    var rng = utils.rng.test_rng();
    var batch = (try round.try_construct(gpa, &rng, strategy)).?;
    defer batch.deinit(gpa);
    try testing.expectEqual(5, batch.processed);
    try testing.expectEqual(0, batch.invalid.len);
    try testing.expect(!batch.fallback);
    const certificate = &batch.certificate.?;
    try testing.expect(certificate.notarization.proposal.eql(value));
    try testing.expect(try certificate.verify(gpa, &rng, &fixture.verifier, sequential));
    try testing.expectEqual(null, try round.try_construct(gpa, &rng, strategy));
}

// commonware `test_offload_on_multithreaded_pool`: verification and construction run on a
// two-worker pool, so jobs finish on pool threads.
test "batcher round verifies and constructs on a multithreaded pool" {
    const pool = try parallel.ThreadPool.create(gpa, testing.io, .{ .threads = 2 });
    defer pool.destroy();
    const strategy = parallel.Rayon.init(pool);
    if (bls) try verify_and_construct(schemes[4], strategy);
    if (bls) try verify_and_construct(schemes[3], strategy);
    try verify_and_construct(schemes[0], strategy);
    try verify_and_construct(schemes[1], strategy);
}
