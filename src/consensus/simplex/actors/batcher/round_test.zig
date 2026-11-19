//! Tests for the batcher round: fault detection, blocking, reporting, and construction.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const round_mod = @import("round.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const Key = cryptography.ed25519.PublicKey;
const ActivityType = types.Activity(Scheme, Digest);
const sequential = parallel.sequential;

const Log = struct {
    blocked: std.ArrayList(Key) = .empty,
    activities: std.ArrayList(std.meta.Tag(ActivityType)) = .empty,

    fn deinit(self: *Log) void {
        self.blocked.deinit(testing.allocator);
        self.activities.deinit(testing.allocator);
    }
};

const Blocker = struct {
    log: *Log,
    pub const PublicKey = Key;
    pub fn block(self: Blocker, peer: Key) actor.Feedback {
        self.log.blocked.append(testing.allocator, peer) catch @panic("out of memory");
        return .ok;
    }
};

const Reporter = struct {
    log: *Log,
    pub const Activity = ActivityType;
    pub fn report(self: Reporter, activity: ActivityType) actor.Feedback {
        const tag = std.meta.activeTag(activity);
        self.log.activities.append(testing.allocator, tag) catch @panic("out of memory");
        return .ok;
    }
};

const Round = round_mod.Round(Scheme, Blocker, Digest, Reporter);
const at: consensus_types.Round = .new(.new(0), .new(1));

fn proposal(payload: u8) types.Proposal(Digest) {
    return .init(at, .zero(), .fill(payload));
}

test "round reports votes and detects conflicts" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "round", 4);
    defer fixture.deinit(gpa);
    var log: Log = .{};
    defer log.deinit();
    var round = Round.init(at, &fixture.schemes[0], .{ .log = &log }, .{ .log = &log }, false);
    defer round.deinit(gpa);
    const Notarize = types.Notarize(Scheme, Digest);
    const Nullify = types.Nullify(Scheme);
    const Finalize = types.Finalize(Scheme, Digest);
    const peer = fixture.participants[1];
    const scheme = &fixture.schemes[1];

    const first = (try Notarize.sign(gpa, scheme, proposal(1))).?;
    try testing.expect(try round.add_network(gpa, peer, .{ .notarize = first }));
    try testing.expect(!try round.add_network(gpa, peer, .{ .notarize = first }));
    try testing.expectEqual(0, log.blocked.items.len);
    // A second proposal from the same signer is reported and blocked.
    const second = (try Notarize.sign(gpa, scheme, proposal(2))).?;
    try testing.expect(!try round.add_network(gpa, peer, .{ .notarize = second }));
    try testing.expectEqual(1, log.blocked.items.len);
    // A vote whose signer is not its sender is blocked without being recorded.
    const impostor = fixture.participants[2];
    try testing.expect(!try round.add_network(gpa, impostor, .{ .notarize = first }));
    try testing.expectEqual(2, log.blocked.items.len);
    // Finalize, then nullify: a NullifyFinalize fault.
    const finalize = (try Finalize.sign(gpa, scheme, proposal(1))).?;
    try testing.expect(try round.add_network(gpa, peer, .{ .finalize = finalize }));
    const nullify = (try Nullify.sign(gpa, scheme, at)).?;
    try testing.expect(!try round.add_network(gpa, peer, .{ .nullify = nullify }));
    try testing.expectEqual(3, log.blocked.items.len);
    const expected = [_]std.meta.Tag(ActivityType){
        .notarize,
        .conflicting_notarize,
        .finalize,
        .nullify_finalize,
    };
    try testing.expectEqualSlices(std.meta.Tag(ActivityType), &expected, log.activities.items);
}

test "round constructs a notarization once the leader's proposal is known" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "round", 4);
    defer fixture.deinit(gpa);
    var log: Log = .{};
    defer log.deinit();
    var round = Round.init(at, &fixture.schemes[0], .{ .log = &log }, .{ .log = &log }, false);
    defer round.deinit(gpa);
    const Notarize = types.Notarize(Scheme, Digest);
    round.set_leader(.init(1));
    for (fixture.schemes[1..], fixture.participants[1..]) |*scheme, peer| {
        const vote = (try Notarize.sign(gpa, scheme, proposal(5))).?;
        try testing.expect(try round.add_network(gpa, peer, .{ .notarize = vote }));
    }
    try testing.expect(round.try_forward_proposal(.init(0)).?.eql(proposal(5)));
    try testing.expectEqual(null, round.try_forward_proposal(.init(0)));
    var batch = (try round.try_construct(gpa, &rng, sequential)).?;
    defer batch.deinit(gpa);
    try testing.expect(batch.certificate.? == .notarization);
    try testing.expect(round.has_certificate(.notarization));
    // The votes were released, but who voted for the proposal is remembered.
    const known = proposal(5);
    try testing.expect(!round.is_missing_voter(&known, .init(2)));
    const missing = try round.missing_voters(gpa, &known);
    defer gpa.free(missing);
    try testing.expectEqual(1, missing.len);
    try testing.expectEqual(0, missing[0].get());
    try testing.expectEqual(null, try round.try_construct(gpa, &rng, sequential));
}

/// A certificate of `kind` over `payload` from the first `count` of `fixture`'s schemes.
fn build_certificate(
    fixture: anytype,
    comptime kind: enum { notarization, finalization },
    payload: u8,
    count: usize,
) !types.Certificate(Scheme, Digest) {
    const gpa = testing.allocator;
    const Vote = switch (kind) {
        .notarization => types.Notarize(Scheme, Digest),
        .finalization => types.Finalize(Scheme, Digest),
    };
    var votes: [8]Vote = undefined;
    for (votes[0..count], fixture.schemes[0..count]) |*vote, *scheme| {
        vote.* = (try Vote.sign(gpa, scheme, proposal(payload))).?;
    }
    const scheme = &fixture.schemes[0];
    const signed = votes[0..count];
    return switch (kind) {
        .notarization => .{ .notarization = try .from_votes(gpa, scheme, signed, sequential) },
        .finalization => .{ .finalization = try .from_votes(gpa, scheme, signed, sequential) },
    };
}

// commonware `test_forward_proposal_from_notarization_without_leader`: a verified
// notarization establishes the proposal, which is forwarded before the leader is known.
test "round forwards a notarization's proposal before the leader is known" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "batcher_test", 5);
    defer fixture.deinit(gpa);
    var log: Log = .{};
    defer log.deinit();
    var round = Round.init(at, &fixture.schemes[1], .{ .log = &log }, .{ .log = &log }, false);
    defer round.deinit(gpa);
    const Notarize = types.Notarize(Scheme, Digest);
    const vote = (try Notarize.sign(gpa, &fixture.schemes[0], proposal(1))).?;
    try testing.expect(try round.add_network(gpa, fixture.participants[0], .{ .notarize = vote }));
    var certificate = try build_certificate(&fixture, .notarization, 1, utils.N3f1.quorum(5));
    defer certificate.deinit(gpa);
    _ = try round.record_certificate(gpa, &certificate);
    try testing.expect(round.has_certificate(.notarization));
    try testing.expect(round.try_forward_proposal(.init(1)).?.eql(proposal(1)));
}

/// commonware `certified_conflict_outcome`: a signer's vote, a certificate for the
/// proposal, then the signer's vote for the other one; returns whether the conflict was
/// reported and whether the signer was blocked.
fn certified_conflict(
    track_historical_votes: bool,
    comptime kind: enum { notarization, finalization },
    first_matches: bool,
) !struct { bool, bool } {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "batcher_test", 5);
    defer fixture.deinit(gpa);
    var log: Log = .{};
    defer log.deinit();
    const scheme = &fixture.schemes[0];
    const historical = track_historical_votes;
    var round = Round.init(at, scheme, .{ .log = &log }, .{ .log = &log }, historical);
    defer round.deinit(gpa);
    const first: u8 = if (first_matches) 1 else 2;
    const second: u8 = if (first_matches) 2 else 1;
    const peer = fixture.participants[0];
    const Vote = switch (kind) {
        .notarization => types.Notarize(Scheme, Digest),
        .finalization => types.Finalize(Scheme, Digest),
    };
    const tag = switch (kind) {
        .notarization => "notarize",
        .finalization => "finalize",
    };
    const Any = types.Vote(Scheme, Digest);
    const early = (try Vote.sign(gpa, scheme, proposal(first))).?;
    try testing.expect(try round.add_network(gpa, peer, @unionInit(Any, tag, early)));
    var certificate = try build_certificate(&fixture, switch (kind) {
        .notarization => .notarization,
        .finalization => .finalization,
    }, 1, utils.N3f1.quorum(5));
    defer certificate.deinit(gpa);
    _ = try round.record_certificate(gpa, &certificate);
    const late = (try Vote.sign(gpa, scheme, proposal(second))).?;
    try testing.expect(!try round.add_network(gpa, peer, @unionInit(Any, tag, late)));
    const conflict: std.meta.Tag(ActivityType) = switch (kind) {
        .notarization => .conflicting_notarize,
        .finalization => .conflicting_finalize,
    };
    const Tag = std.meta.Tag(ActivityType);
    const reported = std.mem.indexOfScalar(Tag, log.activities.items, conflict) != null;
    const blocked = for (log.blocked.items) |key| {
        if (key.eql(peer)) break true;
    } else false;
    return .{ reported, blocked };
}

// commonware `test_certificate_releases_votes_without_retention` and
// `test_certificate_retains_votes_when_configured`: once a certificate releases the votes, a
// conflicting vote still blocks its signer, and is reported as a fault only when historical
// votes are kept.
test "a certificate releases or retains votes, and a later conflict still blocks" {
    for ([_]bool{ false, true }) |retain| {
        inline for (.{ .notarization, .finalization }) |kind| {
            for ([_]bool{ false, true }) |first_matches| {
                const reported, const blocked = try certified_conflict(retain, kind, first_matches);
                try testing.expectEqual(retain, reported);
                try testing.expect(blocked);
            }
        }
    }
}

fn build_nullification(fixture: anytype, count: usize) !types.Certificate(Scheme, Digest) {
    const gpa = testing.allocator;
    const Nullify = types.Nullify(Scheme);
    var votes: [8]Nullify = undefined;
    for (votes[0..count], fixture.schemes[0..count]) |*vote, *scheme| {
        vote.* = (try Nullify.sign(gpa, scheme, at)).?;
    }
    const scheme = &fixture.schemes[0];
    return .{ .nullification = try .from_votes(gpa, scheme, votes[0..count], sequential) };
}

fn count_activities(log: *const Log, tag: std.meta.Tag(ActivityType)) usize {
    var total: usize = 0;
    for (log.activities.items) |activity| total += @intFromBool(activity == tag);
    return total;
}

const Harness = struct {
    fixture: cryptography.certificate.mocks.Fixture(Scheme),
    log: Log = .{},

    fn init(self: *Harness) !void {
        var rng = utils.rng.test_rng();
        const fixture = try ed25519.fixture(Digest, testing.allocator, &rng, "batcher_test", 5);
        self.* = .{ .fixture = fixture };
    }

    fn deinit(self: *Harness) void {
        self.log.deinit();
        self.fixture.deinit(testing.allocator);
    }

    fn round(self: *Harness, me: usize) Round {
        const log = &self.log;
        return Round.init(at, &self.fixture.schemes[me], .{ .log = log }, .{ .log = log }, false);
    }

    fn nullify(self: *Harness, signer: usize) !types.Vote(Scheme, Digest) {
        const scheme = &self.fixture.schemes[signer];
        const vote = try types.Nullify(Scheme).sign(testing.allocator, scheme, at);
        return .{ .nullify = vote.? };
    }

    fn finalize(self: *Harness, signer: usize, payload: u8) !types.Vote(Scheme, Digest) {
        const scheme = &self.fixture.schemes[signer];
        const Finalize = types.Finalize(Scheme, Digest);
        return .{ .finalize = (try Finalize.sign(testing.allocator, scheme, proposal(payload))).? };
    }

    fn notarize(self: *Harness, signer: usize, payload: u8) !types.Vote(Scheme, Digest) {
        const scheme = &self.fixture.schemes[signer];
        const Notarize = types.Notarize(Scheme, Digest);
        return .{ .notarize = (try Notarize.sign(testing.allocator, scheme, proposal(payload))).? };
    }

    fn peer(self: *const Harness, index: usize) Key {
        return self.fixture.participants[index];
    }
};

// commonware `test_nullify_finalize_conflicts_reported_while_evidence_available`: a nullify
// and a finalize from one signer are reported in either order, and against a certificate's
// released votes while the signer's own vote is still held.
test "round reports nullify-finalize conflicts while the evidence is held" {
    const gpa = testing.allocator;
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const quorum = utils.N3f1.quorum(5);
    {
        var round = h.round(0);
        defer round.deinit(gpa);
        try testing.expect(try round.add_network(gpa, h.peer(1), try h.finalize(1, 1)));
        try testing.expect(!try round.add_network(gpa, h.peer(1), try h.nullify(1)));
        try testing.expect(try round.add_network(gpa, h.peer(2), try h.nullify(2)));
        try testing.expect(!try round.add_network(gpa, h.peer(2), try h.finalize(2, 1)));
    }
    {
        var round = h.round(0);
        defer round.deinit(gpa);
        try testing.expect(try round.add_network(gpa, h.peer(1), try h.finalize(1, 1)));
        var nullification = try build_nullification(&h.fixture, quorum);
        defer nullification.deinit(gpa);
        _ = try round.record_certificate(gpa, &nullification);
        try testing.expect(!try round.add_network(gpa, h.peer(1), try h.nullify(1)));
    }
    {
        var round = h.round(0);
        defer round.deinit(gpa);
        try testing.expect(try round.add_network(gpa, h.peer(2), try h.nullify(2)));
        var finalization = try build_certificate(&h.fixture, .finalization, 1, quorum);
        defer finalization.deinit(gpa);
        _ = try round.record_certificate(gpa, &finalization);
        try testing.expect(!try round.add_network(gpa, h.peer(2), try h.finalize(2, 1)));
    }
    try testing.expectEqual(4, count_activities(&h.log, .nullify_finalize));
}

// commonware `test_compacted_votes_still_block_nullify_finalize_conflicts`.
test "round blocks nullify-finalize conflicts after a certificate compacts the votes" {
    const gpa = testing.allocator;
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const quorum = utils.N3f1.quorum(5);
    {
        var round = h.round(0);
        defer round.deinit(gpa);
        try testing.expect(try round.add_network(gpa, h.peer(1), try h.nullify(1)));
        var nullification = try build_nullification(&h.fixture, quorum);
        defer nullification.deinit(gpa);
        _ = try round.record_certificate(gpa, &nullification);
        try testing.expect(!try round.add_network(gpa, h.peer(1), try h.finalize(1, 1)));
    }
    {
        var round = h.round(0);
        defer round.deinit(gpa);
        try testing.expect(try round.add_network(gpa, h.peer(2), try h.finalize(2, 1)));
        var finalization = try build_certificate(&h.fixture, .finalization, 1, quorum);
        defer finalization.deinit(gpa);
        _ = try round.record_certificate(gpa, &finalization);
        try testing.expect(!try round.add_network(gpa, h.peer(2), try h.nullify(2)));
    }
}

// commonware `test_constructed_votes_reported_after_existing_certificates` and
// `test_nullify_retry_after_certificate_is_not_reported_twice`: our own votes are reported
// once each, even after a certificate of their kind.
test "round reports our own votes once, even after their certificates" {
    const gpa = testing.allocator;
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const quorum = utils.N3f1.quorum(5);
    var round = h.round(0);
    defer round.deinit(gpa);
    var notarization = try build_certificate(&h.fixture, .notarization, 1, quorum);
    defer notarization.deinit(gpa);
    _ = try round.record_certificate(gpa, &notarization);
    _ = try round.accept_vote(gpa, try h.notarize(0, 1), true);
    _ = try round.accept_vote(gpa, try h.nullify(0), true);
    var nullification = try build_nullification(&h.fixture, quorum);
    defer nullification.deinit(gpa);
    _ = try round.record_certificate(gpa, &nullification);
    // A nullify retry after the certificate is not reported again.
    _ = try round.accept_vote(gpa, try h.nullify(0), true);
    var finalization = try build_certificate(&h.fixture, .finalization, 1, quorum);
    defer finalization.deinit(gpa);
    _ = try round.record_certificate(gpa, &finalization);
    _ = try round.accept_vote(gpa, try h.finalize(0, 1), true);
    try testing.expectEqual(1, count_activities(&h.log, .notarize));
    try testing.expectEqual(1, count_activities(&h.log, .nullify));
    try testing.expectEqual(1, count_activities(&h.log, .finalize));
}

// commonware `test_finalization_establishes_proposal` and
// `test_constructed_finalize_establishes_proposal`.
test "a finalization or our own finalize establishes the proposal" {
    const gpa = testing.allocator;
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    {
        var round = h.round(1);
        defer round.deinit(gpa);
        // The leader's buffered notarize selects its proposal; the finalization replaces it.
        try testing.expect(try round.add_network(gpa, h.peer(0), try h.notarize(0, 1)));
        round.set_leader(.init(0));
        const quorum = utils.N3f1.quorum(5);
        var finalization = try build_certificate(&h.fixture, .finalization, 2, quorum);
        defer finalization.deinit(gpa);
        try testing.expect(!try round.record_certificate(gpa, &finalization));
        try testing.expect(round.has_certificate(.finalization));
        try testing.expect(round.try_forward_proposal(.init(1)).?.eql(proposal(2)));
    }
    {
        var round = h.round(0);
        defer round.deinit(gpa);
        _ = try round.accept_vote(gpa, try h.finalize(0, 3), true);
        try testing.expect(round.try_forward_proposal(.init(0)).?.eql(proposal(3)));
    }
}

// commonware `test_skipped_round_reports_without_retaining`: a skipped view's round reports
// and deduplicates votes but keeps none, so a full quorum assembles nothing there.
test "a skipped round reports votes once without retaining them" {
    const gpa = testing.allocator;
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const log = &h.log;
    var round = Round.skipped(at, &h.fixture.schemes[0], .{ .log = log }, .{ .log = log });
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    for (0..5) |index| {
        const vote = try h.notarize(index, 1);
        try testing.expect(try round.add_network(gpa, h.peer(index), vote));
        try testing.expect(!try round.add_network(gpa, h.peer(index), vote));
    }
    try testing.expectEqual(5, h.log.activities.items.len);
    var rng = utils.rng.test_rng();
    try testing.expectEqual(null, try round.try_construct(gpa, &rng, sequential));
    try testing.expectEqual(null, round.try_forward_proposal(.init(4)));
}

// commonware `test_skipped_round_redelivery_across_certificate_is_not_conflict`: a vote
// remembered before the proposal was known is a duplicate when redelivered after a
// certificate, while a vote for another proposal is then a conflict.
test "a skipped round's redelivered vote across a certificate is a duplicate" {
    const gpa = testing.allocator;
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const log = &h.log;
    var round = Round.skipped(at, &h.fixture.schemes[0], .{ .log = log }, .{ .log = log });
    defer round.deinit(gpa);
    const vote = try h.notarize(1, 1);
    try testing.expect(try round.add_network(gpa, h.peer(1), vote));
    var notarization = try build_certificate(&h.fixture, .notarization, 1, 4);
    defer notarization.deinit(gpa);
    _ = try round.record_certificate(gpa, &notarization);
    try testing.expect(!try round.add_network(gpa, h.peer(1), vote));
    try testing.expectEqual(0, h.log.blocked.items.len);
    try testing.expect(!try round.add_network(gpa, h.peer(1), try h.notarize(1, 2)));
    try testing.expectEqual(1, h.log.blocked.items.len);
    try testing.expect(h.log.blocked.items[0].eql(h.peer(1)));
}

// commonware `test_conflicting_finalize_creates_evidence` (round level): finalizes for two
// proposals from one signer are reported as a fault and block it.
test "round reports conflicting finalizes as evidence" {
    const gpa = testing.allocator;
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var round = h.round(0);
    defer round.deinit(gpa);
    try testing.expect(try round.add_network(gpa, h.peer(1), try h.finalize(1, 1)));
    try testing.expect(!try round.add_network(gpa, h.peer(1), try h.finalize(1, 2)));
    try testing.expectEqual(1, count_activities(&h.log, .conflicting_finalize));
    try testing.expectEqual(1, h.log.blocked.items.len);
}
