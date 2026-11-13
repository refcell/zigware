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
