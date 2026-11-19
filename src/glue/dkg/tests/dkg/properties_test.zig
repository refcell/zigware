//! Checks of `DkgOutcome` against hand-built participant states: it accepts a consistent
//! success or failure and rejects each way a ceremony can go wrong.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const properties = @import("properties.zig");

const Epoch = consensus.Epoch;
const Set = utils.ordered.Set;
const ed25519 = cryptography.ed25519;
const P = ed25519.PublicKey;
const MinPk = cryptography.bls12381.primitives.MinPk;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Info = properties.Info;

const State = struct {
    done: bool = true,
    artifact: ?Info = null,
    share: bool = true,

    pub fn completed(self: *const State) bool {
        return self.done;
    }

    pub fn info(self: *const State) ?*const Info {
        return if (self.artifact) |*artifact| artifact else null;
    }

    pub fn has_share(self: *const State, epoch: Epoch) bool {
        std.debug.assert(epoch.get() == 0);
        return self.share;
    }
};

const Success = properties.DkgOutcome(State, .success);
const Failure = properties.DkgOutcome(State, .failure);

fn participants(gpa: Allocator, count: u64) !Set(P) {
    var keys: std.ArrayList(P) = .empty;
    defer keys.deinit(gpa);
    for (0..count) |seed| try keys.append(gpa, ed25519.PrivateKey.from_seed(seed).public_key());
    return Set(P).from_dedup(gpa, keys.items);
}

fn output(gpa: Allocator, players: Set(P), seed: u64) !fd.Output(MinPk, P) {
    var rng = utils.rng.TestRng.init(seed);
    var dealt = try fd.deal(MinPk, P, utils.N3f1, gpa, &rng, .non_zero_counter, players);
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    return dealt.output;
}

/// An epoch-zero artifact over `players`, with the output dealt from `seed`.
fn make_artifact(gpa: Allocator, players: Set(P), seed: u64) !Info {
    return .{
        .outcome = .success,
        .epoch = Epoch.zero(),
        .output = try output(gpa, try players.clone(gpa), seed),
        .players = try players.clone(gpa),
        .next_players = .empty,
        .directory = .{},
    };
}

const Fixture = struct {
    gpa: Allocator,
    players: Set(P),
    states: [4]State,
    tracker: Success.Tracker,

    fn init(gpa: Allocator) !Fixture {
        const players = try participants(gpa, 4);
        var fixture: Fixture = .{
            .gpa = gpa,
            .players = players,
            .states = undefined,
            .tracker = .init(gpa),
        };
        var first = try make_artifact(gpa, players, 7);
        errdefer first.deinit(gpa);
        for (&fixture.states, 0..) |*state, index| {
            state.* = .{ .artifact = if (index == 0) first else try first.clone(gpa) };
        }
        return fixture;
    }

    fn deinit(self: *Fixture) void {
        for (&self.states) |*state| if (state.artifact) |*info| info.deinit(self.gpa);
        self.players.deinit(self.gpa);
        self.tracker.deinit();
    }

    fn check(self: *Fixture, comptime Property: type) !void {
        var pointers: [4]*const State = undefined;
        for (&pointers, &self.states) |*pointer, *state| pointer.* = state;
        const property: Property = .{ .participants = self.players };
        return property.check(&self.tracker, &pointers);
    }

    fn replace(self: *Fixture, index: usize, info: ?Info) void {
        if (self.states[index].artifact) |*old| old.deinit(self.gpa);
        self.states[index].artifact = info;
    }
};

test "dkg outcome accepts agreeing successes" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.check(Success);
    try testing.expectError(error.FailedWithInfo, fixture.check(Failure));
}

test "dkg outcome rejects a diverging, missing, or shareless success" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();
    fixture.replace(2, try make_artifact(gpa, fixture.players, 8));
    try testing.expectError(error.OutputsDiffer, fixture.check(Success));
    fixture.replace(2, null);
    try testing.expectError(error.MissingInfo, fixture.check(Success));
    fixture.replace(2, try make_artifact(gpa, fixture.players, 7));
    fixture.states[3].share = false;
    try testing.expectError(error.MissingShare, fixture.check(Success));
    fixture.states[3].share = true;
    fixture.states[1].done = false;
    try testing.expectError(error.NotCompleted, fixture.check(Success));
}

test "dkg outcome rejects malformed artifacts" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();
    const info = &fixture.states[1].artifact.?;
    info.epoch = .new(1);
    try testing.expectError(error.UnexpectedEpoch, fixture.check(Success));
    info.epoch = Epoch.zero();
    info.outcome = .failure;
    try testing.expectError(error.UnexpectedOutcome, fixture.check(Success));
    info.outcome = .success;
    var others = try participants(gpa, 3);
    std.mem.swap(Set(P), &info.players, &others);
    try testing.expectError(error.InfoPlayers, fixture.check(Success));
    std.mem.swap(Set(P), &info.players, &others);
    std.mem.swap(Set(P), &info.next_players, &others);
    try testing.expectError(error.NextPlayers, fixture.check(Success));
    std.mem.swap(Set(P), &info.next_players, &others);
    others.deinit(gpa);
    try fixture.check(Success);
}

test "dkg outcome accepts a clean failure and rejects a persisted share" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit();
    for (0..4) |index| fixture.replace(index, null);
    for (&fixture.states) |*state| state.share = false;
    try fixture.check(Failure);
    try testing.expectError(error.MissingInfo, fixture.check(Success));
    fixture.states[0].share = true;
    try testing.expectError(error.FailedWithShare, fixture.check(Failure));
}
