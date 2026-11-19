//! commonware `glue/src/stateful/actor/syncer/plan.rs` tests. Restarts reopen the plan on the
//! same storage. `complete_height_cannot_move_backward` checks a panic, an assertion here.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const plan_mod = @import("plan.zig");

const gpa = testing.allocator;
const Digest = cryptography.Sha256.Digest;
const ed25519 = consensus.simplex.scheme.ed25519;
const S = ed25519.Scheme(Digest);
const types = consensus.simplex.types;
const Proposal = types.Proposal(Digest);
const Height = consensus.types.Height;
const V = struct {
    pub const Commitment = Digest;
};
const Plan = plan_mod.SyncPlan(S, V);
const Finalization = Plan.Finalization;
const Fixture = cryptography.certificate.mocks.Fixture(S);

const Env = struct {
    gpa: std.mem.Allocator,
    storage: runtime.storage.Storage,
};

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    fixture: Fixture,

    fn init(harness: *Harness) !void {
        var rng = utils.rng.test_rng();
        harness.* = .{
            .storage = .init(gpa),
            .fixture = try ed25519.fixture(Digest, gpa, &rng, "_COMMONWARE_GLUE_SYNC_PLAN", 1),
        };
    }

    fn deinit(harness: *Harness) void {
        harness.fixture.deinit(gpa);
        harness.storage.deinit();
    }

    /// Opens (or reopens, after a restart) the plan stored under `prefix`.
    fn open(harness: *Harness, prefix: []const u8) !Plan {
        const env: Env = .{ .gpa = gpa, .storage = harness.storage.interface() };
        return Plan.init(env, prefix);
    }

    /// commonware's `finalization(schemes, view, digest_byte)` at epoch 0.
    fn finalization(harness: *Harness, view: u64, digest_byte: u8) !Finalization {
        const round: consensus.Round = .new(.zero(), .new(view));
        const proposal = Proposal.init(round, .new(view -| 1), .fill(digest_byte));
        const subject: types.Subject(Digest) = .{ .finalize = &proposal };
        var votes: [1]S.Attestation = undefined;
        for (&votes, harness.fixture.schemes) |*vote, *scheme| {
            vote.* = (try scheme.sign(gpa, subject)).?;
        }
        const scheme = &harness.fixture.schemes[0];
        const certificate = try scheme.assemble(gpa, &votes, parallel.sequential);
        return .{ .proposal = proposal, .certificate = certificate };
    }
};

fn expect_floor(plan: *const Plan, expected: ?*const Finalization) !void {
    const floor = plan.floor();
    try testing.expectEqual(expected == null, floor == null);
    if (expected) |value| try testing.expect(floor.?.eql(value.*));
}

test "stateful sync plan: a selected floor survives restarts before the actors start" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var previous: ?Finalization = null;
    defer if (previous) |*p| p.deinit(gpa);
    for (0..3) |boot| {
        // Each restart finds the previous boot's selection without a request.
        var plan = try harness.open("selected_floor_before_actor_start");
        defer plan.deinit();
        if (previous) |*p| {
            try testing.expect(plan.should_sync(false));
            try expect_floor(&plan, p);
        }
        // Select a newer floor for marshal, then stop before either actor starts.
        var selected = try harness.finalization(7 + boot, @intCast(7 + boot));
        errdefer selected.deinit(gpa);
        try plan.set_floor(&selected);
        var start = try plan.marshal_start(void, {});
        defer if (start == .floor) start.floor.deinit(gpa);
        try testing.expect(start == .floor and start.floor.eql(selected));
        if (previous) |*p| p.deinit(gpa);
        previous = selected;
    }
}

test "stateful sync plan: stored completion disables state sync" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    {
        var plan = try harness.open("stored_completion");
        defer plan.deinit();
        try testing.expect(plan.may_sync());
        try testing.expect(plan.should_sync(true));
        try testing.expect(!plan.should_sync(false));
        try testing.expectEqual(null, plan.completed());
        try plan.set_completed(.new(7));
    }
    var plan = try harness.open("stored_completion");
    defer plan.deinit();
    try testing.expect(!plan.may_sync());
    try testing.expect(!plan.should_sync(true));
    try testing.expectEqual(7, plan.completed().?.get());
    try expect_floor(&plan, null);

    // A completed sync ignores a later selection instead of persisting it.
    var later = try harness.finalization(8, 8);
    defer later.deinit(gpa);
    try plan.set_floor(&later);
    try expect_floor(&plan, null);
    try testing.expectEqual(7, plan.completed().?.get());
    const start = try plan.marshal_start(u8, 42);
    try testing.expectEqual(42, start.genesis);
}

test "stateful sync plan: an in-progress sync persists a newer resume floor" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var stored = try harness.finalization(7, 7);
    defer stored.deinit(gpa);
    {
        var plan = try harness.open("in_progress");
        defer plan.deinit();
        try plan.set_floor(&stored);
    }
    var plan = try harness.open("in_progress");
    defer plan.deinit();
    try testing.expect(plan.may_sync());
    try testing.expect(plan.should_sync(false));
    try plan.set_floor(&stored);
    var newer = try harness.finalization(9, 9);
    defer newer.deinit(gpa);
    try plan.set_floor(&newer);
    try expect_floor(&plan, &newer);
}

test "stateful sync plan: an interrupted sync keeps its floor when the probe lags" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const prefix = "interrupted_sync";
    var stored = try harness.finalization(7, 7);
    defer stored.deinit(gpa);
    {
        var plan = try harness.open(prefix);
        defer plan.deinit();
        try plan.set_floor(&stored);
    }
    {
        var plan = try harness.open(prefix);
        defer plan.deinit();
        try testing.expect(plan.should_sync(false));
        try expect_floor(&plan, &stored);
        var start = try plan.marshal_start(void, {});
        defer start.floor.deinit(gpa);
        try testing.expect(start.floor.eql(stored));
    }
    {
        // A lagging probe must not replace the persisted in-progress floor.
        var plan = try harness.open(prefix);
        defer plan.deinit();
        var lagging = try harness.finalization(6, 6);
        defer lagging.deinit(gpa);
        try plan.set_floor(&lagging);
        try expect_floor(&plan, &stored);
    }
    var plan = try harness.open(prefix);
    defer plan.deinit();
    var newer = try harness.finalization(9, 9);
    defer newer.deinit(gpa);
    try plan.set_floor(&newer);
    try expect_floor(&plan, &newer);
}

test "stateful sync plan: set_floor does not replace a newer selection" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var plan = try harness.open("newer_selection");
    defer plan.deinit();
    var newer = try harness.finalization(9, 9);
    defer newer.deinit(gpa);
    var older = try harness.finalization(8, 8);
    defer older.deinit(gpa);
    try plan.set_floor(&newer);
    try plan.set_floor(&older);
    try expect_floor(&plan, &newer);
}

test "stateful sync plan: set_floor ignores a selection at the persisted round" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var plan = try harness.open("persisted_round");
    defer plan.deinit();
    var stored = try harness.finalization(7, 7);
    defer stored.deinit(gpa);
    var other = try harness.finalization(7, 8); // Same round, another payload.
    defer other.deinit(gpa);
    try plan.set_floor(&stored);
    try plan.set_floor(&other);
    try expect_floor(&plan, &stored);
}

test "stateful sync plan: a completed height cannot move backward" {
    // commonware `syncer/plan.rs complete_height_cannot_move_backward` (#[should_panic]);
    // zigware asserts.
    try utils.death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            var harness: Harness = undefined;
            try harness.init();
            defer harness.deinit();
            var plan = try harness.open("complete_height_cannot_move_backward");
            defer plan.deinit();
            try plan.set_completed(.new(7));
            try plan.set_completed(.new(6));
        }
    }.body);
}
