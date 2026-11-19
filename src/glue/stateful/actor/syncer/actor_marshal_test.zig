//! commonware `glue/src/stateful/actor/syncer/actor.rs` tests that run `resolve` on a real,
//! restartable marshal actor over prunable finalized archives (`marshal_fixture.zig`).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const runtime = @import("runtime");
const actor_mod = @import("actor.zig");
const fixture_mod = @import("../marshal_fixture.zig");

const Ctx = fixture_mod.Ctx;
const Block = fixture_mod.Block;
const Finalization = fixture_mod.Finalization;
const Validators = fixture_mod.Validators;
const Processed = fixture_mod.Processed;
const Height = fixture_mod.Height;
const round = fixture_mod.round;
const Prunable = fixture_mod.Fixture(fixture_mod.PrunableStores);
const Mailbox = Prunable.Mailbox;

/// `resolve`'s parameters over the real marshal mailbox.
const P = struct {
    pub const Marshal = Mailbox;
    pub const Finalization = fixture_mod.Finalization;
    pub fn commitment(block: *const Block) fixture_mod.D {
        return block.digest();
    }
};

/// Runs `body` on a deterministic runtime that fails after 10 simulated seconds.
fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

fn processed_is(mailbox: Mailbox, expected: Processed) !bool {
    const processed = try mailbox.get_processed() orelse return false;
    return std.meta.eql(processed, expected);
}

fn block_absent(mailbox: Mailbox, height: u64) !bool {
    var block = try mailbox.get_block(.{ .height = .new(height) }) orelse return true;
    block.deinit();
    return false;
}

fn digest_absent(mailbox: Mailbox, digest: fixture_mod.D) !bool {
    var block = try mailbox.get_block(.{ .digest = digest }) orelse return true;
    block.deinit();
    return false;
}

/// Verifies `block` at its height's round and reports its finalization.
fn finalize(
    ctx: Ctx,
    mailbox: *Mailbox,
    validators: *const Validators,
    block: *const Block,
) !void {
    const gpa = ctx.gpa();
    const height = block.inner().height().get();
    try testing.expect(try mailbox.verified(round(height), block.clone()));
    var finalization = try fixture_mod.finalization(gpa, validators, height, block.digest());
    defer finalization.deinit(gpa);
    _ = mailbox.report(.{ .finalization = finalization });
}

/// Finalizes and acknowledges `blocks[from..=to]` one at a time.
fn finalize_through(
    ctx: Ctx,
    mailbox: *Mailbox,
    validators: *const Validators,
    blocks: []const Block,
    from: u64,
    to: u64,
) !void {
    assert(from <= to);
    for (from..to + 1) |height| {
        try finalize(ctx, mailbox, validators, &blocks[height]);
        const expected: Processed = .{ .block = .new(height) };
        try fixture_mod.wait_until(ctx, 1000, processed_is, .{ mailbox.*, expected });
    }
}

/// Resolves `selected` within 100 simulated milliseconds: a superseded floor must not wait
/// for its pruned block.
fn resolve_promptly(
    ctx: Ctx,
    mailbox: Mailbox,
    floor: fixture_mod.Floor,
    selected: *const Finalization,
) !Block {
    const started = std.Io.Clock.Timestamp.now(ctx.io(), .awake);
    const block = try actor_mod.resolve(P, ctx.gpa(), mailbox, floor, selected);
    const elapsed = started.durationTo(std.Io.Clock.Timestamp.now(ctx.io(), .awake));
    try testing.expect(elapsed.raw.toNanoseconds() < 100 * std.time.ns_per_ms);
    return block;
}

fn pruned_by_newer_floor(ctx: Ctx) !void {
    const gpa = ctx.gpa();
    var validators = try fixture_mod.make_validators(gpa);
    defer validators.deinit(gpa);
    const blocks = try fixture_mod.chain(gpa, 11);
    defer fixture_mod.free_chain(gpa, blocks);
    var selected = try fixture_mod.finalization(gpa, &validators, 1, blocks[1].digest());
    defer selected.deinit(gpa);
    const prefix = "syncer-pruned-floor";

    var first = try Prunable.init(ctx.child("marshal"), prefix, &validators, .{});
    try finalize_through(ctx, &first.mailbox, &validators, blocks, 1, 9);
    // A newer floor prunes the selected block, then delivers the floor block.
    try testing.expect(try first.mailbox.verified(round(10), blocks[10].clone()));
    try first.mailbox.set_floor(
        try fixture_mod.finalization(gpa, &validators, 10, blocks[10].digest()),
    );
    try fixture_mod.wait_until(ctx, 100, block_absent, .{ first.mailbox, 1 });
    const at_floor: Processed = .{ .block = .new(10) };
    try fixture_mod.wait_until(ctx, 100, processed_is, .{ first.mailbox, at_floor });
    first.abort();
    try ctx.sleep(.fromMilliseconds(1));

    var restarted = try Prunable.init(ctx.child("marshal_restart"), prefix, &validators, .{
        .floor = try selected.clone(gpa),
    });
    defer restarted.abort();
    try testing.expect(std.meta.eql(restarted.floor.processed, at_floor));
    try testing.expect(restarted.floor.cutoff.order(.{ .round = selected.round() }) == .gt);
    try testing.expect(try digest_absent(restarted.mailbox, blocks[1].digest()));
    var resolved = try resolve_promptly(ctx, restarted.mailbox, restarted.floor, &selected);
    defer resolved.deinit();
    try testing.expect(std.meta.eql(resolved.digest(), blocks[10].digest()));
}

test "stateful syncer marshal: resolve skips a selected block pruned by a newer floor" {
    try run(pruned_by_newer_floor);
}

fn processed_height_is(mailbox: Mailbox, height: u64) !bool {
    const processed = try mailbox.get_processed() orelse return false;
    return processed.height().get() == height;
}

fn boundary_prune(ctx: Ctx) !void {
    const gpa = ctx.gpa();
    var validators = try fixture_mod.make_validators(gpa);
    defer validators.deinit(gpa);
    const blocks = try fixture_mod.chain(gpa, 9);
    defer fixture_mod.free_chain(gpa, blocks);
    var selected = try fixture_mod.finalization(gpa, &validators, 1, blocks[1].digest());
    defer selected.deinit(gpa);
    const prefix = "syncer-boundary-floor";

    var first = try Prunable.init(ctx.child("marshal_first"), prefix, &validators, .{});
    try finalize_through(ctx, &first.mailbox, &validators, blocks, 1, 5);
    first.abort();
    try ctx.sleep(.fromMilliseconds(1));

    // A floor installed at 8 prunes the selected block at a section boundary and leaves its
    // predecessor processed but absent.
    var newer = try fixture_mod.finalization(gpa, &validators, 8, blocks[8].digest());
    defer newer.deinit(gpa);
    var second = try Prunable.init(ctx.child("marshal_second"), prefix, &validators, .{
        .block = &blocks[8],
        .floor = try newer.clone(gpa),
        .acknowledge = false,
    });
    try fixture_mod.wait_until(ctx, 1000, processed_height_is, .{ second.mailbox, 7 });
    try testing.expect(try digest_absent(second.mailbox, blocks[1].digest()));
    try testing.expect(!try block_absent(second.mailbox, 8));
    second.abort();
    try ctx.sleep(.fromMilliseconds(1));

    var third = try Prunable.init(ctx.child("marshal_third"), prefix, &validators, .{
        .floor = try selected.clone(gpa),
    });
    defer third.abort();
    const absent: Processed = .{ .absent = .new(7) };
    try testing.expect(std.meta.eql(third.floor.processed, absent));
    try testing.expect(third.floor.cutoff.eql(.{ .round = newer.round() }));
    try testing.expect(try digest_absent(third.mailbox, blocks[1].digest()));
    var resolved = try resolve_promptly(ctx, third.mailbox, third.floor, &selected);
    defer resolved.deinit();
    try testing.expect(std.meta.eql(resolved.digest(), blocks[8].digest()));
}

test "stateful syncer marshal: resolve recovers the round after a boundary prune" {
    try run(boundary_prune);
}

fn block_present(mailbox: Mailbox, height: u64) !bool {
    return !try block_absent(mailbox, height);
}

/// One `resolve_follows_live_floor_after_startup` case.
const LiveFloor = struct {
    acknowledged: u64,
    stored: u64,
    live_floor: u64,
    selected: u64,
    expected: u64,
};

fn live_floor_case(ctx: Ctx, case: LiveFloor) !void {
    const gpa = ctx.gpa();
    var validators = try fixture_mod.make_validators(gpa);
    defer validators.deinit(gpa);
    const blocks = try fixture_mod.chain(gpa, case.live_floor + 1);
    defer fixture_mod.free_chain(gpa, blocks);
    const prefix = "live-floor-resolve";

    // Acknowledge blocks through the snapshot height.
    var first = try Prunable.init(ctx.child("first"), prefix, &validators, .{});
    try finalize_through(ctx, &first.mailbox, &validators, blocks, 1, case.acknowledged);
    first.abort();

    // Store later blocks without acknowledging them.
    var second = try Prunable.init(ctx.child("second"), prefix, &validators, .{
        .acknowledge = false,
    });
    for (case.acknowledged + 1..case.stored + 1) |height| {
        try finalize(ctx, &second.mailbox, &validators, &blocks[height]);
        try fixture_mod.wait_until(ctx, 1000, block_present, .{ second.mailbox, height });
    }
    second.abort();

    // Restart, then install a live floor before resolving from the startup snapshot.
    var third = try Prunable.init(ctx.child("third"), prefix, &validators, .{
        .acknowledge = false,
    });
    defer third.abort();
    const snapshot: Processed = .{ .block = .new(case.acknowledged) };
    try testing.expect(std.meta.eql(third.floor.processed, snapshot));
    const floor_block = &blocks[case.live_floor];
    try testing.expect(try third.mailbox.verified(round(case.live_floor), floor_block.clone()));
    try third.mailbox.set_floor(
        try fixture_mod.finalization(gpa, &validators, case.live_floor, floor_block.digest()),
    );
    const live: Processed = .{ .block = .new(case.live_floor - 1) };
    try fixture_mod.wait_until(ctx, 1000, processed_is, .{ third.mailbox, live });
    const payload = blocks[case.selected].digest();
    var selected = try fixture_mod.finalization(gpa, &validators, case.selected, payload);
    defer selected.deinit(gpa);
    var resolved = try actor_mod.resolve(P, gpa, third.mailbox, third.floor, &selected);
    defer resolved.deinit();
    try testing.expect(std.meta.eql(resolved.digest(), blocks[case.expected].digest()));
}

fn live_floor_pruned_snapshot_anchor(ctx: Ctx) !void {
    try live_floor_case(ctx, .{
        .acknowledged = 2,
        .stored = 4,
        .live_floor = 5,
        .selected = 2,
        .expected = 4,
    });
}

fn live_floor_selected_below(ctx: Ctx) !void {
    try live_floor_case(ctx, .{
        .acknowledged = 4,
        .stored = 6,
        .live_floor = 7,
        .selected = 5,
        .expected = 6,
    });
}

test "stateful syncer marshal: resolve follows a live floor that pruned the snapshot anchor" {
    try run(live_floor_pruned_snapshot_anchor);
}

test "stateful syncer marshal: resolve follows a live floor above the selected block" {
    try run(live_floor_selected_below);
}

const db = @import("../../db/mod.zig");
const db_sync = @import("../../db/sync.zig");
const state_sync = @import("../../db/state_sync.zig");
const utils = @import("utils");
const plan_mod = @import("plan.zig");
const stateful_mod = @import("../core/stateful.zig");
const Plan = plan_mod.SyncPlan(fixture_mod.S, fixture_mod.V);

/// commonware's `WedgeSet`: it opens only at its configured target, and its sync completes
/// after a simulated second without fetching. The other database operations never run.
const WedgeSet = struct {
    value: u64,
    /// No member databases: the resolver set (`.{}`) attaches nothing.
    members: @TypeOf(.{}) = .{},
    pub const Config = u64;
    pub const SyncTargets = u64;
    pub const Readers = void;
    pub const Merkleized = struct {
        pub fn clone(self: Merkleized) Merkleized {
            return self;
        }

        pub fn deinit(_: *Merkleized) void {}
    };
    pub const Unmerkleized = struct {
        pub fn deinit(_: *Unmerkleized) void {}
    };

    pub fn open(_: anytype, config: u64, expected: ?u64) !WedgeSet {
        // Startup must pass the configured target.
        if (expected != config) return error.TestUnexpectedTarget;
        return .{ .value = config };
    }

    pub fn deinit(_: *WedgeSet) void {}

    pub fn sync(
        comptime D: type,
        env: anytype,
        _: u64,
        _: anytype,
        anchor: db_sync.Anchor(D),
        _: u64,
        tip_updates: utils.channel.ring.Receiver(db_sync.TipUpdate(D, u64)),
        _: state_sync.SyncEngineConfig,
    ) !state_sync.SetSynced(WedgeSet, D) {
        var tips = tip_updates;
        defer tips.deinit();
        try env.io.sleep(.fromSeconds(1), .awake);
        return .{ .databases = .{ .value = 0 }, .anchor = anchor };
    }

    pub fn committed_targets(self: WedgeSet) !u64 {
        return self.value;
    }

    pub fn new_batches(_: WedgeSet) !Unmerkleized {
        @panic("WedgeSet only serves the syncer harness");
    }

    pub fn fork_batches(_: *const Merkleized) !Unmerkleized {
        @panic("WedgeSet only serves the syncer harness");
    }

    pub fn matches_sync_targets(_: *const Merkleized, _: *const u64) bool {
        @panic("WedgeSet only serves the syncer harness");
    }

    pub fn readers(_: WedgeSet) void {}

    pub fn apply(_: WedgeSet, _: *const Merkleized) !void {
        @panic("WedgeSet only serves the syncer harness");
    }

    pub fn finalize(_: WedgeSet) !db.Barrier {
        @panic("WedgeSet only serves the syncer harness");
    }

    pub fn prune(_: WedgeSet, _: *const u64) !void {
        @panic("WedgeSet only serves the syncer harness");
    }
};

/// commonware's `WedgeApp`: a block's sync target is its height.
const WedgeApp = struct {
    pub const Block = fixture_mod.B;
    pub const Context = consensus_harness.Ctx;
    pub const Input = void;
    pub const Merkleized = WedgeSet.Merkleized;
    const consensus_harness = @import("consensus").marshal.mocks.harness;
    const Built = @import("../processor/processor.zig").Proposed(WedgeApp);

    pub fn sync_targets(block: *const fixture_mod.B) u64 {
        return block.height().get();
    }

    pub fn process(
        _: *WedgeApp,
        _: std.Io,
        _: Context,
        _: anytype,
        _: WedgeSet.Unmerkleized,
        _: anytype,
    ) !?Merkleized {
        @panic("WedgeApp only serves the syncer harness");
    }

    pub fn propose(
        _: *WedgeApp,
        _: std.Io,
        _: Context,
        _: anytype,
        _: WedgeSet.Unmerkleized,
        _: void,
    ) !?Built {
        @panic("WedgeApp only serves the syncer harness");
    }

    pub fn capture(
        _: *WedgeApp,
        _: std.Io,
        _: Context,
        _: *const fixture_mod.B,
        _: anytype,
        _: anytype,
    ) !void {
        @panic("WedgeApp only serves the syncer harness");
    }

    pub fn finalized(
        _: *WedgeApp,
        _: std.Io,
        _: Context,
        _: *const fixture_mod.B,
        _: void,
        _: anytype,
    ) !void {
        @panic("WedgeApp only serves the syncer harness");
    }
};

const WedgeStateful = stateful_mod.Stateful(struct {
    pub const App = WedgeApp;
    pub const Databases = WedgeSet;
    pub const Marshal = Mailbox;
    pub const Plan = plan_mod.SyncPlan(fixture_mod.S, fixture_mod.V);
    pub const Resolvers = @TypeOf(.{});
});

fn env_of(ctx: Ctx) db.Env {
    return .{ .gpa = ctx.gpa(), .io = ctx.io(), .storage = ctx.storage, .scope = ctx.scope };
}

fn restart_resumes_floor(ctx: Ctx) !void {
    const gpa = ctx.gpa();
    var validators = try fixture_mod.make_validators(gpa);
    defer validators.deinit(gpa);
    const blocks = try fixture_mod.chain(gpa, 3);
    defer fixture_mod.free_chain(gpa, blocks);
    var selected = try fixture_mod.finalization(gpa, &validators, 2, blocks[2].digest());
    defer selected.deinit(gpa);
    const prefix = "syncer-selected-floor";

    // Select the floor, let marshal durably install it, and stop before Stateful starts.
    var plan = try Plan.init(env_of(ctx), prefix);
    try plan.set_floor(&selected);
    var first = try Prunable.init(ctx.child("marshal"), prefix, &validators, .{
        .block = &blocks[2],
        .floor = try plan.floor().?.clone(gpa),
        .acknowledge = false,
    });
    const absent: Processed = .{ .absent = .new(1) };
    try fixture_mod.wait_until(ctx, 1000, processed_is, .{ first.mailbox, absent });
    first.abort();
    plan.deinit();

    // Restart without a request. The empty database matches only the genesis target, so
    // recovering from marshal's installed floor would fail startup.
    plan = try Plan.init(env_of(ctx), prefix);
    var second = try Prunable.init(ctx.child("marshal"), prefix, &validators, .{
        .floor = try plan.floor().?.clone(gpa),
        .acknowledge = false,
    });
    defer second.abort();
    const stateful, var mailbox = try WedgeStateful.init(gpa, ctx.io(), .{
        .app = .{},
        .env = env_of(ctx),
        .db_config = 0,
        .marshal = second.mailbox.clone(),
        .mailbox_size = 1,
        .plan = &plan,
        .sync_config = .{
            .fetch_batch_size = 1,
            .apply_batch_size = 1,
            .max_outstanding_requests = 1,
        },
        .resolvers = .{},
        .floor = second.floor,
    });
    defer stateful.deinit();
    var task = try stateful.start();
    // State sync resumes and completes at the installed floor.
    const synced = try mailbox.subscribe_databases();
    try testing.expectEqual(@as(u64, 0), synced.value);
    mailbox.deinit();
    _ = task.cancel(ctx.io()) catch {};
    plan.deinit();
    plan = try Plan.init(env_of(ctx), prefix);
    defer plan.deinit();
    try testing.expectEqual(@as(?u64, 2), if (plan.completed()) |at| at.get() else null);
}

test "stateful syncer marshal: a restart resumes a floor installed before stateful" {
    try run(restart_resumes_floor);
}

/// Proposes through `mailbox` on its own task (commonware races it against a sleep).
const ProposeTask = struct {
    mailbox: *WedgeStateful.Mailbox,
    done: std.atomic.Value(bool) = .init(false),
    declined: bool = false,

    fn run(task: *ProposeTask) void {
        const leader = @import("consensus").marshal.mocks.harness.default_leader();
        const context: WedgeApp.Context = .{
            .round = round(1),
            .leader = leader,
            .parent = .{ .zero(), .{ .bytes = @splat(0) } },
        };
        const empty: [0]Block = .{};
        if (WedgeStateful.Mailbox.Ancestry.from_blocks(testing.allocator, &empty)) |ancestry| {
            const proposed = task.mailbox.propose({}, context, ancestry, {}) catch null;
            task.declined = proposed == null;
        } else |_| {}
        task.done.store(true, .release);
    }

    fn finished(task: *const ProposeTask) !bool {
        return task.done.load(.acquire);
    }
};

fn propose_while_floor_waits(ctx: Ctx) !void {
    const gpa = ctx.gpa();
    var validators = try fixture_mod.make_validators(gpa);
    defer validators.deinit(gpa);
    const prefix = "pending-floor";
    var plan = try Plan.init(env_of(ctx), prefix);
    defer plan.deinit();
    var floor = try fixture_mod.finalization(gpa, &validators, 1, .{ .bytes = @splat(7) });
    defer floor.deinit(gpa);
    try plan.set_floor(&floor);
    // An unstarted marshal never answers the floor block's subscription.
    var marshal = try Prunable.init(ctx.child("marshal_fixture"), prefix, &validators, .{
        .acknowledge = null,
    });
    defer marshal.abort();
    const stateful, var mailbox = try WedgeStateful.init(gpa, ctx.io(), .{
        .app = .{},
        .env = env_of(ctx),
        .db_config = 0,
        .marshal = marshal.mailbox.clone(),
        .mailbox_size = 8,
        .plan = &plan,
        .sync_config = .{
            .fetch_batch_size = 1,
            .apply_batch_size = 1,
            .max_outstanding_requests = 1,
        },
        .resolvers = .{},
        .floor = marshal.floor,
    });
    defer stateful.deinit();
    defer mailbox.deinit();
    var actor_task = try stateful.start();
    defer _ = actor_task.cancel(ctx.io()) catch {};
    var task: ProposeTask = .{ .mailbox = &mailbox };
    var future = try ctx.io().concurrent(ProposeTask.run, .{&task});
    defer future.cancel(ctx.io());
    try fixture_mod.wait_until(ctx, 100, ProposeTask.finished, .{&task});
    try testing.expect(task.declined);
}

test "stateful syncer marshal: the mailbox declines proposals while floor resolution waits" {
    try run(propose_while_floor_waits);
}
