//! commonware `glue/src/stateful/tests/floor.rs`: a live marshal floor keeps the predecessor
//! the application needs to reopen its state after each crash. Four boots on one runner, each
//! recovering only the storage its predecessor synced (commonware's checkpoint).
//!
//! zigware differences: a boot ends by aborting marshal and cancelling the actor (commonware
//! drops the runner with both running); the held floor report's acknowledgement is dropped
//! with it.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const consensus = @import("consensus");
const runtime = @import("runtime");
const utils = @import("utils");
const single = @import("single_db.zig");
const db = @import("../db/mod.zig");
const fixture_for = @import("../actor/marshal_fixture_for.zig");
const targeted = @import("qmdb_targeted_test.zig");
const wait_until = @import("../actor/marshal_fixture.zig").wait_until;

const Ctx = runtime.deterministic.Context;
const Height = consensus.Height;
const Block = single.Block;
const Any = single.Any;
const Digested = single.Digested;
const StatefulMailbox = targeted.StatefulMailbox;
const Update = StatefulMailbox.Update;
const Processed = consensus.marshal.core.Processed;
const gpa = testing.allocator;

/// The floor report the reporter diverted, until the test takes it.
const Held = struct {
    update: ?Update = null,
};

/// Keeps the finalized block at `height` unapplied across recovery cuts (commonware
/// `HoldBlock`); every other update reaches the stateful actor.
const HoldBlock = struct {
    pub const Activity = Update;

    inner: StatefulMailbox,
    height: Height,
    held: *Held,

    pub fn report(self: *HoldBlock, activity: Activity) consensus.Feedback {
        switch (activity) {
            .block => |value| if (value.block.inner().height().get() == self.height.get()) {
                // A redelivery replaces the earlier report (commonware's lossy ring of one).
                if (self.held.update) |*previous| previous.deinit();
                self.held.update = activity;
                return .ok;
            },
            .tip => {},
        }
        return self.inner.report(activity);
    }

    pub fn clone(self: HoldBlock) HoldBlock {
        return .{ .inner = self.inner.clone(), .height = self.height, .held = self.held };
    }

    pub fn deinit(self: *HoldBlock) void {
        self.inner.deinit();
        self.* = undefined;
    }
};

const Types = struct {
    pub const B = targeted.Types.B;
    pub const D = targeted.Types.D;
    pub const K = targeted.Types.K;
    pub const S = targeted.Types.S;
    pub const Finalization = targeted.Types.Finalization;
    pub const Validators = targeted.Types.Validators;
    pub const Provider = targeted.Types.Provider;
    pub const Application = HoldBlock;
    pub const genesis = targeted.Types.genesis;
};
const Marshal = fixture_for.FixtureFor(Types);
const MarshalFixture = Marshal.Fixture(Marshal.PrunableStores);
const Stateful = targeted.Stateful;
comptime {
    // Marshal's mailbox depends only on the scheme and variant, not the reporter.
    assert(MarshalFixture.Mailbox == targeted.MarshalFixture.Mailbox);
}

/// What every boot shares: the chain and the signing validator.
const State = struct {
    floor_height: u64,
    blocks: [4]Block = undefined,
    validators: Types.Validators,
};

fn processed_is(mailbox: MarshalFixture.Mailbox, expected: Processed) !bool {
    const processed = try mailbox.get_processed() orelse return false;
    return std.meta.eql(processed, expected);
}

fn is_held(held: *const Held) !bool {
    return held.update != null;
}

fn expect_committed(databases: Any.Shared, block: *const Block) !void {
    const committed = try databases.committed_targets();
    const expected = single.App.sync_targets(block);
    try testing.expect(db.targets_eql(Any.SyncTarget, &committed, &expected));
}

/// Verifies and finalizes blocks 1 through F once marshal has processed genesis.
fn finalize_chain(ctx: Ctx, state: *const State, marshal: *MarshalFixture.Mailbox) !void {
    const at_genesis: Processed = .{ .block = .zero() };
    try wait_until(ctx, 1000, processed_is, .{ marshal.*, at_genesis });
    for (state.blocks[0..state.floor_height]) |*block| {
        const digested = try Digested.precomputed(ctx.gpa(), block.*, block.digest());
        try testing.expect(try marshal.verified(block.context().round, digested));
        var certificate = try targeted.finalization_of(ctx.gpa(), &state.validators, block);
        defer certificate.deinit(ctx.gpa());
        _ = marshal.report(.{ .finalization = certificate });
    }
}

/// One boot: recover marshal and the actor from storage, then drive this boot's checks.
fn boot_once(ctx: Ctx, state: *State, boot: u32) anyerror!void {
    const blocks = state.blocks[0..state.floor_height];
    if (boot == 0) try targeted.build_chain(ctx, blocks);
    const floor_height: Height = .new(state.floor_height);
    // F-1 and F commit different targets, so reopening at the wrong block fails startup.
    const predecessor = &blocks[blocks.len - 2];
    const floor_block = &blocks[blocks.len - 1];
    const predecessor_target = single.App.sync_targets(predecessor);
    const floor_target = single.App.sync_targets(floor_block);
    try testing.expect(!db.targets_eql(Any.SyncTarget, &predecessor_target, &floor_target));

    var cache: runtime.buffer.paged.CacheRef =
        try .init(ctx.gpa(), targeted.page_size, targeted.page_cache_size);
    defer cache.deinit();
    // Every boot recovers from marshal; no state sync floor is configured.
    var plan: targeted.Plan = try .init(targeted.env(ctx, "plan"), "floor-stateful");
    defer plan.deinit();
    if (boot > 0) try testing.expect(!plan.should_sync(true));
    try testing.expect(plan.floor() == null);
    // Four-item sections put F=4 on a section boundary, where pruning below F removes F-1.
    const validators = &state.validators;
    var marshal: MarshalFixture =
        try .init(ctx.child("marshal"), "floor-marshal", validators, .{ .acknowledge = null });
    var marshal_running = true;
    defer if (marshal_running) marshal.abort();
    const actor, var mailbox = try Stateful.init(ctx.gpa(), ctx.io(), .{
        .app = .{},
        .env = targeted.env(ctx, "stateful"),
        .db_config = targeted.qmdb_config("floor-stateful", &cache),
        .marshal = marshal.mailbox.clone(),
        .mailbox_size = 8,
        .plan = &plan,
        .floor = marshal.floor,
    });
    defer actor.deinit();
    defer mailbox.deinit();
    var future = try actor.start();
    defer _ = future.cancel(ctx.io()) catch {};
    // Divert F so the test decides when the application sees it.
    var held: Held = .{};
    defer if (held.update) |*update| update.deinit();
    const reporter: HoldBlock =
        .{ .inner = mailbox.clone(), .height = floor_height, .held = &held };
    try marshal.start_actor(ctx, true, reporter);
    const databases = try mailbox.subscribe_databases();
    if (boot == 0) try finalize_chain(ctx, state, &marshal.mailbox);
    try check_boot(ctx, state, boot, &marshal, &mailbox, &held, databases);
    // A crash: marshal (holding the reporter's mailbox) first, then the actor.
    marshal.abort();
    marshal_running = false;
}

fn check_boot(
    ctx: Ctx,
    state: *State,
    boot: u32,
    marshal: *MarshalFixture,
    mailbox: *StatefulMailbox,
    held: *Held,
    databases: Any.Shared,
) !void {
    const blocks = state.blocks[0..state.floor_height];
    const floor_height: Height = .new(state.floor_height);
    const at_predecessor: Processed = .{ .block = .new(state.floor_height - 1) };
    const at_floor: Processed = .{ .block = floor_height };
    if (boot < 3) {
        // The single pending acknowledgement makes delivery at F a durable fence for the
        // predecessor's application state.
        try wait_until(ctx, 5000, is_held, .{held});
        try testing.expect(try processed_is(marshal.mailbox, at_predecessor));
        try expect_committed(databases, &blocks[blocks.len - 2]);
        if (boot == 0) {
            // Marshal persists the new floor and prunes its archives before answering the
            // queued height query. F remains held here.
            const floor_block = &blocks[blocks.len - 1];
            try marshal.mailbox.set_floor(
                try targeted.finalization_of(ctx.gpa(), &state.validators, floor_block),
            );
            try testing.expect(try processed_is(marshal.mailbox, at_predecessor));
            var block = try marshal.mailbox.get_block(.{ .height = floor_height }) orelse
                return error.TestFloorBlockMissing;
            block.deinit();
        }
        if (boot == 2) {
            // Release F to the application; its acknowledgement advances marshal's durable
            // processed height.
            const update = held.update.?;
            held.update = null;
            try testing.expect(mailbox.report(update) != .closed);
            try wait_until(ctx, 5000, processed_is, .{ marshal.mailbox, at_floor });
        }
    }
    if (boot >= 2) {
        try testing.expect(try processed_is(marshal.mailbox, at_floor));
        try expect_committed(databases, &blocks[blocks.len - 1]);
    }
}

fn live_floor(floor_height: u64) !void {
    assert(floor_height >= 2 and floor_height <= 4);
    const config: runtime.deterministic.Config = .{ .timeout_ns = 120 * std.time.ns_per_s };
    try runtime.deterministic.soak(gpa, config, floor_height, live_floor_round);
}

fn live_floor_round(floor_height: u64, runner: *runtime.deterministic.Runner) !void {
    var rng = utils.rng.test_rng();
    var state: State = .{
        .floor_height = floor_height,
        .validators = try consensus.simplex.mocks.scheme.fixture(
            single.Block.Digest,
            gpa,
            &rng,
            "_COMMONWARE_GLUE_LIVE_FLOOR_RECOVERY",
            1,
        ),
    };
    defer state.validators.deinit(gpa);
    // The first two cuts leave F unapplied. The third applies F, and the fourth opens its
    // committed target from durable storage.
    for (0..4) |boot| {
        try try runner.start_context(boot_once, .{ &state, @as(u32, @intCast(boot)) });
    }
}

// commonware `live_floor_preserves_application_recovery::within_section`: floor 3.
test "stateful tests: live floor preserves application recovery within a section" {
    try live_floor(3);
}

// commonware `live_floor_preserves_application_recovery::section_boundary`: floor 4, where
// pruning below the floor removes its predecessor's section.
test "stateful tests: live floor preserves application recovery at a section boundary" {
    try live_floor(4);
}
