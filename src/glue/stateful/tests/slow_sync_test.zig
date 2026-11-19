//! commonware `glue/src/stateful/tests/mod.rs`
//! `stable_leader_finalizations_outpace_slow_qmdb_sync`:
//! the stateful actor's QMDB storage parks every sync (`runtime.storage.mocks.DelayedSync`,
//! commonware's `DelayedSyncContext`) and a flusher releases them every 50 ms, slower than the
//! 10 ms block pace. Durability must keep pace: one barrier covers every height applied while
//! the previous one is pending, so finalizations coalesce rather than sync once per block.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const single = @import("single_db.zig");
const db = @import("../db/mod.zig");
const targeted = @import("qmdb_targeted_test.zig");

const Ctx = runtime.deterministic.Context;
const Block = single.Block;
const Any = single.Any;
const Digested = single.Digested;
const DelayedSync = runtime.storage.mocks.DelayedSync;
const DelayedSynced = runtime.storage.mocks.DelayedSynced;
const ExactWaiter = utils.acknowledgement.ExactWaiter;

const blocks_count = 32;
const block_interval_ms = 10;
const sync_interval_ms = 50;

/// Releases parked syncs: every millisecond until `armed` (commonware `drive_pending_syncs`
/// during startup), then every 50 ms (the slow storage).
const Flusher = struct {
    pending: *DelayedSync,
    armed: bool = false,

    fn run(self: *Flusher, ctx: Ctx) Io.Cancelable!void {
        while (true) {
            const interval: i64 = if (self.armed) sync_interval_ms else 1;
            try ctx.sleep(.fromMilliseconds(interval));
            self.pending.release_all();
        }
    }
};

fn all_durable(waiters: []const ExactWaiter) !bool {
    for (waiters) |*waiter| {
        const outcome = waiter.poll() orelse return false;
        try outcome;
    }
    return true;
}

fn stable_leader(ctx: Ctx) !void {
    const gpa = ctx.gpa();
    const io = ctx.io();
    var blocks: [blocks_count]Block = undefined;
    try targeted.build_chain(ctx, &blocks);
    const leader = blocks[0].context().leader;
    for (&blocks) |*block| try testing.expect(block.context().leader.eql(leader));

    var rng = utils.rng.test_rng();
    var validators = try @import("consensus").simplex.mocks.scheme.fixture(
        single.Block.Digest,
        gpa,
        &rng,
        "_COMMONWARE_GLUE_QMDB_STABLE_LEADER",
        1,
    );
    defer validators.deinit(gpa);
    var cache: runtime.buffer.paged.CacheRef =
        try .init(gpa, targeted.page_size, targeted.page_cache_size);
    defer cache.deinit();
    var marshal: targeted.MarshalFixture =
        try .init(ctx.child("marshal"), "stable-leader-marshal", &validators, .{
            .max_pending_acks = 64,
        });
    defer marshal.abort();

    // Only the stateful actor's storage (its plan and databases) is slow.
    var pending: DelayedSync = .init(gpa, io);
    defer pending.deinit();
    var delayed: DelayedSynced = .init(gpa, ctx.storage, &pending);
    var flusher: Flusher = .{ .pending = &pending };
    var flushing = try io.concurrent(Flusher.run, .{ &flusher, ctx });
    // Release what is still parked once the flusher stops (commonware `pending.unblock()`).
    defer pending.unblock();
    defer flushing.cancel(io) catch {};
    var env = targeted.env(ctx, "stateful");
    env.storage = delayed.storage();
    var plan: targeted.Plan = try .init(env.child("plan"), "stable-leader-stateful");
    defer plan.deinit();
    var config = targeted.qmdb_config("stable-leader-stateful", &cache);
    config.log.items_per_blob = 1024;
    config.merkle.items_per_blob = 1024;
    const actor, var mailbox = try targeted.Stateful.init(gpa, io, .{
        .app = .{},
        .env = env,
        .db_config = config,
        .marshal = marshal.mailbox.clone(),
        .mailbox_size = 64,
        .plan = &plan,
        .floor = marshal.floor,
    });
    defer actor.deinit();
    defer mailbox.deinit();
    var future = try actor.start();
    defer _ = future.cancel(io) catch {};
    const databases = try mailbox.subscribe_databases();
    // Startup completes every sync it starts before serving the databases, so the syncs counted
    // once the gate is armed come from finalization.
    try testing.expectEqual(pending.starts(), pending.completions());
    try testing.expectEqual(@as(usize, 0), pending.parked());
    try pending.arm();
    flusher.armed = true;
    try report_paced(ctx, &mailbox, &blocks, databases, &pending);
}

/// Reports every block 10 ms apart, then expects them all durable within 500 ms, through
/// fewer syncs than blocks, with the last block's targets committed.
fn report_paced(
    ctx: Ctx,
    mailbox: *targeted.StatefulMailbox,
    blocks: []const Block,
    databases: Any.Shared,
    pending: *DelayedSync,
) !void {
    const gpa = ctx.gpa();
    var waiters: [blocks_count]ExactWaiter = undefined;
    var made: usize = 0;
    defer for (waiters[0..made]) |*waiter| waiter.deinit();
    for (blocks) |*block| {
        const handle = try utils.acknowledgement.Exact.handle(gpa, ctx.io());
        waiters[made] = handle.waiter;
        made += 1;
        const update: targeted.StatefulMailbox.Update = .{ .block = .{
            .block = try Digested.precomputed(gpa, block.*, block.digest()),
            .ack = handle.acknowledgement,
        } };
        try testing.expect(mailbox.report(update) != .closed);
        try ctx.sleep(.fromMilliseconds(block_interval_ms));
    }
    // Durability keeps pace: every finalization is durable within a few sync intervals of the
    // last report, so syncs are not serialized per block.
    const wait_until = @import("../actor/marshal_fixture.zig").wait_until;
    wait_until(ctx, 500, all_durable, .{waiters[0..made]}) catch |err| {
        std.debug.print("stalled: calls={d} starts={d} entered={d} completions={d}\n", .{
            pending.calls(),   pending.starts(),
            pending.entered(), pending.completions(),
        });
        return err;
    };
    const calls = pending.calls();
    try testing.expect(calls > 0);
    try testing.expect(calls < blocks_count);
    const committed = try databases.committed_targets();
    const expected = single.App.sync_targets(&blocks[blocks.len - 1]);
    try testing.expect(db.targets_eql(Any.SyncTarget, &committed, &expected));
}

// commonware `stable_leader_finalizations_outpace_slow_qmdb_sync`: with storage slower than the
// block pace, finalizations stay durable within a few sync intervals and their syncs coalesce.
test "stateful tests: stable-leader finalizations outpace a slow qmdb sync" {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
        .timeout_ns = 20 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(stable_leader, .{});
}
