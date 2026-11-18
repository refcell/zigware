//! commonware `glue/src/stateful/actor/processor/mod.rs` finalization tests: fork pruning,
//! deferred prunes, the sealed root through the hooks, and replays retained across a
//! finalization.

const std = @import("std");
const testing = std.testing;
const harness_mod = @import("testing.zig");
const pruning = @import("pruning.zig");

const gpa = testing.allocator;
const io = testing.io;
const Harness = harness_mod.Harness;
const TestBlock = harness_mod.TestBlock;
const TestApp = harness_mod.TestApp;
const Probe = harness_mod.Probe;
const Processor = harness_mod.Processor;
const digested = harness_mod.digested;
const counter_key = harness_mod.counter_key;
const height_key = harness_mod.height_key;
const digest_u64 = harness_mod.digest_u64;
const read_applied = harness_mod.read_applied;

/// The view recorded at `height` in the applied state.
fn view_at(harness: *Harness, height: u64) !?u64 {
    const value = try read_applied(harness.databases.readers(), height_key(.new(height)));
    return if (value) |digest| digest_u64(digest) else null;
}

test "stateful processor: finalization prunes the losing fork" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const winner = try harness.stage_pending_child(&block1, 3);
    const loser = try harness.stage_pending_child(&block1, 2);
    try testing.expect(harness.execution.pending_contains(loser.digest()));

    try harness.finalize(&winner);
    try testing.expect(!harness.execution.pending_contains(loser.digest()));
    try testing.expect(!harness.execution.pending_contains(winner.digest()));
    try testing.expectEqual(winner.digest(), harness.processor.branch_anchor().digest);
    try testing.expectEqual(3, try view_at(&harness, 2));
}

test "stateful processor: finalization prunes the losing fork's descendants" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const loser = try harness.stage_pending_child(&block1, 2);
    const winner = try harness.stage_pending_child(&block1, 3);
    const loser_child = try harness.stage_pending_child(&loser, 4);
    const winner_child = try harness.stage_pending_child(&winner, 5);

    try harness.finalize(&winner);
    try testing.expect(!harness.execution.pending_contains(loser.digest()));
    try testing.expect(!harness.execution.pending_contains(loser_child.digest()));
    // The winner's own descendants stay cached.
    try testing.expect(harness.execution.pending_contains(winner_child.digest()));
}

test "stateful processor: a redelivered block is not applied again" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    var again = try digested(block1);
    defer again.deinit();
    try testing.expect(harness.processor.redelivered(&again));
    var parent = try digested(genesis);
    defer parent.deinit();
    try testing.expect(harness.processor.redelivered(&parent));
}

test "stateful processor: finalization defers the prune to the retention window" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const config: pruning.PruneConfig = .{
        .maintenance_interval = 1,
        .retained_marshal_blocks = 1,
        .retained_qmdb_blocks = 1,
    };
    harness.processor.pruning = try Processor.Pruning.init(gpa, config, 1, 0);
    const genesis = TestBlock.genesis();
    var parent = genesis;
    // The window is max_pending_acks + 1 + retained = 3 heights: the first prune is at 3, and
    // block 1 alone waits (commonware `execution_finalization_returns_deferred_prune`).
    for (1..5) |view| {
        const block = try harness.stage_pending_child(&parent, view);
        var handle = try digested(block);
        defer handle.deinit();
        const provider = harness.provider();
        const applied = try harness.processor.finalize(&provider, &handle, true);
        try applied.barrier.?.durable();
        try testing.expectEqual(view >= 3, applied.prune != null);
        if (applied.prune) |prune| try testing.expectEqual(view - 2, prune.marshal_height.get());
        parent = block;
    }
}

const Finalizing = struct {
    harness: *Harness,
    block: TestBlock,

    fn run(self: *Finalizing) anyerror!void {
        try self.harness.finalize(&self.block);
    }
};

/// The winner is the branch anchor and cached (not speculative) through capture, its state
/// is applied by the finalized hook, and it leaves the cache once the hook returns
/// (commonware `finalization_retains_sealed_root_through_hook`).
fn check_sealed_root(cached: bool) !void {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const winner = try harness.stage_pending_child(&genesis, 7);
    if (!cached) harness.execution.state.clear();

    var capture: Probe = .{ .target = winner.digest() };
    defer capture.deinit();
    var hook: Probe = .{ .target = winner.digest() };
    defer hook.deinit();
    var capture_gate = try capture.add_gate();
    defer capture_gate.started.deinit();
    var hook_gate = try hook.add_gate();
    defer hook_gate.started.deinit();
    harness.processor.app.capture_probe = &capture;
    harness.processor.app.finalized_probe = &hook;

    var finalizing: Finalizing = .{ .harness = &harness, .block = winner };
    var future = try io.concurrent(Finalizing.run, .{&finalizing});
    try capture_gate.started.recv();

    const execution = harness.execution;
    try testing.expectEqual(winner.digest(), execution.branch_anchor().digest);
    try testing.expect(execution.pending_contains(winner.digest()));
    try testing.expectEqual(0, execution.state.speculative_len());
    var fork = try execution.fork_batches(winner.digest());
    try testing.expectEqual(1, digest_u64((try fork.get(&counter_key())).?));
    try testing.expectEqual(7, digest_u64((try fork.get(&height_key(winner.height()))).?));
    fork.deinit();
    try testing.expectEqual(null, try read_applied(harness.databases.readers(), counter_key()));

    try capture_gate.release.send({});
    try hook_gate.started.recv();
    try testing.expect(execution.pending_contains(winner.digest()));
    const applied = try read_applied(harness.databases.readers(), counter_key());
    try testing.expectEqual(1, digest_u64(applied.?));

    try hook_gate.release.send({});
    try future.await(io);
    try testing.expect(!execution.pending_contains(winner.digest()));
    try testing.expectEqual(0, execution.state.speculative_len());
}

test "stateful processor: finalization retains the sealed root through its hook" {
    try check_sealed_root(true);
    try check_sealed_root(false);
}

const Replaying = struct {
    harness: *Harness,
    app: TestApp,
    block: TestBlock,

    fn run(self: *Replaying) anyerror!void {
        const execution = self.harness.execution;
        try execution.process_shared(self.app, try self.harness.ancestry(&.{self.block}));
    }
};

// A child's replay retained by its parent's boundary caches its state across the parent's
// finalization (commonware `finalization_keeps_replay_published_after_boundary` and
// `execution_descendant_replay_survives_finalized_parent_removal`).
test "stateful processor: a retained replay survives its parent's finalization" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var observations: std.ArrayList(TestApp.Observation) = .empty;
    defer observations.deinit(gpa);
    harness.processor.app.observations = &observations;
    const genesis = TestBlock.genesis();
    const parent = try harness.stage_pending_child(&genesis, 1);
    const child, var unused = try harness.build_child(&parent, 2);
    unused.deinit();

    var probe: Probe = .{ .target = child.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    var replaying: Replaying = .{
        .harness = &harness,
        .app = .{ .probe = &probe },
        .block = child,
    };
    var replay = try io.concurrent(Replaying.run, .{&replaying});
    try gate.started.recv();

    var parent_handle = try digested(parent);
    defer parent_handle.deinit();
    var boundary = try harness.processor.boundary(&parent_handle);
    defer boundary.deinit(gpa);
    const step: pruning.ExecutionStep(@TypeOf(child.digest())) = .{
        .digest = child.digest(),
        .parent = child.parent(),
        .round = child.round,
    };
    try testing.expectEqual(.retain, boundary.disposition(&step));
    try testing.expect(!boundary.compatible.contains(child.digest()));

    try harness.finalize(&parent);
    try testing.expectEqual(1, observations.items.len);
    try testing.expectEqual(1, observations.items[0].post_view);
    try testing.expectEqual(null, observations.items[0].captured.prior_counter);
    try testing.expect(!harness.execution.pending_contains(parent.digest()));

    try gate.release.send({});
    try replay.await(io);
    try testing.expect(harness.execution.pending_contains(child.digest()));
    var fork = try harness.execution.fork_batches(child.digest());
    defer fork.deinit();
    try testing.expectEqual(2, digest_u64((try fork.get(&counter_key())).?));
    try testing.expectEqual(2, digest_u64((try fork.get(&height_key(child.height()))).?));
}
