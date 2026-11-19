//! commonware `glue/src/stateful/actor/processor/mod.rs` tests not covered by the sibling
//! processor test files: `rebuild_pending`'s rejections and closed-provider handling.
//! commonware's `ScriptedParentProvider` is the harness provider with the scripted parent
//! stored under the child's parent digest (or removed, for a subscription that ends).

const std = @import("std");
const testing = std.testing;
const harness_mod = @import("testing.zig");

const Harness = harness_mod.Harness;
const TestBlock = harness_mod.TestBlock;
const digested = harness_mod.digested;
const u64_digest = harness_mod.u64_digest;
const Height = @TypeOf(TestBlock.genesis().height());
const TestApp = harness_mod.TestApp;
const Probe = harness_mod.Probe;
const gpa = testing.allocator;

/// Block 1 finalized on genesis, then blocks 2 and 3 staged on it.
fn finalized_chain(harness: *Harness) ![3]TestBlock {
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    const block3 = try harness.stage_pending_child(&block2, 3);
    return .{ block1, block2, block3 };
}

/// Rebuilds `target` with the harness provider and returns the result.
fn rebuild(harness: *Harness, target: TestBlock) !void {
    var provider = harness.provider();
    return harness.execution.rebuild_pending(harness.app, &provider, try digested(target));
}

// commonware `execution_rebuild_pending_rejects_stale_ancestor_quickly`: a block below the
// anchor's height is rejected before its parent is fetched.
test "stateful processor: rebuild_pending rejects a stale ancestor without fetching" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var chain: [5]TestBlock = undefined;
    var parent = TestBlock.genesis();
    for (&chain, 1..) |*block, view| {
        block.* = try harness.stage_pending_child(&parent, view);
        try harness.finalize(block);
        parent = block.*;
    }
    harness.execution.state.clear();
    const fetches = harness.provider_state.fetches;
    try testing.expectError(error.Invalid, rebuild(&harness, chain[1]));
    try testing.expectEqual(fetches, harness.provider_state.fetches);
}

// commonware `execution_rebuild_pending_rejects_sync_target_mismatch_before_caching`: a
// replayed batch whose sync target differs from the block's is rejected and not cached.
test "stateful processor: rebuild_pending rejects a sync target mismatch" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    harness.execution.state.clear();
    var target = chain[1].target;
    target.start = 1;
    target.end = 2;
    const mismatched = TestBlock.init(chain[0].digest(), chain[1].height(), chain[1].round, target);
    try harness.provider_state.insert(mismatched);
    try testing.expectError(error.Invalid, rebuild(&harness, mismatched));
    try testing.expect(!harness.execution.pending_contains(mismatched.digest()));
}

// commonware `execution_rebuild_pending_rejects_height_gap_to_processed_anchor`: a block at
// height 3 whose parent is the anchor at height 1 is rejected and not cached.
test "stateful processor: rebuild_pending rejects a height gap to the anchor" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    const gap = TestBlock.init(chain[0].digest(), .new(3), harness_mod.round(3), chain[0].target);
    try testing.expectError(error.Invalid, rebuild(&harness, gap));
    try testing.expect(!harness.execution.pending_contains(gap.digest()));
}

// commonware `execution_rebuild_pending_rejects_wrong_parent_digest`: a fetched parent
// whose digest is not the one the child names is rejected after one fetch.
test "stateful processor: rebuild_pending rejects a wrong parent digest" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    const wrong_parent = chain[1].with_root(u64_digest(999));
    try testing.expect(!wrong_parent.digest().eql(chain[2].parent()));
    harness.execution.state.clear();
    try harness.provider_state.blocks.put(gpa, chain[2].parent(), wrong_parent);
    const fetches = harness.provider_state.fetches;
    try testing.expectError(error.Invalid, rebuild(&harness, chain[2]));
    try testing.expectEqual(fetches + 1, harness.provider_state.fetches);
    try testing.expect(!harness.execution.pending_contains(chain[2].digest()));
}

// commonware `execution_rebuild_pending_rejects_parent_at_max_height`: an unverified
// ancestor claiming height `u64::MAX` (which has no successor) is rejected after one fetch.
test "stateful processor: rebuild_pending rejects a parent at the maximum height" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    const max: Height = .new(std.math.maxInt(u64));
    const parent = TestBlock.init(chain[1].parent(), max, chain[1].round, chain[1].target);
    const third = chain[2];
    const child = TestBlock.init(parent.digest(), third.height(), third.round, third.target);
    harness.execution.state.clear();
    try harness.provider_state.insert(parent);
    const fetches = harness.provider_state.fetches;
    try testing.expectError(error.Invalid, rebuild(&harness, child));
    try testing.expectEqual(fetches + 1, harness.provider_state.fetches);
    try testing.expect(!harness.execution.pending_contains(child.digest()));
}

// commonware `execution_rebuild_pending_returns_incomplete_when_parent_subscription_ends`
// and `execution_rebuild_pending_does_not_retry_closed_provider_forever`: a parent
// subscription that closes without a block leaves the rebuild incomplete after one fetch,
// without retrying. Adapted: commonware scripts a later answer after the closed one; here
// the provider no longer holds the parent, so a retry would fetch again.
test "stateful processor: rebuild_pending is incomplete once a parent fetch closes" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const chain = try finalized_chain(&harness);
    harness.execution.state.clear();
    try testing.expect(harness.provider_state.blocks.remove(chain[0].digest()));
    const fetches = harness.provider_state.fetches;
    try testing.expectError(error.Incomplete, rebuild(&harness, chain[1]));
    try testing.expectEqual(fetches + 1, harness.provider_state.fetches);
    try testing.expect(!harness.execution.pending_contains(chain[1].digest()));
}

const runtime = @import("runtime");
const db = @import("../../db/mod.zig");
const Any = harness_mod.Any;

fn counter(harness: *Harness) !?u64 {
    const readers = harness.databases.readers();
    const value = try harness_mod.read_applied(readers, harness_mod.counter_key());
    return if (value) |digest| harness_mod.digest_u64(digest) else null;
}

// commonware `execution_finalize_identical_duplicate_returns_false` and
// `execution_duplicate_finalization_skips_hooks`: a duplicate finalization of the applied
// block is reported as such, and applies nothing and runs no hook. Adapted: zigware's
// duplicate check is `redelivered`, which the processing loop consults before `finalize`
// (commonware's `finalize` returns false), so the hooks are never reached.
test "stateful processor: an identical duplicate finalization is a redelivery" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var observations: std.ArrayList(TestApp.Observation) = .empty;
    defer observations.deinit(gpa);
    harness.processor.app.observations = &observations;
    const genesis = TestBlock.genesis();
    const block = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block);
    try testing.expectEqual(1, observations.items.len);
    observations.clearRetainingCapacity();
    var again = try digested(block);
    defer again.deinit();
    try testing.expect(harness.processor.redelivered(&again));
    try testing.expectEqual(0, observations.items.len);
    try testing.expectEqual(1, try counter(&harness));
}

// commonware `execution_finalization_persists_state_to_db`: a finalized block's state
// survives reopening the database.
test "stateful processor: finalization persists state across a reopen" {
    var harness: Harness = undefined;
    try harness.init();
    const genesis = TestBlock.genesis();
    const block = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block);
    try testing.expectEqual(1, try counter(&harness));
    // Close the database (and the processor over it), then reopen it on the same storage.
    harness.processor.deinit();
    harness.databases.deinit();
    defer {
        harness.provider_state.deinit();
        harness.registry.deinit();
        harness.cache_ref.deinit();
        harness.storage.deinit();
    }
    const env: db.Env = .{
        .gpa = gpa,
        .io = testing.io,
        .storage = harness.storage.interface(),
        .scope = runtime.telemetry.metrics.Scope.init(&harness.registry).child("reopen"),
    };
    var reopened = try Any.Shared.open(env, harness.config(), null);
    defer reopened.deinit();
    const key = harness_mod.height_key(block.height());
    const view = (try harness_mod.read_applied(reopened.readers(), key)).?;
    try testing.expectEqual(1, harness_mod.digest_u64(view));
}

// commonware `execution_finalized_handoff_preserves_cached_and_reconstructed_captures`: a
// cached block finalizes from its batch without processing; an uncached one is
// reconstructed through `process`. Each capture sees the pre-apply state, and each
// finalized hook receives that capture after the apply.
test "stateful processor: finalized hooks see cached and reconstructed captures" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var observations: std.ArrayList(TestApp.Observation) = .empty;
    defer observations.deinit(gpa);
    const app = &harness.processor.app;
    app.observations = &observations;
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 7);
    const block2 = try harness.stage_pending_child(&block1, 11);

    var cached: Probe = .{ .target = block1.digest() };
    defer cached.deinit();
    app.probe = &cached;
    try harness.finalize(&block1);
    try testing.expectEqual(0, cached.calls); // Finalized from its cached batch.
    harness.execution.state.clear();
    var reconstructed: Probe = .{ .target = block2.digest() };
    defer reconstructed.deinit();
    app.probe = &reconstructed;
    try harness.finalize(&block2);
    try testing.expectEqual(1, reconstructed.calls);

    const expected = [_]TestApp.Observation{
        .{
            .captured = .{ .prior_counter = null, .batch_counter = 1, .batch_view = 7 },
            .post_counter = 1,
            .post_view = 7,
        },
        .{
            .captured = .{ .prior_counter = 1, .batch_counter = 2, .batch_view = 11 },
            .post_counter = 2,
            .post_view = 11,
        },
    };
    try testing.expectEqualSlices(TestApp.Observation, &expected, observations.items);
}

// commonware `execution_rejects_late_losing_fork_publication`: work on a losing fork that
// completes after the winner's finalization is not published to the pending cache.
test "stateful processor: a late losing fork publication is rejected" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const loser = try harness.stage_pending_child(&block1, 2);
    const winner = try harness.stage_pending_child(&block1, 3);
    const late_child, const merkleized = try harness.build_child(&loser, 4);
    try harness.finalize(&winner);
    const entry: harness_mod.Execution.Entry = .{
        .round = late_child.round,
        .parent = loser.digest(),
        .merkleized = merkleized,
    };
    try testing.expect(!try harness.execution.cache_pending(late_child.digest(), entry));
    try testing.expect(!harness.execution.pending_contains(late_child.digest()));
}

var fork_done: std.atomic.Value(bool) = .init(false);

fn fork_task(harness: *Harness, parent: harness_mod.TestBlock.Digest) anyerror!void {
    defer fork_done.store(true, .release);
    var forked = try harness.execution.fork_batches(parent);
    forked.deinit();
}

fn finalize_task(harness: *Harness, block: TestBlock) anyerror!void {
    return harness.finalize(&block);
}

// commonware `execution_forks_from_finalizing_winner_before_database_apply`: while a
// finalization waits to apply (a reader holds the database), its block stays forkable.
test "stateful processor: a finalizing winner stays forkable before the apply" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const winner = try harness.stage_pending_child(&genesis, 1);
    fork_done.store(false, .release);
    var guard = try harness.databases.readers().read();
    var guard_held = true;
    errdefer if (guard_held) guard.deinit();
    var finalizing = try testing.io.concurrent(finalize_task, .{ &harness, winner });
    // On failure, release the reader before stopping the finalization that waits on it.
    var finalizing_live = true;
    errdefer if (finalizing_live) {
        if (guard_held) guard.deinit();
        guard_held = false;
        _ = finalizing.cancel(testing.io) catch {};
    };
    try testing.io.sleep(.fromMilliseconds(20), .awake); // The apply waits for the reader.
    // Not applied yet (read through the held guard: a new read would queue behind the apply).
    try testing.expectEqual(null, try guard.get().inner.get(&harness_mod.counter_key()));
    // commonware polls the fork once: it must answer without waiting for the apply.
    var fork = try testing.io.concurrent(fork_task, .{ &harness, winner.digest() });
    var answered = false;
    for (0..200) |_| {
        if (fork_done.load(.acquire)) {
            answered = true;
            break;
        }
        try testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    guard_held = false;
    guard.deinit(); // Unblocks a fork waiting behind the apply, so the test ends either way.
    const forked = fork.await(testing.io);
    finalizing_live = false;
    try finalizing.await(testing.io);
    try testing.expect(answered);
    try forked;
    try testing.expectEqual(1, try counter(&harness));
}

fn expect_record(
    record: TestApp.ProcessRecord,
    finality: @import("execution.zig").Finality,
    blocks: []const TestBlock,
) !void {
    try testing.expectEqual(finality, record.finality);
    try testing.expectEqual(blocks.len, record.len);
    for (blocks, record.digests[0..blocks.len]) |block, digest| {
        try testing.expect(block.digest().eql(digest));
    }
}

// commonware `execution_process_ancestry_survives_recovery_and_finalization`: recovery
// processes an uncached block as a candidate with ancestry reaching past its parent; the
// cached result answers a later request without processing again; and finalizing the block
// once uncached processes it as finalized with the same ancestry.
test "stateful processor: process ancestry survives recovery and finalization" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var log: std.ArrayList(TestApp.ProcessRecord) = .empty;
    defer log.deinit(gpa);
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    try harness.finalize(&block2);
    const block3 = try harness.stage_pending_child(&block2, 3);
    harness.execution.state.clear();
    harness.app.process_log = &log;
    harness.processor.app.process_log = &log;

    try rebuild(&harness, block3);
    const expected = [_]TestBlock{ block3, block2, block1 };
    try testing.expectEqual(1, log.items.len);
    try expect_record(log.items[0], .candidate, &expected);
    try testing.expect(harness.execution.pending_contains(block3.digest()));
    // The cached state answers a later request without processing block3 again.
    try harness.execution.process_shared(harness.app, try harness.ancestry(&.{block3}));
    try testing.expectEqual(1, log.items.len);
    harness.execution.state.clear();
    try harness.finalize(&block3);
    try testing.expectEqual(2, log.items.len);
    try expect_record(log.items[1], .finalized, &expected);
    try testing.expectEqual(3, try counter(&harness));
}

fn wait_and_release(
    execution: *harness_mod.Execution,
    flight: *harness_mod.Execution.Flight,
) anyerror!void {
    defer execution.release(flight);
    return flight.wait();
}

/// Block 1 on genesis, built in `harness` but not cached, with a probe gating its processing.
fn gated_candidate(harness: *Harness, probe: *Probe) !struct { TestBlock, HeldGate } {
    const genesis = TestBlock.genesis();
    const block, var merkleized = try harness.build_child(&genesis, 1);
    merkleized.deinit();
    probe.* = .{ .target = block.digest() };
    const handles = try probe.add_gate();
    return .{ block, .{ .started = handles.started, .release = handles.release } };
}

const HeldGate = struct {
    started: @import("utils").channel.oneshot.Receiver(void),
    release: @import("utils").channel.oneshot.Sender(void),
    released: bool = false,

    fn open(gate: *HeldGate) !void {
        gate.released = true;
        try gate.release.send({});
    }

    fn deinit(gate: *HeldGate) void {
        gate.started.deinit();
        if (!gate.released) gate.release.deinit();
    }
};

// commonware `dropped_flight_handle_releases_waker`: of three requests sharing one held
// processing, one leaves while the others wait; the flight stays active, and the remaining
// two receive the result. Adapted: zigware's requests wait on the flight's event rather
// than registering wakers, so the dropped request's release is the observable part.
test "stateful processor: a request leaving a shared flight leaves it running" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var probe: Probe = undefined;
    const block, var gate = try gated_candidate(&harness, &probe);
    defer probe.deinit();
    defer gate.deinit();
    const genesis = TestBlock.genesis();
    const app: TestApp = .{ .probe = &probe };
    const execution = harness.execution;
    const io = testing.io;

    const first = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    try gate.started.recv();
    const second = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    const third = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    try testing.expectEqual(first, second);
    try testing.expectEqual(first, third);
    var first_wait = try io.concurrent(wait_and_release, .{ execution, first });
    var third_wait = try io.concurrent(wait_and_release, .{ execution, third });
    execution.release(second); // The second request leaves while the others wait.
    try testing.expect(!execution.flights_idle());
    try testing.expect(!gate.release.is_closed());
    try gate.open();
    try first_wait.await(io);
    try third_wait.await(io);
    try testing.expect(execution.flights_idle());
    try testing.expect(execution.pending_contains(block.digest()));
    try testing.expectEqual(1, probe.calls);
}

// commonware `woken_request_dropped_before_polling_hands_processing_on`: once the held
// processing finishes, the first request leaves without collecting the result; the second
// still completes it, and the block is cached.
test "stateful processor: a request leaving after completion hands the flight on" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var probe: Probe = undefined;
    const block, var gate = try gated_candidate(&harness, &probe);
    defer probe.deinit();
    defer gate.deinit();
    const genesis = TestBlock.genesis();
    const app: TestApp = .{ .probe = &probe };
    const execution = harness.execution;

    const first = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    try gate.started.recv();
    const second = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    var second_wait = try testing.io.concurrent(wait_and_release, .{ execution, second });
    try gate.open();
    execution.release(first); // Leaves without waiting for the result.
    try second_wait.await(testing.io);
    try testing.expect(execution.pending_contains(block.digest()));
    try testing.expect(execution.flights_idle());
}

fn rebuild_task(harness: *Harness, target: TestBlock) anyerror!void {
    return rebuild(harness, target);
}

/// Waits until `count` requests hold the flight processing `digest` (bounded).
fn await_joiners(execution: *harness_mod.Execution, digest: TestBlock.Digest, count: u32) !void {
    for (0..10_000) |_| {
        execution.mutex.lockUncancelable(testing.io);
        const flight = execution.flights.get(digest);
        const joiners = if (flight) |value| value.joiners else 0;
        execution.mutex.unlock(testing.io);
        if (joiners >= count) return;
        try testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

// commonware `overlapping_rebuilds_share_processing_across_cancellation`: rebuilds needing
// the same missing ancestor share its processing; cancelling requests, including the one
// that started it, leaves it running, and the rest complete from one call. Adapted: each
// rebuild runs on its own task, and dropping a request is cancelling its task.
test "stateful processor: overlapping rebuilds share processing across cancellation" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    const block3 = try harness.stage_pending_child(&block2, 3);
    harness.execution.state.clear();
    var probe: Probe = .{ .target = block1.digest() };
    defer probe.deinit();
    const handles = try probe.add_gate();
    var gate: HeldGate = .{ .started = handles.started, .release = handles.release };
    defer gate.deinit();
    harness.app.probe = &probe;
    const io = testing.io;

    var first = try io.concurrent(rebuild_task, .{ &harness, block2 });
    try gate.started.recv();
    var second = try io.concurrent(rebuild_task, .{ &harness, block2 });
    var third = try io.concurrent(rebuild_task, .{ &harness, block3 });
    var fourth = try io.concurrent(rebuild_task, .{ &harness, block2 });
    try await_joiners(harness.execution, block1.digest(), 4);
    try testing.expectEqual(1, probe.calls);
    // Cancelling requests, including the one that started the processing, leaves it running.
    try testing.expectError(error.Canceled, fourth.cancel(io));
    try testing.expectError(error.Canceled, first.cancel(io));
    try testing.expect(!gate.release.is_closed());
    try gate.open();
    try second.await(io);
    try third.await(io);
    try testing.expectEqual(1, probe.calls);
    try testing.expect(harness.execution.flights_idle());
    try testing.expect(harness.execution.pending_contains(block3.digest()));
}

// commonware `execution_finalization_prunes_before_finalized_hook_completes`: the losing
// fork is pruned from the pending cache before the finalized hook runs, while the winner's
// descendants stay cached.
test "stateful processor: finalization prunes before the finalized hook completes" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const loser = try harness.stage_pending_child(&block1, 2);
    const winner = try harness.stage_pending_child(&block1, 3);
    const winner_child = try harness.stage_pending_child(&winner, 4);
    var probe: Probe = .{ .target = winner.digest() };
    defer probe.deinit();
    const handles = try probe.add_gate();
    var gate: HeldGate = .{ .started = handles.started, .release = handles.release };
    defer gate.deinit();
    harness.processor.app.finalized_probe = &probe;

    var finalizing = try testing.io.concurrent(finalize_task, .{ &harness, winner });
    var live = true;
    errdefer if (live) {
        if (!gate.released) gate.open() catch {};
        finalizing.await(testing.io) catch {};
    };
    try gate.started.recv();
    const execution = harness.execution;
    try testing.expect(execution.pending_contains(winner_child.digest()));
    try testing.expect(!execution.pending_contains(block1.digest()));
    try testing.expect(!execution.pending_contains(loser.digest()));
    try gate.open();
    live = false;
    try finalizing.await(testing.io);
}
