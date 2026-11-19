//! commonware `glue/src/stateful/actor/processor/mod.rs` execution tests: forking, replay,
//! and the flight registry.

const std = @import("std");
const testing = std.testing;
const harness_mod = @import("testing.zig");

const Harness = harness_mod.Harness;
const TestBlock = harness_mod.TestBlock;
const TestApp = harness_mod.TestApp;
const Probe = harness_mod.Probe;
const digested = harness_mod.digested;
const round = harness_mod.round;
const u64_digest = harness_mod.u64_digest;

test "stateful execution: fork_batches rejects an unknown parent" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try testing.expectError(error.Invalid, harness.execution.fork_batches(u64_digest(999)));
}

test "stateful execution: rebuild_pending restores a missing chain" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    const block3 = try harness.stage_pending_child(&block2, 3);
    harness.execution.state.clear();

    var provider = harness.provider();
    try harness.execution.rebuild_pending(harness.app, &provider, try digested(block3));
    try testing.expect(harness.execution.pending_contains(block2.digest()));
    try testing.expect(harness.execution.pending_contains(block3.digest()));
    // block3's parent was fetched, then block2's parent (the anchor) ended the walk.
    try testing.expectEqual(2, harness.provider_state.fetches);
    try testing.expect(harness.execution.flights_idle());
}

/// The candidate block 1 on genesis, claiming a bad root unless `valid`.
fn candidate(harness: *Harness, valid: bool) !TestBlock {
    const genesis = TestBlock.genesis();
    const block, var merkleized = try harness.build_child(&genesis, 1);
    merkleized.deinit();
    return if (valid) block else block.with_root(u64_digest(999));
}

/// A completing flight leaves the registry, caches the block only after a success, and answers
/// every joined request with the same result (commonware
/// `flight_completion_removes_entry_and_shares_result` and `flight_shares_terminal_result`).
fn check_shared_result(valid: bool, joiner_count: u32) !void {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block = try candidate(&harness, valid);
    var probe: Probe = .{ .target = block.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    const app: TestApp = .{ .probe = &probe };
    const execution = harness.execution;

    // The gate holds the processing while the other requests join it.
    const first = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    try gate.started.recv();
    for (0..joiner_count) |_| {
        const joined = try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }));
        try testing.expectEqual(first, joined.?);
    }
    try testing.expectEqual(1 + joiner_count, first.joiners);
    try gate.release.send({});

    const expected: anyerror!void = if (valid) {} else error.Invalid;
    try testing.expectEqual(expected, first.wait());
    try testing.expect(!execution.flights.contains(block.digest()));
    try testing.expectEqual(valid, execution.pending_contains(block.digest()));
    for (0..joiner_count) |_| {
        try testing.expectEqual(expected, first.wait());
        execution.release(first);
    }
    execution.release(first);
    try testing.expect(execution.flights_idle());
    try testing.expectEqual(1, probe.calls);
}

test "stateful execution: a flight shares its terminal result" {
    try check_shared_result(true, 0);
    try check_shared_result(true, 1);
    try check_shared_result(true, 16);
    try check_shared_result(false, 1);
    try check_shared_result(false, 16);
}

test "stateful execution: a flight ends with its last request" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block = try candidate(&harness, true);
    var probe: Probe = .{ .target = block.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    defer gate.release.deinit();
    var fresh_gate = try probe.add_gate();
    defer fresh_gate.started.deinit();
    const app: TestApp = .{ .probe = &probe };
    const execution = harness.execution;

    const first = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    try gate.started.recv();
    // Releasing another request leaves the flight active.
    const other = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    execution.release(other);
    try testing.expect(!execution.flights_idle());

    // A later request joins the same flight and keeps it alive once the first leaves.
    const late = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    try testing.expectEqual(first, late);
    execution.release(first);
    try testing.expect(!execution.flights_idle());
    try testing.expect(!gate.release.is_closed());

    // The last request cancels the processing and removes the entry.
    execution.release(late);
    try testing.expect(execution.flights_idle());
    try testing.expect(gate.release.is_closed());
    try testing.expect(!execution.pending_contains(block.digest()));

    // A new request starts a new flight and processes the block again.
    const fresh = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    defer execution.release(fresh);
    try fresh_gate.started.recv();
    try testing.expect(!execution.flights_idle());
    try fresh_gate.release.send({});
    try fresh.wait();
    try testing.expect(execution.pending_contains(block.digest()));
    try testing.expectEqual(2, probe.calls);
}

test "stateful execution: a cached or anchored block needs no flight" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block = try harness.stage_pending_child(&genesis, 1);
    const execution = harness.execution;
    try testing.expectEqual(null, try execution.join_flight(.{}, try harness.ancestry(&.{block})));
    const anchored = try harness.ancestry(&.{genesis});
    try testing.expectEqual(null, try execution.join_flight(.{}, anchored));
    try execution.process_shared(.{}, try harness.ancestry(&.{block}));
    try testing.expect(execution.flights_idle());
}

test "stateful execution: replay rejects a fork at or below the anchor's height" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    // A sibling of block1 at its height, and a child of the sibling.
    const sibling = try harness.stage_pending_child(&genesis, 2);
    const child = try harness.stage_pending_child(&sibling, 3);
    try harness.finalize(&block1);
    try testing.expect(!harness.execution.pending_contains(sibling.digest()));

    var provider = harness.provider();
    const fetches = harness.provider_state.fetches;
    const result = harness.execution.rebuild_pending(harness.app, &provider, try digested(child));
    try testing.expectError(error.Invalid, result);
    // The walk stops at the sibling without fetching below the anchor's height.
    try testing.expectEqual(fetches + 1, harness.provider_state.fetches);
}

test "stateful execution: replay rejects non-contiguous and missing ancestry" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    harness.execution.state.clear();
    var provider = harness.provider();

    // A block at height 3 naming block1 (height 1) as its parent skips height 2.
    const skipping = TestBlock.init(block1.digest(), .new(3), round(3), block1.target);
    const execution = harness.execution;
    const skipped = execution.rebuild_pending(harness.app, &provider, try digested(skipping));
    try testing.expectError(error.Invalid, skipped);

    // A parent the provider does not have leaves the replay incomplete.
    const orphan = TestBlock.init(u64_digest(7), .new(2), round(2), block1.target);
    const missing = execution.rebuild_pending(harness.app, &provider, try digested(orphan));
    try testing.expectError(error.Incomplete, missing);
    try testing.expect(!execution.pending_contains(block1.digest()));
}

// commonware `execution_rebuild_pending_bounds_parent_requests_by_round`: the recovery walk
// requests the parents of block3 and block2, and both requests carry block3's round as their
// bound, so marshal can retire them once its processed round floor covers that round.
test "stateful execution: rebuild_pending bounds parent requests by round" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    const block3 = try harness.stage_pending_child(&block2, 3);
    harness.execution.state.clear();
    const requested_before = harness.provider_state.bounds.items.len;

    var provider = harness.provider();
    try harness.execution.rebuild_pending(harness.app, &provider, try digested(block3));
    const bounds = harness.provider_state.bounds.items[requested_before..];
    try testing.expect(bounds.len >= 2); // The walk requests both parents.
    for (bounds) |bound| try testing.expectEqual(@as(?@TypeOf(round(3)), round(3)), bound);
}

const utils = @import("utils");

test "stateful execution: finalizing an in-flight winner panics" {
    // commonware `processor/mod.rs` `execution_finalization_rejects_in_flight_winner`
    // (#[should_panic]).
    const expected = "finalized block must not be processed when its finalization starts";
    try utils.death.expect_panic(@src(), expected, struct {
        fn body() !void {
            var harness: Harness = undefined;
            try harness.init();
            defer harness.deinit();
            const genesis = TestBlock.genesis();
            const winner = try candidate(&harness, true);
            var probe: Probe = .{ .target = winner.digest() };
            defer probe.deinit();
            var gate = try probe.add_gate();
            defer gate.started.deinit();
            const app: TestApp = .{ .probe = &probe };
            // The gate keeps the winner's processing in flight.
            const ancestry = try harness.ancestry(&.{ winner, genesis });
            _ = (try harness.execution.join_flight(app, ancestry)).?;
            try gate.started.recv();
            try harness.finalize(&winner);
        }
    }.body);
}

test "stateful execution: a conflicting finalized block at the anchor height panics" {
    // commonware `processor/mod.rs` `execution_finalize_panics_on_conflicting_duplicate_height`
    // (#[should_panic]).
    const expected = "received conflicting finalized block at anchor height";
    try utils.death.expect_panic(@src(), expected, struct {
        fn body() !void {
            var harness: Harness = undefined;
            try harness.init();
            defer harness.deinit();
            const genesis = TestBlock.genesis();
            const canonical = try harness.stage_pending_child(&genesis, 1);
            const conflicting = try harness.stage_pending_child(&genesis, 2);
            try harness.finalize(&canonical);
            try harness.finalize(&conflicting);
        }
    }.body);
}

test "stateful execution: finalizing an unlinked successor panics" {
    // commonware `processor/mod.rs` `execution_finalize_panics_on_unlinked_successor`
    // (#[should_panic]).
    // zigware asserts the parent is the branch anchor ("does not extend the applied tip").
    try utils.death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            var harness: Harness = undefined;
            try harness.init();
            defer harness.deinit();
            const genesis = TestBlock.genesis();
            const canonical = try harness.stage_pending_child(&genesis, 1);
            const sibling = try harness.stage_pending_child(&genesis, 2);
            try harness.finalize(&canonical);
            // A height 2 block built on the canonical state, pointed at the sibling.
            const child, var merkleized = try harness.build_child(&canonical, 3);
            merkleized.deinit();
            const unlinked = TestBlock.init(
                sibling.digest(),
                child.height(),
                round(3),
                child.target,
            );
            try harness.finalize(&unlinked);
        }
    }.body);
}

test "stateful execution: a reconstruction that misses the block commitments panics" {
    // commonware `processor/mod.rs` `execution_finalize_reconstruction_rejects_state_root_mismatch`
    // (#[should_panic]).
    const expected = "finalize reconstruction must match block commitments";
    try utils.death.expect_panic(@src(), expected, struct {
        fn body() !void {
            var harness: Harness = undefined;
            try harness.init();
            defer harness.deinit();
            const genesis = TestBlock.genesis();
            const block1 = try harness.stage_pending_child(&genesis, 1);
            harness.execution.state.clear();
            const wrong = block1.with_root(u64_digest(999));
            try harness.finalize(&wrong);
        }
    }.body);
}

test "stateful execution: a finalized block that skips unapplied heights panics" {
    // commonware `core/processing.rs live_floor_skip_panics` (#[should_panic]).
    // Processing hands a finalized block to `Processor.finalize`, which asserts it is the
    // anchor's successor; the test drives that call directly.
    try utils.death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            var harness: Harness = undefined;
            try harness.init();
            defer harness.deinit();
            const genesis = TestBlock.genesis();
            const block1 = try harness.stage_pending_child(&genesis, 1);
            const block2 = try harness.stage_pending_child(&block1, 2);
            // Height 2 on the genesis anchor skips the unapplied height 1; it names the anchor
            // as its parent, so only the height check can reject it.
            const skipping = TestBlock.init(genesis.digest(), .new(2), round(2), block2.target);
            try harness.finalize(&skipping);
        }
    }.body);
}
