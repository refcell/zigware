//! Tests of the processor's `Verifier`: requests answered without execution, abstentions,
//! and the replay-then-verify step order (commonware `verifier.rs`'s contract).

const std = @import("std");
const testing = std.testing;
const harness_mod = @import("testing.zig");

const gpa = testing.allocator;
const Harness = harness_mod.Harness;
const TestBlock = harness_mod.TestBlock;
const Verifier = harness_mod.Processor.Verifier;
const round = harness_mod.round;

fn prepare(harness: *Harness, blocks: []const TestBlock, verify: bool) !Verifier.Prepared {
    var verifier = harness.processor.verifier();
    var provider = harness.provider();
    return verifier.prepare(&provider, try harness.ancestry(blocks), verify);
}

test "stateful verifier: a cached block verifies without execution" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    var prepared = try prepare(&harness, &.{ block1, genesis }, true);
    defer prepared.deinit(gpa);
    try testing.expect(!prepared.verify);
    try testing.expectEqual(null, prepared.replay);
    var verifier = harness.processor.verifier();
    const provider = harness.provider();
    try testing.expectEqual(null, try verifier.next(&provider, &prepared));
}

test "stateful verifier: blocks at or below the anchor verify only when canonical" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    const rival1, var unused1 = try harness.build_child(&genesis, 5);
    unused1.deinit();
    try harness.finalize(&block1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    try harness.finalize(&block2);

    // block1 is canonical below the anchor; block2 is the anchor.
    var canonical = try prepare(&harness, &.{ block1, genesis }, true);
    canonical.deinit(gpa);
    var anchored = try prepare(&harness, &.{ block2, block1 }, true);
    anchored.deinit(gpa);
    // A competing block at either height is invalid.
    try testing.expectError(error.Invalid, prepare(&harness, &.{ rival1, genesis }, true));
    const rival2 = TestBlock.init(block1.digest(), .new(2), round(6), block2.target);
    try testing.expectError(error.Invalid, prepare(&harness, &.{ rival2, block1 }, true));
    // Without the canonical block in local storage, the verification waits.
    harness.provider_state.canonical.clearRetainingCapacity();
    try testing.expectError(error.Waiting, prepare(&harness, &.{ rival1, genesis }, true));
}

test "stateful verifier: missing ancestry makes verification wait and recovery incomplete" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    harness.execution.state.clear();
    harness.provider_state.blocks.clearRetainingCapacity();

    // block2 without its parent: the verification cannot fetch it.
    try testing.expectError(error.Waiting, prepare(&harness, &.{block2}, true));
    try testing.expectError(error.Waiting, prepare(&harness, &.{}, true));
    // block2 with its parent, but block1's own parent cannot be fetched: recovery runs out.
    try testing.expectError(error.Waiting, prepare(&harness, &.{ block2, block1 }, true));
    try testing.expectError(error.Incomplete, prepare(&harness, &.{}, false));
    // A proposal on block2 needs block1's state, whose ancestry is gone.
    try testing.expectError(error.Incomplete, prepare(&harness, &.{block2}, false));
}

test "stateful verifier: replays the missing path, then verifies the block" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    const block3, var unused = try harness.build_child(&block2, 3);
    unused.deinit();
    harness.execution.state.clear();

    var verifier = harness.processor.verifier();
    const provider = harness.provider();
    var prepared = try prepare(&harness, &.{ block3, block2 }, true);
    defer prepared.deinit(gpa);
    const expected = [_]TestBlock{ block1, block2, block3 };
    for (expected) |block| {
        const next = (try verifier.next(&provider, &prepared)).?;
        try testing.expectEqual(block.digest(), next.step.digest);
        try testing.expectEqual(block.parent(), next.step.parent);
        try verifier.process(next.ancestry);
        try testing.expect(harness.execution.pending_contains(block.digest()));
    }
    try testing.expectEqual(null, try verifier.next(&provider, &prepared));
    try testing.expect(harness.execution.flights_idle());
}

test "stateful verifier: a proposal recovers its parent without verifying it" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    harness.execution.state.clear();

    var verifier = harness.processor.verifier();
    const provider = harness.provider();
    var prepared = try prepare(&harness, &.{block2}, false);
    var steps: u32 = 0;
    while (try verifier.next(&provider, &prepared)) |next| : (steps += 1) {
        try verifier.process(next.ancestry);
    }
    try testing.expectEqual(2, steps);
    var ancestry = prepared.finish(gpa);
    defer ancestry.deinit();
    try testing.expectEqual(block2.digest(), ancestry.peek().?.digest());
    try testing.expect(harness.execution.pending_contains(block2.digest()));
}
