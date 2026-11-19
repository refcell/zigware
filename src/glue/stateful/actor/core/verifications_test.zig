//! Tests of the core actor's `Verifications` handler: answers, abstentions (a waiting
//! verification never votes against its block), cancellation, recovered builds, and pausing.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const harness_mod = @import("../processor/testing.zig");
const verifications_mod = @import("verifications.zig");

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
const Harness = harness_mod.Harness;
const TestBlock = harness_mod.TestBlock;
const Probe = harness_mod.Probe;
const Handler = verifications_mod.Verifications(harness_mod.TestP);

fn handler(harness: *Harness) Handler {
    return .init(gpa, io, harness.processor.verifier(), harness.provider());
}

/// Schedules a verification of `blocks` (newest first) and returns its verdict's receiver.
fn verify(state: *Handler, harness: *Harness, blocks: []const TestBlock) !oneshot.Receiver(bool) {
    const pair = try oneshot.channel(bool, gpa, io);
    state.schedule(.{ .verify = .{
        .ancestry = try harness.ancestry(blocks),
        .verification = pair.sender,
    } });
    return pair.receiver;
}

/// Runs the handler until no request is live.
fn settle(state: *Handler) !void {
    // Each pass ends one phase; every request has a bounded number of steps.
    var passes: u32 = 0;
    while (state.len() > 0) : (passes += 1) {
        try testing.expect(passes < 64);
        try state.complete_next();
    }
}

test "stateful verifications: answer by verdict" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var state = handler(&harness);
    defer state.deinit();
    const genesis = TestBlock.genesis();
    const valid, var batch = try harness.build_child(&genesis, 1);
    batch.deinit();
    const invalid = valid.with_root(harness_mod.u64_digest(999));

    var accepted = try verify(&state, &harness, &.{ valid, genesis });
    defer accepted.deinit();
    var rejected = try verify(&state, &harness, &.{ invalid, genesis });
    defer rejected.deinit();
    try settle(&state);
    try testing.expect(try accepted.recv());
    try testing.expect(!try rejected.recv());
    try testing.expect(harness.execution.pending_contains(valid.digest()));
}

test "stateful verifications: a waiting verification gives no vote" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var state = handler(&harness);
    defer state.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    harness.execution.state.clear();
    harness.provider_state.blocks.clearRetainingCapacity();

    // Neither block2's parent nor block1's parent can be fetched: commonware stays pending.
    var parentless = try verify(&state, &harness, &.{block2});
    defer parentless.deinit();
    var unrecoverable = try verify(&state, &harness, &.{ block2, block1 });
    defer unrecoverable.deinit();
    try settle(&state);
    // No verdict at all, never `false`: the oneshot is dropped unsent.
    try testing.expectError(error.Closed, parentless.recv());
    try testing.expectError(error.Closed, unrecoverable.recv());
    try testing.expect(!harness.execution.pending_contains(block2.digest()));
}

test "stateful verifications: a cancelled request is dropped unanswered" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var state = handler(&harness);
    defer state.deinit();
    const genesis = TestBlock.genesis();
    const block, var batch = try harness.build_child(&genesis, 1);
    batch.deinit();
    var receiver = try verify(&state, &harness, &.{ block, genesis });
    receiver.deinit();
    try settle(&state);
    try testing.expectEqual(0, state.len());
}

test "stateful verifications: a recovery queues its build on the parent" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var state = handler(&harness);
    defer state.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    harness.execution.state.clear();

    const pair = try oneshot.channel(bool, gpa, io);
    var response = pair.receiver;
    defer response.deinit();
    state.schedule(.{ .recover = .{
        .ancestry = try harness.ancestry(&.{block2}),
        .response = pair.sender,
    } });
    try settle(&state);
    try testing.expectEqual(1, state.builds.items.len);
    try testing.expectEqual(block2.digest(), state.builds.items[0].ancestry.peek().?.digest());
    try testing.expect(harness.execution.pending_contains(block2.digest()));
    try testing.expectError(error.Empty, response.try_recv());

    // A recovery whose ancestry runs out declines.
    harness.execution.state.clear();
    harness.provider_state.blocks.clearRetainingCapacity();
    const lost = try oneshot.channel(bool, gpa, io);
    var declined = lost.receiver;
    defer declined.deinit();
    state.schedule(.{ .recover = .{
        .ancestry = try harness.ancestry(&.{block2}),
        .response = lost.sender,
    } });
    try settle(&state);
    try testing.expect(!try declined.recv());
}

test "stateful verifications: pruning parks acquisition until resume" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var state = handler(&harness);
    defer state.deinit();
    const genesis = TestBlock.genesis();
    const block, var batch = try harness.build_child(&genesis, 1);
    batch.deinit();

    // Hold the block's processing so the request is executing when pruning starts.
    var probe: Probe = .{ .target = block.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    state.verifier.app.probe = &probe;
    var receiver = try verify(&state, &harness, &.{ block, genesis });
    defer receiver.deinit();
    try state.complete_next(); // Acquisition ends; the step starts.
    try gate.started.recv();
    try gate.release.send({});
    // Pruning waits for the step, then holds the finished request until resume.
    try state.pause(null);
    try testing.expectEqual(1, state.len());
    try testing.expectError(error.Empty, receiver.try_recv());
    state.@"resume"();
    try settle(&state);
    try testing.expect(try receiver.recv());
}
