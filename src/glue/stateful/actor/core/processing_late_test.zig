//! commonware `glue/src/stateful/actor/core/processing.rs` tests, second half (from
//! `finalization_joins_incompatible_verification`); the first half is processing_test.zig.
//! Barriers complete synchronously here, so tests built on a pending barrier or gated
//! ancestry acquisition say in their comment how they were adapted.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const utils = @import("utils");
const core = @import("testing.zig");

const harness = core.harness;
const TestBlock = harness.TestBlock;
const Fixture = core.Fixture;
const gpa = testing.allocator;
const io = testing.io;

fn deinit_fixture(fixture: *Fixture) void {
    fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
}

// commonware `finalization_joins_incompatible_verification`: a verification on a fork the
// finalization abandons keeps running while finalization waits for it, then resolves
// false. Adapted: commonware also parks an ancestry acquisition to learn when
// finalization paused; here the pending acknowledgement shows the wait.
test "stateful processing: finalization joins an incompatible verification" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const winner, var winner_batch = try fixture.harness.build_child(&genesis, 1);
    winner_batch.deinit();
    // The fork's parent is staged (cached and fetchable) so its child can be built on it.
    const losing_parent = try fixture.harness.stage_pending_child(&genesis, 2);
    const losing_child, var child_batch = try fixture.harness.build_child(&losing_parent, 3);
    child_batch.deinit();

    var fork = try fixture.verify(&.{ losing_parent, genesis });
    defer fork.deinit();
    try testing.expect(try fork.recv());

    var probe: harness.Probe = .{ .target = losing_child.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;
    var child = try fixture.verify(&.{ losing_child, losing_parent });
    defer child.deinit();
    try started.recv();

    var waiter = try fixture.finalize(winner);
    defer waiter.deinit();
    // Give finalization time to act: it must still be waiting on the gated child.
    try testing.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(null, waiter.poll());
    try release.send({});
    try waiter.wait();
    try testing.expect(!try child.recv());
}

// commonware `finalization_rejects_deep_incompatible_verification`: a gated verification two
// blocks deep on a fork the finalization prunes keeps running while finalization waits,
// then resolves false. Adapted like the shallow case: the pending acknowledgement shows the
// wait instead of a parked ancestry acquisition.
test "stateful processing: finalization rejects a deep incompatible verification" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const winner, var winner_batch = try fixture.harness.build_child(&genesis, 1);
    winner_batch.deinit();
    const losing_parent = try fixture.harness.stage_pending_child(&genesis, 2);
    const losing_child = try fixture.harness.stage_pending_child(&losing_parent, 3);
    const grandchild, var grandchild_batch = try fixture.harness.build_child(&losing_child, 4);
    grandchild_batch.deinit();

    var parent = try fixture.verify(&.{ losing_parent, genesis });
    defer parent.deinit();
    try testing.expect(try parent.recv());
    var child = try fixture.verify(&.{ losing_child, losing_parent });
    defer child.deinit();
    try testing.expect(try child.recv());

    var probe: harness.Probe = .{ .target = grandchild.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;
    var deep = try fixture.verify(&.{ grandchild, losing_child });
    defer deep.deinit();
    try started.recv();

    var waiter = try fixture.finalize(winner);
    defer waiter.deinit();
    try testing.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectEqual(null, waiter.poll());
    try release.send({});
    try waiter.wait();
    try testing.expect(!try deep.recv());
}

// commonware `anchor_redelivery_keeps_retained_verification_progressing`: redelivering the
// finalized anchor is acknowledged without rerunning its hooks, and does not resolve a
// gated verification of its child. Adapted: the harness anchors at genesis, so block 1 is
// finalized first and becomes the anchor that is redelivered.
test "stateful processing: anchor redelivery keeps a retained verification running" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    const finalized = try fixture.harness.stage_pending_child(&genesis, 1);
    var first = try fixture.finalize(finalized);
    defer first.deinit();
    try first.wait();
    const child, var batch = try fixture.harness.build_child(&finalized, 2);
    batch.deinit();

    var probe: harness.Probe = .{ .target = child.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    fixture.processing.verifications.verifier.app.probe = &probe;
    var hooks: harness.Probe = .{ .target = finalized.digest() };
    defer hooks.deinit();
    const app = &fixture.processing.processor.app;
    app.probe = &hooks;
    app.capture_probe = &hooks;
    app.finalized_probe = &hooks;

    var verdict = try fixture.verify(&.{ child, finalized });
    defer verdict.deinit();
    try started.recv();
    var again = try fixture.finalize(finalized);
    defer again.deinit();
    try again.wait();
    try testing.expect(!verdict.is_ready());
    try release.send({});
    try testing.expect(try verdict.recv());
    try testing.expectEqual(0, hooks.calls);
}

// commonware `fresh_boot_genesis_skips_hooks`: on a fresh boot the genesis anchor's
// finalization is acknowledged without processing, capture, or finalized hooks.
test "stateful processing: a fresh boot's genesis finalization skips the hooks" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer deinit_fixture(&fixture);
    const genesis = TestBlock.genesis();
    var hooks: harness.Probe = .{ .target = genesis.digest() };
    defer hooks.deinit();
    const app = &fixture.processing.processor.app;
    app.probe = &hooks;
    app.capture_probe = &hooks;
    app.finalized_probe = &hooks;
    var waiter = try fixture.finalize(genesis);
    defer waiter.deinit();
    try waiter.wait();
    try testing.expectEqual(0, hooks.calls);
    try testing.expectEqual(null, try fixture.counter());
}

fn run_processing(processing: *core.Processing) anyerror!void {
    return processing.run();
}

// commonware `deferred_verification_resumes_after_sync`: a verification deferred before
// the processing loop starts (as the syncing actor defers one until its databases are
// ready) runs once the loop starts, and answers.
test "stateful processing: a deferred verification resumes once processing starts" {
    var fixture: Fixture = undefined;
    try fixture.harness.init();
    fixture.prunes = .empty;
    fixture.future = null;
    const pair = try actor.mailbox.new(core.Message, gpa, io, 8);
    fixture.receiver = pair.receiver;
    fixture.mailbox = core.Mailbox.init(gpa, io, pair.sender);
    const marshal: core.TestMarshal = .{ .prunes = &fixture.prunes };
    const provider = fixture.harness.provider();
    const processor = &fixture.harness.processor;
    fixture.processing = .init(gpa, io, &fixture.receiver, provider, marshal, processor);
    defer deinit_fixture(&fixture);

    const genesis = TestBlock.genesis();
    const block, var batch = try fixture.harness.build_child(&genesis, 1);
    batch.deinit();
    const verdict_pair = try utils.channel.oneshot.channel(bool, gpa, io);
    var verdict = verdict_pair.receiver;
    defer verdict.deinit();
    fixture.processing.defer_verification(.{
        .ancestry = try fixture.harness.ancestry(&.{ block, genesis }),
        .verification = verdict_pair.sender,
    });
    try testing.expect(!verdict.is_ready());

    fixture.future = try io.concurrent(run_processing, .{&fixture.processing});
    try testing.expect(try verdict.recv());
}
