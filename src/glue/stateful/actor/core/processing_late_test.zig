//! commonware `glue/src/stateful/actor/core/processing.rs` tests, second half (from
//! `finalization_joins_incompatible_verification`); the first half is processing_test.zig.
//! Barriers complete synchronously here, so tests built on a pending barrier or gated
//! ancestry acquisition say in their comment how they were adapted.

const std = @import("std");
const testing = std.testing;
const core = @import("testing.zig");

const harness = core.harness;
const TestBlock = harness.TestBlock;
const Fixture = core.Fixture;

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
