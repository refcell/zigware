//! commonware `glue/src/stateful/actor/core/processing.rs` tests, first half (lines 1070-3396):
//! independence of verifications, rejections by the application and by an unexecutable or
//! conflicting parent, and proposals that decline on incomplete ancestry. The fixture is in
//! `testing.zig`; commonware's `GatedApp` gates are the processor harness's `Probe` gates.

const std = @import("std");
const testing = std.testing;
const fixture_mod = @import("testing.zig");

const gpa = testing.allocator;
const harness_mod = fixture_mod.harness;
const Fixture = fixture_mod.Fixture;
const TestBlock = harness_mod.TestBlock;
const Probe = harness_mod.Probe;

fn check(fixture: *Fixture) void {
    fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
}

/// A child of `parent` at `view` whose state is not cached, so verifying it processes it.
fn uncached_child(fixture: *Fixture, parent: *const TestBlock, view: u64) !TestBlock {
    const block, var batch = try fixture.harness.build_child(parent, view);
    batch.deinit();
    return block;
}

test "stateful processing: independent verifications do not block each other" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const first = try uncached_child(&fixture, &genesis, 1);
    const second = try uncached_child(&fixture, &genesis, 2);
    // A probe without a target gates every processed block, in call order.
    var probe: Probe = .{ .target = null };
    defer probe.deinit();
    var first_gate = try probe.add_gate();
    defer first_gate.started.deinit();
    var second_gate = try probe.add_gate();
    defer second_gate.started.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    var first_verdict = try fixture.verify(&.{ first, genesis });
    defer first_verdict.deinit();
    try first_gate.started.recv();
    // The second starts while the first is held inside the application.
    var second_verdict = try fixture.verify(&.{ second, genesis });
    defer second_verdict.deinit();
    try second_gate.started.recv();
    try first_gate.release.send({});
    try second_gate.release.send({});
    try testing.expect(try first_verdict.recv());
    try testing.expect(try second_verdict.recv());
}

test "stateful processing: an application rejection returns false" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    // A commitment the processed state cannot match: the application's verdict is invalid.
    const valid = try uncached_child(&fixture, &genesis, 1);
    const block = valid.with_root(harness_mod.u64_digest(404));
    var probe: Probe = .{ .target = block.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    var verdict = try fixture.verify(&.{ block, genesis });
    defer verdict.deinit();
    try gate.started.recv();
    try gate.release.send({});
    try testing.expect(!try verdict.recv());
}

test "stateful processing: an unexecutable parent rejects its child" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const valid_parent = try uncached_child(&fixture, &genesis, 1);
    const parent = valid_parent.with_root(harness_mod.u64_digest(13));
    const child = TestBlock.init(parent.digest(), .new(2), harness_mod.round(2), parent.target);
    var probe: Probe = .{ .target = child.digest() };
    defer probe.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    // The parent's processing invalidates the ancestry before the child is processed.
    var verdict = try fixture.verify(&.{ child, parent, genesis });
    defer verdict.deinit();
    try testing.expect(!try verdict.recv());
    try testing.expectEqual(@as(u32, 0), probe.calls);
}

test "stateful processing: a conflicting block at the processed height is rejected" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const built = (try fixture.propose(genesis, 1)).?;
    const canonical = built.inner().*;
    built.discard();
    var waiter = try fixture.finalize(canonical);
    defer waiter.deinit();
    try waiter.wait();
    // Marshal reports the canonical block at its height, as commonware's fixture does.
    const state = &fixture.harness.provider_state;
    try state.canonical.put(gpa, canonical.height().get(), canonical.digest());

    const round = harness_mod.round(2);
    const conflicting = TestBlock.init(genesis.digest(), .new(1), round, genesis.target);
    var verdict = try fixture.verify(&.{ conflicting, genesis });
    defer verdict.deinit();
    try testing.expect(!try verdict.recv());
}

test "stateful processing: a proposal on incomplete ancestry declines" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    // The parent's own parent is neither cached nor fetchable.
    const target = genesis.target;
    const outgoing = TestBlock.init(genesis.digest(), .new(1), harness_mod.round(1), target);
    const parent = TestBlock.init(outgoing.digest(), .new(2), harness_mod.round(2), target);
    try testing.expectEqual(null, try fixture.propose(parent, 3));

    // The loop keeps serving: a database subscription after the proposal resolves.
    const databases = try fixture.mailbox.?.subscribe_databases();
    try testing.expectEqual(fixture.harness.databases.cell, databases.cell);
}

test "stateful processing: a recovered parent answers its own verification" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const parent = try fixture.harness.stage_pending_child(&genesis, 1);
    const child, var batch = try fixture.harness.build_child(&parent, 2);
    batch.deinit();
    // Neither block's state is cached: verifying the child recovers the parent.
    fixture.harness.execution.state.clear();
    var probe: Probe = .{ .target = parent.digest() };
    defer probe.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    var verdict = try fixture.verify(&.{ child, parent });
    defer verdict.deinit();
    try testing.expect(try verdict.recv());
    try testing.expectEqual(@as(u32, 1), probe.calls);
    // The recovered state answers the parent's own verifications without processing it again.
    for (0..2) |_| {
        var again = try fixture.verify(&.{ parent, genesis });
        defer again.deinit();
        try testing.expect(try again.recv());
    }
    try testing.expectEqual(@as(u32, 1), probe.calls);
}
