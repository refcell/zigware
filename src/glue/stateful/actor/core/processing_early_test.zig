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
const oneshot = @import("utils").channel.oneshot;

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

/// Waits until `sender`'s receiver closes (bounded): the application's processing was dropped.
fn await_closed(sender: *const oneshot.Sender(void)) !void {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        if (sender.is_closed()) return;
        try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

/// Waits until `waiter`'s block is acknowledged (bounded, so a lost acknowledgement fails).
fn await_acknowledged(waiter: *const @import("utils").acknowledgement.Exact.Waiter) !void {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        if (waiter.poll()) |outcome| return outcome;
        try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

/// A parent whose state is not cached, and its child (uncached too), over genesis.
fn uncached_pair(fixture: *Fixture) !struct { TestBlock, TestBlock } {
    const genesis = TestBlock.genesis();
    const parent = try fixture.harness.stage_pending_child(&genesis, 1);
    const child, var batch = try fixture.harness.build_child(&parent, 2);
    batch.deinit();
    fixture.harness.execution.state.clear();
    return .{ parent, child };
}

test "stateful processing: an abandoned verification cancels with its caller" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const block = try uncached_child(&fixture, &genesis, 1);
    var probe: Probe = .{ .target = block.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    var verdict = try fixture.verify(&.{ block, genesis });
    try gate.started.recv();
    // Dropping the caller drops the application's processing, which closes its release gate.
    verdict.deinit();
    try await_closed(&gate.release);
    gate.release.deinit();
    // commonware's second half (an acquisition that never completes) has no counterpart: an
    // unfetchable parent here answers `error.Waiting` at once instead of acquiring forever.
}

test "stateful processing: abandoned incomplete verifications do not block later work" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const block1 = try uncached_child(&fixture, &genesis, 1);
    var probe: Probe = .{ .target = null };
    defer probe.deinit();
    var first_gate = try probe.add_gate();
    defer first_gate.started.deinit();
    var second_gate = try probe.add_gate();
    defer second_gate.started.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    // A verification missing its parent, abandoned once the loop has received it.
    var incomplete = try fixture.verify(&.{block1});
    try fixture.barrier();
    incomplete.deinit();
    var first = try fixture.verify(&.{ block1, genesis });
    defer first.deinit();
    try first_gate.started.recv();
    try first_gate.release.send({});
    try testing.expect(try first.recv());

    const block2, var batch = try fixture.harness.build_child(&block1, 2);
    batch.deinit();
    var missing_parent = try fixture.verify(&.{block2});
    try fixture.barrier();
    missing_parent.deinit();
    var second = try fixture.verify(&.{ block2, block1 });
    defer second.deinit();
    try second_gate.started.recv();
    try second_gate.release.send({});
    try testing.expect(try second.recv());
}

test "stateful processing: a proposal shares its parent's replay with a verification" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const parent, const child = try uncached_pair(&fixture);
    var probe: Probe = .{ .target = parent.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    // Verifying the child replays the missing parent, held in the application.
    var verdict = try fixture.verify(&.{ child, parent });
    defer verdict.deinit();
    try gate.started.recv();
    // A proposal on the parent joins that replay instead of processing the parent again.
    var proposal = try fixture.propose_async(&.{ parent, genesis }, 3);
    defer proposal.deinit();
    try fixture.await_joiners(parent.digest(), 2);
    try testing.expectEqual(@as(u32, 1), probe.calls);
    try gate.release.send({});
    try testing.expect(try verdict.recv());
    const built = try proposal.recv();
    built.discard();
    try testing.expectEqual(@as(u32, 1), probe.calls);
}

test "stateful processing: a verification keeps a cancelled proposal's replay running" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const parent, const child = try uncached_pair(&fixture);
    var probe: Probe = .{ .target = parent.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    // A second gate detects any repeated processing of the parent.
    var duplicate = try probe.add_gate();
    defer duplicate.started.deinit();
    defer duplicate.release.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;

    var proposal = try fixture.propose_async(&.{ parent, genesis }, 3);
    try gate.started.recv();
    var verdict = try fixture.verify(&.{ child, parent });
    defer verdict.deinit();
    try fixture.await_joiners(parent.digest(), 2);

    // Cancelling the proposal leaves the replay running for the verification.
    proposal.deinit();
    try fixture.barrier();
    try testing.expect(!gate.release.is_closed());
    try gate.release.send({});
    try testing.expect(try verdict.recv());
    try testing.expectEqual(@as(u32, 1), probe.calls);
    try testing.expectError(error.Empty, duplicate.started.try_recv());
}

test "stateful processing: a pending proposal does not block an active verification" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const block = try uncached_child(&fixture, &genesis, 1);
    var verify_probe: Probe = .{ .target = block.digest() };
    defer verify_probe.deinit();
    var verify_gate = try verify_probe.add_gate();
    defer verify_gate.started.deinit();
    fixture.processing.verifications.verifier.app.probe = &verify_probe;
    var propose_probe: Probe = .{ .target = genesis.digest() };
    defer propose_probe.deinit();
    var propose_gate = try propose_probe.add_gate();
    defer propose_gate.started.deinit();
    fixture.processing.processor.app.propose_probe = &propose_probe;

    var verdict = try fixture.verify(&.{ block, genesis });
    defer verdict.deinit();
    try verify_gate.started.recv();
    var proposal = try fixture.propose_async(&.{genesis}, 2);
    defer proposal.deinit();
    try propose_gate.started.recv();
    // The active verification answers while the build is held in the application.
    try verify_gate.release.send({});
    try testing.expect(try verdict.recv());
    try propose_gate.release.send({});
    const built = try proposal.recv();
    built.discard();
}

test "stateful processing: a pending proposal does not block a new verification" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const block = try uncached_child(&fixture, &genesis, 2);
    var propose_probe: Probe = .{ .target = genesis.digest() };
    defer propose_probe.deinit();
    var propose_gate = try propose_probe.add_gate();
    defer propose_gate.started.deinit();
    fixture.processing.processor.app.propose_probe = &propose_probe;
    var verify_probe: Probe = .{ .target = block.digest() };
    defer verify_probe.deinit();
    var verify_gate = try verify_probe.add_gate();
    defer verify_gate.started.deinit();
    fixture.processing.verifications.verifier.app.probe = &verify_probe;

    var proposal = try fixture.propose_async(&.{genesis}, 1);
    defer proposal.deinit();
    try propose_gate.started.recv();
    // A verification sent while the build is held still starts and answers.
    var verdict = try fixture.verify(&.{ block, genesis });
    defer verdict.deinit();
    try verify_gate.started.recv();
    try verify_gate.release.send({});
    try testing.expect(try verdict.recv());
    try propose_gate.release.send({});
    const built = try proposal.recv();
    built.discard();
}

test "stateful processing: a cancelled handoff proposal unblocks finalization" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    var propose_probe: Probe = .{ .target = genesis.digest() };
    defer propose_probe.deinit();
    var gate = try propose_probe.add_gate();
    defer gate.started.deinit();
    // Released on any exit, so a failed assertion still lets the held build end.
    var release: ?oneshot.Sender(void) = gate.release;
    defer if (release) |*sender| sender.deinit();
    fixture.processing.processor.app.propose_probe = &propose_probe;

    // A prepare on genesis, held in the application.
    const pair = try oneshot.channel(fixture_mod.Mailbox.Built, gpa, std.testing.io);
    var proposer = pair.receiver;
    try fixture.send(.{ .propose = .{
        .context = .{ .round = harness_mod.round(1) },
        .ancestry = try fixture.harness.ancestry(&.{genesis}),
        .upstream = {},
        .proposal = .{ .prepare = pair.sender },
    } });
    try gate.started.recv();
    // The finalization queues behind the held build.
    const winner = try uncached_child(&fixture, &genesis, 1);
    var waiter = try fixture.finalize(winner);
    defer waiter.deinit();
    try std.testing.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expect(waiter.poll() == null);
    try testing.expect(!release.?.is_closed());

    // The proposer leaving cancels the build, and the queued finalization applies.
    proposer.deinit();
    try await_acknowledged(&waiter);
    try await_closed(&release.?);
}
