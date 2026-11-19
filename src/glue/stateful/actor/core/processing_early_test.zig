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

/// A probe gate whose release is dropped on any exit, so a failed assertion still lets the
/// held application call end.
const Held = struct {
    started: oneshot.Receiver(void),
    release: ?oneshot.Sender(void),

    fn add(probe: *Probe) !Held {
        const gate = try probe.add_gate();
        return .{ .started = gate.started, .release = gate.release };
    }

    /// Waits (bounded) until the held call starts.
    fn await_started(held: *Held) !void {
        // Each pass sleeps 1 ms; the bound is a hang guard.
        for (0..10_000) |_| {
            if (held.started.is_ready()) return held.started.recv();
            try std.testing.io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestTimedOut;
    }

    fn open(held: *Held) !void {
        var sender = held.release.?;
        held.release = null;
        try sender.send({});
    }

    fn deinit(held: *Held) void {
        held.started.deinit();
        if (held.release) |*sender| sender.deinit();
    }
};

/// Waits (bounded) for a verification's verdict.
fn await_verdict(verdict: *oneshot.Receiver(bool)) !bool {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        if (verdict.is_ready()) return verdict.recv();
        try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

// commonware `finalization_joins_and_reuses_winning_execution`: finalizing a block whose
// verification is processing it waits for that processing and reuses its result: the block is
// processed once, never re-executed on the finalized path, and captured once. Adapted:
// commonware learns the finalization started waiting from a parked acquisition; here the test
// waits 20 ms and checks the acknowledgement and the capture are still pending.
test "stateful processing: a finalization joins and reuses the winning execution" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const block = try uncached_child(&fixture, &genesis, 1);
    var verify_probe: Probe = .{ .target = block.digest() };
    defer verify_probe.deinit();
    var candidate = try Held.add(&verify_probe);
    defer candidate.deinit();
    fixture.processing.verifications.verifier.app.probe = &verify_probe;
    var finalized_path: Probe = .{ .target = block.digest() };
    defer finalized_path.deinit();
    fixture.processing.processor.app.probe = &finalized_path;
    var capture_probe: Probe = .{ .target = block.digest() };
    defer capture_probe.deinit();
    fixture.processing.processor.app.capture_probe = &capture_probe;
    var hook_probe: Probe = .{ .target = block.digest() };
    defer hook_probe.deinit();
    var hook = try Held.add(&hook_probe);
    defer hook.deinit();
    fixture.processing.processor.app.finalized_probe = &hook_probe;

    var verdict = try fixture.verify(&.{ block, genesis });
    defer verdict.deinit();
    try candidate.await_started();
    var waiter = try fixture.finalize(block);
    defer waiter.deinit();
    try std.testing.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expect(waiter.poll() == null);
    try testing.expectEqual(0, capture_probe.calls);
    try candidate.open();
    try hook.await_started();
    try testing.expect(waiter.poll() == null);
    try hook.open();
    try await_acknowledged(&waiter);
    try testing.expect(try await_verdict(&verdict));
    try testing.expectEqual(1, verify_probe.calls);
    try testing.expectEqual(0, finalized_path.calls);
    try testing.expectEqual(1, capture_probe.calls);
}

// commonware `finalized_block_request_continues_during_finalization`: a request whose
// processing of the finalized block finishes during finalization goes on to process the
// block's child, and answers, before the finalized hook completes. Adapted: as above, the test
// waits 20 ms for the finalization to start waiting instead of a parked acquisition.
test "stateful processing: a request on the finalized block continues during finalization" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const block, const child = try uncached_pair(&fixture);
    // Null target: the gates hold the recovery's processing of the block, then the child's.
    var probe: Probe = .{ .target = null };
    defer probe.deinit();
    var block_gate = try Held.add(&probe);
    defer block_gate.deinit();
    var child_gate = try Held.add(&probe);
    defer child_gate.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;
    var hook_probe: Probe = .{ .target = block.digest() };
    defer hook_probe.deinit();
    var hook = try Held.add(&hook_probe);
    defer hook.deinit();
    fixture.processing.processor.app.finalized_probe = &hook_probe;

    var verdict = try fixture.verify(&.{ child, block });
    defer verdict.deinit();
    try block_gate.await_started();
    var waiter = try fixture.finalize(block);
    defer waiter.deinit();
    try std.testing.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expect(waiter.poll() == null);
    try block_gate.open();
    try hook.await_started();
    // The child is processed, and the verification answers, while the hook is held.
    try child_gate.await_started();
    try child_gate.open();
    try testing.expect(try await_verdict(&verdict));
    try testing.expect(waiter.poll() == null);
    try hook.open();
    try await_acknowledged(&waiter);
    try testing.expectEqual(2, probe.calls);
}

const Competing = enum { verify, prepare, propose };

/// Sends `kind` on `block` (over genesis) and returns whether it was accepted: a verification's
/// verdict, or whether a build answered a block.
const CompetingRequest = union(Competing) {
    verify: oneshot.Receiver(bool),
    prepare: oneshot.Receiver(fixture_mod.Mailbox.Built),
    propose: oneshot.Receiver(fixture_mod.Mailbox.Digested),

    fn send(fixture: *Fixture, kind: Competing, block: TestBlock) !CompetingRequest {
        const genesis = TestBlock.genesis();
        switch (kind) {
            .verify => return .{ .verify = try fixture.verify(&.{ block, genesis }) },
            .propose => return .{ .propose = try fixture.propose_async(&.{ block, genesis }, 9) },
            .prepare => {
                const pair = try oneshot.channel(fixture_mod.Mailbox.Built, gpa, std.testing.io);
                try fixture.send(.{ .propose = .{
                    .context = .{ .round = harness_mod.round(9) },
                    .ancestry = try fixture.harness.ancestry(&.{ block, genesis }),
                    .upstream = {},
                    .proposal = .{ .prepare = pair.sender },
                } });
                return .{ .prepare = pair.receiver };
            },
        }
    }

    fn accepted(request: *CompetingRequest) !bool {
        switch (request.*) {
            .verify => |*verdict| return verdict.recv(),
            .prepare => |*receiver| {
                const built = try receiver.recv();
                defer built.discard();
                return !built.handoff.is_wait();
            },
            .propose => |*receiver| {
                const built = receiver.recv() catch |err| switch (err) {
                    error.Closed => return false, // Declined: no block.
                    else => return err,
                };
                var owned = built;
                owned.deinit();
                return true;
            },
        }
    }

    fn deinit(request: *CompetingRequest) void {
        switch (request.*) {
            inline else => |*receiver| receiver.deinit(),
        }
    }
};

fn competing_finalization(kind: Competing) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const block = try uncached_child(&fixture, &genesis, 1);
    const competing = try uncached_child(&fixture, &genesis, 2);
    var probe: Probe = .{ .target = block.digest() };
    defer probe.deinit();
    var gate = try Held.add(&probe);
    defer gate.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;
    var capture_probe: Probe = .{ .target = competing.digest() };
    defer capture_probe.deinit();
    fixture.processing.processor.app.capture_probe = &capture_probe;

    var request = try CompetingRequest.send(&fixture, kind, block);
    defer request.deinit();
    try gate.await_started();
    // The competing finalization waits for the losing execution to finish, then rejects it.
    var waiter = try fixture.finalize(competing);
    defer waiter.deinit();
    try std.testing.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expect(waiter.poll() == null);
    try testing.expectEqual(0, capture_probe.calls);
    try testing.expect(!gate.release.?.is_closed());
    try gate.open();
    try testing.expect(!try request.accepted());
    try await_acknowledged(&waiter);
    try testing.expectEqual(1, probe.calls);
}

// commonware `competing_finalization_rejects_executing_request` (verify case): a competing
// finalization lets the request finish executing its block, then rejects it: the verification
// votes false. Adapted: the test waits 20 ms for the finalization to start waiting instead of
// a parked acquisition.
test "stateful processing: a competing finalization rejects an executing verification" {
    try competing_finalization(.verify);
}

// commonware `competing_finalization_rejects_executing_request` (prepare case): the build on
// the block declines.
test "stateful processing: a competing finalization rejects an executing prepare" {
    try competing_finalization(.prepare);
}

// commonware `competing_finalization_rejects_executing_request` (propose case): the build on
// the block declines.
test "stateful processing: a competing finalization rejects an executing proposal" {
    try competing_finalization(.propose);
}

/// Sends a database subscription without waiting, and returns its receiver.
fn subscribe_async(fixture: *Fixture) !oneshot.Receiver(fixture_mod.Mailbox.Databases) {
    const pair = try oneshot.channel(fixture_mod.Mailbox.Databases, gpa, std.testing.io);
    try fixture.send(.{ .subscribe_databases = pair.sender });
    return pair.receiver;
}

// commonware `deferred_messages_keep_mailbox_order`: messages deferred behind a proposal run
// in mailbox order once it ends, while a verification queued after them starts during the
// proposal. Adapted: applied finalizations are counted by the finalized hook, and the
// proposal is cancelled by dropping its receiver.
test "stateful processing: deferred messages keep mailbox order" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    const genesis = TestBlock.genesis();
    const first, const second = try uncached_pair(&fixture);
    const other = try uncached_child(&fixture, &genesis, 3);
    var propose_probe: Probe = .{ .target = genesis.digest() };
    defer propose_probe.deinit();
    var build = try Held.add(&propose_probe);
    defer build.deinit();
    fixture.processing.processor.app.propose_probe = &propose_probe;
    // Reconstructing the second finalized block is held.
    var apply_probe: Probe = .{ .target = second.digest() };
    defer apply_probe.deinit();
    var apply = try Held.add(&apply_probe);
    defer apply.deinit();
    fixture.processing.processor.app.probe = &apply_probe;
    var hooks: Probe = .{ .target = null };
    defer hooks.deinit();
    fixture.processing.processor.app.finalized_probe = &hooks;
    var verify_probe: Probe = .{ .target = other.digest() };
    defer verify_probe.deinit();
    var verify_gate = try Held.add(&verify_probe);
    defer verify_gate.deinit();
    fixture.processing.verifications.verifier.app.probe = &verify_probe;

    var proposal: ?oneshot.Receiver(fixture_mod.Mailbox.Digested) =
        try fixture.propose_async(&.{genesis}, 4);
    defer if (proposal) |*receiver| receiver.deinit();
    try build.await_started();
    // Finalizations and subscriptions queue behind the proposal, then a verification.
    var first_waiter = try fixture.finalize(first);
    defer first_waiter.deinit();
    var first_databases = try subscribe_async(&fixture);
    defer first_databases.deinit();
    var second_waiter = try fixture.finalize(second);
    defer second_waiter.deinit();
    var second_databases = try subscribe_async(&fixture);
    defer second_databases.deinit();
    var verdict = try fixture.verify(&.{ other, genesis });
    defer verdict.deinit();

    // The verification overtakes every deferred message.
    try verify_gate.await_started();
    try verify_gate.open();
    try testing.expect(try await_verdict(&verdict));
    try testing.expect(!first_databases.is_ready());
    try testing.expect(!second_databases.is_ready());
    try testing.expect(second_waiter.poll() == null);
    try testing.expectEqual(0, hooks.calls);

    // Cancelling the proposal runs the deferred messages in order; reconstructing the second
    // finalized block holds the loop between the two subscriptions.
    proposal.?.deinit();
    proposal = null;
    try apply.await_started();
    try testing.expectEqual(1, hooks.calls);
    try testing.expect(first_databases.is_ready());
    try testing.expect(!second_databases.is_ready());
    try apply.open();
    _ = try second_databases.recv();
    try testing.expectEqual(2, hooks.calls);
    try await_acknowledged(&first_waiter);
    try await_acknowledged(&second_waiter);
}
