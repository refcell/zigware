//! commonware `glue/src/stateful/actor/core/processing.rs` tests that hold a barrier pending:
//! the core fixture's database opens over `runtime.storage.mocks.DelayedSynced` (commonware's
//! `spawn_processing` control), so every sync a finalization starts parks until the test
//! releases it.
//!
//! The two that apply later blocks with a barrier pending run instead on the harness's
//! `FlushControl` (commonware's mock database `control.flushes`): on a real QMDB over parked
//! storage, the next block's apply waits for the parked sync (every blob mutation first waits
//! for its owner's pending sync).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const core = @import("testing.zig");

const harness = core.harness;
const TestBlock = harness.TestBlock;
const Fixture = core.Fixture;
const DelayedSync = runtime.storage.mocks.DelayedSync;
const DelayedSynced = runtime.storage.mocks.DelayedSynced;
const gpa = testing.allocator;
const io = testing.io;

/// The fixture over parked storage. Must not move once started.
const Parked = struct {
    pending: DelayedSync,
    delayed: DelayedSynced,
    fixture: Fixture,
    stopped: bool = false,

    fn start(self: *Parked) !void {
        self.stopped = false;
        self.pending = .init(gpa, io);
        self.fixture.harness.init_storage();
        const backing = self.fixture.harness.storage.interface();
        self.delayed = .init(gpa, backing, &self.pending);
        // Opening syncs as it recovers (commonware `drive_pending_syncs`).
        var releaser = try io.concurrent(release_loop, .{&self.pending});
        defer releaser.cancel(io) catch {};
        try self.fixture.init_with(self.delayed.storage());
        try testing.expectEqual(@as(usize, 0), self.pending.parked());
    }

    fn release_loop(pending: *DelayedSync) std.Io.Cancelable!void {
        // Each pass sleeps 1 ms; only cancellation ends the loop.
        while (true) {
            if (pending.parked() > 0) pending.release_all();
            try io.sleep(.fromMilliseconds(1), .awake);
        }
    }

    /// Releases every parked sync, then tears the fixture down (once). Tearing processing
    /// down releases its durability state, which cancels the acknowledgements it still holds.
    fn stop(self: *Parked) void {
        if (self.stopped) return;
        self.stopped = true;
        self.pending.unblock();
        self.fixture.deinit() catch {};
        self.pending.deinit();
    }

    /// Waits until a flush's syncs park (commonware `control.next_flush()`); bounded.
    fn next_flush(self: *Parked) !void {
        for (0..10_000) |_| {
            if (self.pending.parked() > 0) return;
            try io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestTimedOut;
    }

    /// Closes the mailbox and returns how the loop ended, leaving the rest for `stop`.
    fn close(self: *Parked) anyerror!void {
        const fixture = &self.fixture;
        fixture.mailbox.?.deinit();
        fixture.mailbox = null;
        var future = fixture.future.?;
        fixture.future = null;
        return future.await(io);
    }
};

fn expect_canceled(waiter: *const @import("utils").acknowledgement.ExactWaiter) !void {
    try testing.expectError(error.AcknowledgementCanceled, waiter.wait());
}

fn expect_pending(waiter: *const @import("utils").acknowledgement.ExactWaiter) !void {
    try testing.expect(waiter.poll() == null);
}

// commonware `shutdown_cancels_pending_flush_ack`: stopping processing with a flush in flight
// cancels marshal's acknowledgement. Adapted: the acknowledgement is canceled when the stopped
// loop's state is released (`Processing.deinit`), not when `run` returns.
test "stateful processing: shutdown cancels a pending flush's acknowledgement" {
    var parked: Parked = undefined;
    try parked.start();
    defer parked.stop();
    const fixture = &parked.fixture;
    const block1, var batch = try fixture.harness.build_child(&TestBlock.genesis(), 1);
    batch.deinit();
    var waiter = try fixture.finalize(block1);
    defer waiter.deinit();
    try parked.next_flush();
    try parked.close();
    parked.stop();
    try expect_canceled(&waiter);
}

// commonware `duplicate_reports_wait_for_durability::failure`: a redelivered receipt for an
// applied height waits for the flush that covers it; a failed flush stops processing and
// cancels the duplicate receipt. (The success case is in processing_late_test.zig.)
test "stateful processing: a failed flush cancels a duplicate report's receipt" {
    var parked: Parked = undefined;
    try parked.start();
    defer parked.stop();
    const fixture = &parked.fixture;
    const block1, var batch = try fixture.harness.build_child(&TestBlock.genesis(), 1);
    batch.deinit();
    var first = try fixture.finalize(block1);
    defer first.deinit();
    try fixture.barrier();
    var duplicate = try fixture.finalize(block1);
    defer duplicate.deinit();
    // The subscription is a FIFO fence after both reports have been handled.
    try fixture.barrier();
    try testing.expectEqual(@as(?u64, 1), try fixture.counter());
    try parked.next_flush();
    try expect_pending(&duplicate);
    parked.pending.fail_all();
    try testing.expectError(error.DatabaseSyncFailed, parked.close());
    parked.stop();
    try expect_canceled(&duplicate);
}

/// Waits (bounded) until the applied counter reaches `count` (commonware `applied_at_least`).
fn applied_at_least(fixture: *Fixture, count: u64) !void {
    for (0..10_000) |_| {
        if ((try fixture.counter() orelse 0) >= count) return;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

// commonware `stable_leader_finalizations_coalesce_while_barrier_pending`: with block 1's
// barrier pending, blocks 2 and 3 apply without starting a second barrier; once it
// completes, one successor barrier covers both.
test "stateful processing: finalizations coalesce while a barrier is pending" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit() catch {};
    const control = &fixture.harness.flushes;
    defer control.release_all();
    control.arm();
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    const block3 = try fixture.harness.stage_pending_child(&block2, 3);
    var waiter1 = try fixture.finalize(block1);
    defer waiter1.deinit();
    try control.next_flush();
    var waiter2 = try fixture.finalize(block2);
    defer waiter2.deinit();
    var waiter3 = try fixture.finalize(block3);
    defer waiter3.deinit();
    try applied_at_least(&fixture, 3);
    // A pending barrier coalesces later finalized state instead of starting a second one.
    try testing.expectEqual(@as(u32, 1), control.flushes);
    try expect_pending(&waiter1);
    try expect_pending(&waiter2);
    try expect_pending(&waiter3);
    control.release_next({});
    try waiter1.wait();
    try expect_pending(&waiter2);
    try expect_pending(&waiter3);
    // One successor barrier covers every coalesced block.
    try control.next_flush();
    try testing.expectEqual(@as(u32, 2), control.flushes);
    control.release_next({});
    try waiter2.wait();
    try waiter3.wait();
    try fixture.barrier();
    try testing.expectEqual(@as(u32, 2), control.flushes);
    try testing.expectEqual(@as(usize, 0), control.pending());
}

// commonware `shutdown_preempts_successor_barrier_waiting_for_verification_reader`: with
// block 2 applied behind block 1's pending barrier and a verification of block 3 held in the
// application, releasing the first barrier acknowledges block 1, and shutdown then stops
// promptly and cancels block 2's receipt. Adapted: zigware's verification holds no database
// read across the application call, so the successor barrier starts (held) rather than
// waiting for the reader; shutdown must preempt both it and the held verification. The
// receipt cancels when the stopped loop's state is released.
test "stateful processing: shutdown preempts a successor barrier and a held verification" {
    var fixture: Fixture = undefined;
    try fixture.init();
    var torn_down = false;
    defer if (!torn_down) fixture.deinit() catch {};
    const control = &fixture.harness.flushes;
    defer if (!torn_down) control.release_all();
    control.arm();
    const genesis = TestBlock.genesis();
    const block1 = try fixture.harness.stage_pending_child(&genesis, 1);
    const block2 = try fixture.harness.stage_pending_child(&block1, 2);
    const block3, var batch = try fixture.harness.build_child(&block2, 3);
    batch.deinit();
    var waiter1 = try fixture.finalize(block1);
    defer waiter1.deinit();
    try control.next_flush();
    var waiter2 = try fixture.finalize(block2);
    defer waiter2.deinit();
    try applied_at_least(&fixture, 2);

    var probe: harness.Probe = .{ .target = block3.digest() };
    defer probe.deinit();
    const gate = try probe.add_gate();
    var started = gate.started;
    defer started.deinit();
    var release = gate.release;
    defer release.deinit();
    fixture.processing.verifications.verifier.app.probe = &probe;
    var verify = try fixture.verify(&.{ block3, block2 });
    defer verify.deinit();
    try started.recv();

    control.release_next({});
    try waiter1.wait();
    try control.next_flush();
    try expect_pending(&waiter2);
    torn_down = true;
    // Closing the mailbox stops the loop without waiting for the reader or the barrier.
    try fixture.deinit();
    try expect_canceled(&waiter2);
}
