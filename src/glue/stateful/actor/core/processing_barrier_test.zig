//! commonware `glue/src/stateful/actor/core/processing.rs` tests that hold a barrier pending:
//! the core fixture's database opens over `runtime.storage.mocks.DelayedSynced` (commonware's
//! `spawn_processing` control), so every sync a finalization starts parks until the test
//! releases it.
//!
//! Not ported here: `stable_leader_finalizations_coalesce_while_barrier_pending` and
//! `shutdown_preempts_successor_barrier_waiting_for_verification_reader` apply later blocks
//! while a barrier is pending. commonware runs them on a mock database (`control.flushes`);
//! on a real QMDB the next block's apply waits for the parked sync (every blob mutation first
//! waits for its owner's pending sync), so they need a mock database set whose `finalize`
//! returns a pending completion.

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
