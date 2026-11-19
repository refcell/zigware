//! commonware `glue/src/stateful/db/mod.rs`'s `Barrier` tests over pending completions
//! (`runtime.storage.Completion.init_pending` stands in for `Handle::from_receiver`): a barrier
//! waits for every sync, dropping it releases every completion, a canceled sync (runtime
//! shutdown) is not durable, and a later failure wins without waiting on a pending sync.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const db = @import("mod.zig");
const test_io = @import("../test_io.zig");

const gpa = testing.allocator;
const Completion = runtime.storage.Completion;
const Barrier = db.Barrier;
const cases = [_]usize{ 1, 30, 31, 64 };

fn references(completion: Completion) u32 {
    return completion.state.leaf.refs.load(.acquire);
}

const Waiter = struct {
    barrier: Barrier,
    result: Barrier.Error!void = {},
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *Waiter) void {
        self.result = self.barrier.durable();
        self.done.store(true, .release);
    }

    /// Waits up to a second for `durable` to return.
    fn wait_done(self: *Waiter) !void {
        for (0..1000) |_| {
            if (self.done.load(.acquire)) return;
            try test_io.io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestBarrierBlocked;
    }
};

/// The first sync stays pending, so the barrier resolves only once it completes; it is
/// durable unless that sync was canceled (commonware's `Aborted`).
fn waits_for_every_sync(count: usize, shutdown: bool) !void {
    const pending = try Completion.init_pending(gpa, test_io.io);
    var completions: [Barrier.max_syncs]Completion = undefined;
    completions[0] = pending.retain();
    for (completions[1..count]) |*completion| completion.* = .ok;
    var waiter: Waiter = .{ .barrier = .from_completions("TestDb", completions[0..count]) };
    try testing.expectEqual(null, waiter.barrier.poll());
    var task = try test_io.io.concurrent(Waiter.run, .{&waiter});
    try test_io.io.sleep(.fromMilliseconds(10), .awake);
    try testing.expect(!waiter.done.load(.acquire)); // Resolved before the pending sync.
    pending.finish(if (shutdown) error.Canceled else {});
    task.await(test_io.io);
    if (shutdown) {
        try testing.expectError(error.Canceled, waiter.result);
    } else try waiter.result;
    try testing.expectEqual(1, references(pending)); // Only the producer's is left.
    pending.release();
}

test "stateful db barrier: waits for every sync (barrier_waits_for_every_handle)" {
    try test_io.run_on_deterministic(waits_for_every_handle);
}

fn waits_for_every_handle() anyerror!void {
    for (cases) |count| {
        try waits_for_every_sync(count, false);
        try waits_for_every_sync(count, true);
    }
}

/// Dropping a barrier, polled or not, releases every completion.
fn cancellation_releases(count: usize, poll: bool) !void {
    var producers: [Barrier.max_syncs]Completion = undefined;
    var completions: [Barrier.max_syncs]Completion = undefined;
    for (producers[0..count], completions[0..count]) |*producer, *completion| {
        producer.* = try Completion.init_pending(gpa, test_io.io);
        completion.* = producer.retain();
    }
    var barrier: Barrier = .from_completions("TestDb", completions[0..count]);
    if (poll) try testing.expectEqual(null, barrier.poll());
    barrier.deinit();
    for (producers[0..count]) |producer| {
        try testing.expectEqual(1, references(producer));
        producer.finish({});
        producer.release();
    }
}

test "stateful db barrier: dropping releases every sync (barrier_cancellation_releases_handles)" {
    for (cases) |count| {
        try cancellation_releases(count, false);
        try cancellation_releases(count, true);
    }
}

test "stateful db barrier: canceled is not durable (barrier_reports_shutdown_as_not_durable)" {
    const two = [_]Completion{ .ok, .ready(error.Canceled) };
    try testing.expectError(error.Canceled, Barrier.from_completions("TestDb", &two).durable());
    const one = [_]Completion{.ready(error.Canceled)};
    try testing.expectError(error.Canceled, Barrier.from_completions("TestDb", &one).durable());
    const empty: Barrier = .{};
    try empty.durable();
}

/// The first sync stays pending and the last fails; with `shutdown` the second is canceled.
/// The barrier fails without waiting on the pending sync and names the failed member.
fn later_failure(count: usize, shutdown: bool) !void {
    const pending = try Completion.init_pending(gpa, test_io.io);
    defer pending.release();
    var completions: [Barrier.max_syncs]Completion = undefined;
    completions[0] = pending.retain();
    for (completions[1..count], 1..) |*completion, index| {
        completion.* = if (index == count - 1)
            .ready(error.WriteFailed)
        else if (shutdown and index == 1)
            .ready(error.Canceled)
        else
            .ok;
    }
    var waiter: Waiter = .{ .barrier = .from_completions("TestDb", completions[0..count]) };
    const failure = waiter.barrier.first_failure().?;
    try testing.expectEqual(count - 1, failure.index.?);
    try testing.expectEqualStrings("TestDb", failure.db_type);
    var task = try test_io.io.concurrent(Waiter.run, .{&waiter});
    const waited = waiter.wait_done();
    if (waited) |_| {} else |_| pending.finish({}); // Unblock the join before failing.
    task.await(test_io.io);
    try waited;
    try testing.expectError(error.DatabaseSyncFailed, waiter.result);
    // The pending completion was released when the failure surfaced.
    try testing.expectEqual(1, references(pending));
    pending.finish({});
}

test "stateful db barrier: a later failure wins without waiting (barrier_panics_on_later_failure)" {
    for (cases[1..]) |count| {
        try later_failure(count, false);
        try later_failure(count, true);
    }
}

/// Settles `barrier` and records the outcome.
const SettleWaiter = struct {
    barrier: *const Barrier,
    settled: Barrier.Error!void = {},
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *SettleWaiter) void {
        self.settled = self.barrier.settle();
        self.done.store(true, .release);
    }
};

fn cancel_task(future: *std.Io.Future(void)) void {
    future.cancel(test_io.io);
}

// A waiter canceled as one sync completes still sees its cancellation: `settle` returns
// `error.Canceled` instead of waiting on the other sync (an already-taken cancel never wakes a
// later wait). The race is timing-dependent, so it repeats; a swallowed cancel leaves the
// waiter blocked until the held sync finishes, and `settle` then reports success.
test "stateful db barrier: a cancel racing a completed sync is not swallowed" {
    for (0..400) |attempt| {
        const first = try Completion.init_pending(gpa, test_io.io);
        defer first.release();
        const held = try Completion.init_pending(gpa, test_io.io);
        defer held.release();
        const completions = [_]Completion{ first.retain(), held.retain() };
        var barrier: Barrier = .from_completions("TestDb", &completions);
        defer barrier.deinit();
        var waiter: SettleWaiter = .{ .barrier = &barrier };
        var future = try test_io.io.concurrent(SettleWaiter.run, .{&waiter});
        // Let the waiter block on the first sync, then cancel it and complete the sync a
        // varying few microseconds apart, so both orders of the race are sampled.
        try test_io.io.sleep(.fromMicroseconds(200), .awake);
        var canceler = try test_io.io.concurrent(cancel_task, .{&future});
        var spin: u32 = 0;
        while (spin < (attempt % 40) * 50) : (spin += 1) std.atomic.spinLoopHint();
        first.finish({});
        var stuck = true;
        for (0..2000) |_| {
            if (waiter.done.load(.acquire)) {
                stuck = false;
                break;
            }
            try test_io.io.sleep(.fromMicroseconds(500), .awake);
        }
        held.finish({}); // Unblocks a stuck waiter so the test can report it.
        canceler.await(test_io.io);
        try testing.expect(!stuck);
        try testing.expectError(error.Canceled, waiter.settled);
    }
}
