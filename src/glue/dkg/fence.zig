//! Monotonic epoch readiness signal (commonware `glue::dkg::fence`).
//!
//! A `Fence` marks epochs as ready and its `Gate` waits for them. No epoch is ready until the
//! first mark, not even epoch zero. The reshare actor marks an epoch once its registrar's
//! `register` call for that epoch returns, and the orchestrator waits on the gate before
//! entering any epoch, including the one it starts in, so it reads an epoch's scheme only after
//! the reshare actor has registered it.
//!
//! Rust shares the state through an `Arc` and closes the gate when the `Fence` drops; here the
//! owner keeps the `Fence` alive while gates use it and calls `close` instead of dropping it.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const consensus = @import("consensus");

const Epoch = consensus.Epoch;

/// The fence was closed before the requested epoch was ready.
pub const WaitError = Io.Cancelable || error{Closed};

/// Producer side of an epoch readiness signal.
pub const Fence = struct {
    io: Io,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
    /// The highest ready epoch, or null before the first mark.
    ready: ?Epoch = null,
    closed: bool = false,

    /// A fence with no epoch ready.
    pub fn init(io: Io) Fence {
        return .{ .io = io };
    }

    /// The consumer side, valid while the fence lives.
    pub fn gate(fence: *Fence) Gate {
        assert(@intFromPtr(fence) != 0);
        return .{ .fence = fence };
    }

    /// Marks every epoch at or below `epoch` as ready. Marking an epoch at or below the highest
    /// ready epoch has no effect.
    pub fn mark(fence: *Fence, epoch: Epoch) void {
        fence.mutex.lockUncancelable(fence.io);
        defer fence.mutex.unlock(fence.io);
        if (fence.ready) |ready| {
            if (ready.get() >= epoch.get()) return;
        }
        fence.ready = epoch;
        fence.condition.broadcast(fence.io);
        assert(fence.ready.? == epoch);
    }

    /// Closes the gate (Rust drops the `Fence`): waiters on epochs not yet ready fail with
    /// `error.Closed`, and epochs already ready still resolve.
    pub fn close(fence: *Fence) void {
        fence.mutex.lockUncancelable(fence.io);
        defer fence.mutex.unlock(fence.io);
        fence.closed = true;
        fence.condition.broadcast(fence.io);
        assert(fence.closed);
    }

    fn is_ready(fence: *const Fence, epoch: Epoch) bool {
        const ready = fence.ready orelse return false;
        return epoch.get() <= ready.get();
    }
};

/// Consumer side of an epoch readiness signal.
pub const Gate = struct {
    fence: *Fence,

    /// Waits until the fence marks `epoch` or a later epoch. Fails with `error.Closed` if the
    /// fence closes before `epoch` is ready; an epoch already ready still resolves after it
    /// closes.
    pub fn wait(gate: Gate, epoch: Epoch) WaitError!void {
        const fence = gate.fence;
        fence.mutex.lockUncancelable(fence.io);
        defer fence.mutex.unlock(fence.io);
        while (!fence.is_ready(epoch)) {
            if (fence.closed) return error.Closed;
            try fence.condition.wait(fence.io, &fence.mutex);
        }
        assert(fence.ready != null);
    }

    /// The result `wait` would return now, or null when it would block (Rust `now_or_never`).
    pub fn poll(gate: Gate, epoch: Epoch) ?error{Closed}!void {
        const fence = gate.fence;
        fence.mutex.lockUncancelable(fence.io);
        defer fence.mutex.unlock(fence.io);
        if (fence.is_ready(epoch)) return {};
        if (fence.closed) return error.Closed;
        assert(!fence.is_ready(epoch));
        return null;
    }
};

const testing = std.testing;
const runtime = @import("runtime");

fn run(comptime body: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(body, .{runner.io()}));
}

fn expect_ready(gate: Gate, epoch: Epoch) !void {
    const result = gate.poll(epoch) orelse return error.TestExpectedReady;
    try result;
}

fn wait_task(gate: Gate, epoch: Epoch, done: *bool) WaitError!void {
    try gate.wait(epoch);
    done.* = true;
}

test "fence: waits for the first mark (waits_for_first_mark)" {
    var fence: Fence = .init(testing.io);
    const gate = fence.gate();
    // No epoch is ready before the first mark, not even epoch zero.
    try testing.expect(gate.poll(.zero()) == null);
    fence.mark(.zero());
    try expect_ready(gate, .zero());
    try testing.expect(gate.poll(.new(1)) == null);
}

test "fence: resolves sequential waiters (resolves_sequential_waiters)" {
    try run(struct {
        fn body(io: Io) !void {
            var fence: Fence = .init(io);
            for ([_]u64{ 1, 2 }) |epoch| {
                var done = false;
                var task = try io.concurrent(wait_task, .{ fence.gate(), Epoch.new(epoch), &done });
                try io.sleep(.fromMilliseconds(10), .awake);
                try testing.expect(!done);
                fence.mark(.new(epoch));
                try task.await(io);
                try testing.expect(done);
            }
        }
    }.body);
}

test "fence: waits for the requested epoch (waits_for_requested_epoch)" {
    try run(struct {
        fn body(io: Io) !void {
            var fence: Fence = .init(io);
            var done = false;
            var task = try io.concurrent(wait_task, .{ fence.gate(), Epoch.new(2), &done });
            try io.sleep(.fromMilliseconds(10), .awake);
            fence.mark(.new(1));
            try io.sleep(.fromMilliseconds(10), .awake);
            try testing.expect(!done);
            fence.mark(.new(2));
            try task.await(io);
            try testing.expect(done);
        }
    }.body);
}

test "fence: closing wakes a waiter with Closed (producer_drop_wakes_waiter_with_closed)" {
    try run(struct {
        fn body(io: Io) !void {
            var fence: Fence = .init(io);
            var done = false;
            var task = try io.concurrent(wait_task, .{ fence.gate(), Epoch.new(1), &done });
            try io.sleep(.fromMilliseconds(10), .awake);
            fence.close();
            try testing.expectError(error.Closed, task.await(io));
            try testing.expect(!done);
        }
    }.body);
}

test "fence: a ready epoch resolves after close (ready_epoch_still_resolves_after_producer_drop)" {
    var fence: Fence = .init(testing.io);
    fence.mark(.new(1));
    fence.close();
    try fence.gate().wait(.new(1));
    try testing.expectError(error.Closed, fence.gate().poll(.new(2)).?);
}

test "fence: mark does not regress the epoch (mark_does_not_regress_epoch)" {
    var fence: Fence = .init(testing.io);
    fence.mark(.new(2));
    fence.mark(.new(1));
    try expect_ready(fence.gate(), .new(2));
}
