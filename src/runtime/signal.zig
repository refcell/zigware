//! One-time broadcasts for coordinating shutdown across tasks (commonware
//! `runtime/src/utils/signal.rs`).
//!
//! A `Signaler` resolves every `Signal` taken from it with one `i32`. Each open `Signal` holds
//! a reference; `Signaler.signal` reports completion once every reference is released, so a
//! task keeps its `Signal` until its cleanup is done. A `Stopper` is the runtime's `stop` /
//! `stopped`: the first `stop` value wins, and every `stop` waits for the same completion.
//!
//! Rust drops a `Signal`; here call `Signal.deinit`. `Signal.wait` may be called repeatedly and
//! keeps returning the value (Rust panics on a second poll of a resolved future).

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

pub const StopError = Io.Cancelable || error{Timeout};

pub const Signaler = struct {
    io: Io,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
    value: ?i32 = null,
    /// Open `Signal`s not yet released.
    references: u32 = 0,

    pub fn init(io: Io) Signaler {
        return .{ .io = io };
    }

    /// A new `Signal` holding a reference: an open signal until `signal` is called, and an
    /// already-resolved one (holding no reference) after.
    pub fn subscribe(signaler: *Signaler) Signal {
        signaler.mutex.lockUncancelable(signaler.io);
        defer signaler.mutex.unlock(signaler.io);
        if (signaler.value) |value| return .{ .state = .{ .closed = value } };
        signaler.references += 1;
        assert(signaler.references > 0);
        return .{ .state = .{ .open = signaler } };
    }

    /// Resolve every signal with `value`. Returns false if it was already resolved, in which
    /// case the first value stands.
    pub fn signal(signaler: *Signaler, value: i32) bool {
        signaler.mutex.lockUncancelable(signaler.io);
        defer signaler.mutex.unlock(signaler.io);
        if (signaler.value != null) return false;
        signaler.value = value;
        signaler.condition.broadcast(signaler.io);
        assert(signaler.value.? == value);
        return true;
    }

    /// Waits until the signal is resolved and every open `Signal` is released.
    pub fn completed(signaler: *Signaler, timeout: Io.Timeout) StopError!void {
        signaler.mutex.lockUncancelable(signaler.io);
        defer signaler.mutex.unlock(signaler.io);
        const deadline = timeout.toDeadline(signaler.io);
        while (signaler.value == null or signaler.references > 0) {
            try signaler.condition.waitTimeout(signaler.io, &signaler.mutex, deadline);
        }
        assert(signaler.references == 0);
    }

    fn release(signaler: *Signaler) void {
        signaler.mutex.lockUncancelable(signaler.io);
        defer signaler.mutex.unlock(signaler.io);
        assert(signaler.references > 0);
        signaler.references -= 1;
        if (signaler.references == 0) signaler.condition.broadcast(signaler.io);
    }
};

/// A one-time broadcast value. Release it with `deinit` once the work it guards is done.
pub const Signal = struct {
    state: union(enum) {
        open: *Signaler,
        closed: i32,
        released,
    },

    /// Waits for the value.
    pub fn wait(signal: *Signal) Io.Cancelable!i32 {
        const signaler = switch (signal.state) {
            .open => |signaler| signaler,
            .closed => |value| return value,
            .released => unreachable, // Waiting on a released signal.
        };
        signaler.mutex.lockUncancelable(signaler.io);
        defer signaler.mutex.unlock(signaler.io);
        while (signaler.value == null) try signaler.condition.wait(signaler.io, &signaler.mutex);
        assert(signaler.references > 0);
        return signaler.value.?;
    }

    /// The value if resolved, without waiting.
    pub fn peek(signal: *const Signal) ?i32 {
        return switch (signal.state) {
            .open => |signaler| value: {
                signaler.mutex.lockUncancelable(signaler.io);
                defer signaler.mutex.unlock(signaler.io);
                break :value signaler.value;
            },
            .closed => |value| value,
            .released => unreachable,
        };
    }

    /// Release this reference.
    pub fn deinit(signal: *Signal) void {
        switch (signal.state) {
            .open => |signaler| signaler.release(),
            .closed => {},
            .released => unreachable, // Double release.
        }
        signal.state = .released;
    }
};

/// Graceful shutdown of many tasks (commonware `Stopper`): `stopped` hands out signals, and
/// `stop` resolves them with the first value it is given, then waits for all to be released.
pub const Stopper = struct {
    signaler: Signaler,

    pub fn init(io: Io) Stopper {
        return .{ .signaler = .init(io) };
    }

    /// A signal that resolves when `stop` is called (already resolved after it was).
    pub fn stopped(stopper: *Stopper) Signal {
        return stopper.signaler.subscribe();
    }

    /// Resolve every signal with `value` (the first `stop` value wins), then wait until every
    /// signal is released. `error.Timeout` if they are not released within `timeout`.
    pub fn stop(stopper: *Stopper, value: i32, timeout: Io.Timeout) StopError!void {
        _ = stopper.signaler.signal(value);
        assert(stopper.signaler.value != null);
        try stopper.signaler.completed(timeout);
    }
};

const testing = std.testing;
const deterministic = @import("deterministic.zig");

fn run(comptime body: fn (Io) anyerror!void) !void {
    var runner = try deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(body, .{runner.io()}));
}

test "signaler resolves its signals" {
    try run(struct {
        fn body(io: Io) !void {
            var signaler: Signaler = .init(io);
            var signal = signaler.subscribe();
            try testing.expectEqual(@as(?i32, null), signal.peek());
            try testing.expect(signaler.signal(2));
            try testing.expect(!signaler.signal(3)); // The first value stands.
            try testing.expectEqual(@as(i32, 2), try signal.wait());
            try testing.expectEqual(@as(i32, 2), try signal.wait());
            signal.deinit();
            try signaler.completed(.none);
            // Signals taken after resolution are closed and hold no reference.
            var late = signaler.subscribe();
            defer late.deinit();
            try testing.expectEqual(@as(i32, 2), try late.wait());
            try testing.expectEqual(@as(u32, 0), signaler.references);
        }
    }.body);
}

// A task waits on a signal in a loop with a sleep, as in commonware's `Signal` example.
test "signal wakes a waiting task" {
    try run(struct {
        fn waiter(io: Io, signal: *Signal, out: *i32) !void {
            out.* = try signal.wait();
            try io.sleep(.fromMilliseconds(1), .awake);
            signal.deinit();
        }
        fn body(io: Io) !void {
            var signaler: Signaler = .init(io);
            var signal = signaler.subscribe();
            var value: i32 = 0;
            var task = try io.concurrent(waiter, .{ io, &signal, &value });
            try io.sleep(.fromSeconds(1), .awake);
            _ = signaler.signal(9);
            try signaler.completed(.none);
            try testing.expectEqual(@as(i32, 9), value);
            try task.await(io);
        }
    }.body);
}

const kill = 42;

fn cleanup_task(
    io: Io,
    stopper: *Stopper,
    started: *Io.Queue(u8),
    cleanup_ms: i64,
    counter: *u32,
) !void {
    var signal = stopper.stopped();
    defer signal.deinit();
    try started.putOne(io, 0);
    try testing.expectEqual(@as(i32, kill), try signal.wait());
    try io.sleep(.fromMilliseconds(cleanup_ms), .awake);
    counter.* += 1;
}

// commonware `test_shutdown_multiple_signals`: stop waits until every holder finishes cleanup.
test "stop waits for every signal (test_shutdown_multiple_signals)" {
    try run(struct {
        fn body(io: Io) !void {
            var stopper: Stopper = .init(io);
            var counter: u32 = 0;
            var started_buffer: [3]u8 = undefined;
            var started: Io.Queue(u8) = .init(&started_buffer);
            var tasks: [3]Io.Future(anyerror!void) = undefined;
            for (&tasks, 1..) |*task, i| {
                const ms: i64 = @intCast(10 * i);
                const args = .{ io, &stopper, &started, ms, &counter };
                task.* = try io.concurrent(cleanup_erased, args);
            }
            // Wait until every task holds its signal.
            for (0..3) |_| _ = try started.getOne(io);
            try stopper.stop(kill, .none);
            try testing.expectEqual(@as(u32, 3), counter);
            for (&tasks) |*task| try task.await(io);
        }
        fn cleanup_erased(
            io: Io,
            stopper: *Stopper,
            started: *Io.Queue(u8),
            ms: i64,
            counter: *u32,
        ) anyerror!void {
            return cleanup_task(io, stopper, started, ms, counter);
        }
    }.body);
}

// commonware `test_shutdown`: a signal taken after stop resolves at once.
test "stopped after stop resolves immediately (test_shutdown)" {
    try run(struct {
        fn body(io: Io) !void {
            var stopper: Stopper = .init(io);
            var counter: u32 = 0;
            var started_buffer: [1]u8 = undefined;
            var started: Io.Queue(u8) = .init(&started_buffer);
            const args = .{ io, &stopper, &started, 0, &counter };
            var before = try io.concurrent(cleanup_task, args);
            _ = try started.getOne(io);
            try stopper.stop(kill, .none);
            var after = stopper.stopped();
            defer after.deinit();
            try testing.expectEqual(@as(i32, kill), try after.wait());
            try before.await(io);
            try testing.expectEqual(@as(u32, 1), counter);
        }
    }.body);
}

// commonware `test_shutdown_timeout`: a holder that never releases makes stop time out.
test "stop times out on an unreleased signal (test_shutdown_timeout)" {
    try run(struct {
        fn body(io: Io) !void {
            var stopper: Stopper = .init(io);
            var signal = stopper.stopped();
            const result = stopper.stop(kill, .{ .duration = .{
                .raw = .fromMilliseconds(100),
                .clock = .awake,
            } });
            try testing.expectError(error.Timeout, result);
            signal.deinit();
            try stopper.stop(kill, .none);
        }
    }.body);
}

// commonware `test_shutdown_multiple_stop_calls`: the first value wins, every call waits for
// the same completion, and a stop after completion returns at once.
test "multiple stop calls share completion (test_shutdown_multiple_stop_calls)" {
    try run(struct {
        fn stop_erased(stopper: *Stopper, value: i32) anyerror!void {
            return stopper.stop(value, .none);
        }
        fn body(io: Io) !void {
            var stopper: Stopper = .init(io);
            var counter: u32 = 0;
            var started_buffer: [1]u8 = undefined;
            var started: Io.Queue(u8) = .init(&started_buffer);
            var task = try io.concurrent(delayed, .{ io, &stopper, &started, &counter });
            _ = try started.getOne(io);
            var first = try io.concurrent(stop_erased, .{ &stopper, kill });
            // Like commonware polling the first stop before the second: let it signal first.
            {
                var probe = stopper.stopped();
                defer probe.deinit();
                var waited: u32 = 0;
                while (probe.peek() == null and waited < 100) : (waited += 1) {
                    try io.sleep(.fromMilliseconds(1), .awake);
                }
                try testing.expectEqual(@as(?i32, kill), probe.peek());
            }
            var second = try io.concurrent(stop_erased, .{ &stopper, kill + 1 });
            try first.await(io);
            try second.await(io);
            try testing.expectEqual(@as(u32, 1), counter);
            var signal = stopper.stopped();
            defer signal.deinit();
            try testing.expectEqual(@as(i32, kill), try signal.wait());
            try task.await(io);
            try stopper.stop(kill + 1, .none);
        }
        fn delayed(io: Io, stopper: *Stopper, started: *Io.Queue(u8), counter: *u32) !void {
            return cleanup_task(io, stopper, started, 50, counter);
        }
    }.body);
}
