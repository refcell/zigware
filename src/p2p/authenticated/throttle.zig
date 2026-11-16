//! Per-connection rate limiting for one kind of inbound message (commonware
//! `p2p/src/authenticated/throttle.rs`). Counts received and limited messages; a limited
//! message waits until the limiter admits it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const rate_limit = @import("../rate_limit.zig");
const Counter = @import("runtime").telemetry.metrics.raw.Counter;

/// The single key of a direct (unkeyed) limiter.
const Unit = struct {
    pub fn order(_: Unit, _: Unit) std.math.Order {
        return .eq;
    }
};

pub const Throttle = struct {
    io: Io,
    limiter: rate_limit.KeyedRateLimiter(Unit),
    /// Messages received; a series of the caller's `received` family.
    received: *Counter,
    /// Messages that had to wait for the limiter; a series of the `rate_limited` family.
    limited: *Counter,

    /// The counters must outlive the throttle.
    pub fn init(
        gpa: Allocator,
        io: Io,
        quota: rate_limit.Quota,
        received: *Counter,
        limited: *Counter,
    ) Throttle {
        assert(received != limited);
        return .{
            .io = io,
            .limiter = .init(gpa, io, quota),
            .received = received,
            .limited = limited,
        };
    }

    pub fn deinit(throttle: *Throttle) void {
        throttle.limiter.deinit();
        throttle.* = undefined;
    }

    /// Records a received message and, if `limit`, waits until the limiter admits it.
    pub fn receive(throttle: *Throttle, limit: bool) (Io.Cancelable || Allocator.Error)!void {
        throttle.received.inc();
        if (!limit) return;
        var retry = try throttle.limiter.check_key(.{}) orelse return;
        throttle.limited.inc();
        // A rejected check does not consume a cell, so wait until one is taken.
        var attempts: u32 = 0;
        while (true) : (attempts += 1) {
            assert(attempts < 1 << 20);
            const raw: Io.Timestamp = .fromNanoseconds(@intCast(retry.nanos_since_epoch));
            try Io.Clock.Timestamp.wait(.{ .raw = raw, .clock = .real }, throttle.io);
            retry = try throttle.limiter.check_key(.{}) orelse return;
        }
    }
};

const testing = std.testing;
const runtime = @import("runtime");

fn elapsed_ms(io: Io, start: Io.Timestamp) i96 {
    return @divTrunc(start.durationTo(Io.Clock.real.now(io)).nanoseconds, std.time.ns_per_ms);
}

test "receive waits for the limiter only when limited" {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(struct {
        fn run(io: Io) !void {
            var received: Counter = .{};
            var limited: Counter = .{};
            const gpa = testing.allocator;
            var throttle = Throttle.init(gpa, io, .per_second(1), &received, &limited);
            defer throttle.deinit();
            const start = Io.Clock.real.now(io);
            try throttle.receive(true);
            try testing.expectEqual(@as(i96, 0), elapsed_ms(io, start));
            try throttle.receive(false);
            try testing.expectEqual(@as(i96, 0), elapsed_ms(io, start));
            try testing.expectEqual(@as(u64, 0), limited.get());
            try throttle.receive(true);
            try testing.expectEqual(@as(i96, 1000), elapsed_ms(io, start));
            try testing.expectEqual(@as(u64, 3), received.get());
            try testing.expectEqual(@as(u64, 1), limited.get());
        }
    }.run, .{runner.io()}));
}

test "a flood is admitted one per period" {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(struct {
        fn run(io: Io) !void {
            var received: Counter = .{};
            var limited: Counter = .{};
            const gpa = testing.allocator;
            var throttle = Throttle.init(gpa, io, .per_second(1), &received, &limited);
            defer throttle.deinit();
            const start = Io.Clock.real.now(io);
            for (0..5) |i| {
                try throttle.receive(true);
                try testing.expectEqual(@as(i96, @intCast(i * 1000)), elapsed_ms(io, start));
            }
            try testing.expectEqual(@as(u64, 5), received.get());
            try testing.expectEqual(@as(u64, 4), limited.get());
        }
    }.run, .{runner.io()}));
}
