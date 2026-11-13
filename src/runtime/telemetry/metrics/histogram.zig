//! Histogram helpers (commonware `metrics::histogram`): bucket layouts, `observe_between`, and
//! timers that record durations read from an `std.Io` clock (commonware's `Clock::current`,
//! the real clock, which the deterministic runtime simulates).

const std = @import("std");
const raw = @import("raw.zig");
const registry = @import("registry.zig");
const scope_module = @import("scope.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Bucket layouts in seconds (commonware `Buckets`).
pub const Buckets = struct {
    /// Resolving items over a network: between peers or over hops, rounds, and retries.
    pub const network = [13]f64{
        0.010, 0.020, 0.050, 0.100, 0.200, 0.500, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 300.0,
    };
    /// Local work: no network, but possibly expensive computation or disk access.
    pub const local = [12]f64{
        3e-6, 1e-5, 3e-5, 1e-4, 3e-4, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1.0,
    };
    /// Cryptographic operations.
    pub const cryptography = [16]f64{
        3e-6,  1e-5, 3e-5,  1e-4, 3e-4,  0.001, 0.002, 0.003,
        0.005, 0.01, 0.015, 0.02, 0.025, 0.03,  0.1,   0.2,
    };

    comptime {
        assert(cryptography.len < raw.bucket_count_max);
        assert(network.len < raw.bucket_count_max);
    }
};

/// Observes the seconds from `start` to `end`; a clock that went backwards observes 0
/// (commonware `HistogramExt::observe_between`).
pub fn observe_between(histogram: *raw.Histogram, start: Io.Timestamp, end: Io.Timestamp) void {
    const nanoseconds = end.nanoseconds - start.nanoseconds;
    const seconds: f64 = if (nanoseconds <= 0)
        0.0
    else
        @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_s;
    assert(seconds >= 0.0);
    histogram.observe(seconds);
}

/// Registers a duration histogram over `Buckets.local` (commonware `duration_histogram`).
pub fn duration_histogram(
    scope: *const scope_module.Scope,
    name: []const u8,
    help: []const u8,
) Allocator.Error!registry.Registered(raw.Histogram) {
    return scope.histogram(name, help, &Buckets.local);
}

/// A histogram that times operations (commonware `Timed`). Owns its handle.
pub const Timed = struct {
    histogram: registry.Registered(raw.Histogram),

    pub fn init(histogram: registry.Registered(raw.Histogram)) Timed {
        return .{ .histogram = histogram };
    }

    /// Registers a duration histogram (see `duration_histogram`) wrapped for timing.
    pub fn register(
        scope: *const scope_module.Scope,
        name: []const u8,
        help: []const u8,
    ) Allocator.Error!Timed {
        return .init(try duration_histogram(scope, name, help));
    }

    pub fn deinit(timed: *Timed) void {
        timed.histogram.deinit();
        timed.* = undefined;
    }

    /// A timer started now. It borrows the histogram: observe it before `deinit`.
    pub fn timer(timed: *const Timed, io: Io) Timer {
        return .{ .histogram = timed.histogram.metric(), .start = Io.Clock.real.now(io) };
    }

    /// A timer for `defer scoped.finish(io)`: it observes unless `cancel` ran first
    /// (commonware `ScopedTimer`, whose drop observes).
    pub fn scoped(timed: *const Timed, io: Io) ScopedTimer {
        return .{ .timer = timed.timer(io) };
    }
};

/// A started timer (commonware `Timer`).
pub const Timer = struct {
    histogram: *raw.Histogram,
    start: Io.Timestamp,

    /// Records the time since the start.
    pub fn observe(timer: Timer, io: Io) void {
        observe_between(timer.histogram, timer.start, Io.Clock.real.now(io));
    }
};

/// A timer that records once on `finish` unless canceled.
pub const ScopedTimer = struct {
    timer: ?Timer,

    pub fn cancel(scoped: *ScopedTimer) void {
        assert(scoped.timer != null);
        scoped.timer = null;
    }

    pub fn finish(scoped: *ScopedTimer, io: Io) void {
        if (scoped.timer) |timer| timer.observe(io);
        scoped.timer = null;
    }
};

const testing = std.testing;
const deterministic = @import("../../deterministic.zig");

test "duration records all calls (duration_records_all_calls)" {
    var runner = try deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    var registry_value: registry.Registry = .init(testing.allocator);
    defer registry_value.deinit();
    const Root = struct {
        fn run(io: Io, scope: *const scope_module.Scope) !void {
            var timed: Timed = .init(try duration_histogram(scope, "test_duration", "help"));
            defer timed.deinit();
            for (0..3) |round| {
                var timer = timed.scoped(io);
                defer timer.finish(io);
                try io.sleep(.fromMilliseconds(1), .awake);
                if (round == 1) continue; // An early exit still records.
            }
            var canceled = timed.scoped(io);
            canceled.cancel();
            canceled.finish(io);
            const text = try scope.encode(testing.allocator);
            defer testing.allocator.free(text);
            try testing.expect(std.mem.indexOf(u8, text, "test_duration_count 3") != null);
        }
    };
    const scope = scope_module.Scope.init(&registry_value);
    try (try runner.start(Root.run, .{ runner.io(), &scope }));
}

test "observe_between clamps a backwards clock to zero" {
    var histogram: raw.Histogram = .init(&.{ 0.0, 1.0 });
    observe_between(&histogram, .fromNanoseconds(5), .fromNanoseconds(3));
    observe_between(&histogram, .fromNanoseconds(0), .fromNanoseconds(std.time.ns_per_s / 2));
    try testing.expectEqual(@as(u64, 2), histogram.get_count());
    try testing.expectEqualSlices(u64, &.{ 1, 1, 0 }, histogram.counts[0..3]);
    try testing.expectEqual(@as(f64, 0.5), histogram.get_sum());
}
