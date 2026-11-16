//! Durations and wall-clock times (commonware `utils/src/time.rs`).
//!
//! Zig's std has no equivalent of Rust's `Duration` and `SystemTime` values, so this file
//! provides both with Rust's ranges and saturation rules:
//! - `Duration`: seconds (`u64`) plus nanoseconds (`< 1e9`), max `u64` seconds.
//! - `SystemTime`: signed nanoseconds since the Unix epoch, limited to `i64` seconds like
//!   Rust on Unix. Library code gets the current time from the runtime, never the OS.
//!
//! Plus commonware's extensions: `as_millis_u64`, `from_nanos_saturating`, `parse`
//! (`"123ms"`, `"30s"`, `"5m"`, `"2h"`), `epoch`, `epoch_millis`, `add_jittered`, `limit`,
//! and `saturating_add`.

const std = @import("std");
const rng_mod = @import("rng.zig");
const assert = std.debug.assert;

pub const NANOS_PER_SEC: u32 = 1_000_000_000;
const nanos_per_milli: u32 = 1_000_000;

/// A span of time, like Rust's `core::time::Duration`.
pub const Duration = struct {
    secs: u64,
    /// Always below `NANOS_PER_SEC`.
    nanos: u32,

    pub const zero: Duration = .{ .secs = 0, .nanos = 0 };
    pub const max: Duration = .{ .secs = std.math.maxInt(u64), .nanos = NANOS_PER_SEC - 1 };

    /// Carries whole seconds out of `nanos`; panics on overflow like Rust's `Duration::new`.
    pub fn init(secs: u64, nanos: u32) Duration {
        const carry = nanos / NANOS_PER_SEC;
        const total = std.math.add(u64, secs, carry) catch @panic("overflow in Duration::new");
        const result: Duration = .{ .secs = total, .nanos = nanos % NANOS_PER_SEC };
        assert(result.nanos < NANOS_PER_SEC);
        return result;
    }

    pub fn from_secs(secs: u64) Duration {
        return .{ .secs = secs, .nanos = 0 };
    }

    pub fn from_millis(millis: u64) Duration {
        const nanos: u32 = @intCast((millis % 1000) * nanos_per_milli);
        return .{ .secs = millis / 1000, .nanos = nanos };
    }

    pub fn from_micros(micros: u64) Duration {
        const nanos: u32 = @intCast((micros % 1_000_000) * 1000);
        return .{ .secs = micros / 1_000_000, .nanos = nanos };
    }

    pub fn from_nanos(nanos: u64) Duration {
        return .{ .secs = nanos / NANOS_PER_SEC, .nanos = @intCast(nanos % NANOS_PER_SEC) };
    }

    /// Converts nanoseconds, clamping anything beyond `max` to `max`.
    pub fn from_nanos_saturating(nanos: u128) Duration {
        if (nanos > max.as_nanos()) return max;
        const result: Duration = .{
            .secs = @intCast(nanos / NANOS_PER_SEC),
            .nanos = @intCast(nanos % NANOS_PER_SEC),
        };
        assert(result.as_nanos() == nanos);
        return result;
    }

    pub fn as_nanos(duration: Duration) u128 {
        assert(duration.nanos < NANOS_PER_SEC);
        return @as(u128, duration.secs) * NANOS_PER_SEC + duration.nanos;
    }

    pub fn as_millis(duration: Duration) u128 {
        assert(duration.nanos < NANOS_PER_SEC);
        return @as(u128, duration.secs) * 1000 + duration.nanos / nanos_per_milli;
    }

    /// Whole milliseconds as a `u64`; panics when they do not fit.
    pub fn as_millis_u64(duration: Duration) u64 {
        return std.math.cast(u64, duration.as_millis()) orelse
            @panic("duration milliseconds should fit in u64");
    }

    pub fn is_zero(duration: Duration) bool {
        return duration.secs == 0 and duration.nanos == 0;
    }

    pub fn order(a: Duration, b: Duration) std.math.Order {
        return std.math.order(a.as_nanos(), b.as_nanos());
    }

    pub fn checked_add(a: Duration, b: Duration) ?Duration {
        const sum = a.as_nanos() + b.as_nanos(); // Cannot overflow: both are below 2^94.
        if (sum > max.as_nanos()) return null;
        return from_nanos_saturating(sum);
    }

    pub fn saturating_add(a: Duration, b: Duration) Duration {
        return a.checked_add(b) orelse max;
    }

    pub fn checked_sub(a: Duration, b: Duration) ?Duration {
        const difference = std.math.sub(u128, a.as_nanos(), b.as_nanos()) catch return null;
        return from_nanos_saturating(difference);
    }

    pub fn checked_mul(duration: Duration, factor: u32) ?Duration {
        const product = duration.as_nanos() * factor; // Below 2^126: cannot overflow.
        if (product > max.as_nanos()) return null;
        return from_nanos_saturating(product);
    }

    pub const ParseError = error{ InvalidFormat, InvalidNumber, Overflow };

    /// Parses `"<n>ms"`, `"<n>s"`, `"<n>m"`, or `"<n>h"` with `n` a decimal `u64`.
    /// Whitespace around the input and before the suffix is ignored; a suffix is required.
    /// `error.Overflow` is commonware's "too large (would overflow)" for minutes and hours.
    pub fn parse(input: []const u8) ParseError!Duration {
        const text = trim_whitespace(input);
        if (std.mem.endsWith(u8, text, "ms")) {
            return from_millis(try parse_u64(text[0 .. text.len - 2]));
        }
        const units = [_]struct { u8, u64 }{ .{ 'h', 3600 }, .{ 'm', 60 }, .{ 's', 1 } };
        for (units) |unit| {
            if (text.len > 0 and text[text.len - 1] == unit[0]) {
                const count = try parse_u64(text[0 .. text.len - 1]);
                const secs = std.math.mul(u64, count, unit[1]) catch return error.Overflow;
                return from_secs(secs);
            }
        }
        return error.InvalidFormat;
    }
};

/// Rust's `str::parse::<u64>` after `trim`: an optional `+` and at least one ASCII digit.
fn parse_u64(input: []const u8) Duration.ParseError!u64 {
    const text = trim_whitespace(input);
    const digits = if (text.len > 0 and text[0] == '+') text[1..] else text;
    if (digits.len == 0) return error.InvalidNumber;
    var value: u64 = 0;
    for (digits) |char| {
        if (char < '0' or char > '9') return error.InvalidNumber;
        value = std.math.mul(u64, value, 10) catch return error.InvalidNumber;
        value = std.math.add(u64, value, char - '0') catch return error.InvalidNumber;
    }
    return value;
}

/// Whether `codepoint` has the Unicode `White_Space` property (Rust's `char::is_whitespace`).
fn is_whitespace(codepoint: u21) bool {
    return switch (codepoint) {
        0x09...0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000...0x200A => true,
        0x2028, 0x2029, 0x202F, 0x205F, 0x3000 => true,
        else => false,
    };
}

/// Rust's `str::trim`: strips Unicode whitespace from both ends. Invalid UTF-8 is kept.
fn trim_whitespace(input: []const u8) []const u8 {
    var start: usize = 0;
    while (start < input.len) {
        const len = std.unicode.utf8ByteSequenceLength(input[start]) catch break;
        if (start + len > input.len) break;
        const codepoint = std.unicode.utf8Decode(input[start..][0..len]) catch break;
        if (!is_whitespace(codepoint)) break;
        start += len;
    }
    var end = input.len;
    while (end > start) {
        // Find the start of the last code point (at most four bytes back).
        var begin = end - 1;
        while (begin > start and end - begin < 4 and input[begin] & 0xC0 == 0x80) begin -= 1;
        const codepoint = std.unicode.utf8Decode(input[begin..end]) catch break;
        if (!is_whitespace(codepoint)) break;
        end = begin;
    }
    assert(start <= end);
    return input[start..end];
}

/// The latest representable time: the epoch plus `i64` max seconds and 999,999,999 ns.
const limit_nanos: i128 = @as(i128, std.math.maxInt(i64)) * NANOS_PER_SEC + (NANOS_PER_SEC - 1);
const minimum_nanos: i128 = @as(i128, std.math.minInt(i64)) * NANOS_PER_SEC;

/// The largest duration since the epoch that `SystemTime` represents.
pub const MAX_DURATION_SINCE_UNIX_EPOCH: Duration =
    .{ .secs = std.math.maxInt(i64), .nanos = NANOS_PER_SEC - 1 };

/// The smallest step between two `SystemTime`s.
pub const SYSTEM_TIME_PRECISION: Duration = .{ .secs = 0, .nanos = 1 };

/// A wall-clock time, like Rust's `std::time::SystemTime` on Unix.
pub const SystemTime = struct {
    /// Nanoseconds since 1970-01-01T00:00:00Z; negative before the epoch.
    nanos_since_epoch: i128,

    pub const UNIX_EPOCH: SystemTime = .{ .nanos_since_epoch = 0 };

    /// Converts a `std.Io.Timestamp` from a real-time clock.
    pub fn from_timestamp(timestamp: std.Io.Timestamp) SystemTime {
        const nanos: i128 = timestamp.nanoseconds;
        assert(nanos >= minimum_nanos and nanos <= limit_nanos);
        return .{ .nanos_since_epoch = nanos };
    }

    /// The latest representable time (commonware's `SystemTimeExt::limit`).
    pub fn limit() SystemTime {
        return .{ .nanos_since_epoch = limit_nanos };
    }

    pub fn order(a: SystemTime, b: SystemTime) std.math.Order {
        return std.math.order(a.nanos_since_epoch, b.nanos_since_epoch);
    }

    /// `null` when the result would pass `limit()`.
    pub fn checked_add(time: SystemTime, delta: Duration) ?SystemTime {
        const delta_nanos = delta.as_nanos();
        if (delta_nanos > limit_nanos) return null;
        const sum = time.nanos_since_epoch + @as(i128, @intCast(delta_nanos));
        if (sum > limit_nanos) return null;
        return .{ .nanos_since_epoch = sum };
    }

    /// `null` when the result would precede the earliest representable time.
    pub fn checked_sub(time: SystemTime, delta: Duration) ?SystemTime {
        const delta_nanos = delta.as_nanos();
        if (delta_nanos > limit_nanos) return null;
        const difference = time.nanos_since_epoch - @as(i128, @intCast(delta_nanos));
        if (difference < minimum_nanos) return null;
        return .{ .nanos_since_epoch = difference };
    }

    /// Adds `delta`, clamping at `limit()`.
    pub fn saturating_add(time: SystemTime, delta: Duration) SystemTime {
        if (delta.is_zero()) return time;
        const result = time.checked_add(delta) orelse limit();
        assert(result.nanos_since_epoch >= time.nanos_since_epoch);
        return result;
    }

    /// The duration since the epoch; panics for times before it.
    pub fn epoch(time: SystemTime) Duration {
        if (time.nanos_since_epoch < 0) @panic("failed to get epoch time");
        return Duration.from_nanos_saturating(@intCast(time.nanos_since_epoch));
    }

    /// Milliseconds since the epoch, saturating at `u64` max; panics before the epoch.
    pub fn epoch_millis(time: SystemTime) u64 {
        const millis = time.epoch().as_millis();
        return @intCast(@min(millis, std.math.maxInt(u64)));
    }

    /// Adds a uniformly random duration in `[0, 2 * jitter]`, saturating at `limit()`.
    /// Draws exactly like Rust `rand` 0.10's `random_range(Duration::default()..=jitter * 2)`.
    pub fn add_jittered(time: SystemTime, rng: anytype, jitter: Duration) SystemTime {
        const span = jitter.checked_mul(2) orelse @panic("overflow when multiplying duration");
        return time.saturating_add(sample_duration(rng, Duration.zero, span));
    }
};

/// A `Duration` that is never zero (commonware `NonZeroDuration`; `NZDuration!` is
/// `init_panic`).
pub const NonZeroDuration = struct {
    duration: Duration,

    /// Returns null when `duration` is zero.
    pub fn init(duration: Duration) ?NonZeroDuration {
        if (duration.is_zero()) return null;
        return .{ .duration = duration };
    }

    /// Panics when `duration` is zero.
    pub fn init_panic(duration: Duration) NonZeroDuration {
        return init(duration) orelse @panic("duration must be non-zero");
    }

    pub fn get(self: NonZeroDuration) Duration {
        assert(!self.duration.is_zero());
        return self.duration;
    }

    pub fn order(a: NonZeroDuration, b: NonZeroDuration) std.math.Order {
        return a.duration.order(b.duration);
    }
};

/// A uniform duration in `[low, high]`, matching `rand` 0.10's `UniformDuration`.
pub fn sample_duration(rng: anytype, low: Duration, high: Duration) Duration {
    assert(low.order(high) != .gt);
    var high_secs = high.secs;
    var high_nanos = high.nanos;
    if (high_nanos < low.nanos) {
        high_secs -= 1;
        high_nanos += NANOS_PER_SEC;
    }
    if (low.secs == high_secs) {
        const nanos = rng_mod.Uniform(u32).init_inclusive(low.nanos, high_nanos).sample(rng);
        return Duration.init(low.secs, nanos);
    }
    if (std.math.mul(u64, high_secs, NANOS_PER_SEC) catch null) |high_whole| {
        if (std.math.add(u64, high_whole, high_nanos) catch null) |high_total| {
            const low_total = low.secs * NANOS_PER_SEC + low.nanos;
            const nanos = rng_mod.Uniform(u64).init_inclusive(low_total, high_total).sample(rng);
            return Duration.from_nanos(nanos);
        }
    }
    // Large spans: seconds and an offset nanosecond part, rejecting overshoot at the top.
    const secs_uniform = rng_mod.Uniform(u64).init_inclusive(low.secs, high_secs);
    const nanos_uniform = rng_mod.Uniform(u32).init(0, NANOS_PER_SEC);
    const max_nanos = high_nanos - low.nanos;
    while (true) {
        const secs = secs_uniform.sample(rng);
        const nanos = nanos_uniform.sample(rng);
        if (secs == high_secs and nanos > max_nanos) continue;
        return Duration.init(secs, nanos + low.nanos);
    }
}

const testing = std.testing;

test "time: NonZeroDuration" {
    try testing.expectEqual(null, NonZeroDuration.init(Duration.zero));
    const duration = Duration.from_millis(100);
    try testing.expectEqual(duration, NonZeroDuration.init(duration).?.get());
    try testing.expectEqual(duration, NonZeroDuration.init_panic(duration).get());
    const longer = NonZeroDuration.init(Duration.from_millis(200)).?;
    try testing.expectEqual(.lt, NonZeroDuration.init(duration).?.order(longer));
    // Sub-millisecond durations are non-zero too.
    try testing.expect(NonZeroDuration.init(Duration.from_nanos(1)) != null);
}

test "time: as_millis_u64" {
    const cases = [_]struct { Duration, u64 }{
        .{ Duration.zero, 0 },
        .{ Duration.from_nanos(999_999), 0 },
        .{ Duration.init(1, 234_567_890), 1_234 },
        .{ Duration.from_millis(std.math.maxInt(u64)), std.math.maxInt(u64) },
        .{
            Duration.from_millis(std.math.maxInt(u64)).saturating_add(Duration.from_nanos(999_999)),
            std.math.maxInt(u64),
        },
    };
    for (cases) |case| try testing.expectEqual(case[1], case[0].as_millis_u64());
    // Overflowing cases panic in commonware; check the boundary instead.
    const over = Duration.from_millis(std.math.maxInt(u64)).checked_add(Duration.from_millis(1)).?;
    try testing.expect(std.math.cast(u64, over.as_millis()) == null);
    try testing.expect(std.math.cast(u64, Duration.max.as_millis()) == null);
}

test "time: epoch and epoch_millis" {
    try testing.expectEqual(Duration.zero, SystemTime.UNIX_EPOCH.epoch());
    const plus = SystemTime.UNIX_EPOCH.checked_add(Duration.from_millis(1_001)).?;
    try testing.expectEqual(Duration.from_millis(1_001), plus.epoch());
    try testing.expectEqual(@as(u64, 0), SystemTime.UNIX_EPOCH.epoch_millis());
    try testing.expectEqual(@as(u64, 1_001), plus.epoch_millis());
    const rounds = SystemTime.UNIX_EPOCH.checked_add(Duration.init(1, 999_999)).?;
    try testing.expectEqual(@as(u64, 1_000), rounds.epoch_millis());
    const minutes = SystemTime.UNIX_EPOCH.checked_add(Duration.from_secs(300)).?;
    try testing.expectEqual(@as(u64, 300_000), minutes.epoch_millis());
    // Before the epoch, `epoch` panics like commonware.
    const before = SystemTime.UNIX_EPOCH.checked_sub(Duration.from_secs(1)).?;
    try testing.expectEqual(std.math.Order.lt, before.order(SystemTime.UNIX_EPOCH));
}

test "time: from_nanos_saturating" {
    try testing.expectEqual(Duration.zero, Duration.from_nanos_saturating(0));
    try testing.expectEqual(
        Duration.init(0, NANOS_PER_SEC - 1),
        Duration.from_nanos_saturating(NANOS_PER_SEC - 1),
    );
    try testing.expectEqual(Duration.init(1, 1), Duration.from_nanos_saturating(NANOS_PER_SEC + 1));
    const beyond = Duration.from_nanos_saturating(@as(u128, std.math.maxInt(u64)) + 1);
    const std_max = Duration.from_nanos(std.math.maxInt(u64));
    try testing.expectEqual(std.math.Order.gt, beyond.order(std_max));
    try testing.expectEqual(Duration.max, Duration.from_nanos_saturating(Duration.max.as_nanos()));
    const past_max = Duration.max.as_nanos() + 1;
    try testing.expectEqual(Duration.max, Duration.from_nanos_saturating(past_max));
    try testing.expectEqual(Duration.max, Duration.from_nanos_saturating(std.math.maxInt(u128)));
}

test "time: add_jittered stays within bounds" {
    var rng = rng_mod.test_rng();
    const time = SystemTime.UNIX_EPOCH.checked_add(Duration.from_secs(1)).?;
    const jitter = Duration.from_secs(2);
    const average = time.checked_add(jitter).?;
    const top = time.checked_add(jitter.checked_mul(2).?).?;
    var below = false;
    var above = false;
    for (0..100) |_| {
        const jittered = time.add_jittered(&rng, jitter);
        below = below or jittered.order(average) == .lt;
        above = above or jittered.order(average) == .gt;
        try testing.expect(jittered.order(time) != .lt);
        try testing.expect(jittered.order(top) != .gt);
    }
    try testing.expect(below and above);

    const late = SystemTime.limit().checked_sub(Duration.from_secs(1)).?;
    for (0..100) |_| {
        const jittered = late.add_jittered(&rng, Duration.from_secs(60));
        try testing.expect(jittered.order(late) != .lt);
        try testing.expect(jittered.order(SystemTime.limit()) != .gt);
    }
}

test "time: sample_duration matches rand 0.10 UniformDuration" {
    // Reference values from Rust `rand` 0.10.2: `StdRng::seed_from_u64(3)` after the draws in
    // rng.zig's Uniform test, then `random_range` over three duration spans.
    var rng = rng_mod.TestRng.init(3);
    for (0..6) |_| _ = rng_mod.Uniform(u32).init_inclusive(5, 1_000_003).sample(&rng);
    for (0..6) |_| _ = rng_mod.Uniform(u64).init(0, 3_000_000_000_000_000_007).sample(&rng);
    for (0..6) |_| _ = rng_mod.Uniform(u8).init_inclusive(0, 6).sample(&rng);
    const Case = struct { Duration, Duration, [4]Duration };
    const cases = [_]Case{
        .{ Duration.zero, Duration.from_secs(4), .{
            Duration.init(3, 744568348), Duration.init(3, 671805140),
            Duration.init(0, 627428526), Duration.init(2, 450037558),
        } },
        .{ Duration.from_millis(1500), Duration.from_millis(1700), .{
            Duration.init(1, 618776773), Duration.init(1, 650675183),
            Duration.init(1, 546579057), Duration.init(1, 639805823),
        } },
        .{ Duration.init(3, 700), Duration.init(std.math.maxInt(u64) - 1, 500), .{
            Duration.init(16665135411002854098, 970445263),
            Duration.init(11545866227634739735, 577976735),
            Duration.init(16490409879112422679, 126121303),
            Duration.init(18319346247772478446, 249477744),
        } },
    };
    for (cases) |case| {
        for (case[2]) |expected| {
            try testing.expectEqual(expected, sample_duration(&rng, case[0], case[1]));
        }
    }
}

test "time: limit precision and saturating add" {
    const max_time = SystemTime.limit();
    try testing.expect(max_time.checked_add(SYSTEM_TIME_PRECISION) == null);
    try testing.expectEqual(max_time, max_time.checked_add(Duration.zero).?);
    try testing.expectEqual(max_time, max_time.saturating_add(Duration.from_nanos(1)));
    try testing.expectEqual(max_time, max_time.saturating_add(Duration.from_secs(1)));
    try testing.expectEqual(MAX_DURATION_SINCE_UNIX_EPOCH, max_time.epoch());
}

test "time: parse accepted forms" {
    const Case = struct { []const u8, Duration };
    const cases = [_]Case{
        .{ "500ms", Duration.from_millis(500) },
        .{ "0ms", Duration.zero },
        .{ "1ms", Duration.from_millis(1) },
        .{ "1000ms", Duration.from_secs(1) },
        .{ "30s", Duration.from_secs(30) },
        .{ "0s", Duration.zero },
        .{ "3600s", Duration.from_secs(3600) },
        .{ "5m", Duration.from_secs(300) },
        .{ "60m", Duration.from_secs(3600) },
        .{ "0m", Duration.zero },
        .{ "2h", Duration.from_secs(7200) },
        .{ "168h", Duration.from_secs(604800) },
        .{ "  30s  ", Duration.from_secs(30) },
        .{ "\t500ms\n", Duration.from_millis(500) },
        .{ " 2h ", Duration.from_secs(7200) },
        .{ "30 s", Duration.from_secs(30) },
        .{ "500 ms", Duration.from_millis(500) },
        .{ "2 h", Duration.from_secs(7200) },
        .{ "5 m", Duration.from_secs(300) },
        .{ "+5s", Duration.from_secs(5) },
        .{ "999999999ms", Duration.from_millis(999999999) },
        .{ "99999999s", Duration.from_secs(99999999) },
        .{ "\u{3000}7s\u{00A0}", Duration.from_secs(7) },
    };
    for (cases) |case| try testing.expectEqual(case[1], try Duration.parse(case[0]));
}

test "time: parse rejected forms" {
    const rejected = [_][]const u8{
        "invalid",   "abc123ms", "12.5s",     "10x",    "30days", "5y",  "5minutes",
        "10seconds", "2hours",   "500millis", "30sec",  "5min",   "2hr", "60",
        "0",         "3600",     "1",         "",       "   ",    "-5s", "-100ms",
        "30S",       "500MS",    "2H",        "1_000s", "ms",     "s",   "+s",
    };
    for (rejected) |input| try testing.expect(std.meta.isError(Duration.parse(input)));
}

test "time: parse overflow" {
    var buffer: [32]u8 = undefined;
    const u64_max = std.math.maxInt(u64);
    for ([_]struct { u64, u8 }{ .{ 3600, 'h' }, .{ 60, 'm' } }) |unit| {
        const safe = try std.fmt.bufPrint(&buffer, "{d}{c}", .{ u64_max / unit[0], unit[1] });
        _ = try Duration.parse(safe);
        const over = try std.fmt.bufPrint(&buffer, "{d}{c}", .{ u64_max / unit[0] + 1, unit[1] });
        try testing.expectError(error.Overflow, Duration.parse(over));
        const top = try std.fmt.bufPrint(&buffer, "{d}{c}", .{ u64_max, unit[1] });
        try testing.expectError(error.Overflow, Duration.parse(top));
    }
    // A number beyond u64 is an invalid number, not an overflow (Rust's parse fails first).
    try testing.expectError(error.InvalidNumber, Duration.parse("18446744073709551616s"));
}

/// Fuzz body (commonware utils/fuzz time.rs): parse never panics, accepted inputs round
/// trip through milliseconds, and epoch/jitter arithmetic holds for any seconds count.
fn fuzz_time(input: []const u8, generator: *rng_mod.FuzzRng) !void {
    if (Duration.parse(input)) |duration| {
        var buffer: [48]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "{d}ms", .{duration.as_millis()});
        if (duration.as_millis() <= std.math.maxInt(u64)) {
            try testing.expectEqual(duration, try Duration.parse(text));
        }
    } else |_| {}
    const seconds = generator.next_u64();
    if (SystemTime.UNIX_EPOCH.checked_add(Duration.from_secs(seconds))) |time| {
        try testing.expectEqual(Duration.from_secs(seconds), time.epoch());
        const millis = std.math.mul(u64, seconds, 1000) catch std.math.maxInt(u64);
        try testing.expectEqual(millis, time.epoch_millis());
        const jitter = Duration.from_secs(@min(generator.next_u64(), 3600));
        if (time.checked_add(jitter.checked_mul(2).?)) |top| {
            var draw = rng_mod.TestRng.init(generator.next_u64());
            const jittered = time.add_jittered(&draw, jitter);
            try testing.expect(jittered.order(time) != .lt and jittered.order(top) != .gt);
        }
    }
}

test "fuzz time seeded" {
    const build_options = @import("build_options");
    const iterations: u64 = 2_000 * @as(u64, build_options.fuzz_soak);
    var seed_rng = rng_mod.TestRng.init(0x7469_6d65 ^ build_options.fuzz_seed);
    const alphabet = " \t+-0123456789mshx_.";
    var input: [24]u8 = undefined;
    var entropy: [16]u8 = undefined;
    for (0..iterations) |_| {
        const len = rng_mod.range_at_most(&seed_rng, usize, 0, input.len);
        for (input[0..len]) |*char| {
            char.* = alphabet[rng_mod.range_less_than(&seed_rng, usize, 0, alphabet.len)];
        }
        seed_rng.fill_bytes(&entropy);
        var generator = rng_mod.FuzzRng.init(&entropy);
        try fuzz_time(input[0..len], &generator);
    }
}

test "fuzz time" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var input: [64]u8 = undefined;
            const len = smith.slice(&input);
            var entropy: [16]u8 = undefined;
            smith.bytes(&entropy);
            var generator = rng_mod.FuzzRng.init(&entropy);
            try fuzz_time(input[0..len], &generator);
        }
    }.run, .{ .corpus = &.{ "30s", "500 ms", "18446744073709551615h" } });
}
