//! Peer throughput scores (commonware `resolver/src/p2p/score.rs`).
//!
//! An exponentially weighted estimate of useful bytes per charged second. Each observation
//! moves the byte and duration averages halfway toward its samples, and the weight divides one
//! average by the other. The averages do not decay between observations. A zero-byte
//! observation never raises the weight, and an observation with bytes can lower it when its
//! byte rate is below the current estimate.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");

const Duration = utils.Duration;
const nanos_per_sec: u128 = utils.time.NANOS_PER_SEC;

/// Keeps 32 fractional bits in byte averages so even one-byte responses can rebuild a score
/// after repeated failures.
const byte_scale: u128 = 1 << 32;

pub const Score = struct {
    const Averages = struct {
        /// Mean bytes in units of 2^-32.
        bytes: u128,
        /// Mean charged nanoseconds, at least one.
        elapsed_ns: u128,
    };

    /// Initialized together by the first observation.
    averages: ?Averages = null,

    /// Records useful bytes and their charged duration, floored at one nanosecond. The first
    /// observation initializes both estimates; later averages round down.
    pub fn record(self: *Score, elapsed: Duration, bytes: u64) void {
        const scaled = @as(u128, bytes) * byte_scale;
        const elapsed_ns = @max(elapsed.as_nanos(), 1);
        // Scaled bytes stay below 2^96 and nanoseconds below 2^94, so the sums cannot overflow.
        comptime assert(@bitSizeOf(u64) + 32 + 1 < 128);
        self.averages = if (self.averages) |averages| .{
            .bytes = (averages.bytes + scaled) / 2,
            .elapsed_ns = (averages.elapsed_ns + elapsed_ns) / 2,
        } else .{ .bytes = scaled, .elapsed_ns = elapsed_ns };
        assert(self.averages.?.elapsed_ns >= 1);
    }

    /// Estimated bytes per second plus one, saturating at `u64::MAX`. The minimum weight of one
    /// keeps every peer selectable by weighted sampling, including peers without observations.
    pub fn weight(self: Score) u64 {
        const averages = self.averages orelse return 1;
        assert(averages.elapsed_ns >= 1);
        // Both products stay below 2^126; the denominator is nonzero.
        const rate = averages.bytes * nanos_per_sec / (averages.elapsed_ns * byte_scale);
        const clamped: u64 = std.math.cast(u64, rate) orelse std.math.maxInt(u64);
        return clamped +| 1;
    }
};

const testing = std.testing;
const failure_duration: Duration = .from_secs(2);

test "throughput accounts for bytes and duration" {
    // Equal durations reward larger responses. Equal byte rates earn equal weights.
    const cases = [_]struct { u64, u64, u64 }{
        .{ 1, 1, 1_001 },
        .{ 1_024, 1, 1_024_001 },
        .{ 1_024, 2, 512_001 },
        .{ 10_240, 20, 512_001 },
        .{ 10 * 1024 * 1024, 10, 1_048_576_001 },
        .{ 10 * 1024 * 1024, 5, 2_097_152_001 },
    };
    for (cases) |case| {
        var score: Score = .{};
        try testing.expectEqual(@as(u64, 1), score.weight());
        score.record(.from_millis(case[1]), case[0]);
        try testing.expectEqual(case[2], score.weight());
    }
}

test "throughput averages bytes and time before dividing" {
    var score: Score = .{};
    score.record(.from_millis(1), 1_000);
    score.record(.from_millis(999), 1);
    // These observations deliver 1,001 bytes over one second. Averaging their individual
    // rates would overvalue the fast response.
    try testing.expectEqual(@as(u64, 1_002), score.weight());
}

test "failures reduce score and service recovers" {
    var score: Score = .{};
    score.record(.from_millis(100), 1_000_000);
    try testing.expectEqual(@as(u64, 10_000_001), score.weight());
    // A failed request lowers the score even after a useful response.
    score.record(failure_duration, 0);
    try testing.expectEqual(@as(u64, 476_191), score.weight());
    // Successful service rebuilds the estimate without erasing the failure.
    score.record(.from_millis(100), 1_000_000);
    try testing.expectEqual(@as(u64, 1_304_348), score.weight());
}

test "empty responses cannot restore old byte credit" {
    var score: Score = .{};
    score.record(.from_millis(100), 1_000_000);
    for (0..10) |_| {
        const previous = score.weight();
        score.record(failure_duration, 0);
        try testing.expect(score.weight() < previous);
    }
    // Fast empty responses must not revive credit from the old large response.
    for ([_]Duration{ .from_millis(100), .from_nanos(1), .zero }) |elapsed| {
        const previous = score.weight();
        score.record(elapsed, 0);
        try testing.expect(score.weight() <= previous);
        try testing.expect(score.weight() < 1_000);
    }
}

test "small responses recover after repeated failures" {
    var score: Score = .{};
    score.record(.from_nanos(1), std.math.maxInt(u64));
    var previous = score.weight();
    for (0..128) |_| {
        score.record(failure_duration, 0);
        try testing.expect(score.weight() <= previous);
        previous = score.weight();
    }
    try testing.expectEqual(@as(u64, 1), previous);
    // Keeping fractional bytes lets even one-byte successes rebuild the score.
    for (0..16) |_| {
        score.record(.from_millis(1), 1);
        try testing.expect(score.weight() >= previous);
        previous = score.weight();
    }
    try testing.expect(previous > 900);
    try testing.expect(previous < 1_001);
}

test "failure before first success is retained" {
    var score: Score = .{};
    score.record(failure_duration, 0);
    try testing.expectEqual(@as(u64, 1), score.weight());
    score.record(.from_millis(100), 1_000_000);
    try testing.expectEqual(@as(u64, 476_191), score.weight());
}

test "zero and maximum inputs remain bounded" {
    for ([_]u64{ 0, 1, std.math.maxInt(u64) }) |bytes| {
        for ([_]Duration{ .zero, .from_nanos(1), .max }) |elapsed| {
            var score: Score = .{};
            const rate = @as(u128, bytes) * nanos_per_sec / @max(elapsed.as_nanos(), 1);
            const expected: u64 = std.math.cast(u64, rate + 1) orelse std.math.maxInt(u64);
            // Repeating the extremes also exercises the averaging additions.
            for (0..2) |_| {
                score.record(elapsed, bytes);
                try testing.expectEqual(expected, score.weight());
            }
            score.record(.max, 0);
            try testing.expect(score.weight() <= expected);
            score.record(.zero, std.math.maxInt(u64));
            try testing.expect(score.weight() >= 1);
        }
    }
}
