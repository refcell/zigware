//! A platform-independent probability value and sampler (commonware
//! `utils/src/probability.rs`).
//!
//! A `Probability` is a threshold over all `u64` samples: ratios round down to a multiple of
//! 2^-64, and the reserved threshold `maxInt(u64)` means one. Sampling draws one `u64` for
//! probabilities strictly between zero and one and draws nothing at either endpoint, so the
//! same `u64` stream gives the same decisions on every platform. Rust's `probability!` macro
//! is `ratio`/`literal`, evaluated at comptime.

const std = @import("std");
const codec = @import("codec");
const assert = std.debug.assert;

/// Biased `f64` exponent where scaling by 2^64 leaves the 53-bit significand unshifted.
const SCALED_EXPONENT: u64 = 1023 + 52 - 64;
const ONE_BITS: u64 = @bitCast(@as(f64, 1.0));

/// The `f64` cannot be represented as a probability.
pub const InvalidProbability = error{InvalidProbability};

pub const Probability = extern struct {
    threshold: u64,

    pub const zero: Probability = .{ .threshold = 0 };
    pub const one: Probability = .{ .threshold = std.math.maxInt(u64) };

    comptime {
        assert(@sizeOf(Probability) == @sizeOf(u64));
    }

    /// `numerator / denominator`, rounded down (Rust `new`). Null when the denominator is zero
    /// or the numerator exceeds it.
    pub fn init(numerator: u64, denominator: u64) ?Probability {
        if (denominator == 0 or numerator > denominator) return null;
        if (numerator == denominator) return one;
        const threshold = (@as(u128, numerator) << 64) / denominator;
        // A proper fraction with a u64 denominator is at least 2^-64 below one.
        assert(threshold < std.math.maxInt(u64));
        return .{ .threshold = @intCast(threshold) };
    }

    /// The exact IEEE-754 value, when it maps exactly to a threshold: null when `value` is not
    /// finite, outside [0, 1], or would round.
    pub fn from_f64(value: f64) ?Probability {
        const bits: u64 = @bitCast(value);
        const magnitude = bits & (std.math.maxInt(u64) >> 1);
        if (magnitude == 0) return zero;
        if (bits != magnitude or magnitude > ONE_BITS) return null;
        const exponent = magnitude >> 52;
        if (exponent == 0) return null; // Subnormals need rounding.
        const significand = (@as(u64, 1) << 52) | (magnitude & ((@as(u64, 1) << 52) - 1));
        if (exponent < SCALED_EXPONENT) {
            const shift = SCALED_EXPONENT - exponent;
            if (@ctz(significand) < shift) return null;
            assert(shift <= 52);
            return .{ .threshold = significand >> @intCast(shift) };
        }
        const threshold = @as(u128, significand) << @intCast(exponent - SCALED_EXPONENT);
        if (threshold == 1 << 64) return one;
        assert(threshold < std.math.maxInt(u64));
        return .{ .threshold = @intCast(threshold) };
    }

    /// `from_f64` as an error (Rust `TryFrom<f64>`).
    pub fn try_from_f64(value: f64) InvalidProbability!Probability {
        return from_f64(value) orelse error.InvalidProbability;
    }

    /// A comptime ratio (Rust `probability!(n, d)`); invalid ratios fail compilation.
    pub fn ratio(comptime numerator: u64, comptime denominator: u64) Probability {
        return comptime init(numerator, denominator) orelse
            @compileError("probability requires a non-zero denominator and " ++
                "numerator <= denominator");
    }

    /// A comptime float (Rust `probability!(0.98)`); values needing rounding fail compilation.
    pub fn literal(comptime value: f64) Probability {
        return comptime from_f64(value) orelse
            @compileError("probability requires a value in [0, 1] exactly " ++
                "representable as a 64-bit threshold");
    }

    pub fn is_zero(self: Probability) bool {
        return self.threshold == 0;
    }

    pub fn is_one(self: Probability) bool {
        return self.threshold == std.math.maxInt(u64);
    }

    /// As an `f64` in [0, 1]; interior probabilities stay strictly below one.
    pub fn as_f64(self: Probability) f64 {
        if (self.is_one()) return 1.0;
        const value = @as(f64, @floatFromInt(self.threshold)) / 0x1p64;
        if (value == 1.0) return @bitCast(ONE_BITS - 1);
        assert(value < 1.0);
        return value;
    }

    /// Samples with the next `u64` of `rng`; endpoints draw nothing.
    pub fn sample(self: Probability, rng: anytype) bool {
        if (self.is_zero()) return false;
        if (self.is_one()) return true;
        return rng.next_u64() < self.threshold;
    }

    pub fn eql(a: Probability, b: Probability) bool {
        return a.threshold == b.threshold;
    }

    pub fn order(a: Probability, b: Probability) std.math.Order {
        return std.math.order(a.threshold, b.threshold);
    }

    /// Rust `Debug` prints the `f64` value.
    pub fn format(self: Probability, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d}", .{self.as_f64()});
    }

    /// commonware's derived `Arbitrary`: any threshold.
    pub fn arbitrary(
        _: std.mem.Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Probability {
        return .{ .threshold = u.int(u64) };
    }
};

const testing = std.testing;

/// An rng that returns `value` and counts draws.
const CountingRng = struct {
    value: u64,
    calls: usize = 0,

    pub fn next_u64(rng: *CountingRng) u64 {
        rng.calls += 1;
        return rng.value;
    }
};

test "probability: construction" {
    const max = std.math.maxInt(u64);
    try testing.expectEqual(Probability.literal(0.0), Probability.init(0, max).?);
    try testing.expectEqual(Probability.literal(1.0), Probability.init(max, max).?);
    try testing.expectEqual(Probability.ratio(1, 2), Probability.ratio(2, 4));
    try testing.expectEqual(0.5, Probability.ratio(1, 2).as_f64());
    try testing.expectEqual(@as(?Probability, null), Probability.init(1, 0));
    try testing.expectEqual(@as(?Probability, null), Probability.init(2, 1));
}

test "probability: f64 construction preserves the binary value" {
    const from_literal = Probability.literal(0.98);
    const minimum_interior: f64 = @bitCast(@as(u64, 959) << 52);
    try testing.expectEqual(18_077_809_192_235_360_256, from_literal.threshold);
    try testing.expectEqual(0.98, from_literal.as_f64());
    try testing.expect(!from_literal.eql(Probability.ratio(49, 50)));
    try testing.expectEqual(Probability.literal(0.5), Probability.ratio(1, 2));
    try testing.expectEqual(Probability.literal(0.5), try Probability.try_from_f64(0.5));
    try testing.expectEqual(Probability.zero, Probability.from_f64(0.0).?);
    try testing.expectEqual(Probability.zero, Probability.from_f64(-0.0).?);
    try testing.expectEqual(Probability.one, Probability.from_f64(1.0).?);
    try testing.expectEqual(1, Probability.from_f64(minimum_interior).?.threshold);
    const below_one: f64 = @bitCast(ONE_BITS - 1);
    try testing.expectEqual(below_one, Probability.from_f64(below_one).?.as_f64());
}

test "probability: f64 construction rejects lossy or invalid values" {
    const nan_bits: u64 = @bitCast(std.math.nan(f64));
    const invalid = [_]f64{
        @bitCast(@as(u64, 958) << 52),
        @bitCast((@as(u64, 959) << 52) + 1),
        @bitCast(@as(u64, 1)),
        -0.1,
        1.1,
        @bitCast(ONE_BITS + 1),
        std.math.nan(f64),
        @bitCast(nan_bits | (@as(u64, 1) << 63)),
        std.math.inf(f64),
        -std.math.inf(f64),
    };
    for (invalid) |value| {
        try testing.expectEqual(@as(?Probability, null), Probability.from_f64(value));
        try testing.expectError(error.InvalidProbability, Probability.try_from_f64(value));
    }
}

test "probability: ratios use platform-independent thresholds" {
    const scale: u128 = 1 << 64;
    try testing.expectEqual(scale / 3, Probability.ratio(1, 3).threshold);
    try testing.expectEqual(2 * scale / 3, Probability.ratio(2, 3).threshold);
    const max = std.math.maxInt(u64);
    const below_one = Probability.init(max - 1, max).?;
    try testing.expectEqual(max - 1, below_one.threshold);
    try testing.expect(below_one.as_f64() < 1.0);
}

test "probability: sampling uses the threshold and skips the endpoints" {
    var rng: CountingRng = .{ .value = 0 };
    try testing.expect(!Probability.literal(0.0).sample(&rng));
    try testing.expect(Probability.literal(1.0).sample(&rng));
    try testing.expectEqual(0, rng.calls);
    rng.value = (1 << 63) - 1;
    try testing.expect(Probability.ratio(1, 2).sample(&rng));
    try testing.expectEqual(1, rng.calls);
    rng.value = 1 << 63;
    try testing.expect(!Probability.ratio(1, 2).sample(&rng));
    try testing.expectEqual(2, rng.calls);
}

test "probability: from_f64 and as_f64 round-trip every exact value" {
    // Every threshold whose f64 conversion is exact maps back to itself.
    var generator = @import("rng.zig").test_rng();
    for (0..10_000) |_| {
        const shift = generator.next_u64() % 64;
        const threshold = (generator.next_u64() >> 11) >> @intCast(shift % 53);
        const probability: Probability = .{ .threshold = threshold };
        const value = probability.as_f64();
        try testing.expectEqual(probability, Probability.from_f64(value).?);
        try testing.expectEqual(.eq, probability.order(.{ .threshold = threshold }));
    }
}
