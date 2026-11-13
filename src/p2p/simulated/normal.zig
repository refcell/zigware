//! The normal distribution as `rand_distr` 0.6.0 samples it (`Normal<f64>` over
//! `StandardNormal`, Doornik's ziggurat), so the same RNG stream gives the same samples as
//! commonware's simulated links. The simulated network draws link latency from it.
//!
//! Draws use `rng.next_u64()` exactly as rand 0.10 does: one word per ziggurat step, plus
//! `random::<f64>()` (top 53 bits) for the wedge test and `Open01` (top 52 bits) in the tail.
//! `exp` and `ln` come from Zig's math, which may differ from the platform libm in the last bit;
//! that can only matter when a wedge or tail comparison is decided by that bit.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const tables = @import("ziggurat_tables.zig");

/// More ziggurat steps than any sample needs: each step accepts with probability above 0.98.
const max_steps: u32 = 1 << 20;

pub const Error = error{
    /// The standard deviation is not finite (rand_distr `Error::BadVariance`).
    BadVariance,
};

/// `N(mean, std_dev²)`; a negative `std_dev` mirrors the distribution, as in rand_distr.
pub const Normal = struct {
    mean: f64,
    std_dev: f64,

    pub fn init(mean: f64, std_dev: f64) Error!Normal {
        if (!std.math.isFinite(std_dev)) return error.BadVariance;
        return .{ .mean = mean, .std_dev = std_dev };
    }

    /// One sample; draws from `rng` even when `std_dev` is zero, as rand_distr does.
    pub fn sample(normal: Normal, rng: anytype) f64 {
        assert(std.math.isFinite(normal.std_dev));
        return normal.mean + normal.std_dev * standard(rng);
    }
};

/// Combines 52 fraction bits with a fixed exponent (rand's `into_float_with_exponent`).
fn into_float_with_exponent(fraction: u64, exponent: i32) f64 {
    assert(fraction >> 52 == 0);
    const exponent_bits = @as(u64, @intCast(1023 + exponent)) << 52;
    return @bitCast(fraction | exponent_bits);
}

/// Uniform in `(0, 1)` (rand's `Open01` for `f64`).
fn open01(rng: anytype) f64 {
    const fraction = rng.next_u64() >> 12;
    const result = into_float_with_exponent(fraction, 0) - (1.0 - std.math.floatEps(f64) / 2.0);
    assert(result > 0.0 and result < 1.0);
    return result;
}

fn pdf(x: f64) f64 {
    return @exp(-x * x / 2.0);
}

/// A sample from the tail beyond `norm_r`, on the side of `u`'s sign.
fn zero_case(rng: anytype, u: f64) f64 {
    var x: f64 = 1.0;
    var y: f64 = 0.0;
    var steps: u32 = 0;
    while (-2.0 * y < x * x) : (steps += 1) {
        if (steps == max_steps) @panic("normal tail sampling did not converge");
        const x_uniform = open01(rng);
        const y_uniform = open01(rng);
        x = @log(x_uniform) / tables.norm_r;
        y = @log(y_uniform);
    }
    assert(x <= 0.0);
    return if (u < 0.0) x - tables.norm_r else tables.norm_r - x;
}

/// A standard normal sample (rand_distr `StandardNormal` for `f64`).
pub fn standard(rng: anytype) f64 {
    var steps: u32 = 0;
    while (steps < max_steps) : (steps += 1) {
        const bits = rng.next_u64();
        const i: usize = @intCast(bits & 0xff);
        // A value in [2, 4) minus 3 gives [-1, 1).
        const u = into_float_with_exponent(bits >> 12, 1) - 3.0;
        assert(u >= -1.0 and u < 1.0);
        const x = u * tables.norm_x[i];
        if (@abs(x) < tables.norm_x[i + 1]) return x;
        if (i == 0) return zero_case(rng, u);
        const f = &tables.norm_f;
        if (f[i + 1] + (f[i] - f[i + 1]) * utils.rng.float64(rng) < pdf(x)) return x;
    }
    @panic("normal sampling did not converge");
}

/// Milliseconds in `duration` as Rust computes `as_secs_f64() * 1000.0`.
pub fn duration_ms(duration: utils.Duration) f64 {
    const secs: f64 = @floatFromInt(duration.secs);
    const nanos: f64 = @floatFromInt(duration.nanos);
    return (secs + nanos / 1e9) * 1000.0;
}

const testing = std.testing;

test "standard normal matches rand_distr 0.6.0 for StdRng seed 0" {
    // Reference values from Rust: rand 0.10.2 `StdRng::seed_from_u64(0)` and rand_distr 0.6.0.
    const first = [_]u64{
        4604595668361171954,  4605906381913375363,  13836040389191185562,
        4595053117438417687,  13831792991506982620, 4608475721966451724,
        13832722522527401750, 4603692983115048002,
    };
    var rng = utils.rng.TestRng.init(0);
    var tail: u32 = 0;
    var xor: u64 = 0;
    var sum: u64 = 0;
    for (0..100_000) |i| {
        const x = standard(&rng);
        const bits: u64 = @bitCast(x);
        if (i < first.len) try testing.expectEqual(first[i], bits);
        if (@abs(x) > tables.norm_r) tail += 1;
        xor ^= std.math.rotl(u64, bits, i % 64);
        sum +%= bits *% (@as(u64, i) + 1);
    }
    try testing.expectEqual(@as(u32, 29), tail);
    try testing.expectEqual(@as(u64, 0x1ccce39844157bfd), xor);
    try testing.expectEqual(@as(u64, 0x8e190af3f516d374), sum);
}

test "link latency samples match commonware's Normal over milliseconds" {
    // Rust: Normal::new(50ms, 40ms as f64 ms) sampled from StdRng seed 42, then `as u64`.
    const expected = [_]u64{ 52, 55, 60, 40, 23, 41, 57, 109, 0, 0, 123, 51, 33, 24, 50, 17 };
    const normal = try Normal.init(
        duration_ms(.from_millis(50)),
        duration_ms(.from_millis(40)),
    );
    var rng = utils.rng.TestRng.init(42);
    for (expected) |want| {
        const ms = normal.sample(&rng);
        const truncated: u64 = if (ms > 0) @intFromFloat(ms) else 0;
        try testing.expectEqual(want, truncated);
    }
}

test "zero deviation still draws from the rng" {
    var rng = utils.rng.TestRng.init(42);
    const normal = try Normal.init(5.0, 0.0);
    try testing.expectEqual(@as(f64, 5.0), normal.sample(&rng));
    try testing.expectEqual(@as(u64, 10011513049433592189), rng.next_u64());
    try testing.expectError(error.BadVariance, Normal.init(0, std.math.inf(f64)));
}
