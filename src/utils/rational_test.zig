//! Tests for `rational.BigRational` (commonware `utils/src/rational/mod.rs` and the
//! `utils/fuzz` rational target). The two `should_panic` tests (log2 of a negative value) are
//! assertions here and are not run.

const std = @import("std");
const rational = @import("rational.zig");
const fuzz = @import("fuzz.zig");
const rng = @import("rng.zig");
const BigRational = rational.BigRational;
const Int = rational.Int;

const testing = std.testing;
const gpa = testing.allocator;

/// `actual` equals `numerator / denominator` (reduced) and is freed.
fn expect_value(actual: BigRational, numerator: i128, denominator: i128) !void {
    var value = actual;
    defer value.deinit();
    var expected = try BigRational.from_frac(gpa, numerator, denominator);
    defer expected.deinit();
    if (!value.eql(&expected)) {
        std.debug.print("expected {d}/{d}, found {f}/{f}\n", .{
            numerator, denominator, value.numer, value.denom,
        });
        return error.TestExpectedEqual;
    }
}

/// `value` has exactly this numerator and denominator.
fn expect_parts(value: *const BigRational, numerator: anytype, denominator: anytype) !void {
    var numer = try Int.initSet(gpa, numerator);
    defer numer.deinit();
    var denom = try Int.initSet(gpa, denominator);
    defer denom.deinit();
    try testing.expect(value.numer.eql(numer));
    try testing.expect(value.denom.eql(denom));
}

const Log2 = enum { floor, ceil };

fn log2_of(
    numerator: i128,
    denominator: i128,
    digits: usize,
    comptime rounding: Log2,
) !BigRational {
    var value = try BigRational.from_frac(gpa, numerator, denominator);
    defer value.deinit();
    return switch (rounding) {
        .floor => value.log2_floor(digits),
        .ceil => value.log2_ceil(digits),
    };
}

fn expect_log2(
    comptime rounding: Log2,
    value: [2]i128,
    digits: usize,
    expected: [2]i128,
) !void {
    try expect_value(try log2_of(value[0], value[1], digits, rounding), expected[0], expected[1]);
}

test "rational: constructors reduce" {
    var a = try BigRational.from_u64(gpa, 42);
    defer a.deinit();
    try expect_parts(&a, 42, 1);
    var b = try BigRational.from_frac_u64(gpa, 6, 8);
    defer b.deinit();
    try expect_parts(&b, 3, 4);
    const big: u128 = @as(u128, std.math.maxInt(u64)) + 10;
    var c = try BigRational.from_u128(gpa, big);
    defer c.deinit();
    try expect_parts(&c, big, 1);
    var d = try BigRational.from_frac_u128(gpa, 10, 4);
    defer d.deinit();
    try expect_parts(&d, 5, 2);
    var e = try BigRational.from_usize(gpa, std.math.maxInt(usize));
    defer e.deinit();
    try expect_parts(&e, std.math.maxInt(usize), 1);
    var f = try BigRational.from_frac_usize(gpa, 48, 18);
    defer f.deinit();
    try expect_parts(&f, 8, 3);
    // Signs move to the numerator, and zero is 0/1.
    var g = try BigRational.from_frac(gpa, 6, -4);
    defer g.deinit();
    try expect_parts(&g, -3, 2);
    var h = try BigRational.from_frac(gpa, 0, -7);
    defer h.deinit();
    try expect_parts(&h, 0, 1);
}

test "rational: ceil_to_u128" {
    var half = try BigRational.from_frac(gpa, 5, 2);
    defer half.deinit();
    try testing.expectEqual(3, try half.ceil_to_u128());
    var negative = try BigRational.from_frac(gpa, -3, 2);
    defer negative.deinit();
    try testing.expectEqual(0, try negative.ceil_to_u128());
    var large = try BigRational.from_u128(gpa, std.math.maxInt(u128) - 1);
    defer large.deinit();
    try testing.expectEqual(std.math.maxInt(u128) - 1, try large.ceil_to_u128());
    // Saturates past u128.
    var huge = try BigRational.from_frac(gpa, std.math.maxInt(u128), 1);
    defer huge.deinit();
    var doubled = try huge.add(&huge);
    defer doubled.deinit();
    try testing.expectEqual(std.math.maxInt(u128), try doubled.ceil_to_u128());
}

test "rational: arithmetic and order" {
    var a = try BigRational.from_frac(gpa, 3, 4);
    defer a.deinit();
    var b = try BigRational.from_frac(gpa, -5, 6);
    defer b.deinit();
    try expect_value(try a.add(&b), -1, 12);
    try expect_value(try a.sub(&b), 19, 12);
    try expect_value(try a.mul(&b), -5, 8);
    try expect_value(try a.div(&b), -9, 10);
    try expect_value(try b.neg(), 5, 6);
    try expect_value(try b.pow(3), -125, 216);
    try expect_value(try b.pow(-2), 36, 25);
    try expect_value(try b.pow(-1), -6, 5);
    try expect_value(try a.pow(0), 1, 1);
    try testing.expectEqual(.gt, try a.order(&b));
    try testing.expectEqual(.lt, try b.order(&a));
    try testing.expectEqual(.eq, try a.order(&a));
    var seven_halves = try BigRational.from_frac(gpa, -7, 2);
    defer seven_halves.deinit();
    var truncated = try seven_halves.to_integer();
    defer truncated.deinit();
    try testing.expectEqual(-3, try truncated.toInt(i64));
    try testing.expect(seven_halves.is_negative() and !seven_halves.is_integer());
}

test "rational: log2_ceil of powers of two" {
    for ([_]i128{ 1, 2, 8, 1024 }, [_]i128{ 0, 1, 3, 10 }) |value, expected| {
        try expect_log2(.ceil, .{ value, 1 }, 4, .{ expected, 1 });
        try expect_log2(.floor, .{ value, 1 }, 4, .{ expected, 1 });
    }
    try expect_log2(.ceil, .{ 1, 2 }, 4, .{ -1, 1 });
    try expect_log2(.ceil, .{ 1, 4 }, 4, .{ -2, 1 });
    try expect_log2(.ceil, .{ 3, 8 }, 4, .{ -11, 8 });
    try expect_log2(.floor, .{ 1, 2 }, 4, .{ -1, 1 });
    try expect_log2(.floor, .{ 1, 4 }, 4, .{ -2, 1 });
    try expect_log2(.floor, .{ 3, 8 }, 4, .{ -23, 16 });
}

test "rational: log2_ceil values" {
    try expect_log2(.ceil, .{ 3, 1 }, 0, .{ 2, 1 });
    try expect_log2(.ceil, .{ 5, 1 }, 0, .{ 3, 1 });
    try expect_log2(.ceil, .{ 3, 1 }, 1, .{ 2, 1 });
    try expect_log2(.ceil, .{ 3, 1 }, 4, .{ 13, 8 });
    try expect_log2(.ceil, .{ 3, 1 }, 8, .{ 203, 128 });
    try expect_log2(.ceil, .{ 3, 2 }, 4, .{ 5, 8 });
    try expect_log2(.ceil, .{ 7, 4 }, 4, .{ 13, 16 });
    try expect_log2(.ceil, .{ 1000, 1 }, 4, .{ 10, 1 });
    try expect_log2(.ceil, .{ 1, 1000 }, 4, .{ -159, 16 });
}

test "rational: log2_ceil edge cases" {
    try expect_log2(.ceil, .{ 17, 16 }, 8, .{ 23, 256 });
    try expect_log2(.ceil, .{ 129, 128 }, 8, .{ 3, 256 });
    try expect_log2(.ceil, .{ 33, 32 }, 10, .{ 46, 1024 });
    try expect_log2(.ceil, .{ 255, 256 }, 8, .{ -1, 256 });
    try expect_log2(.ceil, .{ 1023, 1024 }, 9, .{ 0, 512 });
    try expect_log2(.ceil, .{ 3, 2 }, 0, .{ 1, 1 });
    try expect_log2(.ceil, .{ 3, 4 }, 0, .{ 0, 1 });
    try expect_log2(.ceil, .{ 3, 4 }, 4, .{ -6, 16 });
    try expect_log2(.ceil, .{ 257, 256 }, 8, .{ 2, 256 });
    try expect_log2(.ceil, .{ 257, 256 }, 9, .{ 3, 512 });
    try expect_log2(.ceil, .{ 17 << 30, 16 << 30 }, 8, .{ 23, 256 });
}

test "rational: log2_floor values" {
    try expect_log2(.floor, .{ 3, 1 }, 0, .{ 1, 1 });
    try expect_log2(.floor, .{ 5, 1 }, 0, .{ 2, 1 });
    try expect_log2(.floor, .{ 3, 1 }, 1, .{ 3, 2 });
    try expect_log2(.floor, .{ 3, 1 }, 4, .{ 25, 16 });
    try expect_log2(.floor, .{ 3, 1 }, 8, .{ 405, 256 });
    try expect_log2(.floor, .{ 3, 2 }, 4, .{ 9, 16 });
    try expect_log2(.floor, .{ 7, 4 }, 4, .{ 12, 16 });
    try expect_log2(.floor, .{ 1000, 1 }, 4, .{ 159, 16 });
    try expect_log2(.floor, .{ 1, 1000 }, 4, .{ -160, 16 });
}

test "rational: log2_floor edge cases" {
    try expect_log2(.floor, .{ 17, 16 }, 8, .{ 22, 256 });
    try expect_log2(.floor, .{ 129, 128 }, 8, .{ 2, 256 });
    try expect_log2(.floor, .{ 33, 32 }, 10, .{ 45, 1024 });
    try expect_log2(.floor, .{ 255, 256 }, 8, .{ -2, 256 });
    try expect_log2(.floor, .{ 1023, 1024 }, 9, .{ -1, 512 });
    try expect_log2(.floor, .{ 3, 2 }, 0, .{ 0, 1 });
    try expect_log2(.floor, .{ 3, 4 }, 0, .{ -1, 1 });
    try expect_log2(.floor, .{ 3, 4 }, 4, .{ -7, 16 });
    try expect_log2(.floor, .{ 257, 256 }, 8, .{ 1, 256 });
    try expect_log2(.floor, .{ 257, 256 }, 9, .{ 2, 512 });
    try expect_log2(.floor, .{ 17 << 30, 16 << 30 }, 8, .{ 22, 256 });
}

test "rational: log2 floor is below ceil except at powers of two" {
    const others = [_][2]i128{ .{ 3, 1 }, .{ 5, 1 }, .{ 3, 2 }, .{ 7, 8 }, .{ 1, 3 } };
    const powers = [_][2]i128{ .{ 1, 1 }, .{ 2, 1 }, .{ 4, 1 }, .{ 1, 2 }, .{ 1, 4 } };
    for (others ++ powers, 0..) |value, index| {
        var floor = try log2_of(value[0], value[1], 8, .floor);
        defer floor.deinit();
        var ceil = try log2_of(value[0], value[1], 8, .ceil);
        defer ceil.deinit();
        const expected: std.math.Order = if (index < others.len) .lt else .eq;
        try testing.expectEqual(expected, try floor.order(&ceil));
    }
}

/// Checks `2^N * q^M <= p^M < 2^(N+1) * q^M` for `M = 2^k`, the definition of
/// `floor(log2(p / q) * 2^k) = N`, independently of the square-and-compare method.
fn check_log2_floor(p: u64, q: u64, k: u6, floor_numerator: *const Int) !void {
    const n = try floor_numerator.toInt(i64);
    const power: u32 = @as(u32, 1) << @intCast(k);
    var p_power = try Int.initSet(gpa, p);
    defer p_power.deinit();
    try p_power.pow(&p_power, power);
    var q_power = try Int.initSet(gpa, q);
    defer q_power.deinit();
    try q_power.pow(&q_power, power);
    // Bring 2^N (and 2^(N+1)) to whichever side keeps the shifts non-negative.
    var low = try Int.init(gpa);
    defer low.deinit();
    var high = try Int.init(gpa);
    defer high.deinit();
    if (n >= 0) {
        try low.shiftLeft(&q_power, @intCast(n));
        try high.shiftLeft(&q_power, @intCast(n + 1));
        try testing.expect(low.order(p_power) != .gt);
        try testing.expect(p_power.order(high) == .lt);
    } else {
        try low.shiftLeft(&p_power, @intCast(-n));
        try high.shiftLeft(&p_power, @intCast(-(n + 1)));
        try testing.expect(q_power.order(low) != .gt);
        try testing.expect(high.order(q_power) == .lt);
    }
}

/// Fuzz (commonware utils/fuzz rational.rs): constructors, `ceil_to_u128` against i128
/// arithmetic, and `log2_floor`/`log2_ceil` against the defining bounds.
fn fuzz_rational(_: void, generator: *rng.FuzzRng) !void {
    const numerator: i64 = @bitCast(generator.next_u64());
    const denominator = generator.next_u64() | 1;
    var value = try BigRational.from_frac(gpa, numerator, denominator);
    defer value.deinit();
    const ceil: i128 = std.math.divCeil(i128, numerator, denominator) catch unreachable;
    try testing.expectEqual(@as(u128, @intCast(@max(ceil, 0))), try value.ceil_to_u128());
    var denominator_value = try BigRational.from_integer(gpa, denominator);
    defer denominator_value.deinit();
    var numerator_value = try BigRational.from_integer(gpa, numerator);
    defer numerator_value.deinit();
    var back = try value.mul(&denominator_value);
    defer back.deinit();
    try testing.expect(back.eql(&numerator_value));

    const p = rng.range_at_most(generator, u64, 1, 255);
    const q = rng.range_at_most(generator, u64, 1, 255);
    const k = rng.range_at_most(generator, u6, 0, 6);
    var floor = try log2_of(p, q, k, .floor);
    defer floor.deinit();
    var ceil_log = try log2_of(p, q, k, .ceil);
    defer ceil_log.deinit();
    // Both are N / 2^k; recover N from the reduced form.
    var scale = try BigRational.from_integer(gpa, @as(u64, 1) << k);
    defer scale.deinit();
    var floor_scaled = try floor.mul(&scale);
    defer floor_scaled.deinit();
    try testing.expect(floor_scaled.is_integer());
    try check_log2_floor(p, q, k, &floor_scaled.numer);
    var ceil_scaled = try ceil_log.mul(&scale);
    defer ceil_scaled.deinit();
    var step = try ceil_scaled.sub(&floor_scaled);
    defer step.deinit();
    // ceil = floor exactly when p / q is a power of two.
    const ratio_power_of_two = (p / q) * q == p and std.math.isPowerOfTwo(p / q) or
        (q / p) * p == q and std.math.isPowerOfTwo(q / p);
    try expect_parts(&step, @intFromBool(!ratio_power_of_two), 1);
}

test "fuzz rational" {
    try fuzz.run({}, fuzz_rational, 0x7261_7469, 300);
}
