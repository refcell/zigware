//! Exact rational numbers over `std.math.big.int` (the subset of `num_rational::BigRational`
//! and commonware's `BigRationalExt` that the bandwidth simulation needs).
//!
//! Values are always normalized: the denominator is positive and shares no factor with the
//! numerator, so equal values have equal representations, like `BigRational::new`. Every
//! operation returns a new value owned by the caller (`deinit`). Exact arithmetic keeps the
//! simulated transfer times identical to commonware's for the same inputs.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Int = std.math.big.int.Managed;

pub const Rational = struct {
    numerator: Int,
    denominator: Int,

    pub const Error = Allocator.Error;

    /// The integer `value`.
    pub fn init_int(gpa: Allocator, value: anytype) Error!Rational {
        var numerator = try Int.initSet(gpa, value);
        errdefer numerator.deinit();
        const denominator = try Int.initSet(gpa, 1);
        return .{ .numerator = numerator, .denominator = denominator };
    }

    /// `numerator / denominator`, normalized. Panics on a zero denominator, like Rust.
    pub fn init_frac(gpa: Allocator, numerator: anytype, denominator: anytype) Error!Rational {
        var n = try Int.initSet(gpa, numerator);
        errdefer n.deinit();
        var d = try Int.initSet(gpa, denominator);
        errdefer d.deinit();
        if (d.eqlZero()) @panic("denominator == 0");
        var result: Rational = .{ .numerator = n, .denominator = d };
        try result.normalize();
        return result;
    }

    pub fn deinit(self: *Rational) void {
        self.numerator.deinit();
        self.denominator.deinit();
        self.* = undefined;
    }

    /// A deep copy whose limbs come from `gpa`.
    pub fn clone(self: Rational, gpa: Allocator) Error!Rational {
        var n = try self.numerator.cloneWithDifferentAllocator(gpa);
        errdefer n.deinit();
        const d = try self.denominator.cloneWithDifferentAllocator(gpa);
        return .{ .numerator = n, .denominator = d };
    }

    pub fn is_zero(self: Rational) bool {
        assert(self.denominator.isPositive());
        return self.numerator.eqlZero();
    }

    pub fn order(a: Rational, b: Rational) Error!std.math.Order {
        const gpa = a.numerator.allocator;
        var left = try Int.init(gpa);
        defer left.deinit();
        var right = try Int.init(gpa);
        defer right.deinit();
        try left.mul(&a.numerator, &b.denominator);
        try right.mul(&b.numerator, &a.denominator);
        return left.order(right);
    }

    pub fn eql(a: Rational, b: Rational) bool {
        return a.numerator.order(b.numerator) == .eq and a.denominator.order(b.denominator) == .eq;
    }

    pub fn add(a: Rational, b: Rational) Error!Rational {
        return a.add_or_sub(b, false);
    }

    pub fn sub(a: Rational, b: Rational) Error!Rational {
        return a.add_or_sub(b, true);
    }

    fn add_or_sub(a: Rational, b: Rational, subtract: bool) Error!Rational {
        const gpa = a.numerator.allocator;
        var left = try Int.init(gpa);
        defer left.deinit();
        var right = try Int.init(gpa);
        defer right.deinit();
        try left.mul(&a.numerator, &b.denominator);
        try right.mul(&b.numerator, &a.denominator);
        var numerator = try Int.init(gpa);
        errdefer numerator.deinit();
        if (subtract) try numerator.sub(&left, &right) else try numerator.add(&left, &right);
        var denominator = try Int.init(gpa);
        errdefer denominator.deinit();
        try denominator.mul(&a.denominator, &b.denominator);
        var result: Rational = .{ .numerator = numerator, .denominator = denominator };
        try result.normalize();
        return result;
    }

    pub fn mul(a: Rational, b: Rational) Error!Rational {
        const gpa = a.numerator.allocator;
        var numerator = try Int.init(gpa);
        errdefer numerator.deinit();
        try numerator.mul(&a.numerator, &b.numerator);
        var denominator = try Int.init(gpa);
        errdefer denominator.deinit();
        try denominator.mul(&a.denominator, &b.denominator);
        var result: Rational = .{ .numerator = numerator, .denominator = denominator };
        try result.normalize();
        return result;
    }

    /// `a / b`. Panics when `b` is zero, like Rust.
    pub fn div(a: Rational, b: Rational) Error!Rational {
        if (b.is_zero()) @panic("division by zero");
        const gpa = a.numerator.allocator;
        var numerator = try Int.init(gpa);
        errdefer numerator.deinit();
        try numerator.mul(&a.numerator, &b.denominator);
        var denominator = try Int.init(gpa);
        errdefer denominator.deinit();
        try denominator.mul(&a.denominator, &b.numerator);
        if (!denominator.isPositive()) {
            numerator.negate();
            denominator.negate();
        }
        var result: Rational = .{ .numerator = numerator, .denominator = denominator };
        try result.normalize();
        return result;
    }

    /// The smallest integer at least `self`, saturating at `u128` max; zero for negative
    /// values (commonware `BigRationalExt::ceil_to_u128`).
    pub fn ceil_to_u128(self: Rational) Error!u128 {
        if (!self.numerator.isPositive() or self.numerator.eqlZero()) return 0;
        const gpa = self.numerator.allocator;
        var quotient = try Int.init(gpa);
        defer quotient.deinit();
        var remainder = try Int.init(gpa);
        defer remainder.deinit();
        try quotient.divTrunc(&remainder, &self.numerator, &self.denominator);
        var result = quotient.toInt(u128) catch std.math.maxInt(u128);
        if (!remainder.eqlZero()) result +|= 1;
        return result;
    }

    fn normalize(self: *Rational) Error!void {
        assert(!self.denominator.eqlZero());
        if (!self.denominator.isPositive()) {
            self.numerator.negate();
            self.denominator.negate();
        }
        if (self.numerator.eqlZero()) {
            try self.denominator.set(1);
            return;
        }
        const gpa = self.numerator.allocator;
        var divisor = try Int.init(gpa);
        defer divisor.deinit();
        var magnitude = try self.numerator.clone();
        defer magnitude.deinit();
        magnitude.abs();
        try divisor.gcd(&magnitude, &self.denominator);
        var remainder = try Int.init(gpa);
        defer remainder.deinit();
        try self.numerator.divTrunc(&remainder, &self.numerator, &divisor);
        try self.denominator.divTrunc(&remainder, &self.denominator, &divisor);
        assert(self.denominator.isPositive());
    }
};

const testing = std.testing;

fn expect_frac(value: Rational, numerator: i64, denominator: i64) !void {
    var expected = try Rational.init_frac(testing.allocator, numerator, denominator);
    defer expected.deinit();
    try testing.expect(value.eql(expected));
}

test "rational normalizes and computes exactly" {
    const gpa = testing.allocator;
    var a = try Rational.init_frac(gpa, 6, -4);
    defer a.deinit();
    try expect_frac(a, -3, 2);
    var b = try Rational.init_frac(gpa, 1, 3);
    defer b.deinit();
    var sum = try a.add(b);
    defer sum.deinit();
    try expect_frac(sum, -7, 6);
    var difference = try b.sub(b);
    defer difference.deinit();
    try testing.expect(difference.is_zero());
    try expect_frac(difference, 0, 1);
    var product = try a.mul(b);
    defer product.deinit();
    try expect_frac(product, -1, 2);
    var quotient = try b.div(a);
    defer quotient.deinit();
    try expect_frac(quotient, -2, 9);
    try testing.expectEqual(std.math.Order.lt, try a.order(b));
    try testing.expectEqual(std.math.Order.gt, try b.order(quotient));
}

test "rational ceil_to_u128" {
    const gpa = testing.allocator;
    const cases = [_]struct { i128, i128, u128 }{
        .{ 7, 2, 4 }, .{ 8, 2, 4 }, .{ 1, 3, 1 }, .{ 0, 5, 0 }, .{ -7, 2, 0 },
    };
    for (cases) |case| {
        var value = try Rational.init_frac(gpa, case[0], case[1]);
        defer value.deinit();
        try testing.expectEqual(case[2], try value.ceil_to_u128());
    }
    var huge = try Rational.init_int(gpa, @as(u256, std.math.maxInt(u128)) * 4);
    defer huge.deinit();
    try testing.expectEqual(@as(u128, std.math.maxInt(u128)), try huge.ceil_to_u128());
}
