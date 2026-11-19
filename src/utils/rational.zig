//! Exact rational numbers over big integers (commonware `utils/src/rational`, which extends
//! `num_rational::BigRational` with `BigRationalExt`).
//!
//! `BigRational` keeps `num_rational`'s canonical form: the numerator and denominator are
//! coprime and the denominator is positive, so equal values have equal representations. Both
//! halves are `std.math.big.int.Managed`; every operation allocates its result with the
//! allocator of its first operand, and the caller frees it with `deinit`.
//!
//! `log2_floor` / `log2_ceil` round log2 to `binary_digits` fractional bits with commonware's
//! exact square-and-compare method (no floating point), so results match bit for bit.
//! Where Rust panics (a zero denominator, log2 of a non-positive value), Zig asserts.

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

/// An arbitrary-precision signed integer.
pub const Int = std.math.big.int.Managed;

pub const BigRational = struct {
    /// Signed; coprime with `denom`.
    numer: Int,
    /// Positive.
    denom: Int,

    /// `numerator / denominator`, reduced. Takes ownership of both, also on error.
    /// Asserts the denominator is not zero (Rust `Ratio::new` panics).
    pub fn from_ints(numerator: Int, denominator: Int) Allocator.Error!BigRational {
        var result: BigRational = .{ .numer = numerator, .denom = denominator };
        result.reduce() catch |err| {
            result.deinit();
            return err;
        };
        return result;
    }

    /// `numerator / denominator` for any integers, reduced. Asserts `denominator != 0`.
    pub fn from_frac(
        gpa: Allocator,
        numerator: anytype,
        denominator: anytype,
    ) Allocator.Error!BigRational {
        var numer = try Int.initSet(gpa, numerator);
        const denom = Int.initSet(gpa, denominator) catch |err| {
            numer.deinit();
            return err;
        };
        return from_ints(numer, denom);
    }

    /// `value / 1` (Rust `from_integer`).
    pub fn from_integer(gpa: Allocator, value: anytype) Allocator.Error!BigRational {
        return from_frac(gpa, value, 1);
    }

    pub fn from_u64(gpa: Allocator, value: u64) Allocator.Error!BigRational {
        return from_integer(gpa, value);
    }

    pub fn from_frac_u64(gpa: Allocator, numerator: u64, denominator: u64) !BigRational {
        return from_frac(gpa, numerator, denominator);
    }

    pub fn from_u128(gpa: Allocator, value: u128) Allocator.Error!BigRational {
        return from_integer(gpa, value);
    }

    pub fn from_frac_u128(gpa: Allocator, numerator: u128, denominator: u128) !BigRational {
        return from_frac(gpa, numerator, denominator);
    }

    pub fn from_usize(gpa: Allocator, value: usize) Allocator.Error!BigRational {
        return from_integer(gpa, value);
    }

    pub fn from_frac_usize(gpa: Allocator, numerator: usize, denominator: usize) !BigRational {
        return from_frac(gpa, numerator, denominator);
    }

    pub fn zero(gpa: Allocator) Allocator.Error!BigRational {
        return from_integer(gpa, 0);
    }

    pub fn one(gpa: Allocator) Allocator.Error!BigRational {
        return from_integer(gpa, 1);
    }

    pub fn deinit(self: *BigRational) void {
        self.numer.deinit();
        self.denom.deinit();
        self.* = undefined;
    }

    pub fn clone(self: *const BigRational) Allocator.Error!BigRational {
        var numer = try self.numer.clone();
        const denom = self.denom.clone() catch |err| {
            numer.deinit();
            return err;
        };
        return .{ .numer = numer, .denom = denom };
    }

    fn allocator(self: *const BigRational) Allocator {
        return self.numer.allocator;
    }

    /// Divides out the gcd and makes the denominator positive.
    fn reduce(self: *BigRational) Allocator.Error!void {
        assert(!self.denom.eqlZero()); // Rust: "denominator == 0".
        if (self.numer.eqlZero()) {
            try self.denom.set(1);
            return;
        }
        const gpa = self.allocator();
        var divisor = try Int.init(gpa);
        defer divisor.deinit();
        try divisor.gcd(&self.numer, &self.denom);
        if (divisor.toConst().orderAgainstScalar(1) != .eq) {
            var quotient = try Int.init(gpa);
            defer quotient.deinit();
            var remainder = try Int.init(gpa);
            defer remainder.deinit();
            try quotient.divTrunc(&remainder, &self.numer, &divisor);
            assert(remainder.eqlZero());
            self.numer.swap(&quotient);
            try quotient.divTrunc(&remainder, &self.denom, &divisor);
            assert(remainder.eqlZero());
            self.denom.swap(&quotient);
        }
        if (!self.denom.isPositive()) {
            self.numer.negate();
            self.denom.negate();
        }
        assert(self.denom.isPositive() and !self.denom.eqlZero());
    }

    pub fn is_zero(self: *const BigRational) bool {
        return self.numer.eqlZero();
    }

    pub fn is_negative(self: *const BigRational) bool {
        return !self.numer.isPositive() and !self.numer.eqlZero();
    }

    pub fn is_positive(self: *const BigRational) bool {
        return self.numer.isPositive() and !self.numer.eqlZero();
    }

    /// Equal values (canonical forms make this exact).
    pub fn eql(a: *const BigRational, b: *const BigRational) bool {
        return a.numer.eql(b.numer) and a.denom.eql(b.denom);
    }

    /// Orders `a` against `b` by cross-multiplying (denominators are positive).
    pub fn order(a: *const BigRational, b: *const BigRational) Allocator.Error!std.math.Order {
        const gpa = a.allocator();
        var left = try product(gpa, &a.numer, &b.denom);
        defer left.deinit();
        var right = try product(gpa, &b.numer, &a.denom);
        defer right.deinit();
        return left.order(right);
    }

    pub fn add(a: *const BigRational, b: *const BigRational) Allocator.Error!BigRational {
        return sum(a, b, .add);
    }

    pub fn sub(a: *const BigRational, b: *const BigRational) Allocator.Error!BigRational {
        return sum(a, b, .sub);
    }

    fn sum(
        a: *const BigRational,
        b: *const BigRational,
        comptime operation: enum { add, sub },
    ) Allocator.Error!BigRational {
        const gpa = a.allocator();
        var left = try product(gpa, &a.numer, &b.denom);
        defer left.deinit();
        var right = try product(gpa, &b.numer, &a.denom);
        defer right.deinit();
        var numer = try Int.init(gpa);
        const combined = switch (operation) {
            .add => numer.add(&left, &right),
            .sub => numer.sub(&left, &right),
        };
        combined catch |err| {
            numer.deinit();
            return err;
        };
        const denom = product(gpa, &a.denom, &b.denom) catch |err| {
            numer.deinit();
            return err;
        };
        return from_ints(numer, denom);
    }

    pub fn mul(a: *const BigRational, b: *const BigRational) Allocator.Error!BigRational {
        const gpa = a.allocator();
        var numer = try product(gpa, &a.numer, &b.numer);
        const denom = product(gpa, &a.denom, &b.denom) catch |err| {
            numer.deinit();
            return err;
        };
        return from_ints(numer, denom);
    }

    /// `a / b`. Asserts `b` is not zero.
    pub fn div(a: *const BigRational, b: *const BigRational) Allocator.Error!BigRational {
        assert(!b.is_zero());
        const gpa = a.allocator();
        var numer = try product(gpa, &a.numer, &b.denom);
        const denom = product(gpa, &a.denom, &b.numer) catch |err| {
            numer.deinit();
            return err;
        };
        return from_ints(numer, denom);
    }

    /// `-self`.
    pub fn neg(self: *const BigRational) Allocator.Error!BigRational {
        var result = try self.clone();
        result.numer.negate();
        return result;
    }

    /// `self^exponent` (Rust `Ratio::pow`). A negative exponent asserts `self != 0`.
    pub fn pow(self: *const BigRational, exponent: i32) Allocator.Error!BigRational {
        const gpa = self.allocator();
        const magnitude: u32 = @abs(exponent);
        var numer = try Int.init(gpa);
        errdefer numer.deinit();
        try numer.pow(&self.numer, magnitude);
        var denom = try Int.init(gpa);
        errdefer denom.deinit();
        try denom.pow(&self.denom, magnitude);
        if (exponent < 0) {
            assert(!self.is_zero());
            numer.swap(&denom);
            if (!denom.isPositive()) {
                numer.negate();
                denom.negate();
            }
        }
        // Powers of coprime integers stay coprime.
        assert(denom.isPositive() and !denom.eqlZero());
        return .{ .numer = numer, .denom = denom };
    }

    /// The integer part, rounded toward zero (Rust `to_integer`).
    pub fn to_integer(self: *const BigRational) Allocator.Error!Int {
        const gpa = self.allocator();
        var quotient = try Int.init(gpa);
        errdefer quotient.deinit();
        var remainder = try Int.init(gpa);
        defer remainder.deinit();
        try quotient.divTrunc(&remainder, &self.numer, &self.denom);
        return quotient;
    }

    /// The ceiling as a `u128`, saturating, with negative values as zero. Rust returns
    /// `Option<u128>`, `None` only for a zero denominator, which this type rules out.
    pub fn ceil_to_u128(self: *const BigRational) Allocator.Error!u128 {
        if (self.is_negative()) return 0;
        var quotient = try self.to_integer();
        defer quotient.deinit();
        var result = quotient.toInt(u128) catch std.math.maxInt(u128);
        // The value is non-negative, so a remainder means the truncation rounded down.
        if (!self.is_integer()) result +|= 1;
        return result;
    }

    pub fn is_integer(self: *const BigRational) bool {
        return self.denom.toConst().orderAgainstScalar(1) == .eq;
    }

    /// log2 rounded up to a multiple of `2^-binary_digits`. Asserts `self > 0`.
    pub fn log2_ceil(self: *const BigRational, binary_digits: usize) Allocator.Error!BigRational {
        return self.log2_rounded(binary_digits, .ceil);
    }

    /// log2 rounded down to a multiple of `2^-binary_digits`. Asserts `self > 0`.
    pub fn log2_floor(self: *const BigRational, binary_digits: usize) Allocator.Error!BigRational {
        return self.log2_rounded(binary_digits, .floor);
    }

    fn log2_rounded(
        self: *const BigRational,
        binary_digits: usize,
        comptime rounding: enum { floor, ceil },
    ) Allocator.Error!BigRational {
        assert(self.is_positive()); // Rust: "log2 undefined for non-positive numbers".
        const gpa = self.allocator();
        var result = try log2(gpa, &self.numer, &self.denom, binary_digits);
        errdefer result.numerator.deinit();
        if (rounding == .ceil and result.has_remainder) {
            try result.numerator.addScalar(&result.numerator, 1);
        }
        return from_dyadic(result.numerator, binary_digits);
    }

    /// `numerator / 2^binary_digits`, reduced. Takes ownership of `numerator`, also on error.
    /// The gcd with a power of two is the numerator's trailing zero count, so this needs no
    /// gcd or division (`Ratio::new` reduces the same value to the same result).
    fn from_dyadic(numerator: Int, binary_digits: usize) Allocator.Error!BigRational {
        var numer = numerator;
        errdefer numer.deinit();
        // Zero counts `binary_digits` trailing zeros, which reduces it to 0/1.
        const shift: usize = numer.toConst().ctz(@intCast(binary_digits));
        assert(shift <= binary_digits);
        try numer.shiftRight(&numer, shift);
        var denom = try Int.initSet(numer.allocator, 1);
        errdefer denom.deinit();
        try denom.shiftLeft(&denom, binary_digits - shift);
        const result: BigRational = .{ .numer = numer, .denom = denom };
        assert(result.denom.isPositive() and !result.denom.eqlZero());
        return result;
    }
};

/// `x * y` in a new integer.
fn product(gpa: Allocator, x: *const Int, y: *const Int) Allocator.Error!Int {
    var result = try Int.init(gpa);
    errdefer result.deinit();
    try result.mul(x, y);
    return result;
}

const Log2 = struct {
    /// log2 is `numerator / 2^binary_digits`, rounded down.
    numerator: Int,
    /// Whether log2 has more precision than the digits computed.
    has_remainder: bool,
};

/// log2(numer / denom) to `binary_digits` fractional bits (commonware `log2`): normalize the
/// ratio into [1, 2), then square it once per digit, emitting a 1 whenever it reaches 2.
fn log2(gpa: Allocator, numer: *const Int, denom: *const Int, binary_digits: usize) !Log2 {
    assert(numer.isPositive() and !numer.eqlZero());
    assert(denom.isPositive() and !denom.eqlZero());
    if (log2_native(numer, denom, binary_digits)) |native| {
        const numerator = try Int.initSet(gpa, native.numerator);
        return .{ .numerator = numerator, .has_remainder = native.has_remainder };
    }
    const numer_bits = numer.bitCountAbs();
    const denom_bits = denom.bitCountAbs();
    var integer_part: i128 = @as(i128, numer_bits) - @as(i128, denom_bits);

    // Align the most significant bits, bringing the ratio into [1/2, 2).
    var normalized_numer = try numer.clone();
    defer normalized_numer.deinit();
    var normalized_denom = try denom.clone();
    defer normalized_denom.deinit();
    if (denom_bits > numer_bits) {
        try normalized_numer.shiftLeft(&normalized_numer, denom_bits - numer_bits);
    }
    if (numer_bits > denom_bits) {
        try normalized_denom.shiftLeft(&normalized_denom, numer_bits - denom_bits);
    }
    if (normalized_numer.order(normalized_denom) == .lt) {
        try normalized_numer.shiftLeft(&normalized_numer, 1);
        integer_part -= 1;
    }

    var numerator = try Int.initSet(gpa, integer_part);
    errdefer numerator.deinit();
    try numerator.shiftLeft(&numerator, binary_digits);
    // An exact power of two has no fractional part.
    if (normalized_numer.eql(normalized_denom)) {
        return .{ .numerator = numerator, .has_remainder = false };
    }

    if (try log2_digits_interval(gpa, &normalized_numer, &normalized_denom, binary_digits)) |bits| {
        // The ratio is in (1, 2) and never squares to exactly a power of two (it is not one),
        // so the exact loop below would end with a remainder.
        var fractional = try Int.initSet(gpa, bits);
        defer fractional.deinit();
        try numerator.add(&numerator, &fractional);
        return .{ .numerator = numerator, .has_remainder = true };
    }

    var fractional_bits = try Int.initSet(gpa, 0);
    defer fractional_bits.deinit();
    var numer_squared = try Int.init(gpa);
    defer numer_squared.deinit();
    var denom_squared = try Int.init(gpa);
    defer denom_squared.deinit();
    for (0..binary_digits) |_| {
        // `mul(x, x)` rather than `sqr(x)`: std's `sqr` is schoolbook only, while `mul` uses
        // Karatsuba, about 4x faster on the ~300k-bit squares of the bloom filter's rates.
        try numer_squared.mul(&normalized_numer, &normalized_numer);
        try denom_squared.mul(&normalized_denom, &normalized_denom);
        try fractional_bits.shiftLeft(&fractional_bits, 1);
        // If the square is at least 2, the digit is 1: halve it (double the denominator).
        try denom_squared.shiftLeft(&denom_squared, 1);
        if (numer_squared.order(denom_squared) != .lt) {
            try fractional_bits.addScalar(&fractional_bits, 1);
        } else {
            try denom_squared.shiftRight(&denom_squared, 1);
        }
        normalized_numer.swap(&numer_squared);
        normalized_denom.swap(&denom_squared);
    }
    try numerator.add(&numerator, &fractional_bits);
    const has_remainder = normalized_numer.order(normalized_denom) == .gt;
    return .{ .numerator = numerator, .has_remainder = has_remainder };
}

/// Fixed-point fractional bits of the interval `interval_digits` squares.
const interval_precision = 120;

/// `log2` without allocating, for a ratio whose terms fit in 64 bits and at most 64 digits
/// (every small rate, such as the benches' 1/2 through 1023/1024). Null when the interval
/// cannot decide a digit or the terms are too wide; `log2` then takes the exact path.
fn log2_native(
    numer: *const Int,
    denom: *const Int,
    binary_digits: usize,
) ?struct { numerator: i128, has_remainder: bool } {
    if (binary_digits > 64) return null;
    var normalized_numer: u128 = numer.toInt(u64) catch return null;
    var normalized_denom: u128 = denom.toInt(u64) catch return null;
    assert(normalized_numer > 0 and normalized_denom > 0);
    const numer_bits: u8 = 128 - @clz(normalized_numer);
    const denom_bits: u8 = 128 - @clz(normalized_denom);
    var integer_part: i128 = @as(i128, numer_bits) - @as(i128, denom_bits);
    if (denom_bits > numer_bits) normalized_numer <<= @intCast(denom_bits - numer_bits);
    if (numer_bits > denom_bits) normalized_denom <<= @intCast(numer_bits - denom_bits);
    if (normalized_numer < normalized_denom) {
        normalized_numer <<= 1;
        integer_part -= 1;
    }
    // |integer_part| <= 64 and 64 digits: the numerator stays below 2^71.
    const whole = integer_part << @intCast(binary_digits);
    if (normalized_numer == normalized_denom) {
        return .{ .numerator = whole, .has_remainder = false };
    }
    assert(normalized_numer > normalized_denom and normalized_numer < normalized_denom << 1);
    // numer / denom = 1 + rest / denom with rest < denom < 2^64. Two 60-bit long-division
    // steps give floor(2^120 numer / denom) in u128 divisions (a u256 division costs ~400 ns).
    comptime assert(interval_precision == 120);
    const rest = normalized_numer - normalized_denom;
    const upper = (rest << 60) / normalized_denom;
    const upper_rest = (rest << 60) % normalized_denom;
    const lower = (upper_rest << 60) / normalized_denom;
    const exact = (upper_rest << 60) % normalized_denom == 0;
    const one: u256 = 1 << interval_precision;
    const low = one + (@as(u256, upper) << 60) + lower;
    const bits = interval_digits(low, low + @intFromBool(!exact), binary_digits) orelse
        return null;
    return .{ .numerator = whole + bits, .has_remainder = true };
}

/// The first `binary_digits` (at most 64) binary digits of log2(numer / denom) for a ratio in
/// (1, 2), from the same square-and-compare as `log2` over a fixed-point interval that holds
/// the exact value: each digit is taken only when the whole interval lies on one side of 2, so
/// the digits equal the exact loop's. Null when the interval straddles 2, which only the exact
/// squaring can decide. The exact squares reach about 2^digits times the ratio's bits (about
/// 900k bits for 1/10000 at 16 digits); this stays within 256 bits.
fn log2_digits_interval(
    gpa: Allocator,
    numer: *const Int,
    denom: *const Int,
    binary_digits: usize,
) Allocator.Error!?u64 {
    assert(numer.order(denom.*) == .gt);
    if (binary_digits > 64) return null;
    var shifted = try numer.clone();
    defer shifted.deinit();
    try shifted.shiftLeft(&shifted, interval_precision);
    var quotient = try Int.init(gpa);
    defer quotient.deinit();
    var remainder = try Int.init(gpa);
    defer remainder.deinit();
    try quotient.divFloor(&remainder, &shifted, denom);
    // Proof: numer / denom < 2, so the quotient is below 2^(interval_precision + 1).
    const low = quotient.toInt(u256) catch unreachable;
    return interval_digits(low, low + @intFromBool(!remainder.eqlZero()), binary_digits);
}

/// Squares the fixed-point bounds `[low, high]` of a ratio in (1, 2) once per digit; see
/// `log2_digits_interval`.
fn interval_digits(low_start: u256, high_start: u256, binary_digits: usize) ?u64 {
    const one: u256 = 1 << interval_precision;
    const two: u256 = one << 1;
    var low = low_start;
    var high = high_start;
    assert(binary_digits <= 64);
    assert(low >= one and high <= two);
    var digits: u64 = 0;
    for (0..binary_digits) |_| {
        // Both bounds stay below 2^(interval_precision + 2), so their squares fit in u256.
        low = (low * low) >> interval_precision;
        high = (high * high + one - 1) >> interval_precision;
        digits <<= 1;
        if (low >= two) {
            digits |= 1;
            low >>= 1;
            high = (high + 1) >> 1;
        } else if (high >= two) {
            return null;
        }
        assert(low <= high);
    }
    return digits;
}

test {
    _ = @import("rational_test.zig");
}

const death = @import("death.zig");

test "rational: log2_ceil of a negative number panics" {
    // commonware `rational/mod.rs log2_ceil_negative_panics` (#[should_panic]).
    try death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            var value = try BigRational.from_integer(std.testing.allocator, @as(i64, -1));
            defer value.deinit();
            var result = try value.log2_ceil(8);
            result.deinit();
        }
    }.body);
}

test "rational: log2_floor of a negative number panics" {
    // commonware `rational/mod.rs log2_floor_negative_panics` (#[should_panic]).
    try death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            var value = try BigRational.from_integer(std.testing.allocator, @as(i64, -1));
            defer value.deinit();
            var result = try value.log2_floor(8);
            result.deinit();
        }
    }.body);
}
