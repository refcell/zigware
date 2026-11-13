//! Algebraic interfaces (commonware `math::algebra`).
//!
//! Rust traits become comptime interfaces: an algebraic type is a value type with these
//! declarations, checked by the `assert_*` functions below.
//!
//! - Additive: `zero: T`, `add(T, T) T`, `sub(T, T) T`, `neg(T) T`, `eql(T, T) bool`, and
//!   optionally a faster `double(T) T`.
//! - Multiplicative: `mul(T, T) T`, optionally a faster `square(T) T`.
//! - Ring: Additive, Multiplicative, and `one: T`.
//! - Field: Ring and `inv(T) T`, with `inv(zero) == zero`.
//! - FieldNTT: Field, `max_lg_root_order: u8`, `root_of_unity(u8) ?T`, `coset_shift() T`,
//!   optionally `coset_shift_inv() T` and `div_2(T) T`.
//! - Space(R): Additive and `mul(T, R) T` (a right R-module), optionally
//!   `msm([]const T, []const R) T`. Every Ring is a Space over itself.
//! - CryptoGroup: Space(Scalar) with `Scalar: type` (a Field) and `generator: T`.
//! - HashToGroup: CryptoGroup and `hash_to_group(dst, message) T`.
//! - Random: `random(std.Random) T`.
//!
//! The free functions (`exp`, `scale`, `double`, `msm`, ...) supply the trait defaults.

const std = @import("std");
const assert = std.debug.assert;
const fuzz = @import("fuzz.zig");
const Unstructured = fuzz.Unstructured;

pub fn assert_additive(comptime T: type) void {
    comptime {
        assert(@hasDecl(T, "zero"));
        assert(@hasDecl(T, "add") and @hasDecl(T, "sub") and @hasDecl(T, "neg"));
        assert(@hasDecl(T, "eql"));
    }
}

pub fn assert_multiplicative(comptime T: type) void {
    comptime assert(@hasDecl(T, "mul"));
}

pub fn assert_ring(comptime T: type) void {
    assert_additive(T);
    assert_multiplicative(T);
    comptime assert(@hasDecl(T, "one"));
}

pub fn assert_field(comptime T: type) void {
    assert_ring(T);
    comptime assert(@hasDecl(T, "inv"));
}

pub fn assert_field_ntt(comptime T: type) void {
    assert_field(T);
    comptime {
        assert(@hasDecl(T, "max_lg_root_order"));
        assert(@hasDecl(T, "root_of_unity") and @hasDecl(T, "coset_shift"));
    }
}

pub fn assert_space(comptime K: type, comptime R: type) void {
    assert_additive(K);
    comptime assert(@hasDecl(K, "mul"));
    _ = R;
}

pub fn assert_crypto_group(comptime G: type) void {
    comptime assert(@hasDecl(G, "Scalar") and @hasDecl(G, "generator"));
    assert_space(G, G.Scalar);
    assert_field(G.Scalar);
}

/// `x + x`, using `T.double` when available.
pub inline fn double(comptime T: type, x: T) T {
    if (@hasDecl(T, "double")) return x.double();
    return x.add(x);
}

/// `x * x`, using `T.square` when available.
pub inline fn square(comptime T: type, x: T) T {
    if (@hasDecl(T, "square")) return x.square();
    return x.mul(x);
}

/// Bits of a little-endian limb array: every bit of each limb but the last, then the last
/// limb's bits up to its highest set bit.
fn bit_count(bits_le: []const u64) u32 {
    if (bits_le.len == 0) return 0;
    const last = bits_le[bits_le.len - 1];
    const count: u32 = @intCast(64 * (bits_le.len - 1) + (64 - @clz(last)));
    assert(count <= 64 * bits_le.len);
    return count;
}

fn bit_at(bits_le: []const u64, position: u32) bool {
    assert(position / 64 < bits_le.len);
    return (bits_le[position / 64] >> @intCast(position % 64)) & 1 == 1;
}

/// Scale `x` by the positive integer given as 64-bit little-endian limbs
/// (`Additive::scale`, double-and-add).
pub fn scale(comptime T: type, x: T, bits_le: []const u64) T {
    assert_additive(T);
    var accumulator = T.zero;
    var power = x;
    const count = bit_count(bits_le);
    var position: u32 = 0;
    while (position < count) : (position += 1) {
        if (bit_at(bits_le, position)) accumulator = accumulator.add(power);
        power = double(T, power);
    }
    assert(position == count);
    return accumulator;
}

/// Raise `x` to the positive integer given as 64-bit little-endian limbs
/// (`Ring::exp`, square-and-multiply).
pub fn exp(comptime T: type, x: T, bits_le: []const u64) T {
    assert_ring(T);
    var accumulator = T.one;
    var power = x;
    const count = bit_count(bits_le);
    var position: u32 = 0;
    while (position < count) : (position += 1) {
        if (bit_at(bits_le, position)) accumulator = accumulator.mul(power);
        power = square(T, power);
    }
    assert(position == count);
    return accumulator;
}

/// Iterator over `shift, shift * base, shift * base^2, ...` (`algebra::powers`).
pub fn Powers(comptime R: type) type {
    return struct {
        state: R,
        base: R,

        pub fn next(self: *@This()) R {
            const out = self.state;
            self.state = self.state.mul(self.base);
            return out;
        }
    };
}

pub fn powers(comptime R: type, shift: R, base: R) Powers(R) {
    assert_ring(R);
    return .{ .state = shift, .base = base };
}

/// `sum_i points[i] * scalars[i]`, treating the shorter slice as zero-padded.
pub fn msm_naive(comptime K: type, comptime R: type, points: []const K, scalars: []const R) K {
    assert_space(K, R);
    var out = K.zero;
    const count = @min(points.len, scalars.len);
    for (points[0..count], scalars[0..count]) |point, scalar| {
        out = out.add(point.mul(scalar));
    }
    return out;
}

/// `Space::msm`: `K.msm` when the type provides a faster algorithm, else `msm_naive`.
pub fn msm(comptime K: type, comptime R: type, points: []const K, scalars: []const R) K {
    assert_space(K, R);
    if (@hasDecl(K, "msm")) return K.msm(points, scalars);
    return msm_naive(K, R, points, scalars);
}

pub fn coset_shift_inv(comptime T: type) T {
    assert_field_ntt(T);
    if (@hasDecl(T, "coset_shift_inv")) return T.coset_shift_inv();
    return T.coset_shift().inv();
}

/// `x / 2`, using `T.div_2` when available.
pub fn div_2(comptime T: type, x: T) T {
    assert_field_ntt(T);
    if (@hasDecl(T, "div_2")) return x.div_2();
    return T.one.add(T.one).inv().mul(x);
}

/// `HashToGroup::rand_to_group`: 32 random bytes hashed with an empty domain separator.
pub fn rand_to_group(comptime G: type, random: std.Random) G {
    comptime assert(@hasDecl(G, "hash_to_group"));
    var bytes: [32]u8 = undefined;
    random.bytes(&bytes);
    return G.hash_to_group(&.{}, &bytes);
}

/// Property suites over algebraic laws (commonware `algebra::test_suites`). Each takes
/// structured input and panics through `std.testing` expectations when a law fails. Element
/// types provide `arbitrary(*Unstructured) T`.
pub const test_suites = struct {
    fn expect_eql(comptime T: type, a: T, b: T) !void {
        if (!a.eql(b)) return error.LawViolated;
    }

    pub fn fuzz_additive(comptime T: type, u: *Unstructured) !void {
        const a = T.arbitrary(u);
        const b = T.arbitrary(u);
        const c = T.arbitrary(u);
        try expect_eql(T, a.add(b), b.add(a));
        try expect_eql(T, a.add(b).add(c), a.add(b.add(c)));
        try expect_eql(T, T.zero.add(a), a);
        try expect_eql(T, a.add(a.neg()), T.zero);
        try expect_eql(T, a.sub(b), a.add(b.neg()));
        try expect_eql(T, double(T, a), a.add(a));
    }

    pub fn fuzz_multiplicative(comptime T: type, u: *Unstructured) !void {
        const a = T.arbitrary(u);
        const b = T.arbitrary(u);
        const c = T.arbitrary(u);
        try expect_eql(T, a.mul(b), b.mul(a));
        try expect_eql(T, a.mul(b).mul(c), a.mul(b.mul(c)));
        try expect_eql(T, square(T, a), a.mul(a));
    }

    pub fn fuzz_ring(comptime T: type, u: *Unstructured) !void {
        try fuzz_additive(T, u);
        try fuzz_multiplicative(T, u);
        const a = T.arbitrary(u);
        const b = T.arbitrary(u);
        const c = T.arbitrary(u);
        try expect_eql(T, T.one.mul(a), a);
        try expect_eql(T, a.add(b).mul(c), a.mul(c).add(b.mul(c)));
    }

    pub fn fuzz_field(comptime T: type, u: *Unstructured) !void {
        try fuzz_ring(T, u);
        const a = T.arbitrary(u);
        if (a.eql(T.zero)) {
            try expect_eql(T, a.inv(), T.zero);
        } else {
            try expect_eql(T, a.inv().mul(a), T.one);
        }
    }

    pub fn fuzz_space(comptime R: type, comptime K: type, u: *Unstructured) !void {
        const a = K.arbitrary(u);
        const b = K.arbitrary(u);
        const x = R.arbitrary(u);
        try expect_eql(K, a.add(b).mul(x), a.mul(x).add(b.mul(x)));
        const count = u.length(16);
        var points: [16]K = undefined;
        var scalars: [16]R = undefined;
        for (0..count) |index| points[index] = K.arbitrary(u);
        for (0..count) |index| scalars[index] = R.arbitrary(u);
        const naive = msm_naive(K, R, points[0..count], scalars[0..count]);
        try expect_eql(K, naive, msm(K, R, points[0..count], scalars[0..count]));
    }

    pub fn fuzz_space_ring(comptime R: type, comptime K: type, u: *Unstructured) !void {
        try fuzz_space(R, K, u);
        const a = K.arbitrary(u);
        const b = R.arbitrary(u);
        const c = R.arbitrary(u);
        try expect_eql(K, a.mul(b).mul(c), a.mul(b.mul(c)));
        try expect_eql(K, a.mul(R.one), a);
        try expect_eql(K, a.mul(R.zero), K.zero);
    }

    pub fn fuzz_hash_to_group(comptime G: type, u: *Unstructured) !void {
        var data: [4][4]u8 = undefined;
        for (&data) |*item| u.bytes(item);
        const inputs_equal = std.mem.eql(u8, &data[0], &data[2]) and
            std.mem.eql(u8, &data[1], &data[3]);
        const left = G.hash_to_group(&data[0], &data[1]);
        const right = G.hash_to_group(&data[2], &data[3]);
        if (inputs_equal != left.eql(right)) return error.LawViolated;
    }

    fn check_root_of_unity_order(comptime T: type, lg: u8) !void {
        if (lg > T.max_lg_root_order) {
            if (T.root_of_unity(lg) != null) return error.LawViolated;
            return;
        }
        const root = T.root_of_unity(lg) orelse return error.LawViolated;
        // order = 2^lg as little-endian limbs (lg <= 255 fits in 4 limbs).
        var order: [4]u64 = @splat(0);
        order[lg / 64] = @as(u64, 1) << @intCast(lg % 64);
        const limbs = order[0 .. lg / 64 + 1];
        try expect_eql(T, exp(T, root, limbs), T.one);
        if (lg == 0) return;
        // order - 1: borrow through the low limbs.
        var position: usize = 0;
        while (true) : (position += 1) {
            const borrow = limbs[position] == 0;
            limbs[position] -%= 1;
            if (!borrow) break;
        }
        if (exp(T, root, limbs).eql(T.one)) return error.LawViolated;
    }

    pub fn fuzz_field_ntt(comptime T: type, u: *Unstructured) !void {
        try fuzz_field(T, u);
        switch (u.int_in_range(u8, 0, 9)) {
            0 => try expect_eql(T, T.coset_shift().mul(coset_shift_inv(T)), T.one),
            1 => try check_root_of_unity_order(T, u.int_in_range(u8, 0, T.max_lg_root_order + 1)),
            else => {
                const a = T.arbitrary(u);
                try expect_eql(T, div_2(T, a).mul(T.one.add(T.one)), a);
            },
        }
    }
};

const goldilocks = @import("fields/goldilocks.zig");
const F = goldilocks.F;

/// The algebra fuzz plan (commonware `algebra::fuzz::Plan`).
pub fn fuzz_plan(_: void, u: *Unstructured) !void {
    const Plan = enum {
        exp_one,
        exp_zero,
        exp,
        powers_match_exp,
        scale_one,
        scale_zero,
        scale,
        msm2,
    };
    const x = F.arbitrary(u);
    switch (u.choose(Plan)) {
        .exp_one => try test_suites.expect_eql(F, exp(F, x, &.{1}), x),
        .exp_zero => try test_suites.expect_eql(F, exp(F, x, &.{}), F.one),
        .exp => {
            const a: u64 = u.int(u32);
            const b: u64 = u.int(u32);
            const product = exp(F, x, &.{a}).mul(exp(F, x, &.{b}));
            try test_suites.expect_eql(F, exp(F, x, &.{a + b}), product);
        },
        .powers_match_exp => {
            const base = F.arbitrary(u);
            const index = u.int(u16);
            var iterator = powers(F, x, base);
            var power = iterator.next();
            for (0..index) |_| power = iterator.next();
            try test_suites.expect_eql(F, power, x.mul(exp(F, base, &.{index})));
        },
        .scale_one => try test_suites.expect_eql(F, scale(F, x, &.{1}), x),
        .scale_zero => try test_suites.expect_eql(F, scale(F, x, &.{}), F.zero),
        .scale => {
            const a: u64 = u.int(u32);
            const b: u64 = u.int(u32);
            const sum = scale(F, x, &.{a}).add(scale(F, x, &.{b}));
            try test_suites.expect_eql(F, scale(F, x, &.{a + b}), sum);
        },
        .msm2 => {
            const points = [2]F{ x, F.arbitrary(u) };
            const scalars = [2]F{ F.arbitrary(u), F.arbitrary(u) };
            const expected = points[0].mul(scalars[0]).add(points[1].mul(scalars[1]));
            try test_suites.expect_eql(F, msm(F, F, &points, &scalars), expected);
        },
    }
}

test "algebra fuzz plan (seeded)" {
    try fuzz.run_seeded(0xa16eb4a, 2000, {}, fuzz_plan);
}

test "algebra fuzz plan (coverage-guided)" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            try fuzz.run_smith({}, smith, fuzz_plan);
        }
    }.one, .{});
}

test "scale and exp on multi-limb exponents" {
    const x = F.from_u64(3);
    // 2^64 = 2^32 - 1 mod P, so x * 2^64 = x * (2^32 - 1).
    try std.testing.expect(scale(F, x, &.{ 0, 1 }).eql(x.mul(F.from_u64((1 << 32) - 1))));
    // x^(2^64) = x^(2^64 mod (P - 1)) since x^(P-1) = 1, and 2^64 mod (P - 1) = 2^32.
    try std.testing.expect(exp(F, x, &.{ 0, 1 }).eql(exp(F, x, &.{1 << 32})));
    // Trailing zero limbs do not change the result.
    try std.testing.expect(exp(F, x, &.{ 5, 0 }).eql(exp(F, x, &.{5})));
}
