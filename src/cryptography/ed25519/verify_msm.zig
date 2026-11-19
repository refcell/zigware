//! Single-signature ZIP-215 verification the way commonware's curve25519 crate checks it
//! (`cryptography/curve25519/src/signing/core.rs`, `Verify` and `straus`).
//!
//! The cofactored check `[8](s B - R - k A) == 0` is multiplied by a short `u`: with
//! `(u, v) = half_size(k)`, so `v = u k (mod l)`, `0 < |u| < 2^127`, and `v < 2^126`, the sum
//! `[8](low B + high 2^128 B - |u| R + v A')` is `sign(u)` times `u [8](s B - R - k A)`, where
//! `|u| s = low + high 2^128 (mod l)` and `A' = -A` for `u >= 0`, `A` otherwise. Since
//! `0 < |u| < l`, one is the identity exactly when the other is. Every scalar is below 2^128,
//! so Straus's method shares one doubling chain of at most 129 steps (std's double-base
//! multiplication doubles 252 times), adding width-5 NAF multiples of `R` and `A'` from
//! per-call tables and width-8 NAF multiples of `B` and `2^128 B` from tables built at compile
//! time.
//!
//! Variable time: every input is public.

const std = @import("std");
const assert = std.debug.assert;
const verify_ifma = @import("verify_ifma.zig");

pub const Point = std.crypto.ecc.Edwards25519;
const Fe = Point.Fe;
const scalar = Point.scalar;

/// The group order `l`.
const order: u256 = scalar.field_order;

/// NAF width of the per-call tables of `R` and `A` (commonware `NAF_WIDTH`).
pub const naf_width = 5;
/// NAF width of the static basepoint tables (commonware `ODD_MULTIPLES_NAF_WIDTH`).
pub const base_naf_width = 8;
/// NAF digits of a scalar below 2^128.
pub const digits_len = 130;

/// A point and its scalar, below 2^128, in a Straus sum.
pub const Term = struct { Point, u128 };

/// A point prepared for addition: `(Y + X, Y - X, Z, 2 d T)` (commonware's cached form).
pub const Cached = struct {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,

    pub fn from(p: Point) Cached {
        return .{
            .y_plus_x = p.y.add(p.x),
            .y_minus_x = p.y.sub(p.x),
            .z = p.z,
            .t2d = p.t.mul(Fe.edwards25519d2),
        };
    }
};

/// `p + q`, or `p - q` when `negate` (negating swaps `Y + X` with `Y - X` and negates `2 d T`).
pub fn add_cached(p: Point, q: *const Cached, negate: bool) Point {
    const y_plus_x = if (negate) q.y_minus_x else q.y_plus_x;
    const y_minus_x = if (negate) q.y_plus_x else q.y_minus_x;
    const a = p.y.sub(p.x).mul(y_minus_x);
    const b = p.y.add(p.x).mul(y_plus_x);
    const c_raw = p.t.mul(q.t2d);
    const c = if (negate) c_raw.neg() else c_raw;
    var d = p.z.mul(q.z);
    d = d.add(d);
    const x = b.sub(a);
    const y = b.add(a);
    const z = d.add(c);
    const t = d.sub(c);
    return .{ .x = x.mul(t), .y = y.mul(z), .z = z.mul(t), .t = x.mul(y) };
}

/// The odd multiples `p, 3 p, ..., (2 len - 1) p`, so a NAF digit `d` selects `|d| / 2`.
pub fn odd_multiples(comptime len: usize, p: Point) [len]Cached {
    comptime assert(len >= 2);
    const double = Cached.from(p.dbl());
    var table: [len]Cached = undefined;
    var multiple = p;
    table[0] = .from(p);
    for (table[1..]) |*entry| {
        multiple = add_cached(multiple, &double, false);
        entry.* = .from(multiple);
    }
    return table;
}

/// Odd multiples of `B` and of `2^128 B` (commonware's static `ODD_MULTIPLES`).
pub const base_tables: [2][1 << (base_naf_width - 2)]Cached = tables: {
    @setEvalBranchQuota(100_000_000);
    const low = plain_base_point();
    var high = low;
    for (0..128) |_| high = high.dbl();
    const len = 1 << (base_naf_width - 2);
    break :tables .{ odd_multiples(len, low), odd_multiples(len, high) };
};

/// `B` without std's `is_base` flag.
fn plain_base_point() Point {
    const b = Point.basePoint;
    return .{ .x = b.x, .y = b.y, .z = b.z, .t = b.t };
}

/// Width-`width` non-adjacent form of `value < 2^128`, least significant digit first: every
/// nonzero digit is odd with magnitude below `2^(width - 1)`.
pub fn naf(comptime width: u4, value: u128) [digits_len]i8 {
    comptime assert(width >= 2 and width <= 8);
    const window: i16 = 1 << width;
    var digits: [digits_len]i8 = @splat(0);
    // One more bit than the value: a negative top digit carries into it.
    var k: u136 = value;
    var index: usize = 0;
    // Bounded: `k` halves each step and stays below 2^129.
    while (k != 0) : (index += 1) {
        assert(index < digits_len);
        if (k & 1 == 1) {
            const low: i16 = @intCast(k & @as(u136, @intCast(window - 1)));
            const digit: i16 = if (low >= @divExact(window, 2)) low - window else low;
            digits[index] = @intCast(digit);
            if (digit >= 0) k -= @intCast(digit) else k += @intCast(-digit);
        }
        k >>= 1;
    }
    return digits;
}

/// `(u, v)` with `v = u x (mod l)`, `0 < |u| < 2^127`, and `v < 2^126` (commonware
/// `Scalar::half_size`), by the extended Euclidean algorithm on `(l, x)` stopped early.
pub fn half_size(x: u256) struct { u: i128, v: u128 } {
    assert(x < order);
    var r0: u256 = order;
    // Coefficients alternate in sign and every partial one lies between two consecutive
    // ones, all below 2^127 in magnitude (commonware's bound), so `i128` never overflows.
    var t0: i128 = 0;
    var r1: u256 = x;
    var t1: i128 = 1;
    // Bounded: each pass reduces the larger remainder below the smaller.
    while (bits(r1) > 126) {
        // Reduces `r0` modulo `r1` by shifted copies of `r1`; every shift is below 127.
        while (r0 >= r1) {
            var shift: u8 = @intCast(bits(r0) - bits(r1));
            var shifted = r1 << shift;
            if (r0 < shifted) {
                shift -= 1;
                shifted = r1 << shift;
            }
            r0 -= shifted;
            t0 -= t1 << @intCast(shift);
        }
        std.mem.swap(u256, &r0, &r1);
        std.mem.swap(i128, &t0, &t1);
    }
    assert(t1 != 0 and @abs(t1) < (1 << 127));
    assert(r1 < (1 << 126));
    return .{ .u = t1, .v = @intCast(r1) };
}

fn bits(x: u256) u16 {
    return 256 - @as(u16, @clz(x));
}

/// `base[0] B + base[1] 2^128 B + sum(scalar point)`, with every scalar below 2^128, by
/// A point in projective coordinates `(X : Y : Z)`, without `T` (commonware's
/// `Projective`): the running sum between additions.
const Projective = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    const identity: Projective = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.one };

    /// `2 p` as a completed point (4 squarings).
    fn double(p: Projective) Completed {
        const xx = p.x.sq();
        const yy = p.y.sq();
        const zz2 = p.z.sq2();
        const x_plus_y_sq = p.x.add(p.y).sq();
        const yy_plus_xx = yy.add(xx);
        const yy_minus_xx = yy.sub(xx);
        return .{
            .x = x_plus_y_sq.sub(yy_plus_xx),
            .y = yy_plus_xx,
            .z = yy_minus_xx,
            .t = zz2.sub(yy_minus_xx),
        };
    }
};

/// A point `((X : Z), (Y : T))` as additions and doublings leave it (commonware's
/// `Completed`), converted only when the next step needs it.
const Completed = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,

    fn to_projective(p: Completed) Projective {
        return .{ .x = p.x.mul(p.t), .y = p.y.mul(p.z), .z = p.z.mul(p.t) };
    }

    fn to_extended(p: Completed) Point {
        return .{ .x = p.x.mul(p.t), .y = p.y.mul(p.z), .z = p.z.mul(p.t), .t = p.x.mul(p.y) };
    }

    /// `p + q`, or `p - q` when `negate` (4 multiplications).
    fn add(p: Point, q: *const Cached, negate: bool) Completed {
        const y_plus_x = if (negate) q.y_minus_x else q.y_plus_x;
        const y_minus_x = if (negate) q.y_plus_x else q.y_minus_x;
        const pp = p.y.add(p.x).mul(y_plus_x);
        const mm = p.y.sub(p.x).mul(y_minus_x);
        const tt2d = p.t.mul(q.t2d);
        var zz2 = p.z.mul(q.z);
        zz2 = zz2.add(zz2);
        return .{
            .x = pp.sub(mm),
            .y = pp.add(mm),
            .z = if (negate) zz2.sub(tt2d) else zz2.add(tt2d),
            .t = if (negate) zz2.add(tt2d) else zz2.sub(tt2d),
        };
    }
};

/// `base[0] B + base[1] 2^128 B + sum(scalar point)`, with every scalar below 2^128, by
/// Straus's method over one shared doubling chain (commonware `straus`).
fn straus(base: [2]u128, terms: [2]Term) Projective {
    const base_digits = [2][digits_len]i8{
        naf(base_naf_width, base[0]),
        naf(base_naf_width, base[1]),
    };
    var digits: [2][digits_len]i8 = undefined;
    var tables: [2][1 << (naf_width - 2)]Cached = undefined;
    for (terms, &digits, &tables) |term, *d, *table| {
        d.* = naf(naf_width, term[1]);
        table.* = odd_multiples(1 << (naf_width - 2), term[0]);
    }
    const all = base_digits ++ digits;
    var sum = Projective.identity;
    var index = (top_digit(&all) orelse return sum) + 1;
    // Horner's rule over digit positions, most significant first. A doubling leaves a
    // completed point, converted to extended coordinates only when an addition follows.
    while (index > 0) {
        index -= 1;
        var step = sum.double();
        for (&base_digits, &base_tables) |*d, *table| step = add_digit(step, table, d[index]);
        for (&digits, &tables) |*d, *table| step = add_digit(step, table, d[index]);
        sum = step.to_projective();
    }
    return sum;
}

/// The highest position holding a nonzero digit of any scalar, where the shared chain starts.
pub fn top_digit(all: []const [digits_len]i8) ?usize {
    assert(all.len > 0);
    var top: ?usize = null;
    for (all) |d| {
        var index: usize = digits_len;
        while (index > 0) : (index -= 1) {
            if (d[index - 1] == 0) continue;
            top = @max(top orelse 0, index - 1);
            break;
        }
    }
    assert(top == null or top.? < digits_len);
    return top;
}

fn add_digit(step: Completed, table: []const Cached, digit: i8) Completed {
    if (digit == 0) return step;
    const magnitude: usize = @abs(digit);
    assert(magnitude % 2 == 1 and magnitude / 2 < table.len);
    return Completed.add(step.to_extended(), &table[magnitude / 2], digit < 0);
}

/// Whether `[8](s B - R + k (-A)) == 0`, given `R`, `-A`, a canonical `s`, and
/// `k = H(R || A || M) mod l`.
pub fn verify(r: Point, minus_a: Point, s: [32]u8, k: [32]u8) bool {
    const k_int = std.mem.readInt(u256, &k, .little);
    assert(k_int < order);
    const split = half_size(k_int);
    // `A'` is `-A` for `u >= 0` and `A` otherwise.
    const a_term = if (split.u < 0) minus_a.neg() else minus_a;
    const magnitude: u128 = @abs(split.u);
    var magnitude_bytes: [32]u8 = @splat(0);
    std.mem.writeInt(u128, magnitude_bytes[0..16], magnitude, .little);
    const us = scalar.mul(s, magnitude_bytes);
    const low = std.mem.readInt(u128, us[0..16], .little);
    const high = std.mem.readInt(u128, us[16..32], .little);
    const sum = cofactored_sum(.{ low, high }, .{ .{ r.neg(), magnitude }, .{ a_term, split.v } });
    return sum[0].isZero() and sum[1].equivalent(sum[2]);
}

/// `[8](base[0] B + base[1] 2^128 B + sum(scalar point))` as `[X, Y, Z]`, on the AVX-512 IFMA
/// backend when the target has it and on the scalar one otherwise.
pub fn cofactored_sum(base: [2]u128, terms: [2]Term) [3]Fe {
    if (comptime verify_ifma.available) return verify_ifma.cofactored_sum(base, terms);
    return scalar_cofactored_sum(base, terms);
}

/// `cofactored_sum` on the scalar backend, on every target.
pub fn scalar_cofactored_sum(base: [2]u128, terms: [2]Term) [3]Fe {
    var sum = straus(base, terms);
    // Multiplying by the cofactor (8) maps the sum into the prime-order subgroup.
    for (0..3) |_| sum = sum.double().to_projective();
    assert(!sum.z.isZero());
    return .{ sum.x, sum.y, sum.z };
}

const testing = std.testing;

test "half_size returns a short multiple" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const cases = [_]u256{ 0, 1, (1 << 126) - 1, 1 << 126, 1 << 127, 1 << 128, order - 1 };
    for (0..cases.len + 256) |index| {
        const x = if (index < cases.len) cases[index] else prng.random().int(u256) % order;
        const split = half_size(x);
        try testing.expect(split.u != 0);
        try testing.expect(@abs(split.u) < 1 << 127);
        try testing.expect(split.v < 1 << 126);
        // `u x = v (mod l)`, with a negative `u` mapped to its residue.
        const magnitude: u512 = @abs(split.u);
        const product = (magnitude * x) % order;
        const residue = if (split.u < 0) (order - product) % order else product;
        try testing.expectEqual(@as(u512, split.v), residue);
    }
}

test "naf digits sum to the value and are odd and bounded" {
    var prng = std.Random.DefaultPrng.init(0x7af);
    inline for (.{ naf_width, base_naf_width }) |width| {
        for (0..256) |index| {
            const value: u128 = switch (index) {
                0 => 0,
                1 => std.math.maxInt(u128),
                else => prng.random().int(u128),
            };
            const digits = naf(width, value);
            var sum: i256 = 0;
            var last_nonzero: ?usize = null;
            for (digits, 0..) |digit, position| {
                if (digit == 0) continue;
                try testing.expect(@mod(digit, 2) == 1);
                try testing.expect(@abs(digit) < 1 << (width - 1));
                if (last_nonzero) |last| try testing.expect(position - last >= width);
                last_nonzero = position;
                sum += @as(i256, digit) << @intCast(position);
            }
            try testing.expectEqual(@as(i256, value), sum);
        }
    }
}

test "straus matches std's double-base multiplication" {
    var prng = std.Random.DefaultPrng.init(0x57a);
    for (0..64) |_| {
        var seed: [32]u8 = undefined;
        prng.random().bytes(&seed);
        const p = Point.basePoint.mulPublic(scalar.reduce(seed)) catch unreachable;
        const point: Point = .{ .x = p.x, .y = p.y, .z = p.z, .t = p.t };
        const a = prng.random().int(u128);
        const b = prng.random().int(u128);
        const c = prng.random().int(u128);
        const d = prng.random().int(u128);
        const projective = straus(.{ a, b }, .{ .{ point, c }, .{ point.neg(), d } });
        const actual: Point = .{
            .x = projective.x.mul(projective.z),
            .y = projective.y.mul(projective.z),
            .z = projective.z.sq(),
            .t = projective.x.mul(projective.y),
        };
        // Expected: (a + b 2^128) B + (c - d) P.
        var base_scalar: [32]u8 = undefined;
        std.mem.writeInt(u256, &base_scalar, (@as(u256, b) << 128 | a) % order, .little);
        const c_minus_d = (@as(u256, c) + order - @as(u256, d) % order) % order;
        var point_scalar: [32]u8 = undefined;
        std.mem.writeInt(u256, &point_scalar, c_minus_d, .little);
        const expected =
            try Point.mulDoubleBasePublic(Point.basePoint, base_scalar, point, point_scalar);
        try testing.expectEqualSlices(u8, &expected.toBytes(), &actual.toBytes());
    }
}
