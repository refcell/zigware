//! The AVX-512 IFMA backend of single-signature verification (commonware
//! `cryptography/curve25519/src/curve/avx512/single.rs`): one point packed across the four
//! 64-bit lanes of a 256-bit vector, so each multiplication level of a point addition or
//! doubling is one lane-wise IFMA multiplication.
//!
//! Row `k` holds limb `k` (radix 2^51) of the point's coordinates, one coordinate per lane.
//! Products are folded but not carried, leaving limbs below `300 * 2^52`; every operation
//! applies its additions and subtractions to such limbs and carries once before it multiplies,
//! so IFMA only ever sees limbs below 2^52.
//!
//! `available` is comptime: the backend compiles only for targets with AVX-512F, AVX-512VL, and
//! AVX-512 IFMA, and `verify_msm` falls back to its scalar Straus everywhere else.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const verify_msm = @import("verify_msm.zig");

const Point = verify_msm.Point;
const Fe = Point.Fe;

/// Whether the build target has the features this backend needs.
pub const available = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .avx512f, .avx512vl, .avx512ifma });

const V = @Vector(4, u64);
const limbs = 5;
const mask_51: u64 = (1 << 51) - 1;

/// One packed point: a limb row per vector.
const Rows = [limbs]V;

/// `k p`, limb-wise.
fn p_times(comptime k: u64) [limbs]u64 {
    return .{ k * ((1 << 51) - 19), k * mask_51, k * mask_51, k * mask_51, k * mask_51 };
}

/// `1024 p`: every limb exceeds every unreduced product limb, so subtracting from it never
/// underflows, and a sum of three terms below 2^61.3 stays below 2^63.
const bias_1024p = p_times(1024);
/// `2 p`: for a carried limb `x`, `2 p - x` lies in `[0, 2^52)`.
const bias_2p = p_times(2);

comptime {
    assert(bias_1024p[0] > 300 << 52 and bias_1024p[1] > 300 << 52);
    assert(bias_2p[0] > (1 << 51) + 19 * (1 << 12));
}

/// IFMA's instructions, which only LLVM's assembler knows. The self-hosted backend (Debug
/// builds) emulates them lane by lane, so Debug tests still check the packed arithmetic.
const native_ifma = builtin.zig_backend == .stage2_llvm;
const mask_52: V = @splat((1 << 52) - 1);

/// `acc` plus the low 52 bits of each lane's `a * b`, for `a, b < 2^52`.
inline fn madd52lo(acc: V, a: V, b: V) V {
    if (comptime !native_ifma) return acc + (@as(V, @truncate(product(a, b))) & mask_52);
    return asm ("vpmadd52luq %[b], %[a], %[acc]"
        : [acc] "=v" (-> V),
        : [acc_in] "0" (acc),
          [a] "v" (a),
          [b] "v" (b),
    );
}

/// `acc` plus bits 52 to 103 of each lane's `a * b`, for `a, b < 2^52`.
inline fn madd52hi(acc: V, a: V, b: V) V {
    if (comptime !native_ifma) return acc + @as(V, @truncate(product(a, b) >> @splat(52)));
    return asm ("vpmadd52huq %[b], %[a], %[acc]"
        : [acc] "=v" (-> V),
        : [acc_in] "0" (acc),
          [a] "v" (a),
          [b] "v" (b),
    );
}

inline fn product(a: V, b: V) @Vector(4, u128) {
    const wide: @Vector(4, u128) = a & mask_52;
    return wide * @as(@Vector(4, u128), b & mask_52);
}

/// `19 z` as `16 z + 2 z + z`, for `z < 2^59`.
inline fn mul19(z: V) V {
    return (z << @splat(4)) + (z << @splat(1)) + z;
}

/// Lane `i` of `a` where `lanes` has bit `i` set, of `b` elsewhere.
inline fn pick(comptime lanes: u4, a: V, b: V) V {
    const choose: @Vector(4, bool) = comptime .{
        lanes & 1 != 0, lanes & 2 != 0, lanes & 4 != 0, lanes & 8 != 0,
    };
    return @select(u64, choose, a, b);
}

/// Lanes `a, b, c, d` of `v` in lanes 0 to 3.
inline fn permute(v: V, comptime order: [4]i32) V {
    return @shuffle(u64, v, undefined, order);
}

inline fn splat(comptime row: [limbs]u64) Rows {
    var out: Rows = undefined;
    inline for (&out, row) |*o, limb| o.* = @splat(limb);
    return out;
}

/// Restores the 2^52 limb bound with one parallel carry pass. Inputs below 2^63 have carries
/// below 2^12, so the outputs are below `2^51 + 19 * 2^12`.
inline fn carry(l: Rows) Rows {
    const mask: V = @splat(mask_51);
    var c: Rows = undefined;
    inline for (&c, l) |*ci, li| ci.* = li >> @splat(51);
    return .{
        (l[0] & mask) + mul19(c[4]),
        (l[1] & mask) + c[0],
        (l[2] & mask) + c[1],
        (l[3] & mask) + c[2],
        (l[4] & mask) + c[3],
    };
}

/// Lane-wise product of limbs below 2^52, folded onto five limbs but not carried.
///
/// IFMA splits each product at bit 52, so high halves weigh twice the next column. Every column
/// `lo + 2 hi` is below `15 * 2^52`, and each folded limb `z[k] + 19 z[k + 5]` below
/// `300 * 2^52 < 2^60.3`.
inline fn mul_wide(a: Rows, b: Rows) Rows {
    var lo: [2 * limbs]V = @splat(@splat(0));
    var hi: [2 * limbs]V = @splat(@splat(0));
    inline for (0..limbs) |i| {
        inline for (0..limbs) |j| {
            lo[i + j] = madd52lo(lo[i + j], a[i], b[j]);
            hi[i + j + 1] = madd52hi(hi[i + j + 1], a[i], b[j]);
        }
    }
    var out: Rows = undefined;
    inline for (&out, 0..) |*o, k| {
        const low = lo[k] + (hi[k] + hi[k]);
        const high = lo[k + limbs] + (hi[k + limbs] + hi[k + limbs]);
        o.* = low + mul19(high);
    }
    return out;
}

/// Lane-wise square, folded but not carried, with each cross product computed once: column
/// `k` is `c1[k] + 2 c2[k] + 4 c4[k]`, bounded as in `mul_wide`.
inline fn square_wide(a: Rows) Rows {
    var c1: [2 * limbs]V = @splat(@splat(0));
    var c2: [2 * limbs]V = @splat(@splat(0));
    var c4: [2 * limbs]V = @splat(@splat(0));
    inline for (0..limbs) |i| {
        c1[2 * i] = madd52lo(c1[2 * i], a[i], a[i]);
        c2[2 * i + 1] = madd52hi(c2[2 * i + 1], a[i], a[i]);
        inline for (i + 1..limbs) |j| {
            c2[i + j] = madd52lo(c2[i + j], a[i], a[j]);
            c4[i + j + 1] = madd52hi(c4[i + j + 1], a[i], a[j]);
        }
    }
    var out: Rows = undefined;
    inline for (&out, 0..) |*o, k| {
        const h = k + limbs;
        const low = c1[k] + (c2[k] + c2[k]) + (c4[k] << @splat(2));
        const high = c1[h] + (c2[h] + c2[h]) + (c4[h] << @splat(2));
        o.* = low + mul19(high);
    }
    return out;
}

/// A point as lanes `[X, Y, Z, T]` with limbs below `300 * 2^52`. Doubling ignores the `T`
/// lane, so the same value serves as projective and extended coordinates.
const Packed = Rows;

/// An addition operand, lanes `[Y - X, Y + X, 2 d T, 2 Z]` with limbs below 2^52.
pub const Operand = Rows;

/// Lanes whose final products are a point: `[E, G, F, E]` and `[F, H, G, H]`.
const Completed = struct { left: Rows, right: Rows };

const identity: Packed = .{ .{ 0, 1, 1, 0 }, @splat(0), @splat(0), @splat(0), @splat(0) };

/// `[Y - X, Y + X, T, Z]`, carried, from lanes `[X, Y, Z, T]`.
inline fn diff_sum(p: Packed) Rows {
    const bias = splat(bias_1024p);
    var out: Rows = undefined;
    inline for (&out, p, bias) |*o, row, b| {
        const swapped = permute(row, .{ 1, 0, 3, 2 }); // [Y, X, T, Z]
        const negated = pick(0b0001, b - row, row); // [-X, Y, Z, T]
        o.* = pick(0b0011, swapped + negated, swapped); // [Y - X, X + Y, T, Z]
    }
    return carry(out);
}

/// `p + q` up to its final products: `[A, B, C, D]` from one multiplication, then
/// `E = B - A`, `H = B + A`, `F = D - C`, `G = D + C`, rearranged as the final operands.
fn add(p: Packed, q: Operand) Completed {
    @setEvalBranchQuota(10_000);
    const products = mul_wide(diff_sum(p), q); // [A, B, C, D]
    const bias = splat(bias_1024p);
    var s: Rows = undefined;
    inline for (&s, products, bias) |*o, row, b| {
        const swapped = permute(row, .{ 1, 0, 3, 2 }); // [B, A, D, C]
        o.* = swapped + pick(0b0101, b - row, row); // [E, H, F, G]
    }
    s = carry(s);
    var out: Completed = undefined;
    inline for (&out.left, &out.right, s) |*left, *right, row| {
        left.* = permute(row, .{ 0, 3, 2, 0 }); // [E, G, F, E]
        right.* = permute(row, .{ 2, 1, 3, 1 }); // [F, H, G, H]
    }
    return out;
}

/// `2 p` up to its final products. One squaring of `[X, Y, Z, X + Y]` gives `[A, B, Z^2, K]`;
/// the operands hold `A + B - K`, `A - B + 2 Z^2`, `A - B`, and `A + B`, the negations of the
/// scalar formula's `E, F, G, H`, so every final product is unchanged.
fn double(p: Packed) Completed {
    @setEvalBranchQuota(10_000);
    var s: Rows = undefined;
    inline for (&s, p) |*o, row| {
        const x = permute(row, .{ 0, 1, 2, 0 }); // [X, Y, Z, X]
        o.* = pick(0b1000, x + permute(row, .{ 0, 0, 0, 1 }), x); // [X, Y, Z, X + Y]
    }
    const squares = square_wide(carry(s)); // [A, B, Z^2, K]
    const bias = splat(bias_1024p);
    var out: Completed = undefined;
    inline for (&out.left, &out.right, squares, bias) |*left, *right, row, b| {
        const a = permute(row, .{ 0, 0, 0, 0 });
        const sq_b = permute(row, .{ 1, 1, 1, 1 });
        const c = permute(row, .{ 3, 2, 2, 3 }); // [K, Z^2, Z^2, K]
        const z2 = permute(row, .{ 2, 2, 2, 2 });
        // Left: [A + B - K, A - B, A - B + 2 Z^2, A + B - K].
        var terms = pick(0b1001, b - c, c);
        terms = pick(0b0100, terms + c, terms);
        const left_sum = a + pick(0b0110, b - sq_b, sq_b);
        left.* = pick(0b1101, left_sum + terms, left_sum);
        // Right: [A - B + 2 Z^2, A + B, A - B, A + B].
        const right_sum = a + pick(0b0101, b - sq_b, sq_b);
        right.* = pick(0b0001, right_sum + (z2 + z2), right_sum);
    }
    return .{ .left = carry(out.left), .right = carry(out.right) };
}

fn finish(c: Completed) Packed {
    @setEvalBranchQuota(10_000);
    return mul_wide(c.left, c.right);
}

/// The negated operand: swaps `Y - X` with `Y + X` and replaces `2 d T` by `2 p - 2 d T`.
inline fn negate(q: Operand) Operand {
    const bias = splat(bias_2p);
    var out: Operand = undefined;
    inline for (&out, q, bias) |*o, row, b| {
        const swapped = pick(0b0011, permute(row, .{ 1, 0, 3, 2 }), row);
        o.* = pick(0b0100, b - swapped, swapped);
    }
    return out;
}

/// The operand of a point, by one multiplication of `[Y - X, Y + X, T, Z]` by `[1, 1, 2d, 2]`.
fn cache(p: Packed) Operand {
    const d2 = Fe.edwards25519d2.limbs;
    var factors: Rows = undefined;
    inline for (&factors, d2, 0..) |*f, limb, k| {
        f.* = if (k == 0) .{ 1, 1, limb, 2 } else .{ 0, 0, limb, 0 };
    }
    return carry(mul_wide(diff_sum(p), factors));
}

/// Lanes `[X, Y, Z, T]` of a point, carried.
fn load(p: Point) Packed {
    var rows: Rows = undefined;
    inline for (&rows, 0..) |*row, k| {
        row.* = .{ p.x.limbs[k], p.y.limbs[k], p.z.limbs[k], p.t.limbs[k] };
    }
    return carry(rows);
}

/// The coordinates `[X, Y, Z, T]`, carried.
fn store(p: Packed) [4]Fe {
    const rows = carry(p);
    var out: [4]Fe = undefined;
    inline for (&out, 0..) |*fe, lane| {
        inline for (&fe.limbs, rows) |*limb, row| limb.* = row[lane];
    }
    return out;
}

/// The odd multiples `p, 3 p, ..., (2 len - 1) p` as operands.
fn odd_multiples(comptime len: usize, p: Point) [len]Operand {
    comptime assert(len >= 2);
    const first = load(p);
    const double_operand = cache(finish(double(first)));
    var table: [len]Operand = undefined;
    var multiple = first;
    table[0] = cache(first);
    for (table[1..]) |*entry| {
        multiple = finish(add(multiple, double_operand));
        entry.* = cache(multiple);
    }
    return table;
}

/// A fully reduced field element: every limb below 2^51.
fn normalized(fe: Fe) Fe {
    return Fe.fromBytes(fe.toBytes());
}

/// The scalar backend's odd multiples of `B` and of `2^128 B` as operands.
const base_tables = tables: {
    @setEvalBranchQuota(10_000_000);
    const len = verify_msm.base_tables[0].len;
    var out: [2][len]Operand = undefined;
    for (&out, verify_msm.base_tables) |*table, source| {
        for (table, source) |*entry, cached| {
            const coordinates = [4]Fe{
                normalized(cached.y_minus_x),
                normalized(cached.y_plus_x),
                normalized(cached.t2d),
                normalized(cached.z.add(cached.z)),
            };
            for (entry, 0..) |*row, k| {
                row.* = .{
                    coordinates[0].limbs[k], coordinates[1].limbs[k],
                    coordinates[2].limbs[k], coordinates[3].limbs[k],
                };
            }
        }
    }
    break :tables out;
};

inline fn add_digit(step: Completed, table: []const Operand, digit: i8) Completed {
    if (digit == 0) return step;
    const magnitude: usize = @abs(digit);
    assert(magnitude % 2 == 1 and magnitude / 2 < table.len);
    const operand = table[magnitude / 2];
    return add(finish(step), if (digit < 0) negate(operand) else operand);
}

/// `[8](base[0] B + base[1] 2^128 B + sum(scalar point))`, every scalar below 2^128, as
/// `[X, Y, Z]`: Straus's method over one shared doubling chain (commonware `straus`).
pub fn cofactored_sum(base: [2]u128, terms: [2]verify_msm.Term) [3]Fe {
    const width = verify_msm.naf_width;
    const base_width = verify_msm.base_naf_width;
    const base_digits = [2][verify_msm.digits_len]i8{
        verify_msm.naf(base_width, base[0]),
        verify_msm.naf(base_width, base[1]),
    };
    var digits: [2][verify_msm.digits_len]i8 = undefined;
    var tables: [2][1 << (width - 2)]Operand = undefined;
    for (terms, &digits, &tables) |term, *d, *table| {
        d.* = verify_msm.naf(width, term[1]);
        table.* = odd_multiples(1 << (width - 2), term[0]);
    }
    const all = base_digits ++ digits;
    var index = verify_msm.top_digit(&all) orelse return .{ Fe.zero, Fe.one, Fe.one };
    var sum = identity;
    index += 1;
    while (index > 0) {
        index -= 1;
        var step = double(sum);
        inline for (0..2) |t| step = add_digit(step, &base_tables[t], base_digits[t][index]);
        inline for (0..2) |t| step = add_digit(step, &tables[t], digits[t][index]);
        sum = finish(step);
    }
    // Multiplying by the cofactor (8) maps the sum into the prime-order subgroup.
    inline for (0..3) |_| sum = finish(double(sum));
    const coordinates = store(sum);
    assert(coordinates[2].isZero() == false);
    return coordinates[0..3].*;
}

const testing = std.testing;

/// Whether two projective `[X, Y, Z]` are the same point.
fn same_point(a: [3]Fe, b: [3]Fe) bool {
    return a[0].mul(b[2]).equivalent(b[0].mul(a[2])) and
        a[1].mul(b[2]).equivalent(b[1].mul(a[2]));
}

test "the IFMA and scalar backends agree" {
    if (comptime !available) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x1f3a);
    const random = prng.random();
    const scalars = [_]u128{ 0, 1, 2, std.math.maxInt(u128), 1 << 127 };
    for (0..256) |index| {
        var seed: [32]u8 = undefined;
        random.bytes(&seed);
        var p = try Point.basePoint.mulPublic(Point.scalar.reduce(seed));
        p = .{ .x = p.x, .y = p.y, .z = p.z, .t = p.t };
        if (index % 3 == 0) p = p.add(torsion_point());
        assert(!p.z.isZero());
        var values: [4]u128 = undefined;
        for (&values, 0..) |*value, slot| {
            const edge = (index + slot) % 8;
            value.* = if (edge < scalars.len) scalars[edge] else random.int(u128);
        }
        const terms = [2]verify_msm.Term{ .{ p, values[2] }, .{ p.neg().dbl(), values[3] } };
        const base = [2]u128{ values[0], values[1] };
        const expected = verify_msm.scalar_cofactored_sum(base, terms);
        const actual = cofactored_sum(base, terms);
        try testing.expect(same_point(expected, actual));
    }
}

/// A point of order 8, so every third test point has a torsion component.
fn torsion_point() Point {
    // A canonical encoding of an order-8 point (ZIP-215's small-order list): it decodes.
    const mixed = Point.fromBytes(.{
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
        0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
        0x6d, 0x53, 0xfc, 0x05,
    }) catch unreachable;
    return .{ .x = mixed.x, .y = mixed.y, .z = mixed.z, .t = mixed.t };
}
