//! `pow2523` for point decompression and `invert` for point encoding, on std's radix-2^51
//! field elements, with a faster squaring than std's: std widens every limb to `u128` before
//! it multiplies, so LLVM emits a 128x128-bit product per term. Here the small coefficients
//! (2, 19, 38) fold into `u64` limbs first, so each term is one 64x64-bit widening multiply,
//! and the carry runs in two parallel stages instead of one serial chain. The exponent chains
//! are std's, so results are identical.

const std = @import("std");
const assert = std.debug.assert;

const Point = std.crypto.ecc.Edwards25519;
const Fe = Point.Fe;
const mask_51: u64 = (1 << 51) - 1;
/// Every limb `square` takes and returns is below this.
const limb_bound: u64 = 1 << 52;

inline fn wide_mul(x: u64, y: u64) u128 {
    return @as(u128, x) * y;
}

/// `a^2` with limbs below 2^52 in and out.
///
/// Bounds: 38 a < 2^58 fits a limb; each column is at most 59 * 2^104 < 2^110. Only column 4
/// wraps into limb 0 times 19, and its coefficients sum to 5, so its carry is below 2^56 and
/// 19 times it below 2^61. After the first stage every limb is below 2^51 + 2^61, so the second
/// stage's carries are below 2^11 (times 19 below 2^16), leaving limbs below 2^51 + 2^16.
inline fn square(a: [5]u64) [5]u64 {
    const d0 = 2 * a[0];
    const d1 = 2 * a[1];
    const e1 = 38 * a[1];
    const e2 = 38 * a[2];
    const e3 = 38 * a[3];
    const f3 = 19 * a[3];
    const f4 = 19 * a[4];
    const columns = [5]u128{
        wide_mul(a[0], a[0]) + wide_mul(e1, a[4]) + wide_mul(e2, a[3]),
        wide_mul(d0, a[1]) + wide_mul(e2, a[4]) + wide_mul(f3, a[3]),
        wide_mul(d0, a[2]) + wide_mul(a[1], a[1]) + wide_mul(e3, a[4]),
        wide_mul(d0, a[3]) + wide_mul(d1, a[2]) + wide_mul(f4, a[4]),
        wide_mul(d0, a[4]) + wide_mul(d1, a[3]) + wide_mul(a[2], a[2]),
    };
    var stage: [5]u64 = undefined;
    inline for (0..5) |i| {
        const carry: u64 = @intCast(columns[(i + 4) % 5] >> 51);
        stage[i] = (@as(u64, @truncate(columns[i])) & mask_51) + if (i == 0) 19 * carry else carry;
    }
    var out: [5]u64 = undefined;
    inline for (0..5) |i| {
        const carry = stage[(i + 4) % 5] >> 51;
        out[i] = (stage[i] & mask_51) + if (i == 0) 19 * carry else carry;
    }
    return out;
}

/// `a^(2^count)`.
fn square_n(a: Fe, count: u32) Fe {
    assert(count > 0);
    for (a.limbs) |limb| assert(limb < limb_bound);
    var limbs = a.limbs;
    for (0..count) |_| limbs = square(limbs);
    return .{ .limbs = limbs };
}

/// `a^((p-5)/8) = a^(2^252-3)`, as std's `Fe.pow2523` (the same addition chain).
pub fn pow2523(a: Fe) Fe {
    for (a.limbs) |limb| assert(limb < limb_bound);
    var t0 = a.mul(square_n(a, 1));
    var t1 = square_n(t0.mul(square_n(t0, 2)), 1).mul(a);
    t0 = square_n(t1, 5).mul(t1);
    var t2 = square_n(t0, 5).mul(t1);
    t1 = square_n(t2, 15).mul(t2);
    t2 = square_n(t1, 30).mul(t1);
    t1 = square_n(t2, 60).mul(t2);
    const result = square_n(square_n(square_n(t1, 120).mul(t1), 10).mul(t0), 2).mul(a);
    for (result.limbs) |limb| assert(limb < limb_bound);
    return result;
}

/// `a^(p-2)`, the inverse of `a` (0 for 0), as std's `Fe.invert` (the same addition chain),
/// in constant time.
pub fn invert(a: Fe) Fe {
    for (a.limbs) |limb| assert(limb < limb_bound);
    var t0 = square_n(a, 1);
    var t1 = square_n(t0, 2).mul(a);
    t0 = t0.mul(t1);
    t1 = t1.mul(square_n(t0, 1));
    t1 = t1.mul(square_n(t1, 5));
    var t2 = square_n(t1, 10).mul(t1);
    t2 = square_n(t2.mul(square_n(t2, 20)), 10);
    t1 = t1.mul(t2);
    t2 = square_n(t1, 50).mul(t1);
    const result = square_n(square_n(t2.mul(square_n(t2, 100)), 50).mul(t1), 5).mul(t0);
    for (result.limbs) |limb| assert(limb < limb_bound);
    return result;
}

/// The 32-byte encoding of `point`, as std's `Edwards25519.toBytes`.
pub fn encode(point: Point) [32]u8 {
    assert(!point.z.isZero());
    const z_inverse = invert(point.z);
    var bytes = point.y.mul(z_inverse).toBytes();
    bytes[31] ^= @as(u8, @intFromBool(point.x.mul(z_inverse).isNegative())) << 7;
    return bytes;
}

const testing = std.testing;

test "pow2523 and invert match std" {
    // Edge elements (0, 1, p - 1, every limb at its largest unreduced value), then random ones.
    const max_limb: Fe = .{ .limbs = @splat(limb_bound - 1) };
    const edges = [_]Fe{ Fe.zero, Fe.one, Fe.zero.sub(Fe.one), max_limb, Fe.edwards25519d };
    var prng = std.Random.DefaultPrng.init(0x2523);
    for (0..edges.len + 2000) |index| {
        const a = if (index < edges.len) edges[index] else element: {
            var bytes: [32]u8 = undefined;
            prng.random().bytes(&bytes);
            break :element Fe.fromBytes(bytes);
        };
        try testing.expectEqualSlices(u8, &a.pow2523().toBytes(), &pow2523(a).toBytes());
        try testing.expectEqualSlices(u8, &a.invert().toBytes(), &invert(a).toBytes());
        // Squaring alone too, on the unreduced limbs a squaring chain sees.
        const squared = square_n(a, 3);
        try testing.expectEqualSlices(u8, &a.sq().sq().sq().toBytes(), &squared.toBytes());
        for (squared.limbs) |limb| try testing.expect(limb < limb_bound);
    }
}

test "encode matches std" {
    // Multiples of the base point, so z is not one and x takes both signs.
    var point = Point.basePoint;
    for (0..64) |_| {
        try testing.expectEqualSlices(u8, &point.toBytes(), &encode(point));
        point = point.add(point.dbl());
    }
}
