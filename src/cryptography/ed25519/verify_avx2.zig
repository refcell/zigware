//! curve25519-dalek's AVX2 backend (`backend/vector/avx2`, curve25519-dalek 5.0.0), which
//! commonware's ed25519 batch verification uses on x86-64 CPUs with AVX2: the four coordinates
//! of an extended point `(X, Y, Z, T)` are one field element each in four lanes `A B C D`, in
//! radix 2^25.5, and Hisil-Wong-Carter-Dawson's parallel formulas add and double them four
//! multiplications at a time.
//!
//! A field element is five `u32x8` vectors. Vector `i` holds limbs `2i` and `2i + 1` of the four
//! lanes as `[a_2i, b_2i, a_2i+1, b_2i+1, c_2i, d_2i, c_2i+1, d_2i+1]`, dalek's layout, so the
//! 32x32 -> 64-bit products (`vpmuludq`) read even lanes and no shuffle crosses a 128-bit half
//! when unpacking. The arithmetic wraps, as AVX2's does: dalek computes some lanes and then
//! blends them away, and those lanes may wrap. Every operation is portable Zig vector code, so
//! the backend runs (more slowly) where AVX2 is missing, and tests exercise it everywhere;
//! `available` says when the bucket MSM should pick it.
//!
//! The interface matches `verify_ifma.zig`'s: `PackedPoint` (`identity_element`, `from_point`,
//! `to_point`, `add_cached`, `add_point`, `dbl`) and `PackedCached` (`from_point`,
//! `from_packed`). Every result is an extended point with a valid `T`, scaled by a common factor
//! (dalek's cached form is scaled by 121666), so it is the same projective point.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const Point = std.crypto.ecc.Edwards25519;
const Fe = Point.Fe;

/// True when the target has AVX2, so these vectors compile to it.
pub const available = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

const U32x8 = @Vector(8, u32);
const U64x4 = @Vector(4, u64);

const a_lanes: u8 = 0b0000_0101;
const b_lanes: u8 = 0b0000_1010;
const c_lanes: u8 = 0b0101_0000;
const d_lanes: u8 = 0b1010_0000;

/// The `u32` lanes whose bit is set in `bits`.
fn lane_mask(comptime bits: u8) @Vector(8, bool) {
    var mask: [8]bool = undefined;
    for (&mask, 0..) |*lane, index| lane.* = (bits >> index) & 1 == 1;
    return mask;
}

/// Which coordinates a blend takes from its second operand.
const Lanes = enum {
    c,
    d,
    ab,
    ac,
    cd,
    ad,
    bc,
    abcd,

    fn bits(comptime lanes: Lanes) u8 {
        return switch (lanes) {
            .c => c_lanes,
            .d => d_lanes,
            .ab => a_lanes | b_lanes,
            .ac => a_lanes | c_lanes,
            .cd => c_lanes | d_lanes,
            .ad => a_lanes | d_lanes,
            .bc => b_lanes | c_lanes,
            .abcd => a_lanes | b_lanes | c_lanes | d_lanes,
        };
    }
};

/// A permutation of the coordinates, named by the source of each destination lane.
const Shuffle = enum {
    aaaa,
    bbbb,
    caca,
    dbbd,
    adda,
    cbcb,
    abab,
    badc,
    bacd,
    abdc,

    /// dalek's `_mm256_permutevar8x32_epi32` control: destination lane `i` reads `mask[i]`.
    fn mask(comptime shuffle: Shuffle) [8]i32 {
        return switch (shuffle) {
            .aaaa => .{ 0, 0, 2, 2, 0, 0, 2, 2 },
            .bbbb => .{ 1, 1, 3, 3, 1, 1, 3, 3 },
            .caca => .{ 4, 0, 6, 2, 4, 0, 6, 2 },
            .dbbd => .{ 5, 1, 7, 3, 1, 5, 3, 7 },
            .adda => .{ 0, 5, 2, 7, 5, 0, 7, 2 },
            .cbcb => .{ 4, 1, 6, 3, 4, 1, 6, 3 },
            .abab => .{ 0, 1, 2, 3, 0, 1, 2, 3 },
            .badc => .{ 1, 0, 3, 2, 5, 4, 7, 6 },
            .bacd => .{ 1, 0, 3, 2, 4, 5, 6, 7 },
            .abdc => .{ 0, 1, 2, 3, 5, 4, 7, 6 },
        };
    }
};

/// `_mm256_mul_epu32`: the 64-bit products of the even `u32` lanes.
inline fn mul32(x: U32x8, y: U32x8) U64x4 {
    const low: U64x4 = @splat(0xffff_ffff);
    return (@as(U64x4, @bitCast(x)) & low) *% (@as(U64x4, @bitCast(y)) & low);
}

/// `mul32` read back as `u32` lanes (for products known to fit in 32 bits).
inline fn mul32_lo(x: U32x8, y: U32x8) U32x8 {
    return @bitCast(mul32(x, y));
}

/// Spreads the even limbs `[a, b, c, d]` and the odd limbs into the even lanes of two vectors.
inline fn unpack_pair(src: U32x8) [2]U32x8 {
    const zero: U32x8 = @splat(0);
    return .{
        @shuffle(u32, src, zero, [8]i32{ 0, -1, 1, -1, 4, -1, 5, -1 }),
        @shuffle(u32, src, zero, [8]i32{ 2, -1, 3, -1, 6, -1, 7, -1 }),
    };
}

/// The inverse of `unpack_pair` for values below 2^32 in the even lanes of `x` and `y`.
inline fn repack_pair(x: U32x8, y: U32x8) U32x8 {
    return @shuffle(u32, x, y, [8]i32{ 0, 2, -1, -3, 4, 6, -5, -7 });
}

/// `[lo, hi]`: the limbs of `2^k p` in every lane, for limbs 0 and 1 (`lo`) and for every other
/// limb pair (`hi`), as dalek's `P_TIMES_*` constants.
fn times(comptime k: u5, comptime low: u32, comptime high: u32) [2]U32x8 {
    const odd: u32 = 33554431 << k;
    return .{
        .{ low << k, low << k, odd, odd, low << k, low << k, odd, odd },
        .{ high << k, high << k, odd, odd, high << k, high << k, odd, odd },
    };
}

/// `2p` and `16p` per lane, as the low vector (limbs 0 and 1) and every other vector.
const p_times_2 = times(1, 67108845, 67108863);
const p_times_16 = times(4, 67108845, 67108863);

/// Four field elements in radix 2^25.5 (dalek `FieldElement2625x4`).
const Fe4 = struct {
    v: [5]U32x8,

    const zero: Fe4 = .{ .v = @splat(@splat(0)) };

    /// Packs four field elements, reducing their limbs first.
    fn init(lanes: [4]Fe) Fe4 {
        var out: [5]U32x8 = undefined;
        const low_26_bits: u64 = (1 << 26) - 1;
        var limbs: [4][5]u64 = undefined;
        for (&limbs, lanes) |*limb, fe| limb.* = weak_reduce(fe).limbs;
        for (&out, 0..) |*vector, i| {
            var lane: [8]u32 = undefined;
            for (0..4) |coordinate| {
                const base: usize = if (coordinate < 2) coordinate else coordinate + 2;
                lane[base] = @intCast(limbs[coordinate][i] & low_26_bits);
                lane[base + 2] = @intCast(limbs[coordinate][i] >> 26);
            }
            vector.* = lane;
        }
        return (Fe4{ .v = out }).reduce();
    }

    /// The four field elements, weakly reduced.
    fn split(fe: Fe4) [4]Fe {
        var out: [4]Fe = undefined;
        for (&out, 0..) |*lane, coordinate| {
            const base: usize = if (coordinate < 2) coordinate else coordinate + 2;
            for (&lane.limbs, fe.v) |*limb, vector| {
                const values: [8]u32 = vector;
                limb.* = @as(u64, values[base]) + (@as(u64, values[base + 2]) << 26);
            }
            lane.* = weak_reduce(lane.*);
        }
        return out;
    }

    fn shuffle(fe: Fe4, comptime control: Shuffle) Fe4 {
        var out: Fe4 = undefined;
        for (&out.v, fe.v) |*vector, source| {
            vector.* = @shuffle(u32, source, undefined, control.mask());
        }
        return out;
    }

    /// `fe` with the coordinates named by `control` taken from `other`.
    fn blend(fe: Fe4, other: Fe4, comptime control: Lanes) Fe4 {
        const mask = comptime lane_mask(control.bits());
        var out: Fe4 = undefined;
        for (&out.v, fe.v, other.v) |*vector, x, y| vector.* = @select(u32, mask, y, x);
        return out;
    }

    fn add(fe: Fe4, other: Fe4) Fe4 {
        var out: Fe4 = undefined;
        for (&out.v, fe.v, other.v) |*vector, x, y| vector.* = x +% y;
        return out;
    }

    /// `2p - fe` without reducing (dalek `negate_lazy`).
    fn negate_lazy(fe: Fe4) Fe4 {
        var out: Fe4 = undefined;
        out.v[0] = p_times_2[0] -% fe.v[0];
        for (out.v[1..], fe.v[1..]) |*vector, x| vector.* = p_times_2[1] -% x;
        return out;
    }

    /// `16p - fe`, reduced.
    fn neg(fe: Fe4) Fe4 {
        var out: Fe4 = undefined;
        out.v[0] = p_times_16[0] -% fe.v[0];
        for (out.v[1..], fe.v[1..]) |*vector, x| vector.* = p_times_16[1] -% x;
        return out.reduce();
    }

    /// `(B - A, B + A, D - C, D + C)` from `(A, B, C, D)`.
    fn diff_sum(fe: Fe4) Fe4 {
        const swapped = fe.shuffle(.badc);
        return swapped.add(fe.blend(fe.negate_lazy(), .ac));
    }

    /// One carry pass from every limb to the next, the top limb's carry wrapping as `19 c`.
    fn reduce(fe: Fe4) Fe4 {
        const shifts: @Vector(8, u5) = .{ 26, 26, 25, 25, 26, 26, 25, 25 };
        const masks: U32x8 = .{
            (1 << 26) - 1, (1 << 26) - 1, (1 << 25) - 1, (1 << 25) - 1,
            (1 << 26) - 1, (1 << 26) - 1, (1 << 25) - 1, (1 << 25) - 1,
        };
        const zero_vector: U32x8 = @splat(0);
        const high = comptime lane_mask(0b1100_1100);
        var v = fe.v;
        var carries: [5]U32x8 = undefined;
        // Each limb's carry, moved to the next limb's lanes (dalek `rotated_carryout`).
        const rotate = [8]i32{ 2, 3, 0, 1, 6, 7, 4, 5 };
        for (&carries, v) |*carry_out, vector| {
            carry_out.* = @shuffle(u32, vector >> shifts, undefined, rotate);
        }
        for (&v, 0..) |*vector, i| {
            const below = if (i == 0) zero_vector else carries[i - 1];
            vector.* = (vector.* & masks) +% @select(u32, high, carries[i], below);
        }
        const c9: U32x8 = carries[4] *% @as(U32x8, @splat(19));
        v[0] +%= @select(u32, comptime lane_mask(0b0011_0011), c9, zero_vector);
        return .{ .v = v };
    }

    /// Carries ten 64-bit limb products down to radix 2^25.5 and packs them.
    fn reduce64(products: [10]U64x4) Fe4 {
        var z = products;
        const low_25_bits: U64x4 = @splat((1 << 25) - 1);
        const low_26_bits: U64x4 = @splat((1 << 26) - 1);
        const order = [_]usize{ 0, 4, 1, 5, 2, 6, 3, 7, 4, 8 };
        for (order) |i| carry(&z, i, low_25_bits, low_26_bits);
        const c = z[9] >> @splat(25);
        z[9] &= low_25_bits;
        const nineteen: U64x4 = @splat(19);
        z[0] +%= (c & low_26_bits) *% nineteen;
        z[1] +%= (c >> @splat(26)) *% nineteen;
        carry(&z, 0, low_25_bits, low_26_bits);
        var out: Fe4 = undefined;
        for (&out.v, 0..) |*vector, i| {
            vector.* = repack_pair(@bitCast(z[2 * i]), @bitCast(z[2 * i + 1]));
        }
        return out;
    }

    inline fn carry(z: *[10]U64x4, i: usize, low_25_bits: U64x4, low_26_bits: U64x4) void {
        assert(i < 9);
        if (i % 2 == 0) {
            z[i + 1] +%= z[i] >> @splat(26);
            z[i] &= low_26_bits;
        } else {
            z[i + 1] +%= z[i] >> @splat(25);
            z[i] &= low_25_bits;
        }
    }

    /// Multiplies lane `A` by `scalars[0]`, ..., lane `D` by `scalars[3]` (each below 2^32).
    fn mul_small(fe: Fe4, scalars: [4]u32) Fe4 {
        const consts: U32x8 = .{ scalars[0], 0, scalars[1], 0, scalars[2], 0, scalars[3], 0 };
        var products: [10]U64x4 = undefined;
        for (fe.v, 0..) |vector, i| {
            const pair = unpack_pair(vector);
            products[2 * i] = mul32(pair[0], consts);
            products[2 * i + 1] = mul32(pair[1], consts);
        }
        return reduce64(products);
    }

    /// Lane-wise product (dalek `Mul<&FieldElement2625x4>`), `fe` being the left operand.
    fn mul(fe: Fe4, rhs: Fe4) Fe4 {
        var x: [10]U32x8 = undefined;
        var y: [10]U32x8 = undefined;
        for (0..5) |i| {
            x[2 * i], x[2 * i + 1] = unpack_pair(fe.v[i]);
            y[2 * i], y[2 * i + 1] = unpack_pair(rhs.v[i]);
        }
        const v19: U32x8 = .{ 19, 0, 19, 0, 19, 0, 19, 0 };
        // y_k_19 = 19 y_k for k >= 1, and x_k_2 = 2 x_k for odd k (dalek's bounds keep both
        // within 32 bits).
        var y19: [10]U32x8 = undefined;
        for (1..10) |k| y19[k] = mul32_lo(v19, y[k]);
        var x2: [10]U32x8 = x;
        for ([_]usize{ 1, 3, 5, 7, 9 }) |k| x2[k] = x[k] +% x[k];
        // z_k = sum_{i+j=k} x_i y_j + 19 sum_{i+j=k+10} x_i y_j, with x_i doubled when i and j
        // are both odd (the radix-2^25.5 rule), as dalek writes out term by term.
        var z: [10]U64x4 = undefined;
        inline for (0..10) |k| {
            var sum: U64x4 = @splat(0);
            inline for (0..10) |i| {
                const wraps = i > k;
                const j = if (wraps) k + 10 - i else k - i;
                const left = if (i % 2 == 1 and j % 2 == 1) x2[i] else x[i];
                sum +%= mul32(left, if (wraps) y19[j] else y[j]);
            }
            z[k] = sum;
        }
        return reduce64(z);
    }

    /// `(A^2, B^2, C^2, -D^2)` for lanes `(A, B, C, D)` (dalek `square_and_negate_D`).
    fn square_and_negate_d(fe: Fe4) Fe4 {
        var x: [10]U32x8 = undefined;
        for (0..5) |i| x[2 * i], x[2 * i + 1] = unpack_pair(fe.v[i]);
        const v19: U32x8 = .{ 19, 0, 19, 0, 19, 0, 19, 0 };
        var x2: [10]U32x8 = undefined;
        for (0..8) |k| x2[k] = x[k] << @splat(1);
        var x19: [10]U32x8 = undefined;
        for (5..10) |k| x19[k] = mul32_lo(v19, x[k]);
        const m = mul32;
        const one: @Vector(4, u6) = @splat(1);
        var z: [10]U64x4 = .{
            m(x[0], x[0]) +% m(x2[2], x19[8]) +% m(x2[4], x19[6]) +%
                ((m(x2[1], x19[9]) +% m(x2[3], x19[7]) +% m(x[5], x19[5])) << one),
            m(x2[0], x[1]) +% m(x2[3], x19[8]) +% m(x2[5], x19[6]) +%
                ((m(x[2], x19[9]) +% m(x[4], x19[7])) << one),
            m(x2[0], x[2]) +% m(x2[1], x[1]) +% m(x2[4], x19[8]) +% m(x[6], x19[6]) +%
                ((m(x2[3], x19[9]) +% m(x2[5], x19[7])) << one),
            m(x2[0], x[3]) +% m(x2[1], x[2]) +% m(x2[5], x19[8]) +%
                ((m(x[4], x19[9]) +% m(x[6], x19[7])) << one),
            m(x2[0], x[4]) +% m(x2[1], x2[3]) +% m(x[2], x[2]) +% m(x2[6], x19[8]) +%
                ((m(x2[5], x19[9]) +% m(x[7], x19[7])) << one),
            m(x2[0], x[5]) +% m(x2[1], x[4]) +% m(x2[2], x[3]) +% m(x2[7], x19[8]) +%
                (m(x[6], x19[9]) << one),
            m(x2[0], x[6]) +% m(x2[1], x2[5]) +% m(x2[2], x[4]) +% m(x2[3], x[3]) +%
                m(x[8], x19[8]) +% (m(x2[7], x19[9]) << one),
            m(x2[0], x[7]) +% m(x2[1], x[6]) +% m(x2[2], x[5]) +% m(x2[3], x[4]) +%
                (m(x[8], x19[9]) << one),
            m(x2[0], x[8]) +% m(x2[1], x2[7]) +% m(x2[2], x[6]) +% m(x2[3], x2[5]) +%
                m(x[4], x[4]) +% (m(x[9], x19[9]) << one),
            m(x2[0], x[9]) +% m(x2[1], x[8]) +% m(x2[2], x[7]) +% m(x2[3], x[6]) +%
                m(x2[4], x[5]),
        };
        // Negates lane D by subtracting from 2^37 p, limb by limb.
        const low_p37: U64x4 = @splat(0x3ffffed << 37);
        const even_p37: U64x4 = @splat(0x3ffffff << 37);
        const odd_p37: U64x4 = @splat(0x1ffffff << 37);
        const lane_d: @Vector(4, bool) = .{ false, false, false, true };
        for (&z, 0..) |*limb, k| {
            const p37 = if (k == 0) low_p37 else if (k % 2 == 0) even_p37 else odd_p37;
            limb.* = @select(u64, lane_d, p37 -% limb.*, limb.*);
        }
        return reduce64(z);
    }
};

/// The 51-bit-limb form `std.crypto` expects: one carry pass, the top carry wrapping as 19.
fn weak_reduce(fe: Fe) Fe {
    var limbs = fe.limbs;
    const mask: u64 = (1 << 51) - 1;
    var carry: u64 = 0;
    for (&limbs) |*limb| {
        const value = limb.* + carry;
        carry = value >> 51;
        limb.* = value & mask;
    }
    limbs[0] += 19 * carry;
    return .{ .limbs = limbs };
}

/// An extended point `(X, Y, Z, T)` in four lanes (dalek `avx2::edwards::ExtendedPoint`).
pub const PackedPoint = struct {
    fe: Fe4,

    /// `(0, 1, 1, 0)`: lanes B and C of limb 0 are one.
    pub const identity_element: PackedPoint = .{ .fe = .{ .v = .{
        .{ 0, 1, 0, 0, 1, 0, 0, 0 },
        @splat(0),
        @splat(0),
        @splat(0),
        @splat(0),
    } } };

    pub fn from_point(point: Point) PackedPoint {
        return .{ .fe = .init(.{ point.x, point.y, point.z, point.t }) };
    }

    pub fn to_point(packed_point: PackedPoint) Point {
        const lanes = packed_point.fe.split();
        return .{ .x = lanes[0], .y = lanes[1], .z = lanes[2], .t = lanes[3] };
    }

    /// `self + q`, or `self - q` when `negate`.
    pub fn add_cached(self: PackedPoint, q: *const PackedCached, negate: bool) PackedPoint {
        const operand = if (negate) q.neg() else q.*;
        var tmp = self.fe;
        tmp = tmp.blend(tmp.diff_sum(), .ab);
        tmp = tmp.mul(operand.fe);
        tmp = tmp.shuffle(.abdc);
        tmp = tmp.diff_sum();
        const t0 = tmp.shuffle(.adda);
        const t1 = tmp.shuffle(.cbcb);
        return .{ .fe = t0.mul(t1) };
    }

    pub fn add_point(self: PackedPoint, other: PackedPoint) PackedPoint {
        return self.add_cached(&PackedCached.from_packed(other), false);
    }

    pub fn dbl(self: PackedPoint) PackedPoint {
        var tmp0 = self.fe.shuffle(.abab);
        var tmp1 = tmp0.shuffle(.badc);
        tmp0 = self.fe.blend(tmp0.add(tmp1), .d);
        tmp1 = tmp0.square_and_negate_d();
        const s1 = tmp1.shuffle(.aaaa);
        const s2 = tmp1.shuffle(.bbbb);
        tmp0 = Fe4.zero.blend(tmp1.add(tmp1), .c);
        tmp0 = tmp0.blend(tmp1, .d);
        tmp0 = tmp0.add(s1);
        tmp0 = tmp0.add(Fe4.zero.blend(s2, .ad));
        tmp0 = tmp0.add(Fe4.zero.blend(s2.negate_lazy(), .bc));
        tmp1 = tmp0.shuffle(.dbbd);
        tmp0 = tmp0.shuffle(.caca);
        return .{ .fe = tmp0.mul(tmp1) };
    }
};

/// A point prepared for addition, `121666 (Y - X, Y + X, 2 Z, 2 d T)` with `d = -121665/121666`
/// (dalek `avx2::edwards::CachedPoint`); `Z` may be any nonzero value.
pub const PackedCached = struct {
    fe: Fe4,

    pub fn from_point(point: Point) PackedCached {
        return from_packed(.from_point(point));
    }

    pub fn from_packed(packed_point: PackedPoint) PackedCached {
        var x = packed_point.fe;
        x = x.blend(x.diff_sum(), .ab);
        x = x.mul_small(.{ 121666, 121666, 2 * 121666, 2 * 121665 });
        x = x.blend(x.neg(), .d);
        return .{ .fe = x };
    }

    /// The cached form of the negated point: swap `Y - X` and `Y + X`, negate `2 d T`.
    fn neg(cached: PackedCached) PackedCached {
        const swapped = cached.fe.shuffle(.bacd);
        return .{ .fe = swapped.blend(swapped.negate_lazy(), .d) };
    }
};

comptime {
    assert(@sizeOf(PackedPoint) == 5 * 32);
}
