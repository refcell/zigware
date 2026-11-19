//! BLS12-381 fields: the base field Fp, the scalar field Fr, and the pairing
//! tower Fp2 = Fp[u]/(u^2 + 1), Fp6 = Fp2[v]/(v^3 - (u + 1)), Fp12 = Fp6[w]/(w^2 - v).
//!
//! Fp and Fr are `montgomery.Field` instances. The tower uses Karatsuba-style
//! products. Arithmetic here is variable time only where documented (sqrt,
//! inverse via Fermat is constant time); callers of the pairing work on public data.

const std = @import("std");
const assert = std.debug.assert;
const montgomery = @import("montgomery.zig");
const Prng = @import("prng.zig").Prng;

pub const p = (0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192) |
    0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
pub const r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

pub const Fp = montgomery.Field(6, p);
pub const Fr = montgomery.Field(4, r);

comptime {
    assert(p % 4 == 3);
    assert(p % 6 == 1);
    assert(Fp.bytes_length == 48);
    assert(Fr.bytes_length == 32);
}

/// Sign of an Fp element for hash-to-curve (RFC 9380 sgn0): the parity.
pub fn fp_sgn0(a: Fp) bool {
    return a.is_odd();
}

/// Reduces a 64-byte big-endian integer modulo p (RFC 9380 hash_to_field, L = 64).
pub fn fp_from_bytes_wide(bytes: *const [64]u8) Fp {
    const high = std.mem.readInt(u128, bytes[0..16], .big);
    const low = std.mem.readInt(u384, bytes[16..64], .big);
    const two_384 = comptime Fp.from_int_comptime((1 << 384) % p);
    const result = Fp.from_int(high).mul(two_384).add(Fp.from_int(low));
    assert(!(high == 0 and low < p) or result.to_int() == low);
    return result;
}

pub const Fp2 = struct {
    c0: Fp,
    c1: Fp,

    pub const zero: Fp2 = .{ .c0 = .zero, .c1 = .zero };
    pub const one: Fp2 = .{ .c0 = .one, .c1 = .zero };

    pub fn from_ints_comptime(comptime c0: comptime_int, comptime c1: comptime_int) Fp2 {
        return .{ .c0 = Fp.from_int_comptime(c0), .c1 = Fp.from_int_comptime(c1) };
    }

    pub fn is_zero(a: Fp2) bool {
        return a.c0.is_zero() and a.c1.is_zero();
    }

    pub fn eql(a: Fp2, b: Fp2) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }

    pub fn add(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
    }

    pub fn sub(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
    }

    pub fn double(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.double(), .c1 = a.c1.double() };
    }

    pub fn neg(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg() };
    }

    pub fn conjugate(a: Fp2) Fp2 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }

    /// The p-power Frobenius is conjugation because u^p = -u.
    pub fn frobenius(a: Fp2) Fp2 {
        return a.conjugate();
    }

    /// Karatsuba with lazy reduction (blst's `mul_mont_384x`): three double-width products
    /// and two Montgomery reductions.
    pub fn mul(a: Fp2, b: Fp2) Fp2 {
        return mul_wide(a, b).reduce();
    }

    /// The product before reduction: v0 - v1 mod p R and cross - v0 - v1 = a0 b1 + a1 b0,
    /// which lies in [0, 2p^2), below p R.
    pub fn mul_wide(a: Fp2, b: Fp2) Fp2Wide {
        comptime assert(Fp.lazy_supported);
        const v0 = Fp.mul_wide(a.c0, b.c0);
        const v1 = Fp.mul_wide(a.c1, b.c1);
        const cross = Fp.mul_wide(a.c0.add_unreduced(a.c1), b.c0.add_unreduced(b.c1));
        return .{ .c0 = Fp.wide_sub_mod(v0, v1), .c1 = Fp.wide_sub(Fp.wide_sub(cross, v0), v1) };
    }

    pub fn square(a: Fp2) Fp2 {
        // (c0 + c1 u)^2 = (c0 + c1)(c0 - c1) + 2 c0 c1 u.
        const product = a.c0.mul(a.c1);
        return .{ .c0 = a.c0.add(a.c1).mul(a.c0.sub(a.c1)), .c1 = product.double() };
    }

    pub fn mul_by_fp(a: Fp2, b: Fp) Fp2 {
        return .{ .c0 = a.c0.mul(b), .c1 = a.c1.mul(b) };
    }

    /// Multiplication by the Fp6 non-residue xi = u + 1.
    pub fn mul_by_nonresidue(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.sub(a.c1), .c1 = a.c0.add(a.c1) };
    }

    /// The norm c0^2 + c1^2 in Fp.
    pub fn norm(a: Fp2) Fp {
        return a.c0.square().add(a.c1.square());
    }

    /// Multiplicative inverse; inverse(0) = 0.
    pub fn inverse(a: Fp2) Fp2 {
        const norm_inverse = a.norm().inverse();
        const result: Fp2 = .{ .c0 = a.c0.mul(norm_inverse), .c1 = a.c1.neg().mul(norm_inverse) };
        assert(a.is_zero() or a.mul(result).eql(one));
        return result;
    }

    /// a^exponent for a public exponent (square-and-multiply, MSB first).
    pub fn pow(a: Fp2, exponent: Fp.Int) Fp2 {
        var result = one;
        var index: u32 = Fp.bits;
        while (index > 0) {
            index -= 1;
            result = result.square();
            if ((exponent >> @intCast(index)) & 1 == 1) result = result.mul(a);
        }
        return result;
    }

    pub fn is_square(a: Fp2) bool {
        return a.norm().is_square();
    }

    /// Square root through Fp square roots (the complex method, Adj and Rodriguez-Henriquez
    /// Algorithm 8, as blst's `sqrt_fp2`): with s = sqrt(c0^2 + c1^2), x0 = sqrt((c0 +- s) / 2)
    /// and x1 = c1 / (2 x0). Null when `a` is not a square. Either root may come back; every
    /// caller fixes the sign. Variable time.
    pub fn sqrt(a: Fp2) ?Fp2 {
        if (a.is_zero()) return zero;
        const candidate = if (a.c1.is_zero()) sqrt_of_fp(a.c0) else sqrt_general(a) orelse
            return null;
        if (!candidate.square().eql(a)) return null;
        return candidate;
    }

    /// A root of c0 + 0u: sqrt(c0), or sqrt(-c0) u since -1 is not a square in Fp.
    fn sqrt_of_fp(c0: Fp) Fp2 {
        if (c0.sqrt()) |root| return .{ .c0 = root, .c1 = .zero };
        const root = c0.neg().sqrt().?; // Proof: c0 or -c0 is a square, as -1 is not.
        return .{ .c0 = .zero, .c1 = root };
    }

    fn sqrt_general(a: Fp2) ?Fp2 {
        assert(!a.c1.is_zero());
        const half = comptime Fp.from_int_comptime((p + 1) / 2);
        const s = a.norm().sqrt() orelse return null;
        // t (c0 - s) / 2 = -c1^2 / 4 is not a square, so exactly one of t and (c0 - s) / 2
        // is. y = t^((p + 1) / 4) squares to t or -t; in the second case (c1 / (2y))^2 =
        // -c1^2 / (4t) = (c0 - s) / 2, so one exponentiation serves both (as blst).
        const t = a.c0.add(s).mul(half);
        // t != 0: otherwise c0 = -s, so c1^2 = s^2 - c0^2 = 0.
        assert(!t.is_zero());
        const y = t.pow((p + 1) / 4);
        const y_square = y.square();
        const other = a.c1.mul(y.double().inverse());
        if (y_square.eql(t)) return .{ .c0 = y, .c1 = other };
        assert(y_square.eql(t.neg()));
        return .{ .c0 = other, .c1 = y };
    }

    /// RFC 9380 sgn0 for m = 2.
    pub fn sgn0(a: Fp2) bool {
        const sign_0 = a.c0.is_odd();
        const zero_0 = a.c0.is_zero();
        const sign_1 = a.c1.is_odd();
        return sign_0 or (zero_0 and sign_1);
    }
};

/// xi^((p - 1) / 3) and xi^(2 (p - 1) / 3): Frobenius coefficients of v and v^2.
const frobenius_v = Fp2.from_ints_comptime(
    0,
    0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4 << 192 |
        0x897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac,
);
const frobenius_v2 = Fp2.from_ints_comptime(
    0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4 << 192 |
        0x897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad,
    0,
);
/// xi^((p - 1) / 6): Frobenius coefficient of w.
const frobenius_w = Fp2.from_ints_comptime(
    0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f << 192 |
        0x7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8,
    0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36f << 192 |
        0xec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3,
);

/// An Fp2 element as two double-width values below p R, before Montgomery reduction
/// (blst's vec384x2): the lazy tower adds products here and reduces each coefficient once.
pub const Fp2Wide = struct {
    c0: Fp.WideLimbs,
    c1: Fp.WideLimbs,

    pub fn add(a: Fp2Wide, b: Fp2Wide) Fp2Wide {
        return .{ .c0 = Fp.wide_add_mod(a.c0, b.c0), .c1 = Fp.wide_add_mod(a.c1, b.c1) };
    }

    pub fn sub(a: Fp2Wide, b: Fp2Wide) Fp2Wide {
        return .{ .c0 = Fp.wide_sub_mod(a.c0, b.c0), .c1 = Fp.wide_sub_mod(a.c1, b.c1) };
    }

    /// Multiplication by xi = u + 1: (c0 - c1) + (c0 + c1) u.
    pub fn mul_by_nonresidue(a: Fp2Wide) Fp2Wide {
        return .{ .c0 = Fp.wide_sub_mod(a.c0, a.c1), .c1 = Fp.wide_add_mod(a.c0, a.c1) };
    }

    pub fn reduce(a: Fp2Wide) Fp2 {
        return .{ .c0 = Fp.reduce_wide(a.c0), .c1 = Fp.reduce_wide(a.c1) };
    }
};

/// An Fp6 element with double-width Fp2 coefficients (blst's vec384fp6x2).
const Fp6Wide = struct {
    c0: Fp2Wide,
    c1: Fp2Wide,
    c2: Fp2Wide,

    fn add(a: Fp6Wide, b: Fp6Wide) Fp6Wide {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1), .c2 = a.c2.add(b.c2) };
    }

    fn sub(a: Fp6Wide, b: Fp6Wide) Fp6Wide {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1), .c2 = a.c2.sub(b.c2) };
    }

    /// Multiplication by v (the Fp12 non-residue).
    fn mul_by_nonresidue(a: Fp6Wide) Fp6Wide {
        return .{ .c0 = a.c2.mul_by_nonresidue(), .c1 = a.c0, .c2 = a.c1 };
    }

    fn reduce(a: Fp6Wide) Fp6 {
        return .{ .c0 = a.c0.reduce(), .c1 = a.c1.reduce(), .c2 = a.c2.reduce() };
    }
};

pub const Fp6 = struct {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,

    pub const zero: Fp6 = .{ .c0 = .zero, .c1 = .zero, .c2 = .zero };
    pub const one: Fp6 = .{ .c0 = .one, .c1 = .zero, .c2 = .zero };

    pub fn is_zero(a: Fp6) bool {
        return a.c0.is_zero() and a.c1.is_zero() and a.c2.is_zero();
    }

    pub fn eql(a: Fp6, b: Fp6) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1) and a.c2.eql(b.c2);
    }

    pub fn add(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1), .c2 = a.c2.add(b.c2) };
    }

    pub fn sub(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1), .c2 = a.c2.sub(b.c2) };
    }

    pub fn neg(a: Fp6) Fp6 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg(), .c2 = a.c2.neg() };
    }

    pub fn double(a: Fp6) Fp6 {
        return .{ .c0 = a.c0.double(), .c1 = a.c1.double(), .c2 = a.c2.double() };
    }

    pub fn mul(a: Fp6, b: Fp6) Fp6 {
        return mul_wide(a, b).reduce();
    }

    /// Karatsuba over Fp2 with lazy reduction (blst's mul_fp6x2): six double-width Fp2
    /// products combined modulo p R, before any reduction.
    fn mul_wide(a: Fp6, b: Fp6) Fp6Wide {
        const aa = Fp2.mul_wide(a.c0, b.c0);
        const bb = Fp2.mul_wide(a.c1, b.c1);
        const cc = Fp2.mul_wide(a.c2, b.c2);
        const t1 = Fp2.mul_wide(a.c1.add(a.c2), b.c1.add(b.c2)).sub(bb).sub(cc)
            .mul_by_nonresidue().add(aa);
        const t2 = Fp2.mul_wide(a.c0.add(a.c1), b.c0.add(b.c1)).sub(aa).sub(bb)
            .add(cc.mul_by_nonresidue());
        const t3 = Fp2.mul_wide(a.c0.add(a.c2), b.c0.add(b.c2)).sub(aa).add(bb).sub(cc);
        return .{ .c0 = t1, .c1 = t2, .c2 = t3 };
    }

    /// Squaring (Chung-Hasan SQR2).
    pub fn square(a: Fp6) Fp6 {
        const s0 = a.c0.square();
        const ab = a.c0.mul(a.c1);
        const s1 = ab.double();
        const s2 = a.c0.sub(a.c1).add(a.c2).square();
        const bc = a.c1.mul(a.c2);
        const s3 = bc.double();
        const s4 = a.c2.square();
        return .{
            .c0 = s3.mul_by_nonresidue().add(s0),
            .c1 = s4.mul_by_nonresidue().add(s1),
            .c2 = s1.add(s2).add(s3).sub(s0).sub(s4),
        };
    }

    pub fn mul_by_fp2(a: Fp6, b: Fp2) Fp6 {
        return .{ .c0 = a.c0.mul(b), .c1 = a.c1.mul(b), .c2 = a.c2.mul(b) };
    }

    /// Multiplication by v (the Fp12 non-residue).
    pub fn mul_by_nonresidue(a: Fp6) Fp6 {
        return .{ .c0 = a.c2.mul_by_nonresidue(), .c1 = a.c0, .c2 = a.c1 };
    }

    /// Product with the sparse element b1 v.
    pub fn mul_by_1(a: Fp6, b1: Fp2) Fp6 {
        return mul_by_1_wide(a, b1).reduce();
    }

    fn mul_by_1_wide(a: Fp6, b1: Fp2) Fp6Wide {
        return .{
            .c0 = Fp2.mul_wide(a.c2, b1).mul_by_nonresidue(),
            .c1 = Fp2.mul_wide(a.c0, b1),
            .c2 = Fp2.mul_wide(a.c1, b1),
        };
    }

    /// Product with the sparse element b0 + b1 v.
    pub fn mul_by_01(a: Fp6, b0: Fp2, b1: Fp2) Fp6 {
        return mul_by_01_wide(a, b0, b1).reduce();
    }

    fn mul_by_01_wide(a: Fp6, b0: Fp2, b1: Fp2) Fp6Wide {
        const aa = Fp2.mul_wide(a.c0, b0);
        const bb = Fp2.mul_wide(a.c1, b1);
        const t1 = Fp2.mul_wide(a.c2, b1).mul_by_nonresidue().add(aa);
        const t2 = Fp2.mul_wide(b0.add(b1), a.c0.add(a.c1)).sub(aa).sub(bb);
        const t3 = Fp2.mul_wide(a.c2, b0).add(bb);
        return .{ .c0 = t1, .c1 = t2, .c2 = t3 };
    }

    pub fn inverse(a: Fp6) Fp6 {
        const t0 = a.c0.square().sub(a.c1.mul(a.c2).mul_by_nonresidue());
        const t1 = a.c2.square().mul_by_nonresidue().sub(a.c0.mul(a.c1));
        const t2 = a.c1.square().sub(a.c0.mul(a.c2));
        const denominator = a.c0.mul(t0)
            .add(a.c2.mul(t1).add(a.c1.mul(t2)).mul_by_nonresidue());
        const scale = denominator.inverse();
        const result: Fp6 = .{ .c0 = t0.mul(scale), .c1 = t1.mul(scale), .c2 = t2.mul(scale) };
        assert(a.is_zero() or a.mul(result).eql(one));
        return result;
    }

    pub fn frobenius(a: Fp6) Fp6 {
        return .{
            .c0 = a.c0.frobenius(),
            .c1 = a.c1.frobenius().mul(frobenius_v),
            .c2 = a.c2.frobenius().mul(frobenius_v2),
        };
    }
};

pub const Fp12 = struct {
    c0: Fp6,
    c1: Fp6,

    pub const zero: Fp12 = .{ .c0 = .zero, .c1 = .zero };
    pub const one: Fp12 = .{ .c0 = .one, .c1 = .zero };

    pub fn is_zero(a: Fp12) bool {
        return a.c0.is_zero() and a.c1.is_zero();
    }

    pub fn eql(a: Fp12, b: Fp12) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }

    pub fn add(a: Fp12, b: Fp12) Fp12 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
    }

    pub fn sub(a: Fp12, b: Fp12) Fp12 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
    }

    /// Karatsuba over Fp6 with lazy reduction (blst's mul_fp12): three double-width Fp6
    /// products and one reduction per coefficient.
    pub fn mul(a: Fp12, b: Fp12) Fp12 {
        const aa = Fp6.mul_wide(a.c0, b.c0);
        const bb = Fp6.mul_wide(a.c1, b.c1);
        const cross = Fp6.mul_wide(a.c0.add(a.c1), b.c0.add(b.c1)).sub(aa).sub(bb);
        return .{ .c0 = bb.mul_by_nonresidue().add(aa).reduce(), .c1 = cross.reduce() };
    }

    /// (c0 + c1 w)^2 = (c0 + c1)(c0 + v c1) - c0 c1 - v c0 c1 + 2 c0 c1 w, with the c0
    /// product lazily reduced.
    pub fn square(a: Fp12) Fp12 {
        const ab = Fp6.mul_wide(a.c0, a.c1);
        const sum = a.c0.add(a.c1);
        const shifted = a.c0.add(a.c1.mul_by_nonresidue());
        const c0 = Fp6.mul_wide(shifted, sum).sub(ab).sub(ab.mul_by_nonresidue());
        return .{ .c0 = c0.reduce(), .c1 = ab.add(ab).reduce() };
    }

    /// Conjugation is the p^6-power Frobenius; it inverts unitary elements.
    pub fn conjugate(a: Fp12) Fp12 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }

    pub fn inverse(a: Fp12) Fp12 {
        const denominator = a.c0.square().sub(a.c1.square().mul_by_nonresidue());
        const scale = denominator.inverse();
        const result: Fp12 = .{ .c0 = a.c0.mul(scale), .c1 = a.c1.mul(scale).neg() };
        assert(a.is_zero() or a.mul(result).eql(one));
        return result;
    }

    pub fn frobenius(a: Fp12) Fp12 {
        const c1 = a.c1.frobenius();
        return .{ .c0 = a.c0.frobenius(), .c1 = c1.mul_by_fp2(frobenius_w) };
    }

    /// Product with the sparse line value b0 + b1 v + b4 v w (M-type twist).
    /// Product with the sparse line b0 + b1 v + b4 v w, lazily reduced (blst's
    /// mul_by_xy00z0_fp12): one reduction per coefficient.
    pub fn mul_by_014(a: Fp12, b0: Fp2, b1: Fp2, b4: Fp2) Fp12 {
        const aa = Fp6.mul_by_01_wide(a.c0, b0, b1);
        const bb = Fp6.mul_by_1_wide(a.c1, b4);
        const cross = Fp6.mul_by_01_wide(a.c1.add(a.c0), b0, b1.add(b4)).sub(aa).sub(bb);
        return .{ .c0 = bb.mul_by_nonresidue().add(aa).reduce(), .c1 = cross.reduce() };
    }

    /// Squaring in the cyclotomic subgroup (Granger-Scott).
    pub fn cyclotomic_square(a: Fp12) Fp12 {
        const t01 = fp4_square(a.c0.c0, a.c1.c1);
        const t23 = fp4_square(a.c1.c0, a.c0.c2);
        const t45 = fp4_square(a.c0.c1, a.c1.c2);
        const z0 = t01[0].sub(a.c0.c0).double().add(t01[0]);
        const z1 = t01[1].add(a.c1.c1).double().add(t01[1]);
        const z4 = t23[0].sub(a.c0.c1).double().add(t23[0]);
        const z5 = t23[1].add(a.c1.c2).double().add(t23[1]);
        const t3 = t45[1].mul_by_nonresidue();
        const z2 = t3.add(a.c1.c0).double().add(t3);
        const z3 = t45[0].sub(a.c0.c2).double().add(t45[0]);
        return .{
            .c0 = .{ .c0 = z0, .c1 = z4, .c2 = z3 },
            .c1 = .{ .c0 = z2, .c1 = z1, .c2 = z5 },
        };
    }

    fn fp4_square(a: Fp2, b: Fp2) [2]Fp2 {
        const t0 = a.square();
        const t1 = b.square();
        const c0 = t1.mul_by_nonresidue().add(t0);
        const c1 = a.add(b).square().sub(t0).sub(t1);
        return .{ c0, c1 };
    }
};

const testing = std.testing;

fn random_fp(prng: *Prng) Fp {
    return Fp.from_int(prng.int(u384));
}

fn random_fp2(prng: *Prng) Fp2 {
    return .{ .c0 = random_fp(prng), .c1 = random_fp(prng) };
}

fn random_fp6(prng: *Prng) Fp6 {
    return .{ .c0 = random_fp2(prng), .c1 = random_fp2(prng), .c2 = random_fp2(prng) };
}

pub fn random_fp12(prng: *Prng) Fp12 {
    return .{ .c0 = random_fp6(prng), .c1 = random_fp6(prng) };
}

test "fields: fp2 laws, sqrt, and frobenius" {
    var prng = Prng.init(0xb15_f2);
    for (0..20) |_| {
        const a = random_fp2(&prng);
        const b = random_fp2(&prng);
        try testing.expect(a.mul(b).eql(b.mul(a)));
        try testing.expect(a.square().eql(a.mul(a)));
        try testing.expect(a.mul(a.inverse()).eql(Fp2.one));
        const s = a.square();
        try testing.expect(s.is_square());
        const root = s.sqrt().?;
        try testing.expect(root.eql(a) or root.eql(a.neg()));
        // Every Fp element is a square in Fp2: c0 + 0u has a real or an imaginary root.
        const real: Fp2 = .{ .c0 = a.c0, .c1 = .zero };
        try testing.expect(real.sqrt().?.square().eql(real));
        // A nonzero square times the sextic non-residue is not a square.
        try testing.expect(s.mul(.{ .c0 = .one, .c1 = .one }).sqrt() == null);
        try testing.expect(a.frobenius().eql(a.pow(p)));
        try testing.expect(a.mul_by_nonresidue().eql(a.mul(.{ .c0 = .one, .c1 = .one })));
    }
    // u + 1 is not a square in Fp2 (it is the sextic non-residue).
    try testing.expect(!Fp2.is_square(.{ .c0 = .one, .c1 = .one }));
    try testing.expect(Fp2.sqrt(.{ .c0 = .one, .c1 = .one }) == null);
}

test "fields: fp6 and fp12 laws and frobenius constants" {
    var prng = Prng.init(0xb15_f12);
    const xi: Fp2 = .{ .c0 = .one, .c1 = .one };
    try testing.expect(frobenius_v.eql(xi.pow((p - 1) / 3)));
    try testing.expect(frobenius_v2.eql(xi.pow(2 * (p - 1) / 3)));
    try testing.expect(frobenius_w.eql(xi.pow((p - 1) / 6)));
    for (0..4) |_| {
        const a = random_fp6(&prng);
        const b = random_fp6(&prng);
        try testing.expect(a.square().eql(a.mul(a)));
        try testing.expect(a.mul(a.inverse()).eql(Fp6.one));
        try testing.expect(a.mul(b).mul_by_nonresidue().eql(a.mul(b.mul_by_nonresidue())));
        const f = random_fp12(&prng);
        const g = random_fp12(&prng);
        try testing.expect(f.square().eql(f.mul(f)));
        try testing.expect(f.mul(f.inverse()).eql(Fp12.one));
        try testing.expect(f.mul(g).frobenius().eql(f.frobenius().mul(g.frobenius())));
        var f6 = f;
        for (0..6) |_| f6 = f6.frobenius();
        try testing.expect(f6.eql(f.conjugate()));
        var f12 = f6;
        for (0..6) |_| f12 = f12.frobenius();
        try testing.expect(f12.eql(f));
    }
}

test "fields: sparse products and cyclotomic squaring" {
    var prng = Prng.init(0xb15_5);
    const f = random_fp12(&prng);
    const b0 = random_fp2(&prng);
    const b1 = random_fp2(&prng);
    const b4 = random_fp2(&prng);
    const sparse: Fp12 = .{
        .c0 = .{ .c0 = b0, .c1 = b1, .c2 = .zero },
        .c1 = .{ .c0 = .zero, .c1 = b4, .c2 = .zero },
    };
    try testing.expect(f.mul_by_014(b0, b1, b4).eql(f.mul(sparse)));
    // Map f into the cyclotomic subgroup: f^((p^6 - 1)(p^2 + 1)).
    const easy = f.conjugate().mul(f.inverse());
    const cyclotomic = easy.frobenius().frobenius().mul(easy);
    try testing.expect(cyclotomic.cyclotomic_square().eql(cyclotomic.square()));
}

test "fields: wide reduction" {
    var bytes: [64]u8 = @splat(0xff);
    const expected = (@as(u512, std.math.maxInt(u512)) % p);
    try testing.expectEqual(@as(u384, @intCast(expected)), fp_from_bytes_wide(&bytes).to_int());
    bytes = @splat(0);
    bytes[63] = 7;
    try testing.expectEqual(@as(u384, 7), fp_from_bytes_wide(&bytes).to_int());
}
