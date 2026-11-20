//! Optimal ate pairing on BLS12-381 with x = -0xd201000000010000.
//!
//! The Miller loop keeps T in Jacobian coordinates over Fp2 and evaluates lines
//! as sparse Fp12 elements (M-type twist: coefficients at 1, v, and v w), using
//! the doubling and addition formulas of Aranha et al. (eprint 2010/354,
//! algorithms 26 and 27). Several pairs share one Miller loop accumulator and
//! one final exponentiation. The hard part of the final exponentiation follows
//! Hayashida-Hayasaka-Teruya (eprint 2020/875) with cyclotomic squarings.

const std = @import("std");
const assert = std.debug.assert;
const fields = @import("fields.zig");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const Prng = @import("prng.zig").Prng;
const fp8 = @import("fp8.zig");
const fp12_lanes = @import("fp12_lanes.zig");

const Fp2 = fields.Fp2;
const Fp12 = fields.Fp12;
const G2 = g2.G2;

pub const x_abs: u64 = 0xd201000000010000;

/// Pairs per Miller loop pass; longer inputs run several passes whose outputs
/// are multiplied before the shared final exponentiation.
pub const pairs_per_loop_max = 16;

pub const Pair = struct {
    g1: g1.Affine,
    g2: g2.Affine,
};

const Line = [3]Fp2;

fn doubling_step(t: *G2) Line {
    const tmp0 = t.x.square();
    const tmp1 = t.y.square();
    const tmp2 = tmp1.square();
    const tmp3 = tmp1.add(t.x).square().sub(tmp0).sub(tmp2).double();
    const tmp4 = tmp0.double().add(tmp0);
    const tmp6 = t.x.add(tmp4);
    const tmp5 = tmp4.square();
    const z_squared = t.z.square();
    t.x = tmp5.sub(tmp3).sub(tmp3);
    t.z = t.z.add(t.y).square().sub(tmp1).sub(z_squared);
    t.y = tmp3.sub(t.x).mul(tmp4).sub(tmp2.double().double().double());
    const c1 = tmp4.mul(z_squared).double().neg();
    const c2 = tmp6.square().sub(tmp0).sub(tmp5).sub(tmp1.double().double());
    const c0 = t.z.mul(z_squared).double();
    assert(!t.z.is_zero());
    return .{ c0, c1, c2 };
}

fn addition_step(t: *G2, q: g2.Affine) Line {
    assert(!q.infinity);
    const z_squared = t.z.square();
    const y_squared = q.y.square();
    const t0 = z_squared.mul(q.x);
    const t1 = q.y.add(t.z).square().sub(y_squared).sub(z_squared).mul(z_squared);
    const t2 = t0.sub(t.x);
    const t3 = t2.square();
    const t4 = t3.double().double();
    const t5 = t4.mul(t2);
    const t6 = t1.sub(t.y).sub(t.y);
    const t9 = t6.mul(q.x);
    const t7 = t4.mul(t.x);
    t.x = t6.square().sub(t5).sub(t7).sub(t7);
    t.z = t.z.add(t2).square().sub(z_squared).sub(t3);
    const t8 = t7.sub(t.x).mul(t6);
    t.y = t8.sub(t.y.mul(t5).double());
    const t10 = q.y.add(t.z).square().sub(y_squared).sub(t.z.square());
    const c2 = t9.double().sub(t10);
    const c0 = t.z.double();
    const c1 = t6.neg().double();
    return .{ c0, c1, c2 };
}

/// Multiplies f by the line evaluated at the G1 point (px, py).
fn pairing_ell(f: Fp12, line: Line, point: g1.Affine) Fp12 {
    const c0 = line[0].mul_by_fp(point.y);
    const c1 = line[1].mul_by_fp(point.x);
    return f.mul_by_014(line[2], c1, c0);
}

/// The Miller loop's f: on fp8's lanes where the target has IFMA (squares and line products
/// there cost half the scalar tower's), the scalar Fp12 elsewhere. Same values either way.
const Accumulator = if (fp8.ifma_available)
    LaneAccumulator(fp8.Lanes(.ifma))
else
    ScalarAccumulator;

const ScalarAccumulator = struct {
    f: Fp12,

    const one: ScalarAccumulator = .{ .f = Fp12.one };

    fn ell(self: ScalarAccumulator, line: Line, point: g1.Affine) ScalarAccumulator {
        return .{ .f = pairing_ell(self.f, line, point) };
    }

    fn square(self: ScalarAccumulator) ScalarAccumulator {
        return .{ .f = self.f.square() };
    }

    fn finish(self: ScalarAccumulator) Fp12 {
        return self.f.conjugate();
    }
};

fn LaneAccumulator(comptime L: type) type {
    const F = fp12_lanes.Fp12Lanes(L);
    return struct {
        const Self = @This();
        f: F,

        const one: Self = .{ .f = F.one };

        fn ell(self: Self, line: Line, point: g1.Affine) Self {
            const c0 = line[0].mul_by_fp(point.y);
            const c1 = line[1].mul_by_fp(point.x);
            return .{ .f = self.f.mul_by_014(F.from_line(line[2], c1, c0)) };
        }

        fn square(self: Self) Self {
            return .{ .f = self.f.square() };
        }

        fn finish(self: Self) Fp12 {
            return self.f.conjugate().to_fp12();
        }
    };
}

/// Miller loop over at most `pairs_per_loop_max` pairs; pairs with an
/// infinity point contribute 1 and are skipped. The result is not reduced.
pub fn miller_loop(pairs: []const Pair) Fp12 {
    return miller_loop_on(Accumulator, pairs);
}

/// `miller_loop` with f kept in `A` (a scalar or lane accumulator).
fn miller_loop_on(comptime A: type, pairs: []const Pair) Fp12 {
    assert(pairs.len <= pairs_per_loop_max);
    var active: [pairs_per_loop_max]Pair = undefined;
    var t: [pairs_per_loop_max]G2 = undefined;
    var count: usize = 0;
    for (pairs) |pair| {
        assert(pair.g1.is_on_curve() and pair.g2.is_on_curve());
        if (pair.g1.infinity or pair.g2.infinity) continue;
        active[count] = pair;
        t[count] = pair.g2.to_jacobian();
        count += 1;
    }
    var f = A.one;
    if (count == 0) return Fp12.one;
    // Bits of |x| below the leading one, most significant first; the last
    // doubling happens after the loop because the low 16 bits are zero.
    var bit: u32 = 63;
    while (bit > 1) {
        bit -= 1;
        for (active[0..count], t[0..count]) |pair, *point| {
            f = f.ell(doubling_step(point), pair.g1);
        }
        if ((x_abs >> @intCast(bit)) & 1 == 1) {
            for (active[0..count], t[0..count]) |pair, *point| {
                f = f.ell(addition_step(point, pair.g2), pair.g1);
            }
        }
        f = f.square();
    }
    for (active[0..count], t[0..count]) |pair, *point| {
        f = f.ell(doubling_step(point), pair.g1);
    }
    assert(x_abs & 1 == 0);
    // x < 0: f_{x} = conj(f_{|x|}) up to factors killed by the final exponentiation.
    return f.finish();
}

/// Lines in one Miller loop: 63 doublings plus one addition per set bit of |x|
/// below the leading one.
pub const line_count = 63 + @popCount(x_abs) - 1;

/// The Miller loop line coefficients of a fixed G2 point, computed once so that
/// pairings against it skip all G2 arithmetic.
pub const PreparedG2 = struct {
    lines: [line_count]Line,
    infinity: bool,
};

pub fn prepare(q: g2.Affine) PreparedG2 {
    assert(q.is_on_curve());
    var prepared: PreparedG2 = .{ .lines = undefined, .infinity = q.infinity };
    if (q.infinity) return prepared;
    var t = q.to_jacobian();
    var index: usize = 0;
    var bit: u32 = 63;
    while (bit > 1) {
        bit -= 1;
        prepared.lines[index] = doubling_step(&t);
        index += 1;
        if ((x_abs >> @intCast(bit)) & 1 == 1) {
            prepared.lines[index] = addition_step(&t, q);
            index += 1;
        }
    }
    prepared.lines[index] = doubling_step(&t);
    index += 1;
    assert(index == line_count);
    return prepared;
}

pub const PreparedPair = struct {
    g1: g1.Affine,
    g2: *const PreparedG2,
};

/// Miller loop over pairs whose G2 points are prepared; same result as `miller_loop`.
pub fn miller_loop_prepared(pairs: []const PreparedPair) Fp12 {
    assert(pairs.len <= pairs_per_loop_max);
    var f = Accumulator.one;
    var index: usize = 0;
    var bit: u32 = 63;
    while (bit > 1) {
        bit -= 1;
        f = ell_prepared(f, pairs, index);
        index += 1;
        if ((x_abs >> @intCast(bit)) & 1 == 1) {
            f = ell_prepared(f, pairs, index);
            index += 1;
        }
        f = f.square();
    }
    f = ell_prepared(f, pairs, index);
    index += 1;
    assert(index == line_count);
    return f.finish();
}

fn ell_prepared(f: Accumulator, pairs: []const PreparedPair, index: usize) Accumulator {
    assert(index < line_count);
    var result = f;
    for (pairs) |pair| {
        if (pair.g1.infinity or pair.g2.infinity) continue;
        result = result.ell(pair.g2.lines[index], pair.g1);
    }
    return result;
}

/// True when the product of e(P_i, Q_i) over prepared pairs is one.
pub fn pairing_check_prepared(pairs: []const PreparedPair) bool {
    assert(pairs.len <= pairs_per_loop_max);
    for (pairs) |pair| assert(pair.g1.is_on_curve());
    return final_exponentiation(miller_loop_prepared(pairs)).eql(Fp12.one);
}

/// f^x with x < 0, for f in the cyclotomic subgroup.
fn cyclotomic_exp_by_x(f: Fp12) Fp12 {
    var result = Fp12.one;
    var found_one = false;
    var bit: u32 = 64;
    while (bit > 0) {
        bit -= 1;
        const set = (x_abs >> @intCast(bit)) & 1 == 1;
        if (found_one) result = result.cyclotomic_square() else found_one = set;
        if (set) result = result.mul(f);
    }
    assert(found_one);
    return result.conjugate();
}

fn frobenius_power(f: Fp12, comptime power: u32) Fp12 {
    var result = f;
    inline for (0..power) |_| result = result.frobenius();
    return result;
}

/// f^((p^12 - 1) / r). On a target with AVX-512 IFMA the hard part runs on fp8's lanes
/// (`final_exponentiation_lanes`); the result is the same.
pub fn final_exponentiation(f: Fp12) Fp12 {
    if (comptime fp8.ifma_available) return final_exponentiation_lanes(fp8.Lanes(.ifma), f);
    return final_exponentiation_scalar(f);
}

/// The easy part f^((p^6 - 1)(p^2 + 1)), which lands in the cyclotomic subgroup.
fn easy_part(f: Fp12) Fp12 {
    assert(!f.is_zero());
    const t = f.conjugate().mul(f.inverse());
    return frobenius_power(t, 2).mul(t);
}

/// `final_exponentiation_scalar` with the hard part's cyclotomic squarings and products on
/// lanes of `L` (an `fp8.Lanes`); frobenius maps run on Fp12 between them.
fn final_exponentiation_lanes(comptime L: type, f: Fp12) Fp12 {
    const F = fp12_lanes.Fp12Lanes(L);
    const t2 = F.from_fp12(easy_part(f));
    var t1 = t2.cyclotomic_square().conjugate();
    const t3 = cyclotomic_exp_by_x_lanes(F, t2);
    var t4 = t3.cyclotomic_square();
    var t5 = t1.mul(t3);
    t1 = cyclotomic_exp_by_x_lanes(F, t5);
    const t0 = cyclotomic_exp_by_x_lanes(F, t1);
    const t6 = cyclotomic_exp_by_x_lanes(F, t0).mul(t4);
    t4 = cyclotomic_exp_by_x_lanes(F, t6);
    t5 = t5.conjugate();
    t4 = t4.mul(t5.mul(t2));
    t5 = t2.conjugate();
    const frob1 = F.from_fp12(frobenius_power(t1.mul(t2).to_fp12(), 3));
    const frob6 = F.from_fp12(t6.mul(t5).to_fp12().frobenius());
    const frob3 = F.from_fp12(frobenius_power(t3.mul(t0).to_fp12(), 2)).mul(frob1).mul(frob6);
    const result = frob3.mul(t4).to_fp12();
    assert(!result.is_zero());
    return result;
}

/// `cyclotomic_exp_by_x` on lanes of `F` (an `fp12_lanes.Fp12Lanes`).
fn cyclotomic_exp_by_x_lanes(comptime F: type, f: F) F {
    var result = f;
    // |x| has its top bit set: start from f and walk the bits below it.
    comptime assert(x_abs >> 63 == 1);
    var bit: u32 = 63;
    while (bit > 0) {
        bit -= 1;
        result = result.cyclotomic_square();
        if ((x_abs >> @intCast(bit)) & 1 == 1) result = result.mul(f);
    }
    return result.conjugate();
}

fn final_exponentiation_scalar(f: Fp12) Fp12 {
    assert(!f.is_zero());
    // Easy part: f^((p^6 - 1)(p^2 + 1)).
    var t2 = f.conjugate().mul(f.inverse());
    var t1 = t2;
    t2 = frobenius_power(t2, 2).mul(t1);
    // Hard part.
    t1 = t2.cyclotomic_square().conjugate();
    var t3 = cyclotomic_exp_by_x(t2);
    var t4 = t3.cyclotomic_square();
    var t5 = t1.mul(t3);
    t1 = cyclotomic_exp_by_x(t5);
    const t0 = cyclotomic_exp_by_x(t1);
    var t6 = cyclotomic_exp_by_x(t0).mul(t4);
    t4 = cyclotomic_exp_by_x(t6);
    t5 = t5.conjugate();
    t4 = t4.mul(t5.mul(t2));
    t5 = t2.conjugate();
    t1 = frobenius_power(t1.mul(t2), 3);
    t6 = t6.mul(t5).frobenius();
    t3 = frobenius_power(t3.mul(t0), 2).mul(t1).mul(t6);
    const result = t3.mul(t4);
    assert(!result.is_zero());
    return result;
}

/// The reduced pairing e(P, Q).
pub fn pairing(point_g1: g1.Affine, point_g2: g2.Affine) Fp12 {
    const pairs = [1]Pair{.{ .g1 = point_g1, .g2 = point_g2 }};
    return final_exponentiation(miller_loop(&pairs));
}

/// True when the product of e(P_i, Q_i) is 1. Points must be in their subgroups.
pub fn pairing_check(pairs: []const Pair) bool {
    var f = Fp12.one;
    var start: usize = 0;
    while (start < pairs.len) {
        const end = @min(pairs.len, start + pairs_per_loop_max);
        f = f.mul(miller_loop(pairs[start..end]));
        start = end;
    }
    assert(start == pairs.len);
    return final_exponentiation(f).eql(Fp12.one);
}

const testing = std.testing;

fn fp12_pow(base: Fp12, exponent: u256) Fp12 {
    var result = Fp12.one;
    var bit: u32 = 256;
    while (bit > 0) {
        bit -= 1;
        result = result.square();
        if ((exponent >> @intCast(bit)) & 1 == 1) result = result.mul(base);
    }
    return result;
}

test {
    _ = fp12_lanes;
}

test "pairing: the Miller loop on lanes matches the scalar one" {
    var prng = Prng.init(0x6d696c);
    const L = LaneAccumulator(fp8.Lanes(.portable));
    for (0..2) |_| {
        const p1 = g1.generator.to_jacobian().mul(prng.int(u256)).to_affine();
        const q1 = g2.generator.to_jacobian().mul(prng.int(u256)).to_affine();
        const p2 = g1.generator.to_jacobian().mul(prng.int(u256)).to_affine();
        const q2 = g2.generator.to_jacobian().mul(prng.int(u256)).to_affine();
        const pairs = [2]Pair{ .{ .g1 = p1, .g2 = q1 }, .{ .g1 = p2, .g2 = q2 } };
        const want = miller_loop_on(ScalarAccumulator, &pairs);
        try testing.expect(miller_loop_on(L, &pairs).eql(want));
        try testing.expect(miller_loop(&pairs).eql(want));
    }
}

test "pairing: the final exponentiation on lanes matches the scalar one" {
    var prng = Prng.init(0x66696e);
    for (0..4) |_| {
        const f = fields.random_fp12(&prng);
        const want = final_exponentiation_scalar(f);
        try testing.expect(final_exponentiation_lanes(fp8.Lanes(.portable), f).eql(want));
        try testing.expect(final_exponentiation(f).eql(want));
    }
}

test "pairing: prepared G2 lines match the plain Miller loop" {
    var prng = Prng.init(0x707265);
    for (0..3) |_| {
        const p1 = g1.generator.to_jacobian().mul(prng.int(u256)).to_affine();
        const p2 = g1.generator.to_jacobian().mul(prng.int(u256)).to_affine();
        const q1 = g2.generator.to_jacobian().mul(prng.int(u256)).to_affine();
        const q2 = g2.generator.to_jacobian().mul(prng.int(u256)).to_affine();
        const prepared = [2]PreparedG2{ prepare(q1), prepare(q2) };
        const pairs = [2]Pair{ .{ .g1 = p1, .g2 = q1 }, .{ .g1 = p2, .g2 = q2 } };
        const prepared_pairs = [2]PreparedPair{
            .{ .g1 = p1, .g2 = &prepared[0] },
            .{ .g1 = p2, .g2 = &prepared[1] },
        };
        try testing.expect(miller_loop(&pairs).eql(miller_loop_prepared(&prepared_pairs)));
        const cancel = [2]PreparedPair{
            .{ .g1 = p1, .g2 = &prepared[0] },
            .{ .g1 = p1.neg(), .g2 = &prepared[0] },
        };
        try testing.expect(pairing_check_prepared(&cancel));
        try testing.expect(!pairing_check_prepared(&prepared_pairs));
    }
    const infinity = prepare(g2.Affine.identity);
    const with_infinity = [1]PreparedPair{.{ .g1 = g1.generator, .g2 = &infinity }};
    try testing.expect(pairing_check_prepared(&with_infinity));
}

test "pairing: non-degenerate, order r, and bilinear" {
    const e = pairing(g1.generator, g2.generator);
    try testing.expect(!e.eql(Fp12.one));
    try testing.expect(fp12_pow(e, fields.r).eql(Fp12.one));
    var prng = Prng.init(0xe11);
    const a = prng.int(u256) % fields.r;
    const b = prng.int(u256) % fields.r;
    const pa = g1.generator.to_jacobian().mul(a).to_affine();
    const qb = g2.generator.to_jacobian().mul(b).to_affine();
    const ab: u256 = @intCast((@as(u512, a) * b) % fields.r);
    try testing.expect(pairing(pa, qb).eql(fp12_pow(e, ab)));
    // e(aP, bQ) e(-abP, Q) = 1 through the shared final exponentiation.
    const minus_ab = g1.generator.to_jacobian().mul(ab).neg().to_affine();
    const pairs = [_]Pair{
        .{ .g1 = pa, .g2 = qb },
        .{ .g1 = minus_ab, .g2 = g2.generator },
        .{ .g1 = g1.Affine.identity, .g2 = g2.generator },
    };
    try testing.expect(pairing_check(&pairs));
    try testing.expect(!pairing_check(pairs[0..1]));
    try testing.expect(pairing_check(pairs[2..3]));
}
