//! Eight BLS12-381 base-field elements at once, one per 64-bit lane: row `k` of `Fp8` holds
//! 52-bit limb `k` of every lane's element, in Montgomery form with R = 2^416. A product is
//! eight lane-wise Montgomery products, each row of the schoolbook multiplication one
//! multiply-add of 52-bit halves per limb.
//!
//! On x86-64 with AVX-512 IFMA (and LLVM, whose assembler knows it) the multiply-adds are
//! `vpmadd52luq` / `vpmadd52huq`, as ed25519's IFMA backend does; every other target runs the
//! same algorithm on plain u64 lanes. For public values only: products and reductions select
//! lane-wise but square roots and inversions built on them branch on their results.
//!
//! Every `Fp8` value lies in [0, 2p) with carried limbs below 2^52, which a Montgomery product
//! keeps: for inputs below 2p, (4 p^2 + R p) / R < 2p because 4p < R.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const fields = @import("fields.zig");

const Fp = fields.Fp;
const Int = Fp.Int;

pub const lanes = 8;
pub const limbs = 8;
pub const V = @Vector(lanes, u64);
pub const Mask = @Vector(lanes, bool);
const Wide = u768;
const mask_52: u64 = (1 << 52) - 1;

/// Whether the build target multiplies with AVX-512 IFMA.
pub const ifma_available = builtin.zig_backend == .stage2_llvm and
    builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .avx512f, .avx512ifma });

pub const Backend = enum { ifma, portable };

/// The lanes of the target's fastest backend.
pub const Fp8 = Lanes(if (ifma_available) .ifma else .portable);

/// `value` (below 2^416) as 52-bit limbs.
fn limbs_of(value: u416) [limbs]u64 {
    var out: [limbs]u64 = undefined;
    for (&out, 0..) |*limb, k| limb.* = @truncate((value >> @intCast(52 * k)) & mask_52);
    return out;
}

const modulus: Int = Fp.modulus;
const p_limbs = limbs_of(modulus);
const two_p_limbs = limbs_of(2 * @as(u416, modulus));
/// -p^-1 mod 2^52.
const inverse_52: u64 = blk: {
    var inverse: u64 = 1;
    for (0..7) |_| inverse *%= 2 -% p_limbs[0] *% inverse;
    break :blk (0 -% inverse) & mask_52;
};
/// Montgomery factors between Field(6) form (x 2^384) and this form (x 2^416).
const into_factor = limbs_of(@intCast((@as(Wide, 1) << 448) % modulus));
const out_of_factor = limbs_of(@intCast((@as(Wide, 1) << 384) % modulus));

comptime {
    assert(4 * @as(u420, modulus) < @as(u420, 1) << 416);
    assert((p_limbs[0] *% inverse_52) & mask_52 == mask_52);
}

pub fn Lanes(comptime backend: Backend) type {
    if (backend == .ifma) assert(ifma_available);
    return struct {
        const Self = @This();

        rows: [limbs]V,

        pub const zero: Self = .{ .rows = @splat(@splat(0)) };
        pub const one: Self = splat_int(1);

        /// `acc` plus the low 52 bits of each lane's `a * b` (bits of a, b above 52 ignored).
        inline fn madd_low(acc: V, a: V, b: V) V {
            if (backend == .portable) return acc + (@as(V, @truncate(product(a, b))) & mask());
            return asm ("vpmadd52luq %[b], %[a], %[acc]"
                : [acc] "=v" (-> V),
                : [acc_in] "0" (acc),
                  [a] "v" (a),
                  [b] "v" (b),
            );
        }

        /// `acc` plus bits 52 to 103 of each lane's `a * b`.
        inline fn madd_high(acc: V, a: V, b: V) V {
            if (backend == .portable) return acc + @as(V, @truncate(product(a, b) >> @splat(52)));
            return asm ("vpmadd52huq %[b], %[a], %[acc]"
                : [acc] "=v" (-> V),
                : [acc_in] "0" (acc),
                  [a] "v" (a),
                  [b] "v" (b),
            );
        }

        inline fn product(a: V, b: V) @Vector(lanes, u128) {
            const wide: @Vector(lanes, u128) = a & mask();
            return wide * @as(@Vector(lanes, u128), b & mask());
        }

        inline fn mask() V {
            return @splat(mask_52);
        }

        /// a b / 2^416 mod p, below 2p, lane-wise.
        pub fn mul(a: Self, b: Self) Self {
            // The unrolled rows count against the comptime branch quota.
            @setEvalBranchQuota(10_000);
            var t: [limbs + 1]V = @splat(@splat(0));
            const m_factor: V = @splat(inverse_52);
            inline for (0..limbs) |i| {
                const factor = b.rows[i];
                inline for (0..limbs) |j| {
                    t[j] = madd_low(t[j], a.rows[j], factor);
                    t[j + 1] = madd_high(t[j + 1], a.rows[j], factor);
                }
                // m = t0 (-p^-1) mod 2^52 zeroes the low 52 bits of t0 + m p.
                const m = madd_low(@splat(0), t[0], m_factor);
                inline for (0..limbs) |j| {
                    const p_j: V = @splat(p_limbs[j]);
                    t[j] = madd_low(t[j], m, p_j);
                    t[j + 1] = madd_high(t[j + 1], m, p_j);
                }
                if (std.debug.runtime_safety) assert(@reduce(.Or, t[0] & mask()) == 0);
                t[1] += t[0] >> @splat(52);
                inline for (0..limbs) |k| t[k] = t[k + 1];
                t[limbs] = @splat(0);
            }
            const result = carry(t[0..limbs].*);
            if (std.debug.runtime_safety) assert(result.below(two_p_limbs));
            return result;
        }

        /// a^2 / 2^416 mod p, below 2p: each cross product once, doubled, then a separate
        /// Montgomery reduction, 208 multiply-adds against `mul`'s 264.
        pub fn square(a: Self) Self {
            @setEvalBranchQuota(10_000);
            var t: [2 * limbs]V = @splat(@splat(0));
            inline for (0..limbs) |i| {
                inline for (i + 1..limbs) |j| {
                    t[i + j] = madd_low(t[i + j], a.rows[i], a.rows[j]);
                    t[i + j + 1] = madd_high(t[i + j + 1], a.rows[i], a.rows[j]);
                }
            }
            // A row holds at most 8 halves below 2^52, so doubling stays below 2^56.
            inline for (&t) |*row| row.* <<= @splat(1);
            inline for (0..limbs) |i| {
                t[2 * i] = madd_low(t[2 * i], a.rows[i], a.rows[i]);
                t[2 * i + 1] = madd_high(t[2 * i + 1], a.rows[i], a.rows[i]);
            }
            const m_factor: V = @splat(inverse_52);
            inline for (0..limbs) |i| {
                // As in `mul`: m zeroes the low 52 bits of row i, which carries into row i + 1.
                const m = madd_low(@splat(0), t[i], m_factor);
                inline for (0..limbs) |j| {
                    const p_j: V = @splat(p_limbs[j]);
                    t[i + j] = madd_low(t[i + j], m, p_j);
                    t[i + j + 1] = madd_high(t[i + j + 1], m, p_j);
                }
                if (std.debug.runtime_safety) assert(@reduce(.Or, t[i] & mask()) == 0);
                t[i + 1] += t[i] >> @splat(52);
            }
            const result = carry(t[limbs..].*);
            if (std.debug.runtime_safety) assert(result.below(two_p_limbs));
            return result;
        }

        /// Carries limbs (each below 2^63, total below 2^416) to 52 bits.
        fn carry(rows: [limbs]V) Self {
            var out: [limbs]V = undefined;
            var c: V = @splat(0);
            inline for (0..limbs) |k| {
                const value = rows[k] + c;
                out[k] = value & mask();
                c = value >> @splat(52);
            }
            if (std.debug.runtime_safety) assert(@reduce(.Or, c) == 0);
            return .{ .rows = out };
        }

        /// Lanes holding a value below `bound`, given carried limbs.
        fn below_mask(self: Self, comptime bound: [limbs]u64) Mask {
            var borrow: V = @splat(0);
            inline for (0..limbs) |k| {
                const difference = self.rows[k] -% @as(V, @splat(bound[k])) -% borrow;
                borrow = difference >> @splat(63);
            }
            return borrow == @as(V, @splat(1));
        }

        fn below(self: Self, comptime bound: [limbs]u64) bool {
            return @reduce(.And, self.below_mask(bound));
        }

        /// Subtracts `bound` from every lane at or above it, given carried limbs.
        fn subtract_if_above(self: Self, comptime bound: [limbs]u64) Self {
            var difference: [limbs]V = undefined;
            var borrow: V = @splat(0);
            inline for (0..limbs) |k| {
                const value = self.rows[k] -% @as(V, @splat(bound[k])) -% borrow;
                difference[k] = value & mask();
                borrow = value >> @splat(63);
            }
            // A final borrow means the lane was below `bound` (as `below_mask` finds).
            const keep = borrow == @as(V, @splat(1));
            var out: Self = undefined;
            inline for (0..limbs) |k| {
                out.rows[k] = @select(u64, keep, self.rows[k], difference[k]);
            }
            return out;
        }

        pub fn add(a: Self, b: Self) Self {
            var sum: [limbs]V = undefined;
            inline for (0..limbs) |k| sum[k] = a.rows[k] + b.rows[k];
            const result = carry(sum).subtract_if_above(two_p_limbs);
            if (std.debug.runtime_safety) assert(result.below(two_p_limbs));
            return result;
        }

        /// a - b + 2p, which lies in (0, 4p), carried with signed limbs and brought below 2p.
        pub fn sub(a: Self, b: Self) Self {
            var out: [limbs]V = undefined;
            var c: V = @splat(0);
            inline for (0..limbs) |k| {
                const value = a.rows[k] +% @as(V, @splat(two_p_limbs[k])) -% b.rows[k] +% c;
                out[k] = value & mask();
                // An arithmetic shift carries a negative limb as a borrow.
                c = @bitCast(@as(@Vector(lanes, i64), @bitCast(value)) >> @splat(52));
            }
            if (std.debug.runtime_safety) assert(@reduce(.Or, c) == 0);
            const result = (Self{ .rows = out }).subtract_if_above(two_p_limbs);
            if (std.debug.runtime_safety) assert(result.below(two_p_limbs));
            return result;
        }

        pub fn neg(a: Self) Self {
            return zero.sub(a);
        }

        pub fn double(a: Self) Self {
            return a.add(a);
        }

        /// Lane-wise `if (choose) a else b`.
        pub fn select(choose: Mask, a: Self, b: Self) Self {
            var out: Self = undefined;
            inline for (0..limbs) |k| out.rows[k] = @select(u64, choose, a.rows[k], b.rows[k]);
            return out;
        }

        /// The value below p, as Fp elements and comparisons see it.
        fn canonical(self: Self) Self {
            return self.subtract_if_above(p_limbs);
        }

        pub fn eql(a: Self, b: Self) Mask {
            const x = a.canonical();
            const y = b.canonical();
            var same: Mask = @splat(true);
            inline for (0..limbs) |k| same = same & (x.rows[k] == y.rows[k]);
            return same;
        }

        pub fn is_zero(a: Self) Mask {
            return a.eql(zero);
        }

        fn splat_int(comptime value: Int) Self {
            const plain: u416 = @intCast((@as(Wide, value) << 416) % modulus);
            return from_limbs(comptime limbs_of(plain));
        }

        fn from_limbs(row: [limbs]u64) Self {
            var out: Self = undefined;
            inline for (0..limbs) |k| out.rows[k] = @splat(row[k]);
            return out;
        }

        /// Every lane set to the compile-time `value`, converted at compile time.
        pub fn constant(comptime value: Fp) Self {
            const row = comptime blk: {
                @setEvalBranchQuota(100_000);
                // Field(6) stores x 2^384; the lanes store x 2^416.
                const stored: Wide = limbs_int(value.limbs_value);
                break :blk limbs_of(@intCast((stored << 32) % modulus));
            };
            return from_limbs(row);
        }

        /// Each lane's RFC 9380 sgn0: whether its value, reduced below p, is odd.
        pub fn sgn0(self: Self) Mask {
            // A Montgomery product with plain 1 leaves the value itself.
            const plain = self.mul(from_limbs(comptime limbs_of(1))).canonical();
            assert(plain.below(p_limbs));
            return (plain.rows[0] & @as(V, @splat(1))) == @as(V, @splat(1));
        }

        /// Each lane's inverse (Fermat), zero for zero.
        pub fn inverse(self: Self) Self {
            return self.pow(modulus - 2);
        }

        /// Every lane set to `value`.
        pub fn splat(value: Fp) Self {
            var values: [lanes]Fp = undefined;
            @memset(&values, value);
            return from_fp(&values);
        }

        /// The lanes of `values`, from Field(6) form (x 2^384) to x 2^416.
        pub fn from_fp(values: *const [lanes]Fp) Self {
            var stored: Self = undefined;
            inline for (0..limbs) |k| {
                var row: [lanes]u64 = undefined;
                for (values, &row) |value, *limb| {
                    const int = limbs_int(value.limbs_value);
                    limb.* = @truncate((int >> (52 * k)) & mask_52);
                }
                stored.rows[k] = row;
            }
            return stored.mul(from_limbs(into_factor));
        }

        /// Each lane as an Fp element in Field(6) form.
        pub fn to_fp(self: Self) [lanes]Fp {
            const stored = self.mul(from_limbs(out_of_factor)).canonical();
            var ints: [lanes]u416 = @splat(0);
            inline for (0..limbs) |k| {
                const row: [lanes]u64 = stored.rows[k];
                for (&ints, row) |*int, limb| int.* |= @as(u416, limb) << (52 * k);
            }
            var out: [lanes]Fp = undefined;
            for (&out, ints) |*value, int| {
                assert(int < modulus);
                value.* = .{ .limbs_value = int_limbs(@intCast(int)) };
            }
            return out;
        }

        /// `a^exponent` for a public exponent, by 5-bit sliding windows from the top: for
        /// (p + 1) / 4, 375 squares and 66 products after a 16-entry table of odd powers.
        pub fn pow(a: Self, comptime exponent: Int) Self {
            comptime assert(exponent > 0);
            const steps = comptime window_steps(exponent);
            // table[k] = a^(2k + 1).
            var table: [16]Self = undefined;
            table[0] = a;
            const a_squared = a.square();
            for (1..16) |index| table[index] = table[index - 1].mul(a_squared);
            var result = table[steps[0].digit >> 1];
            for (steps[1..]) |step| {
                for (0..step.squares) |_| result = result.square();
                if (step.digit != 0) result = result.mul(table[step.digit >> 1]);
            }
            return result;
        }
    };
}

/// One step of a sliding-window exponentiation: square `squares` times, then multiply by
/// the odd power `digit` (none when zero).
const WindowStep = struct { squares: u16, digit: u5 };

/// `exponent`'s 5-bit sliding windows from the top. The first step's digit is the starting
/// power and its `squares` is zero.
fn window_steps(comptime exponent: Int) []const WindowStep {
    @setEvalBranchQuota(1_000_000);
    const width = 5;
    var out: [@bitSizeOf(Int)]WindowStep = undefined;
    var count: usize = 0;
    var bit: isize = @bitSizeOf(Int) - 1 - @clz(exponent);
    var pending: u16 = 0;
    while (bit >= 0) {
        if ((exponent >> @intCast(bit)) & 1 == 0) {
            pending += 1;
            bit -= 1;
            continue;
        }
        // The longest window from `bit` down that ends in a one bit.
        var low: isize = @max(0, bit - (width - 1));
        while ((exponent >> @intCast(low)) & 1 == 0) low += 1;
        const size: u16 = @intCast(bit - low + 1);
        const digit: u5 = @intCast((exponent >> @intCast(low)) & ((1 << size) - 1));
        assert(digit & 1 == 1);
        out[count] = .{ .squares = if (count == 0) 0 else pending + size, .digit = digit };
        count += 1;
        pending = 0;
        bit = low - 1;
    }
    if (pending > 0) {
        out[count] = .{ .squares = pending, .digit = 0 };
        count += 1;
    }
    assert(count > 0 and out[0].squares == 0);
    const final = out[0..count].*;
    return &final;
}

fn limbs_int(value: [6]u64) Int {
    var out: Int = 0;
    inline for (0..6) |index| out |= @as(Int, value[index]) << (64 * index);
    return out;
}

fn int_limbs(value: Int) [6]u64 {
    var out: [6]u64 = undefined;
    inline for (0..6) |index| out[index] = @truncate(value >> (64 * index));
    return out;
}

const testing = std.testing;
const Prng = @import("prng.zig").Prng;

/// Random field elements with the edges 0, 1, p - 1, and p - 2 in the first lanes.
fn random_lanes(prng: *Prng, round: usize) [lanes]Fp {
    var out: [lanes]Fp = undefined;
    for (&out, 0..) |*value, lane| {
        const edge = [_]Int{ 0, 1, modulus - 1, modulus - 2 };
        value.* = if (round == 0 and lane < edge.len)
            Fp.from_int(edge[lane])
        else
            Fp.from_int(prng.int(Int) % modulus);
    }
    return out;
}

fn expect_lanes(expected: [lanes]Fp, got: [lanes]Fp) !void {
    for (expected, got) |want, value| try testing.expect(want.eql(value));
}

/// Every operation of `L` against Field(6), lane by lane.
fn check_against_fp(comptime L: type, seed: u64) !void {
    var prng = Prng.init(seed);
    for (0..300) |round| {
        const a = random_lanes(&prng, round);
        const b = random_lanes(&prng, round + 1);
        const x = L.from_fp(&a);
        const y = L.from_fp(&b);
        var want: [lanes]Fp = undefined;
        try expect_lanes(a, x.to_fp());
        for (&want, a, b) |*w, u, v| w.* = u.mul(v);
        try expect_lanes(want, x.mul(y).to_fp());
        for (&want, a) |*w, u| w.* = u.square();
        try expect_lanes(want, x.square().to_fp());
        for (&want, a, b) |*w, u, v| w.* = u.add(v);
        try expect_lanes(want, x.add(y).to_fp());
        for (&want, a, b) |*w, u, v| w.* = u.sub(v);
        try expect_lanes(want, x.sub(y).to_fp());
        for (&want, a) |*w, u| w.* = u.neg();
        try expect_lanes(want, x.neg().to_fp());
        const same: [lanes]bool = x.eql(L.from_fp(&a));
        const differ: [lanes]bool = x.eql(y);
        for (0..lanes) |lane| {
            try testing.expect(same[lane]);
            try testing.expectEqual(a[lane].eql(b[lane]), differ[lane]);
        }
    }
}

test "fp8: the portable lanes match Field(6)" {
    try check_against_fp(Lanes(.portable), 0x667038);
}

test "fp8: the IFMA lanes match Field(6)" {
    if (!ifma_available) return error.SkipZigTest;
    try check_against_fp(Lanes(.ifma), 0x667039);
}

test "fp8: pow matches Field(6) for the square-root exponent and window edges" {
    // Trailing zeros, a lone top bit, windows split by long zero runs, and all-ones runs.
    const exponents = [_]Int{
        (modulus + 1) / 4, 1,                   2,             0b110000,
        1 << 100,          (1 << 100) + 0b1001, (1 << 37) - 1, (modulus - 1) / 2,
    };
    var prng = Prng.init(0x706f77);
    inline for (.{ Lanes(.portable), Fp8 }) |L| {
        const a = random_lanes(&prng, 0);
        inline for (exponents) |exponent| {
            var want: [lanes]Fp = undefined;
            for (&want, a) |*w, u| w.* = u.pow(exponent);
            try expect_lanes(want, L.from_fp(&a).pow(exponent).to_fp());
        }
    }
}

test "fp8: constant, sgn0, and inverse match Field(6)" {
    var prng = Prng.init(0x736730);
    const c = comptime Fp.from_int_comptime(0x1234_5678_9abc_def0_0fed_cba9_8765_4321);
    inline for (.{ Lanes(.portable), Fp8 }) |L| {
        try expect_lanes(@splat(c), L.constant(c).to_fp());
        for (0..4) |round| {
            const a = random_lanes(&prng, round);
            const x = L.from_fp(&a);
            // A product may store another representative of the same value, with the same sign.
            const signs: [lanes]bool = x.sgn0();
            const shifted: [lanes]bool = x.mul(L.one).sgn0();
            var want: [lanes]Fp = undefined;
            for (&want, a, 0..) |*w, u, lane| {
                try testing.expectEqual(fields.fp_sgn0(u), signs[lane]);
                try testing.expectEqual(signs[lane], shifted[lane]);
                w.* = u.inverse();
            }
            try expect_lanes(want, x.inverse().to_fp());
        }
        // Zero stored as p is the one value whose product with plain 1 is not below p (it is p,
        // which is odd), so sgn0 must reduce it.
        const stored_p = L.from_limbs(p_limbs);
        try testing.expect(@reduce(.And, stored_p.is_zero()));
        try testing.expect(!@reduce(.Or, stored_p.sgn0()));
    }
}

test "fp8: select and is_zero work per lane" {
    var prng = Prng.init(0x73656c);
    const a = random_lanes(&prng, 0);
    const b = random_lanes(&prng, 1);
    const choose: Mask = .{ true, false, true, false, false, true, true, false };
    const picked = Fp8.select(choose, Fp8.from_fp(&a), Fp8.from_fp(&b)).to_fp();
    const chosen: [lanes]bool = choose;
    for (0..lanes) |lane| {
        try testing.expect(picked[lane].eql(if (chosen[lane]) a[lane] else b[lane]));
    }
    // Lane 0 of round 0 is zero; p - p is zero in every lane.
    try testing.expect(Fp8.from_fp(&a).is_zero()[0]);
    try testing.expect(@reduce(.And, Fp8.from_fp(&b).sub(Fp8.from_fp(&b)).is_zero()));
}
