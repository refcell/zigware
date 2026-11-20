//! P-256 field arithmetic for verify.zig and signing.zig. On x86_64, multiplication and
//! squaring are word-by-word Montgomery (R = 2^256) in plain Zig, so LLVM schedules the
//! `mulx`/`adc` chains of neighboring operations together. Each reduction step adds `m p` for
//! `m` = the low limb with shifts and one multiplication, since `-p^-1 = 1 mod 2^64` and
//! `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`, as aws-lc's `ecp_nistz256_mul_mont` does; squaring
//! computes each cross product once. The limbs are std's (fiat-crypto's) Montgomery limbs,
//! fully reduced, so `mul` and `sq` return exactly std's `Fe.mul` and `Fe.sq`; other targets
//! call std. Addition and subtraction are plain u256 arithmetic, about twice as fast as std's,
//! with the same limbs. Everything here is branch-free, since signing.zig runs it on secret
//! values.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Fe = std.crypto.ecc.P256.Fe;

/// Targets where the Zig Montgomery multiplication below beats std's (measured on x86_64).
const accelerated = builtin.cpu.arch == .x86_64;

/// `p`'s limbs, least significant first.
const modulus_limbs = [4]u64{ 0xffffffffffffffff, 0x00000000ffffffff, 0, 0xffffffff00000001 };

/// `a b` in the field: the same limbs as `a.mul(b)`.
pub inline fn mul(a: Fe, b: Fe) Fe {
    if (!accelerated) return a.mul(b);
    const x = a.limbs;
    const y = b.limbs;
    // Limbs 0 to 4 of the running sum; each round adds `x y[i]`, then `m p`, and drops limb 0.
    var t: [5]u64 = @splat(0);
    inline for (0..4) |i| {
        var carry: u64 = 0;
        inline for (0..4) |k| {
            const product: u128 = @as(u128, x[k]) * y[i] + t[k] + carry;
            t[k] = @truncate(product);
            carry = @truncate(product >> 64);
        }
        const top = @addWithOverflow(t[4], carry);
        const step = reduce_step(t[0], .{ t[1], t[2], t[3], top[0] });
        t = .{ step.limbs[0], step.limbs[1], step.limbs[2], step.limbs[3], top[1] + step.carry };
    }
    return subtract_modulus(t);
}

/// `a^2` in the field: the same limbs as `a.sq()`.
pub inline fn sq(a: Fe) Fe {
    if (!accelerated) return a.sq();
    const x = a.limbs;
    var t: [8]u64 = @splat(0);
    // The cross products `x_i x_j` (i < j), doubled, plus the squares `x_i^2`.
    inline for (0..3) |i| {
        var carry: u64 = 0;
        inline for (i + 1..4) |j| {
            const product: u128 = @as(u128, x[i]) * x[j] + t[i + j] + carry;
            t[i + j] = @truncate(product);
            carry = @truncate(product >> 64);
        }
        t[i + 4] = carry;
    }
    var shifted: u64 = 0;
    inline for (1..8) |k| {
        const limb = t[k];
        t[k] = (limb << 1) | shifted;
        shifted = limb >> 63;
    }
    var carry: u1 = 0;
    inline for (0..4) |i| {
        const square: u128 = @as(u128, x[i]) * x[i];
        const low = add_carry(t[2 * i], @truncate(square), carry);
        const high = add_carry(t[2 * i + 1], @truncate(square >> 64), low[1]);
        t[2 * i] = low[0];
        t[2 * i + 1] = high[0];
        carry = high[1];
    }
    assert(carry == 0); // Proof: x^2 < 2^512.
    // Four reduction steps over the 512-bit square, carrying into its upper limbs.
    var spill: u64 = 0;
    inline for (0..4) |i| {
        const step = reduce_step(t[i], t[i + 1 ..][0..4].*);
        t[i + 1 ..][0..4].* = step.limbs;
        var rest: u1 = step.carry;
        inline for (i + 5..8) |k| {
            const sum = @addWithOverflow(t[k], @as(u64, rest));
            t[k] = sum[0];
            rest = sum[1];
        }
        spill += rest;
    }
    return subtract_modulus(.{ t[4], t[5], t[6], t[7], spill });
}

const ReduceStep = struct { limbs: [4]u64, carry: u1 };

/// `(m + upper 2^64 + m p) / 2^64` for the low limb `m`, as `upper + m 2^32 + m p_3 2^128`
/// (the low part `m (p mod 2^128) + m` is `m 2^96`), with its carry out.
inline fn reduce_step(m: u64, upper: [4]u64) ReduceStep {
    const high: u128 = @as(u128, m) * modulus_limbs[3];
    const l1 = add_carry(upper[0], m << 32, 0);
    const l2 = add_carry(upper[1], m >> 32, l1[1]);
    const l3 = add_carry(upper[2], @truncate(high), l2[1]);
    const l4 = add_carry(upper[3], @truncate(high >> 64), l3[1]);
    return .{ .limbs = .{ l1[0], l2[0], l3[0], l4[0] }, .carry = l4[1] };
}

inline fn add_carry(a: u64, b: u64, carry: u1) struct { u64, u1 } {
    const first = @addWithOverflow(a, b);
    const second = @addWithOverflow(first[0], @as(u64, carry));
    return .{ second[0], first[1] | second[1] };
}

/// The value below `2 p` in limbs 0 to 4, less `p` when it is at least `p`, by masking.
inline fn subtract_modulus(t: [5]u64) Fe {
    var difference: [4]u64 = undefined;
    var borrow: u1 = 0;
    inline for (0..4) |k| {
        const first = @subWithOverflow(t[k], modulus_limbs[k]);
        const second = @subWithOverflow(first[0], @as(u64, borrow));
        difference[k] = second[0];
        borrow = first[1] | second[1];
    }
    const below = @subWithOverflow(t[4], @as(u64, borrow))[1];
    const keep: u64 = 0 -% @as(u64, below);
    var result: [4]u64 = undefined;
    inline for (0..4) |k| result[k] = (t[k] & keep) | (difference[k] & ~keep);
    return .{ .limbs = result };
}

/// `a + b`: the same limbs as `a.add(b)` (both fully reduced). Branch-free: signing uses it on
/// secret values.
pub inline fn add(a: Fe, b: Fe) Fe {
    if (!little_endian) return a.add(b);
    const sum = @addWithOverflow(wide(a), wide(b));
    const diff = @subWithOverflow(sum[0], Fe.field_order);
    // The sum is below p exactly when it did not carry out and subtracting p borrows.
    const below: u256 = (sum[1] ^ 1) & diff[1];
    return narrow(select(below, sum[0], diff[0]));
}

/// `a - b`: the same limbs as `a.sub(b)`. Branch-free.
pub inline fn sub(a: Fe, b: Fe) Fe {
    if (!little_endian) return a.sub(b);
    const diff = @subWithOverflow(wide(a), wide(b));
    return narrow(diff[0] +% (Fe.field_order & (0 -% @as(u256, diff[1]))));
}

/// `when_one` if `bit` is 1, else `when_zero`, by masking rather than branching.
inline fn select(bit: u256, when_one: u256, when_zero: u256) u256 {
    assert(bit <= 1);
    const mask = 0 -% bit;
    return (when_one & mask) | (when_zero & ~mask);
}

/// `2 a`: the same limbs as `a.dbl()`.
pub inline fn dbl(a: Fe) Fe {
    return add(a, a);
}

/// `-a`: the same limbs as `a.neg()` (zero stays zero).
pub inline fn neg(a: Fe) Fe {
    return sub(Fe.zero, a);
}

/// std's limbs are least significant first, so they are a native u256 on little-endian hosts.
const little_endian = builtin.cpu.arch.endian() == .little;

inline fn wide(a: Fe) u256 {
    return @bitCast(a.limbs);
}

inline fn narrow(value: u256) Fe {
    assert(value < Fe.field_order);
    return .{ .limbs = @bitCast(value) };
}

const testing = std.testing;

fn field_element(value: u256) !Fe {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    return Fe.fromBytes(bytes, .big);
}

test "secp256r1 field arithmetic equals std's at the edges" {
    const p: u256 = Fe.field_order;
    const values = [_]u256{
        0, 1, 2, p - 1, p - 2, p >> 1, 1 << 255, 0xffffffff, 1 << 224, p - (1 << 64), 1 << 96,
    };
    for (values) |x| {
        const a = try field_element(x);
        try testing.expectEqualSlices(u64, &a.sq().limbs, &sq(a).limbs);
        try testing.expectEqualSlices(u64, &a.dbl().limbs, &dbl(a).limbs);
        try testing.expectEqualSlices(u64, &a.neg().limbs, &neg(a).limbs);
        for (values) |y| {
            const b = try field_element(y);
            try testing.expectEqualSlices(u64, &a.mul(b).limbs, &mul(a, b).limbs);
            try testing.expectEqualSlices(u64, &a.add(b).limbs, &add(a, b).limbs);
            try testing.expectEqualSlices(u64, &a.sub(b).limbs, &sub(a, b).limbs);
        }
    }
}

test "secp256r1 field arithmetic equals std's on random elements" {
    var rng = std.Random.DefaultPrng.init(0x256);
    for (0..20_000) |_| {
        const a = try field_element(rng.random().int(u256) % Fe.field_order);
        const b = try field_element(rng.random().int(u256) % Fe.field_order);
        try testing.expectEqualSlices(u64, &a.mul(b).limbs, &mul(a, b).limbs);
        try testing.expectEqualSlices(u64, &a.add(b).limbs, &add(a, b).limbs);
        try testing.expectEqualSlices(u64, &a.sub(b).limbs, &sub(a, b).limbs);
    }
}
