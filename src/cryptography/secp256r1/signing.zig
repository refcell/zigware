//! Constant-time P-256 arithmetic on secret scalars, for signing and key generation: `k G`
//! (as curve25519-dalek's `EdwardsBasepointTable` and RustCrypto's `BasepointTable`, which
//! commonware's secp256r1 keys sign with) and `k^-1 mod n`.
//!
//! `k G` writes `k` (or `n - k`, so it stays below 2^255) in 64 signed radix-16 digits `e_i`
//! in [-8, 8] and sums `16 (sum of e_i 16^(i-1) G, i odd) + (sum of e_i 16^i G, i even)`:
//! each term is read from table `i / 2`, which holds `256^(i/2) G` times 1..8, so the product
//! is 64 complete mixed additions and 4 doublings (std's `basePoint.mul` doubles 255 times).
//! Every lookup scans its whole table with conditional moves, the formulas are complete
//! (Renes, Costello, and Batina 2015, as std's), the field arithmetic is branch-free
//! (field.zig), and both inverses are powers by public exponents, so the time and memory
//! accesses do not depend on the secret. verify.zig's variable-time routines never see it.

const std = @import("std");
const assert = std.debug.assert;
const field = @import("field.zig");
const P256 = std.crypto.ecc.P256;
const Fe = P256.Fe;
const Scalar = P256.scalar.Scalar;

/// An affine point `(x, y)`, never the identity.
pub const Affine = struct { x: Fe, y: Fe };

/// `(X : Y : Z)` with `x = X / Z` and `y = Y / Z`; `(0 : 1 : 0)` is the identity.
const Projective = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    const identity: Projective = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    /// `2 p` (RCB algorithm 6, std's `dbl`).
    fn double(p: Projective) Projective {
        var t0 = field.sq(p.x);
        const t1 = field.sq(p.y);
        var t2 = field.sq(p.z);
        var t3 = field.dbl(field.mul(p.x, p.y));
        var z3 = field.dbl(field.mul(p.x, p.z));
        var y3 = field.sub(field.mul(P256.B, t2), z3);
        var x3 = field.dbl(y3);
        y3 = field.add(x3, y3);
        x3 = field.sub(t1, y3);
        y3 = field.mul(x3, field.add(t1, y3));
        x3 = field.mul(x3, t3);
        t3 = field.dbl(t2);
        t2 = field.add(t2, t3);
        z3 = field.sub(field.sub(field.mul(P256.B, z3), t2), t0);
        z3 = field.add(field.dbl(z3), z3);
        t0 = field.add(field.dbl(t0), t0);
        t0 = field.mul(field.sub(t0, t2), z3);
        y3 = field.add(y3, t0);
        t0 = field.dbl(field.mul(p.y, p.z));
        x3 = field.sub(x3, field.mul(t0, z3));
        z3 = field.dbl(field.dbl(field.mul(t0, t1)));
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// `p + q` (RCB algorithm 5, std's `addMixed`), or `p` when `q` is `(0, 0)`, which stands
    /// for the identity in the tables.
    fn add_affine(p: Projective, q: *const Affine) Projective {
        var t0 = field.mul(p.x, q.x);
        var t1 = field.mul(p.y, q.y);
        var t3 = field.mul(field.add(q.x, q.y), field.add(p.x, p.y));
        var t4 = field.add(t0, t1);
        t3 = field.sub(t3, t4);
        t4 = field.add(field.mul(q.y, p.z), p.y);
        var y3 = field.add(field.mul(q.x, p.z), p.x);
        var z3 = field.mul(P256.B, p.z);
        var x3 = field.sub(y3, z3);
        x3 = field.add(field.dbl(x3), x3);
        z3 = field.sub(t1, x3);
        x3 = field.add(t1, x3);
        y3 = field.mul(P256.B, y3);
        const t2 = field.add(field.dbl(p.z), p.z);
        y3 = field.sub(field.sub(y3, t2), t0);
        y3 = field.add(field.dbl(y3), y3);
        t0 = field.sub(field.add(field.dbl(t0), t0), t2);
        t1 = field.mul(t4, y3);
        const t5 = field.mul(t0, y3);
        y3 = field.add(field.mul(x3, z3), t5);
        x3 = field.sub(field.mul(t3, x3), t1);
        z3 = field.add(field.mul(t4, z3), field.mul(t3, t0));
        var result: Projective = .{ .x = x3, .y = y3, .z = z3 };
        const skip: u1 = @intFromBool(q.x.isZero());
        result.x.cMov(p.x, skip);
        result.y.cMov(p.y, skip);
        result.z.cMov(p.z, skip);
        return result;
    }
};

/// `tables[k][j - 1] = j 256^k G` for `j` in 1..8, from signing_table.zig (generated, as
/// aws-lc's `p256_table.h`: building it at comptime takes minutes).
const tables: [32][8]Affine = tables: {
    @setEvalBranchQuota(100_000);
    var result: [32][8]Affine = undefined;
    for (&result, &table_limbs) |*table, *rows| {
        for (table, rows) |*entry, row| {
            entry.* = .{ .x = .{ .limbs = row[0] }, .y = .{ .limbs = row[1] } };
        }
    }
    break :tables result;
};

const table_limbs = @import("signing_table.zig").limbs;

/// `digit 256^table G`, reading every entry of the table; `(0, 0)` for a zero digit.
fn select(table: usize, digit: i8) Affine {
    assert(digit >= -8 and digit <= 8);
    const negative: u1 = @intFromBool(digit < 0);
    const magnitude: u8 = @abs(digit);
    var result: Affine = .{ .x = Fe.zero, .y = Fe.zero };
    for (&tables[table], 1..) |*entry, j| {
        const hit: u1 = @intFromBool(magnitude == j);
        result.x.cMov(entry.x, hit);
        result.y.cMov(entry.y, hit);
    }
    result.y.cMov(field.neg(result.y), negative);
    return result;
}

/// The 64 signed radix-16 digits of `s < 2^255` (big-endian), least significant first, each
/// in [-8, 8) except the last, in [0, 8].
fn radix_16(s: [32]u8) [64]i8 {
    assert(s[0] <= 127);
    var digits: [64]i8 = undefined;
    for (0..32) |i| {
        const byte = s[31 - i];
        digits[2 * i] = @intCast(byte & 15);
        digits[2 * i + 1] = @intCast(byte >> 4);
    }
    for (0..63) |i| {
        const carry = (digits[i] + 8) >> 4;
        digits[i] -= carry << 4;
        digits[i + 1] += carry;
    }
    assert(digits[63] >= 0 and digits[63] <= 8);
    return digits;
}

/// `k G` for a secret nonzero `k`, in constant time.
pub fn mul_base(k: Scalar) Affine {
    assert(!k.isZero());
    // k above (n - 1) / 2 becomes n - k < 2^255, and the result is negated back.
    const high: u1 = @intFromBool(is_high(k));
    var bounded = k;
    bounded.fe.cMov(k.neg().fe, high);
    var bytes = bounded.toBytes(.big);
    defer std.crypto.secureZero(u8, &bytes);
    var digits = radix_16(bytes);
    defer std.crypto.secureZero(i8, &digits);
    var sum = Projective.identity;
    var i: usize = 1;
    while (i < 64) : (i += 2) sum = sum.add_affine(&select(i / 2, digits[i]));
    for (0..4) |_| sum = sum.double();
    i = 0;
    while (i < 64) : (i += 2) sum = sum.add_affine(&select(i / 2, digits[i]));
    const z_inverse = invert_field(sum.z);
    var result: Affine = .{ .x = field.mul(sum.x, z_inverse), .y = field.mul(sum.y, z_inverse) };
    result.y.cMov(field.neg(result.y), high);
    return result;
}

/// Whether `k > (n - 1) / 2`, without branching on `k`.
fn is_high(k: Scalar) bool {
    const half: u256 = (P256.scalar.field_order - 1) / 2;
    const value = std.mem.readInt(u256, &k.toBytes(.big), .big);
    return @subWithOverflow(half, value)[1] == 1;
}

/// `a^-1 mod p` for a nonzero `a`, as `a^(p - 2)` with a fixed 4-bit window.
fn invert_field(a: Fe) Fe {
    assert(!a.isZero());
    return power(Fe, a, Fe.field_order - 2, field.mul, field.sq, Fe.one);
}

/// `k^-1 mod n` for a secret nonzero `k`, as `k^(n - 2)` with a fixed 4-bit window.
pub fn invert_scalar(k: Scalar) Scalar {
    assert(!k.isZero());
    return power(Scalar, k, P256.scalar.field_order - 2, Scalar.mul, Scalar.sq, Scalar.one);
}

/// `base^exponent` for a public `exponent`: the squarings and multiplications, and the table
/// entries read, depend only on the exponent.
fn power(
    comptime T: type,
    base: T,
    comptime exponent: u256,
    comptime mul: anytype,
    comptime square: anytype,
    one: T,
) T {
    // The unrolled loop inlines 256 squarings, whose own limb loops unroll at compile time.
    @setEvalBranchQuota(200_000);
    var powers: [16]T = undefined;
    powers[0] = one;
    powers[1] = base;
    for (2..16) |k| powers[k] = mul(powers[k - 1], base);
    var result = one;
    comptime var shift: u9 = 256;
    inline while (shift > 0) {
        shift -= 4;
        result = square(square(square(square(result))));
        const window: u4 = @truncate(exponent >> shift);
        if (window != 0) result = mul(result, powers[window]);
    }
    return result;
}

const testing = std.testing;

fn expect_base_mul(k: Scalar) !void {
    const expected = (try P256.basePoint.mul(k.toBytes(.big), .big)).affineCoordinates();
    const got = mul_base(k);
    try testing.expect(expected.x.equivalent(got.x));
    try testing.expect(expected.y.equivalent(got.y));
}

test "secp256r1 signing: the generated tables are j 256^k G" {
    var base = P256.basePoint;
    for (&tables) |*table| {
        var multiple = base;
        for (table) |*entry| {
            const affine = multiple.affineCoordinates();
            try testing.expect(affine.x.equivalent(entry.x) and affine.y.equivalent(entry.y));
            try testing.expect(!entry.x.isZero());
            multiple = multiple.add(base);
        }
        for (0..8) |_| base = base.dbl();
    }
}

test "secp256r1 signing: mul_base matches std at the edges" {
    const n = P256.scalar.field_order;
    const half = (n - 1) / 2;
    for ([_]u256{ 1, 2, 7, 8, 9, 15, 16, 17, half - 1, half, half + 1, n - 2, n - 1 }) |value| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, value, .big);
        try expect_base_mul(try Scalar.fromBytes(bytes, .big));
    }
    try expect_base_mul(try Scalar.fromBytes(@splat(0x88), .big));
}

test "secp256r1 signing: mul_base and inverses match std on random scalars" {
    var rng = std.Random.DefaultPrng.init(0x5167);
    for (0..64) |_| {
        var bytes: [32]u8 = undefined;
        rng.random().bytes(&bytes);
        const k = Scalar.fromBytes48(@as([16]u8, @splat(0)) ++ bytes, .big);
        if (k.isZero()) continue;
        try expect_base_mul(k);
        try testing.expect(invert_scalar(k).equivalent(k.invert()));
        const a = Fe.fromBytes(bytes, .big) catch continue;
        if (!a.isZero()) try testing.expect(invert_field(a).equivalent(a.invert()));
    }
}
