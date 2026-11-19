//! Constant-time fixed-base multiplication `s B` (curve25519-dalek's `EdwardsBasepointTable`
//! and `mul_base`, which commonware's ed25519 keys and SAKE's X25519 keys use).
//!
//! `s` is written in 64 signed radix-16 digits `e_i` in [-8, 8], and
//! `s B = 16 (sum of e_i 16^(i-1) B, i odd) + (sum of e_i 16^i B, i even)`. Each sum term is
//! read from table `i / 2`, which holds `B 256^(i/2)` times 1..8, so the whole product is 64
//! table additions and 4 doublings, where std's `basePoint.mul` doubles 252 times. Every
//! lookup scans its whole table with conditional moves, so the time does not depend on `s`.

const std = @import("std");
const assert = std.debug.assert;
const verify_msm = @import("verify_msm.zig");

const Point = verify_msm.Point;
const Fe = Point.Fe;
const Cached = verify_msm.Cached;

/// `tables[k][j - 1] = j 256^k B` for `j` in 1..8 (dalek's `ED25519_BASEPOINT_TABLE`).
const tables: [32][8]Cached = tables: {
    @setEvalBranchQuota(1_000_000_000);
    var result: [32][8]Cached = undefined;
    var base = plain_base_point();
    for (&result) |*table| {
        const step = Cached.from(base);
        var multiple = base;
        table[0] = step;
        for (table[1..]) |*entry| {
            multiple = verify_msm.add_cached(multiple, &step, false);
            entry.* = .from(multiple);
        }
        for (0..8) |_| base = base.dbl();
    }
    break :tables result;
};

/// `B` without std's `is_base` flag.
fn plain_base_point() Point {
    const b = Point.basePoint;
    return .{ .x = b.x, .y = b.y, .z = b.z, .t = b.t };
}

const identity: Cached = .{ .y_plus_x = Fe.one, .y_minus_x = Fe.one, .z = Fe.one, .t2d = Fe.zero };

/// `s B` for a little-endian scalar `s` below 2^255 (any clamped or reduced scalar), in
/// constant time.
pub fn mul_base(s: [32]u8) Point {
    assert(s[31] <= 127);
    var digits = radix_16(s);
    defer std.crypto.secureZero(i8, &digits);
    var sum = Point.identityElement;
    var i: usize = 1;
    while (i < 64) : (i += 2) sum = verify_msm.add_cached(sum, &select(i / 2, digits[i]), false);
    for (0..4) |_| sum = sum.dbl();
    i = 0;
    while (i < 64) : (i += 2) sum = verify_msm.add_cached(sum, &select(i / 2, digits[i]), false);
    return sum;
}

/// The X25519 public key of `secret` (RFC 7748): the Montgomery u = (Z + Y) / (Z - Y) of
/// `clamp(secret) B`, as dalek's `mul_base_clamped(..).to_montgomery()`.
pub fn x25519_public_key(secret: [32]u8) [32]u8 {
    var clamped = secret;
    defer std.crypto.secureZero(u8, &clamped);
    Point.scalar.clamp(&clamped);
    const p = mul_base(clamped);
    return p.z.add(p.y).mul(p.z.sub(p.y).invert()).toBytes();
}

/// The 64 signed radix-16 digits of `s < 2^255`, each in [-8, 8) except the last, in [0, 8]
/// (dalek's `as_radix_16`).
fn radix_16(s: [32]u8) [64]i8 {
    var digits: [64]i8 = undefined;
    for (s, 0..) |byte, i| {
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

/// `digit 256^table B` as a cached point, reading every entry of the table.
fn select(table: usize, digit: i8) Cached {
    assert(digit >= -8 and digit <= 8);
    const negative: u8 = @intFromBool(digit < 0);
    const magnitude: u8 = @intCast(@abs(digit));
    var result = identity;
    for (&tables[table], 1..) |*entry, j| {
        const hit: u64 = @intFromBool(magnitude == j);
        result.y_plus_x.cMov(entry.y_plus_x, hit);
        result.y_minus_x.cMov(entry.y_minus_x, hit);
        result.z.cMov(entry.z, hit);
        result.t2d.cMov(entry.t2d, hit);
    }
    const y_plus_x = result.y_plus_x;
    result.y_plus_x.cMov(result.y_minus_x, negative);
    result.y_minus_x.cMov(y_plus_x, negative);
    result.t2d.cMov(result.t2d.neg(), negative);
    return result;
}

const testing = std.testing;
const fuzz = @import("../fuzz.zig");

/// Checks `mul_base` against std's `basePoint.mul` on `s` (taken below 2^255), and the X25519
/// key against std's ladder.
fn check_against_std(s: [32]u8) !void {
    var bounded = s;
    bounded[31] &= 127;
    const expected = Point.basePoint.mul(bounded) catch Point.identityElement;
    try testing.expectEqualSlices(u8, &expected.toBytes(), &mul_base(bounded).toBytes());
    const ladder = std.crypto.dh.X25519.recoverPublicKey(s);
    try testing.expectEqualSlices(u8, &ladder, &x25519_public_key(s));
}

test "base_mul: edge scalars match std" {
    try check_against_std(@splat(0));
    var one: [32]u8 = @splat(0);
    one[0] = 1;
    try check_against_std(one);
    var order_minus_one: [32]u8 = undefined;
    std.mem.writeInt(u256, &order_minus_one, Point.scalar.field_order - 1, .little);
    try check_against_std(order_minus_one);
    order_minus_one[31] = 0x7f;
    try check_against_std(order_minus_one);
    try check_against_std(@splat(0x88));
}

test "base_mul: RFC 7748 X25519 public keys" {
    // RFC 7748 section 6.1: Alice's and Bob's private and public keys.
    const cases = [_][2][]const u8{
        .{
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        },
        .{
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        },
    };
    for (cases) |case| {
        var secret: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&secret, case[0]);
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, case[1]);
        try testing.expectEqualSlices(u8, &expected, &x25519_public_key(secret));
    }
}

test "base_mul fuzz: matches std's basePoint.mul and X25519 ladder" {
    var random = fuzz.prng(0xba5e);
    var s: [32]u8 = undefined;
    for (0..fuzz.iterations(64)) |_| {
        random.random().bytes(&s);
        try check_against_std(s);
    }
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var bytes: [32]u8 = undefined;
            smith.bytes(&bytes);
            try check_against_std(bytes);
        }
    }.run, .{});
}
