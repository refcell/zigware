//! A deliberately naive, independent Ed25519 (ZIP-215) and X25519 implementation for tests.
//!
//! commonware fuzzes this crate against `ed25519-consensus` and `x25519-dalek`; zigware has no
//! third-party code, so the fuzz targets compare against this instead. It shares nothing with
//! `std.crypto.ecc`: field elements are `u256` values reduced with `u512` remainders, points use
//! the unified extended-coordinate addition, and scalar multiplication is plain double-and-add.
//! It is slow and not constant time; never use it outside tests.

const std = @import("std");
const assert = std.debug.assert;
const Sha512 = std.crypto.hash.sha2.Sha512;

/// `p = 2^255 - 19`.
pub const p: u256 = p_int;
const p_int = (1 << 255) - 19;
/// The prime order of the basepoint, `l = 2^252 + 27742317777372353535851937790883648493`.
pub const l: u256 = (1 << 252) + 27742317777372353535851937790883648493;
/// `d = -121665 / 121666 mod p`.
const d: u256 = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;
/// A square root of -1 mod p, `2^((p - 1) / 4)`.
const sqrt_m1: u256 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0;
const base_x = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a;
const base_y = 0x6666666666666666666666666666666666666666666666666666666666666658;

fn add(a: u256, b: u256) u256 {
    assert(a < p and b < p);
    return @intCast((@as(u257, a) + b) % p);
}

fn sub(a: u256, b: u256) u256 {
    assert(a < p and b < p);
    return @intCast((@as(u257, a) + p - b) % p);
}

fn mul(a: u256, b: u256) u256 {
    assert(a < p and b < p);
    return reduce(@as(u512, a) * b);
}

/// `t mod p`, folding with `2^255 = 19 (mod p)`.
fn reduce(t: u512) u256 {
    const mask = (1 << 255) - 1;
    const once = (t & mask) + 19 * (t >> 255); // Below 2^256 * 19.
    const twice = (once & mask) + 19 * (once >> 255); // Below 2^255 + 19 * 2^7.
    var result: u256 = @intCast(twice);
    if (result >= p) result -= p;
    assert(result < p);
    return result;
}

fn pow(base: u256, exponent: u256) u256 {
    var result: u256 = 1;
    var square = base;
    var e = exponent;
    while (e != 0) : (e >>= 1) {
        if (e & 1 == 1) result = mul(result, square);
        square = mul(square, square);
    }
    return result;
}

fn invert(a: u256) u256 {
    return pow(a, p - 2);
}

/// A point `(X : Y : Z : T)` on `-x^2 + y^2 = 1 + d x^2 y^2`, with `x = X/Z`, `y = Y/Z`,
/// `xy = T/Z`.
pub const Point = struct {
    x: u256,
    y: u256,
    z: u256,
    t: u256,

    pub const identity: Point = .{ .x = 0, .y = 1, .z = 1, .t = 0 };
    pub const basepoint: Point = .{
        .x = base_x,
        .y = base_y,
        .z = 1,
        .t = base_x * base_y % p_int,
    };

    /// The unified addition law ("add-2008-hwcd-3"), complete on this curve.
    pub fn sum(a: Point, b: Point) Point {
        const pa = mul(sub(a.y, a.x), sub(b.y, b.x));
        const pb = mul(add(a.y, a.x), add(b.y, b.x));
        const pc = mul(mul(a.t, add(d, d)), b.t);
        const pd = mul(add(a.z, a.z), b.z);
        const e = sub(pb, pa);
        const f = sub(pd, pc);
        const g = add(pd, pc);
        const h = add(pb, pa);
        return .{ .x = mul(e, f), .y = mul(g, h), .z = mul(f, g), .t = mul(e, h) };
    }

    pub fn negate(a: Point) Point {
        return .{ .x = sub(0, a.x), .y = a.y, .z = a.z, .t = sub(0, a.t) };
    }

    /// `[scalar] a` by double-and-add from the top bit.
    pub fn scale(a: Point, scalar: u256) Point {
        var result = identity;
        var bit: u9 = 256;
        while (bit > 0) {
            bit -= 1;
            result = result.sum(result);
            if ((scalar >> @intCast(bit)) & 1 == 1) result = result.sum(a);
        }
        return result;
    }

    pub fn is_identity(a: Point) bool {
        return a.x == 0 and a.y == a.z;
    }

    pub fn compress(a: Point) [32]u8 {
        const z_inverse = invert(a.z);
        const x = mul(a.x, z_inverse);
        const y = mul(a.y, z_inverse);
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, y | (@as(u256, @intCast(x & 1)) << 255), .little);
        return bytes;
    }

    /// ZIP-215 decoding, as curve25519-dalek's: `y` is reduced mod p (non-canonical encodings
    /// are accepted), and the sign bit picks the root (so `x = 0` with the sign bit set is
    /// accepted as `x = 0`). Null when `y` has no point.
    pub fn decompress(bytes: [32]u8) ?Point {
        const encoded = std.mem.readInt(u256, &bytes, .little);
        const sign_bit = encoded >> 255;
        const y = (encoded & ((1 << 255) - 1)) % p;
        const y2 = mul(y, y);
        const x2 = mul(sub(y2, 1), invert(add(mul(d, y2), 1)));
        var x = pow(x2, (p + 3) / 8);
        if (mul(x, x) != x2) {
            if (mul(x, x) != sub(0, x2)) return null;
            x = mul(x, sqrt_m1);
        }
        assert(mul(x, x) == x2);
        if (x & 1 != sign_bit) x = sub(0, x);
        return .{ .x = x, .y = y, .z = 1, .t = mul(x, y) };
    }
};

fn reduce_wide(digest: [64]u8) u256 {
    return @intCast(std.mem.readInt(u512, &digest, .little) % l);
}

/// `H(R || A || message) mod l`.
fn challenge(r: *const [32]u8, a: *const [32]u8, message: []const u8) u256 {
    var hasher = Sha512.init(.{});
    hasher.update(r);
    hasher.update(a);
    hasher.update(message);
    return reduce_wide(hasher.finalResult());
}

/// ZIP-215 verification of `signature` over `message` by the key encoded as `key`, as
/// ed25519-consensus: canonical `s`, lenient `A` and `R`, and `[8](sB - R - kA) = 0`.
pub fn verify(key: [32]u8, signature: [64]u8, message: []const u8) bool {
    const s = std.mem.readInt(u256, signature[32..64], .little);
    if (s >= l) return false;
    const a = Point.decompress(key) orelse return false;
    const r = Point.decompress(signature[0..32].*) orelse return false;
    const k = challenge(signature[0..32], &key, message);
    const lhs = Point.basepoint.scale(s);
    const rhs = r.sum(a.scale(k));
    return lhs.sum(rhs.negate()).scale(8).is_identity();
}

/// The RFC 8032 public key of `seed`.
pub fn public_key(seed: [32]u8) [32]u8 {
    var digest: [64]u8 = undefined;
    Sha512.hash(&seed, &digest, .{});
    return Point.basepoint.scale(clamp_ed25519(digest[0..32].*)).compress();
}

fn clamp_ed25519(bytes: [32]u8) u256 {
    var scalar = std.mem.readInt(u256, &bytes, .little);
    scalar &= ~@as(u256, 7);
    scalar &= (1 << 254) - 1;
    scalar |= 1 << 254;
    return scalar;
}

/// The RFC 8032 signature of `message` by `seed`.
pub fn sign(seed: [32]u8, message: []const u8) [64]u8 {
    var digest: [64]u8 = undefined;
    Sha512.hash(&seed, &digest, .{});
    const a = clamp_ed25519(digest[0..32].*);
    const key = Point.basepoint.scale(a).compress();
    var hasher = Sha512.init(.{});
    hasher.update(digest[32..64]);
    hasher.update(message);
    const r = reduce_wide(hasher.finalResult());
    const r_bytes = Point.basepoint.scale(r).compress();
    const k = challenge(&r_bytes, &key, message);
    const s: u256 = @intCast((@as(u512, r) + @as(u512, k) * (a % l)) % l);
    var signature: [64]u8 = undefined;
    signature[0..32].* = r_bytes;
    std.mem.writeInt(u256, signature[32..64], s, .little);
    return signature;
}

/// RFC 7748 X25519: the clamped `scalar` times the u-coordinate `u` (bit 255 masked,
/// non-canonical values reduced), by the Montgomery ladder.
pub fn x25519(scalar: [32]u8, u: [32]u8) [32]u8 {
    var k = std.mem.readInt(u256, &scalar, .little);
    k &= ~@as(u256, 7);
    k &= (1 << 255) - 1;
    k |= 1 << 254;
    const x1 = (std.mem.readInt(u256, &u, .little) & ((1 << 255) - 1)) % p;
    var x2: u256 = 1;
    var z2: u256 = 0;
    var x3 = x1;
    var z3: u256 = 1;
    var swap: u1 = 0;
    var bit: u9 = 255;
    while (bit > 0) {
        bit -= 1;
        const k_t: u1 = @intCast((k >> @intCast(bit)) & 1);
        if (swap ^ k_t == 1) {
            std.mem.swap(u256, &x2, &x3);
            std.mem.swap(u256, &z2, &z3);
        }
        swap = k_t;
        const a = add(x2, z2);
        const aa = mul(a, a);
        const b = sub(x2, z2);
        const bb = mul(b, b);
        const e = sub(aa, bb);
        const da = mul(sub(x3, z3), a);
        const cb = mul(add(x3, z3), b);
        x3 = mul(add(da, cb), add(da, cb));
        z3 = mul(x1, mul(sub(da, cb), sub(da, cb)));
        x2 = mul(aa, bb);
        z2 = mul(e, add(aa, mul(121665, e)));
    }
    if (swap == 1) {
        std.mem.swap(u256, &x2, &x3);
        std.mem.swap(u256, &z2, &z3);
    }
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, mul(x2, invert(z2)), .little);
    return out;
}
