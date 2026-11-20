//! Shared secp256r1 key storage and ECDSA arithmetic (commonware `secp256r1/common.rs`).
//!
//! commonware signs with the `p256` crate and verifies with aws-lc-rs; this file reproduces
//! both on `std.crypto.ecc.P256` arithmetic:
//!
//! - Private keys are canonical, non-zero big-endian scalars. `random` draws 32 bytes at a
//!   time until they form one, as `SigningKey::generate_from_rng` does, so a seeded RNG yields
//!   the same key as in Rust.
//! - Public keys are 33-byte compressed SEC 1 points; decoding rejects non-canonical x
//!   coordinates and x values that are not on the curve.
//! - Signing hashes the payload with SHA-256 and derives `k` with RFC 6979 (HMAC-SHA256, no
//!   additional data), retrying the next `k` when `r` or `s` is zero, then moves `s` into the
//!   lower half of the order (BIP 62) and flips the recovery id's y parity to match. std's
//!   ECDSA is not used for signing: its nonce mixes in a noise block, so it is not RFC 6979.
//! - `k G`, `d G`, and `k^-1` run in constant time in `signing.zig` (a fixed-base table, as
//!   the `p256` crate's `BasepointTable`), never through verify.zig's variable-time code.
//! - Verification is plain ECDSA (`verify.zig`, structured as aws-lc's); public-key recovery
//!   follows the `ecdsa` crate.

const std = @import("std");
const utils = @import("utils");
const assert = std.debug.assert;
const codec = @import("codec");
const Opaque = @import("../secret.zig").Opaque;
const signing = @import("signing.zig");
const verify = @import("verify.zig");
const P256 = std.crypto.ecc.P256;
const Scalar = P256.scalar.Scalar;
const Fe = P256.Fe;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const curve_name = "secp256r1";
pub const private_key_length = 32;
/// Y parity tag, then the x coordinate.
pub const public_key_length = 33;

/// The group order n, big-endian.
const order_bytes: [32]u8 = order: {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, P256.scalar.field_order, .big);
    break :order bytes;
};
/// (n - 1) / 2: an `s` above it is "high".
const half_order_bytes: [32]u8 = half: {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, (P256.scalar.field_order - 1) / 2, .big);
    break :half bytes;
};

/// Draws from a broken RNG are rejected forever; a working one needs more than one draw with
/// probability about 2^-32, so this bound is never reached in practice.
const draws_max = 64;

/// SHA-256 of `union_unique(namespace, message)`, or of `message` alone without a namespace.
pub fn payload_hash(namespace: ?[]const u8, message: []const u8) [32]u8 {
    var hasher = Sha256.init(.{});
    if (namespace) |ns| {
        var prefix: [codec.varint.max_size(u32)]u8 = undefined;
        var writer = codec.Writer.init(&prefix);
        codec.write(usize, ns.len, &writer);
        assert(writer.written().len >= 1);
        hasher.update(writer.written());
        hasher.update(ns);
    }
    hasher.update(message);
    return hasher.finalResult();
}

/// Reduces a 32-byte big-endian integer modulo n (`bytes2scalar`).
fn reduce(bytes: [32]u8) Scalar {
    var wide: [48]u8 = @splat(0);
    wide[16..].* = bytes;
    return Scalar.fromBytes48(wide, .big);
}

/// The scalar a canonical, non-zero 32-byte big-endian value encodes, or null.
fn nonzero_scalar(bytes: [32]u8) ?Scalar {
    const scalar = Scalar.fromBytes(bytes, .big) catch return null;
    if (scalar.isZero()) return null;
    return scalar;
}

/// Whether `s` is in the upper half of the order (`IsHigh`).
pub fn is_high(s: [32]u8) bool {
    return std.mem.order(u8, &s, &half_order_bytes) == .gt;
}

/// ECDSA `r || s` with both scalars validated: in `[1, n)`, and `s` not high.
pub const Scalars = struct {
    r: Scalar,
    s: Scalar,

    /// Parses `r || s` the way commonware decodes a signature, or returns null.
    pub fn parse(raw: *const [64]u8) ?Scalars {
        const r = nonzero_scalar(raw[0..32].*) orelse return null;
        const s = nonzero_scalar(raw[32..64].*) orelse return null;
        if (is_high(raw[32..64].*)) return null;
        return .{ .r = r, .s = s };
    }

    /// Decodes `r || s` with commonware's errors: out-of-range scalars are `Wrapped`
    /// (`Signature::from_slice`), then a high `s` is `Invalid`.
    pub fn read(reader: *codec.Reader, raw: *const [64]u8) codec.Error!void {
        if (nonzero_scalar(raw[0..32].*) == null or nonzero_scalar(raw[32..64].*) == null) {
            return reader.wrapped(curve_name);
        }
        if (is_high(raw[32..64].*)) return reader.invalid(curve_name, "Signature S is high");
        assert(parse(raw) != null);
    }
};

/// Recovery id byte: bit 0 is the y parity of `R`, bit 1 whether `R.x` was reduced mod n.
pub const RecoveryId = u2;

/// A fresh signature: `r || s` with low `s`, and the recovery id of `R` after normalization.
pub const Signed = struct {
    raw: [64]u8,
    recovery_id: RecoveryId,
};

/// RFC 6979 section 3.2 with HMAC-SHA256 and q = n (qlen = hlen = 256): the HMAC-DRBG that
/// yields candidate nonces in order.
const NonceGenerator = struct {
    key: [32]u8,
    v: [32]u8,

    fn init(secret: *const [32]u8, hash: [32]u8) NonceGenerator {
        // bits2octets(h1): with qlen = hlen this is h1 mod n.
        const h = reduce(hash).toBytes(.big);
        var self: NonceGenerator = .{ .key = @splat(0x00), .v = @splat(0x01) };
        inline for (.{ 0x00, 0x01 }) |separator| {
            var mac = HmacSha256.init(&self.key);
            mac.update(&self.v);
            mac.update(&.{separator});
            mac.update(secret);
            mac.update(&h);
            mac.final(&self.key);
            HmacSha256.create(&self.v, &self.v, &self.key);
        }
        return self;
    }

    /// The next candidate in `[1, n)`.
    fn next(self: *NonceGenerator) Scalar {
        var draws: u32 = 0;
        while (draws < draws_max) : (draws += 1) {
            HmacSha256.create(&self.v, &self.v, &self.key);
            const candidate = self.v;
            var mac = HmacSha256.init(&self.key);
            mac.update(&self.v);
            mac.update(&.{0x00});
            mac.final(&self.key);
            HmacSha256.create(&self.v, &self.v, &self.key);
            if (nonzero_scalar(candidate)) |k| return k;
        }
        @panic("secp256r1: RFC 6979 produced no nonce");
    }

    fn zeroize(self: *NonceGenerator) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.v);
    }
};

/// Signs the payload hash `hash` with secret scalar `d` (big-endian).
fn sign_prehashed(secret: *const [32]u8, hash: [32]u8) Signed {
    const d = nonzero_scalar(secret.*).?;
    const z = reduce(hash);
    var nonces = NonceGenerator.init(secret, hash);
    defer nonces.zeroize();
    var attempts: u32 = 0;
    while (attempts < draws_max) : (attempts += 1) {
        const k = nonces.next();
        // k is in [1, n), so k * G is never the identity.
        const affine = signing.mul_base(k);
        const x_bytes = affine.x.toBytes(.big);
        const r = reduce(x_bytes);
        const s = signing.invert_scalar(k).mul(z.add(r.mul(d)));
        if (r.isZero() or s.isZero()) continue;

        var y_odd = affine.y.isOdd();
        const x_reduced = !std.mem.eql(u8, &r.toBytes(.big), &x_bytes);
        var s_bytes = s.toBytes(.big);
        if (is_high(s_bytes)) {
            // Negating s negates k: R.x is unchanged and R.y flips.
            s_bytes = s.neg().toBytes(.big);
            y_odd = !y_odd;
        }
        assert(!is_high(s_bytes));
        const recovery_id: RecoveryId = @as(u2, @intFromBool(x_reduced)) << 1 |
            @intFromBool(y_odd);
        return .{ .raw = r.toBytes(.big) ++ s_bytes, .recovery_id = recovery_id };
    }
    @panic("secp256r1: no nonce produced a signature");
}

/// A secp256r1 private key and its public key. Formatting never shows the key.
pub const PrivateKeyInner = struct {
    raw: Opaque([private_key_length]u8),
    public: PublicKeyInner,

    /// The key encoded by `raw`, or null if it is zero or not below n.
    pub fn from_bytes(raw: [private_key_length]u8) ?PrivateKeyInner {
        const d = nonzero_scalar(raw) orelse return null;
        // d is in [1, n), so d * G is never the identity.
        const point = signing.mul_base(d);
        return .{ .raw = .{ .value = raw }, .public = .from_affine(point.x, point.y) };
    }

    /// Draws 32-byte candidates from `rng` until one is a valid key.
    pub fn random(rng: anytype) PrivateKeyInner {
        var bytes: [private_key_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &bytes);
        var draws: u32 = 0;
        while (draws < draws_max) : (draws += 1) {
            rng.fill_bytes(&bytes);
            if (from_bytes(bytes)) |key| return key;
        }
        @panic("secp256r1: rng produced no valid key");
    }

    pub fn sign(self: *const PrivateKeyInner, namespace: ?[]const u8, message: []const u8) Signed {
        return sign_prehashed(&self.raw.value, payload_hash(namespace, message));
    }

    /// Constant-time comparison of the keys.
    pub fn eql(a: *const PrivateKeyInner, b: *const PrivateKeyInner) bool {
        return std.crypto.timing_safe.eql([private_key_length]u8, a.raw.value, b.raw.value);
    }

    pub fn zeroize(self: *PrivateKeyInner) void {
        std.crypto.secureZero(u8, &self.raw.value);
    }

    pub fn write(self: *const PrivateKeyInner, writer: *codec.Writer) void {
        writer.write_bytes(&self.raw.value);
    }

    pub fn read(reader: *codec.Reader) codec.Error!PrivateKeyInner {
        const raw = try reader.take_array(private_key_length);
        return from_bytes(raw.*) orelse reader.wrapped(curve_name);
    }
};

/// A secp256r1 public key: its compressed encoding and the decoded point, in affine
/// coordinates so verification needs no inversion to use it.
pub const PublicKeyInner = struct {
    raw: [public_key_length]u8,
    point: verify.Affine,

    pub fn from_point(point: P256) PublicKeyInner {
        point.rejectIdentity() catch unreachable;
        const affine = point.affineCoordinates();
        return .from_affine(affine.x, affine.y);
    }

    /// The key of the curve point `(x, y)`.
    pub fn from_affine(x: Fe, y: Fe) PublicKeyInner {
        var raw: [public_key_length]u8 = undefined;
        raw[0] = if (y.isOdd()) 0x03 else 0x02;
        raw[1..].* = x.toBytes(.big);
        return .{ .raw = raw, .point = .{ .x = x, .y = y } };
    }

    /// Decodes a compressed point, or returns null when it is not one.
    pub fn from_bytes(raw: [public_key_length]u8) ?PublicKeyInner {
        if (raw[0] != 0x02 and raw[0] != 0x03) return null;
        const point = P256.fromSec1(&raw) catch return null;
        point.rejectIdentity() catch return null;
        // fromSec1 returns the point with Z = 1, so X and Y are its affine coordinates.
        assert(point.z.equivalent(Fe.one));
        return .{ .raw = raw, .point = .{ .x = point.x, .y = point.y } };
    }

    /// Verifies ECDSA `r || s` (already validated) over the payload hash `hash`.
    pub fn verify_prehashed(self: *const PublicKeyInner, hash: [32]u8, scalars: Scalars) bool {
        return verify.verify(self.point, reduce(hash), scalars.r, scalars.s);
    }

    pub fn eql(a: *const PublicKeyInner, b: *const PublicKeyInner) bool {
        return utils.bytes_eql(a.raw.len, &a.raw, &b.raw);
    }

    pub fn order(a: *const PublicKeyInner, b: *const PublicKeyInner) std.math.Order {
        return std.mem.order(u8, &a.raw, &b.raw);
    }

    pub fn write(self: *const PublicKeyInner, writer: *codec.Writer) void {
        writer.write_bytes(&self.raw);
    }

    pub fn read(reader: *codec.Reader) codec.Error!PublicKeyInner {
        const raw = try reader.take_array(public_key_length);
        return from_bytes(raw.*) orelse reader.invalid(curve_name, "Invalid PublicKey");
    }
};

/// Recovers the public key that produced `scalars` over `hash` (`recover_from_prehash`), or
/// null when no point matches.
pub fn recover(hash: [32]u8, scalars: Scalars, recovery_id: RecoveryId) ?PublicKeyInner {
    var x_int = std.mem.readInt(u256, &scalars.r.toBytes(.big), .big);
    if (recovery_id & 2 != 0) {
        x_int, const overflow = @addWithOverflow(x_int, P256.scalar.field_order);
        if (overflow != 0) return null;
    }
    var x_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &x_bytes, x_int, .big);
    const x = Fe.fromBytes(x_bytes, .big) catch return null;
    const y = P256.recoverY(x, recovery_id & 1 != 0) catch return null;
    const point_r = P256.fromAffineCoordinates(.{ .x = x, .y = y }) catch return null;

    const r_inverse = scalars.r.invert();
    const scalar_g = r_inverse.mul(reduce(hash)).neg().toBytes(.big);
    const scalar_q = r_inverse.mul(scalars.s).toBytes(.big);
    const point = P256.mulDoubleBasePublic(P256.basePoint, scalar_g, point_r, scalar_q, .big) catch
        return null;
    return .from_point(point);
}

comptime {
    assert(order_bytes[0] == 0xff);
    assert(half_order_bytes[0] == 0x7f);
}
