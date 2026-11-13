//! Ed25519 signing and ZIP-215 verification (commonware `ed25519/core`, a vendored
//! `ed25519-consensus`), on `std.crypto`'s Edwards25519 field and group arithmetic.
//!
//! Verification follows ZIP-215 (https://zips.z.cash/zip-0215), so every node agrees on
//! which signatures are valid:
//! - `A` and `R` may be non-canonical encodings (y >= p, or x = 0 with the sign bit set) and
//!   may have small order; they decode leniently, as curve25519-dalek's `decompress` does.
//! - `s` must be canonical (s < l).
//! - The check is cofactored: `[8](R - (s B - k A)) == 0` with `k = H(R || A || M) mod l`,
//!   where `A` is hashed as encoded, not re-encoded.
//!
//! `std.crypto.sign.Ed25519` is strict (it rejects small-order and non-canonical points), so
//! only its arithmetic is used here. Signing matches RFC 8032 with the clamped scalar reduced
//! mod l before use, which gives the same signatures.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const transcript = @import("../transcript.zig");

pub const Point = std.crypto.ecc.Edwards25519;
const Fe = Point.Fe;
const scalar = Point.scalar;
const Sha512 = std.crypto.hash.sha2.Sha512;

/// Decodes a point from its 32-byte encoding with ZIP-215's lenient rules, or returns null
/// when the y coordinate is not on the curve.
pub fn decompress(bytes: [32]u8) ?Point {
    const y = Fe.fromBytes(bytes); // Ignores the sign bit; a non-canonical y is taken mod p.
    const z = Fe.one;
    const y2 = y.sq();
    const u = y2.sub(z);
    const v = y2.mul(Fe.edwards25519d).add(z);
    var x = u.mul(v).pow2523().mul(u);
    const vxx = x.sq().mul(v);
    const has_m_root = vxx.sub(u).isZero();
    const has_p_root = vxx.add(u).isZero();
    if (!has_m_root and !has_p_root) return null;
    x.cMov(x.mul(Fe.sqrtm1), 1 - @intFromBool(has_m_root));
    // Unlike std's `fromBytes`, x = 0 with the sign bit set is accepted (negating 0 is 0).
    x.cMov(x.neg(), @intFromBool(x.isNegative()) ^ (bytes[31] >> 7));
    const point: Point = .{ .x = x, .y = y, .z = z, .t = x.mul(y) };
    assert(!point.is_base);
    return point;
}

/// True for the identity in projective coordinates.
pub fn is_identity(point: Point) bool {
    return point.x.isZero() and point.y.equivalent(point.z);
}

/// True when `[8] point` is the identity: the point lies in the torsion subgroup.
pub fn is_small_order(point: Point) bool {
    return is_identity(point.clearCofactor());
}

/// A public key: its encoding as given, and the negated point it decodes to.
pub const VerificationKey = struct {
    bytes: [32]u8,
    minus_a: Point,
    /// `A` has order dividing 8, which std's double-base multiplication rejects.
    small_order: bool,

    pub fn decode(bytes: [32]u8) ?VerificationKey {
        const point = decompress(bytes) orelse return null;
        return .{ .bytes = bytes, .minus_a = point.neg(), .small_order = is_small_order(point) };
    }

    /// Verifies `signature` given `k = H(R || A || M) mod l`.
    pub fn verify_prehashed(
        self: *const VerificationKey,
        signature: *const [64]u8,
        k: [32]u8,
    ) bool {
        const s = signature[32..64].*;
        scalar.rejectNonCanonical(s) catch return false;
        const r = decompress(signature[0..32].*) orelse return false;
        const r_prime = self.double_scalar_mul(k, s);
        return is_identity(r.sub(r_prime).clearCofactor());
    }

    /// `k (-A) + s B`, in variable time (every input is public).
    fn double_scalar_mul(self: *const VerificationKey, k: [32]u8, s: [32]u8) Point {
        if (!self.small_order) {
            // Proof: std rejects only points whose fourth multiple has x = 0, i.e. points of
            // order dividing 8, which `small_order` excludes.
            return Point.mulDoubleBasePublic(Point.basePoint, s, self.minus_a, k) catch
                unreachable;
        }
        var sum = MultiScalar.init();
        sum.add(Point.basePoint, s);
        sum.add(self.minus_a, k);
        return sum.finish();
    }
};

/// Hashes the signed payload: the raw message, or `union_unique(namespace, message)`
/// (the varint of the namespace length, the namespace, then the message).
/// Streams the payload so signing never allocates. Like commonware's `union_unique`, a
/// namespace longer than `u32` bytes is a programming error.
pub fn update_payload(hasher: *Sha512, namespace: ?[]const u8, message: []const u8) void {
    if (namespace) |ns| {
        var prefix: [codec.varint.max_size(u32)]u8 = undefined;
        var writer = codec.Writer.init(&prefix);
        codec.varint.write(u32, @intCast(ns.len), &writer);
        assert(writer.written().len == codec.varint.size(u32, @intCast(ns.len)));
        hasher.update(writer.written());
        hasher.update(ns);
    }
    hasher.update(message);
}

/// `k = H(R || A || payload) mod l`.
pub fn challenge(
    r_bytes: *const [32]u8,
    a_bytes: *const [32]u8,
    namespace: ?[]const u8,
    message: []const u8,
) [32]u8 {
    var hasher = Sha512.init(.{});
    hasher.update(r_bytes);
    hasher.update(a_bytes);
    update_payload(&hasher, namespace, message);
    return scalar.reduce64(hasher.finalResult());
}

/// An expanded signing key (RFC 8032 section 5.1.5).
pub const SigningKey = struct {
    seed: [32]u8,
    /// The clamped secret scalar, reduced mod l.
    secret: [32]u8,
    prefix: [32]u8,
    verification_key: VerificationKey,

    pub fn from_seed(seed: [32]u8) SigningKey {
        var digest: [64]u8 = undefined;
        Sha512.hash(&seed, &digest, .{});
        defer std.crypto.secureZero(u8, &digest);
        var clamped = digest[0..32].*;
        scalar.clamp(&clamped);
        const secret = scalar.reduce(clamped);
        std.crypto.secureZero(u8, &clamped);
        // Proof: a clamped scalar is in [2^254, 2^255) and a multiple of 8, so it is not a
        // multiple of l (8 l > 2^255) and the product is never the identity.
        const a = Point.basePoint.mul(secret) catch unreachable;
        const a_bytes = a.toBytes();
        const key: SigningKey = .{
            .seed = seed,
            .secret = secret,
            .prefix = digest[32..64].*,
            .verification_key = .{ .bytes = a_bytes, .minus_a = a.neg(), .small_order = false },
        };
        assert(!is_small_order(a));
        return key;
    }

    /// Signs `message`, framed with `namespace` when it is given; deterministic.
    pub fn sign(self: *const SigningKey, namespace: ?[]const u8, message: []const u8) [64]u8 {
        var hasher = Sha512.init(.{});
        hasher.update(&self.prefix);
        update_payload(&hasher, namespace, message);
        var nonce_digest = hasher.finalResult();
        defer std.crypto.secureZero(u8, &nonce_digest);
        const nonce = scalar.reduce64(nonce_digest);
        // A zero nonce makes R the identity, whose encoding is still a valid signature.
        const r = Point.basePoint.mul(nonce) catch Point.identityElement;
        var signature: [64]u8 = undefined;
        signature[0..32].* = r.toBytes();
        const k = challenge(signature[0..32], &self.verification_key.bytes, namespace, message);
        signature[32..64].* = scalar.mulAdd(k, self.secret, nonce);
        // Proof: mulAdd reduces mod l, so s is canonical.
        scalar.rejectNonCanonical(signature[32..64].*) catch unreachable;
        return signature;
    }

    pub fn zeroize(self: *SigningKey) void {
        std.crypto.secureZero(u8, &self.seed);
        std.crypto.secureZero(u8, &self.secret);
        std.crypto.secureZero(u8, &self.prefix);
    }
};

/// Accumulates `sum s_i P_i` in variable time (Straus with 4-bit windows), for public
/// scalars and points of any order. Points are buffered `chunk_points` at a time, so the
/// working set is bounded and nothing allocates.
pub const MultiScalar = struct {
    const chunk_points = 8;
    const windows = 64;

    tables: [chunk_points][16]Point,
    scalars: [chunk_points][32]u8,
    count: usize,
    total: Point,

    pub fn init() MultiScalar {
        return .{
            .tables = undefined,
            .scalars = undefined,
            .count = 0,
            .total = Point.identityElement,
        };
    }

    /// Adds `s P` to the sum; `s` is a 32-byte little-endian scalar (any value below 2^256).
    pub fn add(self: *MultiScalar, point: Point, s: [32]u8) void {
        assert(self.count < chunk_points);
        const table = &self.tables[self.count];
        table[0] = Point.identityElement;
        table[1] = point;
        for (2..16) |digit| table[digit] = table[digit - 1].add(point);
        self.scalars[self.count] = s;
        self.count += 1;
        if (self.count == chunk_points) self.flush();
        assert(self.count < chunk_points);
    }

    fn flush(self: *MultiScalar) void {
        assert(self.count <= chunk_points);
        var acc = Point.identityElement;
        var window: usize = windows;
        while (window > 0) {
            window -= 1;
            if (window + 1 < windows) acc = acc.dbl().dbl().dbl().dbl();
            for (self.tables[0..self.count], self.scalars[0..self.count]) |*table, *s| {
                const byte = s[window / 2];
                const digit = if (window % 2 == 0) byte & 0x0f else byte >> 4;
                if (digit != 0) acc = acc.add(table[digit]);
            }
        }
        self.total = self.total.add(acc);
        self.count = 0;
    }

    pub fn finish(self: *MultiScalar) Point {
        if (self.count > 0) self.flush();
        assert(self.count == 0);
        return self.total;
    }
};

/// One signature to check in a batch: the key, the 64-byte signature, and the payload.
pub const BatchItem = struct {
    key: *const VerificationKey,
    signature: *const [64]u8,
    namespace: ?[]const u8,
    message: []const u8,
};

const noise_batch_verify = "batch_verify";

/// Verifies `count` signatures at once: `[8](sum z_i (R_i + k_i A_i - s_i B)) == 0` with
/// random 128-bit `z_i`, which an attacker must not predict. As in commonware, the `z_i`
/// come from a v1 transcript resumed from a 32-byte seed drawn from `rng`, committed to the
/// batch index (always 0: one batch on the calling thread), and read as `batch_verify`
/// noise. `items` has `item(index) BatchItem`. An empty batch is rejected.
pub fn verify_batch(rng: anytype, count: usize, items: anytype) bool {
    if (count == 0) return false;
    var seed: transcript.Summary = undefined;
    rng.fill_bytes(&seed.bytes);
    var shard = transcript.Transcript.resume_from(seed, .v1);
    shard.commit(&codec.encode_fixed(u64, 0));
    var noise = shard.noise(noise_batch_verify);
    var sum = MultiScalar.init();
    var base_coefficient = scalar.zero;
    for (0..count) |index| {
        const item: BatchItem = items.item(index);
        const s = item.signature[32..64].*;
        scalar.rejectNonCanonical(s) catch return false;
        const r = decompress(item.signature[0..32].*) orelse return false;
        const k = challenge(item.signature[0..32], &item.key.bytes, item.namespace, item.message);
        var z = scalar.zero;
        noise.fill_bytes(z[0..16]);
        base_coefficient = scalar.sub(base_coefficient, scalar.mul(z, s));
        sum.add(r, z);
        // minus_a carries -A, so the coefficient is negated to add z k A.
        sum.add(item.key.minus_a, scalar.neg(scalar.mul(z, k)));
    }
    sum.add(Point.basePoint, base_coefficient);
    return is_identity(sum.finish().clearCofactor());
}
