//! BLS12-381 group elements (commonware `bls12381::primitives::group`): the scalar field
//! `Scalar`, the 128-bit `SmallScalar`, the groups `G1` and `G2`, the pairing target `GT`,
//! private keys (`Private`), and threshold key shares (`Share`).
//!
//! Encodings are byte-identical to commonware (blst): scalars are 32 big-endian bytes, G1
//! and G2 are ZCash-compressed (48 and 96 bytes), and GT is 12 big-endian Fp elements in
//! blst's `blst_bendian_from_fp12` order. Decoding rejects scalars >= r, the point at
//! infinity, and points outside the prime-order subgroup, with commonware's error contexts.
//!
//! Field arithmetic on scalars is constant time (masked Montgomery arithmetic, Fermat
//! inversion). Point multiplication uses variable-time GLV/GLS windows; see the lane file.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const arithmetic = @import("arithmetic/root.zig");
const Opaque = @import("../../secret.zig").Opaque;

const Allocator = std.mem.Allocator;
const Unstructured = minifuzz.Unstructured;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Fr = arithmetic.Fr;
const Fp = arithmetic.Fp;
const Fp12 = arithmetic.Fp12;
const r = arithmetic.fields.r;

/// Bytes of an encoded scalar (`SCALAR_LENGTH`).
pub const scalar_length = 32;
/// Bytes of an encoded private key (`PRIVATE_KEY_LENGTH`).
pub const private_key_length = scalar_length;
/// Bytes of a compressed G1 element (`G1_ELEMENT_BYTE_LENGTH`).
pub const g1_element_length = 48;
/// Bytes of a compressed G2 element (`G2_ELEMENT_BYTE_LENGTH`).
pub const g2_element_length = 96;
/// Bytes of an encoded GT element (`GT_ELEMENT_BYTE_LENGTH`).
pub const gt_element_length = 576;

/// Domain separation tags (draft-irtf-cfrg-bls-signature-05 proof-of-possession suites).
pub const g1_proof_of_possession = "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
pub const g1_message = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
pub const g2_proof_of_possession = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const g2_message = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Bytes of input key material for BLS KeyGen (`IKM_LENGTH`).
const ikm_length = 64;
/// Bytes of a `SmallScalar`'s entropy (128 bits).
const small_scalar_length = 16;
/// KeyGen output length L = ceil((3 * ceil(log2(r))) / 16) = 48.
const keygen_okm_length = 48;
/// KeyGen loops while the key is zero (probability 2^-255 per attempt).
const keygen_attempts_max = 16;

comptime {
    assert(Fr.bytes_length == scalar_length);
    assert(Fp.bytes_length == g1_element_length);
    assert(gt_element_length == 12 * Fp.bytes_length);
    assert(r >> 254 == 1); // r has 255 bits.
}

/// Configuration for decoding a `Scalar` (`ScalarReadCfg`).
pub const ScalarReadCfg = enum { allow_zero, reject_zero };

/// An element of the BLS12-381 scalar field F_r, the order of G1 and G2.
pub const Scalar = struct {
    fr: Fr,

    pub const fixed_size: usize = scalar_length;
    pub const Cfg = ScalarReadCfg;
    pub const zero: Scalar = .{ .fr = Fr.zero };
    pub const one: Scalar = .{ .fr = Fr.one };
    /// The two-adicity of r - 1 (`FieldNTT::MAX_LG_ROOT_ORDER`).
    pub const max_lg_root_order: u8 = 32;

    /// A primitive 2^32-th root of unity, 7^((r - 1) / 2^32), in blst's Montgomery limbs.
    const root_of_unity_max: Scalar = .{ .fr = .{ .limbs_value = .{
        0xb9b5_8d8c_5f0e_466a, 0x5b1b_4c80_1819_d7ec,
        0x0af5_3ae3_52a3_1e64, 0x5bf3_adda_19e9_b27b,
    } } };
    /// The multiplicative generator 7, used as the coset shift.
    const coset_shift_value: Scalar = .{ .fr = .{ .limbs_value = .{
        0x0000_000e_ffff_fff1, 0x17e3_63d3_0018_9c0f,
        0xff9c_5787_6f84_57b0, 0x3513_3220_8fc5_a8c4,
    } } };
    /// 7^-1 mod r.
    const coset_shift_inv_value: Scalar = .{ .fr = .{ .limbs_value = .{
        0xdb6d_b6da_db6d_b6dc, 0xe6b5_824a_db6c_c6da,
        0xf8b3_56e0_0581_0db9, 0x66d0_f1e6_60ec_4796,
    } } };
    const two_inverse: Fr = Fr.from_int_comptime((r + 1) / 2);
    const two_256: Fr = Fr.from_int_comptime((1 << 256) % r);
    /// (r - 1) / 2, the Legendre exponent.
    const legendre_exponent = (r - 1) / 2;
    /// (Q + 1) / 2 where r - 1 = Q 2^32 with Q odd.
    const sqrt_exponent = (((r - 1) >> 32) + 1) / 2;

    pub fn from_u64(value: u64) Scalar {
        return .{ .fr = Fr.from_int(value) };
    }

    /// The integer `limbs[0] + limbs[1] 2^64 + ...` reduced modulo r.
    pub fn from_limbs(limbs: [4]u64) Scalar {
        var value: u256 = 0;
        for (limbs, 0..) |limb, index| value |= @as(u256, limb) << @intCast(64 * index);
        return .{ .fr = Fr.from_int(value) };
    }

    /// A 384-bit big-endian integer reduced modulo r.
    fn from_bytes_wide(bytes: *const [48]u8) Scalar {
        const high = std.mem.readInt(u128, bytes[0..16], .big);
        const low = std.mem.readInt(u256, bytes[16..48], .big);
        const result = Fr.from_int(high).mul(two_256).add(Fr.from_int(low));
        assert(high != 0 or result.eql(Fr.from_int(low)));
        return .{ .fr = result };
    }

    /// IETF BLS KeyGen with an empty key_info, as `blst_keygen` (the salt is hashed
    /// before the first attempt, and again after each attempt that yields zero).
    pub fn from_ikm(ikm: *const [ikm_length]u8) Scalar {
        var salt: [Sha256.digest_length]u8 = undefined;
        Sha256.hash("BLS-SIG-KEYGEN-SALT-", &salt, .{});
        // IKM || I2OSP(0, 1).
        var input: [ikm_length + 1]u8 = undefined;
        defer std.crypto.secureZero(u8, &input);
        input[0..ikm_length].* = ikm.*;
        input[ikm_length] = 0;
        // key_info || I2OSP(L, 2).
        const info = [2]u8{ 0, keygen_okm_length };
        var attempt: u32 = 0;
        while (attempt < keygen_attempts_max) : (attempt += 1) {
            var prk = HkdfSha256.extract(&salt, &input);
            defer std.crypto.secureZero(u8, &prk);
            var okm: [keygen_okm_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &okm);
            HkdfSha256.expand(&okm, &info, prk);
            const result = from_bytes_wide(&okm);
            if (!result.fr.is_zero()) return result;
            const previous = salt;
            Sha256.hash(&previous, &salt, .{});
        }
        @panic("BLS KeyGen produced zero repeatedly");
    }

    /// Maps bytes to a scalar with RFC 9380 hash-to-field: expand_message_xmd to 48 bytes,
    /// then reduction modulo r. `dst` is at most 255 bytes.
    pub fn map(dst: []const u8, message: []const u8) Scalar {
        return map_parts(dst, &.{message});
    }

    /// `map` over the concatenation of `parts`, without materializing it.
    pub fn map_parts(dst: []const u8, parts: []const []const u8) Scalar {
        assert(dst.len <= arithmetic.map.dst_length_max);
        var uniform: [48]u8 = undefined;
        defer std.crypto.secureZero(u8, &uniform);
        // The output length (48) and dst length (checked above) are in range.
        arithmetic.map.expand_message_xmd_parts(parts, dst, &uniform) catch unreachable;
        return from_bytes_wide(&uniform);
    }

    /// The canonical integer value in [0, r) (blst's `as_blst_scalar`).
    pub fn to_int(self: Scalar) u256 {
        return self.fr.to_int();
    }

    /// A random non-zero scalar: 64 bytes of key material through KeyGen (`Random`).
    pub fn random(rng: anytype) Scalar {
        var ikm: [ikm_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &ikm);
        rng.fill_bytes(&ikm);
        return from_ikm(&ikm);
    }

    /// KeyGen over 64 arbitrary bytes of key material.
    pub fn arbitrary(u: *Unstructured) minifuzz.Error!Scalar {
        const ikm = try u.arbitrary([ikm_length]u8);
        return from_ikm(&ikm);
    }

    pub fn to_bytes(self: Scalar) [scalar_length]u8 {
        return self.fr.to_bytes_be();
    }

    /// Decodes a canonical big-endian scalar; null when it is >= r or a rejected zero.
    pub fn from_bytes(bytes: *const [scalar_length]u8, cfg: ScalarReadCfg) ?Scalar {
        const fr = Fr.from_bytes_be(bytes) orelse return null;
        if (cfg == .reject_zero and fr.is_zero()) return null;
        return .{ .fr = fr };
    }

    pub fn add(a: Scalar, b: Scalar) Scalar {
        return .{ .fr = a.fr.add(b.fr) };
    }

    pub fn sub(a: Scalar, b: Scalar) Scalar {
        return .{ .fr = a.fr.sub(b.fr) };
    }

    pub fn neg(a: Scalar) Scalar {
        return .{ .fr = a.fr.neg() };
    }

    pub fn double(a: Scalar) Scalar {
        return .{ .fr = a.fr.double() };
    }

    pub fn mul(a: Scalar, b: Scalar) Scalar {
        return .{ .fr = a.fr.mul(b.fr) };
    }

    pub fn square(a: Scalar) Scalar {
        return .{ .fr = a.fr.square() };
    }

    /// The multiplicative inverse in constant time; `inv(zero) == zero`.
    pub fn inv(a: Scalar) Scalar {
        return .{ .fr = a.fr.inverse_constant_time() };
    }

    /// Constant-time equality.
    pub fn eql(a: Scalar, b: Scalar) bool {
        return a.fr.eql(b.fr);
    }

    /// Orders scalars by their encoding (big-endian canonical value).
    pub fn order(a: Scalar, b: Scalar) std.math.Order {
        return std.math.order(a.fr.to_int(), b.fr.to_int());
    }

    pub fn less_than(_: void, a: Scalar, b: Scalar) bool {
        return a.order(b) == .lt;
    }

    /// True when the canonical value exceeds (r - 1) / 2 (equivalently `self > -self`).
    pub fn is_positive(self: Scalar) bool {
        return self.fr.to_int() > (r - 1) / 2;
    }

    /// True for a non-zero quadratic residue (Legendre symbol 1).
    pub fn is_square(self: Scalar) bool {
        return self.fr.pow(legendre_exponent).eql(Fr.one);
    }

    /// A square root by Tonelli-Shanks, or null for a non-residue.
    pub fn sqrt(self: Scalar) ?Scalar {
        if (self.fr.is_zero()) return zero;
        var c = root_of_unity_max.fr;
        var m: u32 = max_lg_root_order;
        var root = self.fr.pow(sqrt_exponent);
        // t = self^Q lives in the 2-Sylow subgroup and is driven to one.
        var t = root.square().mul(self.fr.inverse_constant_time());
        var round: u32 = 0;
        while (round <= max_lg_root_order) : (round += 1) {
            if (t.eql(Fr.one)) {
                if (!root.square().eql(self.fr)) return null;
                return .{ .fr = root };
            }
            // The least i in (0, m) with t^(2^i) == 1.
            var i: u32 = 0;
            var t2i = t;
            while (!t2i.eql(Fr.one)) {
                t2i = t2i.square();
                i += 1;
                if (i == m) return null;
            }
            assert(i < m);
            var b = c;
            for (0..m - i - 1) |_| b = b.square();
            m = i;
            c = b.square();
            t = t.mul(c);
            root = root.mul(b);
        }
        unreachable; // m strictly decreases each round, so t reaches one.
    }

    /// A primitive 2^lg-th root of unity, or null when lg > 32.
    pub fn root_of_unity(lg: u8) ?Scalar {
        if (lg > max_lg_root_order) return null;
        var out = root_of_unity_max.fr;
        for (0..max_lg_root_order - lg) |_| out = out.square();
        return .{ .fr = out };
    }

    pub fn coset_shift() Scalar {
        return coset_shift_value;
    }

    pub fn coset_shift_inv() Scalar {
        return coset_shift_inv_value;
    }

    pub fn div_2(self: Scalar) Scalar {
        return .{ .fr = self.fr.mul(two_inverse) };
    }

    /// Clears the scalar's limbs (`Zeroize`).
    pub fn zeroize(self: *Scalar) void {
        std.crypto.secureZero(u64, &self.fr.limbs_value);
    }

    pub fn write(self: Scalar, writer: *codec.Writer) void {
        var bytes = self.to_bytes();
        defer std.crypto.secureZero(u8, &bytes);
        writer.write_bytes(&bytes);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, cfg: ScalarReadCfg) codec.Error!Scalar {
        const bytes = try reader.take_array(scalar_length);
        return from_bytes(bytes, cfg) orelse reader.invalid("Scalar", "Invalid");
    }

    pub fn format(_: Scalar, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("[REDACTED]");
    }
};

/// A scalar in [0, 2^128), for random linear combinations in batch verification. Zero is
/// included: an invalid combination still passes with probability at most 2^-128.
pub const SmallScalar = struct {
    value: u128,

    pub const zero: SmallScalar = .{ .value = 0 };

    /// Fills the low 16 bytes of a 32-byte big-endian scalar from `rng`.
    pub fn random(rng: anytype) SmallScalar {
        var bytes: [small_scalar_length]u8 = undefined;
        rng.fill_bytes(&bytes);
        return .{ .value = std.mem.readInt(u128, &bytes, .big) };
    }

    /// The 32-byte big-endian scalar (commonware's `as_bytes` is its little-endian form).
    pub fn to_bytes(self: SmallScalar) [scalar_length]u8 {
        var out: [scalar_length]u8 = undefined;
        std.mem.writeInt(u256, &out, self.value, .big);
        assert(std.mem.allEqual(u8, out[0..small_scalar_length], 0));
        return out;
    }

    pub fn to_scalar(self: SmallScalar) Scalar {
        return .{ .fr = Fr.from_int(self.value) };
    }

    pub fn eql(a: SmallScalar, b: SmallScalar) bool {
        return a.value == b.value;
    }
};

/// A BLS private key: a non-zero scalar that decodes with `reject_zero`.
pub const Private = struct {
    /// Opaque so that `{}`/`{any}` never print the key (secret.zig).
    scalar: Opaque(Scalar),

    pub const fixed_size: usize = private_key_length;

    pub fn init(scalar: Scalar) Private {
        return .{ .scalar = .{ .value = scalar } };
    }

    pub fn random(rng: anytype) Private {
        return .{ .scalar = .{ .value = Scalar.random(rng) } };
    }

    pub fn arbitrary(u: *Unstructured) minifuzz.Error!Private {
        return .{ .scalar = .{ .value = try Scalar.arbitrary(u) } };
    }

    pub fn eql(a: Private, b: Private) bool {
        return a.scalar.value.eql(b.scalar.value);
    }

    pub fn zeroize(self: *Private) void {
        self.scalar.value.zeroize();
    }

    pub fn write(self: Private, writer: *codec.Writer) void {
        self.scalar.value.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Private {
        return .{ .scalar = .{ .value = try Scalar.read(gpa, reader, .reject_zero) } };
    }

    pub fn format(_: Private, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("Private([REDACTED])");
    }
};

/// A share of a threshold signing key: the participant index, then the private scalar.
pub const Share = struct {
    index: utils.Participant,
    private: Private,

    pub fn init(index: utils.Participant, private: Private) Share {
        return .{ .index = index, .private = private };
    }

    /// The share's public key `generator * private` in `V.Public`'s group.
    pub fn public(self: Share, comptime V: type) V.Public {
        return V.Public.generator.mul(self.private.scalar.value);
    }

    pub fn arbitrary(u: *Unstructured) minifuzz.Error!Share {
        const index = try u.arbitrary(utils.Participant);
        return .{ .index = index, .private = try Private.arbitrary(u) };
    }

    pub fn eql(a: Share, b: Share) bool {
        return a.index.index == b.index.index and a.private.eql(b.private);
    }

    pub const max_encode_size: usize = utils.Participant.max_encode_size + private_key_length;

    pub fn encode_size(self: Share) usize {
        return self.index.encode_size() + private_key_length;
    }

    pub fn write(self: Share, writer: *codec.Writer) void {
        self.index.write(writer);
        self.private.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Share {
        const index = try utils.Participant.read(gpa, reader, {});
        const private = try Private.read(gpa, reader, {});
        return .{ .index = index, .private = private };
    }

    pub fn format(self: Share, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("Share {{ index: {f}, private: [REDACTED] }}", .{self.index});
    }
};

/// An element of the pairing target group GT, a subgroup of Fp12.
pub const GT = struct {
    value: Fp12,

    pub fn eql(a: GT, b: GT) bool {
        return a.value.eql(b.value);
    }

    /// The canonical big-endian encoding in blst's order: for each Fp6 coefficient i, for
    /// each Fp12 coefficient j, the two Fp halves of `value[j][i]`.
    pub fn to_bytes(self: GT) [gt_element_length]u8 {
        var out: [gt_element_length]u8 = undefined;
        var offset: usize = 0;
        for (0..3) |i| {
            for ([2]arithmetic.Fp6{ self.value.c0, self.value.c1 }) |fp6| {
                const fp2 = switch (i) {
                    0 => fp6.c0,
                    1 => fp6.c1,
                    else => fp6.c2,
                };
                out[offset..][0..48].* = fp2.c0.to_bytes_be();
                out[offset + 48 ..][0..48].* = fp2.c1.to_bytes_be();
                offset += 96;
            }
        }
        assert(offset == gt_element_length);
        return out;
    }
};

/// The reduced pairing e(p, q).
pub fn pairing(p: G1, q: G2) GT {
    return .{ .value = arithmetic.pairing.pairing(p.to_affine(), q.to_affine()) };
}

/// Checks `prod_i e(p_i, q_i) == 1` over pairs added one at a time: Miller loops run over
/// batches of `pairs_per_loop_max` pairs, and one final exponentiation ends the check
/// (commonware `multi_pairing_check`). Pairs with an identity point contribute one.
pub const PairingCheck = struct {
    product: Fp12 = Fp12.one,
    g1s: [batch]G1.Jacobian = undefined,
    g2s: [batch]G2.Jacobian = undefined,
    count: usize = 0,

    const batch = arithmetic.pairing.pairs_per_loop_max;

    pub fn add(self: *PairingCheck, p: G1, q: G2) void {
        assert(self.count < batch);
        self.g1s[self.count] = p.point;
        self.g2s[self.count] = q.point;
        self.count += 1;
        if (self.count == batch) self.flush();
        assert(self.count < batch);
    }

    fn flush(self: *PairingCheck) void {
        if (self.count == 0) return;
        var g1_affine: [batch]G1.Affine = undefined;
        var g2_affine: [batch]G2.Affine = undefined;
        var g1_scratch: [batch]Fp = undefined;
        var g2_scratch: [batch]arithmetic.Fp2 = undefined;
        const count = self.count;
        G1.Jacobian.batch_to_affine(self.g1s[0..count], g1_affine[0..count], g1_scratch[0..count]);
        G2.Jacobian.batch_to_affine(self.g2s[0..count], g2_affine[0..count], g2_scratch[0..count]);
        var pairs: [batch]arithmetic.pairing.Pair = undefined;
        for (pairs[0..count], g1_affine[0..count], g2_affine[0..count]) |*pair, p, q| {
            pair.* = .{ .g1 = p, .g2 = q };
        }
        self.product = self.product.mul(arithmetic.pairing.miller_loop(pairs[0..count]));
        self.count = 0;
    }

    /// Finishes the check; true when the product of the pairings is one.
    pub fn verify(self: *PairingCheck) bool {
        self.flush();
        assert(self.count == 0);
        return arithmetic.pairing.final_exponentiation(self.product).eql(Fp12.one);
    }
};

/// The parts of commonware's `union_unique(namespace, message)`: the varint length of the
/// namespace, the namespace, then the message. `prefix` holds the varint.
pub fn union_unique_parts(
    prefix: *[5]u8,
    namespace: []const u8,
    message: []const u8,
) [3][]const u8 {
    var writer = codec.Writer.init(prefix);
    codec.write(usize, namespace.len, &writer);
    const length = writer.written().len;
    assert(length > 0 and length <= prefix.len);
    return .{ prefix[0..length], namespace, message };
}

const PointKind = enum { g1, g2 };

pub const G1 = Point(.g1);
pub const G2 = Point(.g2);

fn Point(comptime kind: PointKind) type {
    const arith = switch (kind) {
        .g1 => arithmetic.g1,
        .g2 => arithmetic.g2,
    };
    const name = switch (kind) {
        .g1 => "G1",
        .g2 => "G2",
    };
    const ScalarType = Scalar;
    return struct {
        const Self = @This();
        pub const Jacobian = switch (kind) {
            .g1 => arith.G1,
            .g2 => arith.G2,
        };
        pub const Affine = arith.Affine;
        pub const Scalar = ScalarType;
        pub const fixed_size: usize = arith.compressed_length;
        pub const zero: Self = .{ .point = Jacobian.identity };
        pub const generator: Self = .{ .point = arith.generator.to_jacobian() };
        /// `hash_to_group` tag for messages.
        pub const message_dst = switch (kind) {
            .g1 => g1_message,
            .g2 => g2_message,
        };
        /// `hash_to_group` tag for proofs of possession.
        pub const proof_of_possession_dst = switch (kind) {
            .g1 => g1_proof_of_possession,
            .g2 => g2_proof_of_possession,
        };

        point: Jacobian,

        pub fn from_affine(affine: Affine) Self {
            return .{ .point = affine.to_jacobian() };
        }

        pub fn to_affine(self: Self) Affine {
            return self.point.to_affine();
        }

        pub fn is_zero(self: Self) bool {
            return self.point.is_identity();
        }

        pub fn add(a: Self, b: Self) Self {
            return .{ .point = a.point.add(b.point) };
        }

        pub fn sub(a: Self, b: Self) Self {
            return .{ .point = a.point.sub(b.point) };
        }

        pub fn neg(a: Self) Self {
            return .{ .point = a.point.neg() };
        }

        pub fn double(a: Self) Self {
            return .{ .point = a.point.double() };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.point.eql(b.point);
        }

        /// Multiplies by a `Scalar` or a `SmallScalar`.
        pub fn mul(self: Self, scalar: anytype) Self {
            const value = scalar_int(scalar);
            const result = switch (kind) {
                .g1 => arith.mul_glv(self.point, value),
                .g2 => arith.mul_gls(self.point, value),
            };
            assert(value != 0 or result.is_identity());
            return .{ .point = result };
        }

        fn scalar_int(scalar: anytype) u256 {
            return switch (@TypeOf(scalar)) {
                ScalarType => scalar.fr.to_int(),
                SmallScalar => scalar.value,
                else => @compileError("expected Scalar or SmallScalar"),
            };
        }

        /// `sum_i points[i] * scalars[i]` with Pippenger's method over chunks of points
        /// (`Space::msm`); `scalars` holds `Scalar` or `SmallScalar` values.
        pub fn msm(points: []const Self, scalars: anytype) Self {
            assert(points.len == scalars.len);
            const chunk = arithmetic.msm.chunk_points_max;
            var result = Jacobian.identity;
            var start: usize = 0;
            while (start < points.len) : (start += chunk) {
                const count = @min(chunk, points.len - start);
                var jacobian: [chunk]Jacobian = undefined;
                var affine: [chunk]Affine = undefined;
                var scratch: [chunk]Jacobian.Field = undefined;
                var values: [chunk]u256 = undefined;
                for (0..count) |index| {
                    jacobian[index] = points[start + index].point;
                    values[index] = scalar_int(scalars[start + index]);
                }
                Jacobian.batch_to_affine(jacobian[0..count], affine[0..count], scratch[0..count]);
                const part = arithmetic.msm.msm(Jacobian, affine[0..count], values[0..count]);
                result = result.add(part);
            }
            return .{ .point = result };
        }

        /// `msm` through `strategy` (commonware's `Space::msm(points, scalars, strategy)`).
        /// A few points run `msm` on the calling thread; where the strategy takes the parallel
        /// shape, zero points and scalars are dropped and the rest are summed in tiles cut by
        /// the strategy (`arithmetic.msm.msm_tiled`). Every shape returns the same point.
        pub fn msm_strategy(
            gpa: Allocator,
            points: []const Self,
            scalars: anytype,
            strategy: anytype,
        ) Allocator.Error!Self {
            assert(points.len == scalars.len);
            const Run = struct {
                gpa: Allocator,
                points: []const Self,
                scalars: @TypeOf(scalars),
                strategy: @TypeOf(strategy),

                pub fn serial(run: @This()) Allocator.Error!Self {
                    return msm(run.points, run.scalars);
                }

                pub fn parallel(run: @This()) Allocator.Error!Self {
                    return msm_parallel(run.gpa, run.points, run.scalars, run.strategy);
                }
            };
            const run: Run = .{
                .gpa = gpa,
                .points = points,
                .scalars = scalars,
                .strategy = strategy,
            };
            if (points.len < 2) return run.serial();
            return strategy.run(points.len, run);
        }

        fn msm_parallel(
            gpa: Allocator,
            points: []const Self,
            scalars: anytype,
            strategy: anytype,
        ) Allocator.Error!Self {
            const Element = std.meta.Elem(@TypeOf(scalars));
            const nbits: u32 = if (Element == SmallScalar) small_scalar_length * 8 else 255;
            var count: usize = 0;
            for (points, scalars) |point, scalar| {
                if (!point.point.is_identity() and scalar_int(scalar) != 0) count += 1;
            }
            if (count < 2) return msm(points, scalars);
            const jacobian = try gpa.alloc(Jacobian, count);
            defer gpa.free(jacobian);
            const values = try gpa.alloc(u256, count);
            defer gpa.free(values);
            var index: usize = 0;
            for (points, scalars) |point, scalar| {
                if (point.point.is_identity() or scalar_int(scalar) == 0) continue;
                jacobian[index] = point.point;
                values[index] = scalar_int(scalar);
                index += 1;
            }
            assert(index == count);
            const affine = try gpa.alloc(Affine, count);
            defer gpa.free(affine);
            const scratch = try gpa.alloc(Jacobian.Field, count);
            defer gpa.free(scratch);
            Jacobian.batch_to_affine(jacobian, affine, scratch);
            const tiled = arithmetic.msm.msm_tiled;
            const sum = try tiled(Jacobian, gpa, affine, values, nbits, strategy);
            return .{ .point = sum };
        }

        /// RFC 9380 hash_to_curve (SSWU, random oracle) with domain separation tag `dst`
        /// of at most 255 bytes.
        pub fn hash_to_group(dst: []const u8, message: []const u8) Self {
            return hash_to_group_parts(dst, &.{message});
        }

        /// `hash_to_group` of the concatenation of `parts`, without materializing it.
        pub fn hash_to_group_parts(dst: []const u8, parts: []const []const u8) Self {
            assert(dst.len <= arithmetic.map.dst_length_max);
            // The dst length is checked above and the expansion length is fixed.
            const affine = switch (kind) {
                .g1 => arithmetic.map.hash_to_g1_parts(parts, dst),
                .g2 => arithmetic.map.hash_to_g2_parts(parts, dst),
            } catch unreachable;
            return from_affine(affine);
        }

        pub fn arbitrary(u: *Unstructured) minifuzz.Error!Self {
            return generator.mul(try ScalarType.arbitrary(u));
        }

        pub fn to_bytes(self: Self) [fixed_size]u8 {
            return arith.compress(self.to_affine());
        }

        /// Orders points by their compressed encoding.
        pub fn order(a: Self, b: Self) std.math.Order {
            return std.mem.order(u8, &a.to_bytes(), &b.to_bytes());
        }

        pub fn less_than(_: void, a: Self, b: Self) bool {
            return a.order(b) == .lt;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_bytes(&self.to_bytes());
        }

        /// Decodes a compressed point, rejecting bad encodings, points off the curve, the
        /// point at infinity, and points outside the subgroup.
        pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const bytes = try reader.take_array(fixed_size);
            const affine = arith.decompress_unchecked(bytes) catch |err| switch (err) {
                error.InvalidEncoding => return reader.invalid(name, "Bad encoding"),
                error.NotOnCurve => return reader.invalid(name, "Not on curve"),
                // decompress_unchecked skips the subgroup check.
                error.NotInSubgroup => unreachable,
            };
            if (affine.infinity) return reader.invalid(name, "Infinity");
            // blst's G1 uncompress reports (0, +-2) as not in the group.
            if (kind == .g1 and affine.x.is_zero()) return reader.invalid(name, "Not in group");
            if (!arith.is_in_subgroup(affine)) return reader.invalid(name, "Outside " ++ name);
            return from_affine(affine);
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("{x}", .{&self.to_bytes()});
        }
    };
}

test {
    _ = @import("group_tests.zig");
    _ = @import("group_msm_tests.zig");
}
