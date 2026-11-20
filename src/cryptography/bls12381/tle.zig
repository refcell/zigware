//! Timelock encryption over BLS12-381 (commonware `bls12381::tle`): Boneh-Franklin
//! identity-based encryption with the Fujisaki-Okamoto transform, where the identity is a
//! signing target and the decryption key is a BLS signature over that target.
//!
//! For `MinPk`, encrypting a 32-byte block `M` to `(namespace, target)` under master key
//! `P` draws a random `sigma`, derives `r = H3(sigma || M)`, and outputs
//! `U = r * G`, `V = sigma XOR H2(e(r * P, Q_id))`, `W = M XOR H4(sigma)` with
//! `Q_id = hash_with_namespace(message, namespace, target)`. Decryption recomputes `r` and
//! rejects the ciphertext unless `U = r * G`.
//!
//! Wire format: `U` (compressed `V.Public`), then `V` and `W` (32 bytes each).

const std = @import("std");
const utils = @import("utils");
const assert = std.debug.assert;
const codec = @import("codec");
const primitives = @import("primitives/root.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Scalar = primitives.group.Scalar;
const GT = primitives.group.GT;
const ops = primitives.ops;

/// Domain separation tag for hashing `sigma || message` to a scalar (H3).
const dst = "TLE_BLS12381_XMD:SHA-256_SSWU_RO_H3_";

/// Bytes in a block (a SHA-256 digest).
pub const block_size = Sha256.digest_length;
/// A message, masked random value, or mask.
pub const Block = [block_size]u8;

pub const Error = error{
    /// The master public key is the group identity, so the mask would not depend on it.
    InvalidPublicKey,
};

/// An encrypted block for variant `V`.
pub fn Ciphertext(comptime V: type) type {
    return struct {
        const Self = @This();
        /// `r * V.Public.generator`.
        u: V.Public,
        /// `sigma XOR H2(e(P, Q_id)^r)`.
        v: Block,
        /// `message XOR H4(sigma)`.
        w: Block,

        pub const fixed_size: usize = V.Public.fixed_size + 2 * block_size;

        pub fn eql(a: Self, b: Self) bool {
            return a.u.eql(b.u) and utils.bytes_eql(a.v.len, &a.v, &b.v) and
                utils.bytes_eql(a.w.len, &a.w, &b.w);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(V.Public, self.u, writer);
            codec.write(Block, self.v, writer);
            codec.write(Block, self.w, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const u = try codec.read(V.Public, gpa, reader);
            const v = try codec.read(Block, gpa, reader);
            const w = try codec.read(Block, gpa, reader);
            return .{ .u = u, .v = v, .w = w };
        }
    };
}

/// H2: GT -> Block, masks sigma.
pub fn h2(gt: GT) Block {
    var bytes = gt.to_bytes();
    defer std.crypto.secureZero(u8, &bytes);
    var hasher = Sha256.init(.{});
    hasher.update("h2");
    hasher.update(&bytes);
    return hasher.finalResult();
}

/// H3: (sigma, message) -> Scalar by RFC 9380 hash-to-field, derives the randomness r.
pub fn h3(sigma: *const Block, message: *const Block) Scalar {
    var combined: [2 * block_size]u8 = undefined;
    defer std.crypto.secureZero(u8, &combined);
    @memcpy(combined[0..block_size], sigma);
    @memcpy(combined[block_size..], message);
    return Scalar.map(dst, &combined);
}

/// H4: sigma -> Block, masks the message.
pub fn h4(sigma: *const Block) Block {
    var hasher = Sha256.init(.{});
    hasher.update("h4");
    hasher.update(sigma);
    return hasher.finalResult();
}

pub fn xor(a: Block, b: Block) Block {
    var out: Block = undefined;
    for (&out, a, b) |*o, x, y| o.* = x ^ y;
    return out;
}

/// Encrypts `message` so that a signature by `public`'s key over `(namespace, target)`
/// decrypts it. Draws 32 bytes (sigma) from `rng`.
pub fn encrypt(
    comptime V: type,
    rng: anytype,
    public: V.Public,
    namespace: []const u8,
    target: []const u8,
    message: *const Block,
) Error!Ciphertext(V) {
    if (public.is_zero()) return error.InvalidPublicKey;
    const q_id = ops.hash_with_namespace(V, V.message, namespace, target);

    var sigma: Block = undefined;
    defer std.crypto.secureZero(u8, &sigma);
    rng.fill_bytes(&sigma);
    var r = h3(&sigma, message);
    defer r.zeroize();

    const u = V.Public.generator.mul(r);
    // e(P, Q_id)^r = e(r * P, Q_id), which is cheaper.
    const gt = V.pairing(public.mul(r), q_id);
    var mask_sigma = h2(gt);
    defer std.crypto.secureZero(u8, &mask_sigma);
    var mask_message = h4(&sigma);
    defer std.crypto.secureZero(u8, &mask_message);
    const result: Ciphertext(V) = .{
        .u = u,
        .v = xor(sigma, mask_sigma),
        .w = xor(message.*, mask_message),
    };
    assert(!result.u.is_zero());
    return result;
}

/// Decrypts `ciphertext` with a signature over the target given to `encrypt`, or returns
/// null when the signature is wrong or the ciphertext was tampered with.
pub fn decrypt(
    comptime V: type,
    signature: V.Signature,
    ciphertext: Ciphertext(V),
) ?Block {
    // An identity signature collapses the pairing to a public constant.
    if (signature.is_zero()) return null;
    const gt = V.pairing(ciphertext.u, signature);
    var sigma = xor(ciphertext.v, h2(gt));
    defer std.crypto.secureZero(u8, &sigma);
    const message = xor(ciphertext.w, h4(&sigma));
    var r = h3(&sigma, &message);
    defer r.zeroize();
    if (!ciphertext.u.eql(V.Public.generator.mul(r))) return null;
    return message;
}

test {
    _ = @import("tle_tests.zig");
}
