//! Ed25519 signing keys, signatures, and verification (commonware
//! `cryptography/curve25519/src/signing.rs`).
//!
//! # Validation criteria (ZIP-215)
//!
//! - The encodings of the verifying key `A` and the signature's `R` are accepted even when
//!   non-canonical (`y >= p`, or a negative-zero `x`) or of small order, as long as they decode to
//!   a curve point.
//! - The scalar `s` must be canonical (`s < L`).
//! - The check is cofactored: `[8](s B - R - H(R || A || M) A) == 0`, with `A` hashed as encoded.
//!
//! `verify` and `verify_batch` apply the same criteria; a non-empty batch is accepted whenever
//! every signature verifies on its own, and an invalid batch is accepted with probability about
//! 2^-128. The codec reads any 32 bytes as a `VerifyingKey` (a key that is not a curve point
//! fails every verification) and any 64 bytes as a `Signature`.
//!
//! The arithmetic is `cryptography.ed25519.core`, which implements exactly these criteria;
//! batches run through `batch`, the crate's counter-mode coefficients and bucket MSM.

const std = @import("std");
const utils = @import("utils");
const codec = @import("codec");
const cryptography = @import("cryptography");
const formatting = @import("formatting");
const assert = std.debug.assert;
const core = cryptography.ed25519.core;
const batch = @import("batch.zig");

/// An Ed25519 signing key. `deinit` zeroizes it. The encoding is the raw secret seed, so the
/// encoded bytes are secret key material.
pub const SigningKey = struct {
    inner: core.SigningKey,

    pub const fixed_size: usize = 32;

    /// The key whose RFC 8032 seed is `seed`.
    pub fn from_seed(seed: [32]u8) SigningKey {
        return .{ .inner = core.SigningKey.from_seed(seed) };
    }

    /// A key from 32 bytes of `rng` (`rng.fill_bytes`), which must be a CSPRNG.
    pub fn random(rng: anytype) SigningKey {
        var seed: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        rng.fill_bytes(&seed);
        return from_seed(seed);
    }

    pub fn deinit(self: *SigningKey) void {
        self.inner.zeroize();
        self.* = undefined;
    }

    pub fn verifying_key(self: *const SigningKey) VerifyingKey {
        const key = self.inner.verification_key;
        return .{ .bytes = key.bytes, .decoded = key };
    }

    /// Signs `union_unique(namespace, message)`.
    pub fn sign(self: *const SigningKey, namespace: []const u8, message: []const u8) Signature {
        return .{ .bytes = self.inner.sign(namespace, message) };
    }

    /// Signs `message` with no namespace framing (RFC 8032).
    pub fn sign_raw(self: *const SigningKey, message: []const u8) Signature {
        return .{ .bytes = self.inner.sign(null, message) };
    }

    pub fn write(self: *const SigningKey, writer: *codec.Writer) void {
        writer.write_bytes(&self.inner.seed.value);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!SigningKey {
        var seed = (try reader.take_array(fixed_size)).*;
        defer std.crypto.secureZero(u8, &seed);
        return from_seed(seed);
    }

    /// commonware's `Arbitrary`: a key from an arbitrary seed.
    pub fn arbitrary(
        gpa: std.mem.Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!SigningKey {
        const seed = try codec.arbitrary.value([32]u8, gpa, u);
        return from_seed(seed);
    }
};

/// An Ed25519 verifying key: its encoding exactly as given, and the point it decodes to (null
/// when the encoding is not a curve point, so every verification fails).
pub const VerifyingKey = struct {
    bytes: [32]u8,
    decoded: ?core.VerificationKey,

    pub const fixed_size: usize = 32;
    pub const Signature = signing_signature;
    pub const Entry = cryptography.BatchEntry(VerifyingKey);

    pub fn from_bytes(bytes: [32]u8) VerifyingKey {
        return .{ .bytes = bytes, .decoded = core.VerificationKey.decode(bytes) };
    }

    /// Verifies `signature` over `union_unique(namespace, message)`.
    pub fn verify(
        self: *const VerifyingKey,
        namespace: []const u8,
        message: []const u8,
        signature: *const signing_signature,
    ) bool {
        return self.verify_framed(namespace, message, signature);
    }

    /// Verifies `signature` over `message` with no namespace framing (RFC 8032).
    pub fn verify_raw(
        self: *const VerifyingKey,
        message: []const u8,
        signature: *const signing_signature,
    ) bool {
        return self.verify_framed(null, message, signature);
    }

    fn verify_framed(
        self: *const VerifyingKey,
        namespace: ?[]const u8,
        message: []const u8,
        signature: *const signing_signature,
    ) bool {
        const key = &(self.decoded orelse return false);
        const k = core.challenge(signature.bytes[0..32], &self.bytes, namespace, message);
        return key.verify_prehashed(&signature.bytes, k);
    }

    /// Verifies every entry `projector.project(index, &items[index])` (an `Entry`) at once,
    /// with the signed payloads framed by their namespaces (commonware
    /// `BatchVerifier::verify_batch`). An empty batch, or one longer than `maxInt(u32)`, is
    /// rejected. `rng` must be unpredictable to whoever chose the signatures.
    pub fn verify_batch(rng: anytype, items: anytype, projector: anytype, strategy: anytype) bool {
        if (items.len == 0 or items.len > std.math.maxInt(u32)) return false;
        for (items, 0..) |*item, index| {
            const entry: Entry = projector.project(index, item);
            if (entry.public_key.decoded == null) return false;
        }
        const View = struct {
            items: @TypeOf(items),
            projector: @TypeOf(projector),

            pub fn item(view: @This(), index: usize) core.BatchItem {
                const entry: Entry = view.projector.project(index, &view.items[index]);
                return .{
                    .key = &entry.public_key.decoded.?,
                    .signature = &entry.signature.bytes,
                    .namespace = entry.namespace,
                    .message = entry.message,
                };
            }
        };
        const view: View = .{ .items = items, .projector = projector };
        return batch.verify_batch(rng, items.len, view, strategy);
    }

    /// `verify_batch` over raw RFC 8032 messages (commonware's test-only `verify_batch_raw`).
    pub fn verify_batch_raw(rng: anytype, items: []const RawEntry, strategy: anytype) bool {
        if (items.len == 0 or items.len > std.math.maxInt(u32)) return false;
        for (items) |entry| if (entry.key.decoded == null) return false;
        const View = struct {
            items: []const RawEntry,

            pub fn item(view: @This(), index: usize) core.BatchItem {
                const entry = view.items[index];
                return .{
                    .key = &entry.key.decoded.?,
                    .signature = &entry.signature.bytes,
                    .namespace = null,
                    .message = entry.message,
                };
            }
        };
        return batch.verify_batch(rng, items.len, View{ .items = items }, strategy);
    }

    pub const RawEntry = struct {
        key: *const VerifyingKey,
        signature: *const signing_signature,
        message: []const u8,
    };

    pub fn as_slice(self: *const VerifyingKey) []const u8 {
        return &self.bytes;
    }

    /// Equality and order are by encoding, so aliases of one point are different keys.
    pub fn eql(a: VerifyingKey, b: VerifyingKey) bool {
        return utils.bytes_eql(a.bytes.len, &a.bytes, &b.bytes);
    }

    pub fn order(a: VerifyingKey, b: VerifyingKey) std.math.Order {
        return std.mem.order(u8, &a.bytes, &b.bytes);
    }

    pub fn write(self: *const VerifyingKey, writer: *codec.Writer) void {
        writer.write_bytes(&self.bytes);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!VerifyingKey {
        return from_bytes((try reader.take_array(fixed_size)).*);
    }

    pub fn arbitrary(
        gpa: std.mem.Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!VerifyingKey {
        const bytes = try codec.arbitrary.value([32]u8, gpa, u);
        return from_bytes(bytes);
    }

    pub fn format(self: VerifyingKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try formatting.fmt_hex(&self.bytes).format(writer);
    }
};

const signing_signature = Signature;

/// An Ed25519 signature, `R || s`, exactly as given.
pub const Signature = struct {
    bytes: [64]u8,

    pub const fixed_size: usize = 64;

    pub fn as_slice(self: *const Signature) []const u8 {
        return &self.bytes;
    }

    pub fn eql(a: Signature, b: Signature) bool {
        return utils.bytes_eql(a.bytes.len, &a.bytes, &b.bytes);
    }

    pub fn order(a: Signature, b: Signature) std.math.Order {
        return std.mem.order(u8, &a.bytes, &b.bytes);
    }

    pub fn write(self: *const Signature, writer: *codec.Writer) void {
        writer.write_bytes(&self.bytes);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!Signature {
        return .{ .bytes = (try reader.take_array(fixed_size)).* };
    }

    pub fn arbitrary(
        gpa: std.mem.Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Signature {
        const bytes = try codec.arbitrary.value([64]u8, gpa, u);
        return .{ .bytes = bytes };
    }

    pub fn format(self: Signature, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try formatting.fmt_hex(&self.bytes).format(writer);
    }
};

comptime {
    assert(@sizeOf(Signature) == 64);
}
