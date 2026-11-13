//! Ed25519 private keys, public keys, and signatures (commonware `ed25519/scheme.rs`).
//!
//! Encodings: a private key is its 32-byte seed, a public key its 32-byte compressed point
//! (kept exactly as given, even when non-canonical), a signature `R || s` in 64 bytes.
//! Messages are signed as `union_unique(namespace, message)`; verification follows ZIP-215.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const core = @import("core.zig");
const signer = @import("../signer.zig");

const curve_name = "ed25519";

/// An Ed25519 signing key. Formatting never shows the key.
pub const PrivateKey = struct {
    key: core.SigningKey,

    pub const fixed_size: usize = 32;
    pub const PublicKey = scheme_public_key;
    pub const Signature = scheme_signature;

    /// A key from 32 random bytes drawn from `rng` (`fill_bytes`).
    pub fn random(rng: anytype) PrivateKey {
        var seed: [32]u8 = undefined;
        rng.fill_bytes(&seed);
        defer std.crypto.secureZero(u8, &seed);
        return from_bytes(seed);
    }

    /// Commonware `Signer::from_seed`: insecure, for tests and examples only.
    pub fn from_seed(seed: u64) PrivateKey {
        return signer.from_seed(PrivateKey, seed);
    }

    /// The key whose RFC 8032 seed is `seed`.
    pub fn from_bytes(seed: [32]u8) PrivateKey {
        return .{ .key = core.SigningKey.from_seed(seed) };
    }

    pub fn public_key(self: *const PrivateKey) PrivateKey.PublicKey {
        return .{ .key = self.key.verification_key };
    }

    /// Signs `message` under `namespace`.
    pub fn sign(
        self: *const PrivateKey,
        namespace: []const u8,
        message: []const u8,
    ) PrivateKey.Signature {
        return .{ .raw = self.key.sign(namespace, message) };
    }

    /// Signs `message` as is, with no namespace framing (RFC 8032).
    pub fn sign_raw(self: *const PrivateKey, message: []const u8) PrivateKey.Signature {
        return .{ .raw = self.key.sign(null, message) };
    }

    /// Constant-time comparison of the seeds.
    pub fn eql(a: *const PrivateKey, b: *const PrivateKey) bool {
        return std.crypto.timing_safe.eql([32]u8, a.key.seed, b.key.seed);
    }

    pub fn zeroize(self: *PrivateKey) void {
        self.key.zeroize();
    }

    pub fn write(self: *const PrivateKey, writer: *codec.Writer) void {
        writer.write_bytes(&self.key.seed);
    }

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, cfg: void) codec.Error!PrivateKey {
        _ = gpa;
        _ = cfg;
        const seed = try reader.take_array(fixed_size);
        return from_bytes(seed.*);
    }

    pub fn format(self: PrivateKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = self;
        try writer.writeAll("[REDACTED]");
    }
};

const scheme_public_key = PublicKey;
const scheme_signature = Signature;

/// An Ed25519 verification key.
pub const PublicKey = struct {
    key: core.VerificationKey,

    pub const fixed_size: usize = 32;
    pub const Signature = scheme_signature;
    pub const Entry = signer.BatchEntry(PublicKey);

    /// Decodes a key, or returns null when the bytes are not a curve point.
    pub fn from_bytes(bytes: [32]u8) ?PublicKey {
        const key = core.VerificationKey.decode(bytes) orelse return null;
        return .{ .key = key };
    }

    /// Verifies `signature` over `message` under `namespace`.
    pub fn verify(
        self: *const PublicKey,
        namespace: []const u8,
        message: []const u8,
        signature: *const PublicKey.Signature,
    ) bool {
        const k = core.challenge(signature.raw[0..32], &self.key.bytes, namespace, message);
        return self.key.verify_prehashed(&signature.raw, k);
    }

    /// Verifies an RFC 8032 signature over `message`, with no namespace framing.
    pub fn verify_raw(
        self: *const PublicKey,
        message: []const u8,
        signature: *const PublicKey.Signature,
    ) bool {
        const k = core.challenge(signature.raw[0..32], &self.key.bytes, null, message);
        return self.key.verify_prehashed(&signature.raw, k);
    }

    /// Verifies every entry `projector.project(index, &items[index])` at once (commonware
    /// `BatchVerifier::verify_batch`); pass `cryptography.entries` for a slice of `Entry`.
    /// Returns false for an empty batch or when any signature is invalid. `rng` must be
    /// unpredictable to whoever chose the signatures. `strategy` is accepted for parity;
    /// the batch is checked on the calling thread.
    pub fn verify_batch(rng: anytype, items: anytype, projector: anytype, strategy: anytype) bool {
        _ = strategy;
        const Items = struct {
            items: @TypeOf(items),
            projector: @TypeOf(projector),

            pub fn item(self: @This(), index: usize) core.BatchItem {
                const entry: Entry = self.projector.project(index, &self.items[index]);
                return .{
                    .key = &entry.public_key.key,
                    .signature = &entry.signature.raw,
                    .namespace = entry.namespace,
                    .message = entry.message,
                };
            }
        };
        return core.verify_batch(rng, items.len, Items{ .items = items, .projector = projector });
    }

    pub fn as_slice(self: *const PublicKey) []const u8 {
        return &self.key.bytes;
    }

    pub fn eql(a: PublicKey, b: PublicKey) bool {
        return std.mem.eql(u8, &a.key.bytes, &b.key.bytes);
    }

    /// Order of the encodings (two encodings of one point are distinct keys).
    pub fn order(a: PublicKey, b: PublicKey) std.math.Order {
        return std.mem.order(u8, &a.key.bytes, &b.key.bytes);
    }

    pub fn less_than(_: void, a: PublicKey, b: PublicKey) bool {
        return order(a, b) == .lt;
    }

    pub fn write(self: *const PublicKey, writer: *codec.Writer) void {
        writer.write_bytes(&self.key.bytes);
    }

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, cfg: void) codec.Error!PublicKey {
        _ = gpa;
        _ = cfg;
        const bytes = try reader.take_array(fixed_size);
        return from_bytes(bytes.*) orelse reader.wrapped(curve_name);
    }

    pub fn format(self: PublicKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}", .{&self.key.bytes});
    }
};

/// An Ed25519 signature, `R || s`. Any 64 bytes decode; verification checks them.
pub const Signature = struct {
    raw: [64]u8,

    pub const fixed_size: usize = 64;

    pub fn as_slice(self: *const Signature) []const u8 {
        return &self.raw;
    }

    pub fn eql(a: Signature, b: Signature) bool {
        return std.mem.eql(u8, &a.raw, &b.raw);
    }

    pub fn order(a: Signature, b: Signature) std.math.Order {
        return std.mem.order(u8, &a.raw, &b.raw);
    }

    pub fn write(self: *const Signature, writer: *codec.Writer) void {
        writer.write_bytes(&self.raw);
    }

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, cfg: void) codec.Error!Signature {
        _ = gpa;
        _ = cfg;
        const raw = try reader.take_array(fixed_size);
        return .{ .raw = raw.* };
    }

    pub fn format(self: Signature, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}", .{&self.raw});
    }
};

comptime {
    signer.assert_signer(PrivateKey);
    signer.assert_batch_verifier(PublicKey);
    assert(codec.fixed_size(PublicKey).? == 32);
    assert(codec.fixed_size(Signature).? == 64);
}
