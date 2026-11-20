//! secp256r1 keys and 64-byte `r || s` signatures (commonware `secp256r1/standard.rs`).
//!
//! Signatures are deterministic (RFC 6979) with low `s`; decoding rejects zero or
//! out-of-range scalars and high `s`, so every signature has one encoding.

const std = @import("std");
const utils = @import("utils");
const assert = std.debug.assert;
const codec = @import("codec");
const signer = @import("../signer.zig");
const common = @import("common.zig");

const PrivateKeyInner = common.PrivateKeyInner;
const PublicKeyInner = common.PublicKeyInner;

pub const signature_length = 64;

/// A secp256r1 signing key. Formatting never shows the key.
pub const PrivateKey = struct {
    inner: PrivateKeyInner,

    pub const fixed_size: usize = common.private_key_length;
    pub const PublicKey = scheme_public_key;
    pub const Signature = scheme_signature;

    pub fn random(rng: anytype) PrivateKey {
        return .{ .inner = .random(rng) };
    }

    /// Commonware `Signer::from_seed`: insecure, for tests and examples only.
    pub fn from_seed(seed: u64) PrivateKey {
        return signer.from_seed(PrivateKey, seed);
    }

    /// The key encoded by `raw`, or null if it is zero or not below the group order.
    pub fn from_bytes(raw: [32]u8) ?PrivateKey {
        return .{ .inner = PrivateKeyInner.from_bytes(raw) orelse return null };
    }

    pub fn public_key(self: *const PrivateKey) PrivateKey.PublicKey {
        return .{ .inner = self.inner.public };
    }

    /// Signs `message` under `namespace`.
    pub fn sign(
        self: *const PrivateKey,
        namespace: []const u8,
        message: []const u8,
    ) PrivateKey.Signature {
        return .{ .raw = self.inner.sign(namespace, message).raw };
    }

    /// Signs `message` as is, with no namespace framing.
    pub fn sign_raw(self: *const PrivateKey, message: []const u8) PrivateKey.Signature {
        return .{ .raw = self.inner.sign(null, message).raw };
    }

    pub fn eql(a: *const PrivateKey, b: *const PrivateKey) bool {
        return a.inner.eql(&b.inner);
    }

    pub fn zeroize(self: *PrivateKey) void {
        self.inner.zeroize();
    }

    pub fn write(self: *const PrivateKey, writer: *codec.Writer) void {
        self.inner.write(writer);
    }

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, cfg: void) codec.Error!PrivateKey {
        _ = gpa;
        _ = cfg;
        return .{ .inner = try PrivateKeyInner.read(reader) };
    }

    pub fn format(self: PrivateKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = self;
        try writer.writeAll("[REDACTED]");
    }
};

const scheme_public_key = PublicKey;
const scheme_signature = Signature;

/// A secp256r1 verification key in compressed form.
pub const PublicKey = struct {
    inner: PublicKeyInner,

    pub const fixed_size: usize = common.public_key_length;
    pub const Signature = scheme_signature;

    /// Decodes a compressed point, or returns null when it is not one.
    pub fn from_bytes(raw: [common.public_key_length]u8) ?PublicKey {
        return .{ .inner = PublicKeyInner.from_bytes(raw) orelse return null };
    }

    /// Verifies `signature` over `message` under `namespace`.
    pub fn verify(
        self: *const PublicKey,
        namespace: []const u8,
        message: []const u8,
        signature: *const PublicKey.Signature,
    ) bool {
        return self.verify_hash(common.payload_hash(namespace, message), signature);
    }

    /// Verifies `signature` over `message`, with no namespace framing.
    pub fn verify_raw(
        self: *const PublicKey,
        message: []const u8,
        signature: *const PublicKey.Signature,
    ) bool {
        return self.verify_hash(common.payload_hash(null, message), signature);
    }

    fn verify_hash(
        self: *const PublicKey,
        hash: [32]u8,
        signature: *const PublicKey.Signature,
    ) bool {
        // A decoded or freshly signed signature always parses.
        const scalars = common.Scalars.parse(&signature.raw) orelse return false;
        return self.inner.verify_prehashed(hash, scalars);
    }

    pub fn as_slice(self: *const PublicKey) []const u8 {
        return &self.inner.raw;
    }

    pub fn eql(a: PublicKey, b: PublicKey) bool {
        return a.inner.eql(&b.inner);
    }

    pub fn order(a: PublicKey, b: PublicKey) std.math.Order {
        return a.inner.order(&b.inner);
    }

    pub fn less_than(_: void, a: PublicKey, b: PublicKey) bool {
        return a.order(b) == .lt;
    }

    pub fn write(self: *const PublicKey, writer: *codec.Writer) void {
        self.inner.write(writer);
    }

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, cfg: void) codec.Error!PublicKey {
        _ = gpa;
        _ = cfg;
        return .{ .inner = try PublicKeyInner.read(reader) };
    }

    pub fn format(self: PublicKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}", .{&self.inner.raw});
    }
};

/// A secp256r1 signature, `r || s` big-endian, with `s` in the lower half of the order.
pub const Signature = struct {
    raw: [signature_length]u8,

    pub const fixed_size: usize = signature_length;

    /// The signature `raw` encodes, or null when commonware would reject it.
    pub fn from_bytes(raw: [signature_length]u8) ?Signature {
        _ = common.Scalars.parse(&raw) orelse return null;
        return .{ .raw = raw };
    }

    pub fn as_slice(self: *const Signature) []const u8 {
        return &self.raw;
    }

    pub fn eql(a: Signature, b: Signature) bool {
        return utils.bytes_eql(a.raw.len, &a.raw, &b.raw);
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
        const raw = try reader.take_array(signature_length);
        try common.Scalars.read(reader, raw);
        return .{ .raw = raw.* };
    }

    pub fn format(self: Signature, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}", .{&self.raw});
    }
};

comptime {
    signer.assert_signer(PrivateKey);
    assert(codec.fixed_size(PublicKey).? == 33);
    assert(codec.fixed_size(Signature).? == 64);
}
