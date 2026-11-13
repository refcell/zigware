//! secp256r1 keys and 65-byte recoverable signatures (commonware `secp256r1/recoverable.rs`).
//!
//! A signature is `recovery_id || r || s`: the recovery id (0 to 3) selects which point `R`
//! produced `r`, so the signer's public key can be recovered from the signature and message.
//! Verification recovers the key and compares it with the expected one.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const signer = @import("../signer.zig");
const common = @import("common.zig");

const PrivateKeyInner = common.PrivateKeyInner;
const PublicKeyInner = common.PublicKeyInner;

const base_signature_length = 64;
pub const signature_length = 1 + base_signature_length;

/// A secp256r1 signing key that produces recoverable signatures. Formatting never shows it.
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
        return .from_signed(self.inner.sign(namespace, message));
    }

    /// Signs `message` as is, with no namespace framing.
    pub fn sign_raw(self: *const PrivateKey, message: []const u8) PrivateKey.Signature {
        return .from_signed(self.inner.sign(null, message));
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

    /// Verifies `signature` over `message` under `namespace` by recovering its signer.
    pub fn verify(
        self: *const PublicKey,
        namespace: []const u8,
        message: []const u8,
        signature: *const PublicKey.Signature,
    ) bool {
        const recovered = signature.recover_signer(namespace, message) orelse return false;
        return recovered.eql(self.*);
    }

    /// Verifies `signature` over `message`, with no namespace framing.
    pub fn verify_raw(
        self: *const PublicKey,
        message: []const u8,
        signature: *const PublicKey.Signature,
    ) bool {
        const recovered = signature.recover_signer_raw(message) orelse return false;
        return recovered.eql(self.*);
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

/// A recoverable secp256r1 signature: `recovery_id || r || s`, with low `s`.
pub const Signature = struct {
    raw: [signature_length]u8,

    pub const fixed_size: usize = signature_length;
    pub const PublicKey = scheme_public_key;

    fn from_signed(signed: common.Signed) Signature {
        return .init(signed.recovery_id, signed.raw);
    }

    /// The signature with `recovery_id` and `r || s` (`Signature::new`), unvalidated: a
    /// malformed `r || s` recovers no signer.
    pub fn init(id: common.RecoveryId, rs: [base_signature_length]u8) Signature {
        const signature: Signature = .{ .raw = [1]u8{id} ++ rs };
        assert(signature.raw[0] <= 3);
        return signature;
    }

    pub fn recovery_id(self: *const Signature) common.RecoveryId {
        return @intCast(self.raw[0]);
    }

    /// The public key whose signature over `message` under `namespace` this is, or null.
    pub fn recover_signer(
        self: *const Signature,
        namespace: []const u8,
        message: []const u8,
    ) ?Signature.PublicKey {
        return self.recover_hash(common.payload_hash(namespace, message));
    }

    /// `recover_signer` for a message signed with no namespace framing.
    pub fn recover_signer_raw(self: *const Signature, message: []const u8) ?Signature.PublicKey {
        return self.recover_hash(common.payload_hash(null, message));
    }

    fn recover_hash(self: *const Signature, hash: [32]u8) ?Signature.PublicKey {
        assert(self.raw[0] <= 3);
        const scalars = common.Scalars.parse(self.raw[1..]) orelse return null;
        const inner = common.recover(hash, scalars, self.recovery_id()) orelse return null;
        return .{ .inner = inner };
    }

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
        const raw = try reader.take_array(signature_length);
        if (raw[0] > 3) return reader.invalid(common.curve_name, "RecoveryId out of range");
        try common.Scalars.read(reader, raw[1..]);
        return .{ .raw = raw.* };
    }

    pub fn format(self: Signature, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}", .{&self.raw});
    }
};

comptime {
    signer.assert_signer(PrivateKey);
    signer.assert_recoverable(Signature);
    assert(codec.fixed_size(PublicKey).? == 33);
    assert(codec.fixed_size(Signature).? == 65);
}
