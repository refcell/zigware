//! BLS12-381 `Signer` and `Verifier` keys (commonware `bls12381/scheme.rs`), in the `MinPk`
//! variant: 32-byte private keys, 48-byte G1 public keys, and 96-byte G2 signatures, encoded
//! in the ZCash BLS12-381 format. Messages are hashed per RFC 9380 under
//! `union_unique(namespace, message)`.
//!
//! Keys and signatures keep their encodings, so equality, order, and formatting work on the
//! bytes, as commonware's do.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const parallel = @import("parallel");
const signer = @import("../signer.zig");
const primitives = @import("primitives/root.zig");

const ops = primitives.ops;
const group = primitives.group;
const Private = group.Private;
const MinPk = primitives.MinPk;

const curve_name = "bls12381";

/// A BLS12-381 private key. Formatting never shows the key.
pub const PrivateKey = struct {
    key: Private,

    pub const fixed_size: usize = Private.fixed_size;
    pub const PublicKey = scheme_public_key;
    pub const Signature = scheme_signature;

    /// A key from `ops.keypair`, drawing 64 bytes of key material from `rng`.
    pub fn random(rng: anytype) PrivateKey {
        return .{ .key = ops.keypair(MinPk, rng).private };
    }

    /// Commonware `Signer::from_seed`: insecure, for tests and examples only.
    pub fn from_seed(seed: u64) PrivateKey {
        return signer.from_seed(PrivateKey, seed);
    }

    pub fn from_private(key: Private) PrivateKey {
        assert(!key.scalar.value.eql(group.Scalar.zero));
        return .{ .key = key };
    }

    pub fn public_key(self: *const PrivateKey) PrivateKey.PublicKey {
        return .from_point(ops.compute_public(MinPk, self.key));
    }

    /// Signs `message` under `namespace`.
    pub fn sign(
        self: *const PrivateKey,
        namespace: []const u8,
        message: []const u8,
    ) PrivateKey.Signature {
        return .from_point(ops.sign_message(MinPk, self.key, namespace, message));
    }

    /// Constant-time comparison of the encodings.
    pub fn eql(a: *const PrivateKey, b: *const PrivateKey) bool {
        const a_bytes = a.key.scalar.value.to_bytes();
        const b_bytes = b.key.scalar.value.to_bytes();
        return std.crypto.timing_safe.eql([fixed_size]u8, a_bytes, b_bytes);
    }

    pub fn zeroize(self: *PrivateKey) void {
        self.key.zeroize();
    }

    pub fn write(self: *const PrivateKey, writer: *codec.Writer) void {
        self.key.write(writer);
    }

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!PrivateKey {
        const key = Private.read(gpa, reader, {}) catch |err| switch (err) {
            error.EndOfBuffer => return err,
            else => return reader.wrapped(curve_name),
        };
        return .{ .key = key };
    }

    pub fn format(_: PrivateKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("PrivateKey([REDACTED])");
    }
};

const scheme_public_key = PublicKey;
const scheme_signature = Signature;

/// A BLS12-381 public key: a G1 point and its compressed encoding.
pub const PublicKey = struct {
    raw: [fixed_size]u8,
    key: MinPk.Public,

    pub const fixed_size: usize = MinPk.Public.fixed_size;
    pub const Signature = scheme_signature;
    pub const Entry = signer.BatchEntry(PublicKey);

    pub fn from_point(key: MinPk.Public) PublicKey {
        return .{ .raw = key.to_bytes(), .key = key };
    }

    /// Verifies `signature` over `message` under `namespace`.
    pub fn verify(
        self: *const PublicKey,
        namespace: []const u8,
        message: []const u8,
        signature: *const PublicKey.Signature,
    ) bool {
        ops.verify_message(MinPk, self.key, namespace, message, signature.signature) catch {
            return false;
        };
        return true;
    }

    /// Verifies every entry `projector.project(index, &items[index])` with one random
    /// linear combination per 64 entries (commonware `BatchVerifier::verify_batch`); pass
    /// `cryptography.entries` for a slice of `Entry`. False for an empty batch or when any
    /// signature is invalid. `strategy` hashes the messages, as in commonware.
    pub fn verify_batch(rng: anytype, items: anytype, projector: anytype, strategy: anytype) bool {
        parallel.assert_strategy(@TypeOf(strategy));
        if (items.len == 0) return false;
        const chunk = 64;
        var publics: [chunk]MinPk.Public = undefined;
        var hms: [chunk]MinPk.Signature = undefined;
        var signatures: [chunk]MinPk.Signature = undefined;
        var start: usize = 0;
        while (start < items.len) : (start += chunk) {
            const count = @min(chunk, items.len - start);
            for (0..count) |offset| {
                const index = start + offset;
                const entry: Entry = projector.project(index, &items[index]);
                publics[offset] = entry.public_key.key;
                signatures[offset] = entry.signature.signature;
            }
            // `strategy` hashes the messages, as in commonware.
            const Hash = struct {
                items: @TypeOf(items),
                projector: @TypeOf(projector),

                pub fn map(hash: @This(), index: usize) MinPk.Signature {
                    const entry: Entry = hash.projector.project(index, &hash.items[index]);
                    return ops.hash_with_namespace(
                        MinPk,
                        MinPk.message,
                        entry.namespace,
                        entry.message,
                    );
                }
            };
            const range = parallel.Range.init(start, start + count);
            strategy.map_into(range, hms[0..count], Hash{ .items = items, .projector = projector });
            // Draws the same scalars, in the same order, as one batch over every entry.
            MinPk.batch_verify(rng, publics[0..count], hms[0..count], signatures[0..count]) catch
                return false;
        }
        return true;
    }

    pub fn as_slice(self: *const PublicKey) []const u8 {
        return &self.raw;
    }

    pub fn eql(a: PublicKey, b: PublicKey) bool {
        return std.mem.eql(u8, &a.raw, &b.raw);
    }

    pub fn order(a: PublicKey, b: PublicKey) std.math.Order {
        return std.mem.order(u8, &a.raw, &b.raw);
    }

    pub fn less_than(_: void, a: PublicKey, b: PublicKey) bool {
        return order(a, b) == .lt;
    }

    pub fn write(self: *const PublicKey, writer: *codec.Writer) void {
        writer.write_bytes(&self.raw);
    }

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!PublicKey {
        const raw = try reader.take_array(fixed_size);
        var inner = codec.Reader.init(raw);
        const key = MinPk.Public.read(gpa, &inner, {}) catch return reader.wrapped(curve_name);
        return .{ .raw = raw.*, .key = key };
    }

    pub fn format(self: PublicKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}", .{&self.raw});
    }
};

/// A BLS12-381 signature: a G2 point and its compressed encoding.
pub const Signature = struct {
    raw: [fixed_size]u8,
    signature: MinPk.Signature,

    pub const fixed_size: usize = MinPk.Signature.fixed_size;

    pub fn from_point(signature: MinPk.Signature) Signature {
        return .{ .raw = signature.to_bytes(), .signature = signature };
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

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!Signature {
        const raw = try reader.take_array(fixed_size);
        var inner = codec.Reader.init(raw);
        const point = MinPk.Signature.read(gpa, &inner, {}) catch
            return reader.wrapped(curve_name);
        return .{ .raw = raw.*, .signature = point };
    }

    pub fn format(self: Signature, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}", .{&self.raw});
    }
};

comptime {
    signer.assert_signer(PrivateKey);
    signer.assert_batch_verifier(PublicKey);
    assert(codec.fixed_size(PrivateKey).? == 32);
    assert(codec.fixed_size(PublicKey).? == 48);
    assert(codec.fixed_size(Signature).? == 96);
}
