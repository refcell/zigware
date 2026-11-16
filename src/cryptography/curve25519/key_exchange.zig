//! X25519 key exchange (commonware `cryptography/curve25519/src/key_exchange.rs`, RFC 7748).
//!
//! A public key is any 32-byte u-coordinate, kept as given: bit 255 is ignored and values at or
//! above p are taken mod p, so aliases compare equal and exchange identically. An exchange
//! whose shared secret is all zero (a low-order public key) is rejected as non-contributory.
//! `deinit` zeroizes secret keys and shared secrets.

const std = @import("std");
const codec = @import("codec");
const formatting = @import("formatting");
const assert = std.debug.assert;
const X25519 = std.crypto.dh.X25519;

/// p = 2^255 - 19.
const field_order: u256 = (@as(u256, 1) << 255) - 19;

pub const SecretKey = struct {
    bytes: [32]u8,

    /// A key from 32 bytes of `rng` (`rng.fill_bytes`), which must be a CSPRNG.
    pub fn random(rng: anytype) SecretKey {
        var key: SecretKey = undefined;
        rng.fill_bytes(&key.bytes);
        return key;
    }

    /// The key with these raw (unclamped) scalar bytes.
    pub fn from_raw(bytes: [32]u8) SecretKey {
        return .{ .bytes = bytes };
    }

    pub fn deinit(self: *SecretKey) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.* = undefined;
    }

    pub fn public_key(self: *const SecretKey) PublicKey {
        return .{ .bytes = X25519.recoverPublicKey(self.bytes) };
    }

    /// The shared secret with `other`, or null when it is all zero.
    pub fn exchange(self: *const SecretKey, other: PublicKey) ?SharedSecret {
        const shared = X25519.scalarmult(self.bytes, other.bytes) catch return null;
        assert(!std.mem.allEqual(u8, &shared, 0));
        return .{ .bytes = shared };
    }
};

pub const PublicKey = struct {
    bytes: [32]u8,

    pub const fixed_size: usize = 32;

    /// The u-coordinate this key denotes: bit 255 cleared, reduced mod p.
    fn coordinate(self: PublicKey) u256 {
        const value = std.mem.readInt(u256, &self.bytes, .little) & ((@as(u256, 1) << 255) - 1);
        return value % field_order;
    }

    /// Equal when both encode the same u-coordinate.
    pub fn eql(a: PublicKey, b: PublicKey) bool {
        return a.coordinate() == b.coordinate();
    }

    pub fn as_slice(self: *const PublicKey) []const u8 {
        return &self.bytes;
    }

    pub fn write(self: *const PublicKey, writer: *codec.Writer) void {
        writer.write_bytes(&self.bytes);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!PublicKey {
        return .{ .bytes = (try reader.take_array(fixed_size)).* };
    }

    pub fn arbitrary(
        gpa: std.mem.Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!PublicKey {
        return .{ .bytes = try codec.arbitrary.value([32]u8, gpa, u) };
    }

    pub fn format(self: PublicKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try formatting.fmt_hex(&self.bytes).format(writer);
    }
};

pub const SharedSecret = struct {
    bytes: [32]u8,

    pub fn deinit(self: *SharedSecret) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.* = undefined;
    }
};

const testing = std.testing;
const basepoint_u: [32]u8 = .{9} ++ @as([31]u8, @splat(0));

fn hex32(comptime text: []const u8) [32]u8 {
    return formatting.hex_literal(text);
}

test "key_exchange: public key equality uses decoded coordinates" {
    var basepoint_high = basepoint_u;
    basepoint_high[31] |= 0x80;
    const one: [32]u8 = .{1} ++ @as([31]u8, @splat(0));
    const aliases = [_][2][32]u8{
        .{ basepoint_u, basepoint_high },
        .{ @splat(0), hex32("0xedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") },
        .{ one, hex32("0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") },
    };
    const secret = SecretKey.from_raw(@splat(42));
    for (aliases) |pair| {
        const canonical: PublicKey = .{ .bytes = pair[0] };
        const alias: PublicKey = .{ .bytes = pair[1] };
        try testing.expect(canonical.eql(alias));
        try testing.expect(!std.mem.eql(u8, &pair[0], &pair[1]));
        const a = secret.exchange(canonical);
        const b = secret.exchange(alias);
        try testing.expectEqual(a == null, b == null);
        if (a) |shared| try testing.expectEqualSlices(u8, &shared.bytes, &b.?.bytes);
    }
    try testing.expect(!(PublicKey{ .bytes = @splat(0) }).eql(.{ .bytes = one }));
}

test "key_exchange: low-order public keys are rejected" {
    const low_order = [_][32]u8{
        @splat(0),
        hex32("0x0100000000000000000000000000000000000000000000000000000000000000"),
        hex32("0xe0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex32("0x5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hex32("0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("0xedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    };
    const secret = SecretKey.from_raw(@splat(42));
    for (low_order) |bytes| try testing.expectEqual(null, secret.exchange(.{ .bytes = bytes }));
}
