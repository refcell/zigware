//! Ephemeral X25519 keys for SAKE (commonware `handshake/sake/exchange.rs`, on
//! `x25519-dalek`), backed by `std.crypto.dh.X25519`, with public keys from ed25519's
//! fixed-base table.
//!
//! A secret key is 32 random bytes, clamped when used (RFC 7748). An exchange whose shared
//! secret is all zeroes (a low-order peer key) is non-contributory and rejected, as
//! x25519-dalek's `was_contributory` does.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const Opaque = @import("../secret.zig").Opaque;
const X25519 = std.crypto.dh.X25519;
const base_mul = @import("../ed25519/base_mul.zig");

/// An ephemeral X25519 public key: its 32-byte u-coordinate, kept as given.
pub const EphemeralPublicKey = struct {
    bytes: [32]u8,

    pub const fixed_size: usize = 32;

    pub fn eql(a: EphemeralPublicKey, b: EphemeralPublicKey) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn write(self: *const EphemeralPublicKey, writer: *codec.Writer) void {
        writer.write_bytes(&self.bytes);
    }

    pub fn read(
        gpa: std.mem.Allocator,
        reader: *codec.Reader,
        cfg: void,
    ) codec.Error!EphemeralPublicKey {
        _ = gpa;
        _ = cfg;
        const bytes = try reader.take_array(fixed_size);
        return .{ .bytes = bytes.* };
    }
};

/// An X25519 shared secret; zeroize it once it is committed.
pub const SharedSecret = [32]u8;

/// An ephemeral X25519 secret key.
pub const SecretKey = struct {
    bytes: Opaque([32]u8),

    /// 32 random bytes from `rng` (`fill_bytes`), as `EphemeralSecret::random_from_rng`.
    pub fn random(rng: anytype) SecretKey {
        var key: SecretKey = undefined;
        rng.fill_bytes(&key.bytes.value);
        return key;
    }

    pub fn public(self: *const SecretKey) EphemeralPublicKey {
        // The clamped scalar is a nonzero multiple of 8 below the group order times 8, so the
        // base point (of prime order) never maps to the identity. A fixed-base table, not
        // std's ladder, as x25519-dalek's `PublicKey::from` (`mul_base_clamped`).
        return .{ .bytes = base_mul.x25519_public_key(self.bytes.value) };
    }

    /// The shared secret with `other`, or null when it is non-contributory. Consumes the key:
    /// the secret bytes are zeroized either way.
    pub fn exchange(self: *SecretKey, other: *const EphemeralPublicKey) ?SharedSecret {
        defer self.zeroize();
        const shared = X25519.scalarmult(self.bytes.value, other.bytes) catch return null;
        assert(!std.mem.allEqual(u8, &shared, 0));
        return shared;
    }

    pub fn zeroize(self: *SecretKey) void {
        std.crypto.secureZero(u8, &self.bytes.value);
    }
};

const testing = std.testing;
const vectors = @import("x25519_vectors.zig");

fn hex32(text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // Proof: test vectors.
    return out;
}

test "x25519 RFC 7748 vectors" {
    for (vectors.rfc7748) |vector| {
        var key: SecretKey = .{ .bytes = .{ .value = hex32(vector.scalar) } };
        const shared = key.exchange(&.{ .bytes = hex32(vector.u) }).?;
        try testing.expectEqualSlices(u8, &hex32(vector.output), &shared);
    }
    const dh = vectors.rfc7748_diffie_hellman;
    var alice: SecretKey = .{ .bytes = .{ .value = hex32(dh.alice_secret) } };
    var bob: SecretKey = .{ .bytes = .{ .value = hex32(dh.bob_secret) } };
    const alice_public = alice.public();
    const bob_public = bob.public();
    try testing.expectEqualSlices(u8, &hex32(dh.alice_public), &alice_public.bytes);
    try testing.expectEqualSlices(u8, &hex32(dh.bob_public), &bob_public.bytes);
    try testing.expectEqualSlices(u8, &hex32(dh.shared_secret), &alice.exchange(&bob_public).?);
    try testing.expectEqualSlices(u8, &hex32(dh.shared_secret), &bob.exchange(&alice_public).?);
}

test "x25519 Wycheproof vectors, non-contributory exchanges rejected" {
    var rejected: usize = 0;
    for (vectors.wycheproof) |vector| {
        var key: SecretKey = .{ .bytes = .{ .value = hex32(vector.private_key) } };
        const shared = key.exchange(&.{ .bytes = hex32(vector.public_key) });
        if (vector.shared_secret) |expected| {
            try testing.expectEqualSlices(u8, &hex32(expected), &shared.?);
        } else {
            try testing.expect(shared == null);
            rejected += 1;
        }
    }
    try testing.expectEqual(@as(usize, 31), rejected);
    try testing.expectEqual(@as(usize, 518), vectors.wycheproof.len);
}

test "x25519 public key codec" {
    const key: EphemeralPublicKey = .{ .bytes = @splat(9) };
    const encoded = codec.encode_fixed(EphemeralPublicKey, key);
    try testing.expect(key.eql(try codec.decode(EphemeralPublicKey, testing.allocator, &encoded)));
}
