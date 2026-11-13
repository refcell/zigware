//! SHA-256 for hash-to-curve, on `std.crypto` (the shape `map.zig` expects).

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const digest_length = Sha256.digest_length;
pub const block_length = Sha256.block_length;
pub const Digest = [digest_length]u8;

pub const Hasher = struct {
    inner: Sha256,

    pub fn init() Hasher {
        return .{ .inner = Sha256.init(.{}) };
    }

    pub fn update(hasher: *Hasher, bytes: []const u8) void {
        hasher.inner.update(bytes);
    }

    pub fn final(hasher: *Hasher) Digest {
        return hasher.inner.finalResult();
    }
};
