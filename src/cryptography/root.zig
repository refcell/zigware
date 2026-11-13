//! cryptography: Generate keys, sign arbitrary messages, and deterministically verify signatures.
//!
//! Zig port of commonware's `commonware-cryptography` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/cryptography). Lane: crypto (see
//! docs/lanes/crypto.md); `bls12381/` belongs to lane bls-math.
//!
//! Rust traits are comptime interfaces here: a hasher is any type that passes
//! `assert_hasher` (see `hasher.zig`), and every digest is a `Digest(length, name)`.

const std = @import("std");

pub const digest = @import("digest.zig");
pub const hasher = @import("hasher.zig");
pub const fuzz = @import("fuzz.zig");

pub const Digest = digest.Digest;
pub const DecodeError = digest.DecodeError;
pub const assert_hasher = hasher.assert_hasher;

pub const sha256 = @import("sha256.zig");
pub const Sha256 = sha256.Sha256;
pub const sha512 = @import("sha512.zig");
pub const Sha512 = sha512.Sha512;
pub const blake3 = @import("blake3.zig");
pub const Blake3 = blake3.Blake3;
pub const keccak256 = @import("keccak256.zig");
pub const Keccak256 = keccak256.Keccak256;
pub const crc32 = @import("crc32.zig");
pub const Crc32 = crc32.Crc32;

/// The digest type of hasher `H` (commonware `DigestOf<H>`).
pub fn DigestOf(comptime H: type) type {
    return H.Digest;
}

/// Checks the hasher contract shared by every hasher (commonware `test_hasher_multiple_runs`).
fn expect_hasher_multiple_runs(comptime H: type) !void {
    var h = H.init();
    h.update("hello world");
    const first = h.finalize();
    try std.testing.expectEqual(H.Digest.size, first.bytes.len);
    _ = try H.Digest.decode(&first.bytes);
    h.update("hello world");
    try std.testing.expect(h.finalize().eql(first));
    try std.testing.expect(H.hash(&.{"hello world"}).eql(first));
    h.update("hello mars");
    try std.testing.expect(!h.finalize().eql(first));
}

test "hasher multiple runs" {
    try expect_hasher_multiple_runs(Keccak256);
    try expect_hasher_multiple_runs(Sha256);
    try expect_hasher_multiple_runs(Sha512);
    try expect_hasher_multiple_runs(Blake3);
    try expect_hasher_multiple_runs(Crc32);
}

test {
    std.testing.refAllDecls(@This());
}
