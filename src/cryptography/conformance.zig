//! Conformance hashes for the cryptography tests (commonware `conformance` crate):
//! SHA-256 over `len(commit(seed)) as u64 little-endian || commit(seed)` for seeds
//! `0..n_cases`, compared with the hex hash from commonware's `conformance.toml`.
//!
//! A small lane-local driver until the conformance package exports one.

const std = @import("std");
const assert = std.debug.assert;

/// Computes the conformance hash of `commit(gpa, seed, *log)` over `n_cases` seeds.
pub fn hash(
    gpa: std.mem.Allocator,
    n_cases: u64,
    comptime commit: fn (std.mem.Allocator, u64, *std.ArrayList(u8)) anyerror!void,
) ![32]u8 {
    assert(n_cases > 0);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(gpa);
    for (0..n_cases) |seed| {
        log.clearRetainingCapacity();
        try commit(gpa, seed, &log);
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, log.items.len, .little);
        hasher.update(&length);
        hasher.update(log.items);
    }
    return hasher.finalResult();
}

/// Expects the conformance hash of `commit` to equal `expected_hex`.
pub fn expect(
    n_cases: u64,
    comptime expected_hex: []const u8,
    comptime commit: fn (std.mem.Allocator, u64, *std.ArrayList(u8)) anyerror!void,
) !void {
    comptime assert(expected_hex.len == 64);
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    const actual = try hash(std.testing.allocator, n_cases, commit);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}
