//! Conformance helpers and root-stability hashes for Merkle-family structures.
//!
//! Port of commonware's `storage/src/merkle/conformance.rs`. A conformance hash is SHA-256
//! over every case `seed in 0..n_cases` of `len_le64 || commit(seed)`, as in
//! `commonware_conformance::compute_conformance_hash`; the expected values come from
//! commonware's `storage/conformance.toml`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const merkle = @import("mod.zig");

const Sha256 = cryptography.Sha256;
const Standard = merkle.hasher.Standard(Sha256);

/// Adds `elements` leaves to `mem`, leaf `i` being `hasher.digest(i_be64)`.
pub fn build_test_mem(gpa: Allocator, hasher: *const Standard, mem: anytype, elements: u64) !void {
    for (0..elements) |i| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, i, .big);
        const element = hasher.digest(&bytes);
        try mem.add(gpa, hasher, &element.bytes);
    }
}

/// The root of a structure of family `F` built from `seed` elements (commonware's
/// `MmrRootStability`/`MmbRootStability` commit).
fn root_stability_commit(comptime F: type, gpa: Allocator, seed: u64) !Sha256.Digest {
    const hasher = Standard.init(.forward_fold);
    var mem: merkle.mem.Mem(F, Sha256.Digest) = .empty;
    defer mem.deinit(gpa);
    try build_test_mem(gpa, &hasher, &mem, seed);
    return mem.root(&hasher, 0);
}

fn root_stability_hash(comptime F: type, gpa: Allocator, n_cases: u64) ![32]u8 {
    var conformance = Sha256.init();
    for (0..n_cases) |seed| {
        const root = try root_stability_commit(F, gpa, seed);
        var len_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_bytes, root.bytes.len, .little);
        conformance.update(&len_bytes);
        conformance.update(&root.bytes);
    }
    return conformance.finalize().bytes;
}

fn expect_hash(expected_hex: *const [64]u8, actual: [32]u8) !void {
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "conformance MmrRootStability" {
    const actual = try root_stability_hash(merkle.mmr.Family, std.testing.allocator, 200);
    try expect_hash("23151a36602cbbf8cadd68638d5290c44a7679f013a1b1b620007e05a544f533", actual);
}

test "conformance MmbRootStability" {
    const actual = try root_stability_hash(merkle.mmb.Family, std.testing.allocator, 200);
    try expect_hash("8defd2a59ffcea7b24fdef437bff9a954267e17ab72aa6d7c2ef7ed5d3d90238", actual);
}
