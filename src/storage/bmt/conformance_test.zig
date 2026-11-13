//! Conformance hashes of the Binary Merkle Tree (commonware's `bmt::tests::conformance`).
//!
//! `RootConformance` builds trees of 0 to 199 leaves, checks every proof, and hashes the
//! roots. `CodecConformance<Proof<Sha256Digest>>` regenerates commonware's 65536 proofs from
//! the same `arbitrary` input and hashes their encodings. The expected values are copied from
//! commonware's `storage/conformance.toml`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const bmt = @import("mod.zig");

const arbitrary = codec.arbitrary;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Proof = bmt.Proof(Digest);

const conformance_file =
    \\["commonware_storage::bmt::tests::conformance::CodecConformance<Proof<Sha256Digest>>"]
    \\n_cases = 65536
    \\hash = "6d6382956289a2f706581a4b1afa08c5cd8e8a4f55b11d454425333b6537cc17"
    \\
    \\["commonware_storage::bmt::tests::conformance::RootConformance"]
    \\n_cases = 200
    \\hash = "18b1108f18520078e2eb5bb29c6a4cdf3bded6b52d8efda19d45c0f10be27207"
    \\
;
const prefix = "commonware_storage::bmt::tests::conformance::";

fn hash_index(i: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, i, .big);
    return Sha256.hash(&.{&bytes});
}

fn expect_rejected(
    proof: *const Proof,
    position: u32,
    leaf: *const Digest,
    root: *const Digest,
) !void {
    if (proof.verify_element_inclusion(Sha256, position, leaf, root, null)) |_| {
        return error.TamperedProofVerified;
    } else |_| {}
}

/// Checks that every leaf of a tree with `n` leaves proves, survives a codec round trip, and
/// fails once a sibling is modified, added, or removed; returns the root.
fn test_merkle_tree(gpa: Allocator, n: u32) !Digest {
    var builder = try bmt.Builder(Sha256).init(gpa, n);
    defer builder.deinit(gpa);
    for (0..n) |i| _ = try builder.add(gpa, &hash_index(i));
    var tree = try builder.build(gpa);
    defer tree.deinit(gpa);
    const root = tree.root();

    const tampered = Sha256.hash(&.{"tampered"});
    for (0..n) |i| {
        const position: u32 = @intCast(i);
        const leaf = hash_index(i);
        var proof = try tree.proof(gpa, position, null);
        defer proof.deinit(gpa);
        try proof.verify_element_inclusion(Sha256, position, &leaf, &root, null);

        const encoded = try codec.encode(Proof, gpa, proof);
        defer gpa.free(encoded);
        var decoded = try codec.decode_cfg(Proof, gpa, encoded, 1);
        defer decoded.deinit(gpa);
        try decoded.verify_element_inclusion(Sha256, position, &leaf, &root, null);

        const longer = try gpa.alloc(Digest, proof.siblings.len + 1);
        defer gpa.free(longer);
        @memcpy(longer[0..proof.siblings.len], proof.siblings);
        longer[proof.siblings.len] = tampered;
        try expect_rejected(&.{ .leaf_count = n, .siblings = longer }, position, &leaf, &root);
        if (proof.siblings.len == 0) continue;
        const shorter = longer[0 .. proof.siblings.len - 1];
        try expect_rejected(&.{ .leaf_count = n, .siblings = shorter }, position, &leaf, &root);
        longer[0] = tampered;
        const modified = longer[0..proof.siblings.len];
        try expect_rejected(&.{ .leaf_count = n, .siblings = modified }, position, &leaf, &root);
    }
    try std.testing.expectError(error.InvalidPosition, tree.proof(gpa, n, null));
    return root;
}

const RootConformance = struct {
    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        const root = try test_merkle_tree(gpa, @intCast(seed));
        return gpa.dupe(u8, &root.bytes);
    }
};

/// `sha256::Digest::arbitrary`: `int_in_range(0..=256)` bytes of data, then their hash.
fn gen_digest(gpa: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!Digest {
    const len = u.int_in_range(u64, 0, 256);
    assert(len <= 256);
    const data = try gpa.alloc(u8, len);
    try u.bytes(data);
    return Sha256.hash(&.{data});
}

/// The derived `Proof::arbitrary`: the leaf count, then `Vec<Digest>::arbitrary`.
fn gen_proof(gpa: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!Proof {
    const leaf_count = u.int(u32);
    var siblings: std.ArrayList(Digest) = .empty;
    while (u.keep_going()) try siblings.append(gpa, try gen_digest(gpa, u));
    return .{ .leaf_count = leaf_count, .siblings = siblings.items };
}

const ProofConformance = struct {
    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const proof = try arbitrary.generate(Proof, gen_proof, arena.allocator(), seed);
        return codec.encode(Proof, gpa, proof);
    }
};

test "conformance RootConformance" {
    const gpa = std.testing.allocator;
    try conformance.verify(
        RootConformance,
        gpa,
        prefix ++ "RootConformance",
        200,
        conformance_file,
    );
}

test "conformance CodecConformance<Proof<Sha256Digest>>" {
    try conformance.verify(
        ProofConformance,
        std.heap.smp_allocator,
        prefix ++ "CodecConformance<Proof<Sha256Digest>>",
        conformance.default_cases,
        conformance_file,
    );
}
