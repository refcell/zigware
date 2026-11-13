//! Single-element and range proof tests (commonware's `bmt` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const bmt = @import("mod.zig");

const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Proof = bmt.Proof(Digest);
const Tree = bmt.Tree(Digest);
const gpa = testing.allocator;

pub fn hash_bytes(bytes: []const u8) Digest {
    return Sha256.hash(&.{bytes});
}

pub fn hash_index(i: u32) Digest {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, i, .big);
    return Sha256.hash(&.{&bytes});
}

/// Leaves `hash(i_be32)` for `i` in `0..n`; the caller frees.
pub fn sequence(n: u32) ![]Digest {
    const digests = try gpa.alloc(Digest, n);
    for (digests, 0..) |*digest, i| digest.* = hash_index(@intCast(i));
    return digests;
}

pub fn build(digests: []const Digest) !Tree {
    var builder = try bmt.Builder(Sha256).init(gpa, digests.len);
    defer builder.deinit(gpa);
    for (digests) |*digest| _ = try builder.add(gpa, digest);
    return builder.build(gpa);
}

fn transactions(comptime n: usize) [n]Digest {
    var digests: [n]Digest = undefined;
    for (&digests, 0..) |*digest, i| {
        const tx = [_]u8{ 't', 'x', '1' + @as(u8, @intCast(i)) };
        digest.* = hash_bytes(&tx);
    }
    return digests;
}

fn expect_element(
    proof: *const Proof,
    position: u32,
    leaf: *const Digest,
    root: *const Digest,
) !void {
    try proof.verify_element_inclusion(Sha256, position, leaf, root, null);
}

fn element_fails(
    proof: *const Proof,
    position: u32,
    leaf: *const Digest,
    root: *const Digest,
) bool {
    proof.verify_element_inclusion(Sha256, position, leaf, root, null) catch return true;
    return false;
}

fn verify_range(
    proof: *const Proof,
    position: u32,
    leaves: []const Digest,
    root: *const Digest,
) !void {
    try proof.verify_range_inclusion(Sha256, gpa, position, leaves, root, null);
}

fn range_fails(
    proof: *const Proof,
    position: u32,
    leaves: []const Digest,
    root: *const Digest,
) bool {
    proof.verify_range_inclusion(Sha256, gpa, position, leaves, root, null) catch |err| {
        std.debug.assert(err != error.OutOfMemory);
        return true;
    };
    return false;
}

fn round_trip(proof: *const Proof, max_items: usize) !Proof {
    const encoded = try codec.encode(Proof, gpa, proof.*);
    defer gpa.free(encoded);
    return codec.decode_cfg(Proof, gpa, encoded, max_items);
}

test "issue 2837 regression: the root binds the leaf count" {
    const digests = try sequence(255);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    var proof = try tree.proof(gpa, 0, null);
    defer proof.deinit(gpa);
    try testing.expectEqual(@as(u32, 255), proof.leaf_count);
    try expect_element(&proof, 0, &digests[0], &root);

    // Identical siblings with a smaller leaf count must not verify.
    const malleated: Proof = .{ .leaf_count = 254, .siblings = proof.siblings };
    try testing.expect(element_fails(&malleated, 0, &digests[0], &root));
}

test "tampered proofs fail: no siblings, extra sibling, modified sibling" {
    const digests = transactions(4);
    var tree = try build(&digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    var proof = try tree.proof(gpa, 0, null);
    defer proof.deinit(gpa);
    const empty: Proof = .{ .leaf_count = proof.leaf_count };
    try testing.expect(element_fails(&empty, 0, &digests[0], &root));

    const extended = try gpa.alloc(Digest, proof.siblings.len + 1);
    defer gpa.free(extended);
    @memcpy(extended[0..proof.siblings.len], proof.siblings);
    extended[proof.siblings.len] = digests[0];
    const extra: Proof = .{ .leaf_count = proof.leaf_count, .siblings = extended };
    try testing.expect(element_fails(&extra, 0, &digests[0], &root));

    var modified = try tree.proof(gpa, 2, null);
    defer modified.deinit(gpa);
    try expect_element(&modified, 2, &digests[2], &root);
    modified.siblings[0] = hash_bytes("modified");
    try testing.expect(element_fails(&modified, 2, &digests[2], &root));
}

test "invalid proofs: wrong element, wrong index, wrong root" {
    const digests = transactions(4);
    var tree = try build(&digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    var proof_2 = try tree.proof(gpa, 2, null);
    defer proof_2.deinit(gpa);
    try testing.expect(element_fails(&proof_2, 2, &hash_bytes("wrong_tx"), &root));

    var proof_1 = try tree.proof(gpa, 1, null);
    defer proof_1.deinit(gpa);
    try testing.expect(element_fails(&proof_1, 2, &digests[1], &root));

    var proof_0 = try tree.proof(gpa, 0, null);
    defer proof_0.deinit(gpa);
    try testing.expect(element_fails(&proof_0, 0, &digests[0], &hash_bytes("wrong_root")));
}

test "proof serialization rejects truncated and extended encodings" {
    const digests = transactions(3);
    var tree = try build(&digests);
    defer tree.deinit(gpa);
    var proof = try tree.proof(gpa, 1, null);
    defer proof.deinit(gpa);

    const encoded = try codec.encode(Proof, gpa, proof);
    defer gpa.free(encoded);
    try testing.expectError(
        error.EndOfBuffer,
        codec.decode_cfg(Proof, gpa, encoded[0 .. encoded.len - 1], 1),
    );
    const extended = try gpa.alloc(u8, encoded.len + 1);
    defer gpa.free(extended);
    @memcpy(extended[0..encoded.len], encoded);
    extended[encoded.len] = 0;
    try testing.expectError(error.ExtraData, codec.decode_cfg(Proof, gpa, extended, 1));

    var decoded = try round_trip(&proof, 1);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&proof));
}

test "odd tree: the last leaf proves, positions past it do not" {
    const digests = transactions(3);
    var tree = try build(&digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    var proof = try tree.proof(gpa, 2, null);
    defer proof.deinit(gpa);
    try expect_element(&proof, 2, &digests[2], &root);
    var diagnostic: bmt.Diagnostic = .{};
    try testing.expectError(error.InvalidPosition, tree.proof(gpa, 3, &diagnostic));
    try testing.expectEqual(@as(u32, 3), diagnostic.position);
    try testing.expect(element_fails(&proof, 3, &digests[2], &root));
}

test "range proof basic and serialization" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    var proof = try tree.range_proof(gpa, 2, 5, null);
    defer proof.deinit(gpa);
    try verify_range(&proof, 2, digests[2..6], &root);
    var decoded = try round_trip(&proof, 4);
    defer decoded.deinit(gpa);
    try verify_range(&decoded, 2, digests[2..6], &root);

    // Missing leaves are rejected.
    try testing.expect(range_fails(&proof, 2, digests[2..5], &root));
}

test "range proof single element, full tree, and edge ranges" {
    const digests = try sequence(15);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    for (0..8) |i| {
        var proof = try tree.range_proof(gpa, @intCast(i), @intCast(i), null);
        defer proof.deinit(gpa);
        try verify_range(&proof, @intCast(i), digests[i .. i + 1], &root);
    }
    const ranges = [_][2]u32{ .{ 0, 14 }, .{ 0, 7 }, .{ 8, 14 }, .{ 13, 14 } };
    for (ranges) |range| {
        var proof = try tree.range_proof(gpa, range[0], range[1], null);
        defer proof.deinit(gpa);
        try verify_range(&proof, range[0], digests[range[0] .. range[1] + 1], &root);
    }

    const seven = try sequence(7);
    defer gpa.free(seven);
    var small = try build(seven);
    defer small.deinit(gpa);
    var full = try small.range_proof(gpa, 0, 6, null);
    defer full.deinit(gpa);
    try verify_range(&full, 0, seven, &small.root());
}

test "range proof invalid ranges and overflow" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);

    const max = std.math.maxInt(u32);
    const invalid = [_][2]u32{
        .{ 8, 8 },   .{ 0, 8 },     .{ 5, 8 },
        .{ 2, 1 },   .{ max, max }, .{ max - 1, max },
        .{ 7, max },
    };
    for (invalid) |range| {
        try testing.expectError(
            error.InvalidPosition,
            tree.range_proof(gpa, range[0], range[1], null),
        );
    }
}

test "range proof tampering" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    var proof = try tree.range_proof(gpa, 2, 4, null);
    defer proof.deinit(gpa);
    const leaves = digests[2..5];
    const wrong = [_]Digest{ hash_bytes("wrong1"), hash_bytes("wrong2"), hash_bytes("wrong3") };
    try testing.expect(range_fails(&proof, 2, &wrong, &root));
    try testing.expect(range_fails(&proof, 2, digests[2..4], &root));
    try testing.expect(range_fails(&proof, 2, leaves, &hash_bytes("wrong_root")));

    // Wrong start positions and reordered leaves.
    try testing.expect(range_fails(&proof, 3, leaves, &root));
    try testing.expect(range_fails(&proof, 1, leaves, &root));
    const reordered = [_]Digest{ digests[3], digests[2], digests[4] };
    try testing.expect(range_fails(&proof, 2, &reordered, &root));

    var tampered = try proof.clone(gpa);
    defer tampered.deinit(gpa);
    try testing.expect(tampered.siblings.len > 0);
    tampered.siblings[0] = hash_bytes("tampered");
    try testing.expect(range_fails(&tampered, 2, leaves, &root));
}

test "range proof with extra or missing siblings fails" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    var pair = try tree.range_proof(gpa, 2, 3, null);
    defer pair.deinit(gpa);
    const extended = try gpa.alloc(Digest, pair.siblings.len + 1);
    defer gpa.free(extended);
    @memcpy(extended[0..pair.siblings.len], pair.siblings);
    extended[pair.siblings.len] = hash_bytes("extra");
    const extra: Proof = .{ .leaf_count = pair.leaf_count, .siblings = extended };
    try verify_range(&pair, 2, digests[2..4], &root);
    try testing.expect(range_fails(&extra, 2, digests[2..4], &root));

    var single = try tree.range_proof(gpa, 2, 2, null);
    defer single.deinit(gpa);
    try testing.expect(single.siblings.len > 0);
    const missing: Proof = .{
        .leaf_count = single.leaf_count,
        .siblings = single.siblings[0 .. single.siblings.len - 1],
    };
    try testing.expect(range_fails(&missing, 2, digests[2..3], &root));
}

test "range proof various sizes and boundaries" {
    const sizes = [_]u32{ 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 63, 64 };
    for (sizes) |size| {
        const digests = try sequence(size);
        defer gpa.free(digests);
        var tree = try build(digests);
        defer tree.deinit(gpa);
        const root = tree.root();
        for (1..@min(size, 8) + 1) |range_size| {
            for (0..size - range_size + 1) |start| {
                const end = start + range_size;
                var proof = try tree.range_proof(gpa, @intCast(start), @intCast(end - 1), null);
                defer proof.deinit(gpa);
                try verify_range(&proof, @intCast(start), digests[start..end], &root);
            }
        }
        var whole = try tree.range_proof(gpa, 0, size - 1, null);
        defer whole.deinit(gpa);
        try verify_range(&whole, 0, digests, &root);
    }
}

test "empty tree: no proofs, only the empty range proof" {
    var tree = try build(&.{});
    defer tree.deinit(gpa);
    const root = tree.root();
    for ([_]u32{ 0, 1, 100 }) |position| {
        try testing.expectError(error.InvalidPosition, tree.proof(gpa, position, null));
    }

    var proof = try tree.range_proof(gpa, 0, 0, null);
    defer proof.deinit(gpa);
    try testing.expect(proof.eql(&.{}));
    const max = std.math.maxInt(u32);
    const invalid = [_][2]u32{
        .{ 0, 1 }, .{ 0, 10 },  .{ 1, 1 },   .{ 1, 2 },
        .{ 5, 5 }, .{ 10, 10 }, .{ 0, max }, .{ max, max },
    };
    for (invalid) |range| {
        try testing.expectError(
            error.InvalidPosition,
            tree.range_proof(gpa, range[0], range[1], null),
        );
    }

    try verify_range(&proof, 0, &.{}, &root);
    try testing.expect(range_fails(&proof, 0, &.{hash_bytes("leaf")}, &root));
    try testing.expect(range_fails(&proof, 0, &.{}, &hash_bytes("wrong")));
    try testing.expect(range_fails(&proof, 1, &.{}, &root));

    var decoded = try round_trip(&.{}, 0);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&.{}));
}

test "empty tree root is hash(0 || hash())" {
    var first = try build(&.{});
    defer first.deinit(gpa);
    for (0..4) |_| {
        var again = try build(&.{});
        defer again.deinit(gpa);
        try testing.expect(again.root().eql(first.root()));
    }
    const empty = hash_bytes("");
    const zero: [4]u8 = @splat(0);
    try testing.expect(first.root().eql(Sha256.hash(&.{ &zero, &empty.bytes })));
}

test "range proof uses every sibling" {
    const digests = try sequence(16);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    const cases = [_][2]u32{ .{ 1, 2 }, .{ 4, 4 }, .{ 0, 16 } };
    for (cases) |case| {
        const start = case[0];
        const end = start + case[1];
        var proof = try tree.range_proof(gpa, start, end - 1, null);
        defer proof.deinit(gpa);
        try verify_range(&proof, start, digests[start..end], &root);
        for (0..proof.siblings.len) |index| {
            var tampered = try proof.clone(gpa);
            defer tampered.deinit(gpa);
            tampered.siblings[index] = hash_bytes("tampered");
            try testing.expect(range_fails(&tampered, start, digests[start..end], &root));
        }
    }
}

test "range proof over the duplicated last node of odd trees" {
    for ([_]u32{ 3, 5, 7, 9, 11, 13, 15 }) |size| {
        const digests = try sequence(size);
        defer gpa.free(digests);
        var tree = try build(digests);
        defer tree.deinit(gpa);
        var proof = try tree.range_proof(gpa, size - 2, size - 1, null);
        defer proof.deinit(gpa);
        try verify_range(&proof, size - 2, digests[size - 2 ..], &tree.root());
    }
}

test {
    _ = @import("multi_test.zig");
}

test {
    _ = @import("conformance_test.zig");
}

test {
    _ = @import("fuzz.zig");
}
