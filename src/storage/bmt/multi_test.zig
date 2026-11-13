//! Multi-proof tests (commonware's `bmt` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const bmt = @import("mod.zig");
const helpers = @import("tests.zig");

const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Proof = bmt.Proof(Digest);
const Element = Proof.Element;
const gpa = testing.allocator;
const hash_bytes = helpers.hash_bytes;
const sequence = helpers.sequence;
const build = helpers.build;

/// The elements `(p, digests[p])` for `p` in `positions`; the caller frees.
fn elements_at(digests: []const Digest, positions: []const u32) ![]Element {
    const elements = try gpa.alloc(Element, positions.len);
    for (positions, elements) |position, *element| {
        element.* = .{ .position = position, .digest = digests[position] };
    }
    return elements;
}

fn verify(proof: *const Proof, elements: []const Element, root: *const Digest) bmt.Error!void {
    return proof.verify_multi_inclusion(
        Sha256,
        gpa,
        elements,
        root,
        null,
    ) catch |err| switch (err) {
        error.OutOfMemory => unreachable,
        else => |e| e,
    };
}

fn fails(proof: *const Proof, elements: []const Element, root: *const Digest) bool {
    verify(proof, elements, root) catch return true;
    return false;
}

/// Proves `positions` in a tree of `size` leaves and checks the proof verifies.
fn expect_proves(size: u32, positions: []const u32) !void {
    const digests = try sequence(size);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    var proof = try tree.multi_proof(gpa, positions, null);
    defer proof.deinit(gpa);
    const elements = try elements_at(digests, positions);
    defer gpa.free(elements);
    try verify(&proof, elements, &tree.root());
}

test "multi-proof basic, adjacent, sparse, and single positions" {
    try expect_proves(8, &.{ 0, 3, 5 });
    try expect_proves(8, &.{ 2, 3 });
    try expect_proves(16, &.{ 0, 7, 8, 15 });
    for (0..8) |i| try expect_proves(8, &.{@intCast(i)});
}

test "multi-proof of every leaf needs no siblings" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const positions = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var proof = try tree.multi_proof(gpa, &positions, null);
    defer proof.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), proof.siblings.len);
    const elements = try elements_at(digests, &positions);
    defer gpa.free(elements);
    try verify(&proof, elements, &tree.root());
}

test "multi-proof various and odd tree sizes" {
    for ([_]u32{ 1, 2, 3, 4, 5, 7, 8, 9, 11, 13, 15, 16, 31, 32 }) |size| {
        if (size >= 2) try expect_proves(size, &.{ 0, size - 1 });
        if (size >= 4) {
            var positions: [16]u32 = undefined;
            var count: usize = 0;
            var position: u32 = 0;
            while (position < size) : (position += 2) {
                positions[count] = position;
                count += 1;
            }
            try expect_proves(size, positions[0..count]);
        }
    }
}

test "multi-proof on the empty tree and with no positions" {
    var empty = try build(&.{});
    defer empty.deinit(gpa);
    var diagnostic: bmt.Diagnostic = .{};
    try testing.expectError(error.NoLeaves, empty.multi_proof(gpa, &.{}, null));
    try testing.expectError(error.InvalidPosition, empty.multi_proof(gpa, &.{0}, &diagnostic));
    try testing.expectEqual(@as(u32, 0), diagnostic.position);

    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    try testing.expectError(error.NoLeaves, tree.multi_proof(gpa, &.{}, null));
}

const Case = struct {
    positions: []const u32,
    err: bmt.Error,
    position: u32 = 0,
};

test "multi-proof and verification report the first invalid position" {
    const digests = try sequence(4);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();
    var proof = try tree.multi_proof(gpa, &.{ 0, 3 }, null);
    defer proof.deinit(gpa);

    const cases = [_]Case{
        .{ .positions = &.{}, .err = error.NoLeaves },
        .{ .positions = &.{ 0, 0, 4 }, .err = error.DuplicatePosition, .position = 0 },
        .{ .positions = &.{ 4, 0, 0 }, .err = error.InvalidPosition, .position = 4 },
        .{ .positions = &.{ 3, 4 }, .err = error.InvalidPosition, .position = 4 },
        .{ .positions = &.{ 3, 1, 1, 3 }, .err = error.UnsortedPosition, .position = 1 },
        .{ .positions = &.{ 1, 3, 3, 1 }, .err = error.DuplicatePosition, .position = 3 },
        .{ .positions = &.{ 0, 1, 2, 3, 0, 4 }, .err = error.UnsortedPosition, .position = 0 },
        .{ .positions = &.{ 0, 1, 2, 3, 4, 0 }, .err = error.InvalidPosition, .position = 4 },
        // The first repeat or descent of an endless input stops the read.
        .{ .positions = &.{ 2, 2, 2, 2 }, .err = error.DuplicatePosition, .position = 2 },
        .{ .positions = &.{ 0, 1, 2, 0, 1, 2 }, .err = error.UnsortedPosition, .position = 0 },
    };
    for (cases) |case| {
        var diagnostic: bmt.Diagnostic = .{ .position = 77 };
        try testing.expectError(case.err, tree.multi_proof(gpa, case.positions, &diagnostic));
        if (case.err != error.NoLeaves) try testing.expectEqual(case.position, diagnostic.position);

        const elements = try gpa.alloc(Element, case.positions.len);
        defer gpa.free(elements);
        for (case.positions, elements) |p, *e| e.* = .{ .position = p, .digest = digests[0] };
        diagnostic = .{ .position = 77 };
        try testing.expectError(
            case.err,
            proof.verify_multi_inclusion(Sha256, gpa, elements, &root, &diagnostic),
        );
        if (case.err != error.NoLeaves) try testing.expectEqual(case.position, diagnostic.position);
    }
}

test "multi-proof duplicate, unsorted, and out-of-range positions" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();
    var diagnostic: bmt.Diagnostic = .{};

    try testing.expectError(
        error.DuplicatePosition,
        tree.multi_proof(gpa, &.{ 1, 1 }, &diagnostic),
    );
    try testing.expectEqual(@as(u32, 1), diagnostic.position);
    try testing.expectError(
        error.DuplicatePosition,
        tree.multi_proof(gpa, &.{ 0, 2, 2, 5 }, &diagnostic),
    );
    try testing.expectEqual(@as(u32, 2), diagnostic.position);
    try testing.expectError(
        error.UnsortedPosition,
        tree.multi_proof(gpa, &.{ 5, 0, 3 }, &diagnostic),
    );
    try testing.expectEqual(@as(u32, 0), diagnostic.position);
    try testing.expectError(error.InvalidPosition, tree.multi_proof(gpa, &.{ 0, 8 }, &diagnostic));
    try testing.expectEqual(@as(u32, 8), diagnostic.position);
    try testing.expectError(error.InvalidPosition, tree.multi_proof(gpa, &.{100}, &diagnostic));
    try testing.expectEqual(@as(u32, 100), diagnostic.position);

    var proof = try tree.multi_proof(gpa, &.{ 0, 3, 5 }, null);
    defer proof.deinit(gpa);
    const unsorted = try elements_at(digests, &.{ 5, 0, 3 });
    defer gpa.free(unsorted);
    try testing.expectError(error.UnsortedPosition, verify(&proof, unsorted, &root));
    const sorted = try elements_at(digests, &.{ 0, 3, 5 });
    defer gpa.free(sorted);
    try verify(&proof, sorted, &root);

    var pair = try tree.multi_proof(gpa, &.{ 0, 3 }, null);
    defer pair.deinit(gpa);
    const invalid = [_]Element{
        .{ .position = 0, .digest = digests[0] },
        .{ .position = 100, .digest = digests[3] },
    };
    try testing.expectError(error.InvalidPosition, verify(&pair, &invalid, &root));
    try testing.expectError(error.InvalidPosition, verify(&pair, invalid[1..], &root));
}

test "multi-proof rejects wrong elements, positions, root, and tampering" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();

    var proof = try tree.multi_proof(gpa, &.{ 0, 3, 5 }, null);
    defer proof.deinit(gpa);
    const elements = try elements_at(digests, &.{ 0, 3, 5 });
    defer gpa.free(elements);
    var wrong = try gpa.dupe(Element, elements);
    defer gpa.free(wrong);
    wrong[0].digest = hash_bytes("wrong1");
    try testing.expect(fails(&proof, wrong, &root));
    wrong[0] = .{ .position = 1, .digest = digests[0] };
    try testing.expect(fails(&proof, wrong, &root));
    try testing.expect(fails(&proof, elements, &hash_bytes("wrong_root")));

    var sparse = try tree.multi_proof(gpa, &.{ 0, 5 }, null);
    defer sparse.deinit(gpa);
    const pair = try elements_at(digests, &.{ 0, 5 });
    defer gpa.free(pair);
    try testing.expect(sparse.siblings.len >= 2);
    var modified = try sparse.clone(gpa);
    defer modified.deinit(gpa);
    modified.siblings[0] = hash_bytes("tampered");
    try testing.expect(fails(&modified, pair, &root));
    // Swapped siblings.
    modified.siblings[1] = sparse.siblings[0];
    modified.siblings[0] = sparse.siblings[1];
    try testing.expect(fails(&modified, pair, &root));

    const extended = try gpa.alloc(Digest, sparse.siblings.len + 1);
    defer gpa.free(extended);
    @memcpy(extended[0..sparse.siblings.len], sparse.siblings);
    extended[sparse.siblings.len] = hash_bytes("extra");
    try testing.expect(fails(&.{ .leaf_count = 8, .siblings = extended }, pair, &root));
    const shorter = sparse.siblings[0 .. sparse.siblings.len - 1];
    const missing: Proof = .{ .leaf_count = 8, .siblings = shorter };
    try testing.expect(fails(&missing, pair, &root));
}

test "multi-proof deduplicates shared siblings" {
    const digests = try sequence(16);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const positions = [_]u32{ 0, 1, 8, 9 };
    var individual: usize = 0;
    for (positions) |position| {
        var proof = try tree.proof(gpa, position, null);
        defer proof.deinit(gpa);
        individual += proof.siblings.len;
    }
    var multi = try tree.multi_proof(gpa, &positions, null);
    defer multi.deinit(gpa);
    try testing.expect(multi.siblings.len < individual);
}

test "multi-proof serialization" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const positions = [_]u32{ 0, 3, 5 };
    var proof = try tree.multi_proof(gpa, &positions, null);
    defer proof.deinit(gpa);

    const encoded = try codec.encode(Proof, gpa, proof);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(Proof, gpa, encoded, positions.len);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&proof));
    const elements = try elements_at(digests, &positions);
    defer gpa.free(elements);
    try verify(&decoded, elements, &tree.root());

    try testing.expectError(
        error.EndOfBuffer,
        codec.decode_cfg(Proof, gpa, encoded[0 .. encoded.len - 1], positions.len),
    );
    const extended = try gpa.alloc(u8, encoded.len + 1);
    defer gpa.free(extended);
    @memcpy(extended[0..encoded.len], encoded);
    extended[encoded.len] = 0;
    try testing.expectError(error.ExtraData, codec.decode_cfg(Proof, gpa, extended, positions.len));

    // A leaf count and a claim of one sibling with no sibling bytes.
    const short = [_]u8{ 0, 0, 0, 8, 1 };
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(Proof, gpa, &short, 1));
}

test "multi-proof verification with no elements" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    var proof = try tree.multi_proof(gpa, &.{ 0, 3 }, null);
    defer proof.deinit(gpa);
    try testing.expectError(error.NoLeaves, verify(&proof, &.{}, &tree.root()));

    // The default proof verifies no elements against the empty tree only.
    var empty = try build(&.{});
    defer empty.deinit(gpa);
    try verify(&.{}, &.{}, &empty.root());
    try testing.expectError(error.InvalidProof, verify(&.{}, &.{}, &hash_bytes("not_empty")));
}

test "multi-proof of a single-leaf tree" {
    const digest = hash_bytes("only_leaf");
    var tree = try build(&.{digest});
    defer tree.deinit(gpa);
    const root = tree.root();
    var proof = try tree.multi_proof(gpa, &.{0}, null);
    defer proof.deinit(gpa);
    try testing.expectEqual(@as(u32, 1), proof.leaf_count);
    try testing.expectEqual(@as(usize, 0), proof.siblings.len);
    try verify(&proof, &.{.{ .position = 0, .digest = digest }}, &root);
    try testing.expect(fails(&proof, &.{.{ .position = 0, .digest = hash_bytes("wrong") }}, &root));
    try testing.expect(fails(&proof, &.{.{ .position = 1, .digest = digest }}, &root));
}

test "multi-proof rejects forged leaf counts and element counts" {
    const digests = try sequence(8);
    defer gpa.free(digests);
    var tree = try build(digests);
    defer tree.deinit(gpa);
    const root = tree.root();
    var proof = try tree.multi_proof(gpa, &.{ 0, 3 }, null);
    defer proof.deinit(gpa);
    const elements = try elements_at(digests, &.{ 0, 3 });
    defer gpa.free(elements);

    for ([_]u32{ 0, 4, 1000, std.math.maxInt(u32) }) |leaf_count| {
        const forged: Proof = .{ .leaf_count = leaf_count, .siblings = proof.siblings };
        try testing.expect(fails(&forged, elements, &root));
    }
    try testing.expect(fails(&proof, elements[0..1], &root));
    const too_many = try elements_at(digests, &.{ 0, 3, 5 });
    defer gpa.free(too_many);
    try testing.expect(fails(&proof, too_many, &root));

    // A huge leaf count must fail without allocating in proportion to it.
    const four = try sequence(4);
    defer gpa.free(four);
    var small = try build(four);
    defer small.deinit(gpa);
    var small_proof = try small.multi_proof(gpa, &.{ 0, 2 }, null);
    defer small_proof.deinit(gpa);
    const small_elements = try elements_at(four, &.{ 0, 2 });
    defer gpa.free(small_elements);
    const huge: Proof = .{ .leaf_count = std.math.maxInt(u32), .siblings = small_proof.siblings };
    try testing.expect(fails(&huge, small_elements, &small.root()));
}
