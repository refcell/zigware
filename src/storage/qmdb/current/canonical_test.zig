//! Tests for current's canonical-root helpers: commonware's `qmdb/current/db.rs` tests of
//! `partial_chunk` and `combine_roots`, plus checks of the pending-chunk window, the sync
//! boundary, and the rebuilt grafted tree against a direct recomputation.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const grafting = @import("grafting.zig");
const canonical = @import("canonical.zig");
const proof = @import("proof.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;
const N = 32;
const Bits = utils.bitmap.Prunable(N);

fn hash(data: []const u8) D {
    return Sha256.hash(&.{data});
}

test "partial chunk" {
    var bits: Bits = .empty;
    defer bits.deinit(gpa);
    try testing.expect(canonical.partial_chunk(N, &bits) == null); // Empty.
    try bits.push(gpa, true);
    const single = canonical.partial_chunk(N, &bits).?;
    try testing.expectEqual(@as(u64, 1), single[1]);
    try testing.expectEqual(@as(u8, 1), single[0][0]);
    for (1..Bits.CHUNK_SIZE_BITS) |_| try bits.push(gpa, true);
    try testing.expect(canonical.partial_chunk(N, &bits) == null); // Aligned.
    for (0..5) |_| try bits.push(gpa, true);
    try testing.expectEqual(@as(u64, 5), canonical.partial_chunk(N, &bits).?[1]);
    // A fully pruned bitmap is aligned with an empty backing store.
    var pruned = try Bits.init_pruned(1);
    defer pruned.deinit(gpa);
    try testing.expect(canonical.partial_chunk(N, &pruned) == null);
}

test "combine roots format golden" {
    const ops = hash("ops");
    const grafted = hash("grafted");
    const pending = hash("pending");
    const partial_digest = hash("partial");
    const next_bit: u64 = 0x1122_3344_5566_7788;
    var bit_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bit_bytes, next_bit, .big);
    const partial: proof.PartialChunk(D) = .{ .next_bit = next_bit, .digest = partial_digest };
    const o = ops.as_slice();
    const g = grafted.as_slice();
    const pe = pending.as_slice();
    const pa = partial_digest.as_slice();
    const none = proof.combine_roots(Sha256, &ops, &grafted, null, null);
    try testing.expect(none.eql(Sha256.hash(&.{ o, g })));
    const only_pending = proof.combine_roots(Sha256, &ops, &grafted, &pending, null);
    try testing.expect(only_pending.eql(Sha256.hash(&.{ o, g, pe })));
    const only_partial = proof.combine_roots(Sha256, &ops, &grafted, null, partial);
    try testing.expect(only_partial.eql(Sha256.hash(&.{ o, g, &bit_bytes, pa })));
    // Pending precedes partial.
    const both = proof.combine_roots(Sha256, &ops, &grafted, &pending, partial);
    try testing.expect(both.eql(Sha256.hash(&.{ o, g, pe, &bit_bytes, pa })));
    try testing.expect(!only_pending.eql(only_partial) and !both.eql(only_pending));
    const other = hash("ops_b");
    try testing.expect(!none.eql(proof.combine_roots(Sha256, &other, &grafted, null, null)));
}

test "graftable chunk window refuses corrupt states" {
    const height = grafting.height(N);
    const chunk_bits: u64 = N * 8;
    // MMR: every complete chunk is graftable.
    const window = canonical.graftable_chunk_window;
    try testing.expectEqual(@as(u64, 2), try window(Mmr, 2 * chunk_bits, 2, 0, height));
    // Two pending chunks, or pruning past the graftable chunks, are corrupt.
    try testing.expectError(error.DataCorrupted, window(Mmr, chunk_bits, 3, 0, height));
    try testing.expectError(error.DataCorrupted, window(Mmr, chunk_bits, 1, 2, height));
}

test "sync boundary never exceeds the floor and settles for mmr" {
    const chunk_bits: u64 = N * 8;
    for (0..6) |floor_usize| {
        const floor_chunks: u64 = floor_usize;
        const mmr_boundary = canonical.sync_boundary(Mmr, N, floor_chunks, 8 * chunk_bits);
        // An MMR chunk's root is born when the chunk completes.
        try testing.expectEqual(floor_chunks * chunk_bits, mmr_boundary);
        const mmb_boundary = canonical.sync_boundary(Mmb, N, floor_chunks, 8 * chunk_bits);
        try testing.expect(mmb_boundary <= floor_chunks * chunk_bits);
        try testing.expect(mmb_boundary % chunk_bits == 0);
    }
    try testing.expectEqual(@as(u64, 0), canonical.sync_boundary(Mmb, N, 3, 0));
}

/// An ops tree of `leaves` elements and a bitmap with every third bit set.
fn Fixture(comptime F: type) type {
    return struct {
        const Self = @This();
        ops: merkle.mem.Mem(F, D) = .empty,
        bits: Bits = .empty,

        fn init(leaves: u64) !Self {
            var self: Self = .{};
            errdefer self.deinit();
            const hasher = qmdb.hasher(Sha256);
            for (0..leaves) |i| {
                var element: [8]u8 = undefined;
                std.mem.writeInt(u64, &element, i, .big);
                try self.ops.add(gpa, &hasher, &element);
                try self.bits.push(gpa, i % 3 == 0);
            }
            return self;
        }

        fn deinit(self: *Self) void {
            self.ops.deinit(gpa);
            self.bits.deinit(gpa);
        }
    };
}

/// The grafted root recomputed without the grafted tree: the ops tree's peaks, with each
/// graftable chunk's height-`G` node replaced by its grafted leaf, re-hashed in grafted space.
fn check_rebuild(comptime F: type, leaves: u64) !void {
    var fixture = try Fixture(F).init(leaves);
    defer fixture.deinit();
    const bits = &fixture.bits;
    const ops = &fixture.ops;
    const build = canonical.build_grafted_tree;
    var tree, var roots = try build(F, Sha256, N, gpa, bits, &.{}, ops, leaves);
    defer tree.deinit(gpa);
    defer roots.deinit(gpa);
    const height = grafting.height(N);
    const complete: u64 = fixture.bits.complete_chunks();
    const graftable = @min(grafting.graftable_chunks(F, leaves, height), complete);
    try testing.expectEqual(graftable, tree.leaves());
    try testing.expectEqual(graftable, roots.end());
    // Each grafted leaf is its chunk grafted onto the ops root covering it.
    for (0..graftable) |chunk| {
        const position = canonical.graft_root_position(F, N, chunk);
        const ops_root = fixture.ops.get_node(position).?;
        try testing.expect(ops_root.eql(roots.get(chunk).?));
        const bytes = fixture.bits.get_chunk(chunk);
        const leaf = grafting.grafted_leaf_digest(Sha256, &bytes, ops_root);
        const grafted_pos = grafting.ops_to_grafted_pos(F, position, height);
        try testing.expect(leaf.eql(tree.get_node(grafted_pos).?));
    }
    // Grafted internal nodes hash at their ops-space positions.
    const hasher = grafting.GraftedHasher(F, Sha256).init(height);
    var position: u64 = 0;
    while (position < tree.size()) : (position += 1) {
        const node_height = F.pos_to_height(position);
        if (node_height == 0) continue;
        const children = F.children(position, node_height);
        const left = tree.get_node(children.left).?;
        const right = tree.get_node(children.right).?;
        const expected = hasher.node_digest(position, &left, &right);
        try testing.expect(expected.eql(tree.get_node(position).?));
    }
}

test "rebuilt grafted tree matches a direct recomputation" {
    const chunk_bits: u64 = N * 8;
    const sizes = [_]u64{
        0, chunk_bits - 1, chunk_bits, chunk_bits + 7, 3 * chunk_bits, 4 * chunk_bits + 9,
    };
    for (sizes) |leaves| {
        try check_rebuild(Mmr, leaves);
        try check_rebuild(Mmb, leaves);
    }
}

test "graft roots release and lookup" {
    const R = canonical.GraftRoots(D);
    var roots: R = .{ .start = 0 };
    defer roots.deinit(gpa);
    for (0..10) |i| try roots.roots.append(gpa, D.fill(@intCast(i)));
    try testing.expectEqual(@as(u64, 10), roots.end());
    // A floor inside chunk 3 releases chunks 0..3 only.
    roots.release_below_floor(N, 3 * N * 8 + 5);
    try testing.expectEqual(@as(u64, 3), roots.start);
    try testing.expect(roots.get(2) == null);
    try testing.expect(roots.get(3).?.eql(D.fill(3)));
    roots.release_below_floor(N, 8 * N * 8);
    try testing.expect(roots.get(9).?.eql(D.fill(9)));
    try testing.expectEqual(@as(u64, 10), roots.end());
    // Releasing past the end stops at the end.
    roots.release_below_floor(N, 100 * N * 8);
    try testing.expectEqual(@as(u64, 10), roots.start);
    try testing.expectEqual(@as(u64, 10), roots.end());
}
