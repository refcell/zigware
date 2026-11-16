//! Grafting bitmap chunks onto an operations tree (commonware's `qmdb/current/grafting.rs`).
//!
//! Each graftable chunk of the activity bitmap is hashed with the root of the ops subtree it
//! covers into a grafted leaf (`hash(chunk || ops_subtree_root)`, or the subtree root itself
//! for an all-zero chunk). Grafted leaves and their ancestors form a grafted tree whose
//! positions map to ops-space positions for hashing. A chunk is graftable once its height-`G`
//! ancestor exists as one ops node: in MMR at once, in MMB after a delayed merge, so MMB has
//! at most one complete but pending chunk.
//!
//! Three coordinate spaces: chunk indices, ops positions, and grafted positions (a tree over
//! chunk indices). The grafted storage view lands with current's database.

const std = @import("std");
const assert = std.debug.assert;
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");

/// The grafting height of a bitmap with `chunk_size` bytes per chunk: `log2(chunk_size * 8)`.
pub fn height(comptime chunk_size: usize) u32 {
    comptime assert(chunk_size > 0 and std.math.isPowerOfTwo(chunk_size));
    const result: u32 = @ctz(@as(u64, chunk_size) * 8);
    comptime assert(result >= 3);
    return result;
}

/// The size at which the peak at `position` and `peak_height` is born (commonware's
/// `Graftable::peak_birth_size`).
pub fn peak_birth_size(comptime F: type, position: u64, peak_height: u32) u64 {
    const leftmost = F.leftmost_leaf(position, peak_height);
    const result = std.math.add(u64, leftmost, F.birth_offset(peak_height)) catch
        @panic("birth size overflow");
    assert(result >= leftmost);
    return result;
}

/// The number of bitmap chunks with a height-`grafting_height` ancestor in the ops tree: every
/// complete chunk for MMR, and all but at most one for MMB.
pub fn graftable_chunks(comptime F: type, ops_leaves: u64, grafting_height: u32) u64 {
    merkle.check_family(F);
    assert(grafting_height >= 1);
    const position = F.subtree_root_position(0, grafting_height);
    const birth_chunk_0 = peak_birth_size(F, position, grafting_height);
    if (ops_leaves < birth_chunk_0) return 0;
    const chunk_size = @as(u64, 1) << @intCast(grafting_height);
    const result = (ops_leaves - birth_chunk_0) / chunk_size + 1;
    assert(result <= ops_leaves / chunk_size);
    return result;
}

/// The grafted leaf of `chunk` over the ops subtree root it covers: the root itself for an
/// all-zero chunk (the zero-chunk identity), else `hash(chunk || ops_subtree_root)`.
pub fn grafted_leaf_digest(
    comptime H: type,
    chunk: []const u8,
    ops_subtree_root: H.Digest,
) H.Digest {
    assert(chunk.len > 0);
    for (chunk) |byte| {
        if (byte != 0) return H.hash(&.{ chunk, ops_subtree_root.as_slice() });
    }
    return ops_subtree_root;
}

/// The number of root peaks whose leaves end at or before `inactivity_floor`, rounded down to
/// the last boundary that is both a peak boundary and a whole chunk.
pub fn chunk_aligned_inactive_peaks(
    comptime F: type,
    leaves: u64,
    inactivity_floor: u64,
    grafting_height: u32,
) merkle.Error!usize {
    const size = try merkle.position_from_location(F, leaves);
    const chunk_size = @as(u64, 1) << @intCast(grafting_height);
    var leaf_end: u64 = 0;
    var aligned: usize = 0;
    var peaks = F.peaks(size);
    var index: usize = 0;
    while (peaks.next()) |peak| : (index += 1) {
        const next_end = leaf_end + (@as(u64, 1) << @intCast(peak.height));
        if (next_end > inactivity_floor) break;
        leaf_end = next_end;
        if (leaf_end % chunk_size == 0) aligned = index + 1;
    }
    assert(aligned <= index);
    return aligned;
}

/// The grafted position of an ops position at or above the grafting height: the ops node at
/// height `h` maps to the grafted node at height `h - grafting_height` over the same leaves.
pub fn ops_to_grafted_pos(comptime F: type, ops_pos: u64, grafting_height: u32) u64 {
    const ops_height = F.pos_to_height(ops_pos);
    assert(ops_height >= grafting_height);
    const grafted_height = ops_height - grafting_height;
    const ops_leaf = F.leftmost_leaf(ops_pos, ops_height);
    const chunk_index = ops_leaf >> @intCast(grafting_height);
    const result = F.subtree_root_position(chunk_index, grafted_height);
    assert(F.pos_to_height(result) == grafted_height);
    return result;
}

/// The ops position whose subtree covers the same ops leaves as `grafted_pos`.
pub fn grafted_to_ops_pos(comptime F: type, grafted_pos: u64, grafting_height: u32) u64 {
    const grafted_height = F.pos_to_height(grafted_pos);
    const grafted_leaf = F.leftmost_leaf(grafted_pos, grafted_height);
    const ops_leaf = grafted_leaf << @intCast(grafting_height);
    assert(ops_leaf >> @intCast(grafting_height) == grafted_leaf);
    const result = F.subtree_root_position(ops_leaf, grafted_height + grafting_height);
    assert(F.pos_to_height(result) == grafted_height + grafting_height);
    return result;
}

/// QMDB's Merkle hasher over grafted positions: node pre-images use the ops-space position
/// covering the same leaves, so grafted and ops nodes stay domain-separated.
pub fn GraftedHasher(comptime F: type, comptime H: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        const Standard = merkle.hasher.Standard(H);
        pub const Digest = H.Digest;
        pub const NodeInput = Standard.NodeInput;

        inner: Standard,
        grafting_height: u32,

        pub fn init(grafting_height: u32) Self {
            assert(grafting_height >= 1);
            return .{ .inner = qmdb.hasher(H), .grafting_height = grafting_height };
        }

        pub fn hash(self: *const Self, parts: []const []const u8) Digest {
            return self.inner.hash(parts);
        }

        pub fn root_bagging(self: *const Self) merkle.Bagging {
            return self.inner.root_bagging();
        }

        pub fn leaf_digest(self: *const Self, position: u64, element: []const u8) Digest {
            return self.inner.leaf_digest(position, element);
        }

        pub fn fold(self: *const Self, accumulator: *const Digest, peak: *const Digest) Digest {
            return self.inner.fold(accumulator, peak);
        }

        pub fn node_digest(
            self: *const Self,
            position: u64,
            left: *const Digest,
            right: *const Digest,
        ) Digest {
            const ops_pos = grafted_to_ops_pos(F, position, self.grafting_height);
            assert(ops_pos >= position);
            return self.inner.node_digest(ops_pos, left, right);
        }

        pub fn node_digest_pair(self: *const Self, nodes: [2]NodeInput) [2]Digest {
            var mapped = nodes;
            for (&mapped) |*node| {
                node.position = grafted_to_ops_pos(F, node.position, self.grafting_height);
            }
            assert(mapped[0].position >= nodes[0].position);
            return self.inner.node_digest_pair(mapped);
        }
    };
}

/// QMDB's Merkle hasher for verifying proofs over a grafted tree, in ops space. Nodes below or
/// above the grafting height hash normally; a node at the grafting height is an ops subtree
/// root that is grafted with its chunk when the chunk is graftable and supplied (`chunks[0]`
/// is chunk `start_chunk_index`). Chunks at or past `graftable_chunks` are pending and not
/// grafted. Borrows `chunks`.
pub fn Verifier(comptime F: type, comptime H: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        const Standard = merkle.hasher.Standard(H);
        pub const Digest = H.Digest;
        pub const NodeInput = Standard.NodeInput;

        inner: Standard,
        grafting_height: u32,
        chunks: []const []const u8,
        start_chunk_index: u64,
        graftable_chunks: u64,

        pub fn init(
            grafting_height: u32,
            start_chunk_index: u64,
            chunks: []const []const u8,
            graftable: u64,
        ) Self {
            assert(grafting_height >= 1);
            return .{
                .inner = qmdb.hasher(H),
                .grafting_height = grafting_height,
                .chunks = chunks,
                .start_chunk_index = start_chunk_index,
                .graftable_chunks = graftable,
            };
        }

        pub fn hash(self: *const Self, parts: []const []const u8) Digest {
            return self.inner.hash(parts);
        }

        pub fn root_bagging(self: *const Self) merkle.Bagging {
            return self.inner.root_bagging();
        }

        pub fn leaf_digest(self: *const Self, position: u64, element: []const u8) Digest {
            return self.inner.leaf_digest(position, element);
        }

        pub fn fold(self: *const Self, accumulator: *const Digest, peak: *const Digest) Digest {
            return self.inner.fold(accumulator, peak);
        }

        pub fn node_digest(
            self: *const Self,
            position: u64,
            left: *const Digest,
            right: *const Digest,
        ) Digest {
            const node_height = F.pos_to_height(position);
            const digest = self.inner.node_digest(position, left, right);
            if (node_height != self.grafting_height) return digest;
            const leaf = F.leftmost_leaf(position, self.grafting_height);
            const chunk_index = leaf >> @intCast(self.grafting_height);
            // A pending chunk enters the root through the pending-chunk digest instead.
            if (chunk_index >= self.graftable_chunks) return digest;
            if (chunk_index < self.start_chunk_index) return digest;
            const local = chunk_index - self.start_chunk_index;
            if (local >= self.chunks.len) return digest;
            return grafted_leaf_digest(H, self.chunks[@intCast(local)], digest);
        }

        pub fn node_digest_pair(self: *const Self, nodes: [2]NodeInput) [2]Digest {
            assert(nodes.len == 2);
            return .{
                self.node_digest(nodes[0].position, nodes[0].left, nodes[0].right),
                self.node_digest(nodes[1].position, nodes[1].left, nodes[1].right),
            };
        }
    };
}
