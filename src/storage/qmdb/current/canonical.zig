//! The canonical `current` root (commonware's root helpers in `qmdb/current/db.rs`).
//!
//! A canonical root commits to the ops root, the grafted root (the ops tree with every
//! graftable bitmap chunk grafted onto its height-`G` node), the pending chunk (MMB only: the
//! one complete chunk whose height-`G` ancestor is not born yet), and the trailing partial
//! chunk. These helpers compute the grafted root and witness, rebuild the grafted tree from
//! the bitmap and the ops tree, track the retained graft roots, and derive the sync boundary.
//!
//! A bitmap argument provides `len()`, `complete_chunks()`, `pruned_chunks()`,
//! `get_chunk(index)`, and `last_chunk()` (as `utils.bitmap.Prunable(N)` does).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const merkle = @import("../../merkle/mod.zig");
const merkle_storage = @import("../../merkle/storage.zig");
const qmdb = @import("../mod.zig");
const grafting = @import("grafting.zig");
const proof = @import("proof.zig");

/// The position of the ops root covering bitmap chunk `chunk` at grafting height `G`.
pub fn graft_root_position(comptime F: type, comptime chunk_size: usize, chunk: u64) u64 {
    const height = grafting.height(chunk_size);
    const result = F.subtree_root_position(chunk << @intCast(height), height);
    assert(F.pos_to_height(result) == height);
    return result;
}

/// The graftable chunk count, refusing more than one pending chunk or pruning past the
/// graftable chunks (`DataCorrupted`).
pub fn graftable_chunk_window(
    comptime F: type,
    ops_leaves: u64,
    complete: u64,
    pruned: u64,
    grafting_height: u32,
) qmdb.Error!u64 {
    const graftable = @min(grafting.graftable_chunks(F, ops_leaves, grafting_height), complete);
    assert(graftable <= complete);
    if (complete - graftable > 1) return error.DataCorrupted; // Multiple pending chunks.
    if (pruned > graftable) return error.DataCorrupted; // Pruned past the graftable chunks.
    return graftable;
}

/// The pending chunk's bytes, if the bitmap has one: complete, but its height-`G` ancestor is
/// not born at `ops_leaves`. `ops_leaves` and `bitmap` must be one consistent snapshot.
pub fn pending_chunk(
    comptime F: type,
    comptime chunk_size: usize,
    bitmap: anytype,
    ops_leaves: u64,
) qmdb.Error!?[chunk_size]u8 {
    const complete: u64 = bitmap.complete_chunks();
    const pruned: u64 = bitmap.pruned_chunks();
    const height = grafting.height(chunk_size);
    const graftable = try graftable_chunk_window(F, ops_leaves, complete, pruned, height);
    if (complete - graftable != 1) return null;
    assert(!grafting_has_no_pending(F) or complete == graftable);
    return bitmap.get_chunk(@intCast(graftable));
}

fn grafting_has_no_pending(comptime F: type) bool {
    return F == merkle.mmr.Family;
}

/// The trailing partial chunk and its bit count, if the bitmap does not end on a chunk
/// boundary.
pub fn partial_chunk(comptime chunk_size: usize, bitmap: anytype) ?struct { [chunk_size]u8, u64 } {
    const chunk_bits: u64 = chunk_size * 8;
    const next_bit = bitmap.len() % chunk_bits;
    if (next_bit == 0) return null;
    const last, const bits = bitmap.last_chunk();
    assert(bits == next_bit);
    return .{ last, next_bit };
}

/// For the youngest of `chunk_count` chunks, the birth size of its chunk-pair parent at height
/// `G + 1`, or null for a family without delayed merges.
pub fn pair_absorption_threshold(
    comptime F: type,
    comptime chunk_size: usize,
    chunk_count: u64,
) ?u64 {
    if (chunk_count == 0) return null;
    const height = grafting.height(chunk_size);
    const youngest = chunk_count - 1;
    const youngest_start = youngest << @intCast(height);
    const youngest_end = (youngest + 1) << @intCast(height);
    const youngest_pos = F.subtree_root_position(youngest_start, height);
    if (grafting.peak_birth_size(F, youngest_pos, height) <= youngest_end) return null;
    const pair_start = (youngest & ~@as(u64, 1)) << @intCast(height);
    const pair_pos = F.subtree_root_position(pair_start, height + 1);
    const result = grafting.peak_birth_size(F, pair_pos, height + 1);
    assert(result > youngest_end);
    return result;
}

/// The safe sync and prune boundary: the most chunks below the floor whose grafted state the
/// ops tree at `ops_leaves` has settled, as a location (a chunk multiple).
pub fn sync_boundary(
    comptime F: type,
    comptime chunk_size: usize,
    floor_chunks_start: u64,
    ops_leaves: u64,
) u64 {
    const chunk_bits: u64 = chunk_size * 8;
    const height = grafting.height(chunk_size);
    var floor_chunks = floor_chunks_start;
    while (floor_chunks > 0) : (floor_chunks -= 1) {
        const required = pair_absorption_threshold(F, chunk_size, floor_chunks) orelse required: {
            const youngest_start = (floor_chunks - 1) * chunk_bits;
            const position = F.subtree_root_position(youngest_start, height);
            break :required grafting.peak_birth_size(F, position, height);
        };
        if (ops_leaves >= required) break;
    }
    assert(floor_chunks <= floor_chunks_start);
    return floor_chunks * chunk_bits;
}

/// The ops roots at the grafting height of the graftable chunks not wholly below the
/// inactivity floor, densely from chunk `start`. The ops tree only appends, so a retained root
/// never changes; merkleization re-grafts dirty chunks from them.
pub fn GraftRoots(comptime D: type) type {
    return struct {
        const Self = @This();

        /// The chunk of `roots.items[head]`.
        start: u64 = 0,
        roots: std.ArrayList(D) = .empty,
        /// Released roots at the front of `roots`, compacted away lazily.
        head: usize = 0,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.roots.deinit(gpa);
            self.* = undefined;
        }

        /// One past the last retained chunk.
        pub fn end(self: *const Self) u64 {
            assert(self.head <= self.roots.items.len);
            return self.start + (self.roots.items.len - self.head);
        }

        pub fn get(self: *const Self, chunk: u64) ?D {
            if (chunk < self.start or chunk >= self.end()) return null;
            return self.roots.items[self.head + @as(usize, @intCast(chunk - self.start))];
        }

        /// The retained root of `chunk`, or else the root `ops_tree` holds for a chunk not yet
        /// grafted (`ElementPruned` if it lacks it). `chunk` is never below the retained ones.
        pub fn get_or_read(
            self: *const Self,
            comptime F: type,
            comptime chunk_size: usize,
            chunk: u64,
            ops_tree: anytype,
        ) !D {
            if (self.get(chunk)) |digest| return digest;
            assert(chunk >= self.end()); // Released chunks lie wholly below the floor.
            const position = graft_root_position(F, chunk_size, chunk);
            return (try merkle_storage.get_node(ops_tree, position)) orelse error.ElementPruned;
        }

        /// Retains the roots of chunks `end()..leaves` read from `ops_tree`, which holds them.
        pub fn extend_to(
            self: *Self,
            gpa: Allocator,
            comptime F: type,
            comptime chunk_size: usize,
            leaves: u64,
            ops_tree: anytype,
        ) !void {
            var chunk = self.end();
            try self.roots.ensureUnusedCapacity(gpa, @intCast(leaves -| chunk));
            while (chunk < leaves) : (chunk += 1) {
                const position = graft_root_position(F, chunk_size, chunk);
                const digest = (try merkle_storage.get_node(ops_tree, position)) orelse
                    return error.ElementPruned;
                self.roots.appendAssumeCapacity(digest);
            }
            assert(self.end() >= leaves or self.end() == chunk);
        }

        /// Releases the roots of chunks wholly below `floor`: no batch can dirty them.
        pub fn release_below_floor(self: *Self, comptime chunk_size: usize, floor: u64) void {
            const chunk_bits: u64 = chunk_size * 8;
            const chunk = @min(floor / chunk_bits, self.end());
            if (chunk <= self.start) return;
            self.head += @intCast(chunk - self.start);
            self.start = chunk;
            // Compact once the released prefix outweighs the retained roots.
            if (self.head > self.roots.items.len / 2) {
                const live = self.roots.items[self.head..];
                std.mem.copyForwards(D, self.roots.items[0..live.len], live);
                self.roots.shrinkRetainingCapacity(live.len);
                self.head = 0;
            }
            assert(self.start == chunk);
        }
    };
}

/// The root of the grafted structure `storage` presents: its peaks bagged with the
/// chunk-aligned inactive peaks. Only graftable chunks are in it; the pending chunk enters the
/// canonical root through the witness.
pub fn compute_grafted_root(
    comptime F: type,
    comptime H: type,
    comptime chunk_size: usize,
    bitmap: anytype,
    storage: anytype,
    ops_leaves: u64,
    inactivity_floor: u64,
) !H.Digest {
    const size = storage.size();
    const leaves = F.position_to_location(size) orelse return error.InvalidSize;
    var peaks: [merkle.max_pinned_nodes]H.Digest = undefined;
    var count: usize = 0;
    var iterator = F.peaks(size);
    while (iterator.next()) |peak| : (count += 1) {
        peaks[count] = (try merkle_storage.get_node(storage, peak.position)) orelse
            return error.MissingNode;
    }
    const height = grafting.height(chunk_size);
    _ = try graftable_chunk_window(
        F,
        ops_leaves,
        bitmap.complete_chunks(),
        bitmap.pruned_chunks(),
        height,
    );
    const inactive = try grafting.chunk_aligned_inactive_peaks(F, leaves, inactivity_floor, height);
    const hasher = qmdb.hasher(H);
    assert(inactive <= count);
    return merkle.hasher.root(F, &hasher, leaves, inactive, peaks[0..count]);
}

/// The witness binding an ops root to the canonical root: the grafted root, the pending chunk
/// digest, and the partial chunk. `bitmap` and `ops_leaves` are one consistent snapshot.
pub fn compute_ops_root_witness(
    comptime F: type,
    comptime H: type,
    comptime chunk_size: usize,
    bitmap: anytype,
    storage: anytype,
    ops_leaves: u64,
    inactivity_floor: u64,
) !proof.OpsRootWitness(F, H.Digest) {
    const grafted_root = try compute_grafted_root(
        F,
        H,
        chunk_size,
        bitmap,
        storage,
        ops_leaves,
        inactivity_floor,
    );
    const pending = try pending_chunk(F, chunk_size, bitmap, ops_leaves);
    const pending_digest: ?H.Digest = if (pending) |chunk| H.hash(&.{&chunk}) else null;
    const slot = proof.pending_from(F, H.Digest, pending_digest) catch
        unreachable; // Proof: MMR has no pending chunk (graftable equals complete).
    const Witness = proof.OpsRootWitness(F, H.Digest);
    var partial: ?Witness.Partial = null;
    if (partial_chunk(chunk_size, bitmap)) |chunk| {
        partial = .{ .next_bit = chunk[1], .digest = H.hash(&.{&chunk[0]}) };
    }
    return .{
        .grafted_root = grafted_root,
        .pending_chunk_digest = slot,
        .partial_chunk = partial,
    };
}

/// The grafted tree rebuilt from the bitmap and the ops tree, with the graft roots it read.
/// The pruned chunks' grafted nodes come from `pinned_nodes`; every graftable chunk from
/// `pruned_chunks` on is read from `ops_tree` (which must still hold its root).
pub fn build_grafted_tree(
    comptime F: type,
    comptime H: type,
    comptime chunk_size: usize,
    gpa: Allocator,
    bitmap: anytype,
    pinned_nodes: []const H.Digest,
    ops_tree: anytype,
    ops_leaves: u64,
) !struct { merkle.mem.Mem(F, H.Digest), GraftRoots(H.Digest) } {
    const height = grafting.height(chunk_size);
    const pruned: u64 = bitmap.pruned_chunks();
    const complete: u64 = bitmap.complete_chunks();
    const graftable = @min(grafting.graftable_chunks(F, ops_leaves, height), complete);
    assert(pruned <= graftable and graftable <= complete);
    var roots: GraftRoots(H.Digest) = .{ .start = pruned };
    errdefer roots.deinit(gpa);
    try roots.extend_to(gpa, F, chunk_size, graftable, ops_tree);
    var tree = try merkle.mem.Mem(F, H.Digest).init(gpa, &.{}, pruned, pinned_nodes);
    errdefer tree.deinit(gpa);
    if (graftable > pruned) {
        var batch = try tree.new_batch(gpa);
        var consumed = false;
        defer if (!consumed) batch.deinit(gpa);
        for (pruned..graftable) |chunk| {
            const bytes = bitmap.get_chunk(@intCast(chunk));
            const root = roots.get(chunk).?;
            try batch.add_leaf_digest(gpa, grafting.grafted_leaf_digest(H, &bytes, root));
        }
        const hasher = grafting.GraftedHasher(F, H).init(height);
        const merkleized = try batch.merkleize(gpa, &tree, &hasher);
        consumed = true; // Merkleize consumed the batch.
        defer merkleized.release(gpa);
        try tree.apply_batch(gpa, merkleized);
    }
    assert(tree.leaves() == graftable);
    return .{ tree, roots };
}
