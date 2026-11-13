//! An in-memory Merkle-family structure (MMR or MMB) that stores every node digest.
//!
//! Port of the core of commonware's `storage/src/merkle/mem.rs`: append leaves, read nodes
//! and peaks, and compute the root. Commonware appends through batches
//! (`new_batch().add(..).merkleize(..)` then `apply_batch`); `add` here is the same as a
//! one-leaf batch, and the batch API lands on top of it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const merkle = @import("mod.zig");
const hasher_module = @import("hasher.zig");

pub fn Mem(comptime F: type, comptime Digest: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();

        /// Digests of the retained nodes, starting at `pruned_size`.
        nodes: std.ArrayList(Digest) = .empty,
        /// Node count pruned from the front; nodes below it are gone except pinned ones.
        pruned_size: u64 = 0,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.nodes.deinit(gpa);
            self.* = undefined;
        }

        /// Total node count, irrespective of pruning.
        pub fn size(self: *const Self) u64 {
            return self.pruned_size + self.nodes.items.len;
        }

        /// Total leaf count.
        pub fn leaves(self: *const Self) u64 {
            return F.position_to_location(self.size()).?; // A Mem is always a valid size.
        }

        /// The digest of the node at `position`, or null if it is pruned or past the end.
        pub fn get_node(self: *const Self, position: u64) ?Digest {
            if (position < self.pruned_size or position >= self.size()) return null;
            return self.nodes.items[@intCast(position - self.pruned_size)];
        }

        fn node(self: *const Self, position: u64) *const Digest {
            assert(position >= self.pruned_size);
            assert(position < self.size());
            return &self.nodes.items[@intCast(position - self.pruned_size)];
        }

        /// Appends `element` as a leaf, hashing it and every parent it completes.
        pub fn add(self: *Self, gpa: Allocator, hasher: anytype, element: []const u8) !void {
            const leaf = hasher.leaf_digest(self.size(), element);
            try self.add_leaf_digest(gpa, hasher, leaf);
        }

        /// Appends a leaf whose digest is already computed.
        pub fn add_leaf_digest(self: *Self, gpa: Allocator, hasher: anytype, leaf: Digest) !void {
            const location = self.leaves();
            if (location >= F.max_leaves) return error.LocationOverflow;
            const heights_max = 64;
            try self.nodes.ensureUnusedCapacity(gpa, 1 + heights_max);
            self.nodes.appendAssumeCapacity(leaf);
            var heights = F.parent_heights(location);
            while (heights.next()) |height| {
                const position = self.size();
                const children = F.children(position, height);
                const parent = hasher.node_digest(
                    position,
                    self.node(children.left),
                    self.node(children.right),
                );
                self.nodes.appendAssumeCapacity(parent);
            }
            assert(F.is_valid_size(self.size()));
            assert(self.leaves() == location + 1);
        }

        /// Writes the peak digests, oldest first, into `out` and returns them.
        pub fn peaks(self: *const Self, out: *[merkle.max_pinned_nodes]Digest) []Digest {
            var count: usize = 0;
            var iterator = F.peaks(self.size());
            while (iterator.next()) |peak| {
                out[count] = self.node(peak.position).*;
                count += 1;
            }
            return out[0..count];
        }

        /// The root, with the oldest `inactive_peaks` peaks folded forward and committed.
        pub fn root(self: *const Self, hasher: anytype, inactive_peaks: usize) !Digest {
            var buffer: [merkle.max_pinned_nodes]Digest = undefined;
            const digests = self.peaks(&buffer);
            return hasher_module.root(F, hasher, self.leaves(), inactive_peaks, digests);
        }
    };
}
