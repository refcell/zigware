//! An in-memory Merkle-family structure (MMR or MMB) that stores every retained node digest.
//!
//! Port of the core of commonware's `storage/src/merkle/mem.rs`: append leaves, read nodes
//! and peaks, compute the root, prune, and generate element and range proofs. Commonware
//! appends through batches (`new_batch().add(..).merkleize(..)` then `apply_batch`); `add`
//! here is the same as a one-leaf batch.
//!
//! After pruning to leaf `l`, nodes below `location_to_position(l)` are dropped except the
//! pinned ones (`merkle.nodes_to_pin(l)`), which are enough to keep growing the structure,
//! compute its root, and prove every retained leaf.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const merkle = @import("mod.zig");
const hasher_module = @import("hasher.zig");
const proof_module = @import("proof.zig");
const batch_module = @import("batch.zig");

pub fn Mem(comptime F: type, comptime Digest: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Proof = proof_module.Proof(F, Digest);
        /// The pins of this structure's own boundary plus, through `add_pinned_nodes`, those of
        /// one other boundary (a journaled structure's pruning boundary).
        pub const max_pins = 2 * merkle.max_pinned_nodes;
        pub const Batch = batch_module.Unmerkleized(F, Digest);
        pub const MerkleizedBatch = batch_module.Merkleized(F, Digest);

        /// Digests of the retained nodes, starting at `pruned_size`.
        nodes: std.ArrayList(Digest) = .empty,
        /// Node count pruned from the front; nodes below it are gone except pinned ones.
        pruned_size: u64 = 0,
        /// Positions of the pinned nodes below `pruned_size`, ascending.
        pinned_positions: merkle.BoundedList(u64, max_pins) = .{},
        /// Digests of the pinned nodes, parallel to `pinned_positions`.
        pinned_digests: merkle.BoundedList(Digest, max_pins) = .{},

        pub const empty: Self = .{};

        /// A structure from its retained `nodes` (starting at the position of
        /// `boundary`) and the digests pinned at that boundary, in
        /// `merkle.nodes_to_pin` order (commonware's `Mem::init(Config)`). Copies `nodes`.
        pub fn init(
            gpa: Allocator,
            nodes: []const Digest,
            boundary: u64,
            pinned_nodes: []const Digest,
        ) (merkle.Error || Allocator.Error)!Self {
            const pruned_size = try merkle.position_from_location(F, boundary);
            const total = merkle.checked_add(pruned_size, nodes.len, F.max_nodes) orelse
                return error.InvalidSize;
            if (!F.is_valid_size(total)) return error.InvalidSize;
            var positions_buffer: [merkle.max_pinned_nodes]u64 = undefined;
            const positions = merkle.nodes_to_pin(F, boundary, &positions_buffer);
            if (pinned_nodes.len != positions.len) return error.InvalidPinnedNodes;
            var self: Self = .{
                .pruned_size = pruned_size,
                .pinned_positions = .from_slice(positions),
                .pinned_digests = .from_slice(pinned_nodes),
            };
            try self.nodes.appendSlice(gpa, nodes);
            assert(self.size() == total);
            assert(self.pruning_boundary() == boundary);
            return self;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.nodes.deinit(gpa);
            self.* = undefined;
        }

        /// An independent copy of the structure.
        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var copy = self.*;
            copy.nodes = try self.nodes.clone(gpa);
            assert(copy.size() == self.size());
            return copy;
        }

        /// Total node count, irrespective of pruning.
        pub fn size(self: *const Self) u64 {
            return self.pruned_size + self.nodes.items.len;
        }

        /// Total leaf count.
        pub fn leaves(self: *const Self) u64 {
            return F.position_to_location(self.size()).?; // A Mem is always a valid size.
        }

        /// The leaf location pruning has reached (0 if never pruned).
        pub fn pruning_boundary(self: *const Self) u64 {
            return F.position_to_location(self.pruned_size).?; // Pruned at a leaf boundary.
        }

        /// The digest of the node at `position`, or null if pruned (and not pinned) or past
        /// the end.
        pub fn get_node(self: *const Self, position: u64) ?Digest {
            if (position >= self.size()) return null;
            if (position >= self.pruned_size) {
                return self.nodes.items[@intCast(position - self.pruned_size)];
            }
            for (self.pinned_positions.slice(), self.pinned_digests.slice()) |pinned, digest| {
                if (pinned == position) return digest;
            }
            return null;
        }

        fn node(self: *const Self, position: u64) Digest {
            assert(position < self.size());
            return self.get_node(position).?; // Requested node is pruned and not pinned.
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
                const left = self.node(children.left);
                const right = self.node(children.right);
                self.nodes.appendAssumeCapacity(hasher.node_digest(position, &left, &right));
            }
            assert(F.is_valid_size(self.size()));
            assert(self.leaves() == location + 1);
        }

        /// Replaces the element of the leaf at `location` (see `update_leaf_digest`).
        pub fn update_leaf(
            self: *Self,
            hasher: anytype,
            location: u64,
            element: []const u8,
        ) merkle.Error!void {
            if (location >= self.leaves()) return error.LeafOutOfBounds;
            const position = F.location_to_position(location);
            try self.update_leaf_digest(hasher, location, hasher.leaf_digest(position, element));
        }

        /// Replaces the digest of the leaf at `location` and recomputes its ancestors up to
        /// their peak (commonware's batch `update_leaf_digest`). Fails, changing nothing, when
        /// the leaf or a node its ancestors hash is pruned.
        pub fn update_leaf_digest(
            self: *Self,
            hasher: anytype,
            location: u64,
            leaf: Digest,
        ) merkle.Error!void {
            if (location >= self.leaves()) return error.LeafOutOfBounds;
            const leaf_position = F.location_to_position(location);
            if (leaf_position < self.pruned_size) return error.ElementPruned;
            const path = self.leaf_path(location);
            assert(path.leaf == leaf_position);
            // Check every sibling first so a failure leaves the structure untouched.
            for (path.ancestors.slice()) |parent| {
                const children = F.children(parent.position, parent.height);
                assert(parent.position >= self.pruned_size); // Parents follow their leaves.
                if (self.get_node(children.left) == null) return error.ElementPruned;
                if (self.get_node(children.right) == null) return error.ElementPruned;
            }
            self.nodes.items[@intCast(leaf_position - self.pruned_size)] = leaf;
            var index = path.ancestors.len;
            while (index > 0) {
                index -= 1;
                const parent = path.ancestors.buffer[index];
                const children = F.children(parent.position, parent.height);
                const left = self.node(children.left);
                const right = self.node(children.right);
                const digest = hasher.node_digest(parent.position, &left, &right);
                self.nodes.items[@intCast(parent.position - self.pruned_size)] = digest;
            }
        }

        const LeafPath = struct {
            /// The ancestors of the leaf, its peak first.
            ancestors: merkle.BoundedList(merkle.Peak, merkle.max_pinned_nodes) = .{},
            leaf: u64,
        };

        /// The ancestors of leaf `location`, found by descending from the peak covering it.
        fn leaf_path(self: *const Self, location: u64) LeafPath {
            assert(location < self.leaves());
            var first_leaf: u64 = 0;
            var current: merkle.Peak = undefined;
            var iterator = F.peaks(self.size());
            while (iterator.next()) |peak| {
                const peak_leaves = @as(u64, 1) << @intCast(peak.height);
                if (location < first_leaf + peak_leaves) {
                    current = peak;
                    break;
                }
                first_leaf += peak_leaves;
            } else unreachable; // The peaks cover every leaf below `leaves()`.
            var path: LeafPath = .{ .leaf = undefined };
            while (current.height > 0) {
                path.ancestors.append(current);
                const children = F.children(current.position, current.height);
                const half = @as(u64, 1) << @intCast(current.height - 1);
                const left = location < first_leaf + half;
                if (!left) first_leaf += half;
                current = .{
                    .position = if (left) children.left else children.right,
                    .height = current.height - 1,
                };
            }
            assert(first_leaf == location);
            path.leaf = current.position;
            return path;
        }

        /// Writes the peak digests, oldest first, into `out` and returns them.
        pub fn peaks(self: *const Self, out: *[merkle.max_pinned_nodes]Digest) []Digest {
            var count: usize = 0;
            var iterator = F.peaks(self.size());
            while (iterator.next()) |peak| {
                out[count] = self.node(peak.position);
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

        /// Prunes every node not needed to prove leaves at or after `location`.
        pub fn prune(self: *Self, location: u64) merkle.Error!void {
            if (location > self.leaves()) return error.LeafOutOfBounds;
            const position = try merkle.position_from_location(F, location);
            if (position <= self.pruned_size) return;
            self.prune_to(location, position);
        }

        /// Prunes everything (keeping only what the root and further appends need).
        pub fn prune_all(self: *Self) void {
            if (self.nodes.items.len == 0) return;
            const location = self.leaves();
            self.prune_to(location, self.size());
        }

        fn prune_to(self: *Self, location: u64, position: u64) void {
            assert(position > self.pruned_size and position <= self.size());
            var positions_buffer: [merkle.max_pinned_nodes]u64 = undefined;
            const positions = merkle.nodes_to_pin(F, location, &positions_buffer);
            var digests: merkle.BoundedList(Digest, max_pins) = .{};
            for (positions) |pinned| digests.append(self.node(pinned));
            self.pinned_positions = .from_slice(positions);
            self.pinned_digests = digests;
            const drop: usize = @intCast(position - self.pruned_size);
            self.nodes.replaceRangeAssumeCapacity(0, drop, &.{});
            self.pruned_size = position;
            assert(self.pruning_boundary() == location);
        }

        /// An inclusion proof for the element at `location`. Caller owns the proof.
        pub fn proof(
            self: *const Self,
            gpa: Allocator,
            hasher: anytype,
            location: u64,
            inactive_peaks: usize,
        ) (merkle.Error || Allocator.Error)!Proof {
            if (location >= F.max_leaves) return error.LocationOverflow;
            const range: merkle.Range = .{ .start = location, .end = location + 1 };
            return self.range_proof(gpa, hasher, range, inactive_peaks) catch |err| switch (err) {
                error.RangeOutOfBounds => error.LeafOutOfBounds,
                else => |e| e,
            };
        }

        /// An inclusion proof for the elements in `range`. Caller owns the proof.
        pub fn range_proof(
            self: *const Self,
            gpa: Allocator,
            hasher: anytype,
            range: merkle.Range,
            inactive_peaks: usize,
        ) (merkle.Error || Allocator.Error)!Proof {
            const plan = try proof_module.RangePlan(F).init(self.leaves(), range);
            return plan.build(gpa, hasher, inactive_peaks, self);
        }

        /// The retained nodes from `position` (at or above the pruned size) to the end.
        pub fn nodes_from(self: *const Self, position: u64) []const Digest {
            assert(position >= self.pruned_size and position <= self.size());
            return self.nodes.items[@intCast(position - self.pruned_size)..];
        }

        /// Pins extra nodes below the pruned size (commonware's `add_pinned_nodes`); a position
        /// already pinned takes the new digest. The caller ensures the set is valid.
        pub fn add_pinned_nodes(
            self: *Self,
            positions: []const u64,
            digests: []const Digest,
        ) void {
            assert(positions.len == digests.len);
            for (positions, digests) |position, digest| {
                assert(position < self.pruned_size);
                const pinned = self.pinned_positions.slice();
                if (std.mem.indexOfScalar(u64, pinned, position)) |slot| {
                    self.pinned_digests.slice_mut()[slot] = digest;
                } else {
                    self.pinned_positions.append(position);
                    self.pinned_digests.append(digest);
                }
            }
            assert(self.pinned_positions.len == self.pinned_digests.len);
        }

        /// A speculative batch on top of the committed state.
        pub fn new_batch(self: *const Self, gpa: Allocator) Allocator.Error!Batch {
            const root_batch = try MerkleizedBatch.from_mem(gpa, self);
            defer root_batch.release(gpa);
            const batch = root_batch.new_batch();
            assert(batch.size() == self.size());
            return batch;
        }

        /// Overwrites the node at `position`, which may have been pruned since the batch was
        /// merkleized: a pinned node takes the digest, any other pruned node no longer counts.
        fn overwrite(self: *Self, position: u64, digest: Digest) void {
            if (position >= self.pruned_size) {
                self.nodes.items[@intCast(position - self.pruned_size)] = digest;
                return;
            }
            const pinned = self.pinned_positions.slice();
            const slot = std.mem.indexOfScalar(u64, pinned, position) orelse return;
            self.pinned_digests.slice_mut()[slot] = digest;
        }

        fn at_state(self: *const Self, size_expected: u64, peaks_expected: []const Digest) bool {
            if (self.size() != size_expected) return false;
            var buffer: [merkle.max_pinned_nodes]Digest = undefined;
            const current = self.peaks(&buffer);
            if (current.len != peaks_expected.len) return false;
            for (current, peaks_expected) |a, b| if (!a.eql(b)) return false;
            return true;
        }

        /// The index of the first retained ancestor of `batch` to replay: the structure must
        /// be at the state before the oldest retained ancestor (or the batch itself), or after
        /// one of them. A batch applies once.
        fn validate_batch(self: *const Self, batch: *const MerkleizedBatch) merkle.Error!usize {
            const oldest = if (batch.ancestors.len > 0) batch.ancestors[0] else batch.data;
            if (self.at_state(oldest.parent_size, oldest.parent_peaks.slice())) return 0;
            var index = batch.ancestors.len;
            while (index > 0) {
                index -= 1;
                const ancestor = batch.ancestors[index];
                if (self.at_state(ancestor.size(), ancestor.tip_peaks.slice())) return index + 1;
            }
            const size_now = self.size();
            if (size_now >= batch.base_size and size_now < oldest.parent_size) {
                return error.AncestorDropped;
            }
            return error.StaleBatch;
        }

        /// Commits `batch`, replaying its uncommitted ancestors first. Pruning after the batch
        /// was merkleized does not invalidate it (prune and apply commute). Fails, changing
        /// nothing, with `AncestorDropped` when it needs nodes of an ancestor released before it
        /// was merkleized, or `StaleBatch` when the structure is at no state of its chain.
        pub fn apply_batch(
            self: *Self,
            gpa: Allocator,
            batch: *const MerkleizedBatch,
        ) (merkle.Error || Allocator.Error)!void {
            const start = try self.validate_batch(batch);
            const appended_total = batch.size() - self.size();
            try self.nodes.ensureUnusedCapacity(gpa, @intCast(appended_total));
            for (batch.ancestors[start..]) |data| self.apply_data(data);
            self.apply_data(batch.data);
            assert(self.size() == batch.size());
        }

        fn apply_data(self: *Self, data: *const MerkleizedBatch.BatchData) void {
            assert(self.size() == data.parent_size);
            var overwrites = data.overwrites.iterator();
            while (overwrites.next()) |entry| self.overwrite(entry.key_ptr.*, entry.value_ptr.*);
            self.nodes.appendSliceAssumeCapacity(data.appended.items);
        }

        /// The digests of the nodes pinned when pruning to `location`, in pin order.
        pub fn node_digests_to_pin(
            self: *const Self,
            location: u64,
            out: *[merkle.max_pinned_nodes]Digest,
        ) []Digest {
            var positions_buffer: [merkle.max_pinned_nodes]u64 = undefined;
            const positions = merkle.nodes_to_pin(F, location, &positions_buffer);
            for (positions, out[0..positions.len]) |pinned, *digest| digest.* = self.node(pinned);
            return out[0..positions.len];
        }
    };
}
