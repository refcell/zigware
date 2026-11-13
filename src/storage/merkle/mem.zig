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

pub fn Mem(comptime F: type, comptime Digest: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Proof = proof_module.Proof(F, Digest);

        /// Digests of the retained nodes, starting at `pruned_size`.
        nodes: std.ArrayList(Digest) = .empty,
        /// Node count pruned from the front; nodes below it are gone except pinned ones.
        pruned_size: u64 = 0,
        /// Positions of the pinned nodes below `pruned_size`, ascending.
        pinned_positions: merkle.BoundedList(u64, merkle.max_pinned_nodes) = .{},
        /// Digests of the pinned nodes, parallel to `pinned_positions`.
        pinned_digests: merkle.BoundedList(Digest, merkle.max_pinned_nodes) = .{},

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
            var digests: merkle.BoundedList(Digest, merkle.max_pinned_nodes) = .{};
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
