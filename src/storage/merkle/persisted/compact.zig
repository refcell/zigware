//! A compact, in-memory Merkle structure (port of commonware's
//! `storage/src/merkle/persisted/compact.rs`).
//!
//! Unlike `merkle.full`, this type retains only the state needed to compute the current root
//! and append new leaves: the leaf count and the pinned frontier nodes (the tree's peaks).
//! These suffice because the root folds the peaks and an append reads only the peaks it merges
//! with, so a tree rebuilt from a `(leaves, pinned_nodes)` snapshot has the same root and the
//! same future appends as the original.
//!
//! Nodes created by appends are retained only until the structure is pruned to its frontier.
//! After that they are no longer readable.
//!
//! Commonware holds the `Mem` in an `Arc` so `snapshot` is zero-copy and mutators copy on
//! write; here the structure owns its `Mem` and `snapshot` returns an owned copy. Merkleizing
//! is sequential, so there is no strategy.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const merkle = @import("../mod.zig");
const mem_module = @import("../mem.zig");

/// A Merkle structure that retains only the state required to continue appending.
pub fn Merkle(comptime F: type, comptime Digest: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Mem = mem_module.Mem(F, Digest);
        pub const MerkleizedBatch = Mem.MerkleizedBatch;

        gpa: Allocator,
        mem: Mem,

        /// An empty structure.
        pub fn init(gpa: Allocator) Self {
            const self: Self = .{ .gpa = gpa, .mem = .empty };
            assert(self.leaves() == 0);
            assert(self.mem.size() == 0);
            return self;
        }

        /// A structure with no retained nodes from its compact state: `leaves` and the digests
        /// pinned at that boundary, in `merkle.nodes_to_pin` order. Fails with
        /// `LocationOverflow` past the family's maximum leaf count and `InvalidPinnedNodes`
        /// when the pin count does not match.
        pub fn from_compact_state(
            gpa: Allocator,
            leaves_count: u64,
            pinned_nodes: []const Digest,
        ) (merkle.Error || Allocator.Error)!Self {
            if (!merkle.location_is_valid(F, leaves_count)) return error.LocationOverflow;
            const self: Self = .{
                .gpa = gpa,
                .mem = try .init(gpa, &.{}, leaves_count, pinned_nodes),
            };
            assert(self.leaves() == leaves_count);
            assert(self.mem.pruning_boundary() == leaves_count);
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.mem.deinit(self.gpa);
            self.* = undefined;
        }

        /// Discards every retained node except the pinned frontier.
        pub fn prune_to_frontier(self: *Self) void {
            const leaves_before = self.leaves();
            self.mem.prune_all();
            assert(self.leaves() == leaves_before);
            assert(self.mem.pruning_boundary() == leaves_before);
        }

        /// Hashes `element` and appends it as a single leaf.
        pub fn append_leaf(self: *Self, hasher: anytype, element: []const u8) !void {
            const leaves_before = self.leaves();
            const merkleized = merkleized: {
                var batch = try self.new_batch();
                errdefer batch.deinit(self.gpa);
                try batch.add(self.gpa, hasher, element);
                break :merkleized try batch.merkleize(self, hasher);
            };
            defer merkleized.release(self.gpa);
            try self.apply_batch(merkleized);
            assert(self.leaves() == leaves_before + 1);
        }

        /// The root digest of the current state.
        pub fn root(self: *const Self, hasher: anytype, inactive_peaks: usize) !Digest {
            assert(self.mem.pruning_boundary() <= self.leaves());
            return self.mem.root(hasher, inactive_peaks);
        }

        /// The number of leaves in the structure.
        pub fn leaves(self: *const Self) u64 {
            return self.mem.leaves();
        }

        /// An independent copy of the in-memory structure that never observes later mutations.
        /// Caller owns it (`Mem.deinit`).
        pub fn snapshot(self: *const Self) Allocator.Error!Mem {
            const copy = try self.mem.clone(self.gpa);
            assert(copy.size() == self.mem.size());
            return copy;
        }

        /// A speculative append-only batch with this structure as its parent.
        pub fn new_batch(self: *const Self) Allocator.Error!AppendBatch {
            const inner = try self.mem.new_batch(self.gpa);
            assert(inner.leaves() == self.leaves());
            return .{ .inner = inner };
        }

        /// An owned merkleized batch representing the current state (release it).
        pub fn to_batch(self: *const Self) Allocator.Error!*MerkleizedBatch {
            const batch = try MerkleizedBatch.from_mem(self.gpa, &self.mem);
            assert(batch.size() == self.mem.size());
            return batch;
        }

        /// Applies a merkleized batch; see `Mem.apply_batch`.
        pub fn apply_batch(
            self: *Self,
            batch: *const MerkleizedBatch,
        ) (merkle.Error || Allocator.Error)!void {
            try self.mem.apply_batch(self.gpa, batch);
            assert(self.mem.size() == batch.size());
        }

        /// An append-only wrapper of `batch.Unmerkleized`.
        pub const AppendBatch = struct {
            inner: Mem.Batch,

            pub fn deinit(self: *AppendBatch, gpa: Allocator) void {
                self.inner.deinit(gpa);
            }

            /// The number of leaves visible through this batch.
            pub fn leaves(self: *const AppendBatch) u64 {
                return self.inner.leaves();
            }

            /// Hashes `element` and adds it as a leaf.
            pub fn add(
                self: *AppendBatch,
                gpa: Allocator,
                hasher: anytype,
                element: []const u8,
            ) !void {
                try self.inner.add(gpa, hasher, element);
            }

            /// Adds the codec encoding of each of `items` as a leaf, in order.
            pub fn add_many(
                self: *AppendBatch,
                gpa: Allocator,
                hasher: anytype,
                comptime Item: type,
                items: []const Item,
            ) !void {
                try self.inner.add_many(gpa, hasher, Item, items);
            }

            /// Merkleizes against the structure's retained nodes. Consumes the batch.
            pub fn merkleize(
                self: *AppendBatch,
                structure: *const Self,
                hasher: anytype,
            ) !*MerkleizedBatch {
                return self.inner.merkleize(structure.gpa, &structure.mem, hasher);
            }
        };
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const Sha256 = cryptography.Sha256;
const Standard = merkle.hasher.Standard(Sha256);

fn append(structure: anytype, values: []const []const u8) !void {
    const hasher = Standard.init(.forward_fold);
    const merkleized = merkleized: {
        var batch = try structure.new_batch();
        errdefer batch.deinit(testing.allocator);
        for (values) |value| try batch.add(testing.allocator, &hasher, value);
        break :merkleized try batch.merkleize(structure, &hasher);
    };
    defer merkleized.release(testing.allocator);
    try structure.apply_batch(merkleized);
}

fn expect_compact_state_round_trip(comptime F: type) !void {
    const D = Sha256.Digest;
    const hasher = Standard.init(.forward_fold);
    var structure = Merkle(F, D).init(testing.allocator);
    defer structure.deinit();
    try append(&structure, &.{ "a", "b", "c" });
    const root = try structure.root(&hasher, 0);
    const leaves = structure.leaves();
    var pinned_buffer: [merkle.max_pinned_nodes]D = undefined;
    const pinned = structure.mem.node_digests_to_pin(leaves, &pinned_buffer);

    // Pruning to the frontier does not change the root.
    structure.prune_to_frontier();
    try testing.expect((try structure.root(&hasher, 0)).eql(root));

    // A structure rebuilt from the compact state has the same root and leaf count.
    var restored = try Merkle(F, D).from_compact_state(testing.allocator, leaves, pinned);
    defer restored.deinit();
    try testing.expect((try restored.root(&hasher, 0)).eql(root));
    try testing.expectEqual(leaves, restored.leaves());

    // Both evolve identically from the snapshot.
    try append(&structure, &.{"d"});
    try append(&restored, &.{"d"});
    try testing.expect((try restored.root(&hasher, 0)).eql(try structure.root(&hasher, 0)));
    try restored.append_leaf(&hasher, "e");
    try testing.expect(!(try restored.root(&hasher, 0)).eql(try structure.root(&hasher, 0)));
    try structure.append_leaf(&hasher, "e");
    try testing.expect((try restored.root(&hasher, 0)).eql(try structure.root(&hasher, 0)));
}

test "compact state round trip mmr" {
    try expect_compact_state_round_trip(merkle.mmr.Family);
}

test "compact state round trip mmb" {
    try expect_compact_state_round_trip(merkle.mmb.Family);
}

test "from compact state rejects invalid snapshot" {
    const F = merkle.mmr.Family;
    const D = Sha256.Digest;
    var structure = Merkle(F, D).init(testing.allocator);
    defer structure.deinit();
    try append(&structure, &.{ "a", "b" });
    const leaves = structure.leaves();
    // Wrong pinned-node count.
    try testing.expectError(
        error.InvalidPinnedNodes,
        Merkle(F, D).from_compact_state(testing.allocator, leaves, &.{}),
    );
    // Leaf count beyond the family maximum.
    try testing.expectError(
        error.LocationOverflow,
        Merkle(F, D).from_compact_state(testing.allocator, F.max_leaves + 1, &.{}),
    );
}

test "snapshot never observes later mutations" {
    const F = merkle.mmb.Family;
    const D = Sha256.Digest;
    const hasher = Standard.init(.forward_fold);
    var structure = Merkle(F, D).init(testing.allocator);
    defer structure.deinit();
    try append(&structure, &.{ "a", "b", "c" });
    var snapshot = try structure.snapshot();
    defer snapshot.deinit(testing.allocator);
    const root = try snapshot.root(&hasher, 0);
    try structure.append_leaf(&hasher, "d");
    structure.prune_to_frontier();
    try testing.expectEqual(@as(u64, 3), snapshot.leaves());
    try testing.expect((try snapshot.root(&hasher, 0)).eql(root));
    try testing.expect(!(try structure.root(&hasher, 0)).eql(root));
}
