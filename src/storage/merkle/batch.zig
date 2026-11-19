//! Speculative batches over a Merkle structure (commonware's `storage/src/merkle/batch.rs`).
//!
//! An `Unmerkleized` batch collects appends and leaf overwrites on top of a parent
//! `Merkleized` batch; `merkleize` hashes the dirty nodes into a new `Merkleized` batch, and
//! `Mem.apply_batch` commits it. Batches stack to any depth, and several forks may share a
//! parent:
//!
//! ```text
//! Mem --new_batch--> Unmerkleized --merkleize(base)--> *Merkleized --Mem.apply_batch--> Mem
//! ```
//!
//! Commonware links batches with `Arc` (to their changes) and `Weak` (to their parent).
//! zigware counts both by hand: `Merkleized.retain`/`release` are the strong references
//! (`release` is commonware's `drop`), and a child's parent link is a weak one. A batch's
//! changes (`Data`) are reference counted too, so a merkleized batch keeps the changes of every
//! live ancestor and `apply_batch` can replay uncommitted ancestors after they are released.
//! Releasing an unapplied ancestor before a descendant is merkleized loses its changes, and
//! `apply_batch` reports `AncestorDropped`. Batches are not thread-safe.
//!
//! `merkleize_with` and `add_many_with` split their hashing across a `parallel` strategy
//! (commonware's batch strategy, passed per call instead of stored on the batch); every split
//! gives the same digests. `merkleize` and `add_many` run them on `parallel.sequential`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const parallel = @import("parallel");
const merkle = @import("mod.zig");
const hasher_module = @import("hasher.zig");
const proof_module = @import("proof.zig");

const max_peaks = merkle.max_pinned_nodes;
/// Node heights in a u64-sized structure are below 64.
const max_height = 64;

/// Internal nodes awaiting hashing, by height, ascending within each height.
const Levels = [max_height]std.ArrayList(u64);

fn levels_deinit(gpa: Allocator, levels: *Levels) void {
    for (levels) |*level| level.deinit(gpa);
}

/// One batch's changes and the peaks of the states before and after them, shared by the
/// batch and its descendants.
pub fn Data(comptime Digest: type) type {
    return struct {
        const Self = @This();

        references: u32,
        /// Node count before this batch's changes.
        parent_size: u64,
        /// Nodes appended after `parent_size`.
        appended: std.ArrayList(Digest),
        /// Overwritten nodes by position, all below `parent_size`.
        overwrites: std.AutoHashMapUnmanaged(u64, Digest),
        parent_peaks: merkle.BoundedList(Digest, max_peaks),
        tip_peaks: merkle.BoundedList(Digest, max_peaks),

        /// Node count after this batch's changes.
        pub fn size(self: *const Self) u64 {
            return self.parent_size + self.appended.items.len;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.appended.items.len == 0 and self.overwrites.count() == 0;
        }

        fn retain(self: *Self) *Self {
            assert(self.references > 0);
            self.references += 1;
            return self;
        }

        fn release(self: *Self, gpa: Allocator) void {
            assert(self.references > 0);
            self.references -= 1;
            if (self.references > 0) return;
            self.appended.deinit(gpa);
            self.overwrites.deinit(gpa);
            gpa.destroy(self);
        }
    };
}

/// A batch whose dirty nodes are hashed: immutable, reference counted.
pub fn Merkleized(comptime F: type, comptime Digest: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Proof = proof_module.Proof(F, Digest);
        pub const BatchData = Data(Digest);

        /// Strong references; the batch's changes live while this is non-zero.
        strong: u32,
        /// Weak references (children's parent links) plus one shared by the strong ones.
        weak: u32,
        /// The parent batch (a weak link), null for a root batch or once released.
        parent: ?*Self,
        data: *BatchData,
        /// The committed node count when the chain was forked; inherited by descendants.
        base_size: u64,
        /// The committed pruning boundary when the chain was forked; inherited too.
        pruning_boundary: u64,
        /// The changes of the non-empty ancestors live at merkleize, oldest first.
        ancestors: []const *BatchData,

        /// A root batch representing `mem`'s committed state.
        pub fn from_mem(gpa: Allocator, mem: anytype) Allocator.Error!*Self {
            var peaks_buffer: [max_peaks]Digest = undefined;
            const peaks = mem.peaks(&peaks_buffer);
            const data = try gpa.create(BatchData);
            errdefer gpa.destroy(data);
            data.* = .{
                .references = 1,
                .parent_size = mem.size(),
                .appended = .empty,
                .overwrites = .empty,
                .parent_peaks = .from_slice(peaks),
                .tip_peaks = .from_slice(peaks),
            };
            const self = try gpa.create(Self);
            self.* = .{
                .strong = 1,
                .weak = 1,
                .parent = null,
                .data = data,
                .base_size = mem.size(),
                .pruning_boundary = mem.pruning_boundary(),
                .ancestors = &.{},
            };
            assert(self.size() == mem.size());
            return self;
        }

        pub fn retain(self: *Self) *Self {
            assert(self.strong > 0);
            self.strong += 1;
            return self;
        }

        /// Drops a strong reference. The last one frees the batch's changes unless a merkleized
        /// descendant holds them; descendants not yet merkleized lose them.
        pub fn release(self: *Self, gpa: Allocator) void {
            assert(self.strong > 0);
            self.strong -= 1;
            if (self.strong > 0) return;
            self.data.release(gpa);
            for (self.ancestors) |ancestor| ancestor.release(gpa);
            gpa.free(self.ancestors);
            if (self.parent) |parent| parent.release_weak(gpa);
            self.parent = null;
            self.release_weak(gpa);
        }

        fn release_weak(self: *Self, gpa: Allocator) void {
            assert(self.weak > 0);
            self.weak -= 1;
            if (self.weak == 0) gpa.destroy(self);
        }

        /// The parent, if it is still alive (commonware's `Weak::upgrade`).
        fn live_parent(self: *const Self) ?*Self {
            const parent = self.parent orelse return null;
            assert(parent.weak > 0);
            return if (parent.strong > 0) parent else null;
        }

        pub fn size(self: *const Self) u64 {
            return self.data.size();
        }

        pub fn leaves(self: *const Self) u64 {
            return F.position_to_location(self.size()).?; // A batch is always a valid size.
        }

        /// The node at `position` from this batch's chain, or null if it is only in the
        /// committed structure (or past the end).
        pub fn get_node(self: *const Self, position: u64) ?Digest {
            if (position >= self.size()) return null;
            var current: ?*const Self = self;
            while (current) |batch| : (current = batch.live_parent()) {
                const data = batch.data;
                if (position >= data.parent_size) {
                    const index: usize = @intCast(position - data.parent_size);
                    if (index < data.appended.items.len) return data.appended.items[index];
                    return null;
                }
                if (data.overwrites.get(position)) |digest| return digest;
            }
            return null;
        }

        /// The root after this batch's changes.
        pub fn root(self: *const Self, hasher: anytype, inactive_peaks: usize) !Digest {
            const peaks = self.data.tip_peaks.slice();
            return hasher_module.root(F, hasher, self.leaves(), inactive_peaks, peaks);
        }

        /// Nodes from this batch's chain, falling back to the committed `base`.
        fn Layered(comptime Base: type) type {
            return struct {
                batch: *const Self,
                base: Base,

                pub fn get_node(layered: *const @This(), position: u64) ?Digest {
                    return layered.batch.get_node(position) orelse layered.base.get_node(position);
                }
            };
        }

        /// An inclusion proof for the element at `location`. Caller owns the proof.
        pub fn proof(
            self: *const Self,
            gpa: Allocator,
            base: anytype,
            hasher: anytype,
            location: u64,
            inactive_peaks: usize,
        ) (merkle.Error || Allocator.Error)!Proof {
            if (location >= F.max_leaves) return error.LocationOverflow;
            const range: merkle.Range = .{ .start = location, .end = location + 1 };
            return self.range_proof(gpa, base, hasher, range, inactive_peaks) catch |err|
                switch (err) {
                    error.RangeOutOfBounds => error.LeafOutOfBounds,
                    else => |e| e,
                };
        }

        /// An inclusion proof for the elements in `range`. Caller owns the proof.
        pub fn range_proof(
            self: *const Self,
            gpa: Allocator,
            base: anytype,
            hasher: anytype,
            range: merkle.Range,
            inactive_peaks: usize,
        ) (merkle.Error || Allocator.Error)!Proof {
            const plan = try proof_module.RangePlan(F).init(self.leaves(), range);
            const layered: Layered(@TypeOf(base)) = .{ .batch = self, .base = base };
            return plan.build(gpa, hasher, inactive_peaks, &layered);
        }

        /// A child batch on top of this one. It becomes invalid if an unapplied ancestor is
        /// released or a sibling fork is applied.
        pub fn new_batch(self: *Self) Unmerkleized(F, Digest) {
            return .{ .parent = self.retain() };
        }
    };
}

/// Collects `parent`'s changes and those of its live ancestors, oldest first, skipping empty
/// ones (root batches). Each returned reference is retained.
fn collect_ancestors(
    comptime F: type,
    comptime Digest: type,
    gpa: Allocator,
    parent: *Merkleized(F, Digest),
) Allocator.Error![]const *Data(Digest) {
    var ancestors: std.ArrayList(*Data(Digest)) = .empty;
    errdefer ancestors.deinit(gpa);
    var current: ?*Merkleized(F, Digest) = parent;
    while (current) |batch| : (current = batch.live_parent()) {
        if (!batch.data.is_empty()) try ancestors.append(gpa, batch.data);
    }
    std.mem.reverse(*Data(Digest), ancestors.items);
    const owned = try ancestors.toOwnedSlice(gpa);
    for (owned) |data| _ = data.retain();
    assert(owned.len <= std.math.maxInt(u32));
    return owned;
}

/// A batch whose new nodes are not hashed yet: appends and leaf overwrites accumulate here.
pub fn Unmerkleized(comptime F: type, comptime Digest: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Parent = Merkleized(F, Digest);
        pub const LeafUpdate = struct { location: u64, digest: Digest };

        /// A strong reference to the parent.
        parent: *Parent,
        appended: std.ArrayList(Digest) = .empty,
        /// Overwritten nodes below the parent's size. Before merkleize, only leaves.
        overwrites: std.AutoHashMapUnmanaged(u64, Digest) = .empty,
        unhashed: Levels = @splat(.empty),
        /// The first leaf `add_many` added; only leaves from here on can have ancestors this
        /// batch hashed already.
        add_many_start: ?u64 = null,
        /// Bit `i` is set when leaf `add_many_start + i` was updated.
        updated_new_leaves: std.DynamicBitSetUnmanaged = .{},

        /// Discards the batch without merkleizing it.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.free_changes(gpa);
            self.appended.deinit(gpa);
            self.overwrites.deinit(gpa);
            self.parent.release(gpa);
            self.* = undefined;
        }

        fn free_changes(self: *Self, gpa: Allocator) void {
            levels_deinit(gpa, &self.unhashed);
            self.updated_new_leaves.deinit(gpa);
        }

        pub fn size(self: *const Self) u64 {
            return self.parent.size() + self.appended.items.len;
        }

        pub fn leaves(self: *const Self) u64 {
            return F.position_to_location(self.size()).?; // A batch is always a valid size.
        }

        /// Own changes, then the parent chain, then the committed `base`.
        fn get_node(self: *const Self, base: anytype, position: u64) ?Digest {
            if (position >= self.size()) return null;
            const parent_size = self.parent.size();
            if (position >= parent_size) {
                return self.appended.items[@intCast(position - parent_size)];
            }
            if (self.overwrites.get(position)) |digest| return digest;
            return self.parent.get_node(position) orelse base.get_node(position);
        }

        fn store_node(self: *Self, gpa: Allocator, position: u64, digest: Digest) !void {
            const parent_size = self.parent.size();
            if (position >= parent_size) {
                self.appended.items[@intCast(position - parent_size)] = digest;
            } else {
                try self.overwrites.put(gpa, position, digest);
            }
        }

        fn store_leaf(self: *Self, gpa: Allocator, location: u64, digest: Digest) !void {
            const position = F.location_to_position(location);
            try self.store_node(gpa, position, digest);
            const start = self.add_many_start orelse return;
            if (location < start) return;
            const bit: usize = @intCast(location - start);
            if (bit >= self.updated_new_leaves.bit_length) {
                try self.updated_new_leaves.resize(gpa, bit + 1, false);
            }
            self.updated_new_leaves.set(bit);
        }

        /// Hashes `element` and adds it as a leaf.
        pub fn add(self: *Self, gpa: Allocator, hasher: anytype, element: []const u8) !void {
            try self.add_leaf_digest(gpa, hasher.leaf_digest(self.size(), element));
        }

        /// Adds a leaf whose digest is already computed.
        pub fn add_leaf_digest(self: *Self, gpa: Allocator, digest: Digest) !void {
            const location = self.leaves();
            if (location >= F.max_leaves) return error.LocationOverflow;
            const end = F.location_to_position(location + 1);
            try self.appended.ensureUnusedCapacity(gpa, @intCast(end - self.size()));
            try self.append_leaf_digest(gpa, digest, location);
            assert(self.size() == end);
        }

        /// Appends a leaf and placeholders for the parents it creates (capacity reserved).
        fn append_leaf_digest(self: *Self, gpa: Allocator, digest: Digest, location: u64) !void {
            self.appended.appendAssumeCapacity(digest);
            var heights = F.parent_heights(location);
            while (heights.next()) |height| {
                try self.unhashed[height].append(gpa, self.size());
                self.appended.appendAssumeCapacity(std.mem.zeroes(Digest));
            }
            assert(F.is_valid_size(self.size()));
        }

        /// Adds leaves whose digests are already computed, in order.
        pub fn add_leaf_digests(self: *Self, gpa: Allocator, digests: []const Digest) !void {
            const first = self.leaves();
            const end = merkle.checked_add(first, digests.len, F.max_leaves) orelse
                return error.LocationOverflow;
            const end_size = F.location_to_position(end);
            try self.appended.ensureUnusedCapacity(gpa, @intCast(end_size - self.size()));
            for (digests, 0..) |digest, offset| {
                try self.append_leaf_digest(gpa, digest, first + offset);
            }
            assert(self.size() == end_size);
        }

        /// Adds `items` as leaves, each hashed from its codec encoding (the same as `add` on
        /// each encoding), hashing every new node whose leaves are all among them.
        pub fn add_many(
            self: *Self,
            gpa: Allocator,
            hasher: anytype,
            comptime Item: type,
            items: []const Item,
        ) !void {
            return self.add_many_with(gpa, hasher, Item, items, parallel.sequential);
        }

        /// `add_many` with the items split into ranges hashed across `strategy`. A node whose
        /// leaves span two ranges is left for `merkleize`; the digests match `add_many`.
        pub fn add_many_with(
            self: *Self,
            gpa: Allocator,
            hasher: anytype,
            comptime Item: type,
            items: []const Item,
            strategy: anytype,
        ) !void {
            if (items.len == 0) return;
            const first = self.leaves();
            if (self.add_many_start == null) self.add_many_start = first;
            const end = merkle.checked_add(first, items.len, F.max_leaves) orelse
                return error.LocationOverflow;
            const old_len = self.appended.items.len;
            const new_len: usize = @intCast(F.location_to_position(end) - self.parent.size());
            try self.appended.resize(gpa, new_len);
            const nodes = self.appended.items[old_len..];
            @memset(nodes, std.mem.zeroes(Digest));
            const ranges: AddRanges(Item, @TypeOf(hasher)) = .{
                .gpa = gpa,
                .hasher = hasher,
                .first = first,
                .items = items,
                .nodes = nodes,
            };
            var unhashed: [parallel.max_chunks]Levels = undefined;
            const run: AddRun(Item, @TypeOf(hasher)) = .{ .ranges = ranges, .unhashed = &unhashed };
            const count = try strategy.try_run_batches(items.len, 1, 1, run);
            // Each range's unhashed nodes are ascending and below the next range's.
            defer for (unhashed[0..count]) |*levels| levels_deinit(gpa, levels);
            for (unhashed[0..count]) |*levels| {
                for (levels, &self.unhashed) |level, *into| try into.appendSlice(gpa, level.items);
            }
            assert(self.leaves() == end);
        }

        fn validate_location(self: *const Self, location: u64) merkle.Error!void {
            if (location >= self.leaves()) return error.LeafOutOfBounds;
            if (location < self.parent.pruning_boundary) return error.ElementPruned;
        }

        /// Replaces the element of the leaf at `location`.
        pub fn update_leaf(
            self: *Self,
            gpa: Allocator,
            hasher: anytype,
            location: u64,
            element: []const u8,
        ) !void {
            try self.validate_location(location);
            const position = F.location_to_position(location);
            try self.store_leaf(gpa, location, hasher.leaf_digest(position, element));
        }

        /// Replaces the digest of the leaf at `location`.
        pub fn update_leaf_digest(
            self: *Self,
            gpa: Allocator,
            location: u64,
            digest: Digest,
        ) !void {
            try self.validate_location(location);
            try self.store_leaf(gpa, location, digest);
        }

        /// Replaces several leaf digests; validates them all first so a failure changes nothing.
        pub fn update_leaf_batched(self: *Self, gpa: Allocator, updates: []const LeafUpdate) !void {
            for (updates) |update| try self.validate_location(update.location);
            for (updates) |update| try self.store_leaf(gpa, update.location, update.digest);
        }

        /// Hashes the dirty nodes, reading committed ones from `base`, and returns the
        /// merkleized batch (one strong reference, for the caller). Consumes this batch on
        /// success; on error only `deinit` may follow.
        pub fn merkleize(self: *Self, gpa: Allocator, base: anytype, hasher: anytype) !*Parent {
            return self.merkleize_with(gpa, base, hasher, parallel.sequential);
        }

        /// `merkleize` with each height's nodes hashed across `strategy`. `hasher` and `base`
        /// must allow concurrent reads.
        pub fn merkleize_with(
            self: *Self,
            gpa: Allocator,
            base: anytype,
            hasher: anytype,
            strategy: anytype,
        ) !*Parent {
            var levels = try self.hash_plan(gpa);
            defer levels_deinit(gpa, &levels);
            for (&levels, 0..) |*level, height| {
                if (level.items.len == 0) continue;
                const positions = level.items;
                try self.merkleize_level(gpa, base, hasher, positions, @intCast(height), strategy);
            }
            const ancestors = try collect_ancestors(F, Digest, gpa, self.parent);
            errdefer release_all(gpa, ancestors);
            const data = try gpa.create(Parent.BatchData);
            errdefer gpa.destroy(data);
            const child = try gpa.create(Parent);
            data.* = .{
                .references = 1,
                .parent_size = self.parent.size(),
                .appended = self.appended,
                .overwrites = self.overwrites,
                .parent_peaks = self.parent.data.tip_peaks,
                .tip_peaks = self.tip_peaks(base),
            };
            self.parent.weak += 1;
            child.* = .{
                .strong = 1,
                .weak = 1,
                .parent = self.parent,
                .data = data,
                .base_size = self.parent.base_size,
                .pruning_boundary = self.parent.pruning_boundary,
                .ancestors = ancestors,
            };
            self.free_changes(gpa);
            self.parent.release(gpa);
            self.* = undefined;
            assert(child.strong == 1);
            return child;
        }

        fn release_all(gpa: Allocator, ancestors: []const *Parent.BatchData) void {
            for (ancestors) |ancestor| ancestor.release(gpa);
            gpa.free(ancestors);
        }

        /// The peaks after this batch's changes; a batch without changes shares its parent's.
        fn tip_peaks(self: *const Self, base: anytype) merkle.BoundedList(Digest, max_peaks) {
            if (self.appended.items.len == 0 and self.overwrites.count() == 0) {
                return self.parent.data.tip_peaks;
            }
            var peaks: merkle.BoundedList(Digest, max_peaks) = .{};
            var iterator = F.peaks(self.size());
            while (iterator.next()) |peak| {
                // Peaks are always in the batch chain or the committed structure.
                peaks.append(self.get_node(base, peak.position).?);
            }
            return peaks;
        }

        /// Every internal node to hash, once each, by height: the new unhashed nodes plus the
        /// ancestors of updated leaves. Takes `unhashed` from the batch.
        fn hash_plan(self: *Self, gpa: Allocator) !Levels {
            var levels = self.unhashed;
            self.unhashed = @splat(.empty);
            errdefer levels_deinit(gpa, &levels);
            var updated: std.ArrayList(u64) = .empty;
            defer updated.deinit(gpa);
            var keys = self.overwrites.keyIterator();
            while (keys.next()) |position| {
                // Only leaves are overwritten before merkleize.
                try updated.append(gpa, F.position_to_location(position.*).?);
            }
            if (self.add_many_start) |start| {
                var bits = self.updated_new_leaves.iterator(.{});
                while (bits.next()) |bit| try updated.append(gpa, start + bit);
            }
            if (updated.items.len == 0) return levels;
            std.mem.sort(u64, updated.items, {}, std.sort.asc(u64));
            try plan_dirty(F, gpa, self.size(), self.parent.size(), updated.items, &levels);
            return levels;
        }

        /// Hashes one height's nodes, two at a time so the hasher can pair them. The strategy
        /// splits the pairs into batches, so every pair reaches `node_digest_pair` together and
        /// only the last batch can end in a lone node; the digests are stored afterwards.
        fn merkleize_level(
            self: *Self,
            gpa: Allocator,
            base: anytype,
            hasher: anytype,
            positions: []const u64,
            height: u32,
            strategy: anytype,
        ) !void {
            assert(height > 0);
            assert(positions.len > 0);
            const digests = try gpa.alloc(Digest, positions.len);
            defer gpa.free(digests);
            const level: Level(@TypeOf(base), @TypeOf(hasher)) = .{
                .batch = self,
                .base = base,
                .hasher = hasher,
                .positions = positions,
                .digests = digests,
                .height = height,
            };
            const pairs = positions.len / 2 + positions.len % 2;
            strategy.run_batches(pairs, 1, 2, level);
            for (positions, digests) |position, digest| try self.store_node(gpa, position, digest);
        }

        /// One height's hashing, as a `run_batches` operation over its node pairs.
        fn Level(comptime Base: type, comptime HasherRef: type) type {
            return struct {
                batch: *const Self,
                base: Base,
                hasher: HasherRef,
                positions: []const u64,
                digests: []Digest,
                height: u32,

                pub fn run(level: @This(), batches: anytype) void {
                    if (batches.is_whole()) {
                        return level.map(0, .{ .start = 0, .end = batches.len });
                    }
                    var done: [parallel.max_chunks]void = undefined;
                    batches.map_collect(done[0..batches.count()], level);
                }

                /// Hashes the nodes of pairs `range`.
                pub fn map(level: @This(), _: usize, range: parallel.Range) void {
                    const end = @min(2 * range.end, level.positions.len);
                    const positions = level.positions[2 * range.start .. end];
                    const digests = level.digests[2 * range.start .. end];
                    assert(positions.len > 0);
                    var index: usize = 0;
                    while (index + 1 < positions.len) : (index += 2) {
                        const left = level.children(positions[index]);
                        const right = level.children(positions[index + 1]);
                        digests[index..][0..2].* = level.hasher.node_digest_pair(.{
                            .{ .position = positions[index], .left = &left[0], .right = &left[1] },
                            .{
                                .position = positions[index + 1],
                                .left = &right[0],
                                .right = &right[1],
                            },
                        });
                    }
                    if (index < positions.len) {
                        const position = positions[index];
                        const children_digests = level.children(position);
                        const left = &children_digests[0];
                        const right = &children_digests[1];
                        digests[index] = level.hasher.node_digest(position, left, right);
                    }
                }

                fn children(level: @This(), position: u64) [2]Digest {
                    return level.batch.child_digests(level.base, position, level.height);
                }
            };
        }

        /// `add_many`'s ranges: range `i` hashes its items into its own slice of `nodes`.
        fn AddRanges(comptime Item: type, comptime HasherRef: type) type {
            return struct {
                gpa: Allocator,
                hasher: HasherRef,
                first: u64,
                items: []const Item,
                nodes: []Digest,

                pub fn map(
                    ranges: @This(),
                    _: usize,
                    range: parallel.Range,
                ) Allocator.Error!Levels {
                    const range_first = ranges.first + range.start;
                    const start = F.location_to_position(range_first) -
                        F.location_to_position(ranges.first);
                    const stop = F.location_to_position(ranges.first + range.end) -
                        F.location_to_position(ranges.first);
                    assert(start < stop and stop <= ranges.nodes.len);
                    const nodes = ranges.nodes[@intCast(start)..@intCast(stop)];
                    const range_items = ranges.items[range.start..range.end];
                    var levels: Levels = @splat(.empty);
                    errdefer levels_deinit(ranges.gpa, &levels);
                    const gpa = ranges.gpa;
                    const hasher = ranges.hasher;
                    try build_range(F, gpa, hasher, Item, range_first, range_items, nodes, &levels);
                    return levels;
                }

                pub fn discard(ranges: @This(), levels: Levels) void {
                    var owned = levels;
                    levels_deinit(ranges.gpa, &owned);
                }
            };
        }

        /// The `run_batches` operation of `add_many`: returns how many ranges it hashed, each
        /// range's unhashed nodes in `unhashed`.
        fn AddRun(comptime Item: type, comptime HasherRef: type) type {
            return struct {
                ranges: AddRanges(Item, HasherRef),
                unhashed: *[parallel.max_chunks]Levels,

                pub fn run(op: @This(), batches: anytype) Allocator.Error!usize {
                    const count = batches.count();
                    assert(count >= 1 and count <= parallel.max_chunks);
                    if (batches.is_whole()) {
                        op.unhashed[0] = try op.ranges.map(0, .{ .start = 0, .end = batches.len });
                        return 1;
                    }
                    try batches.try_map_collect(op.unhashed[0..count], op.ranges);
                    return count;
                }
            };
        }

        fn child_digests(self: *const Self, base: anytype, position: u64, height: u32) [2]Digest {
            const children = F.children(position, height);
            // A missing child means an unapplied ancestor was released, or `base` was pruned
            // past an updated leaf (see the module docs).
            const left = self.get_node(base, children.left).?;
            const right = self.get_node(base, children.right).?;
            return .{ left, right };
        }
    };
}

/// Adds to `levels` the ancestors of the `updated` leaves (sorted, distinct) in a structure of
/// `size` nodes, once each, except those `levels` already lists as new unhashed nodes.
fn plan_dirty(
    comptime F: type,
    gpa: Allocator,
    size: u64,
    parent_size: u64,
    updated: []const u64,
    levels: *Levels,
) !void {
    var dirty: Levels = @splat(.empty);
    defer levels_deinit(gpa, &dirty);
    const Frame = struct { position: u64, height: u32, first_leaf: u64 };
    var cursor: usize = 0;
    var first_leaf: u64 = 0;
    var peaks = F.peaks(size);
    while (peaks.next()) |peak| {
        if (cursor == updated.len) break;
        var stack: merkle.BoundedList(Frame, 2 * max_height) = .{};
        const root: Frame = .{
            .position = peak.position,
            .height = peak.height,
            .first_leaf = first_leaf,
        };
        stack.append(root);
        first_leaf += @as(u64, 1) << @intCast(peak.height);
        while (stack.pop()) |frame| {
            if (cursor == updated.len) break;
            const span = @as(u64, 1) << @intCast(frame.height);
            if (updated[cursor] >= frame.first_leaf + span) continue; // No updated leaf below.
            assert(updated[cursor] >= frame.first_leaf);
            if (frame.height == 0) {
                cursor += 1;
                continue;
            }
            const new = frame.position >= parent_size;
            const unhashed = levels[frame.height].items;
            if (!new or std.sort.binarySearch(u64, unhashed, frame.position, order) == null) {
                try dirty[frame.height].append(gpa, frame.position);
            }
            const children = F.children(frame.position, frame.height);
            const half = span / 2;
            const height = frame.height - 1;
            const right: Frame = .{
                .position = children.right,
                .height = height,
                .first_leaf = frame.first_leaf + half,
            };
            stack.append(right);
            const left: Frame = .{
                .position = children.left,
                .height = height,
                .first_leaf = frame.first_leaf,
            };
            stack.append(left);
        }
    }
    assert(cursor == updated.len); // Every updated leaf lies inside the batch.
    for (levels, &dirty) |*level, *extra| try level.appendSlice(gpa, extra.items);
}

fn order(target: u64, item: u64) std.math.Order {
    return std.math.order(target, item);
}

/// Hashes the leaves `items` (from leaf `first`) into `nodes` (the batch's nodes from the
/// first leaf's position), plus every new internal node whose leaves all lie in the range. The
/// others, which also cover earlier leaves, go to `unhashed` for `merkleize`.
fn build_range(
    comptime F: type,
    gpa: Allocator,
    hasher: anytype,
    comptime Item: type,
    first: u64,
    items: []const Item,
    nodes: anytype,
    unhashed: *Levels,
) !void {
    const first_position = F.location_to_position(first);
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(gpa);
    // Left children waiting for their right sibling, by height, so the two hash as a pair.
    var waiting: [max_height]?u64 = @splat(null);
    var position = first_position;
    for (items, 0..) |*item, offset| {
        const location = first + offset;
        try scratch.resize(gpa, codec.encode_size(Item, item.*));
        var writer = codec.Writer.init(scratch.items);
        codec.write(Item, item.*, &writer);
        assert(writer.written().len == scratch.items.len);
        nodes[@intCast(position - first_position)] = hasher.leaf_digest(position, scratch.items);
        var heights = F.parent_heights(location);
        while (heights.next()) |height| {
            position += 1;
            // The count is now `location + 1`, `birth_offset` past the node's leftmost leaf.
            const leftmost = location + 1 - F.birth_offset(height);
            if (leftmost < first) {
                try unhashed[height].append(gpa, position);
            } else if ((leftmost >> @intCast(height)) % 2 == 0) {
                assert(waiting[height] == null);
                waiting[height] = position;
            } else {
                hash_right(F, hasher, nodes, first_position, &waiting[height], position, height);
            }
        }
        position += 1;
    }
    for (waiting, 0..) |left, height| {
        const node = left orelse continue;
        const children = range_children(F, nodes, first_position, node, @intCast(height));
        const index: usize = @intCast(node - first_position);
        nodes[index] = hasher.node_digest(node, &children[0], &children[1]);
    }
    assert(position == F.location_to_position(first + items.len));
}

fn range_children(
    comptime F: type,
    nodes: anytype,
    first_position: u64,
    position: u64,
    height: u32,
) [2]@typeInfo(@TypeOf(nodes)).pointer.child {
    const children = F.children(position, height);
    assert(children.left >= first_position and children.right >= first_position);
    return .{
        nodes[@intCast(children.left - first_position)],
        nodes[@intCast(children.right - first_position)],
    };
}

/// Hashes a right child, paired with its waiting left sibling when there is one.
fn hash_right(
    comptime F: type,
    hasher: anytype,
    nodes: anytype,
    first_position: u64,
    waiting: *?u64,
    position: u64,
    height: u32,
) void {
    const right = range_children(F, nodes, first_position, position, height);
    const right_index: usize = @intCast(position - first_position);
    const left = waiting.* orelse {
        nodes[right_index] = hasher.node_digest(position, &right[0], &right[1]);
        return;
    };
    waiting.* = null;
    const left_children = range_children(F, nodes, first_position, left, height);
    const digests = hasher.node_digest_pair(.{
        .{ .position = left, .left = &left_children[0], .right = &left_children[1] },
        .{ .position = position, .left = &right[0], .right = &right[1] },
    });
    nodes[@intCast(left - first_position)] = digests[0];
    nodes[right_index] = digests[1];
}

// Commonware's `assert_plan_is_exact` tests: `hash_plan` lists each node that needs hashing
// once, namely every unhashed new node plus the ancestors of each updated leaf. They call the
// private `hash_plan`, so they live here.

const testing = std.testing;
const TestDigest = @import("cryptography").Sha256.Digest;
const test_gpa = testing.allocator;
const test_hasher = hasher_module.Standard(@import("cryptography").Sha256).init(.forward_fold);

fn test_fill(byte: u8) TestDigest {
    return .{ .bytes = @splat(byte) };
}

fn insert_pair(gpa: Allocator, list: *std.ArrayList([2]u64), height: u64, position: u64) !void {
    try list.append(gpa, .{ height, position });
}

fn sort_pairs(pairs: [][2]u64) void {
    std.mem.sort([2]u64, pairs, {}, struct {
        fn less(_: void, a: [2]u64, b: [2]u64) bool {
            return a[0] < b[0] or (a[0] == b[0] and a[1] < b[1]);
        }
    }.less);
}

/// The internal nodes on the path from the peak covering `location` down to it.
fn insert_path(comptime F: type, size: u64, location: u64, out: *std.ArrayList([2]u64)) !void {
    var first_leaf: u64 = 0;
    var peaks = F.peaks(size);
    while (peaks.next()) |peak| {
        const end = first_leaf + (@as(u64, 1) << @intCast(peak.height));
        if (location >= end) {
            first_leaf = end;
            continue;
        }
        var node = peak;
        while (node.height > 0) {
            try insert_pair(test_gpa, out, node.height, node.position);
            const children = F.children(node.position, node.height);
            const half = @as(u64, 1) << @intCast(node.height - 1);
            const left = location < first_leaf + half;
            if (!left) first_leaf += half;
            const next = if (left) children.left else children.right;
            node = .{ .position = next, .height = node.height - 1 };
        }
        return;
    }
    unreachable; // Every updated leaf lies in the batch.
}

fn expect_plan_exact(
    comptime F: type,
    batch: *Unmerkleized(F, TestDigest),
    updates: []const u64,
) !void {
    var expected: std.ArrayList([2]u64) = .empty;
    defer expected.deinit(test_gpa);
    const zero = std.mem.zeroes(TestDigest);
    for (batch.appended.items, batch.parent.size()..) |digest, position| {
        if (F.position_to_location(position) != null or !digest.eql(zero)) continue;
        try insert_pair(test_gpa, &expected, F.pos_to_height(position), position);
    }
    for (updates) |location| try insert_path(F, batch.size(), location, &expected);
    sort_pairs(expected.items);
    var unique: usize = 0;
    for (expected.items) |pair| {
        if (unique > 0 and std.mem.eql(u64, &expected.items[unique - 1], &pair)) continue;
        expected.items[unique] = pair;
        unique += 1;
    }
    var levels = try batch.hash_plan(test_gpa);
    defer levels_deinit(test_gpa, &levels);
    var actual: std.ArrayList([2]u64) = .empty;
    defer actual.deinit(test_gpa);
    for (levels, 0..) |level, height| {
        for (level.items) |position| try insert_pair(test_gpa, &actual, height, position);
    }
    sort_pairs(actual.items);
    try testing.expectEqual(unique, actual.items.len);
    for (expected.items[0..unique], actual.items) |e, a| try testing.expectEqualSlices(u64, &e, &a);
}

fn hash_plan_is_exact(comptime F: type) !void {
    var base: @import("mem.zig").Mem(F, TestDigest) = .empty;
    defer base.deinit(test_gpa);
    for (0..37) |i| try base.add_leaf_digest(test_gpa, &test_hasher, test_fill(@intCast(i)));
    var all: [37]u64 = undefined;
    for (&all, 0..) |*location, i| location.* = i;
    const Case = struct { updates: []const u64, appends: u8 };
    const cases = [_]Case{
        .{ .updates = &.{ 0, 1, 2 }, .appends = 0 },
        .{ .updates = &.{ 36, 5, 5, 20, 0 }, .appends = 0 },
        .{ .updates = &.{ 3, 36 }, .appends = 1 },
        .{ .updates = &.{ 7, 36 }, .appends = 5 },
        .{ .updates = &all, .appends = 3 },
    };
    for (cases) |case| {
        var batch = try base.new_batch(test_gpa);
        defer batch.deinit(test_gpa);
        for (case.updates) |location| {
            try batch.update_leaf_digest(test_gpa, location, test_fill(0xaa));
        }
        for (0..case.appends) |i| {
            try batch.add_leaf_digest(test_gpa, test_fill(0xbb + @as(u8, @intCast(i))));
        }
        try expect_plan_exact(F, &batch, case.updates);
    }
}

/// Adds commonware's test elements `from..to`: the digest of each index as big-endian bytes.
fn add_be_elements(comptime F: type, mem: anytype, from: u64, to: u64) !void {
    for (from..to) |i| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, i, .big);
        try mem.add(test_gpa, &test_hasher, &test_hasher.digest(&bytes).bytes);
    }
    assert(F.position_to_location(mem.size()).? >= to);
}

fn add_many_records_updates_once(comptime F: type) !void {
    var base: @import("mem.zig").Mem(F, TestDigest) = .empty;
    defer base.deinit(test_gpa);
    try add_be_elements(F, &base, 0, 31);
    var digests: [64]TestDigest = undefined;
    for (&digests, 0..) |*digest, i| digest.* = test_fill(@intCast(i));
    var batch = try base.new_batch(test_gpa);
    defer batch.deinit(test_gpa);
    try batch.add_leaf_digests(test_gpa, &digests);
    var updates: [64]u64 = undefined;
    for (&updates, 31..) |*location, i| location.* = i;
    for (updates) |location| try batch.update_leaf_digest(test_gpa, location, test_fill(0xaa));
    try testing.expectEqual(@as(usize, 0), batch.updated_new_leaves.count());
    try expect_plan_exact(F, &batch, &updates);

    var items: [300]u64 = undefined;
    for (&items, 0..) |*item, i| item.* = i;
    var mixed = try base.new_batch(test_gpa);
    defer mixed.deinit(test_gpa);
    try mixed.add(test_gpa, &test_hasher, "before");
    try mixed.add_many(test_gpa, &test_hasher, u64, items[0..100]);
    try mixed.add(test_gpa, &test_hasher, "after");
    const mixed_updates = [_]u64{ 31, 32, 80, 131, 132, 80 };
    for (mixed_updates) |location| {
        try mixed.update_leaf_digest(test_gpa, location, test_fill(0xaa));
    }
    try expect_plan_exact(F, &mixed, &mixed_updates);

    var repeated = try base.new_batch(test_gpa);
    defer repeated.deinit(test_gpa);
    try repeated.add(test_gpa, &test_hasher, "before");
    try repeated.add_many(test_gpa, &test_hasher, u64, items[0..2]);
    for (0..1000) |i| {
        try repeated.update_leaf_digest(test_gpa, 32 + i % 2, test_fill(@truncate(i)));
    }
    try testing.expectEqual(@as(usize, 2), repeated.updated_new_leaves.bit_length);
    try testing.expectEqual(@as(usize, 2), repeated.updated_new_leaves.count());
    try expect_plan_exact(F, &repeated, &.{ 32, 33 });

    // Updates around two add_many runs (commonware's `add_many_hash_plan_is_exact`).
    try add_be_elements(F, &base, 31, 37);
    const cases = [_][]const u64{
        &.{},
        &.{40},
        &.{ 36, 37, 337, 37 },
        &.{ 0, 100, 101, 200, 336 },
        &.{ 5, 50, 150, 237, 238, 250, 300 },
    };
    for (cases) |case| {
        var split = try base.new_batch(test_gpa);
        defer split.deinit(test_gpa);
        try split.update_leaf_digest(test_gpa, 20, test_fill(0xbb));
        try split.add_many(test_gpa, &test_hasher, u64, items[0..200]);
        try split.add(test_gpa, &test_hasher, "between");
        try split.add_many(test_gpa, &test_hasher, u64, items[200..]);
        var with_twenty: [8]u64 = undefined;
        for (case, 0..) |location, i| {
            try split.update_leaf_digest(test_gpa, location, test_fill(0xaa));
            with_twenty[i] = location;
        }
        with_twenty[case.len] = 20;
        try expect_plan_exact(F, &split, with_twenty[0 .. case.len + 1]);
    }
}

test "hash_plan lists each node to hash exactly once" {
    inline for (.{ @import("mmr/mod.zig").Family, @import("mmb/mod.zig").Family }) |F| {
        try hash_plan_is_exact(F);
        try add_many_records_updates_once(F);
    }
}
