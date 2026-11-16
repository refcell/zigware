//! An interim authenticated journal (commonware's `journal/authenticated.rs` `Journal`): a
//! contiguous journal of items paired with a persisted Merkle structure whose leaf `i` is item
//! `i`.
//!
//! The storage-journal lane is porting the real one as `storage.journal.authenticated.Journal`;
//! this one follows its planned API (method names, batch lifecycle, `prepare`/`finish`
//! recovery) so the databases switch over by changing one import. Until then it backs the
//! QMDB variants with the fixed and variable contiguous journals.
//!
//! Batch items are shallow copies: the caller keeps any memory they borrow alive until the
//! batch is applied or released. Syncs complete synchronously, so `start_sync` returns no
//! handle. After a storage error only `deinit` may follow.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const merkle = @import("../merkle/mod.zig");
const journal_mod = @import("../journal/mod.zig");

const backing = journal_mod.authenticated;
const Storage = runtime.storage.Storage;
const Bounds = journal_mod.contiguous.Bounds;
const max_pins = merkle.max_pinned_nodes;

/// Items replayed per Merkle batch while aligning the Merkle structure with the journal.
const apply_batch_size: u64 = 1 << 16;

pub fn Journal(comptime F: type, comptime C: type, comptime Hash: type) type {
    backing.assert_backing(C);
    return struct {
        const Self = @This();
        pub const Item = C.BackingRecovery.Item;
        pub const Digest = Hash.Digest;
        pub const Merkle = merkle.full.Merkle(F, Digest);
        pub const Hasher = merkle.hasher.Standard(Hash);
        pub const Proof = Merkle.Proof;
        const InnerBatch = Merkle.Mem.Batch;
        const InnerMerkleized = Merkle.MerkleizedBatch;

        gpa: Allocator,
        merkle: Merkle,
        /// The backing journal; public for replay.
        journal: C,
        hasher: Hasher,

        pub fn deinit(self: *Self) void {
            self.journal.deinit();
            self.merkle.deinit();
            self.* = undefined;
        }

        /// The number of items ever appended (the next item's location).
        pub fn size(self: *const Self) u64 {
            return self.journal.size();
        }

        pub fn get_bounds(self: *const Self) Bounds {
            return self.journal.get_bounds();
        }

        /// The item at `location`; the caller owns it.
        pub fn read(self: *Self, location: u64) !Item {
            return self.journal.read(location);
        }

        /// The items at strictly increasing `locations` into `out`; the caller owns them.
        pub fn read_many(self: *Self, locations: []const u64, out: []Item) !void {
            assert(locations.len == out.len);
            try self.journal.read_many(locations, out);
        }

        /// The root with the oldest `inactive_peaks` peaks folded.
        pub fn root(self: *const Self, inactive_peaks: usize) !Digest {
            return self.merkle.root(&self.hasher, inactive_peaks);
        }

        /// Appends `item` to the journal and the Merkle structure, returning its location.
        pub fn append(self: *Self, item: Item) !u64 {
            const location = try self.journal.append(item);
            try add_leaves(self.gpa, &self.merkle, &self.hasher, &.{item});
            assert(self.merkle.leaves() == self.journal.size());
            return location;
        }

        /// Adds `items` to `structure` as leaves.
        fn add_leaves(
            gpa: Allocator,
            structure: *Merkle,
            hasher: *const Hasher,
            items: []const Item,
        ) !void {
            var batch = try structure.mem.new_batch(gpa);
            // Merkleizing consumes the batch only on success.
            const merkleized = merkleized: {
                errdefer batch.deinit(gpa);
                try batch.add_many(gpa, hasher, Item, items);
                break :merkleized try batch.merkleize(gpa, &structure.mem, hasher);
            };
            defer merkleized.release(gpa);
            try structure.apply_batch(merkleized);
        }

        /// Makes appended items durable in the journal and flushes Merkle nodes; a crash
        /// recovers both from the journal.
        pub fn commit(self: *Self) !void {
            try self.journal.commit();
            try self.merkle.flush();
        }

        /// Makes the journal and the Merkle structure fully durable.
        pub fn sync(self: *Self) !void {
            try self.journal.sync();
            try self.merkle.sync();
        }

        /// Starts a full sync (it completes at once here).
        pub fn start_sync(self: *Self) !void {
            try self.journal.start_sync();
            try self.merkle.start_sync();
        }

        /// Prunes items below `location` where the journal allows it (section granularity),
        /// then the Merkle structure to the journal's new start. Returns the retained start.
        pub fn prune(self: *Self, location: u64) !u64 {
            if (self.merkle.size() == 0) return self.journal.get_bounds().start;
            try self.journal.commit();
            try self.merkle.sync();
            _ = try self.journal.prune(location);
            const boundary = self.journal.get_bounds().start;
            if (boundary > self.merkle.bounds().start) try self.merkle.prune(boundary);
            assert(self.merkle.bounds().start >= boundary);
            return boundary;
        }

        /// Removes all storage and frees the journal, also on error.
        pub fn destroy(self: *Self) !void {
            defer self.* = undefined;
            self.journal.destroy() catch |err| {
                self.merkle.deinit();
                return err;
            };
            try self.merkle.destroy();
        }

        /// A batch built on the committed state.
        pub fn new_batch(self: *const Self) !Batch {
            return .{
                .gpa = self.gpa,
                .hasher = self.hasher,
                .inner = try self.merkle.mem.new_batch(self.gpa),
                .parent = null,
            };
        }

        /// A merkleized batch representing the committed state (no items).
        pub fn to_merkleized_batch(self: *const Self) !*MerkleizedBatch {
            const batch = try self.gpa.create(MerkleizedBatch);
            errdefer self.gpa.destroy(batch);
            const chunk = try Chunk.create(self.gpa, self.size(), &.{});
            errdefer chunk.release(self.gpa);
            const inner = try self.merkle.to_batch();
            batch.init(self.gpa, self.hasher, inner, chunk, &.{}, null);
            return batch;
        }

        /// Appends the items of `batch` and its unapplied ancestors. Fails, changing nothing,
        /// with `StaleBatch` or `AncestorDropped` (see `Mem.apply_batch`).
        pub fn apply_batch(self: *Self, batch: *const MerkleizedBatch) !void {
            try self.merkle.apply_batch(batch.inner);
            // The Merkle structure accepted the chain, so the chunks from the journal's end on
            // are retained: they were collected with the same liveness as the nodes.
            var next = self.journal.size();
            for (batch.ancestor_items) |chunk| try self.append_chunk(chunk, &next);
            try self.append_chunk(batch.items, &next);
            assert(next == batch.size());
            assert(self.merkle.leaves() == self.journal.size());
        }

        fn append_chunk(self: *Self, chunk: *const Chunk, next: *u64) !void {
            if (chunk.end <= next.*) return;
            assert(chunk.start() == next.*);
            if (chunk.items.len > 0) _ = try self.journal.append_many(chunk.items);
            next.* = chunk.end;
        }

        /// A proof of `[start, min(start + max_items, historical_size))` against the root at
        /// `historical_size`, and those items. The caller owns both.
        pub fn historical_proof(
            self: *Self,
            historical_size: u64,
            start: u64,
            max_items: u64,
            inactive_peaks: usize,
        ) !ProofItems {
            assert(max_items > 0);
            if (historical_size > self.size()) return error.RangeOutOfBounds;
            if (start >= historical_size) return error.RangeOutOfBounds;
            const end = @min(historical_size, start +| max_items);
            const range: merkle.Range = .{ .start = start, .end = end };
            var proof_value = try self.merkle.historical_range_proof(
                &self.hasher,
                historical_size,
                range,
                inactive_peaks,
            );
            errdefer proof_value.deinit(self.gpa);
            const items = try self.gpa.alloc(Item, @intCast(end - start));
            errdefer self.gpa.free(items);
            const locations = try self.gpa.alloc(u64, items.len);
            defer self.gpa.free(locations);
            for (locations, start..) |*location, value| location.* = value;
            try self.journal.read_many(locations, items);
            return .{ .proof = proof_value, .items = items };
        }

        /// `historical_proof` against the current root.
        pub fn proof(self: *Self, start: u64, max_items: u64, inactive_peaks: usize) !ProofItems {
            return self.historical_proof(self.size(), start, max_items, inactive_peaks);
        }

        /// A proof of `batch`'s own items against its root.
        pub fn speculative_proof(
            self: *const Self,
            batch: *const MerkleizedBatch,
            inactive_peaks: usize,
        ) !Proof {
            const range: merkle.Range = .{ .start = batch.items.start(), .end = batch.size() };
            assert(range.end == batch.inner.leaves());
            const base = &self.merkle.mem;
            return batch.inner.range_proof(self.gpa, base, &self.hasher, range, inactive_peaks);
        }

        /// The pins of `batch`'s first item, from the batch chain or the committed structure.
        pub fn speculative_pinned_nodes(
            self: *const Self,
            batch: *const MerkleizedBatch,
            out: *[max_pins]Digest,
        ) ![]Digest {
            var positions_buffer: [max_pins]u64 = undefined;
            const positions = merkle.nodes_to_pin(F, batch.items.start(), &positions_buffer);
            for (positions, out[0..positions.len]) |position, *digest| {
                digest.* = batch.inner.get_node(position) orelse
                    self.merkle.mem.get_node(position) orelse return error.ElementPruned;
            }
            return out[0..positions.len];
        }

        /// A proof and the items it covers.
        pub const ProofItems = struct {
            proof: Proof,
            items: []Item,

            pub fn deinit(self: *ProofItems, gpa: Allocator) void {
                self.proof.deinit(gpa);
                codec.free_items(Item, gpa, self.items);
                gpa.free(self.items);
                self.* = undefined;
            }
        };

        /// A batch's items, shared with the descendants merkleized while it lived
        /// (commonware's `Arc<Vec<Item>>`).
        pub const Chunk = struct {
            references: u32,
            /// The journal size after these items.
            end: u64,
            items: []Item,

            fn create(gpa: Allocator, end: u64, items: []const Item) !*Chunk {
                assert(items.len <= end);
                const chunk = try gpa.create(Chunk);
                errdefer gpa.destroy(chunk);
                chunk.* = .{ .references = 1, .end = end, .items = try gpa.dupe(Item, items) };
                return chunk;
            }

            pub fn start(self: *const Chunk) u64 {
                return self.end - self.items.len;
            }

            fn retain(self: *Chunk) *Chunk {
                assert(self.references > 0);
                self.references += 1;
                return self;
            }

            fn release(self: *Chunk, gpa: Allocator) void {
                assert(self.references > 0);
                self.references -= 1;
                if (self.references > 0) return;
                gpa.free(self.items);
                gpa.destroy(self);
            }
        };

        /// A batch whose items are not hashed yet.
        pub const Batch = struct {
            gpa: Allocator,
            hasher: Hasher,
            inner: InnerBatch,
            items: std.ArrayList(Item) = .empty,
            /// A strong reference to the parent, null for a batch on the committed state.
            parent: ?*MerkleizedBatch,

            /// Discards the batch.
            pub fn deinit(self: *Batch) void {
                self.inner.deinit(self.gpa);
                self.items.deinit(self.gpa);
                if (self.parent) |parent| parent.release();
                self.* = undefined;
            }

            /// The item count after this batch.
            pub fn size(self: *const Batch) u64 {
                return self.inner.leaves();
            }

            pub fn add(self: *Batch, item: Item) !void {
                try self.add_many(&.{item});
            }

            pub fn add_many(self: *Batch, items: []const Item) !void {
                try self.items.ensureUnusedCapacity(self.gpa, items.len);
                try self.inner.add_many(self.gpa, &self.hasher, Item, items);
                self.items.appendSliceAssumeCapacity(items);
                assert(self.items.items.len <= self.size());
            }

            /// Hashes the batch against `journal`'s committed structure. Consumes the batch on
            /// success; on error only `deinit` may follow.
            pub fn merkleize(self: *Batch, journal: *const Self) !*MerkleizedBatch {
                const gpa = self.gpa;
                // Allocate everything first: merkleizing consumes `inner` and cannot fail after.
                const merkleized = try gpa.create(MerkleizedBatch);
                errdefer gpa.destroy(merkleized);
                const ancestors = try collect_ancestor_items(gpa, self.parent);
                errdefer release_chunks(gpa, ancestors);
                const chunk = try Chunk.create(gpa, self.size(), self.items.items);
                errdefer chunk.release(gpa);
                const base = &journal.merkle.mem;
                const inner = try self.inner.merkleize(gpa, base, &self.hasher);
                merkleized.init(gpa, self.hasher, inner, chunk, ancestors, self.parent);
                self.items.deinit(gpa);
                // The child holds a weak link now; drop the strong one this batch held.
                if (self.parent) |parent| parent.release();
                self.* = undefined;
                return merkleized;
            }
        };

        fn release_chunks(gpa: Allocator, chunks: []const *Chunk) void {
            for (chunks) |chunk| chunk.release(gpa);
            gpa.free(chunks);
        }

        /// The non-empty item chunks of `parent` and its live ancestors, oldest first, each
        /// retained.
        fn collect_ancestor_items(gpa: Allocator, parent: ?*MerkleizedBatch) ![]const *Chunk {
            var chunks: std.ArrayList(*Chunk) = .empty;
            errdefer chunks.deinit(gpa);
            var current = parent;
            while (current) |batch| : (current = batch.live_parent()) {
                if (batch.items.items.len > 0) try chunks.append(gpa, batch.items);
            }
            std.mem.reverse(*Chunk, chunks.items);
            const owned = try chunks.toOwnedSlice(gpa);
            for (owned) |chunk| _ = chunk.retain();
            assert(owned.len <= std.math.maxInt(u32));
            return owned;
        }

        /// A merkleized batch, reference counted like the Merkle batches it wraps.
        pub const MerkleizedBatch = struct {
            gpa: Allocator,
            hasher: Hasher,
            /// Strong references; the batch's items live while this is non-zero.
            strong: u32,
            /// Weak references (children's parent links) plus one shared by the strong ones.
            weak: u32,
            parent: ?*MerkleizedBatch,
            inner: *InnerMerkleized,
            items: *Chunk,
            /// The items of the non-empty ancestors live at merkleize, oldest first.
            ancestor_items: []const *Chunk,

            /// Takes ownership of `inner`, `items`, and `ancestor_items`, and a weak link to
            /// `parent`.
            fn init(
                self: *MerkleizedBatch,
                gpa: Allocator,
                hasher: Hasher,
                inner: *InnerMerkleized,
                items: *Chunk,
                ancestor_items: []const *Chunk,
                parent: ?*MerkleizedBatch,
            ) void {
                assert(items.end == inner.leaves());
                assert(ancestor_items.len == 0 or ancestor_items[ancestor_items.len - 1].end <=
                    items.start());
                self.* = .{
                    .gpa = gpa,
                    .hasher = hasher,
                    .strong = 1,
                    .weak = 1,
                    .parent = parent,
                    .inner = inner,
                    .items = items,
                    .ancestor_items = ancestor_items,
                };
                if (parent) |link| link.weak += 1;
            }

            pub fn retain(self: *MerkleizedBatch) *MerkleizedBatch {
                assert(self.strong > 0);
                self.strong += 1;
                return self;
            }

            /// Drops a strong reference; the last one frees the batch's items unless a
            /// merkleized descendant holds them.
            pub fn release(self: *MerkleizedBatch) void {
                assert(self.strong > 0);
                self.strong -= 1;
                if (self.strong > 0) return;
                const gpa = self.gpa;
                self.inner.release(gpa);
                self.items.release(gpa);
                release_chunks(gpa, self.ancestor_items);
                if (self.parent) |parent| parent.release_weak();
                self.parent = null;
                self.release_weak();
            }

            fn release_weak(self: *MerkleizedBatch) void {
                assert(self.weak > 0);
                self.weak -= 1;
                if (self.weak == 0) self.gpa.destroy(self);
            }

            /// The parent, if it is still alive.
            fn live_parent(self: *const MerkleizedBatch) ?*MerkleizedBatch {
                const parent = self.parent orelse return null;
                assert(parent.weak > 0);
                return if (parent.strong > 0) parent else null;
            }

            /// The item count after this batch.
            pub fn size(self: *const MerkleizedBatch) u64 {
                return self.items.end;
            }

            /// This batch's own items.
            pub fn get_items(self: *const MerkleizedBatch) []const Item {
                return self.items.items;
            }

            pub fn root(self: *const MerkleizedBatch, inactive_peaks: usize) !Digest {
                return self.inner.root(&self.hasher, inactive_peaks);
            }

            /// A child batch on top of this one.
            pub fn new_batch(self: *MerkleizedBatch) Batch {
                return .{
                    .gpa = self.gpa,
                    .hasher = self.hasher,
                    .inner = self.inner.new_batch(),
                    .parent = self.retain(),
                };
            }
        };

        /// Recovery state between `prepare` and `finish`.
        pub const Recovery = struct {
            gpa: Allocator,
            journal: C.BackingRecovery,
            merkle: Merkle.Recovery,
            hasher: Hasher,
            /// The end of the prefix recovery retains.
            selected_end: u64,

            pub fn deinit(self: *Recovery) void {
                self.journal.deinit();
                self.merkle.deinit();
                self.* = undefined;
            }

            /// `[retained start, selected end)`.
            pub fn bounds(self: *const Recovery) Bounds {
                return .{ .start = self.journal.get_bounds().start, .end = self.selected_end };
            }

            /// Whether the journal holds no items and was never pruned.
            pub fn is_fresh(self: *const Recovery) bool {
                const span = self.journal.get_bounds();
                return span.start == 0 and span.end == 0;
            }

            pub fn read(self: *Recovery, location: u64) !Item {
                return self.journal.read(location);
            }

            /// Truncates the journal to the selected prefix, aligns the Merkle structure with
            /// it, and publishes both. Consumes the recovery, also on error.
            pub fn finish(self: *Recovery) !Self {
                const gpa = self.gpa;
                const hasher = self.hasher;
                var journal = journal: {
                    errdefer self.merkle.deinit();
                    var journal = try self.journal.finish(self.selected_end);
                    errdefer journal.deinit();
                    try journal.sync();
                    break :journal journal;
                };
                errdefer journal.deinit();
                var structure = try self.merkle.finish();
                errdefer structure.deinit();
                try align_merkle(gpa, &structure, &journal, &hasher);
                try structure.sync();
                self.* = undefined;
                return .{ .gpa = gpa, .merkle = structure, .journal = journal, .hasher = hasher };
            }
        };

        /// Opens storage and selects the prefix ending at the last item satisfying
        /// `predicate` within `max_size`, without publishing anything.
        pub fn prepare(
            gpa: Allocator,
            storage: Storage,
            merkle_cfg: merkle.full.Config,
            journal_cfg: C.BackingConfig,
            max_size: ?u64,
            comptime predicate: fn (Item) bool,
            bagging: merkle.Bagging,
        ) !Recovery {
            var journal = try C.recover(gpa, storage, journal_cfg, max_size);
            errdefer journal.deinit();
            const span = journal.get_bounds();
            const Matcher = struct {
                fn matches(item_gpa: Allocator, item: Item) bool {
                    defer codec.free(Item, item_gpa, item);
                    return predicate(item);
                }
            };
            const ceiling = max_size orelse std.math.maxInt(u64);
            const selected_end = if (max_size == null and span.start == span.end)
                span.end
            else
                try backing.last_matching(&journal, ceiling, gpa, Matcher.matches);
            const hasher = Hasher.init(bagging);
            const retain: merkle.full.Retain = if (span.start == 0 and selected_end == 0)
                .nothing
            else
                .{ .at_most = selected_end };
            var structure = try Merkle.Recovery.prepare(gpa, storage, &hasher, merkle_cfg, retain);
            errdefer structure.deinit();
            if (structure.leaves() < span.start) return error.ItemPruned;
            return .{
                .gpa = gpa,
                .journal = journal,
                .merkle = structure,
                .hasher = hasher,
                .selected_end = selected_end,
            };
        }

        /// Opens the journal, retaining every item through the last satisfying `predicate`
        /// (commonware's `new`).
        pub fn init(
            gpa: Allocator,
            storage: Storage,
            merkle_cfg: merkle.full.Config,
            journal_cfg: C.BackingConfig,
            comptime predicate: fn (Item) bool,
            bagging: merkle.Bagging,
        ) !Self {
            const cfg = journal_cfg;
            var recovery = try prepare(gpa, storage, merkle_cfg, cfg, null, predicate, bagging);
            return recovery.finish();
        }

        /// Replays journal items the Merkle structure lacks.
        fn align_merkle(
            gpa: Allocator,
            structure: *Merkle,
            journal: *C,
            hasher: *const Hasher,
        ) !void {
            const journal_size = journal.size();
            var leaves = structure.leaves();
            if (leaves > journal_size) return error.Corruption;
            var items: std.ArrayList(Item) = .empty;
            defer items.deinit(gpa);
            var locations: std.ArrayList(u64) = .empty;
            defer locations.deinit(gpa);
            while (leaves < journal_size) {
                const count: usize = @intCast(@min(apply_batch_size, journal_size - leaves));
                try items.resize(gpa, count);
                try locations.resize(gpa, count);
                for (locations.items, leaves..) |*location, value| location.* = value;
                try journal.read_many(locations.items, items.items);
                defer codec.free_items(Item, gpa, items.items);
                try add_leaves(gpa, structure, hasher, items.items);
                leaves += count;
            }
            assert(structure.leaves() == journal.size());
        }
    };
}
