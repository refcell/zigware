//! The authenticated journal (commonware's `journal/authenticated.rs`: `Journal`,
//! `Recovery`, `UnmerkleizedBatch`, and `MerkleizedBatch`).
//!
//! A contiguous journal `C` (`contiguous.fixed.Journal` or `contiguous.variable.Journal`)
//! keeps the items, and a persisted Merkle structure of family `F` keeps one leaf per item:
//! leaf `i` is the hash of item `i`'s codec encoding. Proofs show an item is in the journal
//! at its location.
//!
//! Commonware's mutators take the journal by value and drop it on error. Here mutators take
//! `*Self`; after an error only `deinit` may follow (state not yet durable is lost, durable
//! state stays recoverable). Syncs complete synchronously, so `start_sync` has no handle.
//!
//! Batches are reference counted by hand, as in `merkle.batch`: `MerkleizedBatch.retain` and
//! `release` are commonware's `Arc` clone and drop, and a child's parent link is weak. Items
//! added to a batch belong to it and are freed with `codec.free` when the last batch holding
//! them is released. Locations are plain `u64` leaf indices.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const merkle = @import("../merkle/mod.zig");
const refcount = @import("../refcount.zig");
const RefCount = refcount.RefCount;
const contiguous = @import("contiguous/mod.zig");
const authenticated = @import("authenticated.zig");

const Storage = runtime.storage.Storage;
const Bounds = contiguous.Bounds;
const max_pins = merkle.max_pinned_nodes;

/// The number of items applied to the Merkle structure per batch while aligning it.
pub const apply_batch_size: u64 = 1 << 16;

/// An authenticated journal over contiguous journal `C`, Merkle family `F`, and cryptography
/// hasher `H`.
pub fn Journal(comptime F: type, comptime C: type, comptime H: type) type {
    merkle.check_family(F);
    authenticated.assert_backing(C);
    return struct {
        const Self = @This();
        pub const Item = C.BackingRecovery.Item;
        pub const Digest = H.Digest;
        pub const Hasher = merkle.hasher.Standard(H);
        pub const Merkle = merkle.full.Merkle(F, Digest);
        pub const Proof = Merkle.Proof;
        pub const Error = Merkle.Error;

        gpa: Allocator,
        /// Leaf `i` is the digest of item `i`.
        merkle: Merkle,
        /// Item `i` is leaf `i` of `merkle`.
        journal: C,
        hasher: Hasher,

        /// Closes the journal without syncing.
        pub fn deinit(self: *Self) void {
            self.journal.deinit();
            self.merkle.deinit();
            self.* = undefined;
        }

        /// The location of the next appended item.
        pub fn size(self: *const Self) u64 {
            return self.journal.size();
        }

        /// The retained items `[start, end)` (commonware's `bounds`).
        pub fn get_bounds(self: *const Self) Bounds {
            return self.journal.get_bounds();
        }

        /// The root with the oldest `inactive_peaks` peaks folded under the journal's bagging.
        pub fn root(self: *const Self, inactive_peaks: usize) Error!Digest {
            return self.merkle.root(&self.hasher, inactive_peaks);
        }

        /// The item at `position`; for an item type that owns memory the caller frees it.
        pub fn read(self: *const Self, position: u64) Error!Item {
            return self.journal.read(position);
        }

        /// The items at strictly increasing `positions` into `out`.
        pub fn read_many(self: *const Self, positions: []const u64, out: []Item) Error!void {
            assert(positions.len == out.len);
            return self.journal.read_many(positions, out);
        }

        /// The item if it can be read without I/O.
        pub fn try_read_sync(self: *const Self, position: u64) ?Item {
            return self.journal.try_read_sync(position);
        }

        /// Replays the items in `range` (see the backing journal's `replay`).
        pub fn replay(self: *Self, range: Bounds, buffer_bytes: usize) Error!C.Replay {
            return self.journal.replay(range, buffer_bytes);
        }

        /// `replay` with the backing journal's blob reads using `read_options`.
        pub fn replay_options(
            self: *Self,
            range: Bounds,
            buffer_bytes: usize,
            read_options: runtime.storage.ReadOptions,
        ) Error!C.Replay {
            return self.journal.replay_options(range, buffer_bytes, read_options);
        }

        /// Wraps published components, replaying journal items the Merkle structure lacks,
        /// then syncs the structure. Fails with `Corruption` when the structure has more
        /// leaves than the journal has items. Takes both components, also on error.
        pub fn from_components(
            gpa: Allocator,
            merkle_structure: Merkle,
            journal: C,
            hasher: Hasher,
            batch_size: u64,
        ) Error!Self {
            var self: Self = .{
                .gpa = gpa,
                .merkle = merkle_structure,
                .journal = journal,
                .hasher = hasher,
            };
            errdefer self.deinit();
            try align_merkle(gpa, &self.merkle, &self.journal, &self.hasher, batch_size);
            try self.merkle.sync();
            return self;
        }

        /// Adds the journal items the Merkle structure lacks, `batch_size` at a time.
        pub fn align_merkle(
            gpa: Allocator,
            structure: *Merkle,
            journal: *C,
            hasher: *const Hasher,
            batch_size: u64,
        ) Error!void {
            assert(batch_size > 0);
            const journal_size = journal.size();
            if (structure.leaves() > journal_size) return error.Corruption;
            const capacity: usize = @intCast(@min(batch_size, journal_size - structure.leaves()));
            if (capacity == 0) return;
            const positions = try gpa.alloc(u64, capacity);
            defer gpa.free(positions);
            const items = try gpa.alloc(Item, capacity);
            defer gpa.free(items);
            while (structure.leaves() < journal_size) {
                const first = structure.leaves();
                const count: usize = @intCast(@min(batch_size, journal_size - first));
                for (positions[0..count], 0..) |*position, index| position.* = first + index;
                try journal.read_many(positions[0..count], items[0..count]);
                defer codec.free_items(Item, gpa, items[0..count]);
                try add_leaves(gpa, structure, hasher, items[0..count]);
            }
            assert(structure.leaves() == journal_size);
        }

        /// Adds the leaves of `items` to `structure` through one batch.
        fn add_leaves(
            gpa: Allocator,
            structure: *Merkle,
            hasher: *const Hasher,
            items: []const Item,
        ) Error!void {
            const leaves_before = structure.leaves();
            var batch = try structure.new_batch();
            batch.add_many(gpa, hasher, Item, items) catch |err| {
                batch.deinit(gpa);
                return err;
            };
            const merkleized = batch.merkleize(structure, hasher) catch |err| {
                batch.deinit(gpa);
                return err;
            };
            defer merkleized.release(gpa);
            try structure.apply_batch(merkleized);
            assert(structure.leaves() == leaves_before + items.len);
        }

        /// Appends `item` (borrowed) and its leaf, returning its location.
        pub fn append(self: *Self, item: Item) Error!u64 {
            const location = try self.journal.append(item);
            try add_leaves(self.gpa, &self.merkle, &self.hasher, &.{item});
            assert(self.merkle.leaves() == self.journal.size());
            return location;
        }

        /// Appends `items` one at a time, returning the last location. Fails with
        /// `EmptyAppend` when there is nothing to append.
        pub fn append_many(self: *Self, items: []const Item) Error!u64 {
            return self.append_many_nested(&.{items});
        }

        /// Appends the items of `nested` in order, returning the last location.
        pub fn append_many_nested(self: *Self, nested: []const []const Item) Error!u64 {
            var location: ?u64 = null;
            for (nested) |items| {
                for (items) |item| location = try self.append(item);
            }
            return location orelse error.EmptyAppend;
        }

        /// Makes the items durable and flushes the Merkle structure without syncing it, so a
        /// crash may need recovery to replay leaves.
        pub fn commit(self: *Self) Error!void {
            try self.journal.commit();
            try self.merkle.flush();
        }

        /// Makes both components durable. The journal's started sync is waited for here
        /// until this journal returns a completion (async start_sync step 3).
        pub fn start_sync(self: *Self) Error!void {
            try (try self.journal.start_sync()).wait_release();
            try self.merkle.start_sync();
        }

        /// Makes both components durable, so no recovery is needed on startup.
        pub fn sync(self: *Self) Error!void {
            try self.journal.sync();
            try self.merkle.sync();
            assert(self.merkle.leaves() == self.journal.size());
        }

        /// Prunes items before `location`, then raises the Merkle pruning boundary to the
        /// journal's retained start if it is lower. Returns the retained start, which may be
        /// below `location`.
        pub fn prune(self: *Self, location: u64) Error!u64 {
            return (try self.prune_reporting(location)).boundary;
        }

        pub const Pruned = struct { boundary: u64, pruned: bool };

        /// `prune`, also reporting whether either component pruned anything (the contiguous
        /// `Mutable::prune` of commonware's journal, which caps `location` at the end).
        pub fn prune_reporting(self: *Self, location: u64) Error!Pruned {
            if (self.merkle.size() == 0) {
                return .{ .boundary = self.journal.get_bounds().start, .pruned = false };
            }
            // The Merkle structure must not fall behind the journal start after a crash, and
            // the prune target may rest on a buffered append, so persist both first.
            try self.journal.commit();
            try self.merkle.sync();
            const journal_pruned = try self.journal.prune(@min(location, self.journal.size()));
            const boundary = self.journal.get_bounds().start;
            const merkle_boundary = self.merkle.bounds().start;
            if (boundary > merkle_boundary) try self.merkle.prune(boundary);
            assert(self.merkle.bounds().start >= boundary);
            const pruned = journal_pruned or boundary > merkle_boundary;
            return .{ .boundary = boundary, .pruned = pruned };
        }

        /// Removes both components' storage, the journal first: reopening an empty journal
        /// discards the Merkle state beside it. Frees the journal, also on error.
        pub fn destroy(self: *Self) Error!void {
            defer self.* = undefined;
            self.journal.destroy() catch |err| {
                self.merkle.deinit();
                return err;
            };
            try self.merkle.destroy();
        }

        /// Opens a journal ending at its last item matching `predicate`. An empty retained
        /// range keeps its append position.
        pub fn init(
            gpa: Allocator,
            storage: Storage,
            merkle_cfg: merkle.full.Config,
            journal_cfg: C.BackingConfig,
            comptime predicate: fn (Item) bool,
            bagging: merkle.Bagging,
        ) Error!Self {
            var recovery =
                try prepare(gpa, storage, merkle_cfg, journal_cfg, null, predicate, bagging);
            return recovery.finish();
        }

        /// Opens a journal whose last matching item ends at or below `max_size`, durably
        /// discarding the suffix. When the journal retains its first item and nothing matches,
        /// both components are emptied; a cap below retained history, or pruned history with
        /// no match, fails with `ItemPruned`.
        pub fn init_at_most(
            gpa: Allocator,
            storage: Storage,
            merkle_cfg: merkle.full.Config,
            journal_cfg: C.BackingConfig,
            max_size: u64,
            comptime predicate: fn (Item) bool,
            bagging: merkle.Bagging,
        ) Error!Self {
            var recovery =
                try prepare(gpa, storage, merkle_cfg, journal_cfg, max_size, predicate, bagging);
            return recovery.finish();
        }

        /// Selects the item prefix and checks the Merkle structure covers it, before any
        /// history is discarded.
        pub fn prepare(
            gpa: Allocator,
            storage: Storage,
            merkle_cfg: merkle.full.Config,
            journal_cfg: C.BackingConfig,
            max_size: ?u64,
            comptime predicate: fn (Item) bool,
            bagging: merkle.Bagging,
        ) Error!Recovery {
            var journal = try C.recover(gpa, storage, journal_cfg, max_size);
            errdefer journal.deinit();
            const bounds = journal.get_bounds();
            const Matcher = struct {
                fn matches(_: void, item: Item) bool {
                    return predicate(item);
                }
            };
            // A fully pruned empty journal has no item to match; its end stays selected.
            const selected_end = if (max_size == null and bounds.start == bounds.end)
                bounds.end
            else
                try authenticated.last_matching(
                    &journal,
                    max_size orelse std.math.maxInt(u64),
                    {},
                    Matcher.matches,
                );
            assert(selected_end <= bounds.end);
            // An empty selection at genesis leaves nothing to authenticate: drop the Merkle
            // state beside it, whatever it retained.
            const hasher = Hasher.init(bagging);
            const retain: merkle.full.Retain = if (bounds.start == 0 and selected_end == 0)
                .nothing
            else
                .{ .at_most = selected_end };
            var structure = try Merkle.Recovery.prepare(gpa, storage, &hasher, merkle_cfg, retain);
            errdefer structure.deinit();
            if (structure.leaves() < bounds.start) return error.ItemPruned;
            return .{
                .gpa = gpa,
                .journal = journal,
                .merkle = structure,
                .hasher = hasher,
                .selected_end = selected_end,
            };
        }

        /// Selected journal and Merkle state awaiting durable publication.
        pub const Recovery = struct {
            gpa: Allocator,
            journal: C.BackingRecovery,
            /// Capped at `selected_end`, covering the journal's retained start.
            merkle: Merkle.Recovery,
            hasher: Hasher,
            /// The exclusive item end chosen for publication.
            selected_end: u64,

            pub fn deinit(self: *Recovery) void {
                self.journal.deinit();
                self.merkle.deinit();
                self.* = undefined;
            }

            /// The range selected for publication.
            pub fn bounds(self: *const Recovery) Bounds {
                const start = self.journal.get_bounds().start;
                assert(start <= self.selected_end);
                return .{ .start = start, .end = self.selected_end };
            }

            /// Whether storage was empty before selection.
            pub fn is_fresh(self: *const Recovery) bool {
                const stored = self.journal.get_bounds();
                return stored.start == 0 and stored.end == 0;
            }

            /// Reads a retained item, to validate recovery requirements. The caller owns it.
            pub fn read(self: *Recovery, position: u64) Error!Item {
                return self.journal.read(position);
            }

            /// Publishes and syncs the selected items, then finishes the Merkle structure,
            /// replays the items it lacks, and syncs it. Consumes the recovery, also on error.
            pub fn finish(self: *Recovery) Error!Self {
                const gpa = self.gpa;
                const hasher = self.hasher;
                var structure_recovery = self.merkle;
                var journal = self.journal.finish(self.selected_end) catch |err| {
                    structure_recovery.deinit();
                    self.* = undefined;
                    return err;
                };
                self.* = undefined;
                journal.sync() catch |err| {
                    journal.deinit();
                    structure_recovery.deinit();
                    return err;
                };
                const structure = structure_recovery.finish() catch |err| {
                    journal.deinit();
                    return err;
                };
                return from_components(gpa, structure, journal, hasher, apply_batch_size);
            }
        };

        /// A refcounted list of a batch's items, shared with descendant batches.
        pub const ItemChunk = struct {
            references: RefCount,
            items: []Item,

            fn create(gpa: Allocator, items: []Item) Allocator.Error!*ItemChunk {
                const chunk = try gpa.create(ItemChunk);
                chunk.* = .{ .references = .init(), .items = items };
                return chunk;
            }

            fn retain(self: *ItemChunk) *ItemChunk {
                self.references.retain();
                return self;
            }

            fn release(self: *ItemChunk, gpa: Allocator) void {
                if (!self.references.release()) return;
                codec.free_items(Item, gpa, self.items);
                gpa.free(self.items);
                gpa.destroy(self);
            }
        };

        /// A speculative batch whose root is not computed yet.
        pub const UnmerkleizedBatch = struct {
            inner: Merkle.Mem.Batch,
            hasher: Hasher,
            /// The items to append, owned by the batch.
            items: std.ArrayList(Item) = .empty,
            /// The parent batch (a strong reference), or null when it is the journal.
            parent: ?*MerkleizedBatch,

            /// Discards the batch and its items.
            pub fn deinit(self: *UnmerkleizedBatch, gpa: Allocator) void {
                self.inner.deinit(gpa);
                codec.free_items(Item, gpa, self.items.items);
                self.items.deinit(gpa);
                if (self.parent) |parent| parent.release(gpa);
                self.* = undefined;
            }

            /// The item count visible through the batch, ancestors included.
            pub fn size(self: *const UnmerkleizedBatch) u64 {
                return self.inner.leaves();
            }

            /// Adds `item`, which the batch owns on success (the caller keeps it on error).
            pub fn add(self: *UnmerkleizedBatch, gpa: Allocator, item: Item) !void {
                try self.add_many(gpa, &.{item});
            }

            /// Adds `items` (the batch owns each item on success; the slice stays the
            /// caller's).
            pub fn add_many(self: *UnmerkleizedBatch, gpa: Allocator, items: []const Item) !void {
                const leaves_before = self.inner.leaves();
                try self.items.ensureUnusedCapacity(gpa, items.len);
                try self.inner.add_many(gpa, &self.hasher, Item, items);
                self.items.appendSliceAssumeCapacity(items);
                assert(self.inner.leaves() == leaves_before + items.len);
            }

            /// Hashes the batch against `journal`'s committed nodes and returns the merkleized
            /// batch (one strong reference, for the caller). Consumes this batch on success;
            /// on error only `deinit` may follow.
            pub fn merkleize(
                self: *UnmerkleizedBatch,
                gpa: Allocator,
                journal: *const Self,
            ) !*MerkleizedBatch {
                const ancestor_items: []const *ItemChunk = if (self.parent) |parent|
                    try collect_ancestor_items(gpa, parent)
                else
                    &.{};
                errdefer release_chunks(gpa, ancestor_items);
                const batch = try gpa.create(MerkleizedBatch);
                errdefer gpa.destroy(batch);
                const owned = try self.items.toOwnedSlice(gpa);
                const chunk = ItemChunk.create(gpa, owned) catch |err| {
                    self.items = .fromOwnedSlice(owned);
                    return err;
                };
                const base = &journal.merkle.mem;
                const inner = self.inner.merkleize(gpa, base, &self.hasher) catch |err| {
                    gpa.destroy(chunk);
                    self.items = .fromOwnedSlice(owned);
                    return err;
                };
                if (self.parent) |parent| parent.weak.retain();
                batch.* = .{
                    .strong = .init(),
                    .weak = .init(),
                    .inner = inner,
                    .bagging = self.hasher.root_bagging(),
                    .items = chunk,
                    .parent = self.parent,
                    .ancestor_items = ancestor_items,
                };
                if (self.parent) |parent| parent.release(gpa);
                self.* = undefined;
                assert(batch.size() == batch.inner.leaves());
                return batch;
            }
        };

        /// The item chunks of `parent` and its live ancestors, root to tip, skipping empty
        /// ones. Each returned chunk is retained.
        fn collect_ancestor_items(
            gpa: Allocator,
            parent: *MerkleizedBatch,
        ) Allocator.Error![]*ItemChunk {
            var chunks: std.ArrayList(*ItemChunk) = .empty;
            errdefer {
                for (chunks.items) |chunk| chunk.release(gpa);
                chunks.deinit(gpa);
            }
            // The caller holds `parent`; each older batch is held while its chunk is retained.
            if (parent.items.items.len > 0) {
                try chunks.ensureUnusedCapacity(gpa, 1);
                chunks.appendAssumeCapacity(parent.items.retain());
            }
            var walk: refcount.Ancestors(MerkleizedBatch) = .init(gpa, parent);
            defer walk.deinit();
            while (walk.next()) |batch| {
                if (batch.items.items.len == 0) continue;
                try chunks.ensureUnusedCapacity(gpa, 1);
                chunks.appendAssumeCapacity(batch.items.retain());
            }
            std.mem.reverse(*ItemChunk, chunks.items);
            return chunks.toOwnedSlice(gpa);
        }

        fn release_chunks(gpa: Allocator, chunks: []const *ItemChunk) void {
            for (chunks) |chunk| chunk.release(gpa);
            gpa.free(chunks);
        }

        /// A speculative batch whose root is computed: immutable, reference counted.
        pub const MerkleizedBatch = struct {
            /// Strong references; the batch's items live while this is non-zero.
            strong: RefCount,
            /// Weak references (children's parent links) plus one shared by the strong ones.
            weak: RefCount,
            /// The Merkle batch (a strong reference).
            inner: *Merkle.MerkleizedBatch,
            /// The peak bagging inherited from the journal or parent batch.
            bagging: merkle.Bagging,
            /// The items this batch appends.
            items: *ItemChunk,
            /// The parent batch (a weak link), null for a root batch or once released.
            parent: ?*MerkleizedBatch,
            /// The item chunks of the ancestors live at merkleize, root to tip.
            ancestor_items: []const *ItemChunk,

            pub fn retain(self: *MerkleizedBatch) *MerkleizedBatch {
                self.strong.retain();
                return self;
            }

            /// Drops a strong reference (commonware's `drop` of an `Arc`).
            pub fn release(self: *MerkleizedBatch, gpa: Allocator) void {
                if (!self.strong.release()) return;
                assert(self.weak.load() > 0);
                self.inner.release(gpa);
                self.items.release(gpa);
                release_chunks(gpa, self.ancestor_items);
                if (self.parent) |parent| parent.release_weak(gpa);
                self.parent = null;
                self.release_weak(gpa);
            }

            fn release_weak(self: *MerkleizedBatch, gpa: Allocator) void {
                assert(self.weak.load() > 0);
                if (self.weak.release()) gpa.destroy(self);
            }

            /// The item count visible through this batch, ancestors included.
            pub fn size(self: *const MerkleizedBatch) u64 {
                return self.inner.leaves();
            }

            /// The items this batch appends.
            pub fn batch_items(self: *const MerkleizedBatch) []const Item {
                return self.items.items;
            }

            /// The root after this batch is applied.
            pub fn root(
                self: *const MerkleizedBatch,
                hasher: anytype,
                inactive_peaks: usize,
            ) !Digest {
                return self.inner.root(hasher, inactive_peaks);
            }

            /// The node at `position` from the batch chain, or null.
            pub fn get_node(self: *const MerkleizedBatch, position: u64) ?Digest {
                return self.inner.get_node(position);
            }

            /// An inclusion proof for the item at `location`. Caller owns the proof.
            pub fn proof(
                self: *const MerkleizedBatch,
                gpa: Allocator,
                base: anytype,
                hasher: anytype,
                location: u64,
                inactive_peaks: usize,
            ) !Proof {
                return self.inner.proof(gpa, base, hasher, location, inactive_peaks);
            }

            /// An inclusion proof for the items in `range`. Caller owns the proof.
            pub fn range_proof(
                self: *const MerkleizedBatch,
                gpa: Allocator,
                base: anytype,
                hasher: anytype,
                range: merkle.Range,
                inactive_peaks: usize,
            ) !Proof {
                return self.inner.range_proof(gpa, base, hasher, range, inactive_peaks);
            }

            /// A child batch. It becomes invalid if an unapplied ancestor is released before
            /// it is merkleized, or a sibling fork is applied.
            pub fn new_batch(self: *MerkleizedBatch) UnmerkleizedBatch {
                return .{
                    .inner = self.inner.new_batch(),
                    .hasher = Hasher.init(self.bagging),
                    .parent = self.retain(),
                };
            }
        };

        /// A speculative batch on top of the journal.
        pub fn new_batch(self: *const Self) Allocator.Error!UnmerkleizedBatch {
            const inner = try self.merkle.mem.new_batch(self.gpa);
            assert(inner.leaves() == self.merkle.leaves());
            const hasher = Hasher.init(self.hasher.root_bagging());
            return .{ .inner = inner, .hasher = hasher, .parent = null };
        }

        pub const Merkleized = struct { batch: *MerkleizedBatch, root: Digest };

        /// Adds `items` to `batch`, merkleizes it, and computes the post-apply root. Consumes
        /// the batch and the items, also on error.
        pub fn merkleize(
            self: *const Self,
            batch: *UnmerkleizedBatch,
            items: []const Item,
            inactive_peaks: usize,
        ) !Merkleized {
            assert(batch.items.items.len == 0); // Commonware's `add_many` expects no prior adds.
            batch.add_many(self.gpa, items) catch |err| {
                codec.free_items(Item, self.gpa, items);
                batch.deinit(self.gpa);
                return err;
            };
            const merkleized = batch.merkleize(self.gpa, self) catch |err| {
                batch.deinit(self.gpa);
                return err;
            };
            errdefer merkleized.release(self.gpa);
            const batch_root = try merkleized.root(&self.hasher, inactive_peaks);
            return .{ .batch = merkleized, .root = batch_root };
        }

        /// A merkleized batch of the committed state, without items.
        pub fn to_merkleized_batch(self: *const Self) Allocator.Error!*MerkleizedBatch {
            const inner = try self.merkle.to_batch();
            errdefer inner.release(self.gpa);
            const chunk = try ItemChunk.create(self.gpa, &.{});
            errdefer self.gpa.destroy(chunk);
            const batch = try self.gpa.create(MerkleizedBatch);
            batch.* = .{
                .strong = .init(),
                .weak = .init(),
                .inner = inner,
                .bagging = self.hasher.root_bagging(),
                .items = chunk,
                .parent = null,
                .ancestor_items = &.{},
            };
            assert(batch.size() == self.merkle.leaves());
            return batch;
        }

        /// Applies `batch`, first appending the items of its uncommitted ancestors. Fails,
        /// writing nothing, with `StaleBatch` for another fork, or `AncestorDropped` when an
        /// uncommitted ancestor's items are gone.
        pub fn apply_batch(self: *Self, batch: *const MerkleizedBatch) Error!void {
            // Validate before appending any item, so a rejected batch writes nothing.
            const start = try self.merkle.mem.validate_batch(batch.inner);
            // Both chains end at the batch's parent, so the ancestors still to replay are the
            // newest `remaining` entries of each.
            const remaining = batch.inner.ancestors.len - start;
            if (batch.ancestor_items.len < remaining) return error.AncestorDropped;
            const first = batch.ancestor_items.len - remaining;
            var nested: std.ArrayList([]const Item) = .empty;
            defer nested.deinit(self.gpa);
            try nested.ensureTotalCapacity(self.gpa, remaining + 1);
            for (batch.ancestor_items[first..]) |chunk| nested.appendAssumeCapacity(chunk.items);
            if (batch.items.items.len > 0) nested.appendAssumeCapacity(batch.items.items);
            if (nested.items.len > 0) _ = try self.journal.append_many_nested(nested.items);
            try self.merkle.apply_batch(batch.inner);
            assert(self.merkle.leaves() == self.journal.size());
        }

        /// A proof and its items, owned by the caller.
        pub const Proved = struct {
            proof: Proof,
            items: []Item,

            pub fn deinit(self: *Proved, gpa: Allocator) void {
                self.proof.deinit(gpa);
                codec.free_items(Item, gpa, self.items);
                gpa.free(self.items);
                self.* = undefined;
            }
        };

        /// An inclusion proof of the items from `start` against the current root, with the
        /// items `[start, min(size, start + max_ops))`.
        pub fn proof(
            self: *const Self,
            start: u64,
            max_ops: u64,
            inactive_peaks: usize,
        ) Error!Proved {
            return self.historical_proof(self.size(), start, max_ops, inactive_peaks);
        }

        /// `proof` against the state with `historical_leaves` items. Fails with
        /// `RangeOutOfBounds` when `start` is not below `historical_leaves` or that exceeds
        /// the size, and with `ItemPruned` or `ElementPruned` for pruned history.
        pub fn historical_proof(
            self: *const Self,
            historical_leaves: u64,
            start: u64,
            max_ops: u64,
            inactive_peaks: usize,
        ) Error!Proved {
            assert(max_ops > 0);
            if (historical_leaves > self.journal.size()) return error.RangeOutOfBounds;
            if (start >= historical_leaves) return error.RangeOutOfBounds;
            const end = @min(historical_leaves, start +| max_ops);
            const range: merkle.Range = .{ .start = start, .end = end };
            const leaves = historical_leaves;
            // The hasher is stateless (`*const` methods), so readers on several threads share it.
            var range_proof =
                try self.merkle.historical_range_proof(&self.hasher, leaves, range, inactive_peaks);
            errdefer range_proof.deinit(self.gpa);
            const count: usize = @intCast(end - start);
            const positions = try self.gpa.alloc(u64, count);
            defer self.gpa.free(positions);
            for (positions, 0..) |*position, index| position.* = start + index;
            const items = try self.gpa.alloc(Item, count);
            errdefer self.gpa.free(items);
            try self.journal.read_many(positions, items);
            return .{ .proof = range_proof, .items = items };
        }

        /// An inclusion proof of the items `batch` appends, against its speculative root.
        pub fn speculative_proof(
            self: *const Self,
            batch: *const MerkleizedBatch,
            inactive_peaks: usize,
        ) !Proof {
            const end = batch.size();
            const range: merkle.Range = .{ .start = end - batch.items.items.len, .end = end };
            const base = &self.merkle.mem;
            return batch.range_proof(self.gpa, base, &self.hasher, range, inactive_peaks);
        }

        /// The Merkle frontier at the first item `batch` appends (`nodes_to_pin`), into `out`.
        pub fn speculative_pinned_nodes(
            self: *const Self,
            batch: *const MerkleizedBatch,
            out: *[max_pins]Digest,
        ) Error![]Digest {
            const start = batch.size() - batch.items.items.len;
            var positions_buffer: [max_pins]u64 = undefined;
            const positions = merkle.nodes_to_pin(F, start, &positions_buffer);
            for (positions, out[0..positions.len]) |position, *digest| {
                digest.* = batch.get_node(position) orelse self.merkle.mem.get_node(position) orelse
                    return error.ElementPruned;
            }
            return out[0..positions.len];
        }
    };
}

test {
    _ = @import("authenticated_journal_test.zig");
}
