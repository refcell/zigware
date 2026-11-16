//! Batches of a `current` database (commonware's `qmdb/current/batch.rs`): an `any` batch plus
//! the activity chunks it changes and the grafted tree over them, so a merkleized batch knows
//! its canonical root before it is applied.
//!
//! A merkleized batch's chunks live in a reference-counted `Layer` chained to its parent's,
//! ending at the database's bitmap (commonware's `BitmapBatch`). Children read through the
//! chain, which outlives the batches that made it. Merkleizing and applying cut layers the
//! database already holds (commonware's `trim_committed`), so a chain stays as long as the
//! batches still pending.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const diff_mod = @import("../any/diff.zig");
const grafting = @import("grafting.zig");
const grafted_mod = @import("grafted.zig");
const canonical = @import("canonical.zig");

/// One merkleized batch's activity chunks over the layers below it: every chunk the batch
/// changed or completed, by index (commonware's `ChunkOverlay` in a `BitmapBatchLayer`).
pub fn Layer(comptime N: usize) type {
    return struct {
        const Self = @This();
        pub const Chunk = [N]u8;
        pub const chunk_bits: u64 = N * 8;

        references: u32,
        /// The layer below, null for the database's bitmap. A strong reference.
        parent: ?*Self,
        chunks: std.AutoHashMapUnmanaged(u64, Chunk) = .empty,
        /// The bitmap's length with this layer.
        len: u64,

        pub fn retain(self: *Self) *Self {
            assert(self.references > 0);
            self.references += 1;
            return self;
        }

        /// Drops a reference; the last one frees the layer and drops its parent reference.
        pub fn release(self: *Self, gpa: Allocator) void {
            var current: ?*Self = self;
            while (current) |layer| {
                assert(layer.references > 0);
                layer.references -= 1;
                if (layer.references > 0) break;
                current = layer.parent;
                layer.chunks.deinit(gpa);
                gpa.destroy(layer);
            }
        }
    };
}

/// Cuts the chain at `head` below its newest layer the database's bitmap of `committed` bits
/// already holds. Layers are shared, so every chain through the cut layer loses the redundant
/// tail; a chain the database moved past is stale and fails validation anyway.
pub fn trim(comptime N: usize, gpa: Allocator, head: *?*Layer(N), committed: u64) void {
    var link = head;
    var steps: usize = 0;
    while (link.*) |layer| : (steps += 1) {
        assert(steps < std.math.maxInt(u32));
        if (layer.len <= committed) {
            link.* = null;
            layer.release(gpa);
            return;
        }
        link = &layer.parent;
    }
    assert(link.* == null);
}

/// The activity bitmap seen through a layer chain over the database's `bitmap` (commonware's
/// `BitmapBatch` as `bitmap::Readable`).
pub fn View(comptime N: usize, comptime Bitmap: type) type {
    return struct {
        const Self = @This();
        const L = Layer(N);

        bitmap: *const Bitmap,
        layer: ?*const L,

        pub fn len(self: *const Self) u64 {
            const layer = self.layer orelse return self.bitmap.len();
            return layer.len;
        }

        pub fn complete_chunks(self: *const Self) usize {
            return @intCast(self.len() / L.chunk_bits);
        }

        pub fn pruned_chunks(self: *const Self) usize {
            return self.bitmap.pruned_chunks();
        }

        pub fn get_chunk(self: *const Self, index: usize) L.Chunk {
            var current = self.layer;
            while (current) |layer| : (current = layer.parent) {
                if (layer.chunks.get(index)) |chunk| return chunk;
            }
            assert(index >= self.bitmap.pruned_chunks());
            return self.bitmap.get_chunk(index);
        }

        /// The last chunk holding bits and how many it holds.
        pub fn last_chunk(self: *const Self) struct { L.Chunk, u64 } {
            const total = self.len();
            if (total == 0) return .{ @splat(0), 0 };
            const rem = total % L.chunk_bits;
            const bits = if (rem == 0) L.chunk_bits else rem;
            const complete = self.complete_chunks();
            const index = if (rem == 0) complete - 1 else complete;
            assert(bits > 0 and bits <= L.chunk_bits);
            return .{ self.get_chunk(index), bits };
        }
    };
}

/// Builds a batch's layer over `view` (commonware's `build_chunk_overlay`): the commit bit set,
/// the previous commit's cleared, each key's new location in the batch set and its previous
/// one cleared, and every chunk the batch completes present.
fn build_layer(
    comptime N: usize,
    comptime K: type,
    comptime V: type,
    gpa: Allocator,
    view: anytype,
    parent: ?*Layer(N),
    batch_len: u64,
    diff: []const diff_mod.Pair(K, V),
    ancestor_diffs: []const []const diff_mod.Pair(K, V),
) !*Layer(N) {
    const L = Layer(N);
    const base = view.len();
    assert(batch_len > 0); // A batch ends with its commit.
    const layer = try gpa.create(L);
    layer.* = .{ .references = 1, .parent = if (parent) |p| p.retain() else null, .len = base };
    errdefer layer.release(gpa);
    var builder: Builder(N, @TypeOf(view)) = .{
        .gpa = gpa,
        .view = view,
        .layer = layer,
        .parent_len = base,
        .parent_complete = base / L.chunk_bits,
        .parent_pruned = view.pruned_chunks(),
    };
    layer.len = base + batch_len;
    try builder.set(base + batch_len - 1);
    if (base > 0) try builder.clear(base - 1);
    var ancestors = try diff_mod.Cursors(K, V).init(gpa, ancestor_diffs);
    defer ancestors.deinit(gpa);
    for (diff) |*pair| {
        if (pair.entry.loc()) |loc| {
            if (loc >= base and loc < base + batch_len) try builder.set(loc);
        }
        var previous = pair.entry.base_old_loc();
        if (ancestors.resolve(&pair.key)) |entry| previous = entry.loc();
        if (previous) |old| try builder.clear(old);
    }
    var index = builder.parent_complete;
    while (index < layer.len / L.chunk_bits) : (index += 1) _ = try builder.chunk(index);
    assert(layer.len == base + batch_len);
    return layer;
}

/// Writes bits into a new layer, copying each chunk from the view below on first touch.
fn Builder(comptime N: usize, comptime ViewType: type) type {
    return struct {
        const Self = @This();
        const L = Layer(N);

        gpa: Allocator,
        view: ViewType,
        layer: *L,
        parent_len: u64,
        parent_complete: u64,
        parent_pruned: u64,

        fn chunk(self: *Self, index: u64) !*L.Chunk {
            const slot = try self.layer.chunks.getOrPut(self.gpa, index);
            if (slot.found_existing) return slot.value_ptr;
            const has_partial = self.parent_len % L.chunk_bits != 0;
            if (index < self.parent_complete) {
                slot.value_ptr.* = self.view.get_chunk(@intCast(index));
            } else if (index == self.parent_complete and has_partial) {
                slot.value_ptr.* = self.view.last_chunk()[0];
            } else {
                slot.value_ptr.* = @splat(0);
            }
            assert(index >= self.parent_pruned);
            return slot.value_ptr;
        }

        fn set(self: *Self, loc: u64) !void {
            assert(loc < self.layer.len);
            const bits = try self.chunk(loc / L.chunk_bits);
            const rel = loc % L.chunk_bits;
            bits[@intCast(rel / 8)] |= @as(u8, 1) << @intCast(rel % 8);
        }

        fn clear(self: *Self, loc: u64) !void {
            assert(loc < self.layer.len);
            if (loc / L.chunk_bits < self.parent_pruned) return;
            const bits = try self.chunk(loc / L.chunk_bits);
            const rel = loc % L.chunk_bits;
            bits[@intCast(rel / 8)] &= ~(@as(u8, 1) << @intCast(rel % 8));
        }
    };
}

/// The ops tree as a batch sees it: its journal batch's nodes over the database's persisted
/// Merkle (commonware's `Layered`).
fn OpsView(comptime D: type) type {
    return struct {
        const Self = @This();

        batch: *const D.Any.Log.MerkleizedBatch,
        base: *D.Any.Log.Merkle,

        pub fn size(self: *const Self) u64 {
            return self.batch.inner.size();
        }

        pub fn get_node(self: *const Self, position: u64) D.Any.Log.Merkle.Error!?D.Digest {
            if (self.batch.get_node(position)) |digest| return digest;
            if (position >= self.size()) return null;
            return self.base.get_node(position);
        }
    };
}

/// The grafted tree as a batch sees it: its grafted batch over the database's grafted tree.
fn GraftedView(comptime D: type) type {
    return struct {
        const Self = @This();

        batch: *const D.GraftedBatch,
        base: *const D.Mem,

        pub fn get_node(self: *const Self, position: u64) ?D.Digest {
            if (self.batch.get_node(position)) |digest| return digest;
            if (position >= self.batch.size()) return null;
            return self.base.get_node(position);
        }
    };
}

/// A batch of writes not yet merkleized: an `any` batch plus the grafted tree and activity
/// layers it builds on. `deinit` it if dropped; `merkleize` consumes it on success.
pub fn Unmerkleized(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;

        gpa: Allocator,
        /// Null once `any` merkleized it.
        inner: ?D.Any.UnmerkleizedBatch,
        /// A strong reference.
        grafted_parent: *D.GraftedBatch,
        /// A strong reference, null for the database's bitmap.
        bitmap_parent: ?*D.Layer,

        pub fn deinit(self: *Self) void {
            if (self.inner) |*inner| inner.deinit();
            self.grafted_parent.release(self.gpa);
            if (self.bitmap_parent) |layer| layer.release(self.gpa);
            self.* = undefined;
        }

        pub fn with_metadata(self: *Self, metadata: ?V) void {
            assert(self.inner != null);
            self.inner.?.with_metadata(metadata);
        }

        /// Records `key`'s new value, or its deletion when null.
        pub fn write(self: *Self, key: K, value: ?V) !void {
            assert(self.inner != null);
            try self.inner.?.write(key, value);
        }

        /// The key's value with this batch's writes.
        pub fn get(self: *const Self, key: *const K, db: *D) !?V {
            assert(self.inner != null);
            return self.inner.?.get(key, &db.any);
        }

        /// Merkleizes with commonware's default `Proportional` floor policy.
        pub fn merkleize(self: *Self, db: *D) !*D.MerkleizedBatch {
            var policy: @import("../floor.zig").Proportional = .{};
            return self.merkleize_with(db, &policy);
        }

        /// Merkleizes the `any` batch with `policy`, then the activity layer and grafted tree
        /// over it. Consumes the batch on success; after an error only `deinit` may follow.
        pub fn merkleize_with(self: *Self, db: *D, policy: anytype) !*D.MerkleizedBatch {
            assert(self.inner != null);
            trim(D.chunk_bytes, self.gpa, &self.bitmap_parent, db.any.bitmap.len());
            const inner = try self.inner.?.merkleize_with(&db.any, policy);
            self.inner = null; // `any` consumed it.
            errdefer inner.release();
            const result = try current_layer(D, db, inner, self.grafted_parent, self.bitmap_parent);
            self.grafted_parent.release(self.gpa);
            if (self.bitmap_parent) |layer| layer.release(self.gpa);
            self.* = undefined;
            return result;
        }
    };
}

/// Builds a merkleized batch from the merkleized `any` batch `inner` (taking its reference):
/// the batch's activity layer, its grafted tree batch with the dirty and newly graftable chunks
/// regrafted, and the canonical root (commonware's `compute_current_layer`).
fn current_layer(
    comptime D: type,
    db: *D,
    inner: *D.Any.MerkleizedBatch,
    grafted_parent: *D.GraftedBatch,
    bitmap_parent: ?*D.Layer,
) !*D.MerkleizedBatch {
    const gpa = db.gpa;
    const N = D.chunk_bytes;
    const items = inner.journal_batch.batch_items().len;
    const tip = inner.bounds.tip.size;
    const parent_view: D.View = .{ .bitmap = &db.any.bitmap, .layer = bitmap_parent };
    assert(parent_view.len() + items == tip);
    const Item = D.Any.MerkleizedBatch.Diff.Item;
    const ancestors = try gpa.alloc([]const Item, inner.ancestor_diffs.len);
    defer gpa.free(ancestors);
    for (inner.ancestor_diffs, ancestors) |d, *entries| entries.* = d.entries;
    const diff = inner.diff.entries;
    const layer = try build_layer(
        N,
        D.Key,
        D.Value,
        gpa,
        &parent_view,
        bitmap_parent,
        items,
        diff,
        ancestors,
    );
    errdefer layer.release(gpa);
    const ops: OpsView(D) = .{ .batch = inner.journal_batch, .base = &db.any.log.merkle };
    const grafted = try regraft(D, db, layer, grafted_parent, &ops);
    errdefer grafted.release(gpa);
    const witness = try batch_witness(D, db, inner, layer, grafted, &ops);
    const result = try gpa.create(D.MerkleizedBatch);
    result.* = .{
        .gpa = gpa,
        .references = 1,
        .inner = inner,
        .grafted = grafted,
        .layer = layer,
        .canonical_root = witness.root(D.Hasher, &inner.root()),
        .ops_root_witness = witness,
        .pruned_chunks = db.any.bitmap.pruned_chunks(),
    };
    assert(result.layer.?.len == tip);
    return result;
}

/// The witness of the state after `inner`, whose activity is `layer` and grafted tree
/// `grafted` over the database's.
fn batch_witness(
    comptime D: type,
    db: *D,
    inner: *const D.Any.MerkleizedBatch,
    layer: *const D.Layer,
    grafted: *const D.GraftedBatch,
    ops: *const OpsView(D),
) !D.Witness {
    const N = D.chunk_bytes;
    const view: D.View = .{ .bitmap = &db.any.bitmap, .layer = layer };
    const tree: GraftedView(D) = .{ .batch = grafted, .base = &db.grafted_tree };
    const height = grafting.height(N);
    const Grafted = *const GraftedView(D);
    const Storage = grafted_mod.Storage(D.Family, D.Hasher, Grafted, *const OpsView(D));
    const storage: Storage = .{ .grafted = &tree, .ops = ops, .grafting_height = height };
    const floor = inner.bounds.inactivity_floor;
    const tip = inner.bounds.tip.size;
    assert(layer.len == tip);
    const compute = canonical.compute_ops_root_witness;
    return compute(D.Family, D.Hasher, N, &view, &storage, tip, floor);
}

/// The grafted batch over `grafted_parent` with the leaves of `layer`'s dirty chunks rebuilt
/// and the newly graftable chunks added.
fn regraft(
    comptime D: type,
    db: *D,
    layer: *const D.Layer,
    grafted_parent: *D.GraftedBatch,
    ops: anytype,
) !*D.GraftedBatch {
    const gpa = db.gpa;
    const N = D.chunk_bytes;
    const height = grafting.height(N);
    const new_complete = layer.len / D.Layer.chunk_bits;
    const graftable = @min(grafting.graftable_chunks(D.Family, layer.len, height), new_complete);
    const graftable_parent = grafted_parent.leaves();
    const pruned: u64 = db.any.bitmap.pruned_chunks();
    assert(pruned <= graftable_parent and graftable_parent <= graftable);
    var dirty: std.ArrayList(u64) = .empty;
    defer dirty.deinit(gpa);
    var keys = layer.chunks.keyIterator();
    while (keys.next()) |index| {
        if (index.* < graftable_parent and index.* >= pruned) try dirty.append(gpa, index.*);
    }
    std.mem.sort(u64, dirty.items, {}, std.sort.asc(u64));
    var batch = grafted_parent.new_batch(); // Retains the parent for the batch.
    errdefer batch.deinit(gpa);
    const view: D.View = .{ .bitmap = &db.any.bitmap, .layer = layer };
    for (dirty.items) |index| {
        const leaf = try graft_leaf(D, db, &view, index, ops);
        try batch.update_leaf_digest(gpa, index, leaf);
    }
    var index = graftable_parent;
    while (index < graftable) : (index += 1) {
        try batch.add_leaf_digest(gpa, try graft_leaf(D, db, &view, index, ops));
    }
    const hasher = grafting.GraftedHasher(D.Family, D.Hasher).init(height);
    return batch.merkleize(gpa, &db.grafted_tree, &hasher);
}

fn graft_leaf(
    comptime D: type,
    db: *const D,
    view: *const D.View,
    index: u64,
    ops: anytype,
) !D.Digest {
    const root = try db.graft_roots.get_or_read(D.Family, D.chunk_bytes, index, ops);
    const chunk = view.get_chunk(@intCast(index));
    return grafting.grafted_leaf_digest(D.Hasher, &chunk, root);
}

/// A merkleized batch: the `any` batch, its grafted tree batch and activity layer, and the
/// canonical root after it. Reference counted; the caller keeps its reference across
/// `Db.apply_batch`. Children hold the parts they read, not the batch.
pub fn Merkleized(comptime D: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        references: u32,
        /// A strong reference.
        inner: *D.Any.MerkleizedBatch,
        /// A strong reference.
        grafted: *D.GraftedBatch,
        /// A strong reference, null for a batch of the database's own state.
        layer: ?*D.Layer,
        canonical_root: D.Digest,
        ops_root_witness: D.Witness,
        /// The database's pruned chunks at merkleize.
        pruned_chunks: u64,

        /// The current state of `db` as a batch.
        pub fn from_db(db: *const D) !*Self {
            const gpa = db.gpa;
            const inner = try db.any.to_batch();
            errdefer inner.release();
            const grafted = try D.GraftedBatch.from_mem(gpa, &db.grafted_tree);
            errdefer grafted.release(gpa);
            const self = try gpa.create(Self);
            self.* = .{
                .gpa = gpa,
                .references = 1,
                .inner = inner,
                .grafted = grafted,
                .layer = null,
                .canonical_root = db.root_digest,
                .ops_root_witness = db.ops_root_witness,
                .pruned_chunks = db.any.bitmap.pruned_chunks(),
            };
            assert(self.inner.bounds.tip.size == db.any.log.size());
            return self;
        }

        pub fn retain(self: *Self) *Self {
            assert(self.references > 0);
            self.references += 1;
            return self;
        }

        pub fn release(self: *Self) void {
            assert(self.references > 0);
            self.references -= 1;
            if (self.references > 0) return;
            const gpa = self.gpa;
            self.inner.release();
            self.grafted.release(gpa);
            if (self.layer) |layer| layer.release(gpa);
            self.* = undefined;
            gpa.destroy(self);
        }

        /// The canonical root after this batch.
        pub fn root(self: *const Self) D.Digest {
            return self.canonical_root;
        }

        /// The ops root after this batch.
        pub fn ops_root(self: *const Self) D.Digest {
            return self.inner.root();
        }

        pub fn bounds(self: *const Self) *const D.Any.Bounds {
            return &self.inner.bounds;
        }

        /// This batch's own operations and the location of the first.
        pub fn operations(self: *const Self) struct { u64, []const D.Operation } {
            return self.inner.operations();
        }

        /// The sync boundary after this batch.
        pub fn sync_boundary(self: *const Self) u64 {
            const floor_chunks = self.inner.bounds.inactivity_floor / D.Layer.chunk_bits;
            const tip = self.inner.bounds.tip.size;
            return canonical.sync_boundary(D.Family, D.chunk_bytes, floor_chunks, tip);
        }

        /// The key's value after this batch.
        pub fn get(self: *const Self, key: *const D.Key, db: *D) !?D.Value {
            return self.inner.get(key, &db.any);
        }

        /// A child batch on top of this one.
        pub fn new_batch(self: *Self) D.UnmerkleizedBatch {
            return .{
                .gpa = self.gpa,
                .inner = self.inner.new_batch(),
                .grafted_parent = self.grafted.retain(),
                .bitmap_parent = if (self.layer) |layer| layer.retain() else null,
            };
        }
    };
}
