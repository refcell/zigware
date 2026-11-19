//! Batches of an `any` database (qmdb/any/batch.rs and batch/apply.rs), for unordered updates.
//!
//! `db.new_batch()` → `write(key, value)` (null deletes) / `with_metadata` → `merkleize(&db)`
//! → `db.apply_batch(merkleized)`. Merkleizing resolves each written key's previous location
//! (through the live ancestors' diffs, then the snapshot), emits updates of existing keys in
//! location order and creates in key order, walks the inactivity floor forward under a floor
//! policy (moving active updates it reaches to the tip), and appends the commit.
//!
//! Values may own memory (keys may not). A batch owns the values given to `write`,
//! `with_metadata`, and a staged merkleize's `put` slots and unstaged writes; reads return copies
//! the caller owns. Merkleizing borrows values from the batch, the log reads it makes, and the
//! ancestors, and hands the journal batch and the new diff their own copies.
//!
//! A merkleized batch is reference counted (`retain`/`release`); a child holds a weak link to
//! its parent and the diffs of its live ancestors, so reads and applies stay exact after the
//! ancestors are released. A walk under an evicting floor policy deletes each evicted key at
//! the tip; an ordered one first rewrites the evicted keys' predecessors to link past them.
//!
//! Staging (`stage` → `expand` → `Staged.merkleize(slots, unstaged)`) reads keys through the
//! batch and records where each resolved (`StagedLoc`); a staged merkleize then takes one
//! `Slot` per staged read. Commonware reuses the resolved locations to skip re-reads; here the
//! slots become ordinary writes (last put or delete per key, unstaged writes last), which
//! merkleize to the same root.

const std = @import("std");
const assert = std.debug.assert;
const refcount = @import("../../refcount.zig");
const RefCount = refcount.RefCount;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const chain = @import("../chain.zig");
const value_mod = @import("../value.zig");
const floor_mod = @import("../floor.zig");
const bitmap_mod = @import("../bitmap.zig");
const diff_mod = @import("diff.zig");
const ordered_mod = @import("ordered.zig");

/// The unmerkleized batch of database type `D`.
pub fn Unmerkleized(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;
        pub const Mutation = struct { key: K, value: ?V };

        gpa: Allocator,
        journal_batch: D.Log.UnmerkleizedBatch,
        metadata: ?V = null,
        /// Writes in order; a later write of a key replaces an earlier one.
        mutations: std.ArrayList(Mutation) = .empty,
        /// A strong reference to the parent, null for a batch on the database.
        parent: ?*D.MerkleizedBatch,
        /// The commitment this batch builds on.
        base: D.Commitment,
        base_floor: u64,
        base_active_keys: usize,

        /// Discards the batch and the values it owns.
        pub fn deinit(self: *Self) void {
            self.journal_batch.deinit(self.gpa);
            self.free_values();
            self.mutations.deinit(self.gpa);
            if (self.parent) |parent| parent.release();
            self.* = undefined;
        }

        fn free_values(self: *Self) void {
            for (self.mutations.items) |mutation| codec.free(?V, self.gpa, mutation.value);
            codec.free(?V, self.gpa, self.metadata);
            self.metadata = null;
        }

        /// Sets the metadata of this batch's commit (not inherited by children). The batch owns
        /// `metadata` and frees any it held before.
        pub fn with_metadata(self: *Self, metadata: ?V) void {
            codec.free(?V, self.gpa, self.metadata);
            self.metadata = metadata;
        }

        /// Sets `key` to `value`, or deletes it if `value` is null. The batch owns `value` on
        /// success (the caller keeps it on error).
        pub fn write(self: *Self, key: K, value: ?V) !void {
            try self.mutations.append(self.gpa, .{ .key = key, .value = value });
        }

        fn compatible(self: *const Self, db: *const D) !void {
            const parent = self.parent orelse return self.base.compatible(db.commitment());
            return parent.bounds.compatible(db.commitment());
        }

        /// This batch's latest write of `key`, if any.
        fn find_mutation(self: *const Self, key: *const K) ?Mutation {
            var index = self.mutations.items.len;
            while (index > 0) {
                index -= 1;
                const mutation = self.mutations.items[index];
                if (value_mod.eql(K, mutation.key, key.*)) return mutation;
            }
            return null;
        }

        /// The key's value after this batch, its chain, and `db`. The caller owns it.
        pub fn get(self: *const Self, key: *const K, db: *const D) !?V {
            try self.compatible(db);
            if (self.find_mutation(key)) |mutation| {
                return value_mod.clone(?V, self.gpa, mutation.value);
            }
            const parent = self.parent orelse return db.get(key);
            return parent.read_through(key, db);
        }

        const StagedRead = struct { value: ?V, loc: ?StagedLoc };

        /// The key's value (owned by the caller) through this batch and where it resolved:
        /// null when this batch's own writes answer, the key is missing, or an ancestor deleted
        /// it.
        fn stage_read(self: *const Self, key: *const K, db: *const D) !StagedRead {
            if (self.find_mutation(key)) |mutation| {
                return .{ .value = try value_mod.clone(?V, self.gpa, mutation.value), .loc = null };
            }
            if (self.parent) |parent| {
                if (try parent.resolve_entry(key, db.log.size())) |entry| return switch (entry) {
                    .active => |a| .{ .value = try value_mod.clone(V, self.gpa, a.value), .loc = .{
                        .ancestor = .{ .loc = a.loc, .base_old_loc = a.base_old_loc },
                    } },
                    .deleted => .{ .value = null, .loc = null },
                };
            }
            const found = try db.get_with_loc(key) orelse return .{ .value = null, .loc = null };
            assert(found.location < db.log.size());
            return .{ .value = found.update.value, .loc = .{ .committed = found.location } };
        }

        /// Reads `keys` into `out` and stages the reads, so a staged merkleize takes one `Slot`
        /// per read. Consumes the batch on success; on error the batch is unchanged.
        pub fn stage(self: *Self, keys: []const K, db: *const D, out: []?V) !D.StagedBatch {
            assert(keys.len == out.len);
            var staged: D.StagedBatch = .{ .batch = self.* };
            _ = staged.expand(keys, db, out) catch |err| {
                staged.keys.deinit(self.gpa);
                staged.resolutions.deinit(self.gpa);
                return err;
            };
            self.* = undefined;
            return staged;
        }

        /// Hashes the batch with the `Proportional` floor policy. Consumes the batch on
        /// success; on error only `deinit` may follow.
        pub fn merkleize(self: *Self, db: *const D) !*D.MerkleizedBatch {
            var policy: floor_mod.Proportional = .{};
            return self.merkleize_with(db, &policy);
        }

        /// Hashes the batch, advancing the floor with `policy` (which must not evict).
        pub fn merkleize_with(self: *Self, db: *const D, policy: anytype) !*D.MerkleizedBatch {
            floor_mod.check(@TypeOf(policy.*));
            const gpa = self.gpa;
            var m = try Merkleizer(D).init(self, db);
            defer m.deinit();
            const writes = try sorted_writes(gpa, self.mutations.items);
            defer gpa.free(writes);
            var walked = if (comptime D.Update.siblings)
                try m.emit_ordered(writes)
            else
                try m.emit_writes(writes);
            defer walked.deinit(gpa);
            const floor = try m.walk(&walked, policy);
            if (comptime D.Update.siblings) {
                if (policy.evicts()) try ordered_mod.Emitter(D).repair_links(&m, &walked);
                try walked.emit_decided(gpa);
            }
            const merkleized = try m.finish(&walked, floor, self.metadata, &self.journal_batch);
            self.free_values();
            self.mutations.deinit(gpa);
            if (self.parent) |parent| parent.release();
            self.* = undefined;
            return merkleized;
        }

        /// The last write of each key, sorted by key.
        fn sorted_writes(gpa: Allocator, mutations: []const Mutation) ![]Mutation {
            const sorted = try gpa.dupe(Mutation, mutations);
            errdefer gpa.free(sorted);
            // A stable sort keeps each key's writes in order, so the last is the newest.
            std.mem.sort(Mutation, sorted, {}, less);
            var count: usize = 0;
            for (sorted, 0..) |mutation, index| {
                const last = index + 1 == sorted.len or
                    diff_mod.order(K, &mutation.key, &sorted[index + 1].key) != .eq;
                if (!last) continue;
                sorted[count] = mutation;
                count += 1;
            }
            assert(count <= mutations.len);
            if (!gpa.resize(sorted, count)) {
                const shrunk = try gpa.dupe(Mutation, sorted[0..count]);
                gpa.free(sorted);
                return shrunk;
            }
            return sorted[0..count];
        }

        fn less(_: void, a: Mutation, b: Mutation) bool {
            return diff_mod.order(K, &a.key, &b.key) == .lt;
        }
    };
}

/// What a staged merkleize does with the key of one staged read slot.
pub fn Slot(comptime V: type) type {
    return union(enum) {
        /// Leaves the key unchanged unless another slot or an unstaged write changes it.
        keep,
        /// Sets the key to this value.
        put: V,
        /// Deletes the key.
        delete,
    };
}

/// A batch whose reads are staged (commonware's `Staged`): the batch, the staged keys, and
/// where each read resolved.
pub fn Staged(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;
        const Mutation = Unmerkleized(D).Mutation;
        pub const Range = struct { start: usize, end: usize };

        batch: D.UnmerkleizedBatch,
        /// The key of each staged read slot.
        keys: std.ArrayList(K) = .empty,
        /// Where each staged read resolved (commonware's `resolved_locs`), parallel to `keys`.
        resolutions: std.ArrayList(?StagedLoc) = .empty,

        /// Discards the staged batch.
        pub fn deinit(self: *Self) void {
            const gpa = self.batch.gpa;
            self.keys.deinit(gpa);
            self.resolutions.deinit(gpa);
            self.batch.deinit();
            self.* = undefined;
        }

        /// The number of staged read slots.
        pub fn len(self: *const Self) usize {
            assert(self.keys.items.len == self.resolutions.items.len);
            return self.keys.items.len;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.len() == 0;
        }

        /// Sets the metadata recorded in the commit, replacing any set before staging.
        pub fn with_metadata(self: *Self, metadata: ?V) void {
            self.batch.with_metadata(metadata);
        }

        /// Reads more `keys` into `out` (owned by the caller), appending them as the returned
        /// range of slots. Keys are not deduplicated against earlier slots. On error the staged
        /// set is unchanged.
        pub fn expand(self: *Self, keys: []const K, db: *const D, out: []?V) !Range {
            assert(keys.len == out.len);
            const gpa = self.batch.gpa;
            try self.batch.compatible(db);
            const start = self.len();
            try self.keys.ensureUnusedCapacity(gpa, keys.len);
            try self.resolutions.ensureUnusedCapacity(gpa, keys.len);
            errdefer {
                self.keys.shrinkRetainingCapacity(start);
                self.resolutions.shrinkRetainingCapacity(start);
            }
            var filled: usize = 0;
            errdefer for (out[0..filled]) |value| codec.free(?V, gpa, value);
            for (keys, out) |*key, *value| {
                const read = try self.batch.stage_read(key, db);
                value.* = read.value;
                filled += 1;
                self.keys.appendAssumeCapacity(key.*);
                self.resolutions.appendAssumeCapacity(read.loc);
            }
            assert(self.len() == start + keys.len);
            return .{ .start = start, .end = self.len() };
        }

        /// Records `slots` (one per staged read, in slot order) and then `unstaged` as writes,
        /// so each key takes its last put or delete and unstaged writes win. The batch owns the
        /// values of the puts and unstaged writes once recorded (a failed reservation leaves
        /// them with the caller; a later merkleize error frees them with the staged batch).
        fn record(self: *Self, slots: []const Slot(V), unstaged: []const Mutation) !void {
            assert(slots.len == self.len()); // One slot per staged read.
            const gpa = self.batch.gpa;
            const mutations = &self.batch.mutations;
            try mutations.ensureUnusedCapacity(gpa, slots.len + unstaged.len);
            for (slots, self.keys.items) |slot, key| switch (slot) {
                .keep => {},
                .put => |value| mutations.appendAssumeCapacity(.{ .key = key, .value = value }),
                .delete => mutations.appendAssumeCapacity(.{ .key = key, .value = null }),
            };
            mutations.appendSliceAssumeCapacity(unstaged);
        }

        /// The batch with `slots` and `unstaged` recorded as its writes. Consumes the staged
        /// batch on success; on error only `deinit` may follow.
        pub fn resolve_updates(
            self: *Self,
            slots: []const Slot(V),
            unstaged: []const Mutation,
        ) !D.UnmerkleizedBatch {
            try self.record(slots, unstaged);
            const batch = self.batch;
            self.keys.deinit(batch.gpa);
            self.resolutions.deinit(batch.gpa);
            self.* = undefined;
            return batch;
        }

        /// Applies the slots and unstaged writes and merkleizes with `Proportional`.
        pub fn merkleize(
            self: *Self,
            slots: []const Slot(V),
            unstaged: []const Mutation,
            db: *const D,
        ) !*D.MerkleizedBatch {
            var policy: floor_mod.Proportional = .{};
            return self.merkleize_with(slots, unstaged, db, &policy);
        }

        /// Applies the slots and unstaged writes and merkleizes with `policy`. Consumes the
        /// staged batch on success; on error only `deinit` may follow.
        pub fn merkleize_with(
            self: *Self,
            slots: []const Slot(V),
            unstaged: []const Mutation,
            db: *const D,
            policy: anytype,
        ) !*D.MerkleizedBatch {
            try self.record(slots, unstaged);
            const gpa = self.batch.gpa;
            const merkleized = try self.batch.merkleize_with(db, policy);
            self.keys.deinit(gpa);
            self.resolutions.deinit(gpa);
            self.* = undefined;
            return merkleized;
        }
    };
}

/// Where a staged read resolved: in the database, or in an ancestor's diff (commonware's
/// `StagedLoc`).
pub const StagedLoc = union(enum) {
    /// Resolved in the database at this location.
    committed: u64,
    /// Resolved in an ancestor's diff at `loc`, superseding the key's database location
    /// `base_old_loc` (null when an ancestor created the key).
    ancestor: struct { loc: u64, base_old_loc: ?u64 },

    /// The database location a write at this resolution supersedes, given the boundary.
    fn superseded(self: StagedLoc, boundary: u64) ?u64 {
        return switch (self) {
            .committed => |loc| loc,
            .ancestor => |a| if (a.loc < boundary) a.loc else a.base_old_loc,
        };
    }
};

/// How an active floor candidate records its move to the tip.
pub const Move = union(enum) {
    /// The key has a diff entry at this index.
    existing: struct { index: usize, base_old_loc: ?u64 },
    /// The key has no diff entry.
    new: struct { base_old_loc: ?u64 },
};

/// The state a merkleize builds: the batch's operations and key-level changes.
fn Walked(comptime D: type) type {
    return struct {
        const Self = @This();
        const Pair = diff_mod.Pair(D.Key, D.Value);

        /// Location of the batch's first operation.
        base: u64,
        ops: std.ArrayList(D.Operation) = .empty,
        /// This batch's key-level changes (key-sorted once the walk starts).
        diff: std.ArrayList(Pair) = .empty,
        /// Entries the walk adds for keys `diff` lacks.
        floor_diff: std.ArrayList(Pair) = .empty,
        active_keys_delta: i64 = 0,
        /// Database locations the batch's writes supersede.
        superseded: std.ArrayList(u64) = .empty,
        /// An ordered evicting walk's decisions, emitted after the link repair (commonware's
        /// `Decided`): the walk's in location order, then the repaired predecessors.
        decided: std.ArrayList(Decided) = .empty,

        /// A decided update (its value borrowed) and whether the walk evicted its key.
        pub const Decided = struct { update: D.Update, mv: Move, evicted: bool };

        fn deinit(self: *Self, gpa: Allocator) void {
            self.decided.deinit(gpa);
            self.ops.deinit(gpa);
            self.diff.deinit(gpa);
            self.floor_diff.deinit(gpa);
            self.superseded.deinit(gpa);
            self.* = undefined;
        }

        fn next_loc(self: *const Self) u64 {
            return self.base + self.ops.items.len;
        }

        pub fn push_delete(self: *Self, gpa: Allocator, key: D.Key, base_old_loc: ?u64) !void {
            try self.ops.append(gpa, .{ .delete = key });
            try self.diff.append(gpa, .{ .key = key, .entry = .{ .deleted = .{
                .base_old_loc = base_old_loc,
            } } });
            self.active_keys_delta -= 1;
        }

        pub fn push_update(
            self: *Self,
            gpa: Allocator,
            update: D.Update,
            base_old_loc: ?u64,
        ) !void {
            try self.diff.append(gpa, .{ .key = update.key, .entry = .{ .active = .{
                .value = update.value,
                .loc = self.next_loc(),
                .base_old_loc = base_old_loc,
            } } });
            try self.ops.append(gpa, .{ .update = update });
        }

        /// Appends a delete of `key` at the tip (an evicted update), recording it as `mv`
        /// directs.
        fn evict(self: *Self, gpa: Allocator, key: D.Key, mv: Move) !void {
            const ops_before = self.ops.items.len;
            switch (mv) {
                .existing => |e| self.diff.items[e.index].entry = .{ .deleted = .{
                    .base_old_loc = e.base_old_loc,
                } },
                .new => |n| try self.floor_diff.append(gpa, .{
                    .key = key,
                    .entry = .{ .deleted = .{ .base_old_loc = n.base_old_loc } },
                }),
            }
            try self.ops.append(gpa, .{ .delete = key });
            self.active_keys_delta -= 1;
            assert(self.ops.items.len == ops_before + 1);
        }

        /// Emits the collected decisions in order.
        fn emit_decided(self: *Self, gpa: Allocator) !void {
            const ops_before = self.ops.items.len;
            for (self.decided.items) |decided| {
                if (decided.evicted) {
                    try self.evict(gpa, decided.update.key, decided.mv);
                } else {
                    try self.relocate(gpa, decided.update, decided.mv);
                }
            }
            assert(self.ops.items.len == ops_before + self.decided.items.len);
        }

        /// Appends `update` at the tip, recording its move as `mv` directs.
        fn relocate(self: *Self, gpa: Allocator, update: D.Update, mv: Move) !void {
            const loc = self.next_loc();
            switch (mv) {
                .existing => |e| self.diff.items[e.index].entry = .{ .active = .{
                    .value = update.value,
                    .loc = loc,
                    .base_old_loc = e.base_old_loc,
                } },
                .new => |n| try self.floor_diff.append(gpa, .{
                    .key = update.key,
                    .entry = .{ .active = .{
                        .value = update.value,
                        .loc = loc,
                        .base_old_loc = n.base_old_loc,
                    } },
                }),
            }
            try self.ops.append(gpa, .{ .update = update });
        }
    };
}

/// The resolution and merkleization machinery of one batch.
fn Merkleizer(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;
        const Pair = diff_mod.Pair(K, V);
        const Mutation = Unmerkleized(D).Mutation;

        gpa: Allocator,
        db: *const D,
        /// Operations read from the log, which own the values the walk borrows from them.
        reads: std.ArrayList(D.Operation) = .empty,
        /// Values floor policies wrote in place of an update's own, owned here.
        written: std.ArrayList(V) = .empty,
        parent: ?*D.MerkleizedBatch,
        /// The live ancestors, parent first, each retained.
        ancestors: []*D.MerkleizedBatch,
        /// Their diffs' entries, in the same order.
        ancestor_entries: []const []const Pair,
        base_state: D.Commitment,
        /// The effective boundary between the database and the live ancestors.
        db_state: D.Commitment,
        base_floor: u64,
        base_active_keys: usize,

        /// Collects the live ancestors and validates the chain against `db`.
        fn init(batch: *const Unmerkleized(D), db: *const D) !Self {
            const gpa = batch.gpa;
            var ancestors: std.ArrayList(*D.MerkleizedBatch) = .empty;
            defer ancestors.deinit(gpa);
            errdefer for (ancestors.items) |a| a.release();
            var ancestry: refcount.Ancestors(D.MerkleizedBatch) = .from_first(gpa, batch.parent);
            defer ancestry.deinit();
            while (ancestry.next()) |ancestor| {
                try ancestors.ensureUnusedCapacity(gpa, 1);
                ancestors.appendAssumeCapacity(ancestor.retain());
            }
            const inherited = if (batch.parent) |p| p.bounds.db else batch.base;
            const oldest_base: ?D.Commitment = if (ancestors.items.len > 0)
                ancestors.items[ancestors.items.len - 1].bounds.base
            else
                null;
            const db_state = chain.effective_boundary(D.Family, D.Digest, inherited, oldest_base);
            const tips = try gpa.alloc(D.Commitment, ancestors.items.len);
            defer gpa.free(tips);
            for (ancestors.items, tips) |a, *tip| tip.* = a.bounds.tip;
            const db_commitment = db.commitment();
            try chain.validate_batch_applicable(D.Family, D.Digest, db_commitment, db_state, tips);
            const entries = try gpa.alloc([]const Pair, ancestors.items.len);
            for (ancestors.items, entries) |a, *e| e.* = a.diff.entries;
            const owned = ancestors.toOwnedSlice(gpa) catch |err| {
                gpa.free(entries);
                return err;
            };
            return .{
                .gpa = gpa,
                .db = db,
                .parent = batch.parent,
                .ancestors = owned,
                .ancestor_entries = entries,
                .base_state = batch.base,
                .db_state = db_state,
                .base_floor = batch.base_floor,
                .base_active_keys = batch.base_active_keys,
            };
        }

        fn deinit(self: *Self) void {
            for (self.reads.items) |*op| op.deinit(self.gpa);
            self.reads.deinit(self.gpa);
            codec.free_items(V, self.gpa, self.written.items);
            self.written.deinit(self.gpa);
            for (self.ancestors) |ancestor| ancestor.release();
            self.gpa.free(self.ancestors);
            self.gpa.free(self.ancestor_entries);
            self.* = undefined;
        }

        /// The operation at `loc`, which lies at or past the boundary: in an ancestor or in
        /// this batch's `ops`.
        fn peek_uncommitted(self: *const Self, loc: u64, ops: []const D.Operation) D.Operation {
            assert(loc >= self.db_state.size);
            if (loc >= self.base_state.size) return ops[@intCast(loc - self.base_state.size)];
            for (self.ancestors) |ancestor| {
                const items = ancestor.journal_batch.batch_items();
                const end = ancestor.journal_batch.size();
                if (loc >= end - items.len and loc < end) {
                    return items[@intCast(loc - (end - items.len))];
                }
            }
            unreachable; // The ancestors cover [boundary, base) contiguously.
        }

        /// The operation at `loc` below this batch's base, borrowed until `deinit`.
        pub fn read_op(self: *Self, loc: u64) !D.Operation {
            if (loc >= self.db_state.size) return self.peek_uncommitted(loc, &.{});
            if (comptime !D.Operation.owns_memory) return self.db.log.read(loc);
            try self.reads.ensureUnusedCapacity(self.gpa, 1);
            const op = try self.db.log.read(loc);
            self.reads.appendAssumeCapacity(op);
            return op;
        }

        /// The previous locations of the written keys: ancestor diff locations of keys the
        /// ancestors keep active, snapshot candidates of keys they do not touch. Sorted.
        /// Ordered databases also gather the snapshot collision siblings of keys the ancestors
        /// keep active (commonware's `SIBLINGS`), so their links are rewritten when a sibling
        /// leaves.
        pub fn gather_existing_locations(self: *Self, writes: []const Mutation) ![]u64 {
            var locations: std.ArrayList(u64) = .empty;
            errdefer locations.deinit(self.gpa);
            var cursors = try diff_mod.Cursors(K, V).init(self.gpa, self.ancestor_entries);
            defer cursors.deinit(self.gpa);
            for (writes) |*write| {
                var skip: ?u64 = null;
                if (cursors.resolve(&write.key)) |entry| {
                    const loc = entry.loc() orelse continue; // Deleted: nothing is active.
                    try locations.append(self.gpa, loc);
                    if (comptime !D.Update.siblings) continue;
                    skip = entry.base_old_loc();
                }
                var values = self.db.snapshot.get(value_mod.bytes(K, &write.key));
                while (values.next()) |loc| {
                    if (skip != null and loc.* == skip.?) continue;
                    try locations.append(self.gpa, loc.*);
                }
            }
            std.mem.sort(u64, locations.items, {}, std.sort.asc(u64));
            var count: usize = 0;
            for (locations.items) |loc| {
                if (count > 0 and locations.items[count - 1] == loc) continue;
                locations.items[count] = loc;
                count += 1;
            }
            locations.shrinkRetainingCapacity(count);
            return locations.toOwnedSlice(self.gpa);
        }

        /// Emits the writes: updates and deletes of existing keys in location order, then
        /// creates in key order.
        fn emit_writes(self: *Self, writes: []const Mutation) !Walked(D) {
            const gpa = self.gpa;
            var walked: Walked(D) = .{ .base = self.base_state.size };
            errdefer walked.deinit(gpa);
            const consumed = try gpa.alloc(bool, writes.len);
            defer gpa.free(consumed);
            @memset(consumed, false);
            const locations = try self.gather_existing_locations(writes);
            defer gpa.free(locations);
            for (locations) |old_loc| {
                const op = try self.read_op(old_loc);
                if (op != .update) return error.DataCorrupted; // Candidates are updates.
                const key = op.update.key;
                var base_old_loc: ?u64 = old_loc;
                if (diff_mod.resolve(K, V, self.ancestor_entries, &key)) |entry| {
                    if (entry.loc() != old_loc) continue;
                    base_old_loc = entry.base_old_loc();
                }
                const index = find_write(writes, &key) orelse continue; // A collision.
                if (consumed[index]) continue;
                consumed[index] = true;
                try emit(&walked, gpa, writes[index], base_old_loc);
            }
            for (writes, consumed) |write, done| {
                if (done) continue;
                const value = write.value orelse continue; // Deleting an absent key.
                var base_old_loc: ?u64 = null;
                if (diff_mod.resolve(K, V, self.ancestor_entries, &write.key)) |entry| {
                    if (entry.* == .deleted) base_old_loc = entry.base_old_loc();
                }
                if (base_old_loc) |loc| try walked.superseded.append(gpa, loc);
                try walked.push_update(gpa, .{ .key = write.key, .value = value }, base_old_loc);
                walked.active_keys_delta += 1;
            }
            return walked;
        }

        /// `emit_writes` for ordered updates (`ordered.zig`).
        fn emit_ordered(self: *Self, writes: []const Mutation) !Walked(D) {
            var walked: Walked(D) = .{ .base = self.base_state.size };
            errdefer walked.deinit(self.gpa);
            try ordered_mod.Emitter(D).emit(self, &walked, writes);
            assert(walked.next_loc() >= self.base_state.size);
            return walked;
        }

        fn emit(walked: *Walked(D), gpa: Allocator, write: Mutation, base_old_loc: ?u64) !void {
            if (base_old_loc) |loc| try walked.superseded.append(gpa, loc);
            if (write.value) |value| {
                try walked.push_update(gpa, .{ .key = write.key, .value = value }, base_old_loc);
            } else {
                try walked.push_delete(gpa, write.key, base_old_loc);
            }
        }

        fn find_write(writes: []const Mutation, key: *const K) ?usize {
            var low: usize = 0;
            var high: usize = writes.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                switch (diff_mod.order(K, &writes[mid].key, key)) {
                    .lt => low = mid + 1,
                    .gt => high = mid,
                    .eq => return mid,
                }
            }
            return null;
        }

        /// How the update of `key` at `loc` moves, or null if it is not its key's active
        /// update.
        pub fn classify(self: *const Self, diff: []const Pair, loc: u64, key: *const K) ?Move {
            if (lookup_index(diff, key)) |index| {
                const entry = &diff[index].entry;
                if (entry.loc() != loc) return null;
                return .{ .existing = .{ .index = index, .base_old_loc = entry.base_old_loc() } };
            }
            const staged = self.locate(loc, key) orelse return null;
            return .{ .new = .{ .base_old_loc = staged.superseded(self.db_state.size) } };
        }

        /// Where the update of `key` at `loc` resolves among the ancestors, or null if the
        /// nearest ancestor entry for `key` is not an update at `loc`.
        pub fn locate(self: *const Self, loc: u64, key: *const K) ?StagedLoc {
            const entry = diff_mod.resolve(K, V, self.ancestor_entries, key) orelse
                return .{ .committed = loc };
            if (entry.loc() != loc) return null;
            return .{ .ancestor = .{ .loc = loc, .base_old_loc = entry.base_old_loc() } };
        }

        fn lookup_index(diff: []const Pair, key: *const K) ?usize {
            var low: usize = 0;
            var high: usize = diff.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                switch (diff_mod.order(K, &diff[mid].key, key)) {
                    .lt => low = mid + 1,
                    .gt => high = mid,
                    .eq => return mid,
                }
            }
            return null;
        }

        /// Walks the floor from the inherited one over the operations below the tip, moving
        /// the active updates it reaches to the tip. Returns the floor it reached.
        fn walk(self: *Self, walked: *Walked(D), policy: anytype) !u64 {
            std.mem.sort(Pair, walked.diff.items, {}, pair_less);
            const delta = walked.active_keys_delta;
            const active_keys: i64 = @as(i64, @intCast(self.base_active_keys)) + delta;
            assert(active_keys >= 0);
            const made_inactive: usize = @intCast(@as(i64, @intCast(walked.ops.items.len)) - delta);
            const limits = policy.limits(made_inactive);
            const next_loc = walked.next_loc();
            var w = floor_mod.Walk.init(self.base_floor, next_loc, limits.entries, limits.skips);
            if (active_keys == 0 or w.entries == 0) return w.floor;
            const inactive = walked.superseded.items;
            std.mem.sort(u64, inactive, {}, std.sort.asc(u64));
            try walked.superseded.append(self.gpa, self.db_state.size - 1);
            var candidates: std.ArrayList(u64) = .empty;
            defer candidates.deinit(self.gpa);
            var scan = w.floor;
            while (w.entries > 0) {
                if (scan >= w.end) {
                    w.exhaust();
                    break;
                }
                candidates.clearRetainingCapacity();
                try self.read_round(&scan, w.end, w.entries, walked.superseded.items, &candidates);
                if (!try self.walk_round(walked, &w, candidates.items, policy)) break;
            }
            return w.floor;
        }

        /// Decides the round's active candidates; false once the walk ends.
        fn walk_round(
            self: *Self,
            walked: *Walked(D),
            w: *floor_mod.Walk,
            candidates: []const u64,
            policy: anytype,
        ) !bool {
            for (candidates) |loc| {
                const op = if (loc < self.db_state.size)
                    try self.read_op(loc)
                else
                    self.peek_uncommitted(loc, walked.ops.items);
                const key = op.key() orelse continue; // A commit is inactive.
                const mv = self.classify(walked.diff.items, loc, key) orelse continue;
                if (op != .update) return error.DataCorrupted; // Active operations are updates.
                if (!w.reach(loc)) return false;
                const update = op.update;
                if (!try self.decide(walked, update, loc, mv, policy)) return false;
                w.decide();
                if (w.entries == 0) return false;
            }
            return true;
        }

        /// Hands `policy` the active `update` at `loc` (with a value it owns, as commonware's
        /// `Entry` does) and applies its decision at the tip; false if it stopped the walk.
        fn decide(
            self: *Self,
            walked: *Walked(D),
            update: D.Update,
            loc: u64,
            mv: Move,
            policy: anytype,
        ) !bool {
            const gpa = self.gpa;
            try self.written.ensureUnusedCapacity(gpa, 1);
            const entry: floor_mod.Entry(K, V) = .{
                .location = loc,
                .key = &update.key,
                .value = try value_mod.clone(V, gpa, update.value),
            };
            const decision = policy.decide(K, V, entry);
            if (decision.released) |released| codec.free(V, gpa, released);
            // An ordered evicting walk defers its decisions to the link repair.
            if (comptime D.Update.siblings) {
                if (policy.evicts()) {
                    const Decided = Walked(D).Decided;
                    var decided: Decided = .{ .update = update, .mv = mv, .evicted = false };
                    switch (decision.action) {
                        .write => |value| {
                            self.written.appendAssumeCapacity(value);
                            decided.update.value = value;
                        },
                        .evict => decided.evicted = true,
                        .stop => return false,
                    }
                    try walked.decided.append(gpa, decided);
                    return true;
                }
            }
            switch (decision.action) {
                .write => |value| {
                    // The walk owns the written value until the journal batch takes a copy.
                    self.written.appendAssumeCapacity(value);
                    var moved = update; // Ordered updates keep their next key.
                    moved.value = value;
                    try walked.relocate(gpa, moved, mv);
                },
                // The policy owns the evicted value.
                .evict => try walked.evict(gpa, update.key, mv),
                .stop => return false,
            }
            return true;
        }

        /// Selects the next candidates from `scan` below `last` until `need` of them lie
        /// outside the sorted `inactive` locations, moving `scan` past them.
        fn read_round(
            self: *Self,
            scan: *u64,
            last: u64,
            need: usize,
            inactive: []const u64,
            out: *std.ArrayList(u64),
        ) !void {
            var inactive_at = std.sort.lowerBound(u64, inactive, scan.*, order_u64);
            while (out.items.len < need and scan.* < last) {
                const kept = out.items.len;
                const bitmap = &self.db.bitmap;
                const next = try bitmap_mod.fill_from(self.gpa, bitmap, scan.*, last, need, out);
                if (out.items.len == kept) {
                    scan.* = last;
                    break;
                }
                assert(next > scan.*);
                scan.* = next;
                var write: usize = kept;
                for (out.items[kept..]) |loc| {
                    while (inactive_at < inactive.len and inactive[inactive_at] < loc) {
                        inactive_at += 1;
                    }
                    if (inactive_at < inactive.len and inactive[inactive_at] == loc) continue;
                    out.items[write] = loc;
                    write += 1;
                }
                out.shrinkRetainingCapacity(write);
            }
        }

        fn order_u64(context: u64, item: u64) std.math.Order {
            return std.math.order(context, item);
        }

        fn pair_less(_: void, a: Pair, b: Pair) bool {
            return diff_mod.order(K, &a.key, &b.key) == .lt;
        }

        /// Appends the commit, hashes the operations, and builds the merkleized batch.
        fn finish(
            self: *Self,
            walked: *Walked(D),
            walk_floor: u64,
            metadata: ?V,
            journal_batch: *D.Log.UnmerkleizedBatch,
        ) !*D.MerkleizedBatch {
            const gpa = self.gpa;
            const commit_loc = walked.next_loc();
            const total: i64 = @as(i64, @intCast(self.base_active_keys)) + walked.active_keys_delta;
            assert(total >= 0);
            // An empty database raises its floor to the tip.
            const floor = if (total == 0) commit_loc else walk_floor;
            try walked.ops.append(gpa, .{ .commit = .{ .metadata = metadata, .floor = floor } });
            const entries = try self.merged_diff(walked);
            var diff_owned: ?*diff_mod.Diff(K, V) = null;
            errdefer if (diff_owned) |d|
                d.release(gpa)
            else
                diff_mod.free_entries(K, V, gpa, entries);
            diff_owned = try diff_mod.Diff(K, V).create(gpa, entries);
            const base_locs = try self.ancestor_base_locs();
            errdefer gpa.free(base_locs);
            const tips = try gpa.alloc(D.Commitment, self.ancestors.len);
            errdefer gpa.free(tips);
            for (self.ancestors, tips) |a, *tip| tip.* = a.bounds.tip;
            const diffs = try gpa.alloc(*diff_mod.Diff(K, V), self.ancestors.len);
            errdefer gpa.free(diffs);
            const merkleized = try gpa.create(D.MerkleizedBatch);
            errdefer gpa.destroy(merkleized);
            try add_owned(gpa, journal_batch, walked.ops.items);
            const journal = try journal_batch.merkleize(gpa, &self.db.log);
            errdefer journal.release(gpa);
            const tip_size = commit_loc + 1;
            const peaks = merkle.inactive_peaks(D.Family, tip_size, floor);
            const root = try journal.root(&self.db.log.hasher, peaks);
            for (self.ancestors, diffs) |a, *d| d.* = a.diff.retain();
            merkleized.* = .{
                .gpa = gpa,
                .strong = .init(),
                .weak = .init(),
                .parent = self.parent,
                .journal_batch = journal,
                .diff = diff_owned.?,
                .total_active_keys = @intCast(total),
                .ancestor_diffs = diffs,
                .ancestor_base_locs = base_locs,
                .bounds = .{
                    .base = self.base_state,
                    .db = self.db_state,
                    .tip = .{ .size = tip_size, .root = root },
                    .ancestors = tips,
                    .inactivity_floor = floor,
                },
            };
            if (self.parent) |parent| parent.weak.retain();
            return merkleized;
        }

        /// Adds copies of `ops` (which borrow their values) to the journal batch, which owns
        /// them after.
        fn add_owned(
            gpa: Allocator,
            journal_batch: *D.Log.UnmerkleizedBatch,
            ops: []const D.Operation,
        ) !void {
            if (comptime !D.Operation.owns_memory) return journal_batch.add_many(gpa, ops);
            const owned = try gpa.alloc(D.Operation, ops.len);
            defer gpa.free(owned);
            var cloned: usize = 0;
            errdefer for (owned[0..cloned]) |*op| op.deinit(gpa);
            for (ops, owned) |op, *copy| {
                copy.* = try op.clone(gpa);
                cloned += 1;
            }
            try journal_batch.add_many(gpa, owned);
            assert(cloned == ops.len);
        }

        /// The walk's new entries merged into the key-sorted diff (the inputs are disjoint),
        /// with copies of their values.
        fn merged_diff(self: *Self, walked: *Walked(D)) ![]Pair {
            const gpa = self.gpa;
            const total = walked.diff.items.len + walked.floor_diff.items.len;
            const merged = try gpa.alloc(Pair, total);
            errdefer gpa.free(merged);
            @memcpy(merged[0..walked.diff.items.len], walked.diff.items);
            @memcpy(merged[walked.diff.items.len..], walked.floor_diff.items);
            std.mem.sort(Pair, merged, {}, pair_less);
            assert(diff_mod.is_sorted(K, V, merged));
            if (comptime !codec.owns_memory(V)) return merged;
            var cloned: usize = 0;
            errdefer for (merged[0..cloned]) |*pair| {
                if (pair.entry == .active) codec.free(V, gpa, pair.entry.active.value);
            };
            for (merged) |*pair| {
                if (pair.entry == .active) {
                    const value = &pair.entry.active.value;
                    value.* = try value_mod.clone(V, gpa, value.*);
                }
                cloned += 1;
            }
            return merged;
        }

        /// For keys both a live ancestor and an older, dropped one wrote: the key's location
        /// after the dropped ones (commonware's `ancestor_base_locs`).
        fn ancestor_base_locs(self: *Self) ![]D.MerkleizedBatch.BaseLoc {
            const gpa = self.gpa;
            var out: std.ArrayList(D.MerkleizedBatch.BaseLoc) = .empty;
            errdefer out.deinit(gpa);
            if (self.ancestors.len == 0) return out.toOwnedSlice(gpa);
            const oldest = self.ancestors[self.ancestors.len - 1];
            const dropped_entries = try gpa.alloc([]const Pair, oldest.ancestor_diffs.len);
            defer gpa.free(dropped_entries);
            for (oldest.ancestor_diffs, dropped_entries) |d, *e| e.* = d.entries;
            var dropped = try diff_mod.Cursors(K, V).init(gpa, dropped_entries);
            defer dropped.deinit(gpa);
            var merge = try diff_mod.Merge(K, V).init(gpa, self.ancestor_entries);
            defer merge.deinit(gpa);
            while (merge.next()) |pair| {
                const entry = dropped.resolve(&pair.key) orelse continue;
                try out.append(gpa, .{ .key = pair.key, .loc = entry.loc() });
            }
            return out.toOwnedSlice(gpa);
        }
    };
}

/// The merkleized batch of database type `D`.
pub fn Merkleized(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;
        const Pair = diff_mod.Pair(K, V);
        pub const Diff = diff_mod.Diff(K, V);
        /// A key's location after dropped ancestors, null if they deleted it.
        pub const BaseLoc = struct { key: K, loc: ?u64 };

        gpa: Allocator,
        strong: RefCount,
        weak: RefCount,
        parent: ?*Self,
        journal_batch: *D.Log.MerkleizedBatch,
        /// This batch's own key-level changes, sorted by key.
        diff: *Diff,
        /// Active keys after this batch.
        total_active_keys: usize,
        /// The diffs of the ancestors live at merkleize, parent first (1:1 with
        /// `bounds.ancestors`).
        ancestor_diffs: []const *Diff,
        /// Sorted by key.
        ancestor_base_locs: []const BaseLoc,
        bounds: D.Bounds,

        /// A batch representing `db`'s current state.
        pub fn from_db(db: *const D) !*Self {
            const gpa = db.gpa;
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            const diff = try Diff.create(gpa, &.{});
            errdefer diff.release(gpa);
            const journal_batch = try db.log.to_merkleized_batch();
            self.* = .{
                .gpa = gpa,
                .strong = .init(),
                .weak = .init(),
                .parent = null,
                .journal_batch = journal_batch,
                .diff = diff,
                .total_active_keys = db.active_keys,
                .ancestor_diffs = &.{},
                .ancestor_base_locs = &.{},
                .bounds = D.Bounds.from_db(db.commitment(), db.inactivity_floor_loc),
            };
            return self;
        }

        pub fn retain(self: *Self) *Self {
            self.strong.retain();
            return self;
        }

        pub fn release(self: *Self) void {
            if (!self.strong.release()) return;
            const gpa = self.gpa;
            self.journal_batch.release(gpa);
            self.diff.release(gpa);
            for (self.ancestor_diffs) |d| d.release(gpa);
            gpa.free(self.ancestor_diffs);
            gpa.free(self.ancestor_base_locs);
            self.bounds.deinit(gpa);
            if (self.parent) |parent| parent.release_weak();
            self.parent = null;
            self.release_weak();
        }

        fn release_weak(self: *Self) void {
            if (self.weak.release()) self.gpa.destroy(self);
        }

        pub fn commitment(self: *const Self) D.Commitment {
            return self.bounds.tip;
        }

        pub fn root(self: *const Self) D.Digest {
            return self.bounds.tip.root;
        }

        /// This batch's own operations and the location of the first.
        pub fn operations(self: *const Self) struct { u64, []const D.Operation } {
            return .{ self.bounds.base.size, self.journal_batch.batch_items() };
        }

        /// A proof of this batch's operations against its root. Caller owns it.
        pub fn proof(self: *const Self, db: *const D) !D.Proof {
            try self.bounds.compatible(db.commitment());
            const tip = self.bounds.tip.size;
            const peaks = merkle.inactive_peaks(D.Family, tip, self.bounds.inactivity_floor);
            return db.log.speculative_proof(self.journal_batch, peaks);
        }

        /// The pins of this batch's first operation.
        pub fn pinned_nodes(
            self: *const Self,
            db: *const D,
            out: *[merkle.max_pinned_nodes]D.Digest,
        ) ![]D.Digest {
            try self.bounds.compatible(db.commitment());
            return db.log.speculative_pinned_nodes(self.journal_batch, out);
        }

        /// The diffs reads consult, nearest first: this batch's, then its ancestors' while
        /// they are live or unapplied to a database of `db_size` operations.
        fn read_diffs(self: *const Self, db_size: u64, out: *std.ArrayList([]const Pair)) !void {
            try out.append(self.gpa, self.diff.entries);
            var live: usize = 0;
            var walk: refcount.Ancestors(Self) = .init(self.gpa, self);
            defer walk.deinit();
            while (walk.next()) |_| live += 1;
            for (self.ancestor_diffs, self.bounds.ancestors, 0..) |d, state, index| {
                if (index >= live and state.size <= db_size) break;
                try out.append(self.gpa, d.entries);
            }
        }

        /// The nearest entry for `key` in this batch's chain, as read against a database of
        /// `db_size` operations.
        fn resolve_entry(self: *const Self, key: *const K, db_size: u64) !?diff_mod.Entry(V) {
            var diffs: std.ArrayList([]const Pair) = .empty;
            defer diffs.deinit(self.gpa);
            try self.read_diffs(db_size, &diffs);
            assert(diffs.items.len >= 1);
            const entry = diff_mod.resolve(K, V, diffs.items, key) orelse return null;
            return entry.*;
        }

        /// The key's value through this batch's chain, falling back to `db`. The caller owns
        /// it.
        fn read_through(self: *const Self, key: *const K, db: *const D) !?V {
            if (try self.resolve_entry(key, db.log.size())) |entry| {
                return value_mod.clone(?V, self.gpa, entry.value());
            }
            return db.get(key);
        }

        /// The key's value after this batch. The caller owns it.
        pub fn get(self: *const Self, key: *const K, db: *const D) !?V {
            try self.bounds.compatible(db.commitment());
            return self.read_through(key, db);
        }

        /// The smallest active key strictly above `key` after this batch and its chain, null if
        /// none (not wrapping); `key` need not be active. Ordered databases only.
        pub fn get_next_key(self: *const Self, key: *const K, db: *const D) !?K {
            comptime assert(D.Update.siblings);
            try self.bounds.compatible(db.commitment());
            if (self.total_active_keys == 0) return null;
            if (try self.find_cyclic_neighbor(true, key, db.log.size())) |next| {
                return if (diff_mod.order(K, &next, key) == .gt) next else null;
            }
            return db.get_next_key(key);
        }

        /// The largest active key strictly below `key` after this batch and its chain, null if
        /// none (not wrapping); `key` need not be active. Ordered databases only.
        pub fn get_prev_key(self: *const Self, key: *const K, db: *const D) !?K {
            comptime assert(D.Update.siblings);
            try self.bounds.compatible(db.commitment());
            if (self.total_active_keys == 0) return null;
            if (try self.find_cyclic_neighbor(false, key, db.log.size())) |prev| {
                return if (diff_mod.order(K, &prev, key) == .lt) prev else null;
            }
            return db.get_prev_key(key);
        }

        /// The cyclic successor (`next`) or predecessor of `key` from the newest diff whose
        /// span owner holds `key`. Membership changes emit affected predecessors and created
        /// keys, so that layer owns the query's span in this batch's view; null defers to the
        /// committed snapshot.
        fn find_cyclic_neighbor(
            self: *const Self,
            comptime next: bool,
            key: *const K,
            db_size: u64,
        ) !?K {
            var diffs: std.ArrayList([]const Pair) = .empty;
            defer diffs.deinit(self.gpa);
            try self.read_diffs(db_size, &diffs);
            assert(diffs.items.len >= 1);
            for (diffs.items) |diff| {
                const loc = span_owner(next, diff, key) orelse continue;
                const update = self.update_at(loc);
                // Successors use the span [key, next_key); predecessors use (key, next_key].
                const inside = if (next)
                    ordered_mod.in_span(K, &update.key, &update.next_key, key)
                else
                    in_span_after(&update.key, &update.next_key, key);
                if (inside) return if (next) update.next_key else update.key;
            }
            return null;
        }

        /// Whether `key` is in the cyclic span `(start, end]`; equal ends span everything.
        fn in_span_after(start: *const K, end: *const K, key: *const K) bool {
            const after_start = diff_mod.order(K, key, start) == .gt;
            const to_end = diff_mod.order(K, key, end) != .gt;
            if (diff_mod.order(K, start, end) == .lt) return after_start and to_end;
            return after_start or to_end;
        }

        /// The location of the active entry of `diff` that could own `key`'s span: the last at
        /// or below it (strictly below for predecessors), else the last overall (wrapping).
        fn span_owner(comptime next: bool, diff: []const Pair, key: *const K) ?u64 {
            const end = std.sort.partitionPoint(Pair, diff, key, struct {
                fn below(query: *const K, pair: Pair) bool {
                    const order = diff_mod.order(K, &pair.key, query);
                    return if (next) order != .gt else order == .lt;
                }
            }.below);
            assert(end <= diff.len);
            var at = end;
            while (at > 0) {
                at -= 1;
                if (diff[at].entry.loc()) |loc| return loc;
            }
            at = diff.len;
            while (at > end) {
                at -= 1;
                if (diff[at].entry.loc()) |loc| return loc;
            }
            return null;
        }

        /// The update at `loc`, an active entry's location in a diff `read_diffs` yields. The
        /// batch retains the operations of every ancestor whose diff it retains.
        fn update_at(self: *const Self, loc: u64) *const D.Update {
            assert(loc < self.bounds.tip.size);
            const own = self.journal_batch.batch_items();
            var base = self.bounds.tip.size - own.len;
            if (loc >= base) return &own[@intCast(loc - base)].update;
            const chunks = self.journal_batch.ancestor_items;
            var at = chunks.len;
            while (at > 0) {
                at -= 1;
                const items = chunks[at].items;
                base -= items.len;
                if (loc >= base) return &items[@intCast(loc - base)].update;
            }
            unreachable; // Proof: a retained diff's operations are in a retained chunk.
        }

        /// A child batch on top of this one.
        pub fn new_batch(self: *Self) D.UnmerkleizedBatch {
            return .{
                .gpa = self.gpa,
                .journal_batch = self.journal_batch.new_batch(),
                .parent = self.retain(),
                .base = self.bounds.tip,
                .base_floor = self.bounds.inactivity_floor,
                .base_active_keys = self.total_active_keys,
            };
        }

        /// Applies this batch's and its unapplied ancestors' key changes to `db`'s snapshot and
        /// bitmap, which hold the state at `db_size` operations.
        pub fn apply_to_index(self: *const Self, db: *D, db_size: u64) !void {
            const tip = self.bounds.tip.size;
            try db.bitmap.extend_to(self.gpa, tip);
            if (self.ancestor_diffs.len == 0) {
                for (self.diff.entries) |*pair| {
                    try apply_diff(db, &pair.key, &pair.entry, pair.entry.base_old_loc());
                }
            } else {
                try self.apply_chain(db, db_size);
            }
            db.bitmap.set_bit(db_size - 1, false);
            db.bitmap.set_bit(tip - 1, true);
        }

        /// `apply_to_index` with ancestors: the unapplied ones' changes merge with this batch's,
        /// and keys' old locations resolve through the applied ones.
        fn apply_chain(self: *const Self, db: *D, db_size: u64) !void {
            const gpa = self.gpa;
            var split: usize = 0;
            while (split < self.bounds.ancestors.len and
                self.bounds.ancestors[split].size > db_size) split += 1;
            const streams = try gpa.alloc([]const Pair, split + 1);
            defer gpa.free(streams);
            streams[0] = self.diff.entries;
            for (self.ancestor_diffs[0..split], streams[1..]) |d, *s| s.* = d.entries;
            const applied = try gpa.alloc([]const Pair, self.ancestor_diffs.len - split);
            defer gpa.free(applied);
            for (self.ancestor_diffs[split..], applied) |d, *s| s.* = d.entries;
            var resolver = try diff_mod.Cursors(K, V).init(gpa, applied);
            defer resolver.deinit(gpa);
            var merge = try diff_mod.Merge(K, V).init(gpa, streams);
            defer merge.deinit(gpa);
            var base_at: usize = 0;
            const base_locs = self.ancestor_base_locs;
            while (merge.next()) |pair| {
                while (base_at < base_locs.len and
                    diff_mod.order(K, &base_locs[base_at].key, &pair.key) == .lt) base_at += 1;
                var old = pair.entry.base_old_loc();
                if (resolver.resolve(&pair.key)) |entry| {
                    old = entry.loc();
                } else if (base_at < base_locs.len and
                    diff_mod.order(K, &base_locs[base_at].key, &pair.key) == .eq)
                {
                    old = base_locs[base_at].loc;
                    base_at += 1;
                }
                try apply_diff(db, &pair.key, &pair.entry, old);
            }
        }

        fn apply_diff(db: *D, key: *const K, entry: *const diff_mod.Entry(V), old: ?u64) !void {
            switch (entry.*) {
                .active => |a| if (old) |o| {
                    db.update_known_loc(key, o, a.loc);
                } else {
                    try db.snapshot.insert(value_mod.bytes(K, key), a.loc);
                },
                .deleted => if (old) |o| db.delete_known_loc(key, o),
            }
            if (entry.loc()) |loc| db.bitmap.set_bit(loc, true);
            if (old) |o| db.bitmap.set_bit(o, false);
        }
    };
}
