//! Batches of an `any` database (qmdb/any/batch.rs and batch/apply.rs), for unordered updates.
//!
//! `db.new_batch()` → `write(key, value)` (null deletes) / `with_metadata` → `merkleize(&db)`
//! → `db.apply_batch(merkleized)`. Merkleizing resolves each written key's previous location
//! (through the live ancestors' diffs, then the snapshot), emits updates of existing keys in
//! location order and creates in key order, walks the inactivity floor forward under a floor
//! policy (moving active updates it reaches to the tip), and appends the commit.
//!
//! A merkleized batch is reference counted (`retain`/`release`); a child holds a weak link to
//! its parent and the diffs of its live ancestors, so reads and applies stay exact after the
//! ancestors are released. Only policies that never evict are supported so far.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const merkle = @import("../../merkle/mod.zig");
const chain = @import("../chain.zig");
const value_mod = @import("../value.zig");
const floor_mod = @import("../floor.zig");
const bitmap_mod = @import("../bitmap.zig");
const diff_mod = @import("diff.zig");

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

        /// Discards the batch.
        pub fn deinit(self: *Self) void {
            self.journal_batch.deinit(self.gpa);
            self.mutations.deinit(self.gpa);
            if (self.parent) |parent| parent.release();
            self.* = undefined;
        }

        /// Sets the metadata of this batch's commit (not inherited by children).
        pub fn with_metadata(self: *Self, metadata: ?V) void {
            self.metadata = metadata;
        }

        /// Sets `key` to `value`, or deletes it if `value` is null.
        pub fn write(self: *Self, key: K, value: ?V) !void {
            try self.mutations.append(self.gpa, .{ .key = key, .value = value });
        }

        fn compatible(self: *const Self, db: *const D) !void {
            const parent = self.parent orelse return self.base.compatible(db.commitment());
            return parent.bounds.compatible(db.commitment());
        }

        /// The key's value after this batch, its chain, and `db`.
        pub fn get(self: *const Self, key: *const K, db: *D) !?V {
            try self.compatible(db);
            var index = self.mutations.items.len;
            while (index > 0) {
                index -= 1;
                const mutation = self.mutations.items[index];
                if (value_mod.eql(K, mutation.key, key.*)) return mutation.value;
            }
            const parent = self.parent orelse return db.get(key);
            return parent.read_through(key, db);
        }

        /// Hashes the batch with the `Proportional` floor policy. Consumes the batch on
        /// success; on error only `deinit` may follow.
        pub fn merkleize(self: *Self, db: *D) !*D.MerkleizedBatch {
            var policy: floor_mod.Proportional = .{};
            return self.merkleize_with(db, &policy);
        }

        /// Hashes the batch, advancing the floor with `policy` (which must not evict).
        pub fn merkleize_with(self: *Self, db: *D, policy: anytype) !*D.MerkleizedBatch {
            floor_mod.check(@TypeOf(policy.*));
            assert(!policy.evicts()); // Evicting policies are not supported yet.
            const gpa = self.gpa;
            var m = try Merkleizer(D).init(self, db);
            defer m.deinit();
            const writes = try sorted_writes(gpa, self.mutations.items);
            defer gpa.free(writes);
            var walked = try m.emit_writes(writes);
            defer walked.deinit(gpa);
            const floor = try m.walk(&walked, policy);
            const merkleized = try m.finish(&walked, floor, self.metadata, &self.journal_batch);
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

/// Where a write resolved: in the database, or in an ancestor's diff.
const StagedLoc = union(enum) {
    committed: u64,
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
const Move = union(enum) {
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

        fn deinit(self: *Self, gpa: Allocator) void {
            self.ops.deinit(gpa);
            self.diff.deinit(gpa);
            self.floor_diff.deinit(gpa);
            self.superseded.deinit(gpa);
            self.* = undefined;
        }

        fn next_loc(self: *const Self) u64 {
            return self.base + self.ops.items.len;
        }

        fn push_delete(self: *Self, gpa: Allocator, key: D.Key, base_old_loc: ?u64) !void {
            try self.ops.append(gpa, .{ .delete = key });
            try self.diff.append(gpa, .{ .key = key, .entry = .{ .deleted = .{
                .base_old_loc = base_old_loc,
            } } });
            self.active_keys_delta -= 1;
        }

        fn push_update(self: *Self, gpa: Allocator, update: D.Update, base_old_loc: ?u64) !void {
            try self.diff.append(gpa, .{ .key = update.key, .entry = .{ .active = .{
                .value = update.value,
                .loc = self.next_loc(),
                .base_old_loc = base_old_loc,
            } } });
            try self.ops.append(gpa, .{ .update = update });
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
        db: *D,
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
        fn init(batch: *const Unmerkleized(D), db: *D) !Self {
            const gpa = batch.gpa;
            var ancestors: std.ArrayList(*D.MerkleizedBatch) = .empty;
            defer ancestors.deinit(gpa);
            errdefer for (ancestors.items) |a| a.release();
            var current = batch.parent;
            while (current) |ancestor| : (current = ancestor.live_parent()) {
                try ancestors.append(gpa, ancestor.retain());
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

        /// The operation at `loc` below this batch's base.
        fn read_op(self: *Self, loc: u64) !D.Operation {
            if (loc < self.db_state.size) return self.db.log.read(loc);
            return self.peek_uncommitted(loc, &.{});
        }

        /// The previous locations of the written keys: ancestor diff locations of keys the
        /// ancestors keep active, snapshot candidates of keys they do not touch. Sorted.
        fn gather_existing_locations(self: *Self, writes: []const Mutation) ![]u64 {
            var locations: std.ArrayList(u64) = .empty;
            errdefer locations.deinit(self.gpa);
            var cursors = try diff_mod.Cursors(K, V).init(self.gpa, self.ancestor_entries);
            defer cursors.deinit(self.gpa);
            for (writes) |*write| {
                if (cursors.resolve(&write.key)) |entry| {
                    if (entry.loc()) |loc| try locations.append(self.gpa, loc);
                    continue;
                }
                var values = self.db.snapshot.get(value_mod.bytes(K, &write.key));
                while (values.next()) |loc| try locations.append(self.gpa, loc.*);
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
        fn classify(self: *const Self, diff: []const Pair, loc: u64, key: *const K) ?Move {
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
        fn locate(self: *const Self, loc: u64, key: *const K) ?StagedLoc {
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
                    try self.db.log.read(loc)
                else
                    self.peek_uncommitted(loc, walked.ops.items);
                const key = op.key() orelse continue; // A commit is inactive.
                const mv = self.classify(walked.diff.items, loc, key) orelse continue;
                if (op != .update) return error.DataCorrupted; // Active operations are updates.
                if (!w.reach(loc)) return false;
                const update = op.update;
                const entry: floor_mod.Entry(K, V) = .{
                    .location = loc,
                    .key = &update.key,
                    .value = update.value,
                };
                const decision = policy.decide(K, V, entry);
                switch (decision.action) {
                    .write => |value| {
                        const moved: D.Update = .{ .key = update.key, .value = value };
                        try walked.relocate(self.gpa, moved, mv);
                    },
                    .stop => return false,
                    .evict => unreachable, // `merkleize_with` refuses evicting policies.
                }
                w.decide();
                if (w.entries == 0) return false;
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
            errdefer if (diff_owned) |d| d.release(gpa) else gpa.free(entries);
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
            try journal_batch.add_many(gpa, walked.ops.items);
            const journal = try journal_batch.merkleize(gpa, &self.db.log);
            errdefer journal.release(gpa);
            const tip_size = commit_loc + 1;
            const peaks = merkle.inactive_peaks(D.Family, tip_size, floor);
            const root = try journal.root(&self.db.log.hasher, peaks);
            for (self.ancestors, diffs) |a, *d| d.* = a.diff.retain();
            merkleized.* = .{
                .gpa = gpa,
                .strong = 1,
                .weak = 1,
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
            if (self.parent) |parent| parent.weak += 1;
            return merkleized;
        }

        /// The walk's new entries merged into the key-sorted diff (the inputs are disjoint).
        fn merged_diff(self: *Self, walked: *Walked(D)) ![]Pair {
            const gpa = self.gpa;
            const total = walked.diff.items.len + walked.floor_diff.items.len;
            const merged = try gpa.alloc(Pair, total);
            @memcpy(merged[0..walked.diff.items.len], walked.diff.items);
            @memcpy(merged[walked.diff.items.len..], walked.floor_diff.items);
            std.mem.sort(Pair, merged, {}, pair_less);
            assert(diff_mod.is_sorted(K, V, merged));
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
        strong: u32,
        weak: u32,
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
                .strong = 1,
                .weak = 1,
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
            assert(self.strong > 0);
            self.strong += 1;
            return self;
        }

        pub fn release(self: *Self) void {
            assert(self.strong > 0);
            self.strong -= 1;
            if (self.strong > 0) return;
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
            assert(self.weak > 0);
            self.weak -= 1;
            if (self.weak == 0) self.gpa.destroy(self);
        }

        pub fn live_parent(self: *const Self) ?*Self {
            const parent = self.parent orelse return null;
            assert(parent.weak > 0);
            return if (parent.strong > 0) parent else null;
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
            var current = self.live_parent();
            while (current) |batch| : (current = batch.live_parent()) live += 1;
            for (self.ancestor_diffs, self.bounds.ancestors, 0..) |d, state, index| {
                if (index >= live and state.size <= db_size) break;
                try out.append(self.gpa, d.entries);
            }
        }

        /// The key's value through this batch's chain, falling back to `db`.
        fn read_through(self: *const Self, key: *const K, db: *D) !?V {
            var diffs: std.ArrayList([]const Pair) = .empty;
            defer diffs.deinit(self.gpa);
            try self.read_diffs(db.log.size(), &diffs);
            if (diff_mod.resolve(K, V, diffs.items, key)) |entry| return entry.value();
            return db.get(key);
        }

        /// The key's value after this batch.
        pub fn get(self: *const Self, key: *const K, db: *D) !?V {
            try self.bounds.compatible(db.commitment());
            return self.read_through(key, db);
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
