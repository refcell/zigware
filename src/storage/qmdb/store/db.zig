//! An unauthenticated key-value store of variable-size values over an append-only log of
//! operations (qmdb/store/db.rs).
//!
//! `Db(K, E, T)`: keys `K` (fixed arrays, or `[]const u8` for variable-length keys, which the
//! store copies), a value encoding `E` (`qmdb.value.Variable`),
//! and translator `T`. The log holds `any` unordered operations over the MMR family, as in
//! commonware, so a store's log is byte-identical to commonware's. A snapshot maps each active
//! key to its latest update, and an activity bitmap marks the active locations the floor walk
//! reads.
//!
//! Differences from commonware: mutators take `*Self` (after a storage error only `deinit` may
//! follow), syncs complete synchronously, a batch is built against the store passed to its
//! reads, and written keys resolve one at a time (commonware batches the reads by bucket for
//! speed; the result is the same).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const index = @import("../../index/mod.zig");
const variable = @import("../../journal/contiguous/variable.zig");
const authenticated = @import("../../journal/authenticated.zig");
const qmdb = @import("../mod.zig");
const value_mod = @import("../value.zig");
const floor_mod = @import("../floor.zig");
const bitmap_mod = @import("../bitmap.zig");
const snapshot_mod = @import("../snapshot.zig");
const any_operation = @import("../any/operation.zig");

const Storage = runtime.storage.Storage;

/// Bytes per activity bitmap chunk (commonware's `any::BITMAP_CHUNK_BYTES`).
pub const bitmap_chunk_bytes = 64;

/// Configuration of a store.
pub fn Config(comptime T: type, comptime LogConfig: type) type {
    return struct {
        /// The operation log.
        log: LogConfig,
        /// The translator of the snapshot index.
        translator: T,
        /// Entries in the `location -> key` cache that resolves snapshot collisions during
        /// init; null disables it.
        init_cache: ?usize = null,
    };
}

pub fn Db(comptime K: type, comptime E: type, comptime T: type) type {
    value_mod.check(E);
    return struct {
        const Self = @This();
        pub const Family = merkle.mmr.Family;
        pub const Key = K;
        pub const Value = E.Value;
        pub const Operation = any_operation.Unordered(Family, K, E);
        pub const Journal = variable.Journal(Operation);
        pub const Index = index.unordered.Index(T, u64);
        pub const Bitmap = bitmap_mod.Shared(bitmap_chunk_bytes);
        pub const Cfg = Config(T, Journal.Cfg);
        /// A key and its new value, or null to delete it.
        pub const Write = struct { key: K, value: ?Value };
        pub const Batch = BatchOf(Self);
        pub const Changeset = ChangesetOf(Self);

        gpa: Allocator,
        /// Every applied operation. Always ends with a commit, and is never pruned past the
        /// inactivity floor.
        log: Journal,
        /// Each active key's latest update location. Holds only update locations.
        snapshot: Index,
        active_keys: usize,
        /// Bit `i` is set iff location `i` holds the current update of an active key, or is
        /// the last commit. Its length is the log's size.
        bitmap: Bitmap,
        /// Every operation below it is inactive.
        inactivity_floor_loc: u64,

        /// Opens the store: selects the last commit (within `max_size` operations), creates the
        /// initial commit if the log is empty, syncs, and rebuilds the snapshot and bitmap from
        /// the commit's floor.
        pub fn init(gpa: Allocator, storage: Storage, cfg: Cfg, max_size: ?u64) !Self {
            try qmdb.validate_initialization_bound(max_size);
            var log = try recover_log(gpa, storage, cfg.log, max_size);
            errdefer log.deinit();
            const genesis: Operation = .{ .commit = .{ .metadata = null, .floor = 0 } };
            if (log.size() == 0) _ = try log.append(genesis);
            // Persist recovery repairs and any genesis commit.
            try log.sync();
            var last = try log.read(log.size() - 1);
            const floor = last.inactivity_floor().?; // Recovery selected a commit.
            last.deinit(gpa);
            var snapshot = Index.init(gpa, cfg.translator);
            errdefer snapshot.deinit();
            const cache_size = cfg.init_cache;
            var built = try snapshot_mod.build(Operation, gpa, floor, &log, &snapshot, cache_size);
            defer built.deinit(gpa);
            var bitmap = try init_bitmap(gpa, log.get_bounds().start, floor, &built.activity);
            errdefer bitmap.deinit(gpa);
            if (bitmap.len() != log.size()) return error.DataCorrupted;
            const self: Self = .{
                .gpa = gpa,
                .log = log,
                .snapshot = snapshot,
                .active_keys = built.active_keys,
                .bitmap = bitmap,
                .inactivity_floor_loc = floor,
            };
            assert(self.inactivity_floor_loc < self.log.size());
            return self;
        }

        /// Recovers the log to its last commit within `max_size`, validated before any history
        /// is discarded.
        fn recover_log(
            gpa: Allocator,
            storage: Storage,
            cfg: Journal.Cfg,
            max_size: ?u64,
        ) !Journal {
            var pending = try Journal.recover(gpa, storage, cfg, max_size);
            const size = select_commit(gpa, &pending, max_size) catch |err| {
                pending.deinit();
                return err;
            };
            assert(size <= pending.get_bounds().end);
            return pending.finish(size); // Consumes `pending`, also on error.
        }

        fn select_commit(gpa: Allocator, pending: anytype, max_size: ?u64) !u64 {
            const ceiling = max_size orelse std.math.maxInt(u64);
            const size = try authenticated.last_matching(pending, ceiling, {}, is_commit);
            const span = pending.get_bounds();
            var selected: ?Operation = if (size == 0) null else try pending.read(size - 1);
            defer if (selected) |*op| op.deinit(gpa);
            const commit_floor: ??u64 = if (selected) |op| op.inactivity_floor() else null;
            const fresh = span.start == 0 and span.end == 0;
            const start = span.start;
            _ = try qmdb.validate_initialization_commit(start, size, fresh, commit_floor, true);
            return size;
        }

        fn is_commit(_: void, op: Operation) bool {
            return op.is_commit();
        }

        /// The bitmap of a log retained from `start`: pruned below `start`'s chunk, clear up
        /// to `floor`, then `activity`.
        fn init_bitmap(
            gpa: Allocator,
            start: u64,
            floor: u64,
            activity: *const snapshot_mod.ActivityBitMap,
        ) !Bitmap {
            var bitmap = try Bitmap.init_pruned(@intCast(start / Bitmap.CHUNK_SIZE_BITS));
            errdefer bitmap.deinit(gpa);
            assert(bitmap.pruned_bits() <= floor);
            try bitmap.extend_to(gpa, floor);
            try bitmap.extend_from_bitmap(gpa, utils.bitmap.DEFAULT_CHUNK_SIZE, activity);
            assert(bitmap.len() >= floor);
            return bitmap;
        }

        /// Closes the store without syncing.
        pub fn deinit(self: *Self) void {
            self.log.deinit();
            self.snapshot.deinit();
            self.bitmap.deinit(self.gpa);
            self.* = undefined;
        }

        /// Removes the store's storage and frees it, also on error.
        pub fn destroy(self: *Self) !void {
            self.snapshot.deinit();
            self.bitmap.deinit(self.gpa);
            defer self.* = undefined;
            try self.log.destroy();
        }

        /// `[oldest retained location, size)`.
        pub fn bounds(self: *const Self) merkle.Range {
            const span = self.log.get_bounds();
            return .{ .start = span.start, .end = span.end };
        }

        pub fn inactivity_floor(self: *const Self) u64 {
            return self.inactivity_floor_loc;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.active_keys == 0;
        }

        /// The value of `key`, or null. The caller owns it.
        pub fn get(self: *Self, key: *const K) !?Value {
            const located = try self.locate(key) orelse return null;
            return located.value;
        }

        /// The values of `keys` into `out`. The caller owns them.
        pub fn get_many(self: *Self, keys: []const K, out: []?Value) !void {
            assert(keys.len == out.len);
            var filled: usize = 0;
            errdefer for (out[0..filled]) |v| codec.free(?Value, self.gpa, v);
            for (keys, out) |*key, *slot| {
                slot.* = try self.get(key);
                filled += 1;
            }
            assert(filled == keys.len);
        }

        const Located = struct { location: u64, value: Value };

        /// The key's latest update location and its (owned) value, if active.
        fn locate(self: *Self, key: *const K) !?Located {
            var locations = self.snapshot.get(value_mod.bytes(K, key));
            while (locations.next()) |location| {
                var op = try self.read_op(location.*);
                if (op != .update) return error.DataCorrupted; // The snapshot holds updates.
                if (value_mod.eql(K, op.update.key, key.*)) {
                    codec.free(K, self.gpa, op.update.key); // The caller owns only the value.
                    return .{ .location = location.*, .value = op.update.value };
                }
                op.deinit(self.gpa);
            }
            return null;
        }

        fn read_op(self: *Self, location: u64) !Operation {
            assert(location < self.log.size());
            return self.log.read(location) catch |err| switch (err) {
                error.ItemPruned => error.OperationPruned,
                else => err,
            };
        }

        /// The metadata of the last commit. The caller owns it.
        pub fn get_metadata(self: *Self) !?Value {
            const op = try self.log.read(self.log.size() - 1);
            assert(op == .commit); // The log always ends with a commit.
            return op.commit.metadata;
        }

        /// An empty batch of changes.
        pub fn new_batch(self: *const Self) Batch {
            return .{ .gpa = self.gpa };
        }

        /// Prunes operations below `location`, which may not exceed the inactivity floor. The
        /// log prunes whole sections, so the retained start may lie below it. Commits first, so
        /// the floor that justifies the boundary is durable.
        pub fn prune(self: *Self, location: u64) !void {
            if (location > self.inactivity_floor_loc) return error.PruneBeyondMinRequired;
            try self.log.commit();
            if (!try self.log.prune(location)) return;
            const start = self.log.get_bounds().start;
            assert(start <= location);
            self.bitmap.prune_to_bit(start);
        }

        /// Makes every applied operation durable, with no recovery needed on reopen.
        pub fn sync(self: *Self) !void {
            try self.log.sync();
        }

        /// Starts a sync of the applied operations and returns its completion (one reference,
        /// the caller's). Work continues while it is in flight; a dropped (released) one's
        /// failure resurfaces from the next durability or mutating call.
        pub fn start_sync(self: *Self) !runtime.storage.Completion {
            return self.log.start_sync();
        }

        /// Makes every applied operation durable; reopening may replay the log.
        pub fn commit(self: *Self) !void {
            try self.log.commit();
        }

        /// Applies `changeset` (consumed, also on error), walking the floor with
        /// `floor.Proportional`. Call `commit` or `sync` to make it durable.
        pub fn apply_batch(self: *Self, changeset: *Changeset) !void {
            var policy: floor_mod.Proportional = .{};
            return self.apply_batch_with(changeset, &policy);
        }

        /// `apply_batch` walking the floor with `policy`. If the batch leaves the store empty,
        /// the floor moves to its commit.
        pub fn apply_batch_with(self: *Self, changeset: *Changeset, policy: anytype) !void {
            floor_mod.check(@TypeOf(policy.*));
            defer changeset.deinit();
            const gpa = self.gpa;
            const start = self.log.size();
            const old_locs = try self.resolve(changeset.entries);
            defer gpa.free(old_locs);
            var ops: std.ArrayList(Operation) = .empty;
            defer {
                for (ops.items) |*op| op.deinit(gpa);
                ops.deinit(gpa);
            }
            try ops.ensureTotalCapacity(gpa, changeset.entries.len + 1);
            const made_inactive = try self.emit_writes(changeset, old_locs, &ops);
            // The previous commit becomes inactive.
            self.bitmap.set_bit(start - 1, false);
            const limits = policy.limits(made_inactive);
            const tip = start + ops.items.len;
            const floor = self.inactivity_floor_loc;
            var walk = floor_mod.Walk.init(floor, tip, limits.entries, limits.skips);
            try self.walk_floor(&walk, policy, &ops);
            self.inactivity_floor_loc = walk.floor;
            if (self.is_empty()) self.inactivity_floor_loc = start + ops.items.len;
            try self.bitmap.push(gpa, true);
            try ops.append(gpa, .{ .commit = .{
                .metadata = changeset.take_metadata(),
                .floor = self.inactivity_floor_loc,
            } });
            _ = try self.log.append_many(ops.items);
            assert(self.bitmap.len() == self.log.size());
        }

        /// The current location of each entry's key, null if it is not active.
        fn resolve(self: *Self, entries: []const Changeset.Entry) ![]?u64 {
            const old_locs = try self.gpa.alloc(?u64, entries.len);
            errdefer self.gpa.free(old_locs);
            for (entries, old_locs) |*entry, *old| {
                const located = try self.locate(&entry.key);
                old.* = if (located) |l| l.location else null;
                if (located) |l| codec.free(Value, self.gpa, l.value);
            }
            return old_locs;
        }

        /// Appends the changeset's updates and deletes (in key order) to `ops`, applying each to
        /// the snapshot, bitmap, and key count. Returns the number of operations made inactive.
        fn emit_writes(
            self: *Self,
            changeset: *Changeset,
            old_locs: []const ?u64,
            ops: *std.ArrayList(Operation),
        ) !usize {
            const gpa = self.gpa;
            const start = self.log.size();
            var made_inactive: usize = 0;
            for (changeset.entries, old_locs) |*entry, old_loc| {
                const new_loc = start + ops.items.len;
                if (entry.value == null and old_loc == null) continue; // Deletes nothing.
                // The operation owns a copy of the key; the changeset frees its own.
                const op_key = try value_mod.clone(K, gpa, entry.key);
                if (entry.value) |v| {
                    errdefer codec.free(K, gpa, op_key);
                    try self.point_at(&entry.key, old_loc, new_loc);
                    if (old_loc) |old| {
                        self.bitmap.set_bit(old, false);
                        made_inactive += 1;
                    } else {
                        self.active_keys += 1;
                    }
                    try self.bitmap.push(gpa, true);
                    ops.appendAssumeCapacity(.{ .update = .{ .key = op_key, .value = v } });
                    entry.value = null; // Moved into `ops`.
                } else if (old_loc) |old| {
                    self.delete_known_loc(&entry.key, old);
                    self.bitmap.set_bit(old, false);
                    ops.appendAssumeCapacity(.{ .delete = op_key });
                    try self.bitmap.push(gpa, false);
                    made_inactive += 2;
                    self.active_keys -= 1;
                }
            }
            assert(ops.items.len <= changeset.entries.len);
            return made_inactive;
        }

        /// Points `key` at `new_loc`, replacing `old_loc` if the key was active.
        fn point_at(self: *Self, key: *const K, old_loc: ?u64, new_loc: u64) !void {
            const bytes = value_mod.bytes(K, key);
            var cursor = try self.snapshot.get_mut_or_insert(bytes, new_loc) orelse
                return; // A fresh bucket now holds `new_loc`.
            defer cursor.finish();
            // Without a match the search exhausts the bucket, so the insert appends.
            if (cursor.find(old_loc, matches_optional)) return cursor.update(new_loc);
            try cursor.insert(new_loc);
        }

        fn matches_optional(target: ?u64, location: *const u64) bool {
            return target != null and location.* == target.?;
        }

        /// Advances `walk` over the active updates below its end, deciding each with `policy`.
        /// Each decision applies at once to the snapshot, bitmap, and key count, and the update
        /// or delete it writes joins `ops`, which holds the operations from the log's end.
        fn walk_floor(
            self: *Self,
            walk: *floor_mod.Walk,
            policy: anytype,
            ops: *std.ArrayList(Operation),
        ) !void {
            const gpa = self.gpa;
            var candidates: std.ArrayList(u64) = .empty;
            defer candidates.deinit(gpa);
            const bits = &self.bitmap;
            const limit = walk.entries;
            _ = try bitmap_mod.fill_from(gpa, bits, walk.floor, walk.end, limit, &candidates);
            const reachable = walk.reachable(candidates.items);
            try ops.ensureUnusedCapacity(gpa, reachable + 1);
            for (candidates.items[0..reachable]) |location| {
                const reached = walk.reach(location);
                assert(reached); // The candidate is within the walk's reach.
                if (!try self.decide(location, policy, ops)) return;
                walk.decide();
            }
            if (reachable < candidates.items.len) {
                const reached = walk.reach(candidates.items[reachable]);
                assert(!reached); // The first unreachable candidate ends the walk.
            } else if (walk.entries > 0) {
                walk.exhaust();
            }
        }

        /// Decides the active update at `location`; false when the policy stops the walk.
        fn decide(
            self: *Self,
            location: u64,
            policy: anytype,
            ops: *std.ArrayList(Operation),
        ) !bool {
            const gpa = self.gpa;
            const start = self.log.size();
            var op = if (location < start)
                try self.read_op(location)
            else
                try ops.items[@intCast(location - start)].clone(gpa);
            if (op != .update) {
                op.deinit(gpa);
                return error.DataCorrupted; // Active candidates are updates.
            }
            const key = op.update.key;
            const new_loc = start + ops.items.len;
            const entry: floor_mod.Entry(K, Value) = .{
                .location = location,
                .key = &key,
                .value = op.update.value,
            };
            const decision = policy.decide(K, Value, entry);
            if (decision.released) |released| codec.free(Value, gpa, released);
            switch (decision.action) {
                .write => |v| {
                    self.update_known_loc(&key, location, new_loc);
                    try self.bitmap.push(gpa, true);
                    ops.appendAssumeCapacity(.{ .update = .{ .key = key, .value = v } });
                },
                .evict => {
                    self.delete_known_loc(&key, location);
                    self.active_keys -= 1;
                    try self.bitmap.push(gpa, false);
                    ops.appendAssumeCapacity(.{ .delete = key });
                },
                .stop => {
                    codec.free(K, gpa, key); // Not moved into `ops`.
                    return false;
                },
            }
            self.bitmap.set_bit(location, false);
            return true;
        }

        /// Points the known `key` at `new` instead of `old`.
        fn update_known_loc(self: *Self, key: *const K, old: u64, new: u64) void {
            var cursor = self.snapshot.get_mut(value_mod.bytes(K, key)).?; // Known to exist.
            defer cursor.finish();
            const found = cursor.find(old, matches);
            assert(found); // The known key's location is in the snapshot.
            cursor.update(new);
        }

        /// Removes the known `key`'s location `old`.
        fn delete_known_loc(self: *Self, key: *const K, old: u64) void {
            var cursor = self.snapshot.get_mut(value_mod.bytes(K, key)).?; // Known to exist.
            defer cursor.finish();
            const found = cursor.find(old, matches);
            assert(found); // The known key's location is in the snapshot.
            cursor.delete();
        }

        fn matches(target: u64, location: *const u64) bool {
            return location.* == target;
        }
    };
}

/// A mutable batch of writes and deletes (commonware's `Batch`). It owns the values written to
/// it; a later write of a key replaces an earlier one.
fn BatchOf(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;

        gpa: Allocator,
        writes: std.ArrayList(D.Write) = .empty,
        metadata: ?V = null,

        /// Discards the batch and the keys and values it owns.
        pub fn deinit(self: *Self) void {
            for (self.writes.items) |w| free_write(self.gpa, w);
            self.writes.deinit(self.gpa);
            codec.free(?V, self.gpa, self.metadata);
            self.* = undefined;
        }

        /// Records a write (null deletes); the batch copies `key` and owns `value` on success.
        pub fn write(self: *Self, key: K, value: ?V) !void {
            try self.writes.ensureUnusedCapacity(self.gpa, 1);
            const copy = try value_mod.clone(K, self.gpa, key);
            self.writes.appendAssumeCapacity(.{ .key = copy, .value = value });
        }

        /// Sets the metadata of this batch's commit; the batch owns it and frees any before.
        pub fn with_metadata(self: *Self, metadata: ?V) void {
            codec.free(?V, self.gpa, self.metadata);
            self.metadata = metadata;
        }

        /// The value of `key` after the batch: its last write, else `db`'s. The caller owns it.
        pub fn get(self: *const Self, key: *const K, db: *D) !?V {
            var at = self.writes.items.len;
            while (at > 0) {
                at -= 1;
                const w = self.writes.items[at];
                if (!value_mod.eql(K, w.key, key.*)) continue;
                return value_mod.clone(?V, self.gpa, w.value);
            }
            return db.get(key);
        }

        /// The values of `keys` after the batch into `out`. The caller owns them.
        pub fn get_many(self: *const Self, keys: []const K, db: *D, out: []?V) !void {
            assert(keys.len == out.len);
            var filled: usize = 0;
            errdefer for (out[0..filled]) |v| codec.free(?V, self.gpa, v);
            for (keys, out) |*key, *slot| {
                slot.* = try self.get(key, db);
                filled += 1;
            }
        }

        /// The batch's changes, keyed and deduplicated. Consumes the batch, also on error.
        pub fn finalize(self: *Self) !D.Changeset {
            defer self.* = undefined;
            const metadata = self.metadata;
            self.metadata = null;
            var changeset = D.Changeset.from_writes(self.gpa, &self.writes) catch |err| {
                codec.free(?V, self.gpa, metadata);
                return err;
            };
            changeset.metadata = metadata;
            return changeset;
        }
    };
}

/// A finalized batch ready to apply: entries sorted by key without duplicates, and the commit's
/// metadata. It owns their values.
fn ChangesetOf(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;
        pub const Entry = D.Write;

        gpa: Allocator,
        entries: []Entry,
        metadata: ?V = null,

        /// The changes of `writes` (consumed, also on error): the last write of each key wins,
        /// and superseded values are freed.
        pub fn from_writes(gpa: Allocator, writes: *std.ArrayList(D.Write)) !Self {
            const items = writes.items;
            // A stable sort keeps each key's writes in order, so the last is the newest.
            std.mem.sort(D.Write, items, {}, less);
            var count: usize = 0;
            for (items, 0..) |w, i| {
                const last = i + 1 == items.len or !value_mod.eql(K, w.key, items[i + 1].key);
                if (!last) {
                    free_write(gpa, w);
                    continue;
                }
                items[count] = w;
                count += 1;
            }
            assert(count <= items.len);
            writes.shrinkRetainingCapacity(count);
            const entries = writes.toOwnedSlice(gpa) catch |err| {
                for (writes.items) |w| free_write(gpa, w);
                writes.deinit(gpa);
                return err;
            };
            return .{ .gpa = gpa, .entries = entries };
        }

        /// The changes of `writes` (copied; the changeset owns copies of their keys and values).
        pub fn init(gpa: Allocator, writes: []const D.Write) !Self {
            var owned: std.ArrayList(D.Write) = .empty;
            errdefer {
                for (owned.items) |w| free_write(gpa, w);
                owned.deinit(gpa);
            }
            try owned.ensureTotalCapacity(gpa, writes.len);
            for (writes) |w| {
                const key = try value_mod.clone(K, gpa, w.key);
                errdefer codec.free(K, gpa, key);
                const copy = try value_mod.clone(?V, gpa, w.value);
                owned.appendAssumeCapacity(.{ .key = key, .value = copy });
            }
            return from_writes(gpa, &owned);
        }

        pub fn deinit(self: *Self) void {
            for (self.entries) |e| free_write(self.gpa, e);
            self.gpa.free(self.entries);
            codec.free(?V, self.gpa, self.metadata);
            self.* = undefined;
        }

        fn take_metadata(self: *Self) ?V {
            defer self.metadata = null;
            return self.metadata;
        }

        fn less(_: void, a: D.Write, b: D.Write) bool {
            return std.mem.order(u8, value_mod.bytes(K, &a.key), value_mod.bytes(K, &b.key)) == .lt;
        }
    };
}

/// Frees a write's key and value.
fn free_write(gpa: Allocator, write: anytype) void {
    codec.free(@TypeOf(write.key), gpa, write.key);
    codec.free(@TypeOf(write.value), gpa, write.value);
}
