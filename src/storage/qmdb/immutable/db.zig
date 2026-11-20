//! The immutable database and its batches (qmdb/immutable/{db,batch}.rs).
//!
//! `Db(F, K, E, C, H, T)` sets keys of type `K` to values of encoding `E` at most once across
//! its history, in an authenticated log backed by the contiguous journal `C`, with an
//! `index.immutable.Index(T)` from each key to the location of its set. Batches follow
//! commonware's lifecycle: `new_batch` → `set`/`with_metadata`/`with_inactivity_floor` →
//! `merkleize` → `apply_batch`. A merkleized batch is reference counted (`retain`/`release`);
//! it keeps a sorted diff of its sets and its live ancestors' diffs, so reads and applies stay
//! exact after ancestors are released.
//!
//! Values may own memory (variable values such as `[]const u8`): a batch owns what `set` and
//! `with_metadata` give it, a diff owns its entries' values, and every read returns a copy the
//! caller owns. Keys must not own memory. After a storage error only `deinit` may follow.

const std = @import("std");
const assert = std.debug.assert;
const refcount = @import("../../refcount.zig");
const RefCount = refcount.RefCount;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const index = @import("../../index/mod.zig");
const qmdb = @import("../mod.zig");
const sync_target = @import("../sync/target.zig");
const chain = @import("../chain.zig");
const value_mod = @import("../value.zig");
const diff_mod = @import("../any/diff.zig");
const authenticated = @import("../../journal/authenticated.zig");
const metrics_mod = @import("../metrics.zig");
const operation = @import("operation.zig");

const Storage = runtime.storage.Storage;
const Scope = runtime.telemetry.metrics.Scope;

/// Configuration of an immutable database over a journal configured by `JournalConfig`.
pub fn Config(comptime T: type, comptime JournalConfig: type) type {
    return struct {
        /// The Merkle structure backing the authenticated journal.
        merkle: merkle.full.Config,
        /// The operation log.
        log: JournalConfig,
        /// The clock that times calls into the duration metrics; null skips timing.
        io: ?std.Io = null,
        /// The translator of the key index.
        translator: T,
    };
}

/// The sets of one batch, sorted by key, shared by the batch and its descendants.
pub fn Diff(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { key: K, value: V, loc: u64 };

        references: RefCount,
        entries: []const Entry,

        /// Takes ownership of `entries`, which must be sorted by key with no duplicates.
        fn create(gpa: Allocator, entries: []const Entry) !*Self {
            for (entries[0..entries.len -| 1], entries[@min(1, entries.len)..]) |a, b| {
                assert(diff_mod.order(K, &a.key, &b.key) == .lt);
            }
            const self = try gpa.create(Self);
            self.* = .{ .references = .init(), .entries = entries };
            return self;
        }

        fn retain(self: *Self) *Self {
            self.references.retain();
            return self;
        }

        fn release(self: *Self, gpa: Allocator) void {
            if (!self.references.release()) return;
            for (self.entries) |entry| codec.free(V, gpa, entry.value);
            gpa.free(self.entries);
            gpa.destroy(self);
        }

        /// The entry of `key` if this batch set it at or above `floor`.
        pub fn lookup(self: *const Self, key: *const K, floor: u64) ?*const Entry {
            var low: usize = 0;
            var high: usize = self.entries.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                const entry = &self.entries[mid];
                switch (diff_mod.order(K, &entry.key, key)) {
                    .lt => low = mid + 1,
                    .gt => high = mid,
                    .eq => return if (entry.loc >= floor) entry else null,
                }
            }
            assert(low == high);
            return null;
        }
    };
}

/// An authenticated database of keys set once, over family `F`, key `K`, value encoding `E`,
/// backing journal `C`, hash `H`, and index translator `T`.
pub fn Db(F: type, K: type, E: type, C: type, H: type, T: type) type {
    return struct {
        const Self = @This();
        comptime {
            assert(!codec.owns_memory(K));
        }
        pub const Family = F;
        pub const Key = K;
        pub const Value = E.Value;
        pub const Operation = operation.Operation(F, K, E);
        pub const Journal = authenticated.Journal(F, C, H);
        pub const Index = index.immutable.Index(T);
        pub const Digest = H.Digest;
        pub const Commitment = chain.Commitment(F, Digest);
        pub const Bounds = chain.Bounds(F, Digest);
        pub const Proof = Journal.Proof;
        /// A proof and the operations it covers (`deinit` frees both).
        pub const ProofOps = Journal.Proved;
        pub const Cfg = Config(T, C.BackingConfig);
        pub const BatchDiff = Diff(K, Value);
        pub const Set = Operation.Set;

        gpa: Allocator,
        journal: Journal,
        /// The root of the log at its last commit.
        root_digest: Digest,
        /// The location of the set of every key set at or after the floor the index was built
        /// from, excluding pruned locations.
        snapshot: Index,
        inactivity_floor_loc: u64,
        metrics: metrics_mod.Metrics,

        /// Opens the database, creating the initial commit if the log is empty. With
        /// `max_size`, recovery retains at most that many operations (the last commit within).
        pub fn init(
            gpa: Allocator,
            storage: Storage,
            scope: Scope,
            cfg: Cfg,
            max_size: ?u64,
        ) !Self {
            const log_cfg = qmdb.log_with_io(cfg.log, cfg.io);
            var journal = try qmdb.init_journal(Journal, gpa, storage, cfg.merkle, log_cfg, .{
                .max_size = max_size,
                .replay_from_floor = true,
            });
            if (journal.size() == 0) {
                errdefer journal.deinit();
                _ = try journal.append(.{ .commit = .{ .metadata = null, .floor = 0 } });
                try journal.sync();
            }
            var db = try init_from_log(gpa, scope, journal, cfg.translator);
            db.metrics.io = cfg.io;
            return db;
        }

        /// Builds the database over an opened `log` whose last operation is a commit (the
        /// build half of commonware's `from_sync_result`, which state sync uses on the journal
        /// it filled): rebuilds the index from the commit's floor. Takes ownership of `log`,
        /// also on error. An empty log is `HistoricalFloorPruned`. Does not sync.
        pub fn init_from_log(gpa: Allocator, scope: Scope, log: Journal, translator: T) !Self {
            var journal = log;
            errdefer journal.deinit();
            if (journal.size() == 0) return error.HistoricalFloorPruned;
            var reader: LogReader = .{ .journal = &journal };
            // The log ends with a commit, or its data is unexpected.
            const commit_floor = try qmdb.commit_floor_at(gpa, &reader, journal.size());
            const floor = commit_floor orelse return error.UnexpectedData;
            var snapshot = try build_snapshot(gpa, translator, floor, &journal);
            errdefer snapshot.deinit();
            const inactive_peaks = merkle.inactive_peaks(F, journal.size(), floor);
            const root_digest = try journal.root(inactive_peaks);
            var self: Self = .{
                .gpa = gpa,
                .journal = journal,
                .root_digest = root_digest,
                .snapshot = snapshot,
                .inactivity_floor_loc = floor,
                .metrics = try metrics_mod.Metrics.init(scope),
            };
            self.update_metrics();
            assert(self.inactivity_floor_loc < self.journal.size());
            return self;
        }

        /// The index of every set from `floor` (which recovery kept retained) to the end.
        fn build_snapshot(gpa: Allocator, translator: T, floor: u64, journal: *Journal) !Index {
            const end = journal.size();
            assert(journal.get_bounds().start <= floor and floor < end);
            var snapshot = try Index.init(gpa, translator, floor, @intCast(end - floor));
            errdefer snapshot.deinit();
            var loc = floor;
            while (loc < end) : (loc += 1) {
                var op = try journal.read(loc);
                defer op.deinit(gpa);
                switch (op) {
                    .set => |*set| try snapshot.insert(value_mod.bytes(K, &set.key), loc),
                    .commit => {},
                }
            }
            assert(snapshot.len() <= end - floor);
            return snapshot;
        }

        /// Closes the database without syncing.
        pub fn deinit(self: *Self) void {
            self.snapshot.deinit();
            self.journal.deinit();
            self.metrics.deinit();
            self.* = undefined;
        }

        pub fn inactivity_floor(self: *const Self) u64 {
            return self.inactivity_floor_loc;
        }

        /// `[oldest retained location, size)`.
        pub fn bounds(self: *const Self) merkle.Range {
            const span = self.journal.get_bounds();
            return .{ .start = span.start, .end = span.end };
        }

        pub fn update_metrics(self: *Self) void {
            const span = self.journal.get_bounds();
            assert(span.end > 0);
            self.metrics.update(span.end, span.start, self.inactivity_floor_loc, span.end - 1);
        }

        /// The location below which state sync need not fetch operations.
        pub fn sync_boundary(self: *const Self) u64 {
            return self.inactivity_floor_loc;
        }

        /// The value of `key`, or null if no set at or above the inactivity floor holds it. The
        /// caller owns it. Every database at the same commitment answers alike, however far it
        /// has pruned and whether or not it was reopened; null does not mean `key` may be set,
        /// since a key the floor retired was still set once.
        pub fn get(self: *const Self, key: *const K) !?Value {
            self.metrics.get_calls.metric().inc();
            const timing = self.metrics.start("get_duration");
            defer timing.finish();
            self.metrics.lookups_requested.metric().inc();
            return self.get_from(key, self.inactivity_floor_loc);
        }

        /// The value of `key` if a set at or above `floor` holds it.
        pub fn get_from(self: *const Self, key: *const K, floor: u64) !?Value {
            var positions = self.snapshot.get(value_mod.bytes(K, key));
            while (positions.next()) |loc| {
                if (loc < floor) continue;
                if (try self.value_at(key, loc)) |value| return value;
            }
            return null;
        }

        /// The values of `keys` into `out`, each as `get` reads it.
        pub fn get_many(self: *const Self, keys: []const K, out: []?Value) !void {
            return self.get_many_from(keys, self.inactivity_floor_loc, out);
        }

        /// The values of `keys` held by sets at or above `floor` into `out`. The caller owns
        /// them.
        pub fn get_many_from(self: *const Self, keys: []const K, floor: u64, out: []?Value) !void {
            assert(keys.len == out.len);
            if (keys.len == 0) return;
            self.metrics.get_many_calls.metric().inc();
            const timing = self.metrics.start("get_many_duration");
            defer timing.finish();
            self.metrics.lookups_requested.metric().inc_by(keys.len);
            var filled: usize = 0;
            errdefer for (out[0..filled]) |value| codec.free(?Value, self.gpa, value);
            for (keys, out) |*key, *slot| {
                slot.* = try self.get_from(key, floor);
                filled += 1;
            }
        }

        /// The value at `loc` if the set there is of `key`.
        fn value_at(self: *const Self, key: *const K, loc: u64) !?Value {
            if (loc < self.journal.get_bounds().start) return error.OperationPruned;
            var op = try self.journal.read(loc);
            assert(op == .set); // The index holds only the locations of sets.
            if (!value_mod.eql(K, op.set.key, key.*)) {
                op.deinit(self.gpa);
                return null;
            }
            return op.set.value; // The key owns no memory, so the value is all `op` owns.
        }

        /// The metadata of the last commit. The caller owns it.
        pub fn get_metadata(self: *const Self) !?Value {
            const op = try self.journal.read(self.journal.size() - 1);
            assert(op == .commit); // The log always ends with a commit.
            return op.commit.metadata;
        }

        pub fn root(self: *const Self) Digest {
            return self.root_digest;
        }

        /// A proof of up to `max_ops` operations from `start` against the current root.
        pub fn proof(self: *const Self, start: u64, max_ops: u64) !ProofOps {
            return self.historical_proof(self.journal.size(), start, max_ops);
        }

        /// A proof of up to `max_ops` operations from `start` against the root at the commit
        /// ending at `historical_size`.
        pub fn historical_proof(
            self: *const Self,
            historical_size: u64,
            start: u64,
            max_ops: u64,
        ) !ProofOps {
            assert(max_ops > 0);
            if (historical_size > self.journal.size()) return error.RangeOutOfBounds;
            var reader: LogReader = .{ .journal = &self.journal };
            const peaks = try qmdb.inactive_peaks_at(F, self.gpa, &reader, historical_size);
            return self.journal.historical_proof(historical_size, start, max_ops, peaks);
        }

        /// Reads the log for `qmdb.inactive_peaks_at`.
        const LogReader = struct {
            journal: *const Journal,

            pub fn bounds(reader: *const LogReader) merkle.Range {
                const span = reader.journal.get_bounds();
                return .{ .start = span.start, .end = span.end };
            }

            pub fn read(reader: *LogReader, _: Allocator, location: u64) !Operation {
                return reader.journal.read(location);
            }
        };

        /// The pins that authenticate a lower boundary at `location`.
        pub fn pinned_nodes_at(
            self: *const Self,
            location: u64,
            out: *[merkle.max_pinned_nodes]Digest,
        ) ![]Digest {
            return self.journal.merkle.pinned_nodes_at(location, out);
        }

        /// Prunes operations below `location`, which may not exceed the inactivity floor.
        /// Pruning leaves `get` and `get_many` results unchanged; proofs by location still need
        /// their operations and Merkle nodes retained.
        pub fn prune(self: *Self, location: u64) !void {
            self.metrics.prune_calls.metric().inc();
            const timing = self.metrics.start("prune_duration");
            defer timing.finish();
            if (location > self.inactivity_floor_loc) return error.PruneBeyondMinRequired;
            _ = try self.journal.prune(location);
            self.snapshot.prune(self.journal.get_bounds().start);
            self.update_metrics();
        }

        /// Makes every applied operation durable, with no recovery needed on reopen.
        pub fn sync(self: *Self) !void {
            self.metrics.sync_calls.metric().inc();
            const timing = self.metrics.start("sync_duration");
            defer timing.finish();
            try self.journal.sync();
        }

        /// Starts a sync of the applied operations and returns its completion (one reference,
        /// the caller's). Work continues while it is in flight; a dropped (released) one's
        /// failure resurfaces from the next durability or mutating call.
        pub fn start_sync(self: *Self) !runtime.storage.Completion {
            self.metrics.start_sync_calls.metric().inc();
            return self.journal.start_sync();
        }

        /// Makes every applied operation durable; reopening may replay the log.
        pub fn commit(self: *Self) !void {
            self.metrics.commit_calls.metric().inc();
            const timing = self.metrics.start("commit_duration");
            defer timing.finish();
            try self.journal.commit();
        }

        /// Removes the database's storage and frees it, also on error.
        pub fn destroy(self: *Self) !void {
            self.metrics.deinit();
            self.snapshot.deinit();
            defer self.* = undefined;
            try self.journal.destroy();
        }

        pub fn commitment(self: *const Self) Commitment {
            return .{ .size = self.journal.size(), .root = self.root_digest };
        }

        pub fn validate_batch(self: *const Self, batch: *const MerkleizedBatch) !void {
            try batch.bounds.validate_apply_to(self.commitment());
        }

        /// Applies `batch` and its unapplied ancestors; the caller keeps its reference.
        pub fn apply_batch(self: *Self, batch: *const MerkleizedBatch) !void {
            self.metrics.apply_batch_calls.metric().inc();
            const timing = self.metrics.start("apply_batch_duration");
            defer timing.finish();
            try self.validate_batch(batch);
            const db_size = self.journal.size();
            // The snapshot inserts are independent of the journal until publication, so they
            // run first and complete while the append waits on an in-flight sync (commonware
            // joins the two). A failure leaves only `deinit` valid either way.
            try self.index_diff(batch.diff, batch.bounds.tip.size);
            for (batch.ancestor_diffs, batch.bounds.ancestors) |ancestor, state| {
                if (state.size <= db_size) continue; // Already applied.
                try self.index_diff(ancestor, batch.bounds.tip.size);
            }
            try self.journal.apply_batch(batch.journal_batch);
            self.inactivity_floor_loc = batch.bounds.inactivity_floor;
            self.root_digest = batch.root();
            assert(self.journal.size() == batch.bounds.tip.size);
            self.update_metrics();
            self.metrics.operations_applied.metric().inc_by(self.journal.size() - db_size);
        }

        /// Indexes `batch_diff`'s sets, all below `tip`, the size the batch applies to. Each
        /// insert first hints the table slot of the set `prefetch_distance` ahead, so the cache
        /// misses of a batch's random inserts overlap instead of running one at a time.
        fn index_diff(self: *Self, batch_diff: *const BatchDiff, tip: u64) !void {
            assert(tip >= self.journal.size());
            const entries = batch_diff.entries;
            const len_before = self.snapshot.len();
            for (entries[0..@min(prefetch_distance, entries.len)]) |*entry| {
                self.prefetch_slot(&entry.key);
            }
            for (entries, 0..) |*entry, i| {
                assert(entry.loc < tip);
                if (i + prefetch_distance < entries.len) {
                    self.prefetch_slot(&entries[i + prefetch_distance].key);
                }
                try self.snapshot.insert(value_mod.bytes(K, &entry.key), entry.loc);
            }
            assert(self.snapshot.len() == len_before + entries.len);
        }

        /// Sets ahead whose table slot `index_diff` hints: enough to keep several misses in
        /// flight, few enough that the hinted lines are still cached when the insert comes.
        const prefetch_distance = 16;

        /// Hints the CPU to load the table slot `key`'s insert will probe first.
        fn prefetch_slot(self: *const Self, key: *const K) void {
            const translator = self.snapshot.translator;
            const translated = translator.transform(value_mod.bytes(K, key));
            self.snapshot.table.prefetch(translator.hash(translated));
        }

        /// A batch on the database's current state.
        pub fn new_batch(self: *const Self) !UnmerkleizedBatch {
            return .{
                .gpa = self.gpa,
                .journal_batch = try self.journal.new_batch(),
                .parent = null,
                .inactivity_floor = self.inactivity_floor_loc,
                .base = self.commitment(),
            };
        }

        /// A merkleized batch representing the current state.
        pub fn to_batch(self: *const Self) !*MerkleizedBatch {
            const batch = try self.gpa.create(MerkleizedBatch);
            errdefer self.gpa.destroy(batch);
            const empty = try BatchDiff.create(self.gpa, &.{});
            errdefer empty.release(self.gpa);
            const journal_batch = try self.journal.to_merkleized_batch();
            const state = Bounds.from_db(self.commitment(), self.inactivity_floor_loc);
            batch.init(self.gpa, journal_batch, empty, &.{}, null, state);
            return batch;
        }

        pub const UnmerkleizedBatch = Unmerkleized(Self);
        pub const MerkleizedBatch = Merkleized(Self);
    };
}

/// Reads each of `keys` through `reader` (a batch) into `out`, freeing the values read so far
/// on error.
fn get_each(reader: anytype, keys: anytype, db: anytype, out: anytype) !void {
    assert(keys.len == out.len);
    const V = @typeInfo(@TypeOf(out)).pointer.child;
    var filled: usize = 0;
    errdefer for (out[0..filled]) |value| codec.free(V, reader.gpa, value);
    assert(filled == 0);
    for (keys, out) |*key, *slot| {
        slot.* = try reader.get(key, db);
        filled += 1;
    }
    assert(filled == out.len);
}

/// A batch of sets not yet hashed, on the database `D`.
fn Unmerkleized(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;
        const Entry = D.BatchDiff.Entry;

        gpa: Allocator,
        metadata: ?V = null,
        inactivity_floor: u64,
        journal_batch: D.Journal.UnmerkleizedBatch,
        /// Sets in order; a later set of a key replaces an earlier one.
        sets: std.ArrayList(D.Set) = .empty,
        /// A strong reference to the parent, null for a batch on the database.
        parent: ?*D.MerkleizedBatch,
        /// The commitment this batch builds on.
        base: D.Commitment,

        /// Discards the batch and the values it owns.
        pub fn deinit(self: *Self) void {
            self.journal_batch.deinit(self.gpa);
            for (self.sets.items) |pending| codec.free(V, self.gpa, pending.value);
            self.sets.deinit(self.gpa);
            codec.free(?V, self.gpa, self.metadata);
            if (self.parent) |parent| parent.release();
            self.* = undefined;
        }

        /// Sets the metadata of this batch's commit (not inherited by children). The batch owns
        /// `metadata` and frees any it held before.
        pub fn with_metadata(self: *Self, metadata: ?V) void {
            codec.free(?V, self.gpa, self.metadata);
            self.metadata = metadata;
        }

        /// Sets the inactivity floor of this batch's commit (inherited by children).
        pub fn with_inactivity_floor(self: *Self, floor: u64) void {
            self.inactivity_floor = floor;
        }

        /// Sets `key` to `value`, which the batch owns on success. The key must not be set
        /// elsewhere in the database's history.
        pub fn set(self: *Self, key: K, value: V) !void {
            try self.sets.append(self.gpa, .{ .key = key, .value = value });
        }

        fn base_floor(self: *const Self, db: *const D) u64 {
            const parent = self.parent orelse return db.inactivity_floor_loc;
            return parent.bounds.inactivity_floor;
        }

        fn compatible(self: *const Self, db: *const D) !void {
            const parent = self.parent orelse return self.base.compatible(db.commitment());
            return parent.bounds.compatible(db.commitment());
        }

        /// The value of `key` after this batch, its chain, and `db`. The caller owns it.
        pub fn get(self: *const Self, key: *const K, db: *const D) !?V {
            try self.compatible(db);
            var at = self.sets.items.len;
            while (at > 0) {
                at -= 1;
                const pending = self.sets.items[at];
                if (!value_mod.eql(K, pending.key, key.*)) continue;
                return try value_mod.clone(V, self.gpa, pending.value);
            }
            const floor = self.base_floor(db);
            if (self.parent) |parent| {
                if (parent.lookup_chain(key, floor, db.journal.size())) |entry| {
                    return try value_mod.clone(V, self.gpa, entry.value);
                }
            }
            return db.get_from(key, floor);
        }

        /// The values of `keys` into `out`. The caller owns them. A stale batch refuses even
        /// an empty read.
        pub fn get_many(self: *const Self, keys: []const K, db: *const D, out: []?V) !void {
            try self.compatible(db);
            return get_each(self, keys, db, out);
        }

        /// Hashes the batch (its sets in key order, then a commit). Consumes the batch on
        /// success; on error only `deinit` may follow.
        pub fn merkleize(self: *Self, db: *const D) !*D.MerkleizedBatch {
            const gpa = self.gpa;
            var links = try Links.collect(self, db);
            defer links.deinit(gpa);
            try self.keep_last_sets();
            const entries = try self.sorted_entries();
            var entries_owned = true;
            defer if (entries_owned) gpa.free(entries);
            const commit_location = self.base.size + entries.len;
            const floor = self.inactivity_floor;
            try chain.validate_merkleize_floor(self.base_floor(db), floor, commit_location);
            try self.hand_over(entries, floor);
            const merkleized = try gpa.create(D.MerkleizedBatch);
            errdefer gpa.destroy(merkleized);
            const journal_batch = try self.journal_batch.merkleize(gpa, &db.journal);
            errdefer journal_batch.release(gpa);
            const tip_size = commit_location + 1;
            const inactive_peaks = merkle.inactive_peaks(D.Family, tip_size, floor);
            const tip_root = try journal_batch.root(&db.journal.hasher, inactive_peaks);
            links.state.tip = .{ .size = tip_size, .root = tip_root };
            links.state.inactivity_floor = floor;
            const own_diff = try D.BatchDiff.create(gpa, entries);
            entries_owned = false;
            merkleized.init(gpa, journal_batch, own_diff, links.diffs, self.parent, links.state);
            links.moved = true;
            self.sets.deinit(gpa); // The diff owns the values now.
            if (self.parent) |parent| parent.release();
            self.* = undefined;
            return merkleized;
        }

        /// Sorts the sets by key and keeps only each key's last, freeing the values of the
        /// others (reads through the batch see the same values after).
        fn keep_last_sets(self: *Self) !void {
            const sets = self.sets.items;
            // A stable sort keeps each key's sets in order, so the last is the newest.
            std.mem.sort(D.Set, sets, {}, less);
            var kept: usize = 0;
            for (sets, 0..) |pending, at| {
                const last = at + 1 == sets.len or
                    diff_mod.order(K, &pending.key, &sets[at + 1].key) != .eq;
                if (!last) {
                    codec.free(V, self.gpa, pending.value);
                    continue;
                }
                sets[kept] = pending;
                kept += 1;
            }
            self.sets.shrinkRetainingCapacity(kept);
            assert(kept <= sets.len);
        }

        /// The sets (one per key, sorted) at their locations in this batch, borrowing values.
        fn sorted_entries(self: *const Self) ![]Entry {
            const gpa = self.gpa;
            const entries = try gpa.alloc(Entry, self.sets.items.len);
            for (self.sets.items, entries, 0..) |pending, *entry, at| {
                const loc = self.base.size + at;
                entry.* = .{ .key = pending.key, .value = pending.value, .loc = loc };
            }
            assert(entries.len == self.sets.items.len);
            return entries;
        }

        /// Adds the sets (copies of their values) and the commit (which takes the metadata) to
        /// the journal batch, which owns them after.
        fn hand_over(self: *Self, entries: []const Entry, floor: u64) !void {
            const gpa = self.gpa;
            const ops = try gpa.alloc(D.Operation, entries.len + 1);
            defer gpa.free(ops);
            var cloned: usize = 0;
            errdefer for (ops[0..cloned]) |*op| op.deinit(gpa);
            for (entries, ops[0..entries.len]) |entry, *op| {
                const value = try value_mod.clone(V, gpa, entry.value);
                op.* = .{ .set = .{ .key = entry.key, .value = value } };
                cloned += 1;
            }
            ops[entries.len] = .{ .commit = .{ .metadata = self.metadata, .floor = floor } };
            const size_before = self.journal_batch.size();
            try self.journal_batch.add_many(gpa, ops);
            self.metadata = null;
            assert(self.journal_batch.size() == size_before + ops.len);
        }

        fn less(_: void, a: D.Set, b: D.Set) bool {
            return diff_mod.order(K, &a.key, &b.key) == .lt;
        }

        /// The chain state of a new batch: its bounds (`tip` and `inactivity_floor` are filled in
        /// by `merkleize`) and its live ancestors' diffs, retained, parent first.
        const Links = struct {
            state: D.Bounds,
            diffs: []*D.BatchDiff,
            /// Set once the batch owns `state` and `diffs`.
            moved: bool = false,

            fn collect(batch: *const Self, db: *const D) !Links {
                const gpa = batch.gpa;
                var tips: std.ArrayList(D.Commitment) = .empty;
                errdefer tips.deinit(gpa);
                var diffs: std.ArrayList(*D.BatchDiff) = .empty;
                defer diffs.deinit(gpa);
                errdefer for (diffs.items) |d| d.release(gpa);
                var oldest_base: ?D.Commitment = null;
                var walk: refcount.Ancestors(D.MerkleizedBatch) = .from_first(gpa, batch.parent);
                defer walk.deinit();
                while (walk.next()) |ancestor| {
                    try tips.append(gpa, ancestor.bounds.tip);
                    try diffs.ensureUnusedCapacity(gpa, 1);
                    diffs.appendAssumeCapacity(ancestor.diff.retain());
                    oldest_base = ancestor.bounds.base;
                }
                const inherited = if (batch.parent) |p| p.bounds.db else batch.base;
                const F = D.Family;
                const boundary = chain.effective_boundary(F, D.Digest, inherited, oldest_base);
                const now = db.commitment();
                try chain.validate_batch_applicable(F, D.Digest, now, boundary, tips.items);
                const owned_tips = try tips.toOwnedSlice(gpa);
                errdefer gpa.free(owned_tips);
                return .{
                    .state = .{
                        .base = batch.base,
                        .db = boundary,
                        .tip = batch.base,
                        .ancestors = owned_tips,
                        .inactivity_floor = batch.inactivity_floor,
                    },
                    .diffs = try diffs.toOwnedSlice(gpa),
                };
            }

            fn deinit(links: *Links, gpa: Allocator) void {
                if (!links.moved) {
                    for (links.diffs) |d| d.release(gpa);
                    gpa.free(links.diffs);
                    links.state.deinit(gpa);
                }
                links.* = undefined;
            }
        };
    };
}

/// A hashed batch on the database `D`, reference counted: `retain`/`release`.
fn Merkleized(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;

        gpa: Allocator,
        strong: RefCount,
        weak: RefCount,
        parent: ?*Self,
        journal_batch: *D.Journal.MerkleizedBatch,
        /// This batch's sets.
        diff: *D.BatchDiff,
        /// The diffs of the ancestors live at merkleization, parent first, aligned with
        /// `bounds.ancestors`.
        ancestor_diffs: []*D.BatchDiff,
        bounds: D.Bounds,

        /// Takes ownership of `journal_batch`, `diff`, `ancestor_diffs`, and `state`, and a weak
        /// link to `parent`.
        fn init(
            self: *Self,
            gpa: Allocator,
            journal_batch: *D.Journal.MerkleizedBatch,
            diff: *D.BatchDiff,
            ancestor_diffs: []*D.BatchDiff,
            parent: ?*Self,
            state: D.Bounds,
        ) void {
            assert(journal_batch.size() == state.tip.size);
            assert(ancestor_diffs.len == state.ancestors.len);
            self.* = .{
                .gpa = gpa,
                .strong = .init(),
                .weak = .init(),
                .parent = parent,
                .journal_batch = journal_batch,
                .diff = diff,
                .ancestor_diffs = ancestor_diffs,
                .bounds = state,
            };
            if (parent) |link| link.weak.retain();
        }

        pub fn retain(self: *Self) *Self {
            self.strong.retain();
            return self;
        }

        pub fn release(self: *Self) void {
            if (!self.strong.release()) return;
            self.journal_batch.release(self.gpa);
            self.diff.release(self.gpa);
            for (self.ancestor_diffs) |d| d.release(self.gpa);
            self.gpa.free(self.ancestor_diffs);
            self.bounds.deinit(self.gpa);
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

        /// The sync target reached once this batch is applied: its root over
        /// `[inactivity_floor, tip)` (commonware's `MerkleizedBatch::target`).
        pub fn target(self: *const Self) sync_target.Target(D.Family, D.Digest) {
            return .init(self.root(), self.bounds.inactivity_floor, self.bounds.tip.size);
        }

        /// This batch's own operations and the location of the first.
        pub fn operations(self: *const Self) struct { u64, []const D.Operation } {
            return .{ self.bounds.base.size, self.journal_batch.batch_items() };
        }

        /// A proof of this batch's operations against its root. Caller owns it.
        pub fn proof(self: *const Self, db: *const D) !D.Proof {
            try self.bounds.compatible(db.commitment());
            const tip = self.bounds.tip.size;
            const floor = self.bounds.inactivity_floor;
            const inactive_peaks = merkle.inactive_peaks(D.Family, tip, floor);
            return db.journal.speculative_proof(self.journal_batch, inactive_peaks);
        }

        /// The pins of this batch's first operation.
        pub fn pinned_nodes(
            self: *const Self,
            db: *const D,
            out: *[merkle.max_pinned_nodes]D.Digest,
        ) ![]D.Digest {
            try self.bounds.compatible(db.commitment());
            return db.journal.speculative_pinned_nodes(self.journal_batch, out);
        }

        /// The entry of `key` in this batch or the part of its chain the database at
        /// `db_size` has not applied (commonware's `read_diffs`): the ancestors still live,
        /// then any further ones past `db_size`.
        fn lookup_chain(
            self: *const Self,
            key: *const K,
            floor: u64,
            db_size: u64,
        ) ?*const D.BatchDiff.Entry {
            if (self.diff.lookup(key, floor)) |entry| return entry;
            var live: usize = 0;
            var walk: refcount.Ancestors(Self) = .init(self.gpa, self);
            defer walk.deinit();
            while (walk.next()) |_| live += 1;
            for (self.ancestor_diffs, self.bounds.ancestors, 0..) |ancestor, state, at| {
                if (at >= live and state.size <= db_size) break;
                if (ancestor.lookup(key, floor)) |entry| return entry;
            }
            return null;
        }

        /// The value of `key` after this batch's chain and `db`. The caller owns it.
        pub fn get(self: *const Self, key: *const K, db: *const D) !?V {
            try self.bounds.compatible(db.commitment());
            const floor = self.bounds.inactivity_floor;
            if (self.lookup_chain(key, floor, db.journal.size())) |entry| {
                return try value_mod.clone(V, self.gpa, entry.value);
            }
            return db.get_from(key, floor);
        }

        /// The values of `keys` into `out`. The caller owns them. A stale batch refuses even
        /// an empty read.
        pub fn get_many(self: *const Self, keys: []const K, db: *const D, out: []?V) !void {
            try self.bounds.compatible(db.commitment());
            return get_each(self, keys, db, out);
        }

        /// A child batch on top of this one.
        pub fn new_batch(self: *Self) D.UnmerkleizedBatch {
            return .{
                .gpa = self.gpa,
                .journal_batch = self.journal_batch.new_batch(),
                .parent = self.retain(),
                .inactivity_floor = self.bounds.inactivity_floor,
                .base = self.bounds.tip,
            };
        }
    };
}

/// The root of a freshly initialized database (`Commit(None, 0)` alone).
pub fn initial_root(F: type, K: type, E: type, H: type) H.Digest {
    const Op = operation.Operation(F, K, E);
    const op: Op = .{ .commit = .{ .metadata = null, .floor = 0 } };
    var buffer: [1024]u8 = undefined;
    const size = codec.encode_size(Op, op);
    assert(size <= buffer.len); // A metadata-free commit is a tag, padding, and a varint.
    const encoded = codec.encode_to(Op, op, buffer[0..size]);
    return qmdb.single_operation_root(F, H, encoded);
}
