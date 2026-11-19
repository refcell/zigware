//! The `any` database (qmdb/any/{db,mod}.rs): an authenticated key-value store whose log of
//! updates, deletes, and commits is authenticated by a Merkle structure. A snapshot index maps
//! each active key to the location of its latest update, and an activity bitmap marks the
//! locations holding active operations, which the floor walk reads.
//!
//! `Db(F, U, C, I, H)`: family `F`, update type `U` (`any.operation.update.Unordered` or
//! `Ordered` over a value encoding), backing contiguous journal `C`, snapshot index `I` (a
//! `storage.index` index over `u64` locations), and hash `H`. Fields keep commonware's names
//! and are public, so `current` reaches them as commonware's `pub(crate)` allows.
//!
//! Keys and values must be fixed-size (own no memory) for now: batches and diffs hold them by
//! value. Reads return values by copy. Mutators take `*Self`; after a storage error only
//! `deinit` may follow.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const chain = @import("../chain.zig");
const value_mod = @import("../value.zig");
const authenticated = @import("../../journal/authenticated.zig");
const metrics_mod = @import("../metrics.zig");
const snapshot_mod = @import("../snapshot.zig");
const snapshot_parallel = @import("../snapshot_parallel.zig");
const bitmap_mod = @import("../bitmap.zig");
const operation = @import("operation.zig");
const batch_mod = @import("batch.zig");
const diff_mod = @import("diff.zig");
const ordered_mod = @import("ordered.zig");
const range_mod = @import("range.zig");

const Storage = runtime.storage.Storage;
const Scope = runtime.telemetry.metrics.Scope;

/// Configuration of an `any` database.
pub fn Config(comptime T: type, comptime JournalConfig: type) type {
    return struct {
        /// The Merkle structure backing the authenticated journal.
        merkle: merkle.full.Config,
        /// The operation log.
        log: JournalConfig,
        /// The clock that times calls into the duration metrics; null skips timing.
        io: ?std.Io = null,
        /// The translator of the snapshot index.
        translator: T,
        /// Entries in the `location -> key` cache that resolves snapshot collisions during
        /// init; null disables it.
        init_cache: ?usize = null,
        /// Tasks the init snapshot build may use (commonware's `init_concurrency`). Above 1, a
        /// partitioned index builds in parallel on threads started through `io` (also its
        /// allocator must be thread-safe); other indexes, or a null `io`, build serially. The
        /// built state is the same for every value.
        init_concurrency: usize = 1,
    };
}

/// An authenticated database of keys over family `F`, update `U`, backing journal `C`, index
/// `I`, and hash `H`, with an activity bitmap of `N`-byte chunks (commonware's `const N`).
pub fn Db(F: type, U: type, C: type, I: type, H: type, comptime N: usize) type {
    return struct {
        const Self = @This();
        comptime {
            assert(N > 0);
            assert(!codec.owns_memory(U.Key)); // Values may own memory; keys may not.
        }
        pub const Family = F;
        pub const Update = U;
        pub const Key = U.Key;
        pub const Value = U.Value;
        pub const Operation = operation.Operation(F, U);
        pub const Log = authenticated.Journal(F, C, H);
        pub const Digest = H.Digest;
        pub const Commitment = chain.Commitment(F, Digest);
        pub const Bounds = chain.Bounds(F, Digest);
        /// Bytes per activity bitmap chunk.
        pub const chunk_bytes = N;
        pub const Bitmap = bitmap_mod.Shared(N);
        pub const Proof = Log.Proof;
        /// A proof and the operations it covers (`deinit` frees both).
        pub const ProofOps = Log.Proved;
        pub const Cfg = Config(I.Translator, C.BackingConfig);
        pub const UnmerkleizedBatch = batch_mod.Unmerkleized(Self);
        pub const MerkleizedBatch = batch_mod.Merkleized(Self);
        pub const StagedBatch = batch_mod.Staged(Self);
        pub const Slot = batch_mod.Slot(Value);
        pub const StagedLoc = batch_mod.StagedLoc;

        gpa: Allocator,
        log: Log,
        /// The root at the last commit.
        root_digest: Digest,
        inactivity_floor_loc: u64,
        snapshot: I,
        active_keys: usize,
        bitmap: Bitmap,
        metrics: metrics_mod.Metrics,

        /// Opens the database: selects the last commit (within `max_size` operations), creates
        /// the initial commit if the log is empty, and rebuilds the snapshot and bitmap from
        /// the commit's floor.
        pub fn init(
            gpa: Allocator,
            storage: Storage,
            scope: Scope,
            cfg: Cfg,
            max_size: ?u64,
        ) !Self {
            const options: qmdb.InitOptions = .{ .max_size = max_size, .replay_from_floor = true };
            return init_with(gpa, storage, scope, cfg, options);
        }

        /// `init` with the journal selection constraints `options` (commonware's
        /// `init_with_bitmap`), checked before any history is discarded.
        pub fn init_with(
            gpa: Allocator,
            storage: Storage,
            scope: Scope,
            cfg: Cfg,
            options: qmdb.InitOptions,
        ) !Self {
            assert(options.replay_from_floor);
            const log_cfg = qmdb.log_with_io(cfg.log, cfg.io);
            var log = try qmdb.init_journal(Log, gpa, storage, cfg.merkle, log_cfg, options);
            if (log.size() == 0) {
                errdefer log.deinit();
                _ = try log.append(.{ .commit = .{ .metadata = null, .floor = 0 } });
                try log.sync();
            }
            const build: InitBuild = .{
                .cache = cfg.init_cache,
                .concurrency = cfg.init_concurrency,
                .io = cfg.io,
            };
            var db = try init_from_log_with(gpa, scope, log, cfg.translator, build);
            db.metrics.io = cfg.io;
            return db;
        }

        /// Builds the database over an opened `log` whose last operation is a commit
        /// (commonware's `init_from_log`, which state sync uses on the journal it filled):
        /// rebuilds the snapshot and bitmap from the commit's floor. Takes ownership of `log`,
        /// also on error. An empty log is `HistoricalFloorPruned`. Does not sync.
        pub fn init_from_log(
            gpa: Allocator,
            scope: Scope,
            log_owned: Log,
            translator: I.Translator,
            init_cache: ?usize,
        ) !Self {
            const build: InitBuild = .{ .cache = init_cache, .concurrency = 1, .io = null };
            return init_from_log_with(gpa, scope, log_owned, translator, build);
        }

        /// How init builds the snapshot (see `Config.init_concurrency`).
        const InitBuild = struct { cache: ?usize, concurrency: usize, io: ?std.Io };

        fn build_snapshot(
            gpa: Allocator,
            floor: u64,
            log: *Log,
            snapshot: *I,
            build: InitBuild,
        ) !snapshot_mod.Build {
            assert(build.concurrency >= 1);
            if (comptime snapshot_parallel.is_partitioned(I)) {
                if (build.io) |io| if (build.concurrency > 1) {
                    const concurrency = build.concurrency;
                    const run = snapshot_parallel.build_on_io;
                    return run(Operation, gpa, io, floor, log, snapshot, build.cache, concurrency);
                };
            }
            return snapshot_mod.build(Operation, gpa, floor, log, snapshot, build.cache);
        }

        fn init_from_log_with(
            gpa: Allocator,
            scope: Scope,
            log_owned: Log,
            translator: I.Translator,
            build: InitBuild,
        ) !Self {
            var log = log_owned;
            errdefer log.deinit();
            if (log.size() == 0) return error.HistoricalFloorPruned;
            var snapshot = I.init(gpa, translator);
            errdefer snapshot.deinit();
            var reader: LogReader = .{ .log = &log };
            const floor = try qmdb.find_inactivity_floor_at(gpa, &reader, log.size());
            var built = try build_snapshot(gpa, floor, &log, &snapshot, build);
            defer built.deinit(gpa);
            var bitmap = try init_bitmap(gpa, log.get_bounds().start, floor, &built.activity);
            errdefer bitmap.deinit(gpa);
            if (bitmap.len() != log.size()) return error.DataCorrupted;
            const root_digest = try log.root(merkle.inactive_peaks(F, log.size(), floor));
            var self: Self = .{
                .gpa = gpa,
                .log = log,
                .root_digest = root_digest,
                .inactivity_floor_loc = floor,
                .snapshot = snapshot,
                .active_keys = built.active_keys,
                .bitmap = bitmap,
                .metrics = try metrics_mod.Metrics.init(scope),
            };
            self.update_metrics();
            assert(self.inactivity_floor_loc < self.log.size());
            return self;
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
            const M = utils.bitmap.DEFAULT_CHUNK_SIZE;
            try bitmap.extend_from_bitmap(gpa, M, activity);
            assert(bitmap.len() >= floor);
            return bitmap;
        }

        /// Closes the database without syncing.
        pub fn deinit(self: *Self) void {
            self.log.deinit();
            self.snapshot.deinit();
            self.bitmap.deinit(self.gpa);
            self.metrics.deinit();
            self.* = undefined;
        }

        /// Reads the log for `qmdb.find_inactivity_floor_at`.
        pub const LogReader = struct {
            log: *const Log,

            pub fn bounds(reader: *const LogReader) merkle.Range {
                const span = reader.log.get_bounds();
                return .{ .start = span.start, .end = span.end };
            }

            pub fn read(reader: *LogReader, _: Allocator, location: u64) !Operation {
                return reader.log.read(location);
            }
        };

        pub fn inactivity_floor(self: *const Self) u64 {
            return self.inactivity_floor_loc;
        }

        /// The location below which state sync need not fetch operations.
        pub fn sync_boundary(self: *const Self) u64 {
            return self.inactivity_floor_loc;
        }

        /// Whether no key is active.
        pub fn is_empty(self: *const Self) bool {
            return self.active_keys == 0;
        }

        pub fn root(self: *const Self) Digest {
            return self.root_digest;
        }

        pub fn commitment(self: *const Self) Commitment {
            return .{ .size = self.log.size(), .root = self.root_digest };
        }

        /// `[oldest retained location, size)`.
        pub fn bounds(self: *const Self) merkle.Range {
            const span = self.log.get_bounds();
            return .{ .start = span.start, .end = span.end };
        }

        /// The metadata of the last commit. The caller owns it.
        pub fn get_metadata(self: *const Self) !?Value {
            var op = try self.log.read(self.log.size() - 1);
            if (op != .commit) {
                op.deinit(self.gpa);
                return error.DataCorrupted; // The log always ends with a commit.
            }
            return op.commit.metadata;
        }

        /// The update at `location`, which must hold one. The caller owns it (`deinit`).
        pub fn read_update(self: *const Self, location: u64) !U {
            var op = try self.log.read(location);
            if (op != .update) {
                op.deinit(self.gpa);
                return error.DataCorrupted; // Snapshots point at updates.
            }
            return op.update;
        }

        /// An update (owned by the holder) and its location.
        pub const Located = struct { update: U, location: u64 };

        /// The key's latest update and its location, if the key is active. The caller owns
        /// the update.
        pub fn get_with_loc(self: *const Self, key: *const Key) !?Located {
            var values = self.snapshot.get(value_mod.bytes(Key, key));
            while (values.next()) |location| {
                var update = try self.read_update(location.*);
                if (value_mod.eql(Key, update.key, key.*)) {
                    return .{ .update = update, .location = location.* };
                }
                update.deinit(self.gpa);
            }
            return null;
        }

        /// The update whose span `[key, next_key)` (cyclic) holds `key`, and its location; null
        /// when the database is empty. Ordered databases only. The caller owns the update.
        pub fn get_span(self: *const Self, key: *const Key) !?Located {
            comptime assert(U.siblings);
            if (self.is_empty()) return null;
            var values = self.snapshot.get(value_mod.bytes(Key, key));
            if (try self.find_span(&values, key)) |span| return span;
            const neighbor = self.snapshot.prev_translated_key(value_mod.bytes(Key, key)) orelse
                return error.DataCorrupted; // A non-empty database indexes some key.
            var before = neighbor.values;
            return try self.find_span(&before, key) orelse error.DataCorrupted;
        }

        fn find_span(self: *const Self, values: anytype, key: *const Key) !?Located {
            while (values.next()) |location| {
                var update = try self.read_update(location.*);
                if (ordered_mod.in_span(Key, &update.key, &update.next_key, key)) {
                    return .{ .update = update, .location = location.* };
                }
                update.deinit(self.gpa);
            }
            return null;
        }

        /// The smallest active key above `key` (not wrapping), which need not be active.
        pub fn get_next_key(self: *const Self, key: *const Key) !?Key {
            var span = try self.get_span(key) orelse return null;
            defer span.update.deinit(self.gpa);
            const next = span.update.next_key;
            return if (diff_mod.order(Key, &next, key) == .gt) next else null;
        }

        /// The largest active key below `key` (not wrapping), which need not be active.
        pub fn get_prev_key(self: *const Self, key: *const Key) !?Key {
            comptime assert(U.siblings);
            var values = self.snapshot.get(value_mod.bytes(Key, key));
            if (try self.find_strict_prev(&values, key)) |prev| return prev;
            const neighbor = self.snapshot.prev_translated_key(value_mod.bytes(Key, key)) orelse
                return null;
            if (neighbor.cycled) return null;
            var before = neighbor.values;
            return self.find_strict_prev(&before, key);
        }

        /// The active key below `key` whose link passes `key`: `key` in `(k, next_key]`.
        fn find_strict_prev(self: *const Self, values: anytype, key: *const Key) !?Key {
            while (values.next()) |location| {
                var update = try self.read_update(location.*);
                defer update.deinit(self.gpa);
                if (diff_mod.order(Key, &update.key, key) != .lt) continue;
                const next = &update.next_key;
                const at_next = diff_mod.order(Key, key, next) == .eq;
                if (at_next or ordered_mod.in_span(Key, &update.key, next, key)) return update.key;
            }
            return null;
        }

        pub const Range = range_mod.Range(Self);
        pub const Bound = range_mod.Bound(Key);

        /// The active pairs in `[start, end]` (per the bounds) in ascending key order, as a pull
        /// iterator (commonware's `stream_range`; `Range.next_key` is its `keys`). Ordered
        /// databases only; the iterator must not outlive a mutation of the database.
        pub fn range(self: *Self, start: Bound, end: Bound) Range {
            return Range.init(self, start, end);
        }

        pub const ValueAndNext = struct { value: Value, next_key: Key };

        /// The key's value (owned by the caller) and the next active key (wrapping), if the key
        /// is active.
        pub fn get_with_next_key(self: *const Self, key: *const Key) !?ValueAndNext {
            comptime assert(U.siblings);
            const found = try self.get_with_loc(key) orelse return null;
            return .{ .value = found.update.value, .next_key = found.update.next_key };
        }

        /// The key's value, if it is active. The caller owns it.
        pub fn get(self: *const Self, key: *const Key) !?Value {
            self.metrics.get_calls.metric().inc();
            const timing = self.metrics.start("get_duration");
            defer timing.finish();
            self.metrics.lookups_requested.metric().inc();
            const found = try self.get_with_loc(key) orelse return null;
            return found.update.value;
        }

        /// The values of `keys` into `out`. The caller owns them.
        pub fn get_many(self: *const Self, keys: []const Key, out: []?Value) !void {
            assert(keys.len == out.len);
            if (keys.len == 0) return;
            self.metrics.get_many_calls.metric().inc();
            const timing = self.metrics.start("get_many_duration");
            defer timing.finish();
            self.metrics.lookups_requested.metric().inc_by(keys.len);
            var filled: usize = 0;
            errdefer for (out[0..filled]) |value| codec.free(?Value, self.gpa, value);
            for (keys, out) |*key, *slot| {
                const found = try self.get_with_loc(key);
                slot.* = if (found) |f| f.update.value else null;
                filled += 1;
            }
        }

        pub fn update_metrics(self: *Self) void {
            const span = self.log.get_bounds();
            assert(span.end > 0);
            self.metrics.update(span.end, span.start, self.inactivity_floor_loc, span.end - 1);
        }

        /// The pins that authenticate a lower boundary at `location`.
        pub fn pinned_nodes_at(
            self: *const Self,
            location: u64,
            out: *[merkle.max_pinned_nodes]Digest,
        ) ![]Digest {
            return self.log.merkle.pinned_nodes_at(location, out);
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
            if (historical_size > self.log.size()) return error.RangeOutOfBounds;
            var reader: LogReader = .{ .log = &self.log };
            const floor = try qmdb.find_inactivity_floor_at(self.gpa, &reader, historical_size);
            const peaks = merkle.inactive_peaks(F, historical_size, floor);
            return self.log.historical_proof(historical_size, start, max_ops, peaks);
        }

        /// A proof of up to `max_ops` operations from `start` against the current root.
        pub fn proof(self: *const Self, start: u64, max_ops: u64) !ProofOps {
            return self.historical_proof(self.log.size(), start, max_ops);
        }

        /// Prunes the log below `location` (at most the inactivity floor). For `current`.
        pub fn prune_log(self: *Self, location: u64) !void {
            if (location > self.inactivity_floor_loc) return error.PruneBeyondMinRequired;
            _ = try self.log.prune(location);
        }

        /// Prunes the activity bitmap below `location`'s chunk. For `current`.
        pub fn prune_bitmap(self: *Self, location: u64) void {
            assert(location <= self.bitmap.len());
            self.bitmap.prune_to_bit(location);
        }

        /// Prunes operations below `location`, which may not exceed the inactivity floor.
        pub fn prune(self: *Self, location: u64) !void {
            self.metrics.prune_calls.metric().inc();
            const timing = self.metrics.start("prune_duration");
            defer timing.finish();
            try self.prune_log(location);
            self.prune_bitmap(location);
            self.update_metrics();
        }

        /// Makes every applied operation durable, with no recovery needed on reopen.
        pub fn sync(self: *Self) !void {
            self.metrics.sync_calls.metric().inc();
            const timing = self.metrics.start("sync_duration");
            defer timing.finish();
            try self.log.sync();
        }

        /// Starts a sync of the applied operations and returns its completion (one reference,
        /// the caller's). Work continues while it is in flight; a dropped (released) one's
        /// failure resurfaces from the next durability or mutating call.
        pub fn start_sync(self: *Self) !runtime.storage.Completion {
            self.metrics.start_sync_calls.metric().inc();
            return self.log.start_sync();
        }

        /// Makes every applied operation durable; reopening may replay the log.
        pub fn commit(self: *Self) !void {
            self.metrics.commit_calls.metric().inc();
            const timing = self.metrics.start("commit_duration");
            defer timing.finish();
            try self.log.commit();
        }

        /// Removes the database's storage and frees it, also on error.
        pub fn destroy(self: *Self) !void {
            self.snapshot.deinit();
            self.bitmap.deinit(self.gpa);
            self.metrics.deinit();
            defer self.* = undefined;
            try self.log.destroy();
        }

        pub fn validate_batch(self: *const Self, batch: *const MerkleizedBatch) !void {
            try batch.bounds.validate_apply_to(self.commitment());
        }

        /// Applies `batch` and its unapplied ancestors; the caller keeps its reference. A
        /// storage or allocation failure leaves only `deinit` valid.
        pub fn apply_batch(self: *Self, batch: *const MerkleizedBatch) !void {
            self.metrics.apply_batch_calls.metric().inc();
            const timing = self.metrics.start("apply_batch_duration");
            defer timing.finish();
            try self.validate_batch(batch);
            const db_size = self.log.size();
            try self.log.apply_batch(batch.journal_batch);
            try batch.apply_to_index(self, db_size);
            self.active_keys = batch.total_active_keys;
            self.inactivity_floor_loc = batch.bounds.inactivity_floor;
            self.root_digest = batch.root();
            assert(self.log.size() == batch.bounds.tip.size);
            assert(self.bitmap.len() == self.log.size());
            self.update_metrics();
            self.metrics.operations_applied.metric().inc_by(self.log.size() - db_size);
        }

        /// A batch on the database's current state.
        pub fn new_batch(self: *const Self) !UnmerkleizedBatch {
            return .{
                .gpa = self.gpa,
                .journal_batch = try self.log.new_batch(),
                .parent = null,
                .base = self.commitment(),
                .base_floor = self.inactivity_floor_loc,
                .base_active_keys = self.active_keys,
            };
        }

        /// A merkleized batch representing the current state.
        pub fn to_batch(self: *const Self) !*MerkleizedBatch {
            return MerkleizedBatch.from_db(self);
        }

        /// Points the known `key` at `new` instead of `old`.
        pub fn update_known_loc(self: *Self, key: *const Key, old: u64, new: u64) void {
            var cursor = self.snapshot.get_mut(value_mod.bytes(Key, key)).?; // Known to exist.
            defer cursor.finish();
            const found = cursor.find(old, matches);
            assert(found); // The known key's location is in the snapshot.
            cursor.update(new);
        }

        /// Removes the known `key`'s location `old`.
        pub fn delete_known_loc(self: *Self, key: *const Key, old: u64) void {
            var cursor = self.snapshot.get_mut(value_mod.bytes(Key, key)).?; // Known to exist.
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

/// The root of a freshly initialized database (`Commit(None, 0)` alone).
pub fn initial_root(comptime F: type, comptime U: type, comptime H: type) H.Digest {
    const Op = operation.Operation(F, U);
    const op: Op = .{ .commit = .{ .metadata = null, .floor = 0 } };
    var buffer: [1024]u8 = undefined;
    const size = codec.encode_size(Op, op);
    assert(size <= buffer.len); // A metadata-free commit is a tag, padding, and a varint.
    const encoded = codec.encode_to(Op, op, buffer[0..size]);
    return qmdb.single_operation_root(F, H, encoded);
}
