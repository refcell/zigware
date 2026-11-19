//! The keyless database and its batches (qmdb/keyless/{db,batch}.rs).
//!
//! `Db(F, E, C, H)` appends values of encoding `E` to an authenticated log backed by the
//! contiguous journal `C` and reads them back by location. Batches follow commonware's
//! lifecycle: `new_batch` → `append`/`with_metadata`/`with_inactivity_floor` → `merkleize` →
//! `apply_batch`. A merkleized batch is reference counted (`retain`/`release`); a child holds a
//! weak link to its parent, and the journal batch keeps every live ancestor's operations so
//! reads stay exact after ancestors are released.
//!
//! Values may own memory (variable values such as `[]const u8`): a batch owns what it is
//! given through `append` and `with_metadata`, and every read returns a copy the caller owns.
//! After a storage error only `deinit` may follow.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const chain = @import("../chain.zig");
const value_mod = @import("../value.zig");
const authenticated = @import("../../journal/authenticated.zig");
const metrics_mod = @import("../metrics.zig");
const operation = @import("operation.zig");

const Storage = runtime.storage.Storage;
const Scope = runtime.telemetry.metrics.Scope;

/// Configuration of a keyless database over a journal configured by `JournalConfig`.
pub fn Config(comptime JournalConfig: type) type {
    return struct {
        /// The Merkle structure backing the authenticated journal.
        merkle: merkle.full.Config,
        /// The operation log.
        log: JournalConfig,
        /// The clock that times calls into the duration metrics; null skips timing.
        io: ?std.Io = null,
    };
}

/// Checks that `locations` strictly increase and lie below `end`.
pub fn check_locations(locations: []const u64, end: u64) qmdb.Error!void {
    if (locations.len == 0) return;
    for (locations[1..], locations[0 .. locations.len - 1]) |location, previous| {
        if (previous >= location) return error.LocationOutOfOrder;
    }
    if (locations[locations.len - 1] >= end) return error.LocationOutOfBounds;
}

fn check_floor(location: u64, floor: u64) qmdb.Error!void {
    if (location < floor) return error.BelowInactivityFloor;
}

pub fn Db(comptime F: type, comptime E: type, comptime C: type, comptime H: type) type {
    return struct {
        const Self = @This();
        pub const Operation = operation.Operation(F, E);
        pub const Value = E.Value;
        pub const Journal = authenticated.Journal(F, C, H);
        pub const Digest = H.Digest;
        pub const Commitment = chain.Commitment(F, Digest);
        pub const Bounds = chain.Bounds(F, Digest);
        pub const Proof = Journal.Proof;
        /// A proof and the operations it covers (`deinit` frees both).
        pub const ProofOps = Journal.Proved;
        pub const Cfg = Config(C.BackingConfig);

        gpa: Allocator,
        journal: Journal,
        /// The root of the log at its last commit.
        root_digest: Digest,
        inactivity_floor_loc: u64,
        metrics: metrics_mod.Metrics,

        fn has_floor(op: Operation) bool {
            return op.inactivity_floor() != null;
        }

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
                .replay_from_floor = false,
            });
            if (journal.size() == 0) {
                errdefer journal.deinit();
                _ = try journal.append(.{ .commit = .{ .metadata = null, .floor = 0 } });
                try journal.sync();
            }
            var db = try init_from_log(gpa, scope, journal);
            db.metrics.io = cfg.io;
            return db;
        }

        /// Builds the database over an opened `log` whose last operation is a commit (the
        /// build half of commonware's `from_sync_result`, which state sync uses on the journal
        /// it filled). Takes ownership of `log`, also on error. An empty log is
        /// `HistoricalFloorPruned`. Does not sync.
        pub fn init_from_log(gpa: Allocator, scope: Scope, log: Journal) !Self {
            var journal = log;
            errdefer journal.deinit();
            if (journal.size() == 0) return error.HistoricalFloorPruned;
            var reader: LogReader = .{ .journal = &journal };
            const floor = try qmdb.find_inactivity_floor_at(gpa, &reader, journal.size());
            const inactive_peaks = merkle.inactive_peaks(F, journal.size(), floor);
            const root_digest = try journal.root(inactive_peaks);
            var self: Self = .{
                .gpa = gpa,
                .journal = journal,
                .root_digest = root_digest,
                .inactivity_floor_loc = floor,
                .metrics = try metrics_mod.Metrics.init(scope),
            };
            self.update_metrics();
            assert(self.inactivity_floor_loc < self.journal.size());
            return self;
        }

        /// Closes the database without syncing.
        pub fn deinit(self: *Self) void {
            self.journal.deinit();
            self.metrics.deinit();
            self.* = undefined;
        }

        /// The value at `location` (the metadata, for a commit). The caller owns it.
        pub fn get(self: *const Self, location: u64) !?Value {
            self.metrics.get_calls.metric().inc();
            const timing = self.metrics.start("get_duration");
            defer timing.finish();
            self.metrics.lookups_requested.metric().inc();
            if (location >= self.journal.size()) return error.LocationOutOfBounds;
            const op = try self.journal.read(location);
            return op.into_value();
        }

        /// The values at strictly increasing `locations` into `out`. The caller owns them.
        pub fn get_many(self: *const Self, locations: []const u64, out: []?Value) !void {
            assert(locations.len == out.len);
            if (locations.len == 0) return;
            self.metrics.get_many_calls.metric().inc();
            const timing = self.metrics.start("get_many_duration");
            defer timing.finish();
            self.metrics.lookups_requested.metric().inc_by(locations.len);
            try check_locations(locations, self.journal.size());
            const ops = try self.gpa.alloc(Operation, locations.len);
            defer self.gpa.free(ops);
            try self.journal.read_many(locations, ops);
            for (ops, out) |op, *slot| slot.* = op.into_value();
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
        pub fn prune(self: *Self, location: u64) !void {
            self.metrics.prune_calls.metric().inc();
            const timing = self.metrics.start("prune_duration");
            defer timing.finish();
            if (location > self.inactivity_floor_loc) return error.PruneBeyondMinRequired;
            _ = try self.journal.prune(location);
            self.update_metrics();
        }

        /// Makes every applied operation durable, with no recovery needed on reopen.
        pub fn sync(self: *Self) !void {
            self.metrics.sync_calls.metric().inc();
            const timing = self.metrics.start("sync_duration");
            defer timing.finish();
            try self.journal.sync();
        }

        /// Starts a sync (it completes at once here).
        pub fn start_sync(self: *Self) !void {
            self.metrics.start_sync_calls.metric().inc();
            try self.journal.start_sync();
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
            const start = self.journal.size();
            try self.journal.apply_batch(batch.journal_batch);
            self.inactivity_floor_loc = batch.bounds.inactivity_floor;
            self.root_digest = batch.root();
            assert(self.journal.size() == batch.bounds.tip.size);
            self.update_metrics();
            self.metrics.operations_applied.metric().inc_by(self.journal.size() - start);
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
            const journal_batch = try self.journal.to_merkleized_batch();
            const state = Bounds.from_db(self.commitment(), self.inactivity_floor_loc);
            batch.init(self.gpa, journal_batch, null, state);
            return batch;
        }

        /// The operation at `location` if a batch in `batch`'s chain holds it: its own items,
        /// then its live ancestors' (contiguous below it, nearest last).
        fn read_chain_op(batch: *const MerkleizedBatch, location: u64) ?Operation {
            const journal_batch = batch.journal_batch;
            const chunks = journal_batch.ancestor_items;
            var items = journal_batch.batch_items();
            var end = journal_batch.size();
            var index = chunks.len;
            while (true) {
                assert(items.len <= end);
                const start = end - items.len;
                if (location >= start and location < end) return items[@intCast(location - start)];
                if (location >= end or index == 0) return null;
                index -= 1;
                items = chunks[index].items;
                end = start;
            }
        }

        /// A clone of the value of `op`, owned by the caller.
        fn owned_value(gpa: Allocator, op: Operation) !?Value {
            return value_mod.clone(?Value, gpa, op.into_value());
        }

        /// Reads `locations` (strictly increasing, already bounds-checked) through a batch
        /// chain: `local` answers the locations a batch holds, the database the rest.
        fn get_many_layered(
            self: *const Self,
            locations: []const u64,
            out: []?Value,
            local: anytype,
        ) !void {
            assert(locations.len == out.len);
            var db_locations: std.ArrayList(u64) = .empty;
            defer db_locations.deinit(self.gpa);
            var db_slots: std.ArrayList(usize) = .empty;
            defer db_slots.deinit(self.gpa);
            var filled: usize = 0;
            errdefer for (out[0..filled]) |value| codec.free(?Value, self.gpa, value);
            for (locations, out, 0..) |location, *slot, index| {
                if (try local.read(self.gpa, location)) |value| {
                    slot.* = value;
                } else {
                    slot.* = null;
                    try db_locations.append(self.gpa, location);
                    try db_slots.append(self.gpa, index);
                }
                filled += 1;
            }
            if (db_locations.items.len == 0) return;
            const values = try self.gpa.alloc(?Value, db_locations.items.len);
            defer self.gpa.free(values);
            try self.get_many(db_locations.items, values);
            for (db_slots.items, values) |slot, value| out[slot] = value;
        }

        /// A batch of appends not yet hashed.
        pub const UnmerkleizedBatch = struct {
            gpa: Allocator,
            metadata: ?Value = null,
            inactivity_floor: u64,
            journal_batch: Journal.UnmerkleizedBatch,
            appends: std.ArrayList(Value) = .empty,
            /// A strong reference to the parent, null for a batch on the database.
            parent: ?*MerkleizedBatch,
            /// The commitment this batch builds on.
            base: Commitment,

            /// Discards the batch and the values it owns.
            pub fn deinit(self: *UnmerkleizedBatch) void {
                self.journal_batch.deinit(self.gpa);
                codec.free_items(Value, self.gpa, self.appends.items);
                self.appends.deinit(self.gpa);
                codec.free(?Value, self.gpa, self.metadata);
                if (self.parent) |parent| parent.release();
                self.* = undefined;
            }

            /// The operation count after the appends (before the commit).
            pub fn size(self: *const UnmerkleizedBatch) u64 {
                return self.base.size + self.appends.items.len;
            }

            /// Sets the metadata of this batch's commit (not inherited by children). The batch
            /// owns `metadata` and frees any it held before.
            pub fn with_metadata(self: *UnmerkleizedBatch, metadata: ?Value) void {
                codec.free(?Value, self.gpa, self.metadata);
                self.metadata = metadata;
            }

            /// Sets the inactivity floor of this batch's commit (inherited by children).
            pub fn with_inactivity_floor(self: *UnmerkleizedBatch, floor: u64) void {
                self.inactivity_floor = floor;
            }

            /// Appends `value`, which the batch owns on success (the caller keeps it on error).
            pub fn append(self: *UnmerkleizedBatch, value: Value) !void {
                try self.appends.append(self.gpa, value);
            }

            /// The recorded database boundary of this batch's chain.
            fn db_state(self: *const UnmerkleizedBatch) Commitment {
                const parent = self.parent orelse return self.base;
                return parent.bounds.db;
            }

            fn base_floor(self: *const UnmerkleizedBatch, db: *const Self) u64 {
                const parent = self.parent orelse return db.inactivity_floor_loc;
                return parent.bounds.inactivity_floor;
            }

            fn compatible(self: *const UnmerkleizedBatch, db: *const Self) !void {
                const parent = self.parent orelse return self.base.compatible(db.commitment());
                return parent.bounds.compatible(db.commitment());
            }

            /// The value at `location`, from this batch, its chain, or `db`. Caller owns it.
            pub fn get(self: *const UnmerkleizedBatch, location: u64, db: *const Self) !?Value {
                try self.compatible(db);
                if (location >= self.size()) return error.LocationOutOfBounds;
                if (location >= self.base.size) {
                    const index: usize = @intCast(location - self.base.size);
                    return try value_mod.clone(?Value, self.gpa, self.appends.items[index]);
                }
                try check_floor(location, self.base_floor(db));
                var local: Local = .{ .batch = self };
                if (try local.read(self.gpa, location)) |value| return value;
                return db.get(location);
            }

            /// Answers locations held by the batch or its chain, checking the floor below them.
            const Local = struct {
                batch: *const UnmerkleizedBatch,

                fn read(local: *Local, gpa: Allocator, location: u64) !??Value {
                    const batch = local.batch;
                    if (location >= batch.base.size) {
                        const index: usize = @intCast(location - batch.base.size);
                        return try value_mod.clone(?Value, gpa, batch.appends.items[index]);
                    }
                    const parent = batch.parent orelse return null;
                    if (location < parent.bounds.db.size) return null;
                    const op = read_chain_op(parent, location) orelse return null;
                    return try owned_value(gpa, op);
                }
            };

            /// The values at strictly increasing `locations` into `out`. Caller owns them.
            pub fn get_many(
                self: *const UnmerkleizedBatch,
                locations: []const u64,
                db: *const Self,
                out: []?Value,
            ) !void {
                assert(locations.len == out.len);
                try self.compatible(db);
                if (locations.len == 0) return;
                try check_locations(locations, self.size());
                try check_floor(locations[0], self.base_floor(db));
                var local: Local = .{ .batch = self };
                try db.get_many_layered(locations, out, &local);
            }

            /// Hashes the batch's operations (its appends, then a commit). Consumes the batch
            /// on success; on error only `deinit` may follow.
            pub fn merkleize(self: *UnmerkleizedBatch, db: *const Self) !*MerkleizedBatch {
                const gpa = self.gpa;
                var state = try self.chain_bounds(db);
                errdefer gpa.free(state.ancestors);
                const start_floor = self.base_floor(db);
                const floor_new = self.inactivity_floor;
                const commit_location = self.size();
                try chain.validate_merkleize_floor(start_floor, floor_new, commit_location);
                try self.hand_over(floor_new);
                const merkleized = try gpa.create(MerkleizedBatch);
                errdefer gpa.destroy(merkleized);
                const journal_batch = try self.journal_batch.merkleize(gpa, &db.journal);
                errdefer journal_batch.release(gpa);
                const tip_size = commit_location + 1;
                const inactive_peaks = merkle.inactive_peaks(F, tip_size, floor_new);
                const tip_root = try journal_batch.root(&db.journal.hasher, inactive_peaks);
                state.tip = .{ .size = tip_size, .root = tip_root };
                state.inactivity_floor = floor_new;
                merkleized.init(gpa, journal_batch, self.parent, state);
                self.appends.deinit(gpa);
                if (self.parent) |parent| parent.release();
                self.* = undefined;
                return merkleized;
            }

            /// Moves the appends and the commit into the journal batch, which owns them after.
            fn hand_over(self: *UnmerkleizedBatch, floor_new: u64) !void {
                const gpa = self.gpa;
                const count = self.appends.items.len;
                const ops = try gpa.alloc(Operation, count + 1);
                defer gpa.free(ops);
                for (self.appends.items, ops[0..count]) |value, *op| op.* = .{ .append = value };
                ops[count] = .{ .commit = .{ .metadata = self.metadata, .floor = floor_new } };
                const size_before = self.journal_batch.size();
                try self.journal_batch.add_many(gpa, ops);
                self.appends.clearRetainingCapacity();
                self.metadata = null;
                assert(self.journal_batch.size() == size_before + count + 1);
            }

            /// The base, boundary, and live ancestor tips of the new batch, validated against
            /// `db` (`tip` and `inactivity_floor` are filled in by `merkleize`).
            fn chain_bounds(self: *const UnmerkleizedBatch, db: *const Self) !Bounds {
                var ancestors: std.ArrayList(Commitment) = .empty;
                errdefer ancestors.deinit(self.gpa);
                var oldest_base: ?Commitment = null;
                var current = self.parent;
                while (current) |batch| : (current = batch.live_parent()) {
                    try ancestors.append(self.gpa, batch.bounds.tip);
                    oldest_base = batch.bounds.base;
                }
                const boundary = chain.effective_boundary(F, Digest, self.db_state(), oldest_base);
                try chain.validate_batch_applicable(
                    F,
                    Digest,
                    db.commitment(),
                    boundary,
                    ancestors.items,
                );
                return .{
                    .base = self.base,
                    .db = boundary,
                    .tip = self.base,
                    .ancestors = try ancestors.toOwnedSlice(self.gpa),
                    .inactivity_floor = self.inactivity_floor,
                };
            }
        };

        /// A hashed batch, reference counted: `retain`/`release`.
        pub const MerkleizedBatch = struct {
            gpa: Allocator,
            strong: u32,
            weak: u32,
            parent: ?*MerkleizedBatch,
            journal_batch: *Journal.MerkleizedBatch,
            bounds: Bounds,

            /// Takes ownership of `journal_batch` and `state`, and a weak link to `parent`.
            fn init(
                self: *MerkleizedBatch,
                gpa: Allocator,
                journal_batch: *Journal.MerkleizedBatch,
                parent: ?*MerkleizedBatch,
                state: Bounds,
            ) void {
                assert(journal_batch.size() == state.tip.size);
                assert(state.base.size <= state.tip.size);
                self.* = .{
                    .gpa = gpa,
                    .strong = 1,
                    .weak = 1,
                    .parent = parent,
                    .journal_batch = journal_batch,
                    .bounds = state,
                };
                if (parent) |link| link.weak += 1;
            }

            pub fn retain(self: *MerkleizedBatch) *MerkleizedBatch {
                assert(self.strong > 0);
                self.strong += 1;
                return self;
            }

            pub fn release(self: *MerkleizedBatch) void {
                assert(self.strong > 0);
                self.strong -= 1;
                if (self.strong > 0) return;
                self.journal_batch.release(self.gpa);
                self.bounds.deinit(self.gpa);
                if (self.parent) |parent| parent.release_weak();
                self.parent = null;
                self.release_weak();
            }

            fn release_weak(self: *MerkleizedBatch) void {
                assert(self.weak > 0);
                self.weak -= 1;
                if (self.weak == 0) self.gpa.destroy(self);
            }

            fn live_parent(self: *const MerkleizedBatch) ?*MerkleizedBatch {
                const parent = self.parent orelse return null;
                assert(parent.weak > 0);
                return if (parent.strong > 0) parent else null;
            }

            pub fn commitment(self: *const MerkleizedBatch) Commitment {
                return self.bounds.tip;
            }

            pub fn root(self: *const MerkleizedBatch) Digest {
                return self.bounds.tip.root;
            }

            /// This batch's own operations and the location of the first.
            pub fn operations(self: *const MerkleizedBatch) struct { u64, []const Operation } {
                return .{ self.bounds.base.size, self.journal_batch.batch_items() };
            }

            /// A proof of this batch's operations against its root. Caller owns it.
            pub fn proof(self: *const MerkleizedBatch, db: *const Self) !Proof {
                try self.bounds.compatible(db.commitment());
                const tip = self.bounds.tip.size;
                const inactive_peaks = merkle.inactive_peaks(F, tip, self.bounds.inactivity_floor);
                return db.journal.speculative_proof(self.journal_batch, inactive_peaks);
            }

            /// The pins of this batch's first operation.
            pub fn pinned_nodes(
                self: *const MerkleizedBatch,
                db: *const Self,
                out: *[merkle.max_pinned_nodes]Digest,
            ) ![]Digest {
                try self.bounds.compatible(db.commitment());
                return db.journal.speculative_pinned_nodes(self.journal_batch, out);
            }

            /// The value at `location` from this batch's chain or `db`. Caller owns it.
            pub fn get(self: *const MerkleizedBatch, location: u64, db: *const Self) !?Value {
                try self.bounds.compatible(db.commitment());
                if (location >= self.bounds.tip.size) return error.LocationOutOfBounds;
                try check_floor(location, self.bounds.inactivity_floor);
                var local: ChainLocal = .{ .batch = self };
                if (try local.read(self.gpa, location)) |value| return value;
                return db.get(location);
            }

            const ChainLocal = struct {
                batch: *const MerkleizedBatch,

                fn read(local: *ChainLocal, gpa: Allocator, location: u64) !??Value {
                    if (location < local.batch.bounds.db.size) return null;
                    const op = read_chain_op(local.batch, location) orelse return null;
                    return try owned_value(gpa, op);
                }
            };

            /// The values at strictly increasing `locations` into `out`. Caller owns them.
            pub fn get_many(
                self: *const MerkleizedBatch,
                locations: []const u64,
                db: *const Self,
                out: []?Value,
            ) !void {
                assert(locations.len == out.len);
                try self.bounds.compatible(db.commitment());
                if (locations.len == 0) return;
                try check_locations(locations, self.bounds.tip.size);
                try check_floor(locations[0], self.bounds.inactivity_floor);
                var local: ChainLocal = .{ .batch = self };
                try db.get_many_layered(locations, out, &local);
            }

            /// A child batch on top of this one.
            pub fn new_batch(self: *MerkleizedBatch) UnmerkleizedBatch {
                return .{
                    .gpa = self.gpa,
                    .journal_batch = self.journal_batch.new_batch(),
                    .parent = self.retain(),
                    .inactivity_floor = self.bounds.inactivity_floor,
                    .base = self.bounds.tip,
                };
            }
        };
    };
}

/// The root of a freshly initialized database (`Commit(None, 0)` alone).
pub fn initial_root(comptime F: type, comptime E: type, comptime H: type) H.Digest {
    const Op = operation.Operation(F, E);
    const op: Op = .{ .commit = .{ .metadata = null, .floor = 0 } };
    var buffer: [1024]u8 = undefined;
    const size = codec.encode_size(Op, op);
    assert(size <= buffer.len); // A metadata-free commit is a tag, padding, and a varint.
    const encoded = codec.encode_to(Op, op, buffer[0..size]);
    return qmdb.single_operation_root(F, H, encoded);
}
