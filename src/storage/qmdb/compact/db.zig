//! The compact db and its batches (commonware's `qmdb/compact/db.rs`). See `mod.zig`.
//!
//! Differences from commonware, all from zigware's synchronous storage: `start_sync` completes
//! at once (no pending sync to wait on or resurface), and the db is a value with `*Self`
//! methods instead of being consumed and returned. After an error from a mutating method the
//! db must only be closed (`deinit`), as commonware drops it.

const std = @import("std");
const assert = std.debug.assert;
const refcount = @import("../../refcount.zig");
const RefCount = refcount.RefCount;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const chain = @import("../chain.zig");
const value_mod = @import("../value.zig");
const source = @import("../sync/source.zig");
const target_mod = @import("../sync/target.zig");
const diff_mod = @import("../any/diff.zig");
const witness = @import("witness.zig");
const op_mod = @import("operation.zig");
const sync_mod = @import("sync.zig");

const Storage = runtime.storage.Storage;

/// Configuration of a compact db over operations `O`. The db borrows the witness journal's
/// partition name, which must outlive it. `codec_config` decodes the commits the witnesses
/// hold (commonware keeps it in the witness journal's config).
pub fn Config(comptime F: type, comptime D: type, comptime O: type) type {
    return struct {
        witness: witness.Journal(F, D).Cfg,
        codec_config: codec.Cfg(O),
    };
}

/// `Db` declares its own `Config` (the sync interface's name for `Cfg`).
const ConfigOf = Config;

pub fn Db(comptime F: type, comptime O: type, comptime H: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Family = F;
        pub const Operation = O;
        pub const Value = O.Value;
        pub const Digest = H.Digest;
        pub const Mutation = op_mod.Mutation(O);
        pub const Commitment = chain.Commitment(F, Digest);
        pub const Bounds = chain.Bounds(F, Digest);
        pub const Proof = merkle.Proof(F, Digest);
        pub const Cfg = ConfigOf(F, Digest, O);
        pub const WitnessJournal = witness.Journal(F, Digest);
        pub const Stored = witness.Stored(F, Digest);
        pub const Witness = witness.Witness(F, Digest, O);
        pub const Verified = witness.Verified(F, Digest, O);
        pub const Merkle = witness.Merkle(F, Digest);
        pub const Request = source.Request(F);
        pub const Response = source.Response(F, O, Digest);
        pub const keyed = op_mod.is_keyed(O);
        const Rebuilt = witness.Rebuilt(F, Digest, O);

        // The sync `Database` interface (sync.zig).
        const SyncImpl = sync_mod.Sync(Self);
        pub const Op = O;
        pub const Hasher = H;
        pub const Config = Cfg;
        pub const Journal = SyncImpl.Journal;
        pub const Target = SyncImpl.Target;
        pub const journal_config = SyncImpl.journal_config;
        pub const open_journal = SyncImpl.open_journal;
        pub const from_sync_result = SyncImpl.from_sync_result;
        pub const persist_sync_result = SyncImpl.persist_sync_result;
        pub const discard_local_state = SyncImpl.discard_local_state;
        pub const local_pinned_nodes = SyncImpl.local_pinned_nodes;
        pub const prune_to_target = SyncImpl.prune_to_target;
        pub const validate_target = SyncImpl.validate_target;

        const Open = struct {
            journal: WitnessJournal,
            /// Whether a durability operation covers the tip.
            committed: bool,
            /// The db's reference on the sync the last `start_sync` began, kept until the next
            /// full journal sync, so a dropped completion's failure still surfaces.
            pending_sync: ?runtime.storage.Completion = null,

            /// Waits for the sync `start_sync` began, surfacing its failure.
            fn wait_for_sync(open: *const Open) runtime.storage.Error!void {
                const pending = open.pending_sync orelse return;
                try pending.wait();
            }

            fn release_sync(open: *Open) void {
                if (open.pending_sync) |pending| pending.release();
                open.pending_sync = null;
            }
        };

        /// Where the witnesses live: the open journal, or a compact-sync import not yet
        /// journaled, whose partition keeps its previous contents unopened until the first
        /// apply or durability operation replaces them with the tip.
        const State = union(enum) { open: Open, replacing };

        gpa: Allocator,
        storage: Storage,
        cfg: Cfg,
        /// The peak-only Merkle the witnesses describe.
        merkle: Merkle,
        state: State,
        /// The verified tip witness.
        tip: Verified,

        /// Opens from the latest retained witness at or below `max_size` operations (null: the
        /// latest). Fresh storage receives a durable genesis witness. A bounded open durably
        /// discards every witness newer than the selected one. Fails with
        /// `InvalidInitializationBound` for a zero bound, `HistoricalFloorPruned` when no
        /// retained witness is within it, a codec error when the selected commit cannot be
        /// decoded, and `DataCorrupted` when it cannot be rebuilt or an import was interrupted.
        pub fn init(gpa: Allocator, storage: Storage, cfg: Cfg, max_size: ?u64) !Self {
            try qmdb.validate_initialization_bound(max_size);
            var recovery = try witness.recover(F, Digest, gpa, storage, cfg.witness, max_size);
            var selected = select(gpa, &recovery, cfg.codec_config, max_size) catch |err| {
                recovery.deinit();
                return err;
            };
            errdefer {
                selected.rebuilt.merkle.deinit();
                selected.rebuilt.tip.deinit(gpa);
            }
            var journal = try recovery.finish(selected.end);
            errdefer journal.deinit();
            if (selected.fresh) {
                try append_witness(gpa, &journal, &selected.rebuilt.tip.witness);
                try journal.sync();
            }
            assert(journal.size() > 0);
            return .{
                .gpa = gpa,
                .storage = storage,
                .cfg = cfg,
                .merkle = selected.rebuilt.merkle,
                .state = .{ .open = .{ .journal = journal, .committed = true } },
                .tip = selected.rebuilt.tip,
            };
        }

        const Selected = struct { rebuilt: Rebuilt, end: u64, fresh: bool };

        /// Selects and rebuilds the witness to open, before any history is discarded.
        fn select(
            gpa: Allocator,
            recovery: *WitnessJournal.RecoveryType,
            codec_config: codec.Cfg(O),
            max_size: ?u64,
        ) !Selected {
            const bounds = recovery.get_bounds();
            assert(bounds.start <= bounds.end);
            if (bounds.start == bounds.end) {
                if (bounds.start != 0) return error.DataCorrupted; // An interrupted import.
                const genesis = witness.genesis(F, Digest, O);
                const rebuilt = try witness.restore(F, O, H, gpa, genesis);
                return .{ .rebuilt = rebuilt, .end = 0, .fresh = true };
            }
            // Journal positions count witnesses; the cap counts database operations.
            var end = bounds.end;
            if (max_size) |cap| {
                var start = bounds.start;
                while (start < end) {
                    const mid = start + (end - start) / 2;
                    var entry = try recovery.read(mid);
                    const entry_size = entry.size;
                    entry.deinit(gpa);
                    if (entry_size <= cap) start = mid + 1 else end = mid;
                }
                if (end == bounds.start) return error.HistoricalFloorPruned;
            }
            var entry = try recovery.read(end - 1);
            defer entry.deinit(gpa);
            const rebuilt = try witness.rebuild(F, O, H, gpa, &entry, codec_config);
            assert(rebuilt.tip.size() == entry.size);
            return .{ .rebuilt = rebuilt, .end = end, .fresh = false };
        }

        /// Builds a db from state fetched by sync: `last_commit_op`, a commit whose floor is at
        /// or below `last_commit_loc`, and the pinned nodes at `last_commit_loc`. The import
        /// lives in memory, and the configured partition stays unopened, until the first
        /// `apply_batch`, `commit`, `sync`, `start_sync`, or `prune` replaces the partition's
        /// contents with it. Takes `last_commit_op`, also on error.
        pub fn init_from_sync(
            gpa: Allocator,
            storage: Storage,
            cfg: Cfg,
            last_commit_loc: u64,
            pinned_nodes: []const Digest,
            last_commit_op: O,
        ) !Self {
            var op_owned = true;
            errdefer if (op_owned) codec.free(O, gpa, last_commit_op);
            // Reject a commit this db could not decode on reopen.
            try check_decodes(gpa, cfg.codec_config, last_commit_op);
            const pinned = try gpa.dupe(Digest, pinned_nodes);
            op_owned = false;
            const imported: Witness = .{
                .commit = last_commit_op,
                .size = last_commit_loc + 1,
                .pinned_nodes = pinned,
            };
            const rebuilt = try witness.restore(F, O, H, gpa, imported);
            assert(rebuilt.tip.size() == last_commit_loc + 1);
            return .{
                .gpa = gpa,
                .storage = storage,
                .cfg = cfg,
                .merkle = rebuilt.merkle,
                .state = .replacing,
                .tip = rebuilt.tip,
            };
        }

        fn check_decodes(gpa: Allocator, cfg: codec.Cfg(O), op: O) !void {
            const encoded = try codec.encode(O, gpa, op);
            defer gpa.free(encoded);
            const decoded = try codec.decode_cfg(O, gpa, encoded, cfg);
            codec.free(O, gpa, decoded);
        }

        /// Closes the db without syncing.
        pub fn deinit(self: *Self) void {
            switch (self.state) {
                .open => |*open| {
                    open.release_sync();
                    open.journal.deinit();
                },
                .replacing => {},
            }
            self.merkle.deinit();
            self.tip.deinit(self.gpa);
            self.* = undefined;
        }

        pub fn root(self: *const Self) Digest {
            return self.tip.root;
        }

        /// The inactivity floor declared by the last applied batch.
        pub fn inactivity_floor(self: *const Self) u64 {
            return self.tip.inactivity_floor;
        }

        /// The location of the next operation appended.
        pub fn size(self: *const Self) u64 {
            return self.tip.size();
        }

        /// The metadata of the last applied commit, owned by the caller.
        pub fn get_metadata(self: *const Self) !?Value {
            return value_mod.clone(?Value, self.gpa, op_mod.metadata(O, &self.tip.witness.commit));
        }

        /// The sync target of the current witness, whose range covers only the last commit
        /// (durable once a covering `commit`, `sync`, `start_sync`, or `prune` returns).
        pub fn target(self: *const Self) Target {
            return self.tip.target();
        }

        pub fn commitment(self: *const Self) Commitment {
            return .{ .size = self.size(), .root = self.root() };
        }

        /// The open journal, first replacing the partition's contents with the tip if an
        /// import is pending: a durable reset to position 1, then the tip witness.
        fn open_witnesses(self: *Self) !*Open {
            switch (self.state) {
                .open => |*open| return open,
                .replacing => {},
            }
            const witness_cfg = self.cfg.witness;
            var journal = try WitnessJournal.init_at_size(self.gpa, self.storage, witness_cfg, 1);
            errdefer journal.deinit();
            try append_witness(self.gpa, &journal, &self.tip.witness);
            self.state = .{ .open = .{ .journal = journal, .committed = false } };
            assert(self.state.open.journal.size() == 2);
            return &self.state.open;
        }

        fn append_witness(gpa: Allocator, journal: *WitnessJournal, tip: *const Witness) !void {
            const stored = try tip.stored(gpa);
            defer gpa.free(stored.commit);
            const before = journal.size();
            _ = try journal.append(stored);
            assert(journal.size() == before + 1);
        }

        /// A batch on the db's current state.
        pub fn new_batch(self: *const Self) !UnmerkleizedBatch {
            return .{
                .gpa = self.gpa,
                .merkle_batch = try self.merkle.new_batch(),
                .parent = null,
                .inactivity_floor = self.inactivity_floor(),
                .base = self.commitment(),
            };
        }

        /// A merkleized batch representing the current state (it has no operations).
        pub fn to_batch(self: *const Self) !*MerkleizedBatch {
            const batch = try self.gpa.create(MerkleizedBatch);
            errdefer self.gpa.destroy(batch);
            const merkle_batch = try self.merkle.to_batch();
            const state = Bounds.from_db(self.commitment(), self.inactivity_floor());
            batch.init(self.gpa, merkle_batch, &.{}, null, state);
            return batch;
        }

        /// Checks that `batch` can be applied to the db in its current state.
        pub fn validate_batch(self: *const Self, batch: *const MerkleizedBatch) !void {
            return batch.bounds.validate_apply_to(self.commitment());
        }

        /// Applies `batch`, journaling a pending import first; the new witness is durable after
        /// a covering durability operation. A batch without operations only journals a pending
        /// import. The caller keeps its reference.
        pub fn apply_batch(self: *Self, batch: *const MerkleizedBatch) !void {
            try self.validate_batch(batch);
            assert(self.tip.size() == self.merkle.leaves());
            const open = try self.open_witnesses();
            try self.merkle.apply_batch(batch.merkle_batch);
            const ops = batch.ops;
            // Only a `to_batch` snapshot has no operations; any other batch ends with a commit.
            assert((ops.len == 0) == (self.tip.size() == self.merkle.leaves()));
            if (ops.len == 0) return;
            const commit_op = try op_mod.clone_commit(O, self.gpa, ops[ops.len - 1]);
            // Built before pruning: the commit's proof needs the unpruned Merkle.
            const floor = batch.bounds.inactivity_floor;
            var tip = try witness.build(F, O, H, self.gpa, &self.merkle, commit_op, floor);
            errdefer tip.deinit(self.gpa);
            self.merkle.prune_to_frontier();
            try append_witness(self.gpa, &open.journal, &tip.witness);
            open.committed = false;
            self.tip.deinit(self.gpa);
            self.tip = tip;
            assert(self.commitment().eql(batch.bounds.tip));
        }

        /// Makes the current state durable (journaling a pending import first).
        /// First waits for a sync `start_sync` began, surfacing its failure.
        pub fn commit(self: *Self) !void {
            const open = try self.open_witnesses();
            try open.wait_for_sync();
            if (!open.committed) try open.journal.commit();
            open.committed = true;
        }

        /// Starts persisting the current state (journaling a pending import first) and returns
        /// the sync's completion, one reference the caller owns; the db keeps another, so a
        /// dropped completion's failure surfaces from the next `commit` or `start_sync`. A
        /// prior sync's failure returns as a ready completion before a new sync replaces it.
        pub fn start_sync(self: *Self) !runtime.storage.Completion {
            const open = try self.open_witnesses();
            open.wait_for_sync() catch |err| return .ready(err);
            const completion = try open.journal.start_sync();
            open.release_sync();
            open.pending_sync = completion.retain();
            open.committed = true;
            assert(open.pending_sync != null);
            return completion;
        }

        /// Makes the current state durable, journal metadata included.
        pub fn sync(self: *Self) !void {
            const open = try self.open_witnesses();
            try open.journal.sync();
            open.release_sync(); // The full sync settles the pipelined one.
            open.committed = true;
        }

        /// Drops witnesses of commits with fewer than `location` operations (some below it may
        /// survive). The tip's witness always survives. Durable when this returns.
        pub fn prune(self: *Self, location: u64) !void {
            const open = try self.open_witnesses();
            const bounds = open.journal.get_bounds();
            assert(bounds.start < bounds.end); // An open journal holds the tip.
            var found = try first_at_or_above(self.gpa, &open.journal, location);
            if (found.entry) |*entry| entry.deinit(self.gpa);
            _ = try open.journal.prune(@min(found.position, bounds.end - 1));
            try open.journal.sync();
            open.committed = true;
            assert(open.journal.get_bounds().end == bounds.end);
        }

        /// Destroys all persisted state.
        pub fn destroy(self: *Self) !void {
            const gpa = self.gpa;
            defer {
                self.merkle.deinit();
                self.tip.deinit(gpa);
                self.* = undefined;
            }
            switch (self.state) {
                .open => |*open| {
                    open.release_sync();
                    try open.journal.destroy();
                },
                // Reset rather than open, so the previous witnesses are never decoded.
                .replacing => {
                    const storage = self.storage;
                    const witness_cfg = self.cfg.witness;
                    var journal = try WitnessJournal.init_at_size(gpa, storage, witness_cfg, 0);
                    try journal.destroy();
                },
            }
        }

        const Found = struct { position: u64, entry: ?Stored };

        /// The first retained position whose witness commits at least `size` operations (the
        /// journal end if none does), with that witness, owned by the caller.
        fn first_at_or_above(gpa: Allocator, journal: *const WitnessJournal, size_min: u64) !Found {
            const bounds = journal.get_bounds();
            var low = bounds.start;
            var high = bounds.end;
            var found: ?Stored = null;
            errdefer if (found) |*entry| entry.deinit(gpa);
            while (low < high) {
                const mid = low + (high - low) / 2;
                var entry = try journal.read(mid);
                if (entry.size < size_min) {
                    entry.deinit(gpa);
                    low = mid + 1;
                } else {
                    high = mid;
                    if (found) |*old| old.deinit(gpa);
                    found = entry;
                }
            }
            assert(low == high);
            return .{ .position = low, .entry = found };
        }

        /// Serves `request` from a committed state the witness journal retains: exactly its
        /// commit and the pinned nodes one operation below it. Other requests fail as a pruned
        /// log does. The caller owns the response (`deinit`).
        pub fn serve(self: *const Self, request: Request) !Response {
            const request_size = request.size();
            const start = request.start();
            if (request_size > self.size() or request_size == 0) return error.RangeOutOfBounds;
            if (start >= request_size) return error.RangeOutOfBounds;
            if (start < request_size - 1) return error.ItemPruned;
            if (request_size == self.size()) return respond(self.gpa, request, &self.tip);
            var witnessed = try self.retained(request_size);
            defer witnessed.deinit(self.gpa);
            return respond(self.gpa, request, &witnessed);
        }

        fn respond(gpa: Allocator, request: Request, verified: *const Verified) !Response {
            var proof = try verified.proof.clone(gpa);
            errdefer proof.deinit(gpa);
            const op = try op_mod.clone_commit(O, gpa, verified.witness.commit);
            errdefer codec.free(O, gpa, op);
            switch (request) {
                .operations => {
                    const ops = try gpa.alloc(O, 1);
                    ops[0] = op;
                    return .{ .operations = .{ .proof = proof, .operations = ops } };
                },
                .boundary => {
                    const pinned = try gpa.dupe(Digest, verified.witness.pinned_nodes);
                    return .{ .boundary = .{ .proof = proof, .op = op, .pinned_nodes = pinned } };
                },
            }
        }

        /// The retained witness below the tip that commits exactly `size_exact` operations.
        fn retained(self: *const Self, size_exact: u64) !Verified {
            // A pending import is absent from the journal, which holds the previous contents.
            const open = switch (self.state) {
                .open => |*open| open,
                .replacing => return error.ItemPruned,
            };
            const found = try first_at_or_above(self.gpa, &open.journal, size_exact);
            var entry = found.entry orelse return error.ItemPruned;
            defer entry.deinit(self.gpa);
            if (entry.size != size_exact) return error.ItemPruned;
            var rebuilt = try witness.rebuild(F, O, H, self.gpa, &entry, self.cfg.codec_config);
            rebuilt.merkle.deinit();
            assert(rebuilt.tip.size() == size_exact);
            return rebuilt.tip;
        }

        fn free_mutation(gpa: Allocator, mutation: Mutation) void {
            if (comptime keyed) {
                codec.free(O.Key, gpa, mutation.key);
                codec.free(Value, gpa, mutation.value);
            } else {
                codec.free(Value, gpa, mutation);
            }
        }

        /// A speculative batch of mutations.
        pub const UnmerkleizedBatch = struct {
            gpa: Allocator,
            metadata: ?Value = null,
            inactivity_floor: u64,
            merkle_batch: Merkle.AppendBatch,
            mutations: std.ArrayList(Mutation) = .empty,
            /// A strong reference to the parent, null for a batch on the db.
            parent: ?*MerkleizedBatch,
            /// The commitment this batch builds on.
            base: Commitment,

            /// Discards the batch and the values it owns.
            pub fn deinit(self: *UnmerkleizedBatch) void {
                self.merkle_batch.deinit(self.gpa);
                for (self.mutations.items) |mutation| free_mutation(self.gpa, mutation);
                self.mutations.deinit(self.gpa);
                codec.free(?Value, self.gpa, self.metadata);
                if (self.parent) |parent| parent.release();
                self.* = undefined;
            }

            /// The operation count after the appends, before the commit (keyless).
            pub fn size(self: *const UnmerkleizedBatch) u64 {
                comptime assert(!keyed);
                return self.base.size + self.mutations.items.len;
            }

            /// Sets the metadata of this batch's commit (not inherited). The batch owns it.
            pub fn with_metadata(self: *UnmerkleizedBatch, metadata: ?Value) void {
                codec.free(?Value, self.gpa, self.metadata);
                self.metadata = metadata;
            }

            /// Sets the inactivity floor of this batch's commit (inherited by children). It
            /// does not drive pruning here.
            pub fn with_inactivity_floor(self: *UnmerkleizedBatch, floor: u64) void {
                self.inactivity_floor = floor;
            }

            /// Appends `value` (keyless), which the batch owns on success.
            pub fn append(self: *UnmerkleizedBatch, value: Value) !void {
                comptime assert(!keyed);
                try self.mutations.append(self.gpa, value);
            }

            /// Sets `key` to `value` (immutable); a later set of a key replaces an earlier one.
            /// The batch owns both on success.
            pub fn set(self: *UnmerkleizedBatch, key: O.Key, value: Value) !void {
                comptime assert(keyed);
                try self.mutations.append(self.gpa, .{ .key = key, .value = value });
            }

            fn db_state(self: *const UnmerkleizedBatch) Commitment {
                const parent = self.parent orelse return self.base;
                return parent.bounds.db;
            }

            fn base_floor(self: *const UnmerkleizedBatch, db: *const Self) u64 {
                const parent = self.parent orelse return db.inactivity_floor();
                return parent.bounds.inactivity_floor;
            }

            /// Resolves the mutations into operations (sets in key order, one per key), adds
            /// the commit, and merkleizes. Consumes the batch on success; on error only
            /// `deinit` may follow. Fails with `StaleBatch` when `db` is at no state of the
            /// chain, `FloorRegressed` or `FloorBeyondCommit` for a bad floor.
            pub fn merkleize(self: *UnmerkleizedBatch, db: *const Self) !*MerkleizedBatch {
                const gpa = self.gpa;
                if (comptime keyed) self.keep_last_sets();
                var state = try self.chain_bounds(db);
                errdefer gpa.free(state.ancestors);
                const floor = self.inactivity_floor;
                const commit_location = self.base.size + self.mutations.items.len;
                try chain.validate_merkleize_floor(self.base_floor(db), floor, commit_location);
                const merkleized = try gpa.create(MerkleizedBatch);
                errdefer gpa.destroy(merkleized);
                const ops = try self.take_operations();
                errdefer {
                    codec.free_items(O, gpa, ops);
                    gpa.free(ops);
                }
                const hasher = qmdb.hasher(H);
                try self.merkle_batch.add_many(gpa, &hasher, O, ops);
                const merkle_batch = try self.merkle_batch.merkleize(&db.merkle, &hasher);
                errdefer merkle_batch.release(gpa);
                const tip_size = commit_location + 1;
                const inactive_peaks = merkle.inactive_peaks(F, tip_size, floor);
                const tip_root = try merkle_batch.root(&hasher, inactive_peaks);
                state.tip = .{ .size = tip_size, .root = tip_root };
                state.inactivity_floor = floor;
                merkleized.init(gpa, merkle_batch, ops, self.parent, state);
                self.mutations.deinit(gpa);
                if (self.parent) |parent| parent.release();
                self.* = undefined;
                return merkleized;
            }

            /// Moves the mutations and the commit into owned operations.
            fn take_operations(self: *UnmerkleizedBatch) ![]O {
                const count = self.mutations.items.len;
                const ops = try self.gpa.alloc(O, count + 1);
                for (self.mutations.items, ops[0..count]) |mutation, *op| {
                    op.* = op_mod.from_mutation(O, mutation);
                }
                ops[count] = op_mod.commit(O, self.metadata, self.inactivity_floor);
                self.mutations.clearRetainingCapacity();
                self.metadata = null;
                assert(ops[count] == .commit);
                return ops;
            }

            /// Sorts the sets by key and keeps each key's last, freeing the others.
            fn keep_last_sets(self: *UnmerkleizedBatch) void {
                const sets = self.mutations.items;
                // `std.mem.sort` is stable, so each key's last set stays last.
                std.mem.sort(Mutation, sets, {}, less);
                var kept: usize = 0;
                for (sets, 0..) |pending, at| {
                    const last = at + 1 == sets.len or
                        diff_mod.order(O.Key, &pending.key, &sets[at + 1].key) != .eq;
                    if (!last) {
                        free_mutation(self.gpa, pending);
                        continue;
                    }
                    sets[kept] = pending;
                    kept += 1;
                }
                self.mutations.shrinkRetainingCapacity(kept);
                assert(kept <= sets.len);
            }

            fn less(_: void, a: Mutation, b: Mutation) bool {
                return diff_mod.order(O.Key, &a.key, &b.key) == .lt;
            }

            /// The base, boundary, and live ancestor tips of the new batch, validated against
            /// `db` (`tip` and `inactivity_floor` are filled in by `merkleize`).
            fn chain_bounds(self: *const UnmerkleizedBatch, db: *const Self) !Bounds {
                var ancestors: std.ArrayList(Commitment) = .empty;
                errdefer ancestors.deinit(self.gpa);
                var oldest_base: ?Commitment = null;
                var walk: refcount.Ancestors(MerkleizedBatch) = .from_first(self.gpa, self.parent);
                defer walk.deinit();
                while (walk.next()) |batch| {
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

        /// A merkleized batch, reference counted (`retain`/`release`), with a weak parent link.
        pub const MerkleizedBatch = struct {
            gpa: Allocator,
            strong: RefCount,
            weak: RefCount,
            parent: ?*MerkleizedBatch,
            merkle_batch: *Merkle.MerkleizedBatch,
            /// This batch's operations (owned), ending with its commit.
            ops: []O,
            bounds: Bounds,

            fn init(
                self: *MerkleizedBatch,
                gpa: Allocator,
                merkle_batch: *Merkle.MerkleizedBatch,
                ops: []O,
                parent: ?*MerkleizedBatch,
                state: Bounds,
            ) void {
                assert(state.base.size + ops.len == state.tip.size);
                assert(merkle_batch.leaves() == state.tip.size);
                self.* = .{
                    .gpa = gpa,
                    .strong = .init(),
                    .weak = .init(),
                    .parent = parent,
                    .merkle_batch = merkle_batch,
                    .ops = ops,
                    .bounds = state,
                };
                if (parent) |link| link.weak.retain();
            }

            pub fn retain(self: *MerkleizedBatch) *MerkleizedBatch {
                self.strong.retain();
                return self;
            }

            pub fn release(self: *MerkleizedBatch) void {
                if (!self.strong.release()) return;
                self.merkle_batch.release(self.gpa);
                codec.free_items(O, self.gpa, self.ops);
                self.gpa.free(self.ops);
                self.bounds.deinit(self.gpa);
                if (self.parent) |parent| parent.release_weak();
                self.parent = null;
                self.release_weak();
            }

            fn release_weak(self: *MerkleizedBatch) void {
                if (self.weak.release()) self.gpa.destroy(self);
            }

            pub fn commitment(self: *const MerkleizedBatch) Commitment {
                return self.bounds.tip;
            }

            pub fn root(self: *const MerkleizedBatch) Digest {
                return self.bounds.tip.root;
            }

            /// The sync target reached once this batch is applied; its range covers only the
            /// last commit, the one operation a compact db holds.
            pub fn target(self: *const MerkleizedBatch) Target {
                const end = self.bounds.tip.size;
                return .init(self.root(), end - 1, end);
            }

            /// This batch's operations and the location of the first.
            pub fn operations(self: *const MerkleizedBatch) struct { u64, []const O } {
                return .{ self.bounds.base.size, self.ops };
            }

            /// An inclusion proof of `operations` against this batch's root, until the batch
            /// is applied. Fails with `StaleRead` off the chain and `Empty` without operations.
            pub fn proof(self: *const MerkleizedBatch, db: *const Self) !Proof {
                try self.bounds.compatible(db.commitment());
                if (self.ops.len == 0) return error.Empty;
                const tip = self.bounds.tip.size;
                const inactive_peaks = merkle.inactive_peaks(F, tip, self.bounds.inactivity_floor);
                const hasher = qmdb.hasher(H);
                const range: merkle.Range = .{ .start = self.bounds.base.size, .end = tip };
                const base = &db.merkle.mem;
                const batch = self.merkle_batch;
                return batch.range_proof(self.gpa, base, &hasher, range, inactive_peaks);
            }

            /// The Merkle frontier at this batch's first operation (`merkle.nodes_to_pin`).
            pub fn pinned_nodes(
                self: *const MerkleizedBatch,
                db: *const Self,
                out: *[merkle.max_pinned_nodes]Digest,
            ) ![]Digest {
                try self.bounds.compatible(db.commitment());
                var positions_buffer: [merkle.max_pinned_nodes]u64 = undefined;
                const positions = merkle.nodes_to_pin(F, self.bounds.base.size, &positions_buffer);
                for (positions, out[0..positions.len]) |position, *digest| {
                    digest.* = self.merkle_batch.get_node(position) orelse
                        db.merkle.mem.get_node(position) orelse return error.ElementPruned;
                }
                return out[0..positions.len];
            }

            /// A child batch on top of this one. Unapplied ancestors must be held until the
            /// child is merkleized.
            pub fn new_batch(self: *MerkleizedBatch) UnmerkleizedBatch {
                return .{
                    .gpa = self.gpa,
                    .merkle_batch = .{ .inner = self.merkle_batch.new_batch() },
                    .parent = self.retain(),
                    .inactivity_floor = self.bounds.inactivity_floor,
                    .base = self.bounds.tip,
                };
            }
        };
    };
}

/// The root of a fresh compact db: `Commit(None, 0)` alone.
pub fn initial_root(comptime F: type, comptime O: type, comptime H: type) H.Digest {
    const genesis = op_mod.commit(O, null, 0);
    var buffer: [256]u8 = undefined;
    assert(codec.encode_size(O, genesis) <= buffer.len);
    return qmdb.single_operation_root(F, H, codec.encode_to(O, genesis, &buffer));
}
