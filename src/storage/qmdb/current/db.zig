//! The `current` database (commonware's `qmdb/current/{db,mod}.rs`): an `any` database whose
//! canonical root also commits to the activity bitmap, grafted onto the ops tree in `N`-byte
//! chunks, so a proof can show that an operation is its key's current value.
//!
//! `Db(F, U, C, I, H, N)` takes `any.Db`'s parameters. It adds the grafted tree, the graft
//! roots its batches regraft from, and a metadata partition holding the bitmap's pruned
//! chunks (key `(1, 0)`) and the grafted tree's pinned nodes (keys `(0, i)`), as commonware
//! does. Mutators take `*Self`; after a storage error only `deinit` may follow.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const value_mod = @import("../value.zig");
const metadata_mod = @import("../../metadata/mod.zig");
const any = @import("../any/mod.zig");
const qmdb = @import("../mod.zig");
const metrics_mod = @import("../metrics.zig");
const grafting = @import("grafting.zig");
const grafted_mod = @import("grafted.zig");
const canonical = @import("canonical.zig");
const proof_mod = @import("proof.zig");
const unordered_proof = @import("unordered/proof.zig");
const ordered_proof = @import("ordered/proof.zig");
const batch_mod = @import("batch.zig");

const Storage = runtime.storage.Storage;
const Scope = runtime.telemetry.metrics.Scope;
const MetadataKey = utils.sequence.PrefixedU64;

/// Metadata key prefix of the grafted tree's pinned nodes.
const node_prefix: u8 = 0;
/// Metadata key prefix of the bitmap's pruned chunk count.
const pruned_chunks_prefix: u8 = 1;

/// Configuration of a `current` database.
pub fn Config(comptime T: type, comptime JournalConfig: type) type {
    return struct {
        /// The Merkle structure backing the authenticated journal.
        merkle: merkle.full.Config,
        /// The operation log.
        log: JournalConfig,
        /// The clock that times calls into the duration metrics (also the `any` database's);
        /// null skips timing.
        io: ?std.Io = null,
        /// The partition of the grafted tree's metadata.
        grafted_metadata_partition: []const u8,
        /// The translator of the snapshot index.
        translator: T,
        /// Entries in the `location -> key` cache used during init; null disables it.
        init_cache: ?usize = null,
    };
}

/// A `current` database over `any.Db(F, U, C, I, H, N)`. `N` must be a power-of-two multiple
/// of the digest size.
pub fn Db(F: type, U: type, C: type, I: type, H: type, comptime N: usize) type {
    return struct {
        const Self = @This();
        comptime {
            assert(N % H.Digest.fixed_size == 0); // Chunks hold whole digests.
            assert(std.math.isPowerOfTwo(N)); // Chunks align with ops subtrees.
        }
        pub const Any = any.Db(F, U, C, I, H, N);
        pub const Family = F;
        pub const Hasher = H;
        pub const Key = U.Key;
        pub const Value = U.Value;
        pub const Operation = Any.Operation;
        pub const Digest = H.Digest;
        pub const chunk_bytes = N;
        pub const Mem = merkle.mem.Mem(F, Digest);
        pub const GraftedBatch = Mem.MerkleizedBatch;
        pub const Layer = batch_mod.Layer(N);
        pub const View = batch_mod.View(N, Any.Bitmap);
        pub const Witness = proof_mod.OpsRootWitness(F, Digest);
        pub const RangeProof = proof_mod.RangeProof(F, Digest);
        pub const OperationProof = proof_mod.OperationProof(F, Digest, N);
        /// The key-value proof: ordered proofs also carry the key's next key.
        pub const KeyValueProof = if (U.siblings)
            ordered_proof.KeyValueProof(F, Key, Digest, N)
        else
            unordered_proof.KeyValueProof(F, Digest, N);
        /// The exclusion proof of an ordered database.
        pub const ExclusionProof = if (U.siblings)
            ordered_proof.ExclusionProof(F, Key, U.Encoding, Digest, N)
        else
            void;
        pub const Cfg = Config(I.Translator, C.BackingConfig);
        pub const UnmerkleizedBatch = batch_mod.Unmerkleized(Self);
        pub const MerkleizedBatch = batch_mod.Merkleized(Self);
        pub const StagedBatch = batch_mod.Staged(Self);
        pub const Slot = Any.Slot;
        const Metadata = metadata_mod.Metadata(MetadataKey, []const u8);
        const GraftedStorage = grafted_mod.Storage(F, H, *const Mem, *Any.Log.Merkle);
        const chunk_bits: u64 = N * 8;

        gpa: Allocator,
        any: Any,
        /// The grafted tree: one leaf per graftable bitmap chunk.
        grafted_tree: Mem,
        graft_roots: canonical.GraftRoots(Digest),
        metadata: Metadata,
        /// The canonical root.
        root_digest: Digest,
        ops_root_witness: Witness,
        metrics: Metrics,

        /// Opens the database: the `any` database at the last commit (within `max_size`
        /// operations), its bitmap pruned as the metadata records, and the grafted tree rebuilt
        /// over it. Fails with `HistoricalFloorPruned` if the bitmap was pruned past the
        /// selected commit or its floor.
        pub fn init(
            gpa: Allocator,
            storage: Storage,
            scope: Scope,
            cfg: Cfg,
            max_size: ?u64,
        ) !Self {
            var metadata = try open_metadata(gpa, storage, cfg.grafted_metadata_partition);
            errdefer metadata.deinit();
            var pins: [merkle.max_pinned_nodes]Digest = undefined;
            var pruned_chunks = try read_pruned_chunks(&metadata);
            // An interrupted destroy can leave old pruning metadata beside an emptied log.
            if (pruned_chunks > 0) {
                const span = try C.span(gpa, storage, cfg.log);
                if (span.start == 0 and span.end == 0) {
                    metadata.clear();
                    try metadata.sync();
                    pruned_chunks = 0;
                }
            }
            const pinned = try read_pins(&metadata, pruned_chunks, &pins);
            const any_cfg: Any.Cfg = .{
                .merkle = cfg.merkle,
                .log = cfg.log,
                .io = cfg.io,
                .translator = cfg.translator,
                .init_cache = cfg.init_cache,
            };
            const options: qmdb.InitOptions = .{
                .max_size = max_size,
                .replay_from_floor = true,
                .pruned_bits = pruned_chunks * chunk_bits,
                .minimum_size = canonical.pair_absorption_threshold(F, N, pruned_chunks) orelse 0,
            };
            var any_db = try Any.init_with(gpa, storage, scope.child("any"), any_cfg, options);
            errdefer any_db.deinit();
            try prune_any_bitmap(&any_db, pruned_chunks);
            var db = try finish_init(gpa, scope, any_db, metadata, pinned);
            db.metrics.io = cfg.io;
            return db;
        }

        /// Builds the database over `log`, an authenticated log state sync filled from its
        /// Merkle pruning boundary (commonware's current `build_db`): the `any` database is
        /// rebuilt from the last commit's floor, its bitmap pruned to the chunks wholly below
        /// the boundary, and the grafted tree rebuilt with pins read from the ops tree (a
        /// pruned chunk is all zeros, so its grafted digest is the ops subtree root). The
        /// grafted metadata partition is overwritten at the next `sync`. Takes ownership of
        /// `log`, also on error. The boundary must not exceed the source's sync boundary.
        pub fn init_from_sync(
            gpa: Allocator,
            storage: Storage,
            scope: Scope,
            cfg: Cfg,
            log: Any.Log,
        ) !Self {
            var owned_log = log;
            const pruned_chunks = owned_log.merkle.bounds().start / chunk_bits;
            const partition = cfg.grafted_metadata_partition;
            var metadata = open_metadata(gpa, storage, partition) catch |err| {
                owned_log.deinit();
                return err;
            };
            errdefer metadata.deinit();
            const any_scope = scope.child("any");
            const translator = cfg.translator;
            const cache = cfg.init_cache;
            var any_db = try Any.init_from_log(gpa, any_scope, owned_log, translator, cache);
            errdefer any_db.deinit();
            any_db.metrics.io = cfg.io;
            try prune_any_bitmap(&any_db, pruned_chunks);
            var pins: [merkle.max_pinned_nodes]Digest = undefined;
            const pinned = try ops_pins(&any_db, pruned_chunks, &pins);
            assert(any_db.bitmap.pruned_chunks() == pruned_chunks);
            var db = try finish_init(gpa, scope, any_db, metadata, pinned);
            db.metrics.io = cfg.io;
            return db;
        }

        /// The grafted tree's pins at `pruned_chunks` leaves, read from the ops tree.
        fn ops_pins(
            any_db: *Any,
            pruned_chunks: u64,
            out: *[merkle.max_pinned_nodes]Digest,
        ) ![]const Digest {
            var positions: [merkle.max_pinned_nodes]u64 = undefined;
            const pinned = merkle.nodes_to_pin(F, pruned_chunks, &positions);
            const height = grafting.height(N);
            for (pinned, out[0..pinned.len]) |grafted_pos, *digest| {
                const ops_pos = grafting.grafted_to_ops_pos(F, grafted_pos, height);
                digest.* = try any_db.log.merkle.get_node(ops_pos) orelse
                    return error.DataCorrupted; // A missing ops pinned node.
            }
            assert(pinned.len <= out.len);
            return out[0..pinned.len];
        }

        /// Clears the grafted metadata `cfg` names when it records pruned chunks: they describe
        /// the operations of a Merkle structure being discarded (sync's `discard_local_state`).
        pub fn discard_grafted_metadata(gpa: Allocator, storage: Storage, cfg: Cfg) !void {
            var metadata = try open_metadata(gpa, storage, cfg.grafted_metadata_partition);
            defer metadata.deinit();
            if (try read_pruned_chunks(&metadata) == 0) return;
            metadata.clear();
            try metadata.sync();
            assert(metadata.count() == 0);
        }

        /// Prunes the freshly opened `any` bitmap to the persisted `pruned_chunks`, checking
        /// that the selected commit is still reconstructible (commonware's checks in
        /// `init_with_bitmap`).
        fn prune_any_bitmap(any_db: *Any, pruned_chunks: u64) !void {
            const pruned_bits = pruned_chunks * chunk_bits;
            const size = any_db.log.size();
            if (size < pruned_bits) return error.HistoricalFloorPruned;
            if (any_db.inactivity_floor_loc < pruned_bits) return error.HistoricalFloorPruned;
            if (canonical.pair_absorption_threshold(F, N, pruned_chunks)) |minimum| {
                if (size < minimum) return error.HistoricalFloorPruned;
            }
            // The log is pruned after the metadata, never past it.
            if (any_db.bitmap.pruned_chunks() > pruned_chunks) return error.DataCorrupted;
            any_db.bitmap.prune_to_bit(pruned_bits);
            assert(any_db.bitmap.pruned_chunks() == pruned_chunks);
            assert(any_db.bitmap.len() == size);
        }

        /// Rebuilds the grafted tree, graft roots, and witness over the opened `any_db`.
        fn finish_init(
            gpa: Allocator,
            scope: Scope,
            any_db: Any,
            metadata: Metadata,
            pinned: []const Digest,
        ) !Self {
            var self: Self = .{
                .gpa = gpa,
                .any = any_db,
                .grafted_tree = .empty,
                .graft_roots = .{},
                .metadata = metadata,
                .root_digest = undefined,
                .ops_root_witness = undefined,
                .metrics = undefined,
            };
            errdefer {
                self.grafted_tree.deinit(gpa);
                self.graft_roots.deinit(gpa);
            }
            const ops_leaves = self.any.log.size();
            const bitmap = &self.any.bitmap;
            const ops = &self.any.log.merkle;
            const build = canonical.build_grafted_tree;
            self.grafted_tree, self.graft_roots =
                try build(F, H, N, gpa, bitmap, pinned, ops, ops_leaves);
            self.graft_roots.release_below_floor(N, self.any.inactivity_floor_loc);
            const storage = self.grafted_storage();
            const floor = self.any.inactivity_floor_loc;
            const witness_of = canonical.compute_ops_root_witness;
            self.ops_root_witness = try witness_of(F, H, N, bitmap, &storage, ops_leaves, floor);
            self.root_digest = self.ops_root_witness.root(H, &self.any.root());
            self.metrics = try Metrics.init(scope);
            self.update_metrics();
            assert(self.grafted_tree.leaves() <= self.any.bitmap.complete_chunks());
            return self;
        }

        /// Closes the database without syncing.
        pub fn deinit(self: *Self) void {
            self.any.deinit();
            self.grafted_tree.deinit(self.gpa);
            self.graft_roots.deinit(self.gpa);
            self.metadata.deinit();
            self.metrics.deinit();
            self.* = undefined;
        }

        fn open_metadata(gpa: Allocator, storage: Storage, partition: []const u8) !Metadata {
            return Metadata.init(gpa, storage, .{
                .partition = partition,
                .codec_config = .{ .range = .full(), .item = {} },
            });
        }

        fn read_pruned_chunks(metadata: *const Metadata) !u64 {
            const bytes = metadata.get(MetadataKey.init(pruned_chunks_prefix, 0)) orelse
                return 0;
            if (bytes.len != 8) return error.DataCorrupted; // Not a u64.
            const pruned = std.mem.readInt(u64, bytes.*[0..8], .big);
            if (!merkle.location_is_valid(F, pruned)) return error.DataCorrupted;
            return pruned;
        }

        /// The grafted tree's pinned nodes of `pruned_chunks` leaves, from metadata.
        fn read_pins(
            metadata: *const Metadata,
            pruned_chunks: u64,
            out: *[merkle.max_pinned_nodes]Digest,
        ) ![]const Digest {
            var positions: [merkle.max_pinned_nodes]u64 = undefined;
            const pinned = merkle.nodes_to_pin(F, pruned_chunks, &positions);
            for (out[0..pinned.len], 0..) |*digest, index| {
                const key = MetadataKey.init(node_prefix, index);
                const bytes = metadata.get(key) orelse return error.DataCorrupted;
                if (bytes.len != Digest.fixed_size) return error.DataCorrupted;
                digest.* = codec.decode_fixed(Digest, bytes.*[0..Digest.fixed_size]) catch
                    return error.DataCorrupted;
            }
            assert(pinned.len <= out.len);
            return out[0..pinned.len];
        }

        /// The grafted view of the ops tree: grafted nodes at and above the grafting height.
        pub fn grafted_storage(self: *Self) GraftedStorage {
            const height = grafting.height(N);
            assert(self.grafted_tree.leaves() <= self.any.bitmap.complete_chunks());
            return .{
                .grafted = &self.grafted_tree,
                .ops = &self.any.log.merkle,
                .grafting_height = height,
            };
        }

        /// The canonical root: the ops root bound to the activity bitmap.
        pub fn root(self: *const Self) Digest {
            return self.root_digest;
        }

        /// The ops root (the sync target).
        pub fn ops_root(self: *const Self) Digest {
            return self.any.root();
        }

        pub fn inactivity_floor(self: *const Self) u64 {
            return self.any.inactivity_floor();
        }

        pub fn is_empty(self: *const Self) bool {
            return self.any.is_empty();
        }

        pub fn bounds(self: *const Self) merkle.Range {
            return self.any.bounds();
        }

        pub fn get(self: *const Self, key: *const Key) !?Value {
            return self.any.get(key);
        }

        pub fn get_many(self: *const Self, keys: []const Key, out: []?Value) !void {
            return self.any.get_many(keys, out);
        }

        pub fn get_metadata(self: *const Self) !?Value {
            return self.any.get_metadata();
        }

        /// The highest location a sync or prune may start from: the floor's chunk boundary,
        /// lowered until the youngest pruned chunk is settled and absorbed.
        pub fn sync_boundary(self: *const Self) u64 {
            const floor_chunks = self.any.inactivity_floor_loc / chunk_bits;
            return canonical.sync_boundary(F, N, floor_chunks, self.any.log.size());
        }

        fn update_metrics(self: *Self) void {
            const pruned: u64 = self.any.bitmap.pruned_chunks();
            self.metrics.update(pruned, self.sync_boundary());
        }

        /// An ops-tree proof of up to `max_ops` operations from `start` against the ops root
        /// with `historical_size` operations, for state sync.
        pub fn ops_historical_proof(
            self: *Self,
            historical_size: u64,
            start: u64,
            max_ops: u64,
        ) !Any.ProofOps {
            return self.any.historical_proof(historical_size, start, max_ops);
        }

        /// The ops-tree pins of a lower boundary at `location`.
        pub fn ops_pinned_nodes_at(
            self: *Self,
            location: u64,
            out: *[merkle.max_pinned_nodes]Digest,
        ) ![]Digest {
            return self.any.pinned_nodes_at(location, out);
        }

        /// The proof that the operation at `location` is part of the database, with its
        /// activity chunk. Fails with `OperationPruned` if its chunk is pruned.
        pub fn operation_proof(self: *Self, location: u64) !OperationProof {
            const chunk_index = location / chunk_bits;
            if (chunk_index < self.any.bitmap.pruned_chunks()) return error.OperationPruned;
            const range: merkle.Range = .{ .start = location, .end = location + 1 };
            const range_proof_value = try self.build_range_proof(range);
            assert(chunk_index < self.any.bitmap.chunks_len());
            return .{
                .loc = location,
                .chunk = self.any.bitmap.get_chunk(@intCast(chunk_index)),
                .range_proof = range_proof_value,
            };
        }

        fn build_range_proof(self: *Self, range: merkle.Range) !RangeProof {
            const storage = self.grafted_storage();
            const floor = self.any.inactivity_floor_loc;
            const ops_root_value = self.any.root();
            const build = grafted_mod.build_range_proof;
            const bitmap = &self.any.bitmap;
            return build(F, H, N, self.gpa, bitmap, &storage, floor, range, ops_root_value);
        }

        /// A range proof with the operations and activity chunks it covers (`deinit` frees
        /// all three).
        pub const Ranged = struct {
            proof: RangeProof,
            operations: []Operation,
            chunks: [][N]u8,

            pub fn deinit(self: *Ranged, gpa: Allocator) void {
                self.proof.deinit(gpa);
                codec.free_items(Operation, gpa, self.operations);
                gpa.free(self.operations);
                gpa.free(self.chunks);
                self.* = undefined;
            }
        };

        /// A proof of up to `max_ops` operations from `start` against the canonical root, with
        /// the operations and the activity chunks verification needs. Fails with
        /// `OperationPruned` if `start`'s chunk is pruned.
        pub fn range_proof(self: *Self, start: u64, max_ops: u64) !Ranged {
            assert(max_ops > 0);
            const leaves = self.any.bitmap.len();
            if (start >= leaves) return error.RangeOutOfBounds;
            if (start / chunk_bits < self.any.bitmap.pruned_chunks()) return error.OperationPruned;
            const end = @min(start +| max_ops, leaves);
            var proof = try self.build_range_proof(.{ .start = start, .end = end });
            errdefer proof.deinit(self.gpa);
            const operations = try self.gpa.alloc(Operation, @intCast(end - start));
            errdefer self.gpa.free(operations);
            var read: usize = 0;
            errdefer codec.free_items(Operation, self.gpa, operations[0..read]);
            for (operations, start..) |*operation, location| {
                operation.* = try self.any.log.read(location);
                read += 1;
            }
            assert(read == operations.len);
            const first_chunk = start / chunk_bits;
            const last_chunk = (end - 1) / chunk_bits;
            const chunks = try self.gpa.alloc([N]u8, @intCast(last_chunk - first_chunk + 1));
            for (chunks, first_chunk..) |*chunk, index| {
                chunk.* = self.any.bitmap.get_chunk(@intCast(index));
            }
            assert(operations.len > 0 and chunks.len > 0);
            return .{ .proof = proof, .operations = operations, .chunks = chunks };
        }

        /// A key's current value and the proof of it against the canonical root.
        pub const ProvedValue = struct {
            proof: KeyValueProof,
            value: Value,

            pub fn deinit(self: *ProvedValue, gpa: Allocator) void {
                self.proof.deinit(gpa);
                codec.free(Value, gpa, self.value);
                self.* = undefined;
            }
        };

        /// The proof of `key`'s current value. Fails with `KeyNotFound` if it has none.
        pub fn key_value_proof(self: *Self, key: *const Key) !ProvedValue {
            var located = try self.any.get_with_loc(key) orelse return error.KeyNotFound;
            errdefer located.update.deinit(self.gpa);
            assert(value_mod.eql(Key, located.update.key, key.*));
            const proof = try self.operation_proof(located.location);
            assert(proof.loc == located.location);
            const kv: KeyValueProof = if (comptime U.siblings)
                .{ .proof = proof, .next_key = located.update.next_key }
            else
                .{ .proof = proof };
            return .{ .proof = kv, .value = located.update.value };
        }

        /// The proof that `key` is absent (ordered databases): the active update whose span
        /// covers it, or an empty database's last commit. Fails with `KeyExists` if `key` is
        /// active.
        pub fn exclusion_proof(self: *Self, key: *const Key) !ExclusionProof {
            comptime assert(U.siblings);
            if (try self.any.get_span(key)) |located| {
                var span = located;
                errdefer span.update.deinit(self.gpa);
                if (value_mod.eql(Key, span.update.key, key.*)) return error.KeyExists;
                const proof = try self.operation_proof(span.location);
                return .{ .key_value = .{ .proof = proof, .update = span.update } };
            }
            const last = self.any.log.size() - 1;
            var op = try self.any.log.read(last);
            errdefer op.deinit(self.gpa);
            if (op != .commit) return error.DataCorrupted; // The log ends with a commit.
            // An empty database's last commit raised its floor to itself.
            if (op.commit.floor != last) return error.DataCorrupted;
            const proof = try self.operation_proof(last);
            assert(proof.loc == last);
            return .{ .commit = .{ .proof = proof, .value = op.commit.metadata } };
        }

        /// Whether `proof` shows `key` absent from a database with canonical `root`.
        pub fn verify_exclusion_proof(
            proof: *const ExclusionProof,
            key: Key,
            root_value: *const Digest,
        ) bool {
            comptime assert(U.siblings);
            return proof.verify(H, key, root_value);
        }

        /// `verify_exclusion_proof` for values that own memory, encoding with `gpa`.
        pub fn verify_exclusion_proof_alloc(
            gpa: Allocator,
            proof: *const ExclusionProof,
            key: Key,
            root_value: *const Digest,
        ) Allocator.Error!bool {
            comptime assert(U.siblings);
            const verify = ordered_proof.verify_exclusion;
            return verify(F, H, ExclusionProof, proof, gpa, key, root_value);
        }

        /// The active key after `key` (not wrapping), as in `any`.
        pub fn get_next_key(self: *const Self, key: *const Key) !?Key {
            return self.any.get_next_key(key);
        }

        /// The active key before `key` (not wrapping), as in `any`.
        pub fn get_prev_key(self: *const Self, key: *const Key) !?Key {
            return self.any.get_prev_key(key);
        }

        /// The active update whose span covers `key`, and its location, as in `any`.
        pub fn get_span(self: *const Self, key: *const Key) !?Any.Located {
            return self.any.get_span(key);
        }

        /// Whether `proof` shows `key` holds `value` in a database with canonical `root`.
        pub fn verify_key_value_proof(
            proof: *const KeyValueProof,
            key: Key,
            value: Value,
            root_value: *const Digest,
        ) bool {
            return proof.verify(H, U, key, value, root_value);
        }

        /// `verify_key_value_proof` for values that own memory, encoding with `gpa`.
        pub fn verify_key_value_proof_alloc(
            gpa: Allocator,
            proof: *const KeyValueProof,
            key: Key,
            value: Value,
            root_value: *const Digest,
        ) Allocator.Error!bool {
            if (comptime !U.siblings) return proof.verify_alloc(gpa, H, U, key, value, root_value);
            const update: U = .{ .key = key, .value = value, .next_key = proof.next_key };
            return ordered_proof.verify_update(F, H, U, gpa, &proof.proof, update, root_value);
        }

        /// Prunes operations below `location`, which may not exceed the sync boundary. Commits
        /// the log, prunes the bitmap and grafted tree to `location`'s chunk, persists them in
        /// metadata, then prunes the log (so a crash leaves the metadata ahead of the log,
        /// never behind it).
        pub fn prune(self: *Self, location: u64) !void {
            self.metrics.prune_calls.metric().inc();
            const timing = self.metrics.start("prune_duration");
            defer timing.finish();
            if (location > self.sync_boundary()) return error.PruneBeyondMinRequired;
            try self.any.commit();
            self.any.prune_bitmap(location);
            try self.prune_grafted_tree();
            try self.sync_metadata();
            try self.any.prune_log(location);
            self.any.update_metrics();
            self.update_metrics();
            assert(self.grafted_tree.pruning_boundary() <= self.any.bitmap.pruned_chunks());
        }

        /// Prunes the grafted tree to the bitmap's pruned chunks.
        fn prune_grafted_tree(self: *Self) !void {
            const pruned: u64 = self.any.bitmap.pruned_chunks();
            if (pruned <= self.grafted_tree.pruning_boundary()) return;
            assert(pruned <= self.grafted_tree.leaves());
            try self.grafted_tree.prune(pruned);
            assert(self.grafted_tree.pruning_boundary() == pruned);
        }

        /// Persists the bitmap's pruned chunks and the grafted tree's pins.
        fn sync_metadata(self: *Self) !void {
            self.metadata.clear();
            const pruned: u64 = self.any.bitmap.pruned_chunks();
            var count: [8]u8 = undefined;
            std.mem.writeInt(u64, &count, pruned, .big);
            try self.put_metadata(MetadataKey.init(pruned_chunks_prefix, 0), &count);
            var pins: [merkle.max_pinned_nodes]Digest = undefined;
            const digests = self.grafted_tree.node_digests_to_pin(pruned, &pins);
            for (digests, 0..) |*digest, index| {
                var bytes: [Digest.fixed_size]u8 = undefined;
                _ = codec.encode_to(Digest, digest.*, &bytes);
                try self.put_metadata(MetadataKey.init(node_prefix, index), &bytes);
            }
            try self.metadata.sync();
            assert(self.metadata.count() == digests.len + 1);
        }

        fn put_metadata(self: *Self, key: MetadataKey, bytes: []const u8) !void {
            const owned = try self.gpa.dupe(u8, bytes);
            const previous = self.metadata.put(key, owned) catch |err| {
                self.gpa.free(owned);
                return err;
            };
            assert(previous == null); // The metadata was cleared.
        }

        /// Makes applied operations durable (not the bitmap's pruning metadata).
        pub fn commit(self: *Self) !void {
            try self.any.commit();
        }

        /// Starts a sync of applied operations (it completes at once here).
        pub fn start_sync(self: *Self) !void {
            try self.any.start_sync();
        }

        /// Syncs every database state to disk, including the bitmap's pruning metadata.
        pub fn sync(self: *Self) !void {
            self.metrics.sync_calls.metric().inc();
            const timing = self.metrics.start("sync_duration");
            defer timing.finish();
            try self.any.sync();
            try self.sync_metadata();
            self.update_metrics();
        }

        /// Removes the database's storage and frees it, also on error. The log goes first: an
        /// interrupted destroy needs the metadata to reopen an old log.
        pub fn destroy(self: *Self) !void {
            const gpa = self.gpa;
            defer self.* = undefined;
            self.grafted_tree.deinit(gpa);
            self.graft_roots.deinit(gpa);
            self.metrics.deinit();
            self.any.destroy() catch |err| {
                self.metadata.deinit();
                return err;
            };
            try self.metadata.destroy();
        }

        pub fn validate_batch(self: *const Self, batch: *const MerkleizedBatch) !void {
            try self.any.validate_batch(batch.inner);
        }

        /// Applies `batch` and its unapplied ancestors; the caller keeps its reference.
        pub fn apply_batch(self: *Self, batch: *const MerkleizedBatch) !void {
            self.metrics.apply_batch_calls.metric().inc();
            const timing = self.metrics.start("apply_batch_duration");
            defer timing.finish();
            try self.any.apply_batch(batch.inner);
            // Retain the newly graftable roots, then release those wholly below the floor.
            const leaves = batch.grafted.leaves();
            try self.graft_roots.extend_to(self.gpa, F, N, leaves, &self.any.log.merkle);
            self.graft_roots.release_below_floor(N, self.any.inactivity_floor_loc);
            try self.grafted_tree.apply_batch(self.gpa, batch.grafted);
            self.root_digest = batch.canonical_root;
            self.ops_root_witness = batch.ops_root_witness;
            if (batch.layer) |layer| {
                batch_mod.trim(N, self.gpa, &layer.parent, self.any.bitmap.len());
            }
            self.update_metrics();
            assert(self.grafted_tree.leaves() == leaves);
        }

        /// A batch on the database's current state.
        pub fn new_batch(self: *const Self) !UnmerkleizedBatch {
            const grafted = try GraftedBatch.from_mem(self.gpa, &self.grafted_tree);
            errdefer grafted.release(self.gpa);
            return .{
                .gpa = self.gpa,
                .inner = try self.any.new_batch(),
                .grafted_parent = grafted,
                .bitmap_parent = null,
            };
        }

        /// A merkleized batch representing the current state.
        pub fn to_batch(self: *const Self) !*MerkleizedBatch {
            return MerkleizedBatch.from_db(self);
        }
    };
}

/// The `current`-specific metrics (commonware's `current::db::Metrics`); the `any` database
/// registers its own under the `any` child scope.
pub const Metrics = struct {
    const metrics_api = runtime.telemetry.metrics;

    pruned_chunks: metrics_api.Gauge,
    sync_boundary: metrics_api.Gauge,
    apply_batch_calls: metrics_api.Counter,
    apply_batch_duration: Timed,
    sync_calls: metrics_api.Counter,
    sync_duration: Timed,
    prune_calls: metrics_api.Counter,
    prune_duration: Timed,
    /// The clock of the duration timers; null skips timing. The database sets it.
    io: ?std.Io = null,

    const Timed = metrics_api.histogram.Timed;

    pub fn init(scope: Scope) Allocator.Error!Metrics {
        var self: Metrics = undefined;
        self.pruned_chunks = try scope.gauge("pruned_chunks", "Number of pruned bitmap chunks");
        errdefer self.pruned_chunks.deinit();
        const help = "Most recent safe sync boundary location";
        self.sync_boundary = try scope.gauge("sync_boundary", help);
        errdefer self.sync_boundary.deinit();
        const apply_help = "Number of apply-batch calls";
        self.apply_batch_calls = try scope.counter("apply_batch_calls", apply_help);
        errdefer self.apply_batch_calls.deinit();
        self.sync_calls = try scope.counter("sync_calls", "Number of sync calls");
        errdefer self.sync_calls.deinit();
        self.prune_calls = try scope.counter("prune_calls", "Number of prune calls");
        errdefer self.prune_calls.deinit();
        const apply_duration = "Duration of apply-batch calls";
        const apply_name = "apply_batch_duration";
        self.apply_batch_duration = try Timed.register(&scope, apply_name, apply_duration);
        errdefer self.apply_batch_duration.deinit();
        self.sync_duration = try Timed.register(&scope, "sync_duration", "Duration of sync calls");
        errdefer self.sync_duration.deinit();
        const prune_help = "Duration of prune calls";
        self.prune_duration = try Timed.register(&scope, "prune_duration", prune_help);
        self.io = null;
        return self;
    }

    /// Starts timing a call into the duration histogram `name`, if the database has a clock.
    pub fn start(self: *const Metrics, comptime name: []const u8) metrics_mod.Timing {
        return .start(&@field(self, name), self.io);
    }

    pub fn deinit(self: *Metrics) void {
        self.pruned_chunks.deinit();
        self.sync_boundary.deinit();
        self.apply_batch_calls.deinit();
        self.sync_calls.deinit();
        self.prune_calls.deinit();
        self.apply_batch_duration.deinit();
        self.sync_duration.deinit();
        self.prune_duration.deinit();
        self.* = undefined;
    }

    /// Values above i64's range leave a gauge unchanged, as commonware's `try_set` does.
    pub fn update(self: *Metrics, pruned_chunks: u64, sync_boundary: u64) void {
        _ = self.pruned_chunks.metric().try_set(pruned_chunks) catch {};
        _ = self.sync_boundary.metric().try_set(sync_boundary) catch {};
    }
};
