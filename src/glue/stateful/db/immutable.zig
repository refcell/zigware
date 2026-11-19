//! The ManagedDb implementation for QMDB `immutable` databases (commonware
//! `glue/src/stateful/db/immutable/standard.rs`).
//!
//! Immutable databases accept new keyed values but no updates or deletions. Batch reads
//! consult the database at the time of the read for keys their batch chain does not write,
//! and fail with `error.StaleRead` once the database is at no state of that chain. One adapter
//! covers commonware's fixed and variable databases: `E` is the value encoding
//! (`qmdb.value.Fixed` or `qmdb.value.Variable`) and `C` the matching contiguous journal of
//! `qmdb.immutable.Operation(F, K, E)`; `T` is the key index's translator.

const std = @import("std");
const runtime = @import("runtime");
const assert = std.debug.assert;
const storage = @import("storage");
const db = @import("mod.zig");
const state_sync = @import("state_sync.zig");

const qmdb = storage.qmdb;

/// A `storage.qmdb.immutable.Db(F, K, E, C, H, T)` managed by `Stateful`.
pub fn Immutable(F: type, K: type, E: type, C: type, H: type, T: type) type {
    const D = qmdb.immutable.Db(F, K, E, C, H, T);
    comptime assert(H.Digest == D.Digest);
    return struct {
        const Self = @This();
        pub const Database = D;
        pub const Family = F;
        pub const Key = K;
        pub const Encoding = E;
        pub const Value = D.Value;
        pub const Digest = D.Digest;
        pub const Config = D.Cfg;
        /// The database's root and the operation range `[sync_boundary, size)` needed to reach
        /// it.
        pub const SyncTarget = qmdb.sync.Target(F, D.Digest);
        pub const Shared = db.Shared(Self);
        /// qmdb keyless/immutable reads, batch reads, and merkleize take `*const` and are safe
        /// from several tasks at once, so `Shared` read guards share the database.
        pub const concurrent_reads = true;

        inner: D,

        pub fn init(env: anytype, config: Config, expected: ?SyncTarget) !Self {
            const max_size: ?u64 = if (expected) |target| target.end else null;
            var self: Self = .{
                .inner = try D.init(env.gpa, env.storage, env.scope, config, max_size),
            };
            errdefer self.inner.deinit();
            try db.validate_initialization(Self, &self, expected);
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit();
            self.* = undefined;
        }

        pub fn initial_sync_target() SyncTarget {
            return .init(qmdb.immutable.initial_root(F, K, E, H), 0, 1);
        }

        pub fn new_batch(context: db.BatchContext(Self)) !Unmerkleized {
            return .{ .batch = try context.database.inner.new_batch(), .db = context.shared };
        }

        pub fn matches_sync_target(batch: *const Merkleized, target: *const SyncTarget) bool {
            return batch.inner.target().eql(target.*);
        }

        /// Applies `batch` and its unapplied ancestors; durability starts with `finalize`.
        pub fn apply(self: *Self, batch: *const Merkleized) !void {
            try self.inner.apply_batch(batch.inner);
        }

        /// Starts persisting the applied state; the completion finishes once it is durable.
        pub fn finalize(self: *Self) !runtime.storage.Completion {
            return self.inner.start_sync();
        }

        pub fn prune(self: *Self, target: *const SyncTarget) !void {
            try self.inner.prune(target.start);
        }

        pub fn sync_target(self: *const Self) SyncTarget {
            return .init(self.inner.root(), self.inner.sync_boundary(), self.inner.bounds().end);
        }

        /// The database's `qmdb.sync` interface.
        pub const SyncDatabase = qmdb.immutable.sync.Database(F, K, E, C, H, T);

        /// Serves peers' sync requests from this database (commonware's `Source` for the
        /// locked database, which `state_sync.SharedSource` takes under the lock).
        pub const SyncSource = qmdb.sync.JournalSource(F, D.Journal);

        pub fn sync_source(self: *const Self) SyncSource {
            return .{ .journal = &self.inner.journal };
        }

        /// Syncs a new database from `source` (the StateSyncDb contract, `state_sync.zig`).
        pub fn sync_db(
            env: anytype,
            config: Config,
            source: anytype,
            target: SyncTarget,
            channels: state_sync.Channels(SyncTarget),
            sync_config: state_sync.SyncEngineConfig,
        ) !Self {
            const synced = try state_sync.sync_standard_db(
                SyncDatabase,
                env,
                config,
                source,
                target,
                channels,
                sync_config,
            );
            return .{ .inner = synced.db };
        }

        /// A speculative batch of new keyed values over the shared database.
        pub const Unmerkleized = struct {
            batch: D.UnmerkleizedBatch,
            db: Shared,

            pub fn deinit(self: *Unmerkleized) void {
                self.batch.deinit();
                self.* = undefined;
            }

            /// Sets the metadata committed by `merkleize`; null clears it. The batch owns it.
            pub fn with_metadata(self: *Unmerkleized, metadata: ?Value) void {
                self.batch.with_metadata(metadata);
            }

            /// Sets the inactivity floor committed by `merkleize` (inherited from the database
            /// or parent batch when unset).
            pub fn with_inactivity_floor(self: *Unmerkleized, floor: u64) void {
                self.batch.with_inactivity_floor(floor);
            }

            /// Sets `key` to `value`, which the batch then owns.
            pub fn set(self: *Unmerkleized, key: Key, value: Value) !void {
                try self.batch.set(key, value);
            }

            /// Reads a value by key, falling back to applied state. The caller owns it.
            pub fn get(self: *const Unmerkleized, key: *const Key) !?Value {
                var guard = try self.db.read();
                defer guard.deinit();
                return self.batch.get(key, &guard.get().inner);
            }

            /// Reads `keys` into `out`, in order; the caller owns them.
            pub fn get_many(self: *const Unmerkleized, keys: []const Key, out: []?Value) !void {
                assert(keys.len == out.len);
                var guard = try self.db.read();
                defer guard.deinit();
                try self.batch.get_many(keys, &guard.get().inner, out);
            }

            /// Seals the batch. Consumes it on success; on error only `deinit` may follow.
            pub fn merkleize(self: *Unmerkleized) !Merkleized {
                var guard = try self.db.read();
                defer guard.deinit();
                const inner = try self.batch.merkleize(&guard.get().inner);
                return .{ .inner = inner, .db = self.db };
            }
        };

        /// A sealed batch with a computed root; `clone` shares it, `deinit` releases one share.
        pub const Merkleized = struct {
            inner: *D.MerkleizedBatch,
            db: Shared,

            pub fn clone(self: *const Merkleized) Merkleized {
                return .{ .inner = self.inner.retain(), .db = self.db };
            }

            pub fn deinit(self: *Merkleized) void {
                self.inner.release();
                self.* = undefined;
            }

            pub fn root(self: *const Merkleized) Digest {
                return self.inner.root();
            }

            /// The batch's chain bounds (commonware's `Deref` to the storage batch).
            pub fn bounds(self: *const Merkleized) D.Bounds {
                return self.inner.bounds;
            }

            /// A child batch whose reads see this batch's sets before the applied state.
            pub fn new_batch(self: *const Merkleized) !Unmerkleized {
                return .{ .batch = self.inner.new_batch(), .db = self.db };
            }

            /// Reads a value by key, falling back to applied state. The caller owns it.
            pub fn get(self: *const Merkleized, key: *const Key) !?Value {
                var guard = try self.db.read();
                defer guard.deinit();
                return self.inner.get(key, &guard.get().inner);
            }

            /// Reads `keys` into `out`, in order; the caller owns them.
            pub fn get_many(self: *const Merkleized, keys: []const Key, out: []?Value) !void {
                assert(keys.len == out.len);
                var guard = try self.db.read();
                defer guard.deinit();
                try self.inner.get_many(keys, &guard.get().inner, out);
            }
        };
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("immutable_test.zig");
}
