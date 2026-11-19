//! The ManagedDb implementation for QMDB `keyless` databases (commonware
//! `glue/src/stateful/db/keyless/standard.rs`).
//!
//! Keyless databases are append-only: operations are addressed by location rather than by key.
//! Batch reads consult the database at the time of the read for locations their batch chain
//! does not hold, and fail with `error.StaleRead` once the database is at no state of that
//! chain. One adapter covers commonware's fixed and variable databases: `E` is the value
//! encoding (`qmdb.value.Fixed` or `qmdb.value.Variable`) and `C` the matching contiguous
//! journal of `qmdb.keyless.Operation(F, E)`.

const std = @import("std");
const assert = std.debug.assert;
const storage = @import("storage");
const db = @import("mod.zig");
const state_sync = @import("state_sync.zig");

const qmdb = storage.qmdb;

/// A `storage.qmdb.keyless.Db(F, E, C, H)` managed by `Stateful`.
pub fn Keyless(comptime F: type, comptime E: type, comptime C: type, comptime H: type) type {
    const D = qmdb.keyless.Db(F, E, C, H);
    comptime assert(H.Digest == D.Digest);
    return struct {
        const Self = @This();
        pub const Database = D;
        pub const Family = F;
        pub const Encoding = E;
        pub const Value = D.Value;
        pub const Digest = D.Digest;
        pub const Config = D.Cfg;
        /// The database's root and the operation range `[sync_boundary, size)` needed to reach
        /// it.
        pub const SyncTarget = qmdb.sync.Target(F, D.Digest);
        pub const Shared = db.Shared(Self);

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
            return .init(qmdb.keyless.initial_root(F, E, H), 0, 1);
        }

        pub fn new_batch(context: db.BatchContext(Self)) !Unmerkleized {
            return .{ .batch = try context.database.inner.new_batch(), .db = context.shared };
        }

        pub fn matches_sync_target(batch: *const Merkleized, target: *const SyncTarget) bool {
            const bounds = &batch.inner.bounds;
            return batch.root().eql(target.root) and
                target.start == bounds.inactivity_floor and
                target.end == bounds.tip.size;
        }

        /// Applies `batch` and its unapplied ancestors; durability starts with `finalize`.
        pub fn apply(self: *Self, batch: *const Merkleized) !void {
            try self.inner.apply_batch(batch.inner);
        }

        pub fn finalize(self: *Self) !void {
            try self.inner.start_sync();
        }

        pub fn prune(self: *Self, target: *const SyncTarget) !void {
            try self.inner.prune(target.start);
        }

        pub fn sync_target(self: *const Self) SyncTarget {
            return .init(self.inner.root(), self.inner.sync_boundary(), self.inner.bounds().end);
        }

        /// The database's `qmdb.sync` interface.
        pub const SyncDatabase = qmdb.keyless.sync.Database(F, E, C, H);

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

        /// A speculative batch of appended values over the shared database.
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

            /// Appends `value`, which the batch then owns.
            pub fn append(self: *Unmerkleized, value: Value) !void {
                try self.batch.append(value);
            }

            /// Reads a value by location, falling back to applied state. The caller owns it.
            /// Fails with `StaleRead`, `LocationOutOfBounds`, or `BelowInactivityFloor`.
            pub fn get(self: *const Unmerkleized, location: u64) !?Value {
                var guard = try self.db.read();
                defer guard.deinit();
                return self.batch.get(location, &guard.get().inner);
            }

            /// Reads strictly increasing `locations` into `out`, in order; the caller owns
            /// them. Also fails with `LocationOutOfOrder`.
            pub fn get_many(
                self: *const Unmerkleized,
                locations: []const u64,
                out: []?Value,
            ) !void {
                assert(locations.len == out.len);
                var guard = try self.db.read();
                defer guard.deinit();
                try self.batch.get_many(locations, &guard.get().inner, out);
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

            /// A child batch whose reads see this batch's appends before the applied state.
            pub fn new_batch(self: *const Merkleized) !Unmerkleized {
                return .{ .batch = self.inner.new_batch(), .db = self.db };
            }

            /// Reads a value by location, falling back to applied state. The caller owns it.
            pub fn get(self: *const Merkleized, location: u64) !?Value {
                var guard = try self.db.read();
                defer guard.deinit();
                return self.inner.get(location, &guard.get().inner);
            }

            /// Reads strictly increasing `locations` into `out`, in order.
            pub fn get_many(self: *const Merkleized, locations: []const u64, out: []?Value) !void {
                assert(locations.len == out.len);
                var guard = try self.db.read();
                defer guard.deinit();
                try self.inner.get_many(locations, &guard.get().inner, out);
            }
        };
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("keyless_test.zig");
}
