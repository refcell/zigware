//! The ManagedDb implementation for QMDB `compact` databases (commonware
//! `glue/src/stateful/db/compact.rs`, with `keyless/compact.rs` and `immutable/compact.rs`).
//!
//! Compact databases retain only the current Merkle peaks. Batches support merkleization but
//! no historical reads. Keyless batches add operations with `append` and immutable batches
//! with `set` (commonware adds each in its own module; here `O` decides which one compiles).

const std = @import("std");
const runtime = @import("runtime");
const assert = std.debug.assert;
const storage = @import("storage");
const db = @import("mod.zig");
const state_sync = @import("state_sync.zig");

const qmdb = storage.qmdb;

/// A `storage.qmdb.compact.Db(F, O, H)` managed by `Stateful`; `O` is a keyless or immutable
/// operation (see `qmdb.compact.Keyless` and `qmdb.compact.Immutable`).
pub fn Compact(comptime F: type, comptime O: type, comptime H: type) type {
    const D = qmdb.compact.Db(F, O, H);
    comptime assert(H.Digest == D.Digest);
    return struct {
        const Self = @This();
        pub const Database = D;
        pub const Family = F;
        pub const Operation = O;
        pub const Value = D.Value;
        pub const Digest = D.Digest;
        pub const Config = D.Cfg;
        /// The database's root over its last commit, `[size - 1, size)`.
        pub const SyncTarget = qmdb.sync.Target(F, D.Digest);
        pub const Shared = db.Shared(Self);

        inner: D,

        pub fn init(env: anytype, config: Config, expected: ?SyncTarget) !Self {
            const max_size: ?u64 = if (expected) |target| target.end else null;
            var self: Self = .{ .inner = try D.init(env.gpa, env.storage, config, max_size) };
            errdefer self.inner.deinit();
            try db.validate_initialization(Self, &self, expected);
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit();
            self.* = undefined;
        }

        pub fn initial_sync_target() SyncTarget {
            return .init(qmdb.compact.initial_root(F, O, H), 0, 1);
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
            try self.inner.prune_to_target(target.*);
        }

        pub fn sync_target(self: *const Self) SyncTarget {
            const reached = self.inner.target();
            assert(reached.end == self.inner.size());
            return reached;
        }

        /// Serves peers' sync requests from this database's current peaks (commonware's
        /// `Source` for the locked database, which `state_sync.SharedSource` takes under the
        /// lock). Responses carry no feedback.
        pub const SyncSource = struct {
            pub const Family = F;
            pub const Op = O;
            pub const Digest = D.Digest;
            pub const Error = ServeError;
            const ServeError = @typeInfo(@typeInfo(@TypeOf(D.serve)).@"fn".return_type.?)
                .error_union.error_set;

            database: *const D,

            /// The response is allocated with the database's allocator, which must be `gpa`.
            pub fn serve(
                self: *SyncSource,
                gpa: std.mem.Allocator,
                request: D.Request,
            ) Error!qmdb.sync.Served(D.Response) {
                assert(gpa.ptr == self.database.gpa.ptr);
                const response = try self.database.serve(request);
                assert(std.mem.eql(u8, @tagName(response), @tagName(request)));
                return .{ .response = response, .feedback = null };
            }
        };

        pub fn sync_source(self: *const Self) SyncSource {
            return .{ .database = &self.inner };
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
                D,
                env,
                config,
                source,
                target,
                channels,
                sync_config,
            );
            return .{ .inner = synced };
        }

        /// A speculative batch over the shared database.
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

            /// Appends `value` (keyless operations only), which the batch then owns.
            pub fn append(self: *Unmerkleized, value: Value) !void {
                comptime assert(!D.keyed);
                try self.batch.append(value);
            }

            /// Sets `key` to `value` (immutable operations only); the batch then owns both.
            pub fn set(self: *Unmerkleized, key: O.Key, value: Value) !void {
                comptime assert(D.keyed);
                try self.batch.set(key, value);
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

            /// A child batch on top of this one.
            pub fn new_batch(self: *const Merkleized) !Unmerkleized {
                return .{ .batch = self.inner.new_batch(), .db = self.db };
            }
        };
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("compact_test.zig");
    _ = @import("compact_sync_test.zig");
}
