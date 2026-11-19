//! The ManagedDb implementation for QMDB `current` databases (commonware
//! `glue/src/stateful/db/current.rs`).
//!
//! Batch reads consult the database at the time of the read for keys their batch chain does
//! not write, and fail with `error.StaleRead` once the database is at no state of that chain.
//! A `current` database's sync target commits to its ops root, not its canonical root, over
//! `[sync_boundary, size)`.

const std = @import("std");
const assert = std.debug.assert;
const storage = @import("storage");
const db = @import("mod.zig");
const state_sync = @import("state_sync.zig");

const qmdb = storage.qmdb;

/// `D` (a `storage.qmdb.current.Db`) managed by `Stateful`.
pub fn Current(comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Database = D;
        pub const Key = D.Key;
        pub const Value = D.Value;
        pub const Digest = D.Digest;
        pub const Config = D.Cfg;
        pub const Slot = D.StagedBatch.Slot;
        pub const Mutation = D.StagedBatch.Mutation;
        pub const Range = D.StagedBatch.Range;
        /// The database's ops root and the operation range `[sync_boundary, size)` needed to
        /// reach it.
        pub const SyncTarget = qmdb.sync.Target(D.Family, D.Digest);
        pub const Shared = db.Shared(Self);
        /// qmdb any/current reads, batch reads, and merkleize take `*const` and are safe from
        /// several tasks at once, so `Shared` read guards share the database.
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

        /// The empty database's ops root over `[0, 1)`: its initial commit.
        pub fn initial_sync_target() SyncTarget {
            return .init(qmdb.any.initial_root(D.Family, D.Any.Update, D.Hasher), 0, 1);
        }

        pub fn new_batch(context: db.BatchContext(Self)) !Unmerkleized {
            return .{ .batch = try context.database.inner.new_batch(), .db = context.shared };
        }

        pub fn matches_sync_target(batch: *const Merkleized, target: *const SyncTarget) bool {
            return batch.inner.ops_root().eql(target.root) and
                target.start == batch.inner.sync_boundary() and
                target.end == batch.inner.bounds().tip.size;
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
            const end = self.inner.bounds().end;
            return .init(self.inner.ops_root(), self.inner.sync_boundary(), end);
        }

        pub const SyncDatabase = qmdb.current.sync.Database(D, D.Hasher);

        /// Syncs a new database from `source` (the StateSyncDb contract, `state_sync.zig`).
        /// The target commits to the ops root.
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

        /// Serves this database's operations to syncing peers (`state_sync.SharedSource`).
        pub const SyncSource = qmdb.sync.JournalSource(D.Family, D.Any.Log);

        pub fn sync_source(self: *Self) SyncSource {
            return .{ .journal = &self.inner.any.log };
        }

        /// A speculative batch of updates and deletes over the shared database.
        pub const Unmerkleized = struct {
            batch: D.UnmerkleizedBatch,
            db: Shared,

            pub fn deinit(self: *Unmerkleized) void {
                self.batch.deinit();
                self.* = undefined;
            }

            /// Sets the metadata committed by `merkleize`; null clears it. It carries over to
            /// a batch returned by `stage`.
            pub fn with_metadata(self: *Unmerkleized, metadata: ?Value) void {
                self.batch.with_metadata(metadata);
            }

            /// Records an upsert (a value) or a delete (null) of `key`.
            pub fn write(self: *Unmerkleized, key: Key, value: ?Value) !void {
                try self.batch.write(key, value);
            }

            /// Reads a value by key, falling back to applied state.
            pub fn get(self: *const Unmerkleized, key: *const Key) !?Value {
                var guard = try self.db.read();
                defer guard.deinit();
                return self.batch.get(key, &guard.get().inner);
            }

            /// Reads `keys` into `out`, in order.
            pub fn get_many(self: *const Unmerkleized, keys: []const Key, out: []?Value) !void {
                assert(keys.len == out.len);
                var guard = try self.db.read();
                defer guard.deinit();
                for (keys, out) |*key, *value| {
                    value.* = try self.batch.get(key, &guard.get().inner);
                }
            }

            /// Reads `keys` into `out` and stages them, one slot each. Consumes the batch on
            /// success; on error the batch is unchanged.
            pub fn stage(self: *Unmerkleized, keys: []const Key, out: []?Value) !Staged {
                assert(keys.len == out.len);
                var guard = try self.db.read();
                defer guard.deinit();
                const shared = self.db;
                const staged = try self.batch.stage(keys, &guard.get().inner, out);
                self.* = undefined;
                return .{ .staged = staged, .db = shared };
            }

            /// Seals the batch. Consumes it on success; on error only `deinit` may follow.
            pub fn merkleize(self: *Unmerkleized) !Merkleized {
                var guard = try self.db.read();
                defer guard.deinit();
                const inner = try self.batch.merkleize(&guard.get().inner);
                return .{ .inner = inner, .db = self.db };
            }
        };

        /// A batch whose reads are staged, returned by `Unmerkleized.stage`. Like any
        /// speculative batch it reads the database only while the database is at a state of
        /// its chain. `deinit` it if dropped.
        pub const Staged = struct {
            staged: D.StagedBatch,
            db: Shared,

            pub fn deinit(self: *Staged) void {
                self.staged.deinit();
                self.* = undefined;
            }

            /// Sets the metadata committed by `merkleize`, replacing any set before staging.
            pub fn with_metadata(self: *Staged, metadata: ?Value) void {
                self.staged.with_metadata(metadata);
            }

            /// The staged read slots: the keys passed to `stage` and every `expand` range.
            pub fn len(self: *const Staged) usize {
                return self.staged.len();
            }

            pub fn is_empty(self: *const Staged) bool {
                return self.staged.is_empty();
            }

            /// Reads more `keys` into `out`, appending them as the returned range of slots.
            /// Existing slots keep their positions; keys are not deduplicated against earlier
            /// slots. On error the staged set is unchanged.
            pub fn expand(self: *Staged, keys: []const Key, out: []?Value) !Range {
                assert(keys.len == out.len);
                var guard = try self.db.read();
                defer guard.deinit();
                const before = self.len();
                const range = try self.staged.expand(keys, &guard.get().inner, out);
                assert(self.len() == before + keys.len);
                return range;
            }

            /// Applies `slots` (one per staged read, in slot order) and then `unstaged` writes,
            /// and merkleizes. A key staged in several slots takes its last put or delete, and
            /// an unstaged write to a staged key wins. Consumes the staged batch, also on error.
            pub fn merkleize(
                self: *Staged,
                slots: []const Slot,
                unstaged: []const Mutation,
            ) !Merkleized {
                assert(slots.len == self.len());
                const shared = self.db;
                var guard = shared.read() catch |err| {
                    self.deinit();
                    return err;
                };
                defer guard.deinit();
                const result = self.staged.merkleize(slots, unstaged, &guard.get().inner);
                self.* = undefined; // Storage consumed the staged batch, also on error.
                return .{ .inner = try result, .db = shared };
            }
        };

        /// A sealed batch with a computed canonical root; `clone` shares it, `deinit` releases
        /// one share.
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

            /// The canonical root after this batch.
            pub fn root(self: *const Merkleized) Digest {
                return self.inner.root();
            }

            /// The ops root after this batch, which sync targets commit to.
            pub fn ops_root(self: *const Merkleized) Digest {
                return self.inner.ops_root();
            }

            /// A child batch whose reads see this batch's changes before the applied state.
            pub fn new_batch(self: *const Merkleized) !Unmerkleized {
                return .{ .batch = self.inner.new_batch(), .db = self.db };
            }

            /// Reads a value by key, falling back to applied state.
            pub fn get(self: *const Merkleized, key: *const Key) !?Value {
                var guard = try self.db.read();
                defer guard.deinit();
                return self.inner.get(key, &guard.get().inner);
            }

            pub fn get_many(self: *const Merkleized, keys: []const Key, out: []?Value) !void {
                assert(keys.len == out.len);
                var guard = try self.db.read();
                defer guard.deinit();
                for (keys, out) |*key, *value| {
                    value.* = try self.inner.get(key, &guard.get().inner);
                }
            }
        };
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("current_test.zig");
}
