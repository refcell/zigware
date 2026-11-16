//! Database batch lifecycle for `Stateful` (commonware `glue/src/stateful/db/mod.rs`).
//!
//! `db` defines the contract a storage backend implements to be driven by `Stateful` and
//! implements it for QMDB databases (`any`). A block's state changes pass through three stages:
//!
//! 1. Unmerkleized: a mutable batch (concrete types expose reads and writes).
//! 2. Merkleized: a sealed batch with a computed state root.
//! 3. Applied: `ManagedDb.apply` exposes the batch as a recoverable checkpoint. `finalize`
//!    then persists it, and a `Barrier` reports completion. A barrier covers the state applied
//!    before it was requested.
//!
//! A database set groups one or more managed databases into one unit for execution and commit:
//! `Shared(T)` is the set of one database, and `Tuple(.{ T1, T2, ... })` (up to eight) of
//! several.
//!
//! # The ManagedDb contract
//!
//! Rust's `ManagedDb<E>` trait is a comptime contract on a type `T` (see `assert_managed_db`):
//!
//! - `T.Unmerkleized` with `merkleize(*Self) !T.Merkleized` and `deinit(*Self)`.
//! - `T.Merkleized` with `root() Digest`, `new_batch() !T.Unmerkleized`, `clone() Merkleized`
//!   (cheap, the same sealed branch state), and `deinit(*Self)`.
//! - `T.Config`, `T.SyncTarget` (compared with `eql` when declared, else `std.meta.eql`).
//! - `T.init(env, config, ?SyncTarget) !T`: opens the database at the expected target (or its
//!   latest checkpoint), durably discarding state beyond it; `error.TargetMismatch` when the
//!   recovered target differs (see `validate_initialization`).
//! - `T.initial_sync_target() SyncTarget`, the target of a new, empty database.
//! - `T.new_batch(BatchContext(T)) !T.Unmerkleized`: a batch over the applied state. The batch
//!   may keep the `Shared` handle for later reads, never the borrowed database.
//! - `T.matches_sync_target(*const Merkleized, *const SyncTarget) bool`.
//! - `t.apply(*const Merkleized) !void`, `t.finalize() !void` (persist every checkpoint
//!   applied before the call), optionally `t.prune(*const SyncTarget) !void`,
//!   `t.sync_target() SyncTarget`, and `t.deinit()`.
//!
//! # Failures
//!
//! Database failures are fatal. commonware's sets panic when a database fails to open, apply,
//! finalize, or prune; here they return the error, and `Stateful` stops on it. A failed
//! mutation leaves its database lost: every later `read` or `write` on it panics, and only a
//! restart recovers it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const runtime = @import("runtime");

pub const any = @import("any.zig");
pub const current = @import("current.zig");

/// What a QMDB database needs to open: memory, storage, and a metrics scope (commonware's
/// runtime context `E`). Sets pass each member `env.child("db_<index>")`.
pub const Env = struct {
    gpa: Allocator,
    io: Io,
    storage: runtime.storage.Storage,
    scope: runtime.telemetry.metrics.Scope,

    pub fn child(env: Env, label: []const u8) Env {
        var result = env;
        result.scope = env.scope.child(label);
        return result;
    }
};

const lost_message =
    "database was lost by an earlier failed or interrupted operation; restart to recover";

/// A database shared across tasks (commonware `Shared`).
///
/// A copy of the handle refers to the same database; the creator owns it and calls `deinit`
/// once every copy is done. Mutations take the database with `write` and restore it with
/// `WriteSlot.put`; a slot released without a put leaves the database lost, and every later
/// `read` or `write` panics.
///
/// Reads and writes are exclusive: storage reads take `*Db` (journal reads fill buffers), so
/// two readers must not run at once. As in commonware, holding a guard while acquiring the same
/// database again deadlocks.
pub fn Shared(comptime DB: type) type {
    return struct {
        const Self = @This();
        pub const Database = DB;

        cell: *Cell,

        const Cell = struct {
            gpa: Allocator,
            io: Io,
            label: []const u8,
            mutex: Io.Mutex = .init,
            database: ?DB,
        };

        /// Shares `database`, identified by `label` in diagnostics.
        pub fn init(gpa: Allocator, io: Io, name: []const u8, database: DB) !Self {
            const cell = try gpa.create(Cell);
            cell.* = .{ .gpa = gpa, .io = io, .label = name, .database = database };
            return .{ .cell = cell };
        }

        /// Closes the database (if it was not lost) and frees the handle. No guard may be held.
        pub fn deinit(self: Self) void {
            const cell = self.cell;
            assert(cell.mutex.tryLock());
            if (cell.database) |*database| database.deinit();
            const gpa = cell.gpa;
            gpa.destroy(cell);
        }

        pub fn label(self: Self) []const u8 {
            return self.cell.label;
        }

        /// Whether an earlier failed mutation lost the database.
        pub fn is_lost(self: Self) bool {
            return self.cell.database == null;
        }

        /// Access to the database; panics if it was lost.
        pub fn read(self: Self) Io.Cancelable!ReadGuard {
            try self.cell.mutex.lock(self.cell.io);
            if (self.cell.database == null) {
                self.cell.mutex.unlock(self.cell.io);
                @panic(lost_message);
            }
            return .{ .cell = self.cell };
        }

        /// Takes the database out for a mutation; panics if it was lost.
        pub fn write(self: Self) Io.Cancelable!WriteSlot {
            const guard = try self.read();
            return .{ .cell = guard.cell };
        }

        /// A read-only handle (commonware `Reader`).
        pub fn reader(self: Self) Reader(DB) {
            return .{ .shared = self };
        }

        /// The capability `DB.new_batch` receives: the read-locked database and this handle.
        fn batch_context(self: Self, guard: *const ReadGuard) BatchContext(DB) {
            assert(guard.cell == self.cell);
            return .{ .database = guard.get(), .shared = self };
        }

        pub const ReadGuard = struct {
            cell: *Cell,

            pub fn get(guard: ReadGuard) *DB {
                return &guard.cell.database.?;
            }

            pub fn deinit(guard: *ReadGuard) void {
                guard.cell.mutex.unlock(guard.cell.io);
                guard.* = undefined;
            }
        };

        /// The locked database during a mutation (commonware `WriteSlot`).
        pub const WriteSlot = struct {
            cell: *Cell,

            pub fn get(slot: WriteSlot) *DB {
                return &slot.cell.database.?;
            }

            /// Releases the lock after a successful mutation.
            pub fn put(slot: *WriteSlot) void {
                assert(slot.cell.database != null);
                slot.cell.mutex.unlock(slot.cell.io);
                slot.* = undefined;
            }

            /// Releases the lock after a failed mutation: the database is closed and lost.
            pub fn lose(slot: *WriteSlot) void {
                slot.cell.database.?.deinit();
                slot.cell.database = null;
                slot.cell.mutex.unlock(slot.cell.io);
                slot.* = undefined;
            }
        };

        // The set of one database (commonware `impl DatabaseSet for Shared<T>`).

        pub const Unmerkleized = DB.Unmerkleized;
        pub const Merkleized = DB.Merkleized;
        pub const Readers = Reader(DB);
        pub const Config = DB.Config;
        pub const SyncTargets = DB.SyncTarget;

        /// Opens the database at `expected` when supplied.
        pub fn open(env: anytype, config: Config, expected: ?SyncTargets) !Self {
            comptime assert_managed_db(DB);
            var database = try DB.init(env, config, expected);
            errdefer database.deinit();
            return init(env.gpa, env.io, "stateful.db", database);
        }

        pub fn initial_sync_targets() SyncTargets {
            return DB.initial_sync_target();
        }

        /// A batch over the applied state; the lock is released before this returns.
        pub fn new_batches(self: Self) !Unmerkleized {
            var guard = try self.read();
            defer guard.deinit();
            return DB.new_batch(self.batch_context(&guard));
        }

        /// A child batch of a pending merkleized parent; takes no lock.
        pub fn fork_batches(parent: *const Merkleized) !Unmerkleized {
            return parent.new_batch();
        }

        pub fn matches_sync_targets(batches: *const Merkleized, targets: *const SyncTargets) bool {
            return DB.matches_sync_target(batches, targets);
        }

        pub fn readers(self: Self) Readers {
            return self.reader();
        }

        /// Applies `batches`; the caller keeps its reference.
        pub fn apply(self: Self, batches: *const Merkleized) !void {
            try mutate(DB, self, .apply, .{batches});
        }

        /// Persists every checkpoint applied before this call.
        pub fn finalize(self: Self) !Barrier {
            var barrier: Barrier = .{};
            barrier.record(@typeName(DB), null, mutate(DB, self, .finalize, .{}));
            return barrier;
        }

        pub fn prune(self: Self, targets: *const SyncTargets) !void {
            try mutate(DB, self, .prune, .{targets});
        }

        /// The target of the latest applied checkpoint.
        pub fn committed_targets(self: Self) !SyncTargets {
            var guard = try self.read();
            defer guard.deinit();
            return guard.get().sync_target();
        }
    };
}

/// Read-only access to a database managed by `Stateful`: it cannot write, build or apply
/// batches, finalize, or prune, so observing finalized state cannot invalidate speculative
/// batches.
pub fn Reader(comptime DB: type) type {
    return struct {
        shared: Shared(DB),

        pub fn read(self: @This()) Io.Cancelable!Shared(DB).ReadGuard {
            return self.shared.read();
        }
    };
}

/// The read-locked database and its `Shared` handle, for building a batch. Only the sets in
/// this module construct it, and the batch may keep only `shared`.
pub fn BatchContext(comptime DB: type) type {
    return struct {
        database: *DB,
        shared: Shared(DB),
    };
}

/// A mutation of one member, holding only that member's lock. On failure the member is lost
/// and the error returned; commonware panics with the member's index and type, which the
/// caller knows here.
const Mutation = enum { apply, finalize, prune };

fn mutate(
    comptime DB: type,
    shared: Shared(DB),
    comptime mutation: Mutation,
    args: anytype,
) !void {
    var slot = try shared.write();
    run_mutation(DB, slot.get(), mutation, args) catch |err| {
        // The database may be partially mutated: it is lost until a restart.
        slot.lose();
        return err;
    };
    slot.put();
}

fn run_mutation(
    comptime DB: type,
    database: *DB,
    comptime mutation: Mutation,
    args: anytype,
) !void {
    switch (mutation) {
        .apply => try database.apply(args[0]),
        .finalize => try database.finalize(),
        // Databases without prunable history omit `prune`.
        .prune => if (@hasDecl(DB, "prune")) try database.prune(args[0]),
    }
}

/// A durability barrier returned by `finalize` (commonware `Barrier`).
///
/// zigware's databases persist synchronously in `finalize`, so the barrier holds each
/// member's outcome; `durable` reports a failure, which is fatal, as commonware's panic.
pub const Barrier = struct {
    pub const max_members = 8;

    failures: [max_members]?Failure = @splat(null),
    count: usize = 0,

    pub const Failure = struct {
        db_type: []const u8,
        index: ?usize,
        err: anyerror,
    };

    fn record(barrier: *Barrier, db_type: []const u8, index: ?usize, outcome: anyerror!void) void {
        assert(barrier.count < max_members);
        barrier.failures[barrier.count] = if (outcome) |_| null else |err| .{
            .db_type = db_type,
            .index = index,
            .err = err,
        };
        barrier.count += 1;
    }

    /// Succeeds once every member's state is durable; an empty barrier is durable at once.
    /// Fails with the first member's sync error.
    pub fn durable(barrier: *const Barrier) error{DatabaseSyncFailed}!void {
        for (barrier.failures[0..barrier.count]) |failure| {
            if (failure != null) return error.DatabaseSyncFailed;
        }
    }

    /// The first failure, if any.
    pub fn first_failure(barrier: *const Barrier) ?Failure {
        for (barrier.failures[0..barrier.count]) |failure| {
            if (failure != null) return failure;
        }
        return null;
    }
};

/// The set of several databases `types` (commonware's tuple `DatabaseSet` impls, up to eight).
/// Each `*Batches`, `Config`, `SyncTargets`, and `Readers` is a tuple with one entry per
/// member, in order.
pub fn Tuple(comptime types: anytype) type {
    const count = types.len;
    comptime assert(count >= 1 and count <= Barrier.max_members);
    return struct {
        const Self = @This();
        pub const Members = Map(types, SharedOf);
        pub const Unmerkleized = Map(types, UnmerkleizedOf);
        pub const Merkleized = Map(types, MerkleizedOf);
        pub const Readers = Map(types, ReaderOf);
        pub const Config = Map(types, ConfigOf);
        pub const SyncTargets = Map(types, SyncTargetOf);

        members: Members,

        /// Opens every member at its target in `expected` when supplied, as
        /// `env.child("db_<index>")`. On failure the members already opened are closed.
        pub fn open(env: anytype, config: Config, expected: ?SyncTargets) !Self {
            var self: Self = undefined;
            var opened: usize = 0;
            errdefer inline for (0..count) |i| {
                if (i < opened) self.members[i].deinit();
            };
            inline for (types, 0..) |DB, i| {
                comptime assert_managed_db(DB);
                const target: ?DB.SyncTarget = if (expected) |e| e[i] else null;
                const name = std.fmt.comptimePrint("db_{d}", .{i});
                var database = try DB.init(env.child(name), config[i], target);
                errdefer database.deinit();
                const label = std.fmt.comptimePrint("stateful.db.{d}", .{i});
                self.members[i] = try Shared(DB).init(env.gpa, env.io, label, database);
                opened += 1;
            }
            return self;
        }

        pub fn deinit(self: *Self) void {
            inline for (0..count) |i| self.members[i].deinit();
            self.* = undefined;
        }

        pub fn initial_sync_targets() SyncTargets {
            var targets: SyncTargets = undefined;
            inline for (types, 0..) |DB, i| targets[i] = DB.initial_sync_target();
            return targets;
        }

        /// A batch over each member's applied state. Each member's lock is released before the
        /// next is taken, so no lock is held when this returns.
        pub fn new_batches(self: *const Self) !Unmerkleized {
            var batches: Unmerkleized = undefined;
            var built: usize = 0;
            errdefer inline for (0..count) |i| {
                if (i < built) batches[i].deinit();
            };
            inline for (0..count) |i| {
                batches[i] = try self.members[i].new_batches();
                built += 1;
            }
            return batches;
        }

        pub fn fork_batches(parent: *const Merkleized) !Unmerkleized {
            var batches: Unmerkleized = undefined;
            var built: usize = 0;
            errdefer inline for (0..count) |i| {
                if (i < built) batches[i].deinit();
            };
            inline for (0..count) |i| {
                batches[i] = try parent[i].new_batch();
                built += 1;
            }
            return batches;
        }

        pub fn matches_sync_targets(batches: *const Merkleized, targets: *const SyncTargets) bool {
            inline for (types, 0..) |DB, i| {
                if (!DB.matches_sync_target(&batches[i], &targets[i])) return false;
            }
            return true;
        }

        pub fn readers(self: *const Self) Readers {
            var result: Readers = undefined;
            inline for (0..count) |i| result[i] = self.members[i].reader();
            return result;
        }

        /// Applies each batch to its member, holding one member's lock at a time (holding
        /// several could deadlock reads that span members). A failure loses that member and
        /// stops; earlier members stay applied, so the set must be discarded.
        pub fn apply(self: *const Self, batches: *const Merkleized) !void {
            inline for (types, 0..) |DB, i| {
                try mutate(DB, self.members[i], .apply, .{&batches[i]});
            }
        }

        /// Persists every member; the barrier reports each member's outcome.
        pub fn finalize(self: *const Self) !Barrier {
            var barrier: Barrier = .{};
            inline for (types, 0..) |DB, i| {
                barrier.record(@typeName(DB), i, mutate(DB, self.members[i], .finalize, .{}));
            }
            return barrier;
        }

        pub fn prune(self: *const Self, targets: *const SyncTargets) !void {
            inline for (types, 0..) |DB, i| {
                try mutate(DB, self.members[i], .prune, .{&targets[i]});
            }
        }

        pub fn committed_targets(self: *const Self) !SyncTargets {
            var targets: SyncTargets = undefined;
            inline for (0..count) |i| targets[i] = try self.members[i].committed_targets();
            return targets;
        }
    };
}

fn SharedOf(comptime DB: type) type {
    return Shared(DB);
}
fn UnmerkleizedOf(comptime DB: type) type {
    return DB.Unmerkleized;
}
fn MerkleizedOf(comptime DB: type) type {
    return DB.Merkleized;
}
fn ReaderOf(comptime DB: type) type {
    return Reader(DB);
}
fn ConfigOf(comptime DB: type) type {
    return DB.Config;
}
fn SyncTargetOf(comptime DB: type) type {
    return DB.SyncTarget;
}

/// The tuple of `F(T)` for each `T` in `types`.
fn Map(comptime types: anytype, comptime F: fn (type) type) type {
    var fields: [types.len]type = undefined;
    for (types, 0..) |T, i| fields[i] = F(T);
    return @Tuple(&fields);
}

/// Whether two sync targets are equal: `eql` when `T` declares it, else field equality.
pub fn targets_eql(comptime T: type, a: *const T, b: *const T) bool {
    if (@typeInfo(T) == .@"struct" and @hasDecl(T, "eql")) return T.eql(a.*, b.*);
    return std.meta.eql(a.*, b.*);
}

/// commonware's `validate_initialization`: `error.TargetMismatch` when `database` was opened
/// at a target other than `expected`.
pub fn validate_initialization(
    comptime DB: type,
    database: *const DB,
    expected: ?DB.SyncTarget,
) error{TargetMismatch}!void {
    const target = expected orelse return;
    const recovered = database.sync_target();
    if (!targets_eql(DB.SyncTarget, &recovered, &target)) return error.TargetMismatch;
}

/// Asserts `DB` implements the ManagedDb contract (see the module docs).
pub fn assert_managed_db(comptime DB: type) void {
    comptime {
        const decls = .{
            "Unmerkleized",        "Merkleized", "Config",              "SyncTarget", "init",
            "initial_sync_target", "new_batch",  "matches_sync_target", "apply",      "finalize",
            "sync_target",         "deinit",
        };
        for (decls) |decl| {
            if (!@hasDecl(DB, decl)) @compileError(@typeName(DB) ++ " lacks ManagedDb." ++ decl);
        }
        for (.{ "merkleize", "deinit" }) |decl| {
            if (!@hasDecl(DB.Unmerkleized, decl)) {
                @compileError(@typeName(DB) ++ ".Unmerkleized lacks " ++ decl);
            }
        }
        for (.{ "root", "new_batch", "clone", "deinit" }) |decl| {
            if (!@hasDecl(DB.Merkleized, decl)) {
                @compileError(@typeName(DB) ++ ".Merkleized lacks " ++ decl);
            }
        }
    }
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("mod_test.zig");
}
