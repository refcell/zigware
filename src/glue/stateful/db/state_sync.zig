//! Building databases by state sync (commonware `glue/src/stateful/db/mod.rs`:
//! `SyncEngineConfig`, `StateSyncDb`, `StateSyncSet` for `Shared`, `sync_standard_db`, and
//! `sync_compact_db`).
//!
//! # The StateSyncDb contract
//!
//! Rust's `StateSyncDb<E, R>` is a comptime contract on a ManagedDb `T` (see
//! `assert_state_sync_db`):
//!
//! - `T.sync_db(env, config, source, target, channels: Channels(T.SyncTarget), sync_config)
//!   !T` syncs a new database from `source` (a pointer the call borrows) to `target`.
//!
//! The caller sends valid targets of the same database on `channels.tip_updates` in advancing
//! order; a target may be superseded by a newer one before it is read. Implementations adopt
//! a target only if it advances the current one. With `channels.finish`, they complete only
//! once it has signaled and the current target is reached; without it, as soon as the target
//! is reached. With `channels.reached_target`, they report each reached target on it at most
//! once, in the order reached, without waiting, and release the sender when they return, also
//! on error. The receivers are borrowed; the sender is owned.
//!
//! # Single-database sets
//!
//! `sync_shared` runs `T.sync_db` beside a coordinator that adopts finalized tips (the anchor
//! rules in `sync.zig`), forwards their targets, and signals `finish` once the database
//! reports the newest adopted target. The result is the synced database, shared, and the
//! anchor whose targets it reached.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const storage = @import("storage");
const utils = @import("utils");
const db = @import("mod.zig");
const sync = @import("sync.zig");

const qmdb = storage.qmdb;
const mpsc = utils.channel.mpsc;
const ring = utils.channel.ring;
const Anchor = sync.Anchor;
const TipUpdate = sync.TipUpdate;

/// The sync engine's request and apply sizing (commonware's `SyncEngineConfig`).
pub const SyncEngineConfig = struct {
    /// Most operations fetched per source request. Peers ignore requests larger than their
    /// `max_serve_ops`, so a larger value stalls sync: keep it at or below every peer's.
    fetch_batch_size: u64,
    /// Operations applied per local apply step.
    apply_batch_size: u64,
    /// Most outstanding source requests; the request for the pinned nodes counts toward it.
    max_outstanding_requests: usize,

    fn assert_valid(config: SyncEngineConfig) void {
        assert(config.fetch_batch_size > 0);
        assert(config.apply_batch_size > 0);
        assert(config.max_outstanding_requests > 0);
    }
};

/// What a database sync reads targets from and reports progress on (commonware's
/// `tip_updates`, `finish`, and `reached_target` arguments).
pub fn Channels(comptime Target: type) type {
    return struct {
        /// Advancing targets (borrowed).
        tip_updates: *ring.Receiver(Target),
        /// When set, completion waits for a signal on it (borrowed).
        finish: ?*mpsc.Receiver(void) = null,
        /// When set, each reached target is reported on it (owned, released on return).
        reached_target: ?ring.Sender(Target) = null,

        /// Releases the owned reporter (for implementations that return before using it).
        pub fn release(channels: *@This()) void {
            if (channels.reached_target) |*sender| sender.deinit();
            channels.reached_target = null;
        }
    };
}

/// Asserts `T` implements the StateSyncDb contract (see the module docs).
pub fn assert_state_sync_db(comptime T: type) void {
    comptime {
        db.assert_managed_db(T);
        if (!@hasDecl(T, "sync_db")) @compileError(@typeName(T) ++ " lacks StateSyncDb.sync_db");
    }
}

fn SourceOf(comptime source: type) type {
    const info = @typeInfo(source);
    comptime assert(info == .pointer and info.pointer.size == .one);
    return info.pointer.child;
}

/// Syncs a standard database `DB` (a `qmdb.sync` Database whose operation log is retained)
/// from `source` (commonware's `sync_standard_db`).
pub fn sync_standard_db(
    comptime DB: type,
    env: anytype,
    config: DB.Config,
    source: anytype,
    target: qmdb.sync.Target(DB.Family, DB.Digest),
    channels: Channels(qmdb.sync.Target(DB.Family, DB.Digest)),
    sync_config: SyncEngineConfig,
) !DB {
    comptime qmdb.sync.database.assert_database(DB);
    sync_config.assert_valid();
    return qmdb.sync.sync(DB, SourceOf(@TypeOf(source)), env.gpa, env.io, .{
        .storage = env.storage,
        .scope = env.scope,
        .source = source,
        .target = target,
        .max_outstanding_requests = sync_config.max_outstanding_requests,
        .fetch_batch_size = sync_config.fetch_batch_size,
        .apply_batch_size = sync_config.apply_batch_size,
        .db_config = config,
        .update_rx = channels.tip_updates,
        .finish_rx = channels.finish,
        .reached_target_tx = channels.reached_target,
    });
}

/// Syncs a compact database `DB`, which keeps no operation log (commonware's
/// `sync_compact_db`). Compact targets convert to engine targets: one that does not fails the
/// sync as `target` and is ignored on `tip_updates`. Reached engine targets convert back.
pub fn sync_compact_db(
    comptime DB: type,
    env: anytype,
    config: DB.Config,
    source: anytype,
    target: qmdb.sync.CompactTarget(DB.Family, DB.Digest),
    channels: Channels(qmdb.sync.CompactTarget(DB.Family, DB.Digest)),
    sync_config: SyncEngineConfig,
) !DB {
    const Compact = qmdb.sync.CompactTarget(DB.Family, DB.Digest);
    const Target = qmdb.sync.Target(DB.Family, DB.Digest);
    const gpa = env.gpa;
    const io = env.io;
    var outer = channels;
    errdefer outer.release();
    var initial = try target.to_target();
    // Start at the newest target already queued.
    while (outer.tip_updates.try_recv()) |update| {
        const converted = update.to_target() catch continue;
        if (converted.advances(initial)) initial = converted;
    } else |_| {}

    var updates = try ring.channel(Target, gpa, io, 1);
    defer updates.receiver.deinit();
    const forward = Updates(Compact, Target).forward;
    const forward_args = .{ outer.tip_updates, updates.sender };
    var update_forwarder = io.concurrent(forward, forward_args) catch |err| {
        updates.sender.deinit();
        return err;
    };
    defer update_forwarder.cancel(io);

    var reached = try Reached(Compact, Target).start(io, gpa, &outer);
    defer reached.join(io);
    return qmdb.sync.sync(DB, SourceOf(@TypeOf(source)), gpa, io, .{
        .storage = env.storage,
        .scope = env.scope,
        .source = source,
        .target = initial,
        .max_outstanding_requests = sync_config.max_outstanding_requests,
        .fetch_batch_size = sync_config.fetch_batch_size,
        .apply_batch_size = sync_config.apply_batch_size,
        .db_config = config,
        .update_rx = &updates.receiver,
        .finish_rx = outer.finish,
        .reached_target_tx = reached.engine_sender(),
    });
}

/// Forwards the compact targets on `tips` as engine targets until canceled or `out` closes.
fn Updates(comptime Compact: type, comptime Target: type) type {
    return struct {
        /// Owns `out`.
        fn forward(tips: *ring.Receiver(Compact), out: ring.Sender(Target)) void {
            var sender = out;
            defer sender.deinit();
            while (true) {
                const update = (tips.recv() catch return) orelse return;
                const converted = update.to_target() catch continue;
                assert(converted.end == update.size);
                if (!sender.send_lossy(converted)) return;
            }
        }
    };
}

/// The compact reporter's adapter: reached engine targets become compact targets.
fn Reached(comptime Compact: type, comptime Target: type) type {
    return struct {
        const Self = @This();

        engine: ?ring.Sender(Target) = null,
        forwarder: ?Io.Future(void) = null,

        /// Takes `channels.reached_target`, if any, and starts its forwarder.
        fn start(io: Io, gpa: Allocator, channels: *Channels(Compact)) !Self {
            const outer = channels.reached_target orelse return .{};
            const pair = try ring.channel(Target, gpa, io, 1);
            var self: Self = .{ .engine = pair.sender };
            self.forwarder = io.concurrent(forward, .{ pair.receiver, outer }) catch |err| {
                var receiver = pair.receiver;
                receiver.deinit();
                self.engine.?.deinit();
                return err;
            };
            channels.reached_target = null; // The forwarder owns it now.
            return self;
        }

        /// The sender the engine takes (and releases).
        fn engine_sender(self: *Self) ?ring.Sender(Target) {
            const sender = self.engine;
            self.engine = null;
            return sender;
        }

        /// Waits for the forwarder, which ends once the engine releases its sender.
        fn join(self: *Self, io: Io) void {
            assert(self.engine == null);
            if (self.forwarder) |*future| future.await(io);
        }

        fn forward(engine: ring.Receiver(Target), out: ring.Sender(Compact)) void {
            var receiver = engine;
            defer receiver.deinit();
            var sender = out;
            defer sender.deinit();
            while (true) {
                const reached = (receiver.recv() catch return) orelse return;
                if (!sender.send_lossy(.{ .root = reached.root, .size = reached.end })) return;
            }
        }
    };
}

/// A synced single-database set and the anchor whose targets it reached.
pub fn Synced(comptime T: type, comptime D: type) type {
    return struct { databases: db.Shared(T), anchor: Anchor(D) };
}

/// Syncs database `T` from `source` to `target`, carried by `anchor`, adopting the finalized
/// tips on `tip_updates` (commonware's `StateSyncSet::sync` for `Shared<T>`). Takes
/// `tip_updates`. Fails with the database's error, or `error.SyncTargetMismatch` when the
/// database finished at another target than the coordinator converged on (commonware panics).
pub fn sync_shared(
    comptime T: type,
    comptime D: type,
    env: anytype,
    config: T.Config,
    source: anytype,
    anchor: Anchor(D),
    target: T.SyncTarget,
    tip_updates: ring.Receiver(TipUpdate(D, T.SyncTarget)),
    sync_config: SyncEngineConfig,
) !Synced(T, D) {
    comptime assert_state_sync_db(T);
    const gpa = env.gpa;
    const io = env.io;
    const C = Coordinator(D, T.SyncTarget);
    var coordinator = try C.init(gpa, io, anchor, target, tip_updates);
    var targets = coordinator.targets_rx;
    var finish = coordinator.finish_rx;
    const reached = coordinator.reached_tx;
    var future = io.concurrent(C.run, .{&coordinator}) catch |err| {
        var sender = reached;
        sender.deinit();
        targets.deinit();
        finish.deinit();
        coordinator.release();
        return err;
    };
    const result = T.sync_db(env, config, source, target, .{
        .tip_updates = &targets,
        .finish = &finish,
        .reached_target = reached,
    }, sync_config);
    // Closing the target channel ends a coordinator still waiting to forward a tip; the
    // database released `reached`, which ends one waiting for a report.
    targets.deinit();
    finish.deinit();
    const converged = future.await(io);
    var database = try result;
    errdefer database.deinit();
    const outcome = try converged;
    if (!db.targets_eql(T.SyncTarget, &database.sync_target(), &outcome.target)) {
        return error.SyncTargetMismatch;
    }
    const shared = try db.Shared(T).init(gpa, io, "stateful.db", database);
    return .{ .databases = shared, .anchor = outcome.anchor };
}

/// The single-database coordinator: adopts tips, forwards targets, and finishes the sync.
fn Coordinator(comptime D: type, comptime Target: type) type {
    return struct {
        const Self = @This();
        const Update = TipUpdate(D, Target);
        pub const Converged = struct { anchor: Anchor(D), target: Target };

        io: Io,
        tip_updates: ?ring.Receiver(Update),
        targets_tx: ring.Sender(Target),
        targets_rx: ring.Receiver(Target),
        finish_tx: mpsc.Sender(void),
        finish_rx: mpsc.Receiver(void),
        reached_tx: ring.Sender(Target),
        reached_rx: ring.Receiver(Target),
        anchor: Anchor(D),
        target: Target,
        last_reached: ?Target = null,

        /// The coordinator and the database's channel ends (`targets_rx`, `finish_rx`, and
        /// `reached_tx` go to the database). Takes `tip_updates`, also on error.
        fn init(
            gpa: Allocator,
            io: Io,
            anchor: Anchor(D),
            target: Target,
            tip_updates: ring.Receiver(Update),
        ) !Self {
            var tips = tip_updates;
            errdefer tips.deinit();
            const targets = try ring.channel(Target, gpa, io, 1);
            errdefer release_pair(targets);
            const finish = try mpsc.channel(void, gpa, io, 1);
            errdefer release_pair(finish);
            const reached = try ring.channel(Target, gpa, io, 1);
            return .{
                .io = io,
                .tip_updates = tips,
                .targets_tx = targets.sender,
                .targets_rx = targets.receiver,
                .finish_tx = finish.sender,
                .finish_rx = finish.receiver,
                .reached_tx = reached.sender,
                .reached_rx = reached.receiver,
                .anchor = anchor,
                .target = target,
            };
        }

        fn release_pair(pair: anytype) void {
            var ends = pair;
            ends.sender.deinit();
            ends.receiver.deinit();
        }

        /// Releases the coordinator's own channel ends.
        fn release(self: *Self) void {
            if (self.tip_updates) |*tips| tips.deinit();
            self.tip_updates = null;
            self.targets_tx.deinit();
            self.finish_tx.deinit();
            self.reached_rx.deinit();
        }

        fn converged(self: *const Self) Converged {
            return .{ .anchor = self.anchor, .target = self.target };
        }

        /// Runs until the database reaches the newest adopted target (then signals finish),
        /// stops reporting, or drops its target receiver. Releases the coordinator's ends.
        fn run(self: *Self) (Io.ConcurrentError || Io.Cancelable)!Converged {
            defer self.release();
            while (true) {
                const queued_ok = sync.dispatch_queued_tips(
                    D,
                    Target,
                    &self.tip_updates,
                    self.targets_tx,
                    &self.anchor,
                    &self.target,
                );
                if (!queued_ok) return self.converged();
                // Queued tips are adopted first, so a report for a target they replaced
                // cannot finish the sync.
                if (self.last_reached) |reached| {
                    if (db.targets_eql(Target, &reached, &self.target)) {
                        // Capacity 1 and one send: the only failure is a gone database.
                        self.finish_tx.try_send({}) catch {};
                        return self.converged();
                    }
                }
                if (!try self.wait()) return self.converged();
            }
        }

        const Wake = union(enum) {
            reached: Io.Cancelable!?Target,
            tip: Io.Cancelable!?Update,
        };

        /// Waits for a progress report or a newer tip and handles what arrived. Returns
        /// false when the coordinator should stop.
        fn wait(self: *Self) (Io.ConcurrentError || Io.Cancelable)!bool {
            const io = self.io;
            var buffer: [2]Wake = undefined;
            var select: Io.Select(Wake) = .init(io, &buffer);
            select.concurrent(.reached, ring.Receiver(Target).recv, .{&self.reached_rx}) catch |err|
                return err;
            if (self.tip_updates) |*tips| {
                select.concurrent(.tip, ring.Receiver(Update).recv, .{tips}) catch |err| {
                    while (select.cancel()) |rest| _ = self.handle(rest);
                    return err;
                };
            }
            const first = select.await() catch |err| {
                while (select.cancel()) |rest| _ = self.handle(rest);
                return err;
            };
            var keep = self.handle(first);
            // A wait that completed while the others were canceled is kept.
            while (select.cancel()) |rest| keep = self.handle(rest) and keep;
            return keep;
        }

        /// Handles one wake; false when the coordinator should stop.
        fn handle(self: *Self, wake: Wake) bool {
            switch (wake) {
                .reached => |result| {
                    const reached = (result catch return true) orelse return false;
                    self.last_reached = reached;
                    return true;
                },
                .tip => |result| {
                    var update = (result catch return true) orelse {
                        self.tip_updates.?.deinit();
                        self.tip_updates = null;
                        return true;
                    };
                    var adopt: Adopt = .{ .coordinator = self };
                    update.record(&adopt);
                    const forward = adopt.forward orelse return true;
                    return self.targets_tx.send_lossy(forward);
                },
            }
        }

        /// Records a tip: a higher anchor moves the anchor, and a changed target is forwarded.
        const Adopt = struct {
            coordinator: *Self,
            forward: ?Target = null,

            pub fn record(adopt: *Adopt, anchor: Anchor(D), targets: Target) void {
                const self = adopt.coordinator;
                if (anchor.height.get() <= self.anchor.height.get()) return;
                self.anchor = anchor;
                if (db.targets_eql(Target, &targets, &self.target)) return;
                self.target = targets;
                adopt.forward = targets;
            }
        };
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("state_sync_test.zig");
}
