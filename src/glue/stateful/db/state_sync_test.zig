//! commonware `glue/src/stateful/db/mod.rs` state-sync tests of single-database sets (on its
//! mock databases), plus real syncs of the keyless, immutable, and compact adapters through
//! `sync_shared` (commonware's `state_sync_fetches_compact_state` and the adapters'
//! `StateSyncDb` impls), and the release of a sync's reporter when the engine cannot open.
//!
//! commonware polls futures with `now_or_never` to park the coordinator; here the sync runs
//! in its own task and the tests sequence it with tip observers and release gates.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("mod.zig");
const state_sync = @import("state_sync.zig");
const sync = @import("sync.zig");
const keyless = @import("keyless.zig");
const immutable = @import("immutable.zig");
const compact = @import("compact.zig");

const gpa = testing.allocator;
const io = testing.io;
const qmdb = storage.qmdb;
const ring = utils.channel.ring;
const mpsc = utils.channel.mpsc;
const oneshot = utils.channel.oneshot;
const metrics = runtime.telemetry.metrics;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Anchor = sync.Anchor(Digest);
const Update = sync.TipUpdate(Digest, u64);

const engine_config: state_sync.SyncEngineConfig = .{
    .fetch_batch_size = 1,
    .apply_batch_size = 1,
    .max_outstanding_requests = 1,
};

/// commonware's mock `anchor(height, height as u8)`.
fn anchor(height: u64) Anchor {
    return .{
        .height = .new(height),
        .round = .new(.zero(), .new(height)),
        .digest = .{ .bytes = @splat(@truncate(height)) },
    };
}

/// The environment mocks receive.
const TestEnv = struct {
    gpa: std.mem.Allocator = gpa,
    io: std.Io = io,
};

const TestUnmerkleized = struct {
    pub fn merkleize(_: *TestUnmerkleized) !TestMerkleized {
        return .{};
    }
    pub fn deinit(_: *TestUnmerkleized) void {}
};

const TestMerkleized = struct {
    pub fn root(_: *const TestMerkleized) u64 {
        return 0;
    }
    pub fn new_batch(_: *const TestMerkleized) !TestUnmerkleized {
        return .{};
    }
    pub fn clone(self: *const TestMerkleized) TestMerkleized {
        return self.*;
    }
    pub fn deinit(_: *TestMerkleized) void {}
};

/// A mock database built only by state sync, at `final_target`; `Sync` is its `sync_db` body
/// (commonware's mock `StateSyncDb`s).
fn SyncMock(comptime Sync: type) type {
    return struct {
        const Self = @This();
        final_target: u64,

        pub const Config = void;
        pub const SyncTarget = u64;
        pub const Unmerkleized = TestUnmerkleized;
        pub const Merkleized = TestMerkleized;

        pub fn init(_: anytype, _: void, _: ?u64) !Self {
            unreachable; // Built only through state sync.
        }
        pub fn initial_sync_target() u64 {
            unreachable; // Built only through state sync.
        }
        pub fn new_batch(_: db.BatchContext(Self)) !TestUnmerkleized {
            return .{};
        }
        pub fn matches_sync_target(_: *const TestMerkleized, _: *const u64) bool {
            return true;
        }
        pub fn apply(_: *Self, _: *const TestMerkleized) !void {}
        pub fn finalize(_: *Self) !void {}
        pub fn deinit(_: *Self) void {}
        pub fn sync_target(self: *const Self) u64 {
            return self.final_target;
        }

        pub fn sync_db(
            _: anytype,
            _: void,
            source: anytype,
            target: u64,
            channels: state_sync.Channels(u64),
            _: state_sync.SyncEngineConfig,
        ) !Self {
            var owned = channels;
            defer owned.release();
            return .{ .final_target = try Sync.run(source, target, &owned) };
        }
    };
}

/// A gate the test opens to let a mock database proceed, recording duplicate targets. The
/// database signals `started` as it begins.
const Gate = struct {
    release: oneshot.Receiver(void),
    started: ?oneshot.Sender(void),
    duplicate: bool = false,
    /// Target updates the database received (commonware's `update_count`).
    updates: u64 = 0,

    fn wait(gate: *Gate) void {
        if (gate.started) |*started| started.send({}) catch {}; // Unwatched starts are fine.
        gate.started = null;
        gate.release.recv() catch {}; // A dropped sender also opens the gate.
    }

    fn deinit(gate: *Gate) void {
        gate.release.deinit();
        if (gate.started) |*started| started.deinit();
    }
};

const GatePair = struct {
    gate: Gate,
    release: ?oneshot.Sender(void),
    started: oneshot.Receiver(void),

    /// Waits until the database started, then lets the coordinator park in its wait (the
    /// tips that follow reach its select rather than its queued-tip drain).
    fn park(pair: *GatePair) !void {
        try pair.started.recv();
        try io.sleep(.fromMilliseconds(5), .awake);
    }

    /// Opens the gate.
    fn open(pair: *GatePair) !void {
        try pair.release.?.send({});
        pair.release = null;
    }

    fn deinit(pair: *GatePair) void {
        pair.started.deinit();
        if (pair.release) |*release| release.deinit();
    }
};

fn gate_pair() !GatePair {
    const release = try oneshot.channel(void, gpa, io);
    const started = try oneshot.channel(void, gpa, io);
    return .{
        .gate = .{ .release = release.receiver, .started = started.sender },
        .release = release.sender,
        .started = started.receiver,
    };
}

const Signal = union(enum) { finish, finish_closed, update: u64, updates_closed, slept };

/// Polls for a finish signal, a target update, or the end of the optional `sleep_ms` window.
/// Polling takes nothing it does not return, unlike a select that cancels the losers.
fn next_signal(channels: *state_sync.Channels(u64), tips_open: bool, sleep_ms: ?u64) !Signal {
    const start = std.Io.Clock.Timestamp.now(io, .awake);
    while (true) {
        if (channels.finish) |finish| {
            if (finish.try_recv()) |_| return .finish else |err| switch (err) {
                error.Empty => {},
                error.Disconnected => return .finish_closed,
            }
        }
        if (tips_open) {
            if (channels.tip_updates.try_recv()) |value| return .{ .update = value } else |err| {
                switch (err) {
                    error.Empty => {},
                    error.Disconnected => return .updates_closed,
                }
            }
        }
        if (sleep_ms) |ms| {
            const elapsed = start.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw;
            if (elapsed.toMilliseconds() >= ms) return .slept;
        }
        try io.sleep(.fromMilliseconds(1), .awake);
    }
}

/// How a looping mock reports and adopts targets.
const LoopOptions = struct {
    /// Report a target only once (commonware's `reported_target` guard).
    dedupe: bool = false,
    /// Report nothing until an update arrived (commonware `ObservedSlowSyncDb`).
    after_update: bool = false,
    /// Ignore an update that repeats the current target (`DistinctObservedFastSyncDb`).
    distinct: bool = false,
};

/// Waits for its gate (signaling `started`), then reports its target and adopts updates until
/// told to finish (commonware `SlowSyncDb`; with a gate already open, `FastSyncDb`; with
/// options, the `Observed*` variants). Counts the updates it receives on the gate.
fn LoopSync(comptime options: LoopOptions) type {
    return struct {
        fn run(gate: *Gate, target: u64, channels: *state_sync.Channels(u64)) !u64 {
            gate.wait();
            var final = target;
            var tips_open = true;
            var reported: ?u64 = null;
            var observed = false;
            while (true) {
                const due = !options.dedupe or reported != final;
                if (due and (!options.after_update or observed)) {
                    if (channels.reached_target) |reached| {
                        if (!reached.send_lossy(final)) break;
                    }
                    reported = final;
                }
                if (channels.finish == null and !tips_open) break;
                switch (try next_signal(channels, tips_open, null)) {
                    .finish, .finish_closed => break,
                    .update => |value| {
                        gate.updates += 1;
                        if (options.distinct and value == final) continue;
                        final = value;
                        observed = true;
                    },
                    .updates_closed => {
                        tips_open = false;
                        if (channels.finish == null) break;
                    },
                    .slept => unreachable,
                }
            }
            return final;
        }
    };
}
const SlowSyncDb = SyncMock(LoopSync(.{}));
const ObservedSlowSyncDb = SyncMock(LoopSync(.{ .dedupe = true, .after_update = true }));
const ObservedFastSyncDb = SyncMock(LoopSync(.{ .dedupe = true }));
const DistinctObservedFastSyncDb = SyncMock(LoopSync(.{ .dedupe = true, .distinct = true }));

/// Returns its target at once (commonware `ImmediateStateSyncDb`).
const ImmediateSync = struct {
    fn run(_: void, target: u64, _: *state_sync.Channels(u64)) !u64 {
        return target;
    }
};
const ImmediateStateSyncDb = SyncMock(ImmediateSync);

/// Reports its target, then finishes one past it (commonware `MismatchedTargetSyncDb`).
const MismatchedSync = struct {
    fn run(_: void, target: u64, channels: *state_sync.Channels(u64)) !u64 {
        if (channels.reached_target) |reached| _ = reached.send_lossy(target);
        if (channels.finish) |finish| _ = try finish.recv();
        return target + 1;
    }
};
const MismatchedTargetSyncDb = SyncMock(MismatchedSync);

/// Waits to finish and fails if the finish channel closes (commonware `FinishClosedSyncDb`).
const FinishClosedSync = struct {
    fn run(_: void, target: u64, channels: *state_sync.Channels(u64)) !u64 {
        const finish = channels.finish.?; // Sets always pass one.
        _ = (try finish.recv()) orelse return error.FinishClosedSyncError;
        return target;
    }
};
const FinishClosedSyncDb = SyncMock(FinishClosedSync);

/// Fails at once (commonware `FailingStateSyncDb`).
const FailingSync = struct {
    fn run(_: void, _: u64, _: *state_sync.Channels(u64)) !u64 {
        return error.TestSyncError;
    }
};
const FailingStateSyncDb = SyncMock(FailingSync);

/// Adopts updates until released, records a repeated target, then reports and waits to
/// finish (commonware `RejectDuplicateTargetSyncDb`).
const RejectDuplicateSync = struct {
    fn run(gate: *Gate, target: u64, channels: *state_sync.Channels(u64)) !u64 {
        gate.wait();
        var final_target = target;
        // Targets queued before the release are taken now; a repeat of the current target is
        // a coordinator bug.
        while (channels.tip_updates.try_recv()) |update| {
            if (update == final_target) gate.duplicate = true;
            final_target = update;
        } else |_| {}
        if (channels.reached_target) |reached| _ = reached.send_lossy(final_target);
        if (channels.finish) |finish| _ = try finish.recv();
        return final_target;
    }
};
const RejectDuplicateTargetSyncDb = SyncMock(RejectDuplicateSync);

/// Takes one forwarded tip, reports its initial (now stale) target, and holds for a settle
/// window; a coordinator that finishes on the stale report ends the hold early (commonware
/// `StaleReachedSyncDb`).
const StaleReachedSync = struct {
    fn run(_: void, target: u64, channels: *state_sync.Channels(u64)) !u64 {
        const update = (try channels.tip_updates.recv()) orelse return error.ExpectedTip;
        if (channels.reached_target) |reached| _ = reached.send_lossy(target);
        switch (try next_signal(channels, false, 10)) {
            .finish, .finish_closed => return target,
            .slept => {
                if (channels.reached_target) |reached| _ = reached.send_lossy(update);
                if (channels.finish) |finish| _ = try finish.recv();
                return update;
            },
            .update, .updates_closed => unreachable,
        }
    }
};
const StaleReachedSyncDb = SyncMock(StaleReachedSync);

/// Syncs mock `T` from `source`, starting at `anchor(start)` and target `start`.
fn run_sync(
    comptime T: type,
    source: anytype,
    start: u64,
    tips: ring.Receiver(Update),
) !state_sync.Synced(T, Digest) {
    const env: TestEnv = .{};
    return state_sync.sync_shared(
        T,
        Digest,
        env,
        {},
        source,
        anchor(start),
        start,
        tips,
        engine_config,
    );
}

/// `run_sync` over a gate, as a task function.
fn Gated(comptime T: type) type {
    return struct {
        fn run(gate: *Gate, start: u64, tips: ring.Receiver(Update)) !state_sync.Synced(T, Digest) {
            return run_sync(T, gate, start, tips);
        }
    };
}

/// The final target of a synced mock, which it then closes.
fn synced_target(comptime T: type, synced: state_sync.Synced(T, Digest)) !u64 {
    defer synced.databases.deinit();
    var guard = try synced.databases.read();
    defer guard.deinit();
    return guard.get().final_target;
}

test "stateful state sync: a single sync handles a closed tip updates channel" {
    const tips = try ring.channel(Update, gpa, io, 1);
    var pair = try gate_pair();
    defer pair.deinit();
    var gate = pair.gate;
    defer gate.deinit();
    var future = try io.concurrent(Gated(SlowSyncDb).run, .{ &gate, 0, tips.receiver });
    // The tip channel closes while the coordinator waits for tips and reports.
    try pair.park();
    var sender = tips.sender;
    sender.deinit();
    // Once released, the database reports the initial target and the sync finishes there.
    try pair.open();
    const synced = try future.await(io);
    try testing.expect(synced.anchor.eql(anchor(0)));
    try testing.expectEqual(@as(u64, 0), try synced_target(SlowSyncDb, synced));
}

test "stateful state sync: a single sync preserves the database's error" {
    var tips = try ring.channel(Update, gpa, io, 1);
    defer tips.sender.deinit();
    try testing.expect(tips.sender.send_lossy(.init(anchor(1), 1)));
    // The database drops its target receiver as it fails, so forwarding the tip fails too;
    // the database's error is the one returned.
    const result = run_sync(FailingStateSyncDb, {}, 0, tips.receiver);
    try testing.expectError(error.TestSyncError, result);
}

test "stateful state sync: a single sync ignores backward tip updates" {
    const tips = try ring.channel(Update, gpa, io, 4);
    var sender = tips.sender;
    try testing.expect(sender.send_lossy(.init(anchor(2), 2)));
    try testing.expect(sender.send_lossy(.init(anchor(1), 1)));
    sender.deinit();
    var pair = try gate_pair();
    defer pair.deinit();
    try pair.open();
    var gate = pair.gate;
    defer gate.deinit();
    const synced = try run_sync(SlowSyncDb, &gate, 0, tips.receiver);
    // The converged anchor remains on the highest tip seen.
    try testing.expect(synced.anchor.eql(anchor(2)));
    // The target never moves backward.
    try testing.expectEqual(@as(u64, 2), try synced_target(SlowSyncDb, synced));
}

test "stateful state sync: a parked single sync ignores backward tip updates" {
    const tips = try ring.channel(Update, gpa, io, 4);
    var sender = tips.sender;
    var pair = try gate_pair();
    defer pair.deinit();
    var gate = pair.gate;
    defer gate.deinit();
    var future = try io.concurrent(Gated(SlowSyncDb).run, .{ &gate, 0, tips.receiver });
    try pair.park();
    // Each tip reaches the parked coordinator's select, one at a time.
    for ([_]u64{ 2, 1 }) |target| {
        var observed = try Update.with_observation(gpa, io, anchor(target), target);
        try testing.expect(sender.send_lossy(observed.update));
        defer observed.observed.deinit();
        try observed.observed.recv();
    }
    sender.deinit();
    try pair.open();
    const synced = try future.await(io);
    try testing.expect(synced.anchor.eql(anchor(2)));
    try testing.expectEqual(@as(u64, 2), try synced_target(SlowSyncDb, synced));
}

test "stateful state sync: a single sync advances the anchor without a duplicate target" {
    const tips = try ring.channel(Update, gpa, io, 4);
    var sender = tips.sender;
    var pair = try gate_pair();
    defer pair.deinit();
    var gate = pair.gate;
    defer gate.deinit();
    const run = Gated(RejectDuplicateTargetSyncDb).run;
    var future = try io.concurrent(run, .{ &gate, 7, tips.receiver });
    // Park the coordinator so the tip reaches its select rather than the initial drain. The
    // tip advances the anchor but repeats the target; the coordinator records it.
    try pair.park();
    var observed = try Update.with_observation(gpa, io, anchor(9), 7);
    try testing.expect(sender.send_lossy(observed.update));
    defer observed.observed.deinit();
    try observed.observed.recv();
    // The database never receives a duplicate target and finishes at its initial one.
    try pair.open();
    sender.deinit();
    const synced = try future.await(io);
    try testing.expect(!gate.duplicate);
    try testing.expect(synced.anchor.eql(anchor(9)));
    try testing.expectEqual(@as(u64, 7), try synced_target(RejectDuplicateTargetSyncDb, synced));
}

test "stateful state sync: a single sync ignores a stale reached report after a forwarded tip" {
    var tips = try ring.channel(Update, gpa, io, 4);
    defer tips.sender.deinit();
    try testing.expect(tips.sender.send_lossy(.init(anchor(2), 2)));
    const synced = try run_sync(StaleReachedSyncDb, {}, 0, tips.receiver);
    // The sync does not finish on the stale report, and the anchor matches what it reached.
    try testing.expect(synced.anchor.eql(anchor(2)));
    try testing.expectEqual(@as(u64, 2), try synced_target(StaleReachedSyncDb, synced));
}

test "stateful state sync: a single sync records tips while the database is held" {
    const tips = try ring.channel(Update, gpa, io, 4);
    var sender = tips.sender;
    defer sender.deinit();
    var pair = try gate_pair();
    defer pair.deinit();
    var gate = pair.gate;
    defer gate.deinit();
    var future = try io.concurrent(Gated(SlowSyncDb).run, .{ &gate, 0, tips.receiver });
    try pair.park();
    // The coordinator records every tip while the database takes no targets; one that waited
    // for target capacity would stop before recording the third.
    for ([_]u64{ 1, 2, 3 }) |target| {
        var observed = try Update.with_observation(gpa, io, anchor(target), target);
        try testing.expect(sender.send_lossy(observed.update));
        defer observed.observed.deinit();
        try observed.observed.recv();
    }
    // Once released, the database takes the newest target and the sync converges there.
    try pair.open();
    const synced = try future.await(io);
    try testing.expect(synced.anchor.eql(anchor(3)));
    try testing.expectEqual(@as(u64, 3), try synced_target(SlowSyncDb, synced));
}

test "stateful state sync: every adapter implements StateSyncDb" {
    comptime {
        state_sync.assert_state_sync_db(KeylessDb);
        state_sync.assert_state_sync_db(ImmutableDb);
        state_sync.assert_state_sync_db(KeylessCompact);
        state_sync.assert_state_sync_db(ImmutableCompact);
    }
}

// Real databases.

const Family = storage.mmr.Family;
const U64 = utils.sequence.U64;
const contiguous = storage.journal.contiguous;
const KeylessEncoding = qmdb.value.Fixed(U64);
const KeylessDb = keyless.Keyless(
    Family,
    KeylessEncoding,
    contiguous.fixed.Journal(qmdb.keyless.Operation(Family, KeylessEncoding)),
    Sha256,
);
const DigestEncoding = qmdb.value.Fixed(Digest);
const ImmutableDb = immutable.Immutable(
    Family,
    Digest,
    DigestEncoding,
    contiguous.fixed.Journal(qmdb.immutable.Operation(Family, Digest, DigestEncoding)),
    Sha256,
    storage.translator.TwoCap,
);
const KeylessCompact = compact.Compact(
    Family,
    qmdb.keyless.Operation(Family, KeylessEncoding),
    Sha256,
);
const ImmutableCompact = compact.Compact(
    Family,
    qmdb.immutable.Operation(Family, Digest, DigestEncoding),
    Sha256,
);

/// One node's storage, page cache, and metrics.
const Node = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(node: *Node) !void {
        node.* = .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(node: *Node) void {
        node.registry.deinit();
        node.cache_ref.deinit();
        node.storage.deinit();
    }

    fn env(node: *Node) db.Env {
        return .{
            .gpa = gpa,
            .io = io,
            .storage = node.storage.interface(),
            .scope = metrics.Scope.init(&node.registry).child("db"),
        };
    }

    fn merkle_config(node: *Node) storage.merkle.full.Config {
        return .{
            .journal_partition = "state-sync-journal",
            .metadata_partition = "state-sync-metadata",
            .items_per_blob = 11,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &node.cache_ref,
        };
    }

    fn log_config(node: *Node) contiguous.fixed.Config {
        return .{
            .partition = "state-sync-log",
            .items_per_blob = 7,
            .cache_ref = &node.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
    }

    fn keyless_config(node: *Node) KeylessDb.Config {
        return .{ .merkle = node.merkle_config(), .log = node.log_config() };
    }

    fn immutable_config(node: *Node) ImmutableDb.Config {
        return .{
            .merkle = node.merkle_config(),
            .log = node.log_config(),
            .translator = .{},
        };
    }

    fn compact_config(node: *Node, comptime A: type) A.Config {
        return .{
            .witness = .{
                .partition = "state-sync-compact-witness",
                .items_per_section = 64,
                .codec_config = {},
                .cache_ref = &node.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .codec_config = {},
        };
    }
};

/// A tip channel whose sender is closed: syncs to the initial target only.
fn closed_tips(comptime T: type) !ring.Receiver(sync.TipUpdate(Digest, T)) {
    var tips = try ring.channel(sync.TipUpdate(Digest, T), gpa, io, 1);
    tips.sender.deinit();
    return tips.receiver;
}

/// Syncs `T` to `target` at `anchor(1)` with no later tips.
fn sync_closed(
    comptime T: type,
    env: db.Env,
    config: T.Config,
    source: anytype,
    target: T.SyncTarget,
    sync_config: state_sync.SyncEngineConfig,
) !state_sync.Synced(T, Digest) {
    const tips = try closed_tips(T.SyncTarget);
    const start = anchor(1);
    return state_sync.sync_shared(T, Digest, env, config, source, start, target, tips, sync_config);
}

/// Seeds `shared` with `count` applied and finalized batches built by `fill(batch, i)`.
fn seed(shared: anytype, count: u64, fill: anytype) !void {
    for (0..count) |i| {
        var batch = try shared.new_batches();
        errdefer batch.deinit();
        try fill(&batch, i);
        var merkleized = try batch.merkleize();
        defer merkleized.deinit();
        try shared.apply(&merkleized);
    }
    const barrier = try shared.finalize();
    try barrier.durable();
}

fn fill_keyless(batch: *KeylessDb.Unmerkleized, i: u64) !void {
    for (0..5) |j| try batch.append(U64.init(i * 10 + j));
    batch.with_metadata(U64.init(1000 + i));
}

fn fill_immutable(batch: *ImmutableDb.Unmerkleized, i: u64) !void {
    for (0..5) |j| {
        var bytes: [16]u8 = undefined;
        std.mem.writeInt(u64, bytes[0..8], i, .big);
        std.mem.writeInt(u64, bytes[8..16], j, .big);
        try batch.set(Sha256.hash(&.{&bytes}), Sha256.hash(&.{bytes[8..]}));
    }
}

/// Syncs a fresh `T` on its own node from a populated source served from its journal, and
/// checks the synced database reached the source's target.
fn expect_standard_sync(
    comptime T: type,
    comptime configure: anytype,
    comptime fill: anytype,
) !void {
    var source_node: Node = undefined;
    try source_node.init();
    defer source_node.deinit();
    const source = try T.Shared.open(source_node.env(), configure(&source_node), null);
    defer source.deinit();
    try seed(source, 4, fill);
    const target = try source.committed_targets();

    var guard = try source.read();
    defer guard.deinit();
    const Journal = T.SyncDatabase.Db.Journal;
    var journal_source: qmdb.sync.JournalSource(Family, Journal) = .{
        .journal = &guard.get().inner.journal,
    };
    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    const synced = try sync_closed(T, node.env(), configure(&node), &journal_source, target, .{
        .fetch_batch_size = 3,
        .apply_batch_size = 2,
        .max_outstanding_requests = 2,
    });
    defer synced.databases.deinit();
    try testing.expect(synced.anchor.eql(anchor(1)));
    const reached = try synced.databases.committed_targets();
    try testing.expect(db.targets_eql(T.SyncTarget, &reached, &target));
}

test "stateful state sync: a keyless database syncs from a populated one" {
    try expect_standard_sync(KeylessDb, Node.keyless_config, fill_keyless);
}

test "stateful state sync: an immutable database syncs from a populated one" {
    try expect_standard_sync(ImmutableDb, Node.immutable_config, fill_immutable);
}

test "stateful state sync: an engine that cannot open releases the sync's reporter" {
    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    var journal: KeylessDb.SyncDatabase.Db.Journal = undefined;
    const Source = qmdb.sync.JournalSource(Family, @TypeOf(journal));
    var journal_source: Source = .{ .journal = &journal };
    // An end past the largest valid location: the engine rejects it before opening anything.
    // The coordinator waits on the reporter, so a leaked one hangs the sync.
    const invalid: KeylessDb.SyncTarget = .init(.{ .bytes = @splat(1) }, 0, std.math.maxInt(u64));
    const config = node.keyless_config();
    const source = &journal_source;
    const result = sync_closed(KeylessDb, node.env(), config, source, invalid, engine_config);
    try testing.expectError(error.InvalidTarget, result);
}

/// A compact database served as a sync source (commonware's `Arc<Db>: Source`).
fn CompactSource(comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Family = D.Family;
        pub const Op = D.Operation;
        pub const Digest = D.Digest;
        const Served = @typeInfo(@TypeOf(D.serve)).@"fn".return_type.?;
        pub const Error = @typeInfo(Served).error_union.error_set;
        const Response = qmdb.sync.Response(D.Family, D.Operation, D.Digest);

        db: *D,

        pub fn serve(
            self: *Self,
            _: std.mem.Allocator,
            request: qmdb.sync.Request(D.Family),
        ) (Error || std.Io.Cancelable)!qmdb.sync.Served(Response) {
            return .{ .response = try self.db.serve(request), .feedback = null };
        }
    };
}

/// commonware's `state_sync_fetches_compact_state`: a fresh compact database syncs the state
/// of a compact source with one synced batch.
fn expect_compact_sync(comptime A: type, comptime mutate: anytype) !void {
    var source_node: Node = undefined;
    try source_node.init();
    defer source_node.deinit();
    const source = try A.Shared.open(source_node.env(), source_node.compact_config(A), null);
    defer source.deinit();
    try seed(source, 1, mutate);
    const target = try source.committed_targets();

    var guard = try source.read();
    defer guard.deinit();
    var compact_source: CompactSource(A.Database) = .{ .db = &guard.get().inner };
    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    const config = node.compact_config(A);
    const synced = try sync_closed(A, node.env(), config, &compact_source, target, engine_config);
    defer synced.databases.deinit();
    const reached = try synced.databases.committed_targets();
    try testing.expect(reached.eql(target));
    var synced_guard = try synced.databases.read();
    defer synced_guard.deinit();
    const metadata = try synced_guard.get().inner.get_metadata();
    try testing.expect(std.meta.eql(metadata, try guard.get().inner.get_metadata()));
}

fn mutate_keyless_compact(batch: *KeylessCompact.Unmerkleized, _: u64) !void {
    try batch.append(U64.init(7));
    batch.with_metadata(U64.init(1007));
}

fn mutate_immutable_compact(batch: *ImmutableCompact.Unmerkleized, _: u64) !void {
    try batch.set(Sha256.hash(&.{"key"}), Sha256.hash(&.{"value"}));
    batch.with_metadata(Sha256.hash(&.{"metadata"}));
}

test "stateful state sync: compact databases fetch compact state" {
    try expect_compact_sync(KeylessCompact, mutate_keyless_compact);
    try expect_compact_sync(ImmutableCompact, mutate_immutable_compact);
}

test "stateful state sync: an unconvertible compact target fails the sync" {
    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    var unused: KeylessCompact.Database = undefined;
    var compact_source: CompactSource(KeylessCompact.Database) = .{ .db = &unused };
    const zero: KeylessCompact.SyncTarget = .{ .root = .{ .bytes = @splat(0) }, .size = 0 };
    const config = node.compact_config(KeylessCompact);
    const source = &compact_source;
    const result = sync_closed(KeylessCompact, node.env(), config, source, zero, engine_config);
    try testing.expectError(error.InvalidTarget, result);
}

// Tuple sets.

const state_sync_tuple = @import("state_sync_tuple.zig");

fn Pair(comptime A: type, comptime B: type) type {
    const types = .{ A, B };
    return struct {
        const Targets = db.Tuple(types).SyncTargets;
        const TipUpdates = ring.Receiver(sync.TipUpdate(Digest, Targets));
        const Result = state_sync_tuple.Synced(types, Digest);

        /// Syncs the pair from `sources` at `anchor(start)` toward `targets`.
        fn run(
            sources: anytype,
            start: u64,
            targets: Targets,
            tips: TipUpdates,
            failure: ?*?state_sync_tuple.Failure,
        ) !Result {
            const env: TestEnv = .{};
            const config = .{ {}, {} };
            const at = anchor(start);
            return state_sync_tuple.sync_tuple(
                types,
                Digest,
                env,
                config,
                sources,
                at,
                targets,
                tips,
                engine_config,
                failure,
            );
        }

        /// `run` over two gates, as a task function.
        fn run_gated(a: *Gate, b: *Gate, start: u64, targets: Targets, tips: TipUpdates) !Result {
            return run(.{ a, b }, start, targets, tips, null);
        }

        fn channel(capacity: usize) !ring.Pair(sync.TipUpdate(Digest, Targets)) {
            return ring.channel(sync.TipUpdate(Digest, Targets), gpa, io, capacity);
        }

        /// The members' final targets; closes the set.
        fn finals(result: Result) !struct { u64, u64 } {
            var synced = result;
            defer synced.databases.deinit();
            var first = try synced.databases.members[0].read();
            defer first.deinit();
            var second = try synced.databases.members[1].read();
            defer second.deinit();
            return .{ first.get().final_target, second.get().final_target };
        }
    };
}

/// A gate already open: the database starts at once (commonware's fast databases).
fn open_gate() !GatePair {
    var pair = try gate_pair();
    try pair.open();
    return pair;
}

test "stateful state sync: a tuple sync converges before finishing" {
    const P = Pair(SlowSyncDb, SlowSyncDb);
    const tips = try P.channel(4);
    var sender = tips.sender;
    var slow = try gate_pair();
    defer slow.deinit();
    var fast = try open_gate();
    defer fast.deinit();
    defer slow.gate.deinit();
    defer fast.gate.deinit();
    const gates = .{ &slow.gate, &fast.gate };
    var future = try io.concurrent(P.run_gated, gates ++ .{ 0, .{ 0, 0 }, tips.receiver });
    try fast.park();
    try testing.expect(sender.send_lossy(.init(anchor(1), .{ 1, 1 })));
    try testing.expect(sender.send_lossy(.init(anchor(2), .{ 2, 2 })));
    try slow.open();
    sender.deinit();
    const synced = try future.await(io);
    const finals = try P.finals(synced);
    // Every database finishes on the converged targets, those of the returned anchor.
    try testing.expectEqual(finals[0], finals[1]);
    try testing.expectEqual(finals[0], synced.anchor.height.get());
}

test "stateful state sync: a tuple sync ignores backward tip updates" {
    const P = Pair(SlowSyncDb, SlowSyncDb);
    const tips = try P.channel(8);
    var sender = tips.sender;
    var slow = try gate_pair();
    defer slow.deinit();
    var fast = try open_gate();
    defer fast.deinit();
    defer slow.gate.deinit();
    defer fast.gate.deinit();
    const gates = .{ &slow.gate, &fast.gate };
    var future = try io.concurrent(P.run_gated, gates ++ .{ 0, .{ 0, 0 }, tips.receiver });
    try fast.park();
    try testing.expect(sender.send_lossy(.init(anchor(2), .{ 2, 2 })));
    const Tip = sync.TipUpdate(Digest, P.Targets);
    var backward = try Tip.with_observation(gpa, io, anchor(1), .{ 1, 1 });
    defer backward.observed.deinit();
    try testing.expect(sender.send_lossy(backward.update));
    sender.deinit();
    try backward.observed.recv(); // The coordinator records the backward tip.
    try slow.open();
    const synced = try future.await(io);
    // Neither target moves backward, and the anchor stays on the highest tip seen.
    try testing.expect(synced.anchor.eql(anchor(2)));
    try testing.expectEqual(.{ @as(u64, 2), @as(u64, 2) }, try P.finals(synced));
}

test "stateful state sync: a tuple sync rejects a database target mismatch" {
    const P = Pair(MismatchedTargetSyncDb, SlowSyncDb);
    var tips = try P.channel(1);
    defer tips.sender.deinit();
    var fast = try open_gate();
    defer fast.deinit();
    defer fast.gate.deinit();
    const result = P.run(.{ {}, &fast.gate }, 7, .{ 7, 7 }, tips.receiver, null);
    try testing.expectError(error.SyncTargetMismatch, result);
}

/// Checks a tuple sync failed with the error of the `FailingStateSyncDb` at index 1.
fn expect_second_failed(result: anytype, failure: ?state_sync_tuple.Failure) !void {
    try testing.expectError(error.TestSyncError, result);
    const first = failure.?;
    try testing.expectEqual(@as(usize, 1), first.index);
    try testing.expect(std.mem.indexOf(u8, first.name, "FailingSync") != null);
    try testing.expectEqual(error.TestSyncError, first.err);
}

test "stateful state sync: a tuple sync returns a database's error when the anchor is missing" {
    const P = Pair(ImmediateStateSyncDb, FailingStateSyncDb);
    var tips = try P.channel(1);
    defer tips.sender.deinit();
    var failure: ?state_sync_tuple.Failure = null;
    const result = P.run(.{ {}, {} }, 0, .{ 0, 0 }, tips.receiver, &failure);
    try expect_second_failed(result, failure);
}

test "stateful state sync: a tuple sync returns a database's error while another waits" {
    const P = Pair(SlowSyncDb, FailingStateSyncDb);
    var tips = try P.channel(1);
    defer tips.sender.deinit();
    var slow = try open_gate();
    defer slow.deinit();
    defer slow.gate.deinit();
    var failure: ?state_sync_tuple.Failure = null;
    const result = P.run(.{ &slow.gate, {} }, 0, .{ 0, 0 }, tips.receiver, &failure);
    try expect_second_failed(result, failure);
}

test "stateful state sync: a tuple sync keeps the original failure when a finish channel closes" {
    const P = Pair(FinishClosedSyncDb, FailingStateSyncDb);
    var tips = try P.channel(1);
    defer tips.sender.deinit();
    var failure: ?state_sync_tuple.Failure = null;
    // The failure stops the coordinator, which closes the other database's finish channel;
    // that database's later error is not the one returned.
    const result = P.run(.{ {}, {} }, 0, .{ 0, 0 }, tips.receiver, &failure);
    try expect_second_failed(result, failure);
}

test "stateful state sync: a reached tuple member takes no updates until a regroup" {
    const P = Pair(ObservedSlowSyncDb, ObservedFastSyncDb);
    const tips = try P.channel(32);
    var sender = tips.sender;
    var slow = try open_gate();
    defer slow.deinit();
    var fast = try open_gate();
    defer fast.deinit();
    defer slow.gate.deinit();
    defer fast.gate.deinit();
    const gates = .{ &slow.gate, &fast.gate };
    var future = try io.concurrent(P.run_gated, gates ++ .{ 0, .{ 0, 0 }, tips.receiver });
    try fast.park();
    for (1..17) |target| {
        try testing.expect(sender.send_lossy(.init(anchor(target), .{ target, target })));
    }
    sender.deinit();
    const synced = try future.await(io);
    const finals = try P.finals(synced);
    try testing.expectEqual(finals[0], finals[1]);
    try testing.expectEqual(finals[0], synced.anchor.height.get());
    // A reached database must not receive tip updates before the regroup; only the regroup's
    // retarget reaches it.
    try testing.expectEqual(@as(u64, 1), fast.gate.updates);
}

test "stateful state sync: a tuple member at its target idles while another catches up" {
    const P = Pair(SlowSyncDb, ObservedFastSyncDb);
    var tips = try P.channel(4);
    var slow = try gate_pair();
    defer slow.deinit();
    var fast = try open_gate();
    defer fast.deinit();
    defer slow.gate.deinit();
    defer fast.gate.deinit();
    const gates = .{ &slow.gate, &fast.gate };
    var future = try io.concurrent(P.run_gated, gates ++ .{ 7, .{ 7, 7 }, tips.receiver });
    try fast.park();
    tips.sender.deinit();
    try slow.open();
    const synced = try future.await(io);
    try testing.expect(synced.anchor.eql(anchor(7)));
    try testing.expectEqual(.{ @as(u64, 7), @as(u64, 7) }, try P.finals(synced));
    // The database already at its target receives no tip updates.
    try testing.expectEqual(@as(u64, 0), fast.gate.updates);
}

test "stateful state sync: a tuple regroup completes when a database's target is unchanged" {
    const P = Pair(SlowSyncDb, DistinctObservedFastSyncDb);
    const tips = try P.channel(4);
    var sender = tips.sender;
    var slow = try gate_pair();
    defer slow.deinit();
    var fast = try open_gate();
    defer fast.deinit();
    defer slow.gate.deinit();
    defer fast.gate.deinit();
    const gates = .{ &slow.gate, &fast.gate };
    var future = try io.concurrent(P.run_gated, gates ++ .{ 0, .{ 0, 7 }, tips.receiver });
    try fast.park();
    const Tip = sync.TipUpdate(Digest, P.Targets);
    var update = try Tip.with_observation(gpa, io, anchor(9), .{ 9, 7 });
    defer update.observed.deinit();
    try testing.expect(sender.send_lossy(update.update));
    try update.observed.recv(); // The coordinator records the tip.
    try slow.open();
    sender.deinit();
    const synced = try future.await(io);
    try testing.expect(synced.anchor.eql(anchor(9)));
    try testing.expectEqual(.{ @as(u64, 9), @as(u64, 7) }, try P.finals(synced));
    // The unchanged-target database receives no duplicate target updates.
    try testing.expectEqual(@as(u64, 0), fast.gate.updates);
}
