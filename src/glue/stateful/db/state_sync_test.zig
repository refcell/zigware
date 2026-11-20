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
/// The test I/O: threaded, except while `run_on_deterministic` runs a test on a runner.
var io: std.Io = testing.io;
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
    io: std.Io,
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
    /// Targets a looping database reported reached (read by the test while it runs).
    reports: std.atomic.Value(u32) = .init(0),

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

    /// `park`, after the database's first reached report: tips that follow find it reached.
    /// Only under `run_on_deterministic`, whose simulated sleep lets the coordinator take the
    /// report first, as commonware's deterministic runtime does; on threads a starved reporter
    /// can still be behind the tips.
    fn park_reported(pair: *GatePair) !void {
        std.debug.assert(io.userdata != testing.io.userdata); // Under `run_on_deterministic`.
        try pair.started.recv();
        var waited: u32 = 0;
        while (pair.gate.reports.load(.acquire) == 0) : (waited += 1) {
            if (waited > 10_000) return error.TestTimedOut;
            try io.sleep(.fromMilliseconds(1), .awake);
        }
        std.debug.assert(pair.gate.reports.load(.acquire) > 0);
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
                    _ = gate.reports.fetchAdd(1, .release);
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
    const env: TestEnv = .{ .io = io };
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

    // Each request is served under the source's lock (commonware's `Shared<DB>: Source`).
    var shared_source: state_sync.SharedSource(T) = .{ .shared = source };
    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    const synced = try sync_closed(T, node.env(), configure(&node), &shared_source, target, .{
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

    var shared_source: state_sync.SharedSource(A) = .{ .shared = source };
    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    const config = node.compact_config(A);
    const synced = try sync_closed(A, node.env(), config, &shared_source, target, engine_config);
    defer synced.databases.deinit();
    const reached = try synced.databases.committed_targets();
    try testing.expect(reached.eql(target));
    var synced_guard = try synced.databases.read();
    defer synced_guard.deinit();
    const metadata = try synced_guard.get().inner.get_metadata();
    var guard = try source.read();
    defer guard.deinit();
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

// commonware `StateSyncDb::sync_db`: an unreachable target, here a compact one covering more
// than its last commit, fails the sync before any request.
test "stateful state sync: a compact target wider than one commit fails the sync" {
    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    var unused: KeylessCompact.Database = undefined;
    var compact_source: KeylessCompact.SyncSource = .{ .database = &unused };
    const wide: KeylessCompact.SyncTarget = .init(.{ .bytes = @splat(0) }, 0, 2);
    const config = node.compact_config(KeylessCompact);
    const source = &compact_source;
    const result = sync_closed(KeylessCompact, node.env(), config, source, wide, engine_config);
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
            const env: TestEnv = .{ .io = io };
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

        /// `run` with a sourceless first database and a gated second, as a task function.
        fn run_gated_second(b: *Gate, start: u64, targets: Targets, tips: TipUpdates) !Result {
            return run(.{ {}, b }, start, targets, tips, null);
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
    try run_on_deterministic(tuple_converges_before_finishing);
}

fn tuple_converges_before_finishing() anyerror!void {
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
    try run_on_deterministic(tuple_ignores_backward_tips);
}

fn tuple_ignores_backward_tips() anyerror!void {
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
    try run_on_deterministic(tuple_rejects_target_mismatch);
}

fn tuple_rejects_target_mismatch() anyerror!void {
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
    try run_on_deterministic(tuple_fails_without_anchor);
}

fn tuple_fails_without_anchor() anyerror!void {
    const P = Pair(ImmediateStateSyncDb, FailingStateSyncDb);
    var tips = try P.channel(1);
    defer tips.sender.deinit();
    var failure: ?state_sync_tuple.Failure = null;
    const result = P.run(.{ {}, {} }, 0, .{ 0, 0 }, tips.receiver, &failure);
    try expect_second_failed(result, failure);
}

test "stateful state sync: a tuple sync returns a database's error while another waits" {
    try run_on_deterministic(tuple_fails_while_another_waits);
}

fn tuple_fails_while_another_waits() anyerror!void {
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
    try run_on_deterministic(tuple_keeps_original_failure);
}

fn tuple_keeps_original_failure() anyerror!void {
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
    try run_on_deterministic(reached_member_takes_no_updates);
}

fn reached_member_takes_no_updates() anyerror!void {
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
    try fast.park_reported();
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
    try run_on_deterministic(member_at_target_idles);
}

fn member_at_target_idles() anyerror!void {
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
    try fast.park_reported();
    tips.sender.deinit();
    try slow.open();
    const synced = try future.await(io);
    try testing.expect(synced.anchor.eql(anchor(7)));
    try testing.expectEqual(.{ @as(u64, 7), @as(u64, 7) }, try P.finals(synced));
    // The database already at its target receives no tip updates.
    try testing.expectEqual(@as(u64, 0), fast.gate.updates);
}

test "stateful state sync: a tuple regroup completes when a database's target is unchanged" {
    try run_on_deterministic(regroup_completes_unchanged_target);
}

fn regroup_completes_unchanged_target() anyerror!void {
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
    try fast.park_reported();
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

// Attaching resolvers.

/// Records the order resolvers are attached in (commonware's `RecordingResolver`).
const AttachLog = struct {
    ids: [4][]const u8 = undefined,
    len: usize = 0,
};

const RecordingResolver = struct {
    id: []const u8,
    log: *AttachLog,

    pub fn attach_database(self: RecordingResolver, _: anytype) !void {
        self.log.ids[self.log.len] = self.id;
        self.log.len += 1;
    }
};

fn attach_db() !db.Shared(SyncMock(ImmediateSync)) {
    return db.Shared(SyncMock(ImmediateSync)).init(gpa, io, "test", .{ .final_target = 0 });
}

test "stateful state sync: a single database attaches to its resolver" {
    var log: AttachLog = .{};
    const shared = try attach_db();
    defer shared.deinit();
    try state_sync.attach_databases(RecordingResolver{ .id = "db1", .log = &log }, shared);
    try testing.expectEqual(@as(usize, 1), log.len);
    try testing.expectEqualStrings("db1", log.ids[0]);
}

test "stateful state sync: tuple attachment is index-stable" {
    var log: AttachLog = .{};
    const types = .{ SyncMock(ImmediateSync), SyncMock(FailingSync) };
    var databases: db.Tuple(types) = undefined;
    databases.members[0] = try db.Shared(types[0]).init(gpa, io, "0", .{ .final_target = 0 });
    databases.members[1] = try db.Shared(types[1]).init(gpa, io, "1", .{ .final_target = 0 });
    defer databases.deinit();
    const resolvers = .{
        RecordingResolver{ .id = "resolver_0", .log = &log },
        RecordingResolver{ .id = "resolver_1", .log = &log },
    };
    try state_sync.attach_databases(resolvers, databases);
    try testing.expectEqual(@as(usize, 2), log.len);
    try testing.expectEqualStrings("resolver_0", log.ids[0]);
    try testing.expectEqualStrings("resolver_1", log.ids[1]);
}

// Evicted targets and late reports (commonware `LaggingReportSyncDb` and its scenarios).

/// Gates for `LaggingReportSyncDb`: it signals `started` once syncing, and each message on
/// `report` makes it adopt the newest queued target and report every target it reached.
const ReportGates = struct {
    io: std.Io,
    started: ?oneshot.Sender(void),
    report: mpsc.Receiver(void),
};

/// Adopts targets and reports them only when told to, so the coordinator can queue several
/// targets before one is taken and replace a reported target before the report arrives.
const LaggingReportSync = struct {
    fn run(gates: *ReportGates, target: u64, channels: *state_sync.Channels(u64)) !u64 {
        if (gates.started) |*started| started.send({}) catch {}; // Unwatched starts are fine.
        gates.started = null;
        var current = target;
        // Every target reached and not yet reported, in the order reached.
        var unreported: [16]u64 = undefined;
        unreported[0] = target;
        var count: usize = 1;
        while (true) {
            // Like the engine, a requested finish completes at the current target.
            if (channels.finish) |finish| {
                if (finish.try_recv()) |_| break else |err| switch (err) {
                    error.Empty => {},
                    error.Disconnected => break,
                }
            }
            if (gates.report.try_recv()) |_| {
                while (channels.tip_updates.try_recv()) |update| {
                    if (update <= current) continue;
                    current = update;
                    std.debug.assert(count < unreported.len);
                    unreported[count] = update;
                    count += 1;
                } else |_| {}
                if (channels.reached_target) |reached| {
                    for (unreported[0..count]) |value| _ = reached.send_lossy(value);
                }
                count = 0;
            } else |err| switch (err) {
                error.Empty => {},
                error.Disconnected => break,
            }
            try gates.io.sleep(.fromMilliseconds(1), .awake);
        }
        return current;
    }
};
const LaggingReportSyncDb = SyncMock(LaggingReportSync);

fn lagging_sync(
    env: TestEnv,
    gates: *ReportGates,
    tips: ring.Receiver(Update),
) !state_sync.Synced(LaggingReportSyncDb, Digest) {
    const T = LaggingReportSyncDb;
    return state_sync.sync_shared(T, Digest, env, {}, gates, anchor(0), 0, tips, engine_config);
}

/// Runs `body` on a deterministic runtime that fails after 5 simulated seconds.
fn run_deterministic(comptime body: fn (std.Io) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 5 * std.time.ns_per_s };
    try runtime.deterministic.soak(gpa, config, {}, struct {
        fn run(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try try runner.start(body, .{runner.io()});
        }
    }.run);
}

/// A lagging sync started and running, so the coordinator is parked before the test sends.
const LaggingRun = struct {
    gates: ReportGates,
    report: mpsc.Sender(void),
    tips: ring.Sender(Update),
    future: std.Io.Future(anyerror!state_sync.Synced(LaggingReportSyncDb, Digest)),

    fn start(run: *LaggingRun, io_: std.Io, tip_capacity: usize) !void {
        const tips = try ring.channel(Update, gpa, io_, tip_capacity);
        const report = try mpsc.channel(void, gpa, io_, 1);
        var started = try oneshot.channel(void, gpa, io_);
        defer started.receiver.deinit();
        run.gates = .{ .io = io_, .started = started.sender, .report = report.receiver };
        run.report = report.sender;
        run.tips = tips.sender;
        const env: TestEnv = .{ .io = io_ };
        run.future = try io_.concurrent(lagging_sync_any, .{ env, &run.gates, tips.receiver });
        try started.receiver.recv();
    }

    fn lagging_sync_any(
        env: TestEnv,
        gates: *ReportGates,
        tips: ring.Receiver(Update),
    ) anyerror!state_sync.Synced(LaggingReportSyncDb, Digest) {
        return lagging_sync(env, gates, tips);
    }

    /// Sends `heights` without yielding, then waits until the coordinator recorded the last.
    fn burst(run: *LaggingRun, io_: std.Io, first: u64, last: u64) !void {
        var observed: ?oneshot.Receiver(void) = null;
        defer if (observed) |*receiver| receiver.deinit();
        var height = first;
        while (height <= last) : (height += 1) {
            if (observed) |*receiver| receiver.deinit();
            const update = try Update.with_observation(gpa, io_, anchor(height), height);
            observed = update.observed;
            try testing.expect(run.tips.send_lossy(update.update));
        }
        try observed.?.recv();
    }

    /// Closes the tips and the reports, awaits the sync, and checks it converged at `height`.
    fn expect_converged(run: *LaggingRun, io_: std.Io, height: u64) !void {
        run.tips.deinit();
        const synced = try run.future.await(io_);
        run.report.deinit();
        run.gates.report.deinit();
        try testing.expect(synced.anchor.eql(anchor(height)));
        try testing.expectEqual(height, try synced_target(LaggingReportSyncDb, synced));
    }
};

fn converges_after_evicted_targets(io_: std.Io) anyerror!void {
    var run: LaggingRun = undefined;
    try run.start(io_, 2);
    // Each burst overflows the two-slot tip ring, and the two dispatches overflow the
    // one-slot target ring before the database takes a target.
    try run.burst(io_, 1, 3);
    try run.burst(io_, 4, 6);
    // A third burst and a report request are queued without yielding, and the fourth burst
    // evicts the third. The coordinator reads the report of its current target first but
    // adopts the queued tips before finishing, so the sync continues to the newest target.
    for (7..10) |height| try testing.expect(run.tips.send_lossy(.init(anchor(height), height)));
    try run.report.try_send({});
    try run.burst(io_, 10, 12);
    // The database adopts the newest target and reports it, finishing the sync there.
    try run.report.try_send({});
    try run.expect_converged(io_, 12);
}

fn adopts_queued_tip_before_finishing(io_: std.Io) anyerror!void {
    var run: LaggingRun = undefined;
    try run.start(io_, 1);
    // A report of the initial target and a newer tip reach the coordinator together. The
    // report matches the target it last sent, but the queued tip is adopted first.
    var update = try Update.with_observation(gpa, io_, anchor(1), 1);
    defer update.observed.deinit();
    try testing.expect(run.tips.send_lossy(update.update));
    try run.report.try_send({});
    try update.observed.recv();
    // The database takes the tip's target and reports it, finishing the sync there.
    try run.report.try_send({});
    try run.expect_converged(io_, 1);
}

test "stateful state sync: a single sync converges with late reports after evicted targets" {
    try run_deterministic(converges_after_evicted_targets);
}

test "stateful state sync: a single sync adopts a queued tip before finishing" {
    try run_deterministic(adopts_queued_tip_before_finishing);
}

/// Runs `body` with `io` on a deterministic runner, through `runtime.deterministic.soak`:
/// `-Dfuzz-soak` runner seeds (one, the default seed, in a plain `zig build test`), and a
/// failure prints the `-Dfuzz-seed` that replays it.
fn run_on_deterministic(comptime body: fn () anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 5 * std.time.ns_per_s };
    try runtime.deterministic.soak(gpa, config, {}, struct {
        fn run(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            const threaded = io;
            defer io = threaded;
            io = runner.io();
            try try runner.start(struct {
                fn run(_: std.Io) anyerror!void {
                    try body();
                }
            }.run, .{runner.io()});
            std.debug.assert(io.userdata == runner.io().userdata);
        }
    }.run);
}

test "stateful state sync: a tuple sync converges after evicted targets" {
    try run_on_deterministic(tuple_converges_after_evicted_targets);
}

fn tuple_converges_after_evicted_targets() anyerror!void {
    const P = Pair(SlowSyncDb, ObservedFastSyncDb);
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
    try fast.park_reported();
    // Each tip is its own generation while the slow database takes no targets, so its
    // one-slot target ring keeps only the newest.
    const Tip = sync.TipUpdate(Digest, P.Targets);
    for (1..4) |target| {
        var update = try Tip.with_observation(gpa, io, anchor(target), .{ target, target });
        defer update.observed.deinit();
        try testing.expect(sender.send_lossy(update.update));
        try update.observed.recv();
    }
    sender.deinit();
    try slow.open();
    const synced = try future.await(io);
    try testing.expect(synced.anchor.eql(anchor(3)));
    try testing.expectEqual(.{ @as(u64, 3), @as(u64, 3) }, try P.finals(synced));
    // The reached database is retargeted once, at the regroup.
    try testing.expectEqual(@as(u64, 1), fast.gate.updates);
}

test "stateful state sync: a tuple sync ignores a stale reached report after a forwarded tip" {
    try run_on_deterministic(tuple_ignores_stale_reached_report);
}

fn tuple_ignores_stale_reached_report() anyerror!void {
    const P = Pair(StaleReachedSyncDb, ObservedFastSyncDb);
    const tips = try P.channel(4);
    var sender = tips.sender;
    var fast = try open_gate();
    defer fast.deinit();
    defer fast.gate.deinit();
    const run = P.run_gated_second;
    var future = try io.concurrent(run, .{ &fast.gate, 0, P.Targets{ 0, 0 }, tips.receiver });
    // The stale database reports the initial target only after it takes the forwarded tip,
    // then holds there longer than a regroup takes. Accepting the stale report would finish
    // the set at mismatched targets.
    try fast.park_reported();
    try testing.expect(sender.send_lossy(.init(anchor(1), .{ 1, 1 })));
    sender.deinit();
    const synced = try future.await(io);
    try testing.expect(synced.anchor.eql(anchor(1)));
    try testing.expectEqual(.{ @as(u64, 1), @as(u64, 1) }, try P.finals(synced));
    try testing.expectEqual(@as(u64, 1), fast.gate.updates);
}
