//! State sync of `current` databases (commonware's `qmdb/current/sync/tests.rs`), over
//! unordered and ordered, fixed and variable databases of both families: syncs against the ops
//! root rebuild the source's canonical root, from genesis and from the sync boundary of a
//! pruned source, and survive a reopen (`test_current_mmb_sync_with_pruned_full_chunk_reopens`
//! across every variant); a synced database accepts further batches; a client whose storage
//! holds another pruned database discards it, grafted metadata included; and local pinned
//! nodes use the last commit's floor (`test_local_pinned_nodes_below_floor`).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const sync = @import("../sync/mod.zig");
const qmdb_support = @import("../test_support.zig");
const current_sync = @import("sync.zig");
const support = @import("test_support.zig");

const Digest = support.Digest;
const Sha256 = support.Sha256;
const metrics = runtime.telemetry.metrics;
const gpa = testing.allocator;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;

const all_syncs = .{
    current_sync.Database(support.UnorderedFixed(Mmr), Sha256),
    current_sync.Database(support.UnorderedFixed(Mmb), Sha256),
    current_sync.Database(support.OrderedFixed(Mmr), Sha256),
    current_sync.Database(support.OrderedFixed(Mmb), Sha256),
    current_sync.Database(support.UnorderedVariable(Mmr), Sha256),
    current_sync.Database(support.UnorderedVariable(Mmb), Sha256),
    current_sync.Database(support.OrderedVariable(Mmr), Sha256),
    current_sync.Database(support.OrderedVariable(Mmb), Sha256),
};

comptime {
    for (all_syncs) |S| sync.database.assert_database(S);
}

fn Source(comptime S: type) type {
    return sync.JournalSource(S.Family, S.Db.Any.Log);
}

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    /// One page cache per database: the engine's tasks read the source while they write the
    /// target, and a page cache is not shared across tasks.
    cache_ref: runtime.buffer.paged.CacheRef,
    target_cache_ref: runtime.buffer.paged.CacheRef,
    source_registry: metrics.Registry,
    target_registry: metrics.Registry,

    fn init() !Harness {
        return .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .target_cache_ref = try .init(gpa, 101, 11),
            .source_registry = .init(gpa),
            .target_registry = .init(gpa),
        };
    }

    fn deinit(self: *Harness) void {
        self.target_registry.deinit();
        self.source_registry.deinit();
        self.target_cache_ref.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg(self: *Harness, comptime S: type, comptime prefix: []const u8) S.Config {
        const is_target = comptime std.mem.eql(u8, prefix, "target");
        const cache_ref = if (is_target) &self.target_cache_ref else &self.cache_ref;
        var log = qmdb_support.log_config(@FieldType(S.Config, "log"), cache_ref);
        log.partition = prefix ++ "-log";
        return .{
            .merkle = .{
                .journal_partition = prefix ++ "-merkle",
                .metadata_partition = prefix ++ "-metadata",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = cache_ref,
            },
            .log = log,
            .grafted_metadata_partition = prefix ++ "-grafted",
            .translator = .{},
            .init_cache = 3,
        };
    }

    fn registry(self: *Harness, comptime prefix: []const u8) *metrics.Registry {
        const is_target = comptime std.mem.eql(u8, prefix, "target");
        return if (is_target) &self.target_registry else &self.source_registry;
    }

    fn open(self: *Harness, comptime S: type, comptime prefix: []const u8) !S.Db {
        const reg = self.registry(prefix);
        reg.deinit();
        reg.* = .init(gpa);
        const scope = metrics.Scope.init(reg).child("db");
        const storage = self.storage.interface();
        return S.Db.init(gpa, storage, scope, self.cfg(S, prefix), null);
    }

    /// A fresh registry per sync, as commonware gives each sync a fresh context.
    fn target_scope(self: *Harness) metrics.Scope {
        self.target_registry.deinit();
        self.target_registry = .init(gpa);
        return metrics.Scope.init(&self.target_registry).child("db");
    }
};

/// `count` writes of keys `0..count` from `seed` (one in seven deleted), applied and committed.
fn apply_ops(comptime S: type, db: *S.Db, count: u64, seed: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (0..count) |i| {
            const k = support.to_digest(i);
            const v: ?Digest = if ((i + seed) % 7 == 6) null else support.to_val(i, seed);
            try batch.write(k, v);
        }
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
    try db.commit();
}

fn sync_from(comptime S: type, harness: *Harness, source: *Source(S), target: S.Target) !S {
    return sync.sync(S, Source(S), gpa, testing.io, .{
        .storage = harness.storage.interface(),
        .scope = harness.target_scope(),
        .source = source,
        .target = target,
        .max_outstanding_requests = 4,
        .fetch_batch_size = 64,
        .apply_batch_size = 16,
        .db_config = harness.cfg(S, "target"),
    });
}

fn expect_same_state(comptime S: type, a: *S.Db, b: *S.Db, count: u64) !void {
    try testing.expect(a.root().eql(b.root()));
    try testing.expect(a.ops_root().eql(b.ops_root()));
    try testing.expectEqual(a.bounds().end, b.bounds().end);
    try testing.expectEqual(a.inactivity_floor(), b.inactivity_floor());
    for (0..count) |i| {
        const k = support.to_digest(i);
        const x = try a.get(&k);
        const y = try b.get(&k);
        try testing.expectEqual(x == null, y == null);
        if (x) |v| try testing.expect(v.eql(y.?));
    }
}

/// Rewrites 40 keys a round, pruning to the sync boundary each time, until a full bitmap chunk
/// is pruned (commonware's repeated rewrites past a 256-bit chunk).
fn pruned_source(comptime S: type, db: *S.Db) !void {
    var round: u64 = 0;
    while (db.any.bitmap.pruned_chunks() == 0) : (round += 1) {
        if (round == 256) return error.NeverPrunedAChunk;
        try apply_ops(S, db, 40, round);
        try db.prune(db.sync_boundary());
    }
    try testing.expect(db.sync_boundary() >= S.Db.chunk_bytes * 8);
}

// Commonware's `test_current_mmb_sync_with_pruned_full_chunk_reopens`, over every variant,
// plus a sync from genesis.
test "current sync rebuilds the canonical root from genesis and a pruned source" {
    inline for (all_syncs) |S| {
        var harness = try Harness.init();
        defer harness.deinit();
        var source_db = try harness.open(S, "source");
        defer source_db.deinit();
        try apply_ops(S, &source_db, 60, 0);
        var source: Source(S) = .{ .journal = &source_db.any.log };
        {
            const end = source_db.bounds().end;
            var synced = try sync_from(S, &harness, &source, .init(source_db.ops_root(), 0, end));
            errdefer synced.deinit();
            try expect_same_state(S, &synced.db, &source_db, 60);
            try synced.db.destroy(); // Closes it.
        }
        try pruned_source(S, &source_db);
        const start = source_db.sync_boundary();
        const target: S.Target = .init(source_db.ops_root(), start, source_db.bounds().end);
        var synced = try sync_from(S, &harness, &source, target);
        try expect_same_state(S, &synced.db, &source_db, 40);
        try testing.expectEqual(start, synced.db.sync_boundary());
        synced.deinit();
        var reopened = try harness.open(S, "target");
        defer reopened.deinit();
        try expect_same_state(S, &reopened, &source_db, 40);
        try testing.expectEqual(start, reopened.sync_boundary());
    }
}

// Commonware's `test_sync_post_sync_usability`.
test "current synced database accepts further batches" {
    inline for (all_syncs) |S| {
        var harness = try Harness.init();
        defer harness.deinit();
        var source_db = try harness.open(S, "source");
        defer source_db.deinit();
        try apply_ops(S, &source_db, 50, 0);
        const end = source_db.bounds().end;
        var source: Source(S) = .{ .journal = &source_db.any.log };
        const target: S.Target = .init(source_db.ops_root(), source_db.sync_boundary(), end);
        var synced = try sync_from(S, &harness, &source, target);
        defer synced.deinit();
        const root = synced.db.root();
        try apply_ops(S, &synced.db, 10, 1);
        try testing.expect(!synced.db.root().eql(root));
        try testing.expect(synced.db.bounds().end > end);
    }
}

test "current sync replaces a client's unrelated pruned database" {
    inline for (all_syncs) |S| {
        var harness = try Harness.init();
        defer harness.deinit();
        {
            var client = try harness.open(S, "target");
            defer client.deinit();
            try pruned_source(S, &client);
            try apply_ops(S, &client, 7, 99);
            try client.sync();
        }
        var source_db = try harness.open(S, "source");
        defer source_db.deinit();
        try apply_ops(S, &source_db, 30, 5);
        var source: Source(S) = .{ .journal = &source_db.any.log };
        const end = source_db.bounds().end;
        var synced = try sync_from(S, &harness, &source, .init(source_db.ops_root(), 0, end));
        try expect_same_state(S, &synced.db, &source_db, 40);
        synced.deinit();
        var reopened = try harness.open(S, "target");
        defer reopened.deinit();
        try expect_same_state(S, &reopened, &source_db, 40);
    }
}

// Commonware's `test_local_pinned_nodes_below_floor`, which also runs on current.
test "current local pinned nodes use the last commit's floor" {
    inline for (all_syncs) |S| {
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.cfg(S, "source");
        var db = try harness.open(S, "source");
        var round: u64 = 0;
        while (true) : (round += 1) {
            if (round == 64) {
                db.deinit();
                return error.FloorNeverPassedAPeak;
            }
            try apply_ops(S, &db, 100, round);
            const end = db.bounds().end;
            const below = merkle.inactive_peaks(S.Family, end, db.inactivity_floor());
            if (below > merkle.inactive_peaks(S.Family, end, 1)) break;
        }
        const target: S.Target = .init(db.ops_root(), 1, db.bounds().end);
        try db.sync();
        db.deinit();
        const storage = harness.storage.interface();
        const bounds: sync.journal.Bounds = .{ .start = target.start, .end = target.end };
        var log = try sync.journal.init(S.Journal, gpa, storage, S.journal_config(cfg), bounds);
        defer log.deinit();
        const pins = try S.local_pinned_nodes(gpa, storage, cfg, target, &log);
        try testing.expect(pins != null);
        gpa.free(pins.?);
    }
}
