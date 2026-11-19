//! State sync of `any` databases (commonware's `qmdb/any/sync/tests.rs`), over unordered and
//! ordered, fixed and variable databases of both families: full syncs from a populated source
//! served through its journal (from genesis and from the sync boundary of a pruned source),
//! usability after sync, `from_sync_result` from an exact, a partial, and an empty local state
//! and from the initial commit alone, local pinned nodes whose floor lies above the target's
//! start, and a wrong root.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const sync = @import("../sync/mod.zig");
const qmdb_support = @import("../test_support.zig");
const any_sync = @import("sync.zig");
const support = @import("test_support.zig");

const Digest = support.Digest;
const metrics = runtime.telemetry.metrics;
const gpa = testing.allocator;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;

const all_syncs = .{
    any_sync.Database(support.UnorderedFixed(Mmr), support.Sha256),
    any_sync.Database(support.UnorderedFixed(Mmb), support.Sha256),
    any_sync.Database(support.OrderedFixed(Mmr), support.Sha256),
    any_sync.Database(support.OrderedFixed(Mmb), support.Sha256),
    any_sync.Database(support.UnorderedVariable(Mmr), support.Sha256),
    any_sync.Database(support.UnorderedVariable(Mmb), support.Sha256),
    any_sync.Database(support.OrderedVariable(Mmr), support.Sha256),
    any_sync.Database(support.OrderedVariable(Mmb), support.Sha256),
};

comptime {
    for (all_syncs) |S| sync.database.assert_database(S);
}

fn Source(comptime S: type) type {
    return sync.JournalSource(S.Family, S.Db.Log);
}

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    /// One page cache shared by source and target, which the engine's tasks read and write
    /// concurrently.
    cache_ref: runtime.buffer.paged.CacheRef,
    source_registry: metrics.Registry,
    target_registry: metrics.Registry,

    fn init() !Harness {
        return .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .source_registry = .init(gpa),
            .target_registry = .init(gpa),
        };
    }

    fn deinit(self: *Harness) void {
        self.target_registry.deinit();
        self.source_registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg(self: *Harness, comptime S: type, comptime prefix: []const u8) S.Config {
        const cache_ref = &self.cache_ref;
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
            .translator = .{},
            .init_cache = 3,
        };
    }

    fn open(self: *Harness, comptime S: type, comptime prefix: []const u8) !S.Db {
        self.source_registry.deinit();
        self.source_registry = .init(gpa);
        const scope = metrics.Scope.init(&self.source_registry).child("db");
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

/// Commonware's `create_ops_seeded(count, seed)` applied and committed: `count` writes of
/// keys `0..count` (rewrites when called again), one key in seven deleted.
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

fn sync_from(
    comptime S: type,
    harness: *Harness,
    source: *Source(S),
    target: S.Target,
    batch_size: u64,
) !S {
    return sync.sync(S, Source(S), gpa, testing.io, .{
        .storage = harness.storage.interface(),
        .scope = harness.target_scope(),
        .source = source,
        .target = target,
        .max_outstanding_requests = 3,
        .fetch_batch_size = batch_size,
        .apply_batch_size = 16,
        .db_config = harness.cfg(S, "target"),
    });
}

/// Every key `apply_ops` touched reads the same from both databases.
fn expect_same_state(comptime S: type, a: *S.Db, b: *S.Db, count: u64) !void {
    try testing.expect(a.root().eql(b.root()));
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

test "any sync from genesis and from the sync boundary match the source" {
    inline for (all_syncs) |S| {
        var harness = try Harness.init();
        defer harness.deinit();
        var source_db = try harness.open(S, "source");
        defer source_db.deinit();
        try apply_ops(S, &source_db, 60, 0);
        try apply_ops(S, &source_db, 40, 1);
        const end = source_db.bounds().end;
        var source: Source(S) = .{ .journal = &source_db.log };
        {
            var synced = try sync_from(S, &harness, &source, .init(source_db.root(), 0, end), 7);
            errdefer synced.deinit();
            try expect_same_state(S, &synced.db, &source_db, 60);
            try synced.db.destroy(); // Closes it.
        }
        try source_db.prune(source_db.sync_boundary());
        const start = source_db.sync_boundary();
        var synced = try sync_from(S, &harness, &source, .init(source_db.root(), start, end), 9);
        defer synced.deinit();
        try expect_same_state(S, &synced.db, &source_db, 60);
        try testing.expectEqual(start, synced.db.sync_boundary());
    }
}

// Commonware's `test_sync_post_sync_usability`.
test "any synced database accepts further batches" {
    inline for (all_syncs) |S| {
        var harness = try Harness.init();
        defer harness.deinit();
        var source_db = try harness.open(S, "source");
        defer source_db.deinit();
        try apply_ops(S, &source_db, 50, 0);
        const end = source_db.bounds().end;
        var source: Source(S) = .{ .journal = &source_db.log };
        const target: S.Target = .init(source_db.root(), source_db.sync_boundary(), end);
        var synced = try sync_from(S, &harness, &source, target, 100);
        defer synced.deinit();
        const root = synced.db.root();
        try apply_ops(S, &synced.db, 10, 1);
        try testing.expect(!synced.db.root().eql(root));
        try testing.expect(synced.db.bounds().end > end);
    }
}

/// `from_sync_result` over the backing log of the database `prefix` names, closed after
/// `source` was copied: opens the log for `range` and builds into `into`'s partitions.
fn rebuild(
    comptime S: type,
    harness: *Harness,
    comptime from: []const u8,
    comptime into: []const u8,
    pins: ?[]Digest,
    range: merkle.Range,
) !S {
    const storage = harness.storage.interface();
    const log_cfg = S.journal_config(harness.cfg(S, from));
    const bounds: sync.journal.Bounds = .{ .start = range.start, .end = range.end };
    const log = sync.journal.init(S.Journal, gpa, storage, log_cfg, bounds) catch |err| {
        if (pins) |p| gpa.free(p);
        return err;
    };
    var cfg = harness.cfg(S, into);
    cfg.log = log_cfg;
    return S.from_sync_result(gpa, storage, harness.target_scope(), cfg, log, pins, range, 1024);
}

fn pins_at(comptime S: type, db: *S.Db, location: u64) ![]Digest {
    var buffer: [merkle.max_pinned_nodes]Digest = undefined;
    return gpa.dupe(Digest, try db.pinned_nodes_at(location, &buffer));
}

// Commonware's `test_from_sync_result_nonempty_to_nonempty_exact_match` and
// `test_from_sync_result_empty_to_nonempty`: the rebuilt database reproduces the source's
// bounds, floor, sync boundary, and root, on its own storage or the source's.
test "any from_sync_result rebuilds a pruned source onto empty or matching storage" {
    inline for (all_syncs) |S| {
        inline for (.{ "source", "fresh" }) |into| {
            var harness = try Harness.init();
            defer harness.deinit();
            var db = try harness.open(S, "source");
            try apply_ops(S, &db, 100, 0);
            try db.prune(db.sync_boundary());
            const range: merkle.Range = .{ .start = db.sync_boundary(), .end = db.bounds().end };
            const root = db.root();
            const floor = db.inactivity_floor();
            const pins = pins_at(S, &db, range.start) catch |err| {
                db.deinit();
                return err;
            };
            try db.sync();
            db.deinit();
            var rebuilt = try rebuild(S, &harness, "source", into, pins, range);
            defer rebuilt.deinit();
            try testing.expect(rebuilt.db.root().eql(root));
            try testing.expectEqual(range.end, rebuilt.db.bounds().end);
            try testing.expectEqual(floor, rebuilt.db.inactivity_floor());
            try testing.expectEqual(range.start, rebuilt.db.sync_boundary());
        }
    }
}

// Commonware's `test_from_sync_result_nonempty_to_nonempty_partial_match`: the client's own
// storage persisted a prefix of the target's history.
test "any from_sync_result rebuilds over a client that persisted a prefix" {
    inline for (all_syncs) |S| {
        var harness = try Harness.init();
        defer harness.deinit();
        var client = try harness.open(S, "client");
        try apply_ops(S, &client, 100, 0);
        try client.prune(client.sync_boundary());
        try client.sync();
        client.deinit();
        var db = try harness.open(S, "source");
        try apply_ops(S, &db, 100, 0);
        try db.prune(db.sync_boundary());
        try apply_ops(S, &db, 5, 1);
        const range: merkle.Range = .{ .start = db.sync_boundary(), .end = db.bounds().end };
        const root = db.root();
        const floor = db.inactivity_floor();
        const pins = pins_at(S, &db, range.start) catch |err| {
            db.deinit();
            return err;
        };
        try db.sync();
        db.deinit();
        var rebuilt = try rebuild(S, &harness, "source", "client", pins, range);
        defer rebuilt.deinit();
        try testing.expect(rebuilt.db.root().eql(root));
        try testing.expectEqual(range.end, rebuilt.db.bounds().end);
        try testing.expectEqual(floor, rebuilt.db.inactivity_floor());
        try testing.expectEqual(range.start, rebuilt.db.sync_boundary());
    }
}

// Commonware's `test_from_sync_result_empty_to_empty`.
test "any from_sync_result rebuilds the initial commit and accepts batches" {
    inline for (all_syncs) |S| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(S, "source");
        try testing.expectEqual(@as(u64, 1), db.bounds().end);
        const root = db.root();
        try db.sync();
        db.deinit();
        var rebuilt = try rebuild(S, &harness, "source", "fresh", null, .{ .start = 0, .end = 1 });
        defer rebuilt.deinit();
        try testing.expect(rebuilt.db.root().eql(root));
        try testing.expectEqual(@as(u64, 0), rebuilt.db.inactivity_floor());
        try apply_ops(S, &rebuilt.db, 10, 0);
        try testing.expect(rebuilt.db.bounds().end > 1);
    }
}

// Commonware's `test_local_pinned_nodes_below_floor`: the floor comes from the last commit,
// not the target's start, so the local root matches only with the commit's floor.
test "any local pinned nodes use the last commit's floor" {
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
            const floor = db.inactivity_floor();
            const below = merkle.inactive_peaks(S.Family, end, floor);
            if (below > merkle.inactive_peaks(S.Family, end, 1)) break;
        }
        const target: S.Target = .init(db.root(), 1, db.bounds().end);
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

test "any sync to a wrong root fails with InvalidResponse" {
    const S = all_syncs[0];
    var harness = try Harness.init();
    defer harness.deinit();
    var source_db = try harness.open(S, "source");
    defer source_db.deinit();
    try apply_ops(S, &source_db, 9, 0);
    var source: Source(S) = .{ .journal = &source_db.log };
    const target: S.Target = .init(.fill(3), 0, source_db.bounds().end);
    try testing.expectError(error.InvalidResponse, sync_from(S, &harness, &source, target, 3));
}
