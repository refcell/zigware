//! End-to-end state sync of immutable databases (commonware's `qmdb/immutable/sync/tests.rs`
//! core cases): a fresh database syncs from a populated one served through its journal, and
//! the synced root, floor, and keys match the source's.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const translator = @import("../../translator.zig");
const sync = @import("../sync/mod.zig");
const immutable = @import("mod.zig");
const immutable_sync = @import("sync.zig");
const support = @import("test_support.zig");

const Sha256 = support.Sha256;
const Digest = support.Digest;
const Encoding = support.Encoding;
const fill = support.fill;
const metrics = runtime.telemetry.metrics;
const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };

fn SyncDb(comptime F: type) type {
    const C = fixed.Journal(immutable.Operation(F, Digest, Encoding));
    return immutable_sync.Database(F, Digest, Encoding, C, Sha256, translator.TwoCap);
}

fn Source(comptime F: type) type {
    return sync.JournalSource(F, SyncDb(F).Db.Journal);
}

comptime {
    sync.database.assert_database(SyncDb(merkle.mmr.Family));
}

/// The target's config: the source harness's, under partitions of its own.
fn target_cfg(comptime F: type, harness: *support.Harness) SyncDb(F).Config {
    var cfg = harness.cfg(SyncDb(F).Db);
    cfg.merkle.journal_partition = "sync-target-mj";
    cfg.merkle.metadata_partition = "sync-target-mm";
    cfg.log.partition = "sync-target-log";
    return cfg;
}

fn append(comptime F: type, db: *SyncDb(F).Db, first: u8, count: u8, floor: ?u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (first..first + count) |k| {
            const key: u8 = @intCast(k);
            try batch.set(fill(key), fill(key +% 100));
        }
        if (floor) |location| batch.with_inactivity_floor(location);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn run(comptime F: type, floor: ?u64) !void {
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var source_db = try harness.open(F, null);
    defer source_db.deinit();
    try append(F, &source_db, 1, 20, null);
    try append(F, &source_db, 30, 15, floor);
    var source: Source(F) = .{ .journal = &source_db.journal };
    const start = source_db.sync_boundary();
    const size = source_db.bounds().end;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var synced = try sync.sync(SyncDb(F), Source(F), gpa, testing.io, .{
        .storage = harness.storage.interface(),
        .scope = metrics.Scope.init(&registry).child("db"),
        .source = &source,
        .target = .init(source_db.root(), start, size),
        .max_outstanding_requests = 3,
        .fetch_batch_size = 4,
        .apply_batch_size = 5,
        .db_config = target_cfg(F, &harness),
    });
    defer synced.deinit();
    try testing.expect(synced.db.root().eql(source_db.root()));
    try testing.expectEqual(size, synced.db.bounds().end);
    try testing.expectEqual(source_db.inactivity_floor(), synced.db.inactivity_floor());
    // A key set at or after the floor reads back with its value.
    try testing.expectEqual(try source_db.get(&fill(40)), try synced.db.get(&fill(40)));
    try testing.expect((try synced.db.get(&fill(40))) != null);
}

test "immutable sync from genesis matches the source" {
    inline for (families) |F| try run(F, null);
}

test "immutable sync from the inactivity floor fetches pinned nodes" {
    inline for (families) |F| try run(F, 17);
}
