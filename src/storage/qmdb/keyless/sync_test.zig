//! End-to-end state sync of keyless databases (commonware's `qmdb/keyless/sync/tests.rs`
//! core cases): a fresh database syncs from a populated one served through its journal, and
//! the synced root, bounds, floor, and values match the source's.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const value = @import("../value.zig");
const sync = @import("../sync/mod.zig");
const keyless = @import("mod.zig");
const keyless_sync = @import("sync.zig");

const Sha256 = cryptography.Sha256;
const U64 = utils.sequence.U64;
const metrics = runtime.telemetry.metrics;
const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const Encoding = value.Fixed(U64);

fn Backing(comptime F: type) type {
    return fixed.Journal(keyless.Operation(F, Encoding));
}

fn SyncDb(comptime F: type) type {
    return keyless_sync.Database(F, Encoding, Backing(F), Sha256);
}

fn Source(comptime F: type) type {
    return sync.JournalSource(F, SyncDb(F).Db.Journal);
}

comptime {
    sync.database.assert_database(SyncDb(merkle.mmr.Family));
}

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
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

    fn cfg(self: *Harness, comptime F: type, comptime prefix: []const u8) SyncDb(F).Config {
        return .{
            .merkle = .{
                .journal_partition = prefix ++ "-merkle",
                .metadata_partition = prefix ++ "-metadata",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &self.cache_ref,
            },
            .log = .{
                .partition = prefix ++ "-log",
                .items_per_blob = 7,
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
        };
    }

    fn open_source(self: *Harness, comptime F: type) !SyncDb(F).Db {
        const scope = metrics.Scope.init(&self.source_registry).child("db");
        const storage = self.storage.interface();
        return SyncDb(F).Db.init(gpa, storage, scope, self.cfg(F, "source"), null);
    }

    /// A fresh registry per sync, as commonware gives each sync a fresh context.
    fn target_scope(self: *Harness) metrics.Scope {
        self.target_registry.deinit();
        self.target_registry = .init(gpa);
        return metrics.Scope.init(&self.target_registry).child("db");
    }
};

/// Appends `count` values from `seed` in one batch with inactivity floor `floor`, and applies it.
fn append(comptime F: type, db: *SyncDb(F).Db, seed: u64, count: u64, floor: ?u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (0..count) |i| try batch.append(U64.init(seed * 1000 + i));
        if (floor) |location| batch.with_inactivity_floor(location);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn sync_from(
    comptime F: type,
    harness: *Harness,
    source: *Source(F),
    target: sync.Target(F, Sha256.Digest),
    batch_size: u64,
    outstanding: usize,
) !SyncDb(F) {
    return sync.sync(SyncDb(F), Source(F), gpa, testing.io, .{
        .storage = harness.storage.interface(),
        .scope = harness.target_scope(),
        .source = source,
        .target = target,
        .max_outstanding_requests = outstanding,
        .fetch_batch_size = batch_size,
        .apply_batch_size = 4,
        .db_config = harness.cfg(F, "target"),
    });
}

fn expect_matches(comptime F: type, synced: *SyncDb(F), source: *SyncDb(F).Db) !void {
    try testing.expect(synced.db.root().eql(source.root()));
    try testing.expectEqual(source.bounds().end, synced.db.bounds().end);
    try testing.expectEqual(source.inactivity_floor(), synced.db.inactivity_floor());
    const last = source.bounds().end - 1;
    try testing.expectEqual(try source.get(last), try synced.db.get(last));
}

test "keyless sync from genesis matches the source" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var source_db = try harness.open_source(F);
        defer source_db.deinit();
        try append(F, &source_db, 1, 23, null);
        try append(F, &source_db, 2, 17, null);
        var source: Source(F) = .{ .journal = &source_db.journal };
        const size = source_db.bounds().end;
        const target: sync.Target(F, Sha256.Digest) = .init(source_db.root(), 0, size);
        var synced = try sync_from(F, &harness, &source, target, 5, 3);
        defer synced.deinit();
        try expect_matches(F, &synced, &source_db);
    }
}

test "keyless sync from the inactivity floor fetches pinned nodes" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var source_db = try harness.open_source(F);
        defer source_db.deinit();
        try append(F, &source_db, 1, 30, null);
        try append(F, &source_db, 2, 12, 19);
        const floor = source_db.sync_boundary();
        try testing.expectEqual(@as(u64, 19), floor);
        var source: Source(F) = .{ .journal = &source_db.journal };
        const size = source_db.bounds().end;
        const target: sync.Target(F, Sha256.Digest) = .init(source_db.root(), floor, size);
        var synced = try sync_from(F, &harness, &source, target, 4, 2);
        defer synced.deinit();
        try expect_matches(F, &synced, &source_db);
        try testing.expectEqual(floor, synced.db.bounds().start);
    }
}

test "keyless sync to a wrong root fails with RootMismatch or InvalidResponse" {
    var harness = try Harness.init();
    defer harness.deinit();
    const F = merkle.mmr.Family;
    var source_db = try harness.open_source(F);
    defer source_db.deinit();
    try append(F, &source_db, 1, 9, null);
    var source: Source(F) = .{ .journal = &source_db.journal };
    const target: sync.Target(F, Sha256.Digest) = .init(.fill(3), 0, source_db.bounds().end);
    // Every response fails verification against the wrong root.
    try testing.expectError(error.InvalidResponse, sync_from(F, &harness, &source, target, 3, 2));
}
