//! End-to-end state sync of keyless databases (commonware's `qmdb/keyless/sync/tests.rs`
//! core cases): a fresh database syncs from a populated one served through its journal, and
//! the synced root, bounds, floor, and values match the source's. The shared sync tests
//! (`sync/harness.zig`) run over commonware's variable harness (byte values) in both families.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const codec = @import("codec");
const fixed = @import("../../journal/contiguous/fixed.zig");
const variable = @import("../../journal/contiguous/variable.zig");
const qmdb_support = @import("../test_support.zig");
const value = @import("../value.zig");
const sync = @import("../sync/mod.zig");
const sync_harness = @import("../sync/harness.zig");
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

/// commonware's keyless `VariableHarness`: byte values of 1 to 100 random bytes per seed.
fn VariableHarness(comptime F: type) type {
    const E = value.Variable([]const u8);
    const Log = variable.Journal(keyless.Operation(F, E));
    return struct {
        pub const Family = F;
        pub const Sync = keyless_sync.Database(F, E, Log, Sha256);
        pub const Source = sync.JournalSource(F, Sync.Db.Journal);
        const Db = Sync.Db;
        const Self = @This();
        const sample_metadata: []const u8 = &.{42};

        pub fn config(fixture: *sync_harness.Fixture, suffix: []const u8) !Sync.Config {
            const LogCfg = @FieldType(Sync.Config, "log");
            return .{
                .merkle = .{
                    .journal_partition = try fixture.partition(suffix, "journal"),
                    .metadata_partition = try fixture.partition(suffix, "metadata"),
                    .items_per_blob = 11,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                    .cache_ref = &fixture.cache_ref,
                },
                .log = .{
                    .partition = try fixture.partition(suffix, "log"),
                    .items_per_section = 5,
                    .codec_config = qmdb_support.codec_config(@FieldType(LogCfg, "codec_config")),
                    .cache_ref = &fixture.cache_ref,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                },
            };
        }

        pub fn source(db: *Db) Self.Source {
            return .{ .journal = &db.journal };
        }

        /// The next value of `create_ops_seeded`'s stream (owned by the caller).
        fn next_value(random: std.Random) ![]u8 {
            const bytes = try gpa.alloc(u8, random.uintLessThan(usize, 100) + 1);
            random.bytes(bytes);
            return bytes;
        }

        fn apply_with_floor(db: *Db, seed: u64, count: u64, metadata: bool, floor: u64) !void {
            var prng: std.Random.DefaultPrng = .init(seed);
            var batch = try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (0..count) |_| {
                    const bytes = try next_value(prng.random());
                    errdefer gpa.free(bytes);
                    try batch.append(bytes);
                }
                if (metadata) batch.with_metadata(try gpa.dupe(u8, sample_metadata));
                batch.with_inactivity_floor(floor);
                break :merkleized try batch.merkleize(db);
            };
            defer merkleized.release();
            try db.apply_batch(merkleized);
        }

        pub fn apply_ops(db: *Db, seed: u64, count: u64, metadata: bool) !void {
            try apply_with_floor(db, seed, count, metadata, db.inactivity_floor());
        }

        /// Prune requires the floor at or beyond `location`, so commit it as the floor first
        /// unless the floor already exceeds it.
        pub fn prune(db: *Db, location: u64) !void {
            if (db.inactivity_floor() <= location) {
                try apply_with_floor(db, 0, 0, false, location);
                try db.commit();
            }
            try db.prune(location);
        }

        pub fn expect_ops_applied(db: *Db, start: u64, seed: u64, count: u64) !void {
            var prng: std.Random.DefaultPrng = .init(seed);
            for (start..start + count) |location| {
                const expected = try next_value(prng.random());
                defer gpa.free(expected);
                const got = try db.get(location);
                defer codec.free(?[]const u8, gpa, got);
                try testing.expectEqualSlices(u8, expected, got orelse return error.TestMissing);
            }
        }

        pub fn expect_ops_absent(db: *Db, seed: u64, count: u64) !void {
            var prng: std.Random.DefaultPrng = .init(seed);
            for (0..count) |_| {
                const unexpected = try next_value(prng.random());
                defer gpa.free(unexpected);
                const bounds = db.bounds();
                for (bounds.start..bounds.end) |location| {
                    const got = try db.get(location);
                    defer codec.free(?[]const u8, gpa, got);
                    if (got) |bytes| try testing.expect(!std.mem.eql(u8, bytes, unexpected));
                }
            }
        }

        pub fn expect_sample_metadata(db: *Db) !void {
            const got = try db.get_metadata();
            defer codec.free(?[]const u8, gpa, got);
            try testing.expectEqualSlices(u8, sample_metadata, got orelse return error.TestMissing);
        }
    };
}

comptime {
    _ = sync_harness.Tests(VariableHarness(merkle.mmr.Family));
    _ = sync_harness.Tests(VariableHarness(merkle.mmb.Family));
}
