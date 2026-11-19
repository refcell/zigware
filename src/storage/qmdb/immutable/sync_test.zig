//! End-to-end state sync of immutable databases (commonware's `qmdb/immutable/sync/tests.rs`
//! core cases): a fresh database syncs from a populated one served through its journal, and
//! the synced root, floor, and keys match the source's. The shared sync tests
//! (`sync/harness.zig`) run over commonware's variable harness (random digest keys and values)
//! in both families.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const variable = @import("../../journal/contiguous/variable.zig");
const qmdb_support = @import("../test_support.zig");
const value = @import("../value.zig");
const translator = @import("../../translator.zig");
const sync = @import("../sync/mod.zig");
const sync_harness = @import("../sync/harness.zig");
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

/// commonware's immutable `VariableHarness`: each operation sets a random key to a random
/// value, both drawn from the seed's stream.
fn VariableHarness(comptime F: type) type {
    const E = value.Variable(Digest);
    const Log = variable.Journal(immutable.Operation(F, Digest, E));
    return struct {
        const Self = @This();
        pub const Family = F;
        pub const Sync = immutable_sync.Database(F, Digest, E, Log, Sha256, translator.TwoCap);
        pub const Source = sync.JournalSource(F, Sync.Db.Journal);
        const Db = Sync.Db;
        const sample_metadata = fill(1);

        pub fn config(fixture: *sync_harness.Fixture, suffix: []const u8) !Sync.Config {
            const LogCfg = @FieldType(Sync.Config, "log");
            var log = qmdb_support.log_config(LogCfg, &fixture.cache_ref);
            log.partition = try fixture.partition(suffix, "log");
            log.items_per_section = 5;
            return .{
                .merkle = .{
                    .journal_partition = try fixture.partition(suffix, "journal"),
                    .metadata_partition = try fixture.partition(suffix, "metadata"),
                    .items_per_blob = 11,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                    .cache_ref = &fixture.cache_ref,
                },
                .log = log,
                .translator = .{},
            };
        }

        pub fn source(db: *Db) Self.Source {
            return .{ .journal = &db.journal };
        }

        fn random_digest(random: std.Random) Digest {
            var digest: Digest = undefined;
            random.bytes(&digest.bytes);
            return digest;
        }

        fn apply_with_floor(db: *Db, seed: u64, count: u64, metadata: bool, floor: u64) !void {
            var prng: std.Random.DefaultPrng = .init(seed);
            var batch = try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (0..count) |_| {
                    const key = random_digest(prng.random());
                    try batch.set(key, random_digest(prng.random()));
                }
                if (metadata) batch.with_metadata(sample_metadata);
                batch.with_inactivity_floor(floor);
                break :merkleized try batch.merkleize(db);
            };
            defer merkleized.release();
            try db.apply_batch(merkleized);
        }

        pub fn apply_ops(db: *Db, seed: u64, count: u64, metadata: bool) !void {
            try apply_with_floor(db, seed, count, metadata, db.inactivity_floor());
        }

        /// Prune requires the floor at or beyond `location`, so commit it as the floor first.
        pub fn prune(db: *Db, location: u64) !void {
            try apply_with_floor(db, 0, 0, false, location);
            try db.commit();
            try db.prune(location);
        }

        pub fn expect_ops_applied(db: *Db, _: u64, seed: u64, count: u64) !void {
            var prng: std.Random.DefaultPrng = .init(seed);
            for (0..count) |_| {
                const key = random_digest(prng.random());
                const expected = random_digest(prng.random());
                const got = (try db.get(&key)) orelse return error.TestMissing;
                try testing.expect(got.eql(expected));
            }
        }

        pub fn expect_ops_absent(db: *Db, seed: u64, count: u64) !void {
            var prng: std.Random.DefaultPrng = .init(seed);
            for (0..count) |_| {
                const key = random_digest(prng.random());
                _ = random_digest(prng.random());
                try testing.expect(try db.get(&key) == null);
            }
        }

        pub fn expect_sample_metadata(db: *Db) !void {
            const got = (try db.get_metadata()) orelse return error.TestMissing;
            try testing.expect(got.eql(sample_metadata));
        }
    };
}

comptime {
    _ = sync_harness.Tests(VariableHarness(merkle.mmr.Family));
    _ = sync_harness.Tests(VariableHarness(merkle.mmb.Family));
}
