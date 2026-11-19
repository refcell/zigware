//! commonware `glue/src/stateful/db/keyless/standard.rs` tests, over a fixed keyless database
//! of `U64` values (commonware's `FixedDb`) and a variable one of byte strings (`VariableDb`).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("mod.zig");
const keyless = @import("keyless.zig");

const qmdb = storage.qmdb;
const contiguous = storage.journal.contiguous;
const Sha256 = cryptography.Sha256;
const Family = storage.mmr.Family;
const U64 = utils.sequence.U64;
const metrics = runtime.telemetry.metrics;
const gpa = testing.allocator;

const FixedEncoding = qmdb.value.Fixed(U64);
const FixedJournal = contiguous.fixed.Journal(qmdb.keyless.Operation(Family, FixedEncoding));
const FixedDb = keyless.Keyless(Family, FixedEncoding, FixedJournal, Sha256);

const Bytes = []const u8;
const VariableEncoding = qmdb.value.Variable(Bytes);
const VariableJournal = contiguous.variable.Journal(
    qmdb.keyless.Operation(Family, VariableEncoding),
);
const VariableDb = keyless.Keyless(Family, VariableEncoding, VariableJournal, Sha256);

/// Storage, a page cache, and metrics for opening test databases.
const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(harness: *Harness) !void {
        harness.* = .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(harness: *Harness) void {
        harness.registry.deinit();
        harness.cache_ref.deinit();
        harness.storage.deinit();
    }

    fn env(harness: *Harness) db.Env {
        return .{
            .gpa = gpa,
            .io = testing.io,
            .storage = harness.storage.interface(),
            .scope = metrics.Scope.init(&harness.registry).child("db"),
        };
    }

    /// commonware's `fixed_config(suffix)`.
    fn fixed_config(harness: *Harness, comptime suffix: []const u8) FixedDb.Config {
        return .{
            .merkle = .{
                .journal_partition = "journal-" ++ suffix,
                .metadata_partition = "metadata-" ++ suffix,
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &harness.cache_ref,
            },
            .log = .{
                .partition = "log-" ++ suffix,
                .items_per_blob = 7,
                .cache_ref = &harness.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
        };
    }

    fn variable_config(harness: *Harness) VariableDb.Config {
        return .{
            .merkle = .{
                .journal_partition = "journal-stateful-keyless-variable",
                .metadata_partition = "metadata-stateful-keyless-variable",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &harness.cache_ref,
            },
            .log = .{
                .partition = "log-stateful-keyless-variable",
                .items_per_section = 7,
                .codec_config = .{ .range = .inclusive(0, 10000) },
                .cache_ref = &harness.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
        };
    }

    /// Opens a fixed database, registering its metrics afresh (as commonware's new child
    /// contexts do); the previous handle must be closed.
    fn open(harness: *Harness, comptime suffix: []const u8) !FixedDb.Shared {
        harness.registry.deinit();
        harness.registry = metrics.Registry.init(gpa);
        return FixedDb.Shared.open(harness.env(), harness.fixed_config(suffix), null);
    }
};

/// A batch over `shared` appending `value` with the inactivity floor at 1, merkleized.
fn append_with_floor(shared: FixedDb.Shared, value: u64, metadata: ?u64) !FixedDb.Merkleized {
    var batch = try shared.new_batches();
    errdefer batch.deinit();
    try batch.append(U64.init(value));
    batch.with_inactivity_floor(1);
    if (metadata) |meta| batch.with_metadata(U64.init(meta));
    return batch.merkleize();
}

test "stateful keyless: an unset inactivity floor inherits the parent's floor" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("stateful-keyless-inherit-parent-floor");
    defer shared.deinit();

    var parent = try append_with_floor(shared, 7, null);
    defer parent.deinit();
    var child_batch = try FixedDb.Shared.fork_batches(&parent);
    errdefer child_batch.deinit();
    try child_batch.append(U64.init(8));
    var child = try child_batch.merkleize();
    defer child.deinit();
    try testing.expectEqual(@as(u64, 1), child.bounds().inactivity_floor);
    try testing.expectEqual(@as(u64, 1), parent.bounds().inactivity_floor);
}

test "stateful keyless: an unset inactivity floor inherits the applied floor" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("stateful-keyless-inherit-applied-floor");
    defer shared.deinit();

    var first = try append_with_floor(shared, 7, null);
    defer first.deinit();
    try shared.apply(&first);

    var next_batch = try shared.new_batches();
    errdefer next_batch.deinit();
    try next_batch.append(U64.init(9));
    var next = try next_batch.merkleize();
    defer next.deinit();
    try testing.expectEqual(@as(u64, 1), next.bounds().inactivity_floor);
    try shared.apply(&next);
    var guard = try shared.read();
    defer guard.deinit();
    try testing.expectEqual(@as(u64, 1), guard.get().inner.inactivity_floor());
}

test "stateful keyless: trait impls compile" {
    comptime db.assert_managed_db(FixedDb);
    comptime db.assert_managed_db(VariableDb);
}

test "stateful keyless: apply and finalize persist fixed batches" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("stateful-keyless-managed-db");
    defer shared.deinit();

    var merkleized = try append_with_floor(shared, 7, 9);
    defer merkleized.deinit();
    try shared.apply(&merkleized);
    const barrier = try shared.finalize();
    try barrier.durable();

    var guard = try shared.read();
    defer guard.deinit();
    const inner = &guard.get().inner;
    try testing.expectEqual(U64.init(7), (try inner.get(1)).?);
    try testing.expectEqual(U64.init(9), (try inner.get_metadata()).?);
    const target = guard.get().sync_target();
    try testing.expect(target.root.eql(inner.root()));
    try testing.expectEqual(@as(u64, 1), target.start);
    try testing.expectEqual(@as(u64, 3), target.end);
}

test "stateful keyless: matches_sync_target rejects a wrong replay range" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("stateful-keyless-matches-sync-target");
    defer shared.deinit();

    var merkleized = try append_with_floor(shared, 7, 9);
    defer merkleized.deinit();
    const bounds = merkleized.bounds();
    const valid: FixedDb.SyncTarget = .init(
        merkleized.root(),
        bounds.inactivity_floor,
        bounds.tip.size,
    );
    try testing.expect(FixedDb.matches_sync_target(&merkleized, &valid));
    const wrong_start: FixedDb.SyncTarget = .init(merkleized.root(), 0, bounds.tip.size);
    try testing.expect(!FixedDb.matches_sync_target(&merkleized, &wrong_start));
    const wrong_end: FixedDb.SyncTarget = .init(
        merkleized.root(),
        bounds.inactivity_floor,
        bounds.tip.size - 1,
    );
    try testing.expect(!FixedDb.matches_sync_target(&merkleized, &wrong_end));
    var wrong_root = valid;
    wrong_root.root = Sha256.hash(&.{"other"});
    try testing.expect(!FixedDb.matches_sync_target(&merkleized, &wrong_root));
}

test "stateful keyless: batch reads, a stale read, and the initial target" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("stateful-keyless-reads");
    defer shared.deinit();
    const initial = FixedDb.Shared.initial_sync_targets();
    const committed = try shared.committed_targets();
    try testing.expect(db.targets_eql(FixedDb.SyncTarget, &initial, &committed));

    var stale = try shared.new_batches();
    defer stale.deinit();
    var parent = try append_with_floor(shared, 7, null);
    defer parent.deinit();
    // Location 0 is the initial commit, 1 the append, 2 the batch's commit.
    var out: [2]?U64 = undefined;
    try parent.get_many(&.{ 1, 2 }, &out);
    try testing.expectEqual(U64.init(7), out[0].?);
    try testing.expectEqual(@as(?U64, null), out[1]);
    try testing.expectError(error.LocationOutOfBounds, parent.get(3));
    try testing.expectError(error.BelowInactivityFloor, parent.get(0));

    try shared.apply(&parent);
    var child = try parent.new_batch();
    defer child.deinit();
    try child.append(U64.init(8));
    try testing.expectEqual(U64.init(8), (try child.get(3)).?);
    try testing.expectEqual(U64.init(7), (try child.get(1)).?);
    // `stale` was built on the state before `parent`, a state the database left.
    try testing.expectError(error.StaleRead, stale.get(0));
}

test "stateful keyless: variable batches own their values and reopen at their target" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var target: VariableDb.SyncTarget = undefined;
    {
        const shared = try VariableDb.Shared.open(harness.env(), harness.variable_config(), null);
        defer shared.deinit();
        var batch = try shared.new_batches();
        errdefer batch.deinit();
        const value = try gpa.dupe(u8, "value");
        errdefer gpa.free(value);
        try batch.append(value);
        batch.with_metadata(try gpa.dupe(u8, "meta"));
        var merkleized = try batch.merkleize();
        defer merkleized.deinit();
        const read = (try merkleized.get(1)).?;
        defer gpa.free(read);
        try testing.expectEqualStrings("value", read);
        try shared.apply(&merkleized);
        const barrier = try shared.finalize();
        try barrier.durable();
        target = try shared.committed_targets();
        try testing.expect(VariableDb.matches_sync_target(&merkleized, &target));
    }
    harness.registry.deinit();
    harness.registry = metrics.Registry.init(gpa);
    const reopened = try VariableDb.Shared.open(harness.env(), harness.variable_config(), target);
    defer reopened.deinit();
    var guard = try reopened.read();
    defer guard.deinit();
    const meta = (try guard.get().inner.get_metadata()).?;
    defer codec.free(Bytes, gpa, meta);
    try testing.expectEqualStrings("meta", meta);
}
