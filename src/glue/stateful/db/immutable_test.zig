//! commonware `glue/src/stateful/db/immutable/standard.rs` tests, over a fixed immutable
//! database of SHA-256 keys and values with a `TwoCap` translator (commonware's `FixedDb`),
//! plus the adapter's sync target, read, and variable-value checks.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const db = @import("mod.zig");
const immutable = @import("immutable.zig");

const qmdb = storage.qmdb;
const contiguous = storage.journal.contiguous;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Family = storage.mmr.Family;
const TwoCap = storage.translator.TwoCap;
const metrics = runtime.telemetry.metrics;
const gpa = testing.allocator;

const FixedEncoding = qmdb.value.Fixed(Digest);
const FixedJournal = contiguous.fixed.Journal(
    qmdb.immutable.Operation(Family, Digest, FixedEncoding),
);
const FixedDb = immutable.Immutable(Family, Digest, FixedEncoding, FixedJournal, Sha256, TwoCap);

const Bytes = []const u8;
const VariableEncoding = qmdb.value.Variable(Bytes);
const VariableJournal = contiguous.variable.Journal(
    qmdb.immutable.Operation(Family, Digest, VariableEncoding),
);
const VariableDb = immutable.Immutable(
    Family,
    Digest,
    VariableEncoding,
    VariableJournal,
    Sha256,
    TwoCap,
);

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

    /// The environment of a fresh open: metrics register afresh, as commonware's new child
    /// contexts do; the previous handle must be closed.
    fn env(harness: *Harness) db.Env {
        harness.registry.deinit();
        harness.registry = metrics.Registry.init(gpa);
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
                .journal_partition = "stateful-immutable-journal-" ++ suffix,
                .metadata_partition = "stateful-immutable-metadata-" ++ suffix,
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &harness.cache_ref,
            },
            .log = .{
                .partition = "stateful-immutable-log-" ++ suffix,
                .items_per_blob = 7,
                .cache_ref = &harness.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .translator = .{},
        };
    }

    fn variable_config(harness: *Harness) VariableDb.Config {
        return .{
            .merkle = .{
                .journal_partition = "stateful-immutable-journal-variable",
                .metadata_partition = "stateful-immutable-metadata-variable",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &harness.cache_ref,
            },
            .log = .{
                .partition = "stateful-immutable-log-variable",
                .items_per_section = 7,
                .codec_config = .{ {}, .{ .range = .inclusive(0, 10000) } },
                .cache_ref = &harness.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .translator = .{},
        };
    }

    fn open(harness: *Harness, comptime suffix: []const u8) !FixedDb.Shared {
        return FixedDb.Shared.open(harness.env(), harness.fixed_config(suffix), null);
    }
};

/// commonware's `Sha256::hash(&[&[byte]])`.
fn hash(byte: u8) Digest {
    return Sha256.hash(&.{&.{byte}});
}

/// A batch on `parent` (or over `shared` when null) setting `hash(key)` to `hash(value)`,
/// with `floor` when given, merkleized.
fn set_one(
    shared: FixedDb.Shared,
    parent: ?*const FixedDb.Merkleized,
    key: u8,
    value: u8,
    floor: ?u64,
) !FixedDb.Merkleized {
    var batch = if (parent) |link| try link.new_batch() else try shared.new_batches();
    errdefer batch.deinit();
    try batch.set(hash(key), hash(value));
    if (floor) |location| batch.with_inactivity_floor(location);
    return batch.merkleize();
}

test "stateful immutable: an unset inactivity floor inherits the parent's floor" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("inherit-parent-floor");
    defer shared.deinit();

    var parent = try set_one(shared, null, 1, 2, 1);
    defer parent.deinit();
    var child = try set_one(shared, &parent, 3, 4, null);
    defer child.deinit();
    try testing.expectEqual(@as(u64, 1), child.bounds().inactivity_floor);
}

test "stateful immutable: an unset inactivity floor inherits the applied floor" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("inherit-applied-floor");
    defer shared.deinit();

    var first = try set_one(shared, null, 1, 2, 1);
    defer first.deinit();
    try shared.apply(&first);
    var next = try set_one(shared, null, 3, 4, null);
    defer next.deinit();
    try testing.expectEqual(@as(u64, 1), next.bounds().inactivity_floor);
    try shared.apply(&next);
    var guard = try shared.read();
    defer guard.deinit();
    try testing.expectEqual(@as(u64, 1), guard.get().inner.inactivity_floor());
}

test "stateful immutable: trait impls compile" {
    comptime db.assert_managed_db(FixedDb);
    comptime db.assert_managed_db(VariableDb);
}

test "stateful immutable: sync targets track applied batches and reopen" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var target: FixedDb.SyncTarget = undefined;
    {
        const shared = try harness.open("targets");
        defer shared.deinit();
        const initial = FixedDb.Shared.initial_sync_targets();
        const committed = try shared.committed_targets();
        try testing.expect(db.targets_eql(FixedDb.SyncTarget, &initial, &committed));

        var merkleized = try set_one(shared, null, 1, 2, 1);
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
        var wrong_end = valid;
        wrong_end.end -= 1;
        try testing.expect(!FixedDb.matches_sync_target(&merkleized, &wrong_end));

        try shared.apply(&merkleized);
        target = try shared.committed_targets();
        try testing.expect(db.targets_eql(FixedDb.SyncTarget, &valid, &target));
        const barrier = try shared.finalize();
        try barrier.durable();
        try shared.prune(&target);
    }
    const config = harness.fixed_config("targets");
    const reopened = try FixedDb.Shared.open(harness.env(), config, target);
    reopened.deinit();
    var wrong = target;
    wrong.root = hash(9);
    const mismatch = FixedDb.Shared.open(harness.env(), config, wrong);
    try testing.expectError(error.TargetMismatch, mismatch);
}

test "stateful immutable: batch reads and a stale read" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("reads");
    defer shared.deinit();

    var stale = try shared.new_batches();
    defer stale.deinit();
    var parent = try set_one(shared, null, 1, 2, null);
    defer parent.deinit();
    var out: [2]?Digest = undefined;
    try parent.get_many(&.{ hash(1), hash(3) }, &out);
    try testing.expect(out[0].?.eql(hash(2)));
    try testing.expectEqual(@as(?Digest, null), out[1]);

    try shared.apply(&parent);
    var child = try parent.new_batch();
    defer child.deinit();
    try child.set(hash(3), hash(4));
    try testing.expect((try child.get(&hash(3))).?.eql(hash(4)));
    try testing.expect((try child.get(&hash(1))).?.eql(hash(2)));
    // `stale` was built on the state before `parent`, a state the database left.
    try testing.expectError(error.StaleRead, stale.get(&hash(1)));
}

test "stateful immutable: variable batches own their values and persist" {
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
        try batch.set(hash(1), value);
        batch.with_metadata(try gpa.dupe(u8, "meta"));
        var merkleized = try batch.merkleize();
        defer merkleized.deinit();
        const read = (try merkleized.get(&hash(1))).?;
        defer gpa.free(read);
        try testing.expectEqualStrings("value", read);
        try shared.apply(&merkleized);
        const barrier = try shared.finalize();
        try barrier.durable();
        target = try shared.committed_targets();
    }
    const config = harness.variable_config();
    const reopened = try VariableDb.Shared.open(harness.env(), config, target);
    defer reopened.deinit();
    var guard = try reopened.read();
    defer guard.deinit();
    const value = (try guard.get().inner.get(&hash(1))).?;
    defer codec.free(Bytes, gpa, value);
    try testing.expectEqualStrings("value", value);
}
