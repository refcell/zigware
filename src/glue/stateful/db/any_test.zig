//! commonware `glue/src/stateful/db/any.rs` tests, over an unordered fixed `any` database of
//! SHA-256 keys and values with a `TwoCap` index (commonware's `UnorderedFixedDb`).

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const db = @import("mod.zig");
const any_mod = @import("any.zig");

const qmdb = storage.qmdb;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Family = storage.mmr.Family;
const Encoding = qmdb.value.Fixed(Digest);
const Journal = storage.journal.contiguous.fixed.Journal(
    qmdb.any.operation.Unordered(Family, Digest, Encoding),
);
const Update = qmdb.any.operation.update.Unordered(Digest, Encoding);
const Index = storage.index.unordered.Index(storage.translator.TwoCap, u64);
// commonware's `ANY_BITMAP_CHUNK_BYTES`.
const Inner = qmdb.any.Db(Family, Update, Journal, Index, Sha256, 64);
const Any = any_mod.Any(Inner, Sha256);
const metrics = runtime.telemetry.metrics;

/// Storage, a page cache, and metrics for opening test databases.
const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(harness: *Harness) !void {
        harness.* = .{
            .storage = .init(testing.allocator),
            .cache_ref = try .init(testing.allocator, 101, 11),
            .registry = metrics.Registry.init(testing.allocator),
        };
    }

    fn deinit(harness: *Harness) void {
        harness.registry.deinit();
        harness.cache_ref.deinit();
        harness.storage.deinit();
    }

    fn env(harness: *Harness) db.Env {
        return .{
            .gpa = testing.allocator,
            .io = testing.io,
            .storage = harness.storage.interface(),
            .scope = metrics.Scope.init(&harness.registry).child("db"),
        };
    }

    fn config(harness: *Harness) Any.Config {
        return .{
            .merkle = .{
                .journal_partition = "stateful-any-journal",
                .metadata_partition = "stateful-any-metadata",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &harness.cache_ref,
            },
            .log = .{
                .partition = "stateful-any-log",
                .items_per_blob = 7,
                .cache_ref = &harness.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .translator = .{},
            .init_cache = 1024,
        };
    }

    /// Opens the database, registering its metrics afresh (as commonware's new child
    /// contexts do); the previous handle must be closed.
    fn open(harness: *Harness, expected: ?Any.SyncTarget) !Any.Shared {
        harness.registry.deinit();
        harness.registry = metrics.Registry.init(testing.allocator);
        return Any.Shared.open(harness.env(), harness.config(), expected);
    }
};

fn hash(text: []const u8) Digest {
    return Sha256.hash(&.{text});
}

/// Merkleizes a batch over `shared` writing `key` = `value`.
fn write_one(shared: Any.Shared, key: Digest, value: Digest) !Any.Merkleized {
    var batch = try shared.new_batches();
    errdefer batch.deinit();
    try batch.write(key, value);
    return batch.merkleize();
}

test "stateful any: an unmerkleized batch refuses reads after a competing finalization" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open(null);
    defer shared.deinit();

    const key = hash("key");
    var pre_finalization = try shared.new_batches();
    defer pre_finalization.deinit();
    var winner = try write_one(shared, key, hash("winner"));
    defer winner.deinit();
    try shared.apply(&winner);
    const barrier = try shared.finalize();
    try barrier.durable();

    // `winner` is a sibling built on the same state, so applying it moves the database to a
    // state outside `pre_finalization`'s chain.
    try testing.expectError(error.StaleRead, pre_finalization.get(&key));
}

test "stateful any: apply does not finalize" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open(null);
    defer shared.deinit();

    const key = hash("key");
    const value = hash("value");
    var merkleized = try write_one(shared, key, value);
    defer merkleized.deinit();

    const starts = start_sync_calls(shared);
    try shared.apply(&merkleized);
    try testing.expectEqual(starts, start_sync_calls(shared)); // Apply must not start syncs.
    {
        var guard = try shared.read();
        defer guard.deinit();
        try testing.expectEqual(value, (try guard.get().inner.get(&key)).?);
    }
    const barrier = try shared.finalize();
    try barrier.durable();
    try testing.expectEqual(starts + 1, start_sync_calls(shared));
}

fn start_sync_calls(shared: Any.Shared) u64 {
    var guard = shared.read() catch unreachable; // testing.io does not cancel.
    defer guard.deinit();
    return guard.get().inner.metrics.start_sync_calls.metric().get();
}

test "stateful any: sync targets track applied batches and reopen" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var target: Any.SyncTarget = undefined;
    {
        const shared = try harness.open(null);
        defer shared.deinit();
        const initial = Any.Shared.initial_sync_targets();
        const committed = try shared.committed_targets();
        try testing.expect(db.targets_eql(Any.SyncTarget, &initial, &committed));

        var batch = try shared.new_batches();
        errdefer batch.deinit();
        for (0..20) |i| {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, i, .big);
            try batch.write(Sha256.hash(&.{&bytes}), hash("value"));
        }
        var merkleized = try batch.merkleize();
        defer merkleized.deinit();
        target = (try shared.committed_targets());
        try testing.expect(!Any.matches_sync_target(&merkleized, &target));
        try shared.apply(&merkleized);
        target = try shared.committed_targets();
        try testing.expect(Any.matches_sync_target(&merkleized, &target));
        try testing.expect(merkleized.root().eql(target.root));
        const barrier = try shared.finalize();
        try barrier.durable();
        try shared.prune(&target);
    }
    // Reopening at the committed target succeeds; at another target it is a mismatch.
    const reopened = try harness.open(target);
    reopened.deinit();
    var wrong = target;
    wrong.root = hash("other");
    try testing.expectError(error.TargetMismatch, harness.open(wrong));
}

test "stateful any: a child batch reads its parent's pending writes" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open(null);
    defer shared.deinit();

    const key = hash("key");
    var parent = try write_one(shared, key, hash("parent"));
    defer parent.deinit();
    var child = try Any.Shared.fork_batches(&parent);
    defer child.deinit();
    try testing.expectEqual(hash("parent"), (try child.get(&key)).?);
    try testing.expectEqual(hash("parent"), (try parent.get(&key)).?);
    var keys = [_]Digest{ key, hash("missing") };
    var values: [2]?Digest = undefined;
    try child.get_many(&keys, &values);
    try testing.expectEqual(hash("parent"), values[0].?);
    try testing.expectEqual(null, values[1]);

    // The applied database does not see the pending write.
    var fresh = try shared.new_batches();
    defer fresh.deinit();
    try testing.expectEqual(null, try fresh.get(&key));
}

fn hash_u64(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

test "stateful any: staged merkleize matches explicit writes" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open(null);
    defer shared.deinit();
    const metadata = hash("metadata");

    // Seed keys 0..50 and persist them.
    {
        var seed = try shared.new_batches();
        errdefer seed.deinit();
        for (0..50) |i| try seed.write(hash_u64(i), hash_u64(i + 10_000));
        var merkleized = try seed.merkleize();
        defer merkleized.deinit();
        try shared.apply(&merkleized);
        try (try shared.finalize()).durable();
    }

    // Read set: key 1 updated, key 2 deleted, key 999 missing and created.
    const keys = [_]Digest{ hash_u64(1), hash_u64(2), hash_u64(999) };
    const slots = [_]Any.Slot{
        .{ .put = hash_u64(11_000) }, .delete, .{ .put = hash_u64(11_001) },
    };
    const unstaged = [_]Any.Mutation{.{ .key = hash_u64(3), .value = hash_u64(11_002) }};

    // Explicit path.
    var explicit_values: [keys.len]?Digest = undefined;
    const explicit_root = explicit: {
        var batch = try shared.new_batches();
        errdefer batch.deinit();
        try batch.get_many(&keys, &explicit_values);
        for (keys, slots) |key, slot| try batch.write(key, switch (slot) {
            .put => |value| value,
            .delete => null,
            .keep => unreachable, // Every staged read is written.
        });
        for (unstaged) |m| try batch.write(m.key, m.value);
        batch.with_metadata(metadata);
        var merkleized = try batch.merkleize();
        defer merkleized.deinit();
        break :explicit merkleized.root();
    };
    try testing.expectEqual(hash_u64(10_001), explicit_values[0].?);
    try testing.expectEqual(null, explicit_values[2]);

    // Staged path in two reads, with metadata set on the staged handle.
    var staged_values: [keys.len]?Digest = undefined;
    {
        var batch = try shared.new_batches();
        var staged = batch.stage(keys[0..2], staged_values[0..2]) catch |err| {
            batch.deinit();
            return err;
        };
        var merkleized = merkleized: {
            errdefer staged.deinit();
            const range = try staged.expand(keys[2..], staged_values[2..]);
            try testing.expectEqual(2, range.start);
            try testing.expectEqual(keys.len, range.end);
            try testing.expectEqual(keys.len, staged.len());
            try testing.expect(!staged.is_empty());
            staged.with_metadata(metadata);
            break :merkleized try staged.merkleize(&slots, &unstaged);
        };
        defer merkleized.deinit();
        try testing.expectEqualSlices(?Digest, &explicit_values, &staged_values);
        try testing.expect(explicit_root.eql(merkleized.root()));
    }

    // Metadata set before staging carries through to the staged merkleize.
    var carried_values: [keys.len]?Digest = undefined;
    var batch = try shared.new_batches();
    batch.with_metadata(metadata);
    var staged = batch.stage(&keys, &carried_values) catch |err| {
        batch.deinit();
        return err;
    };
    var carried = try staged.merkleize(&slots, &unstaged);
    defer carried.deinit();
    try testing.expectEqualSlices(?Digest, &explicit_values, &carried_values);
    try testing.expect(explicit_root.eql(carried.root()));
}
