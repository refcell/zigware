//! commonware `glue/src/stateful/db/current.rs` tests, over an unordered fixed `current`
//! database of SHA-256 keys and values with a `TwoCap` index and 64-byte chunks (commonware's
//! `FixedDb`). The ordered and variable tests wait on those `current` databases; the staged
//! test runs on the unordered database here.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const db = @import("mod.zig");
const current_mod = @import("current.zig");

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
const Inner = qmdb.current.Db(Family, Update, Journal, Index, Sha256, 64);
const Current = current_mod.Current(Inner);
const metrics = runtime.telemetry.metrics;

/// Storage, a page cache, and metrics for opening test databases. Each open takes a distinct
/// metrics label, as commonware's child contexts do.
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

    fn env(harness: *Harness, label: []const u8) db.Env {
        return .{
            .gpa = testing.allocator,
            .io = testing.io,
            .storage = harness.storage.interface(),
            .scope = metrics.Scope.init(&harness.registry).child(label),
        };
    }

    /// commonware's `fixed_config(suffix)`.
    fn config(harness: *Harness, comptime suffix: []const u8) Current.Config {
        return .{
            .merkle = .{
                .journal_partition = "stateful-current-journal-" ++ suffix,
                .metadata_partition = "stateful-current-metadata-" ++ suffix,
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &harness.cache_ref,
            },
            .log = .{
                .partition = "stateful-current-log-" ++ suffix,
                .items_per_blob = 7,
                .cache_ref = &harness.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .grafted_metadata_partition = "stateful-current-grafted-" ++ suffix,
            .translator = .{},
            .init_cache = 1024,
        };
    }

    fn open(
        harness: *Harness,
        label: []const u8,
        comptime suffix: []const u8,
        expected: ?Current.SyncTarget,
    ) !Current.Shared {
        return Current.Shared.open(harness.env(label), harness.config(suffix), expected);
    }
};

fn hash(text: []const u8) Digest {
    return Sha256.hash(&.{text});
}

fn hash_u64(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

fn apply_and_finalize(shared: Current.Shared, batch: *const Current.Merkleized) !void {
    try shared.apply(batch);
    const barrier = try shared.finalize();
    try barrier.durable();
}

/// A batch over `shared` writing `key` = `value` with `metadata`.
fn write_one(shared: Current.Shared, key: Digest, value: Digest) !Current.Merkleized {
    var batch = try shared.new_batches();
    errdefer batch.deinit();
    try batch.write(key, value);
    batch.with_metadata(hash("metadata"));
    return batch.merkleize();
}

test "stateful current: a managed db applies a batch and proves its value" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("db", "managed-db", null);
    defer shared.deinit();

    const key = hash("key");
    const value = hash("value");
    var merkleized = try write_one(shared, key, value);
    defer merkleized.deinit();
    const expected_root = merkleized.root();
    try testing.expect(!expected_root.eql(merkleized.ops_root()));
    try apply_and_finalize(shared, &merkleized);

    var guard = try shared.read();
    defer guard.deinit();
    const inner = &guard.get().inner;
    try testing.expect(inner.root().eql(expected_root));
    try testing.expectEqual(value, (try inner.get(&key)).?);
    var proved = try inner.key_value_proof(&key);
    defer proved.deinit(testing.allocator);
    try testing.expectEqual(value, proved.value);
    const root = inner.root();
    try testing.expect(Inner.verify_key_value_proof(&proved.proof, key, value, &root));
    try testing.expect(!Inner.verify_key_value_proof(&proved.proof, key, hash("other"), &root));
    try testing.expectError(error.KeyNotFound, inner.key_value_proof(&hash("missing")));
}

test "stateful current: matches_sync_target rejects a wrong ops root and range" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("db", "matches-sync-target", null);
    defer shared.deinit();
    var merkleized = try write_one(shared, hash("key"), hash("value"));
    defer merkleized.deinit();

    const verification_config = harness.config("matches-sync-target-verification");
    var verification = try Current.init(harness.env("verification"), verification_config, null);
    defer verification.deinit();
    try verification.inner.apply_batch(merkleized.inner);
    try verification.inner.sync();

    const valid = verification.sync_target();
    try testing.expect(Current.matches_sync_target(&merkleized, &valid));
    // The target commits to the ops root, not the canonical root.
    try testing.expect(valid.root.eql(merkleized.ops_root()));

    var wrong_root = valid;
    wrong_root.root = hash("wrong ops root");
    try testing.expect(!Current.matches_sync_target(&merkleized, &wrong_root));
    var canonical_root = valid;
    canonical_root.root = merkleized.root();
    try testing.expect(!Current.matches_sync_target(&merkleized, &canonical_root));
    var wrong_end = valid;
    wrong_end.end += 1;
    try testing.expect(!Current.matches_sync_target(&merkleized, &wrong_end));
    var wrong_start = valid;
    wrong_start.start += 1;
    try testing.expect(!Current.matches_sync_target(&merkleized, &wrong_start));
}

test "stateful current: staged merkleize matches explicit writes" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("db", "glue-staged", null);
    defer shared.deinit();
    const metadata = hash("metadata");

    // Seed keys 0..50 and persist them.
    {
        var seed = try shared.new_batches();
        errdefer seed.deinit();
        for (0..50) |i| try seed.write(hash_u64(i), hash_u64(i + 10_000));
        var merkleized = try seed.merkleize();
        defer merkleized.deinit();
        try apply_and_finalize(shared, &merkleized);
    }

    // Read set: key 1 updated, key 2 deleted, key 999 missing and created.
    const keys = [_]Digest{ hash_u64(1), hash_u64(2), hash_u64(999) };
    const slots = [_]Current.Slot{
        .{ .put = hash_u64(11_000) }, .delete, .{ .put = hash_u64(11_001) },
    };
    const unstaged = [_]Current.Mutation{.{ .key = hash_u64(3), .value = hash_u64(11_002) }};

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

test "stateful current: bounded initialization discards later targets durably" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var first: Current.SyncTarget = undefined;
    var second: Current.SyncTarget = undefined;
    {
        const shared = try harness.open("db", "bounded-init", null);
        defer shared.deinit();
        var a = try write_one(shared, hash("key1"), hash("value1"));
        defer a.deinit();
        try apply_and_finalize(shared, &a);
        first = try shared.committed_targets();
        var b = try write_one(shared, hash("key2"), hash("value2"));
        defer b.deinit();
        try apply_and_finalize(shared, &b);
        second = try shared.committed_targets();
    }
    try testing.expect(!db.targets_eql(Current.SyncTarget, &first, &second));

    // Reopening at the first target discards the second, durably.
    {
        const bounded = try harness.open("bounded", "bounded-init", first);
        defer bounded.deinit();
        const reopened = try bounded.committed_targets();
        try testing.expect(db.targets_eql(Current.SyncTarget, &first, &reopened));
    }
    const unbounded = try harness.open("unbounded", "bounded-init", null);
    const recovered = try unbounded.committed_targets();
    unbounded.deinit();
    try testing.expect(db.targets_eql(Current.SyncTarget, &first, &recovered));

    // The discarded second target cannot be restored, and the rejection leaves the first.
    try testing.expectError(error.TargetMismatch, harness.open("second", "bounded-init", second));
    const restart = try harness.open("restart", "bounded-init", null);
    defer restart.deinit();
    const restarted = try restart.committed_targets();
    try testing.expect(db.targets_eql(Current.SyncTarget, &first, &restarted));
}

test "stateful current: pruning keeps retained targets initializable" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var targets: [4]Current.SyncTarget = undefined;
    {
        const shared = try harness.open("db", "prune-recovery-window", null);
        defer shared.deinit();
        // Four generations rewrite the same keys. H1 through H3 are durable, and H4 is applied
        // without a barrier of its own when the prune to H2 runs.
        for (0..4) |generation| {
            var batch = try shared.new_batches();
            errdefer batch.deinit();
            for (0..384) |i| {
                var value: [8]u8 = undefined;
                std.mem.writeInt(u64, &value, generation * 1_000 + i, .little);
                try batch.write(hash_u64(i), Sha256.hash(&.{&value}));
            }
            var merkleized = try batch.merkleize();
            defer merkleized.deinit();
            try shared.apply(&merkleized);
            if (generation < 3) try (try shared.finalize()).durable();
            targets[generation] = try shared.committed_targets();
        }
        // The pruned target starts a whole chunk above zero, so the prune moves the bitmap.
        try testing.expect(targets[1].start > 0);
        try shared.prune(&targets[1]);
    }

    // An unbounded reopen recovers H4, which the prune committed.
    {
        const reopened = try harness.open("reopen", "prune-recovery-window", null);
        defer reopened.deinit();
        const recovered = try reopened.committed_targets();
        try testing.expect(db.targets_eql(Current.SyncTarget, &targets[3], &recovered));
    }
    // H3 and H2 stay inside the retained window, so bounded initialization at either succeeds.
    const labels = [_][]const u8{ "h3", "h2" };
    for (labels, [_]usize{ 2, 1 }) |label, index| {
        const bounded = try harness.open(label, "prune-recovery-window", targets[index]);
        defer bounded.deinit();
        const recovered = try bounded.committed_targets();
        try testing.expect(db.targets_eql(Current.SyncTarget, &targets[index], &recovered));
    }
}
