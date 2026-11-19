//! commonware `glue/src/stateful/db/any.rs` tests, over `any` databases of SHA-256 keys and
//! values with a `TwoCap` index: commonware's `UnorderedFixedDb`, and the variable-encoded and
//! ordered databases the adapter also manages.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const db = @import("mod.zig");
const any_mod = @import("any.zig");
const state_sync = @import("state_sync.zig");
const sync = @import("sync.zig");
const utils = @import("utils");

const qmdb = storage.qmdb;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Family = storage.mmr.Family;
const operation = qmdb.any.operation;
const metrics = runtime.telemetry.metrics;
const contiguous = storage.journal.contiguous;
const Unordered = storage.index.unordered.Index(storage.translator.TwoCap, u64);
const Ordered = storage.index.ordered.Index(storage.translator.TwoCap, u64);

/// An `any` database over `Digest` keys and `E`-encoded values, ordered or not, with
/// commonware's 64-byte bitmap chunks (`ANY_BITMAP_CHUNK_BYTES`).
fn Database(comptime ordered: bool, comptime E: type) type {
    const Operation = if (ordered) operation.Ordered else operation.Unordered;
    const Update = if (ordered) operation.update.Ordered else operation.update.Unordered;
    const Op = Operation(Family, Digest, E);
    const Journal = if (E.fixed) contiguous.fixed.Journal(Op) else contiguous.variable.Journal(Op);
    const Index = if (ordered) Ordered else Unordered;
    const Inner = qmdb.any.Db(Family, Update(Digest, E), Journal, Index, Sha256, 64);
    return any_mod.Any(Inner, Sha256);
}

/// commonware's `UnorderedFixedDb` and the variable and ordered databases the adapter also
/// manages, all with `Digest` values.
const variants = .{
    Database(false, qmdb.value.Fixed(Digest)),
    Database(false, qmdb.value.Variable(Digest)),
    Database(true, qmdb.value.Fixed(Digest)),
    Database(true, qmdb.value.Variable(Digest)),
};

/// The codec configuration of a test operation: units stay units, and slices (a field
/// `range`) are bounded to 10000 items. Configurations nest at most one tuple deep.
fn codec_config(comptime C: type) C {
    if (comptime is_slice_cfg(C) or C == void) return leaf_config(C);
    var result: C = undefined;
    inline for (@typeInfo(C).@"struct".field_types, 0..) |field_type, index| {
        result[index] = leaf_config(field_type);
    }
    return result;
}

fn is_slice_cfg(comptime C: type) bool {
    return @typeInfo(C) == .@"struct" and @hasField(C, "range");
}

fn leaf_config(comptime C: type) C {
    if (comptime is_slice_cfg(C)) return .{ .range = .inclusive(0, 10000) };
    return codec.unit_cfg(C);
}

fn log_config(comptime LogCfg: type, cache_ref: *runtime.buffer.paged.CacheRef) LogCfg {
    if (comptime @hasField(LogCfg, "items_per_section")) return .{
        .partition = "stateful-any-log",
        .items_per_section = 7,
        .codec_config = codec_config(@FieldType(LogCfg, "codec_config")),
        .cache_ref = cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
    return .{
        .partition = "stateful-any-log",
        .items_per_blob = 7,
        .cache_ref = cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
}

/// Storage, a page cache, and metrics for opening test databases of `Any`.
fn Harness(comptime Any: type) type {
    return struct {
        const Self = @This();

        storage: runtime.buffer.mocks.Storage,
        cache_ref: runtime.buffer.paged.CacheRef,
        registry: metrics.Registry,

        fn init(harness: *Self) !void {
            harness.* = .{
                .storage = .init(testing.allocator),
                .cache_ref = try .init(testing.allocator, 101, 11),
                .registry = metrics.Registry.init(testing.allocator),
            };
        }

        fn deinit(harness: *Self) void {
            harness.registry.deinit();
            harness.cache_ref.deinit();
            harness.storage.deinit();
        }

        fn env(harness: *Self) db.Env {
            return .{
                .gpa = testing.allocator,
                .io = testing.io,
                .storage = harness.storage.interface(),
                .scope = metrics.Scope.init(&harness.registry).child("db"),
            };
        }

        fn config(harness: *Self) Any.Config {
            return .{
                .merkle = .{
                    .journal_partition = "stateful-any-journal",
                    .metadata_partition = "stateful-any-metadata",
                    .items_per_blob = 11,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                    .cache_ref = &harness.cache_ref,
                },
                .log = log_config(@FieldType(Any.Config, "log"), &harness.cache_ref),
                .translator = .{},
                .init_cache = 1024,
            };
        }

        /// Opens the database, registering its metrics afresh (as commonware's new child
        /// contexts do); the previous handle must be closed.
        fn open(harness: *Self, expected: ?Any.SyncTarget) !Any.Shared {
            harness.registry.deinit();
            harness.registry = metrics.Registry.init(testing.allocator);
            return Any.Shared.open(harness.env(), harness.config(), expected);
        }
    };
}

fn hash(text: []const u8) Digest {
    return Sha256.hash(&.{text});
}

/// Merkleizes a batch over `shared` writing `key` = `value`.
fn write_one(shared: anytype, key: Digest, value: Digest) !@TypeOf(shared).Merkleized {
    var batch = try shared.new_batches();
    errdefer batch.deinit();
    try batch.write(key, value);
    return batch.merkleize();
}

test "stateful any: an unmerkleized batch refuses reads after a competing finalization" {
    inline for (variants) |Any| try refuses_after_competing_finalization(Any);
}

fn refuses_after_competing_finalization(comptime Any: type) !void {
    var harness: Harness(Any) = undefined;
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
    inline for (variants) |Any| try apply_does_not_finalize(Any);
}

fn apply_does_not_finalize(comptime Any: type) !void {
    var harness: Harness(Any) = undefined;
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

fn start_sync_calls(shared: anytype) u64 {
    var guard = shared.read() catch unreachable; // testing.io does not cancel.
    defer guard.deinit();
    return guard.get().inner.metrics.start_sync_calls.metric().get();
}

test "stateful any: sync targets track applied batches and reopen" {
    inline for (variants) |Any| try sync_targets_track_applied_batches_and_reopen(Any);
}

fn sync_targets_track_applied_batches_and_reopen(comptime Any: type) !void {
    var harness: Harness(Any) = undefined;
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
        // The root alone does not match: the operation range must too.
        var shifted = target;
        shifted.start += 1;
        try testing.expect(!Any.matches_sync_target(&merkleized, &shifted));
        shifted = target;
        shifted.end += 1;
        try testing.expect(!Any.matches_sync_target(&merkleized, &shifted));
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
    inline for (variants) |Any| try a_child_batch_reads_its_parent_s_pending_writes(Any);
}

fn a_child_batch_reads_its_parent_s_pending_writes(comptime Any: type) !void {
    var harness: Harness(Any) = undefined;
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
    inline for (variants) |Any| try staged_merkleize_matches_explicit_writes(Any);
}

/// Seeds keys 0..50 and persists them.
fn seed_keys(shared: anytype) !void {
    var seed = try shared.new_batches();
    errdefer seed.deinit();
    for (0..50) |i| try seed.write(hash_u64(i), hash_u64(i + 10_000));
    var merkleized = try seed.merkleize();
    defer merkleized.deinit();
    try shared.apply(&merkleized);
    try (try shared.finalize()).durable();
}

/// Metadata set before staging carries through to the staged merkleize.
fn expect_carried_metadata(
    comptime Any: type,
    shared: Any.Shared,
    keys: *const [3]Digest,
    slots: []const Any.Slot,
    unstaged: []const Any.Mutation,
    metadata: Digest,
    explicit: struct { *const [3]?Digest, Digest },
) !void {
    var carried_values: [3]?Digest = undefined;
    var batch = try shared.new_batches();
    batch.with_metadata(metadata);
    var staged = batch.stage(keys, &carried_values) catch |err| {
        batch.deinit();
        return err;
    };
    var carried = try staged.merkleize(slots, unstaged);
    defer carried.deinit();
    try testing.expectEqualSlices(?Digest, explicit[0], &carried_values);
    try testing.expect(explicit[1].eql(carried.root()));
}

fn staged_merkleize_matches_explicit_writes(comptime Any: type) !void {
    var harness: Harness(Any) = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open(null);
    defer shared.deinit();
    const metadata = hash("metadata");

    try seed_keys(shared);

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

    try expect_carried_metadata(Any, shared, &keys, &slots, &unstaged, metadata, .{
        &explicit_values,
        explicit_root,
    });
}

/// commonware's variable-value adapter with owned byte values (`Vec<u8>`).
const Bytes = Database(false, qmdb.value.Variable([]const u8));

/// An owned value of `len` copies of `byte`.
fn bytes_of(byte: u8, len: usize) ![]const u8 {
    const value = try testing.allocator.alloc(u8, len);
    @memset(value, byte);
    return value;
}

/// Checks `got` (owned, freed here) against `len` copies of `byte`, or null.
fn expect_bytes(expected: ?struct { u8, usize }, got: ?[]const u8) !void {
    defer codec.free(?[]const u8, testing.allocator, got);
    const want = expected orelse return testing.expectEqual(@as(?[]const u8, null), got);
    try testing.expectEqual(want[1], got.?.len);
    for (got.?) |byte| try testing.expectEqual(want[0], byte);
}

test "stateful any: variable byte values move through batches and reopen" {
    var harness: Harness(Bytes) = undefined;
    try harness.init();
    defer harness.deinit();
    const a = hash("a");
    const b = hash("b");
    var target: Bytes.SyncTarget = undefined;
    {
        const shared = try harness.open(null);
        defer shared.deinit();
        var parent_batch = try shared.new_batches();
        errdefer parent_batch.deinit();
        try parent_batch.write(a, try bytes_of(1, 0));
        try parent_batch.write(b, try bytes_of(2, 300));
        parent_batch.with_metadata(try bytes_of(9, 5));
        var parent = try parent_batch.merkleize();
        defer parent.deinit();
        // A child sees its parent's values, with an update and a delete of its own.
        var child_batch = try Bytes.Shared.fork_batches(&parent);
        errdefer child_batch.deinit();
        try expect_bytes(.{ 2, 300 }, try child_batch.get(&b));
        try child_batch.write(a, try bytes_of(3, 7));
        try child_batch.write(b, null);
        var child = try child_batch.merkleize();
        defer child.deinit();
        try expect_bytes(.{ 1, 0 }, try parent.get(&a));
        var keys = [_]Digest{ a, b };
        var values: [2]?[]const u8 = undefined;
        try child.get_many(&keys, &values);
        try expect_bytes(.{ 3, 7 }, values[0]);
        try expect_bytes(null, values[1]);
        try shared.apply(&child);
        try (try shared.finalize()).durable();
        target = try shared.committed_targets();
        try testing.expect(Bytes.matches_sync_target(&child, &target));
    }
    // The applied values survive a reopen at the committed target.
    const shared = try harness.open(target);
    defer shared.deinit();
    var batch = try shared.new_batches();
    defer batch.deinit();
    try expect_bytes(.{ 3, 7 }, try batch.get(&a));
    try expect_bytes(null, try batch.get(&b));
}

test "stateful any: every adapter implements StateSyncDb" {
    comptime {
        for (variants) |Any| state_sync.assert_state_sync_db(Any);
        state_sync.assert_state_sync_db(Bytes);
    }
}

/// Syncs a fresh `Any` (on its own storage and page cache) from a populated one served from
/// its log, with no later tips, and checks it reached the source's target and values.
fn syncs_from_populated(comptime Any: type) !void {
    var source_harness: Harness(Any) = undefined;
    try source_harness.init();
    defer source_harness.deinit();
    const source = try source_harness.open(null);
    defer source.deinit();
    try seed_keys(source);
    const target = try source.committed_targets();

    var guard = try source.read();
    defer guard.deinit();
    const Log = @FieldType(Any.Database, "log");
    var log_source: qmdb.sync.JournalSource(Family, Log) = .{ .journal = &guard.get().inner.log };
    var harness: Harness(Any) = undefined;
    try harness.init();
    defer harness.deinit();
    var tips = try utils.channel.ring.channel(
        sync.TipUpdate(Digest, Any.SyncTarget),
        testing.allocator,
        testing.io,
        1,
    );
    tips.sender.deinit();
    const start: sync.Anchor(Digest) = .{
        .height = .new(1),
        .round = .new(.zero(), .new(1)),
        .digest = .{ .bytes = @splat(1) },
    };
    const synced = try state_sync.sync_shared(
        Any,
        Digest,
        harness.env(),
        harness.config(),
        &log_source,
        start,
        target,
        tips.receiver,
        .{ .fetch_batch_size = 3, .apply_batch_size = 2, .max_outstanding_requests = 2 },
    );
    defer synced.databases.deinit();
    const reached = try synced.databases.committed_targets();
    try testing.expect(db.targets_eql(Any.SyncTarget, &reached, &target));
    var batch = try synced.databases.new_batches();
    defer batch.deinit();
    try testing.expectEqual(hash_u64(10_007), (try batch.get(&hash_u64(7))).?);
}

test "stateful any: a database syncs from a populated one" {
    inline for (variants) |Any| try syncs_from_populated(Any);
}
