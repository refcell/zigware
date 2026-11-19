//! Tests for the freezer, ported from commonware's `freezer/mod.rs`, and the
//! `freezer_operations` fuzz target (storage/fuzz) checked against a reference model.
//!
//! Restarts close the freezer (or drop it) and reopen it from a checkpoint on the same storage;
//! `crash()` drops unsynced data as commonware's `start_and_recover` does. Commonware's
//! determinism test compares auditor states; here it compares storage audits.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const cryptography = @import("cryptography");
const metrics = runtime.telemetry.metrics;
const freezer = @import("mod.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");

const MockStorage = runtime.buffer.mocks.Storage;
const Checkpoint = freezer.Checkpoint;
const gpa = testing.allocator;

const Key = [64]u8;
const F = freezer.Freezer(Key, i32);

const default_write_buffer: usize = 1024;
const default_value_target_size: u64 = 10 * 1024 * 1024;
const default_table_initial_size: u32 = 256;
const default_table_resize_frequency: u8 = 4;
const default_table_resize_chunk_size: u32 = 128;
const default_table_replay_buffer: usize = 64 * 1024;

fn test_key(name: []const u8) Key {
    var key: Key = @splat(0);
    @memcpy(key[0..name.len], name);
    return key;
}

const Harness = struct {
    storage: MockStorage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init() !Harness {
        return .{
            .storage = MockStorage.init(gpa),
            .cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn config(self: *Harness, comptime V: type) freezer.Config(V) {
        return .{
            .key_partition = "test-key-index",
            .key_write_buffer = default_write_buffer,
            .key_cache_ref = &self.cache_ref,
            .value_partition = "test-value-journal",
            .value_write_buffer = default_write_buffer,
            .value_target_size = default_value_target_size,
            .table_partition = "test-table",
            .table_initial_size = default_table_initial_size,
            .table_resize_frequency = default_table_resize_frequency,
            .table_resize_chunk_size = default_table_resize_chunk_size,
            .table_replay_buffer = default_table_replay_buffer,
            .codec_config = {},
        };
    }

    fn open(
        self: *Harness,
        comptime K: type,
        comptime V: type,
        cfg: freezer.Config(V),
        checkpoint: ?Checkpoint,
    ) !freezer.Freezer(K, V) {
        const scope = metrics.Scope.init(&self.registry).child("storage");
        return freezer.Freezer(K, V).init(gpa, self.storage.interface(), scope, cfg, checkpoint);
    }

    fn expect_metric(self: *Harness, needle: []const u8) !void {
        const text = try self.registry.encode(gpa);
        defer gpa.free(text);
        if (std.mem.indexOf(u8, text, needle) == null) {
            std.debug.print("missing '{s}' in:\n{s}\n", .{ needle, text });
            return error.TestExpectedMetric;
        }
    }

    fn reset_metrics(self: *Harness) void {
        self.registry.deinit();
        self.registry = metrics.Registry.init(gpa);
    }

    /// Write `bytes` durably at `offset` of the table blob (null appends).
    fn write_table(self: *Harness, offset: ?u64, bytes: []const u8) !void {
        const opened = try self.storage.open("test-table", freezer.table_blob_name);
        defer opened.blob.close();
        try opened.blob.write_at(offset orelse opened.len, bytes, .{});
        try opened.blob.sync();
    }
};

fn expect_get(store: *F, name: []const u8, expected: ?i32) !void {
    const key = test_key(name);
    try testing.expectEqual(expected, try store.get(.{ .key = &key }));
}

fn check_put_get(compression: ?u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var cfg = harness.config(i32);
    cfg.value_compression = compression;
    var store = try harness.open(Key, i32, cfg, null);
    defer store.deinit();
    try expect_get(&store, "testkey", null);
    _ = try store.put(test_key("testkey"), 42);
    try expect_get(&store, "testkey", 42);
    try harness.expect_metric("gets_total 2");
    try harness.expect_metric("puts_total 1");
    try harness.expect_metric("unnecessary_reads_total 0");
    _ = try store.sync();
}

test "freezer put get no compression" {
    try check_put_get(null);
}

test "freezer put get compression" {
    try check_put_get(3);
}

test "freezer has" {
    var harness = try Harness.init();
    defer harness.deinit();
    var store = try harness.open(Key, i32, harness.config(i32), null);
    defer store.deinit();
    try testing.expect(!try store.has(test_key("testkey")));
    _ = try store.put(test_key("testkey"), 42);
    try testing.expect(try store.has(test_key("testkey")));
    try testing.expect(!try store.has(test_key("otherkey")));
    // Existence checks count as has, never as gets.
    try harness.expect_metric("has_total 3");
    try harness.expect_metric("gets_total 0");
}

test "freezer multiple keys" {
    var harness = try Harness.init();
    defer harness.deinit();
    var store = try harness.open(Key, i32, harness.config(i32), null);
    defer store.deinit();
    const names = [_][]const u8{ "key1", "key2", "key3", "key4", "key5" };
    for (names, 1..) |name, value| _ = try store.put(test_key(name), @intCast(value));
    for (names, 1..) |name, value| try expect_get(&store, name, @intCast(value));
}

test "freezer collision handling" {
    var harness = try Harness.init();
    defer harness.deinit();
    var cfg = harness.config(i32);
    cfg.table_initial_size = 4;
    var store = try harness.open(Key, i32, cfg, null);
    defer store.deinit();
    const names = [_][]const u8{ "key1", "key2", "key3", "key4", "key5", "key6", "key7", "key8" };
    for (names, 1..) |name, value| _ = try store.put(test_key(name), @intCast(value));
    _ = try store.sync();
    for (names, 1..) |name, value| try expect_get(&store, name, @intCast(value));
    try harness.expect_metric("gets_total 8");
    // The number of chain links walked past depends on crc32c(key) & 3, as in commonware.
    try harness.expect_metric("unnecessary_reads_total 5");
}

test "freezer restart" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config(i32);
    const names = [_][]const u8{ "persist1", "persist2", "persist3" };
    const checkpoint = checkpoint: {
        var store = try harness.open(Key, i32, cfg, null);
        for (names, 1..) |name, i| _ = try store.put(test_key(name), @intCast(i * 100));
        break :checkpoint store.close() catch |err| {
            store.deinit();
            return err;
        };
    };
    harness.reset_metrics();
    var store = try harness.open(Key, i32, cfg, checkpoint);
    defer store.deinit();
    for (names, 1..) |name, i| try expect_get(&store, name, @intCast(i * 100));
}

test "freezer crash consistency" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config(i32);
    const checkpoint = checkpoint: {
        var store = try harness.open(Key, i32, cfg, null);
        defer store.deinit();
        _ = try store.put(test_key("committed1"), 1);
        _ = try store.put(test_key("committed2"), 2);
        const checkpoint = try store.sync();
        // Unsynced puts are lost in the crash.
        _ = try store.put(test_key("uncommitted1"), 3);
        _ = try store.put(test_key("uncommitted2"), 4);
        break :checkpoint checkpoint;
    };
    harness.storage.crash();
    harness.reset_metrics();
    var store = try harness.open(Key, i32, cfg, checkpoint);
    defer store.deinit();
    try expect_get(&store, "committed1", 1);
    try expect_get(&store, "committed2", 2);
    // Restoring the checkpoint truncates everything past it, so uncommitted data is gone.
    try expect_get(&store, "uncommitted1", null);
    try expect_get(&store, "uncommitted2", null);
}

test "freezer restore drops data written after the checkpoint" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config(i32);
    const checkpoint = checkpoint: {
        var store = try harness.open(Key, i32, cfg, null);
        defer store.deinit();
        _ = try store.put(test_key("before"), 1);
        const checkpoint = try store.sync();
        // Synced after the checkpoint was taken: durable, but newer than it.
        _ = try store.put(test_key("after"), 2);
        _ = try store.sync();
        break :checkpoint checkpoint;
    };
    harness.reset_metrics();
    var store = try harness.open(Key, i32, cfg, checkpoint);
    defer store.deinit();
    try expect_get(&store, "before", 1);
    try expect_get(&store, "after", null);
    // New writes after the restore are visible.
    _ = try store.put(test_key("again"), 3);
    try expect_get(&store, "again", 3);
}

test "freezer destroy" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config(i32);
    {
        var store = try harness.open(Key, i32, cfg, null);
        _ = try store.put(test_key("destroy1"), 1);
        _ = try store.put(test_key("destroy2"), 2);
        try store.destroy();
    }
    harness.reset_metrics();
    var store = try harness.open(Key, i32, cfg, null);
    defer store.deinit();
    try expect_get(&store, "destroy1", null);
    try expect_get(&store, "destroy2", null);
}

/// Store `key1 = 42`, sync, close, then damage the table with `corrupt`.
fn closed_with_key1(harness: *Harness) !Checkpoint {
    var store = try harness.open(Key, i32, harness.config(i32), null);
    _ = store.put(test_key("key1"), 42) catch |err| {
        store.deinit();
        return err;
    };
    _ = store.sync() catch |err| {
        store.deinit();
        return err;
    };
    const checkpoint = store.close() catch |err| {
        store.deinit();
        return err;
    };
    harness.reset_metrics();
    return checkpoint;
}

test "freezer partial table entry write" {
    var harness = try Harness.init();
    defer harness.deinit();
    const checkpoint = try closed_with_key1(&harness);
    const garbage: [10]u8 = @splat(0xFF);
    try harness.write_table(0, &garbage);
    var store = try harness.open(Key, i32, harness.config(i32), checkpoint);
    defer store.deinit();
    // The damaged slot is cleared; the key is gone or intact, never wrong.
    const result = try store.get(.{ .key = &test_key("key1") });
    try testing.expect(result == null or result.? == 42);
}

test "freezer table entry invalid crc" {
    var harness = try Harness.init();
    defer harness.deinit();
    const checkpoint = try closed_with_key1(&harness);
    for (0..default_table_initial_size) |index| {
        // Flip a CRC byte of the first slot of every entry.
        const offset = index * freezer.Entry.full_size + 25;
        try harness.write_table(offset, &.{0xFF});
    }
    var store = try harness.open(Key, i32, harness.config(i32), checkpoint);
    defer store.deinit();
    const result = try store.get(.{ .key = &test_key("key1") });
    try testing.expect(result == null or result.? == 42);
}

test "freezer table extra bytes" {
    var harness = try Harness.init();
    defer harness.deinit();
    const checkpoint = try closed_with_key1(&harness);
    try harness.write_table(null, &.{ 0xde, 0xad, 0xbe, 0xef });
    var store = try harness.open(Key, i32, harness.config(i32), checkpoint);
    defer store.deinit();
    try expect_get(&store, "key1", 42);
    _ = try store.put(test_key("key2"), 43);
    try expect_get(&store, "key2", 43);
}

test "freezer checkpoint against a missing or short table is a mismatch" {
    var harness = try Harness.init();
    defer harness.deinit();
    var checkpoint = try closed_with_key1(&harness);
    checkpoint.table_size *= 2;
    try testing.expectError(
        error.CheckpointMismatch,
        harness.open(Key, i32, harness.config(i32), checkpoint),
    );
}

test "freezer indexing across resizes" {
    var harness = try Harness.init();
    defer harness.deinit();
    var cfg = harness.config(i32);
    cfg.table_initial_size = 2;
    cfg.table_resize_frequency = 2;
    var name_buffer: [16]u8 = undefined;
    const count = 1000;
    const checkpoint = checkpoint: {
        var store = try harness.open(Key, i32, cfg, null);
        errdefer store.deinit();
        for (0..count) |i| {
            const name = try std.fmt.bufPrint(&name_buffer, "key{d}", .{i});
            _ = try store.put(test_key(name), @intCast(i));
            _ = try store.sync();
        }
        for (0..count) |i| {
            const name = try std.fmt.bufPrint(&name_buffer, "key{d}", .{i});
            try expect_get(&store, name, @intCast(i));
        }
        try harness.expect_metric("resizes_total 8");
        break :checkpoint try store.close();
    };
    harness.reset_metrics();
    var store = try harness.open(Key, i32, cfg, checkpoint);
    defer store.deinit();
    for (0..count) |i| {
        const name = try std.fmt.bufPrint(&name_buffer, "key{d}", .{i});
        try expect_get(&store, name, @intCast(i));
    }
}

fn small_resize_config(harness: *Harness) freezer.Config(i32) {
    var cfg = harness.config(i32);
    cfg.table_initial_size = 2;
    cfg.table_resize_frequency = 1;
    cfg.table_resize_chunk_size = 1;
    return cfg;
}

test "freezer insert during resize" {
    var harness = try Harness.init();
    defer harness.deinit();
    var store = try harness.open(Key, i32, small_resize_config(&harness), null);
    defer store.deinit();
    // key0 maps to entry 0 and key2 to entry 1.
    _ = try store.put(test_key("key0"), 0);
    _ = try store.put(test_key("key2"), 1);
    _ = try store.sync(); // Starts the resize.
    try testing.expect(store.resizing() != null);
    // key6 maps to the already split entry 0.
    _ = try store.put(test_key("key6"), 2);
    try harness.expect_metric("unnecessary_writes_total 1");
    try testing.expectEqual(@as(u32, 3), store.resizable_entries());
    // key3 maps to the unsplit entry 1.
    _ = try store.put(test_key("key3"), 3);
    try harness.expect_metric("unnecessary_writes_total 1");
    try testing.expectEqual(@as(u32, 3), store.resizable_entries());
    _ = try store.sync();
    try testing.expectEqual(@as(?u32, null), store.resizing());
    try testing.expectEqual(@as(u32, 2), store.resizable_entries());
    _ = try store.put(test_key("key4"), 4);
    _ = try store.put(test_key("key7"), 5);
    _ = try store.sync();
    try testing.expect(store.resizing() != null);
    const names = [_][]const u8{ "key0", "key2", "key6", "key3", "key4", "key7" };
    for (names, 0..) |name, i| try expect_get(&store, name, @intCast(i));
    while (store.resizing() != null) _ = try store.sync();
    try testing.expectEqual(@as(u32, 0), store.resizable_entries());
}

test "freezer resize after startup" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = small_resize_config(&harness);
    const checkpoint = checkpoint: {
        var store = try harness.open(Key, i32, cfg, null);
        defer store.deinit();
        _ = try store.put(test_key("key0"), 0);
        _ = try store.put(test_key("key2"), 1);
        const checkpoint = try store.sync();
        try testing.expect(store.resizing() != null);
        break :checkpoint checkpoint;
    };
    harness.reset_metrics();
    var store = try harness.open(Key, i32, cfg, checkpoint);
    defer store.deinit();
    try testing.expectEqual(@as(u32, 1), store.resizable_entries());
    try testing.expectEqual(@as(?u32, null), store.resizing());
    // The resize restarts from the checkpointed table.
    _ = try store.sync();
    try testing.expectEqual(@as(?u32, 1), store.resizing());
    while (store.resizing() != null) _ = try store.sync();
    try testing.expectEqual(@as(u32, 0), store.resizable_entries());
}

test "freezer put multiple updates" {
    var harness = try Harness.init();
    defer harness.deinit();
    var store = try harness.open(Key, i32, harness.config(i32), null);
    defer store.deinit();
    _ = try store.put(test_key("key1"), 1);
    _ = try store.put(test_key("key1"), 2);
    _ = try store.sync();
    // The latest put shadows the earlier one.
    try expect_get(&store, "key1", 2);
}

/// Commonware's `test_operations_and_restart`: random 96-byte keys and 256-byte values over
/// many sections, random syncs, a restart, and more puts. Returns the storage audit.
fn check_operations_and_restart(num_keys: usize) ![4]u8 {
    const BigKey = [96]u8;
    const Value = [256]u8;
    const G = freezer.Freezer(BigKey, Value);
    var harness = try Harness.init();
    defer harness.deinit();
    var cfg = harness.config(Value);
    cfg.value_target_size = 128;
    cfg.table_initial_size = 8;
    cfg.table_resize_frequency = 2;
    var rng = utils.rng.TestRng.init(0);
    const keys = try gpa.alloc(BigKey, num_keys);
    defer gpa.free(keys);
    const values = try gpa.alloc(Value, num_keys);
    defer gpa.free(values);
    const checkpoint = checkpoint: {
        var store = try harness.open(BigKey, Value, cfg, null);
        errdefer store.deinit();
        for (keys, values) |*key, *value| {
            rng.fill_bytes(key);
            rng.fill_bytes(value);
            _ = try store.put(key.*, value.*);
            if (utils.rng.bernoulli(&rng, 0.1)) _ = try store.sync();
        }
        _ = try store.sync();
        for (keys, values) |*key, value| {
            try testing.expectEqual(value, (try store.get(.{ .key = key })).?);
        }
        for (0..10) |_| {
            var key: BigKey = undefined;
            rng.fill_bytes(&key);
            try testing.expectEqual(@as(?Value, null), try store.get(.{ .key = &key }));
        }
        break :checkpoint try store.close();
    };
    harness.reset_metrics();
    var store: G = try harness.open(BigKey, Value, cfg, checkpoint);
    defer store.deinit();
    for (keys, values) |*key, value| {
        try testing.expectEqual(value, (try store.get(.{ .key = key })).?);
    }
    for (0..10) |_| {
        var key: BigKey = undefined;
        var value: Value = undefined;
        rng.fill_bytes(&key);
        rng.fill_bytes(&value);
        _ = try store.put(key, value);
    }
    _ = try store.sync();
    return harness.storage.backend.audit();
}

test "freezer determinism" {
    const first = try check_operations_and_restart(300);
    const second = try check_operations_and_restart(300);
    try testing.expectEqual(first, second);
}

// `freezer_operations` fuzz target: random puts (keys drawn from a small pool so collisions
// and shadowing happen), gets, has, syncs, crash restarts from the last checkpoint, and
// closes, checked against a model of the latest value per key at each checkpoint.

const fuzz_operations_max = 64;
const fuzz_keys = 24;
const FuzzKey = [8]u8;
const FuzzFreezer = freezer.Freezer(FuzzKey, u32);

const FuzzModel = struct {
    latest: [fuzz_keys]?u32 = @splat(null),
};

fn fuzz_key(index: u64) FuzzKey {
    var key: FuzzKey = undefined;
    std.mem.writeInt(u64, &key, index *% 0x9e3779b97f4a7c15, .big);
    return key;
}

fn fuzz_open(harness: *Harness, cfg: freezer.Config(u32), checkpoint: ?Checkpoint) !FuzzFreezer {
    harness.reset_metrics();
    return harness.open(FuzzKey, u32, cfg, checkpoint);
}

fn fuzz_check(store: *FuzzFreezer, model: *const FuzzModel) !void {
    for (model.latest, 0..) |expected, index| {
        const key = fuzz_key(index);
        try testing.expectEqual(expected, try store.get(.{ .key = &key }));
        try testing.expectEqual(expected != null, try store.has(key));
    }
}

fn fuzz_run(input: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(input);
    var harness = try Harness.init();
    defer harness.deinit();
    var cfg = harness.config(u32);
    cfg.table_initial_size = @as(u32, 1) << @intCast(reader.below(4));
    cfg.table_resize_frequency = @intCast(1 + reader.below(4));
    cfg.table_resize_chunk_size = @intCast(1 + reader.below(4));
    cfg.value_target_size = 16 + reader.below(256);
    var store = try fuzz_open(&harness, cfg, null);
    var model: FuzzModel = .{};
    var committed: FuzzModel = .{};
    var checkpoint: ?Checkpoint = null;
    var operations: u32 = 0;
    var live = true;
    defer if (live) store.deinit();
    while (!reader.done() and operations < fuzz_operations_max) : (operations += 1) {
        switch (reader.below(6)) {
            0, 1 => {
                const index = reader.below(fuzz_keys);
                const value: u32 = @truncate(reader.int(u64));
                const cursor = try store.put(fuzz_key(index), value);
                model.latest[index] = value;
                try testing.expectEqual(@as(?u32, value), try store.get(.{ .cursor = cursor }));
            },
            2 => {
                checkpoint = try store.sync();
                committed = model;
            },
            3 => {
                // Crash and restore the last checkpoint: later puts are lost.
                live = false;
                store.deinit();
                harness.storage.crash();
                store = try fuzz_open(&harness, cfg, checkpoint);
                live = true;
                model = committed;
            },
            4 => {
                const closed = try store.close();
                live = false;
                store = try fuzz_open(&harness, cfg, closed);
                live = true;
                checkpoint = closed;
                committed = model;
            },
            5 => try fuzz_check(&store, &model),
            else => unreachable,
        }
    }
    try fuzz_check(&store, &model);
}

test "fuzz freezer operations (seeded)" {
    try fuzz_bytes.seeded(256, 0x66727a72, 48, fuzz_run);
}

test "fuzz freezer operations" {
    try testing.fuzz({}, fuzz_bytes.smith(256, fuzz_run), .{});
}

// Ported from commonware's `freezer/storage.rs` tests.

/// A freezer config with a small table: `initial` entries, resizing after every added item,
/// `chunk` entries per resize step.
fn table_config(harness: *Harness, initial: u32, chunk: u32) freezer.Config(i32) {
    var cfg = harness.config(i32);
    cfg.table_initial_size = initial;
    cfg.table_resize_frequency = 1;
    cfg.table_resize_chunk_size = chunk;
    return cfg;
}

/// The first key `be(value) || zeros` whose table index is `table_index` at `table_size`
/// (commonware `test_key_at_index`).
fn key_at_index(table_size: u32, table_index: u32) Key {
    std.debug.assert(std.math.isPowerOfTwo(table_size) and table_index < table_size);
    var value: u64 = 0;
    while (true) : (value += 1) {
        var key: Key = @splat(0);
        std.mem.writeInt(u64, key[0..8], value, .big);
        if (cryptography.Crc32.checksum(&key) & (table_size - 1) == table_index) return key;
    }
}

/// Reads the whole table blob. Caller frees it.
fn read_table(harness: *Harness) ![]u8 {
    const opened = try harness.storage.open("test-table", freezer.table_blob_name);
    defer opened.blob.close();
    const bytes = try gpa.alloc(u8, @intCast(opened.len));
    errdefer gpa.free(bytes);
    try opened.blob.read_at(0, bytes);
    return bytes;
}

test "freezer resize leaves empty entries empty (issue 2966)" {
    var harness = try Harness.init();
    defer harness.deinit();
    var store = try harness.open(Key, i32, table_config(&harness, 4, 4), null);
    // Two keys in two of four entries leave two empty.
    _ = store.put(test_key("key0"), 0) catch |err| return store_fail(&store, err);
    _ = store.put(test_key("key2"), 1) catch |err| return store_fail(&store, err);
    _ = try store.close();

    const table = try read_table(&harness);
    defer gpa.free(table);
    const full = freezer.Entry.full_size;
    try testing.expectEqual(@as(usize, 8 * full), table.len); // Resized from 4 to 8 entries.
    // An empty slot is all zeros; resize must not write a valid epoch-0 slot into one.
    var both_empty: usize = 0;
    for (0..8) |index| {
        const entry = table[index * full ..][0..full];
        if (std.mem.allEqual(u8, entry, 0)) both_empty += 1;
    }
    try testing.expectEqual(@as(usize, 4), both_empty);
}

fn store_fail(store: *F, err: anyerror) anyerror {
    store.deinit();
    return err;
}

test "freezer reopens over an entry whose two slots have bad crcs (issue 2955)" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = table_config(&harness, 4, 4);
    const checkpoint = checkpoint: {
        var store = try harness.open(Key, i32, cfg, null);
        errdefer store.deinit();
        _ = try store.put(test_key("key0"), 42);
        _ = try store.sync();
        break :checkpoint try store.close();
    };
    // Flip a CRC byte of both slots of entry 0. Recovery must clear them to truly empty
    // slots, not to an all-zero entry with a valid CRC (two "valid" epoch-0 slots).
    const fixed = freezer.Entry.fixed_size;
    try harness.write_table(fixed - 4, &.{0xFF});
    try harness.write_table(2 * fixed - 4, &.{0xFF});
    harness.reset_metrics();
    {
        var store = try harness.open(Key, i32, cfg, checkpoint);
        defer store.deinit();
        const result = try store.get(.{ .key = &test_key("key0") });
        try testing.expect(result == null or result.? == 42);
    }
    const table = try read_table(&harness);
    defer gpa.free(table);
    for (0..2) |slot| {
        const bytes = table[slot * fixed ..][0..fixed];
        try testing.expect(std.mem.allEqual(u8, bytes, 0));
    }
}

/// Opens with no checkpoint and checks the freezer starts empty at its initial size.
fn expect_reset(harness: *Harness, cfg: freezer.Config(i32), key: *const Key) !void {
    harness.reset_metrics();
    var store = try harness.open(Key, i32, cfg, null);
    defer store.deinit();
    try testing.expectEqual(@as(u32, 2), store.table_size);
    try testing.expectEqual(@as(?u32, null), store.resizing());
    try testing.expectEqual(@as(?i32, null), try store.get(.{ .key = key }));
}

test "freezer without a checkpoint deletes a resize a sync left partial" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = table_config(&harness, 2, 1);
    const key = key_at_index(4, 3);
    {
        var store = try harness.open(Key, i32, cfg, null);
        defer store.deinit();
        _ = try store.put(key, 42);
        _ = try store.sync();
        try testing.expectEqual(@as(?u32, 1), store.resizing());
        try testing.expectEqual(@as(?i32, 42), try store.get(.{ .key = &key }));
    }
    try expect_reset(&harness, cfg, &key);
}

test "freezer without a checkpoint deletes a resize close started" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = table_config(&harness, 2, 1);
    const key = key_at_index(4, 3);
    {
        var store = try harness.open(Key, i32, cfg, null);
        _ = store.put(key, 42) catch |err| return store_fail(&store, err);
        const checkpoint = try store.close();
        try testing.expectEqual(@as(u32, 2), checkpoint.table_size);
    }
    try expect_reset(&harness, cfg, &key);
}

test "freezer without a checkpoint deletes a completed resize" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = table_config(&harness, 2, 2);
    const key = key_at_index(4, 3);
    {
        var store = try harness.open(Key, i32, cfg, null);
        defer store.deinit();
        _ = try store.put(key, 42);
        const checkpoint = try store.sync();
        try testing.expectEqual(@as(u32, 4), checkpoint.table_size);
        try testing.expectEqual(@as(?u32, null), store.resizing());
        try testing.expectEqual(@as(?i32, 42), try store.get(.{ .key = &key }));
    }
    try expect_reset(&harness, cfg, &key);
}

test "freezer empty checkpoint deletes existing data" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = table_config(&harness, 2, 1);
    const key = key_at_index(4, 3);
    {
        var store = try harness.open(Key, i32, cfg, null);
        defer store.deinit();
        _ = try store.put(key, 42);
        _ = try store.sync();
        try testing.expectEqual(@as(?i32, 42), try store.get(.{ .key = &key }));
    }
    harness.reset_metrics();
    var store = try harness.open(Key, i32, cfg, .{});
    defer store.deinit();
    try testing.expectEqual(@as(u32, 2), store.table_size);
    try testing.expectEqual(@as(?i32, null), try store.get(.{ .key = &key }));
}

test "freezer non-empty checkpoint against an empty table is a mismatch" {
    var harness = try Harness.init();
    defer harness.deinit();
    const checkpoint: Checkpoint = .{ .epoch = 1, .table_size = 2 };
    try testing.expectError(
        error.CheckpointMismatch,
        harness.open(Key, i32, table_config(&harness, 2, 1), checkpoint),
    );
}

test "freezer corrupted committed value surfaces at read" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = table_config(&harness, 4, 4);
    const checkpoint = checkpoint: {
        var store = try harness.open(Key, i32, cfg, null);
        errdefer store.deinit();
        _ = try store.put(test_key("key0"), 42);
        _ = try store.put(test_key("key1"), 43);
        _ = try store.sync();
        break :checkpoint try store.close();
    };
    try testing.expect(checkpoint.oversized_size > 0);
    {
        // Flip the last byte of the value journal (the last committed value's checksum).
        var name: [8]u8 = undefined;
        std.mem.writeInt(u64, &name, checkpoint.section, .big);
        const opened = try harness.storage.open("test-value-journal", &name);
        defer opened.blob.close();
        var byte: [1]u8 = undefined;
        try opened.blob.read_at(opened.len - 1, &byte);
        byte[0] ^= 0xFF;
        try opened.blob.write_at(opened.len - 1, &byte, .{});
        try opened.blob.sync();
    }
    // Recovery does not probe committed values: init succeeds and only key1's read fails.
    harness.reset_metrics();
    var store = try harness.open(Key, i32, cfg, checkpoint);
    defer store.deinit();
    try testing.expectError(error.ChecksumMismatch, store.get(.{ .key = &test_key("key1") }));
    try expect_get(&store, "key0", 42);
    _ = try store.put(test_key("key2"), 44);
    _ = try store.sync();
    try expect_get(&store, "key2", 44);
}

test "freezer committed value section short by one byte fails init" {
    var harness = try Harness.init();
    defer harness.deinit();
    var cfg = table_config(&harness, 4, 4);
    cfg.value_target_size = 8; // One value per section.
    const checkpoint = checkpoint: {
        var store = try harness.open(Key, i32, cfg, null);
        errdefer store.deinit();
        _ = try store.put(test_key("key0"), 42);
        _ = try store.put(test_key("key1"), 43);
        _ = try store.sync();
        break :checkpoint try store.close();
    };
    try testing.expect(checkpoint.section > 0);
    {
        var name: [8]u8 = @splat(0); // Section 0.
        const opened = try harness.storage.open("test-value-journal", &name);
        defer opened.blob.close();
        try testing.expect(opened.len > 0);
        try opened.blob.resize(opened.len - 1);
        try opened.blob.sync();
    }
    // The checkpoint covers the damaged section: init fails, and nothing is repaired.
    for (0..2) |_| {
        harness.reset_metrics();
        try testing.expectError(error.Corruption, harness.open(Key, i32, cfg, checkpoint));
    }
}
