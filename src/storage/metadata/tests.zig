//! Tests for `Metadata`, ported from commonware's `storage/src/metadata/mod.rs`, plus the
//! `metadata_operations` fuzz target (storage/fuzz) checked against a reference model.
//!
//! Keys are `u64`, whose codec encoding (8 bytes, big-endian) is commonware's `U64`.
//! Values are `[]const u8` (`Vec<u8>`). Metric names map to fields: `sync_rewrites`,
//! `sync_overwrites`, `count()` for `keys`, and the memory storage's `write_bytes` for
//! `runtime_storage_write_bytes_total`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const metadata = @import("mod.zig");
const memory = @import("../journal/memory.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");
const Crc32 = @import("cryptography").crc32.Crc32;

const Storage = memory.Storage;
const Store = metadata.Metadata(Storage, u64, []const u8);
const gpa = testing.allocator;

const config: metadata.Config([]const u8) = .{
    .partition = "test",
    .codec_config = .{ .range = .full(), .item = {} },
};

fn open(storage: *Storage) !Store {
    return Store.init(gpa, storage, config);
}

/// Put a copy of `bytes`, freeing any previous value.
fn put(store: *Store, key: u64, bytes: []const u8) !void {
    const value = try gpa.dupe(u8, bytes);
    errdefer gpa.free(value);
    if (try store.put(key, value)) |previous| gpa.free(previous);
}

/// Put `len` copies of `byte`.
fn put_fill(store: *Store, key: u64, byte: u8, len: usize) !void {
    const value = try gpa.alloc(u8, len);
    errdefer gpa.free(value);
    @memset(value, byte);
    if (try store.put(key, value)) |previous| gpa.free(previous);
}

fn expect_value(store: *const Store, key: u64, expected: ?[]const u8) !void {
    const value = store.get(key);
    if (expected) |bytes| {
        try testing.expect(value != null);
        try testing.expectEqualSlices(u8, bytes, value.?.*);
    } else {
        try testing.expect(value == null);
    }
}

fn expect_metrics(store: *const Store, rewrites: u64, overwrites: u64, keys: usize) !void {
    try testing.expectEqual(rewrites, store.sync_rewrites);
    try testing.expectEqual(overwrites, store.sync_overwrites);
    try testing.expectEqual(keys, store.count());
}

/// Overwrite the start of blob `name` with junk, durably.
fn corrupt(storage: *Storage, name: []const u8) !void {
    const opened = try storage.open("test", name);
    defer opened.blob.deinit();
    try opened.blob.write_at(0, "corrupted");
    try opened.blob.sync();
}

/// Truncate blob `name` to `len` (or by `shrink` bytes), durably.
fn truncate(storage: *Storage, name: []const u8, len: ?u64, shrink: u64) !void {
    const opened = try storage.open("test", name);
    defer opened.blob.deinit();
    try opened.blob.resize(len orelse opened.len - shrink);
    try opened.blob.sync();
}

test "put get clear" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    try expect_value(&store, 42, null);
    try expect_metrics(&store, 0, 0, 0);

    try put(&store, 42, "hello");
    try expect_value(&store, 42, "hello");
    try expect_metrics(&store, 0, 0, 1);
    try store.sync();
    try expect_metrics(&store, 1, 0, 1);
    store.deinit();

    store = try open(&storage);
    try expect_metrics(&store, 0, 0, 1);
    try expect_value(&store, 42, "hello");
    store.clear();
    try expect_value(&store, 42, null);
    try expect_metrics(&store, 0, 0, 0);
    try store.destroy();
    try testing.expectEqual(@as(usize, 0), storage.partitions.count());
}

test "put returns previous value" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    for ([_][]const u8{ "first", "second", "third" }, 0..) |value, index| {
        const previous = try store.put(42, try gpa.dupe(u8, value));
        defer if (previous) |bytes| gpa.free(bytes);
        try testing.expectEqual(index == 0, previous == null);
        if (index == 1) try testing.expectEqualStrings("first", previous.?);
        if (index == 2) try testing.expectEqualStrings("second", previous.?);
    }
    try expect_value(&store, 42, "third");
    try testing.expect(try store.put(99, try gpa.dupe(u8, "other")) == null);
    try store.sync();
    store.deinit();

    store = try open(&storage);
    const previous = try store.put(42, try gpa.dupe(u8, "fourth"));
    defer gpa.free(previous.?);
    try testing.expectEqualStrings("third", previous.?);
    try store.destroy();
}

test "multi sync" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    try put(&store, 42, "hello");
    try store.sync();
    try expect_metrics(&store, 1, 0, 1);
    try put(&store, 42, "world");
    try put(&store, 43, "foo");
    try store.sync();
    try expect_metrics(&store, 2, 0, 2);
    store.deinit();

    store = try open(&storage);
    try expect_metrics(&store, 0, 0, 2);
    try expect_value(&store, 42, "world");
    try expect_value(&store, 43, "foo");
    gpa.free(store.remove(42).?);
    try store.sync();
    try expect_metrics(&store, 1, 0, 1);
    store.deinit();

    store = try open(&storage);
    try expect_metrics(&store, 0, 0, 1);
    try expect_value(&store, 42, null);
    try expect_value(&store, 43, "foo");
    try store.destroy();
}

/// Two syncs: "hello" lands in the right blob, then "world" and "foo" in the left blob.
fn write_two_versions(storage: *Storage) !void {
    var store = try open(storage);
    defer store.deinit();
    try put(&store, 42, "hello");
    try store.sync();
    try put(&store, 42, "world");
    try put(&store, 43, "foo");
    try store.sync();
}

test "recover from a corrupted, truncated, or short copy" {
    for (0..3) |case| {
        var storage = Storage.init(gpa);
        defer storage.deinit();
        try write_two_versions(&storage);
        switch (case) {
            0 => try corrupt(&storage, "left"),
            1 => try truncate(&storage, "left", null, 8),
            2 => try truncate(&storage, "left", 5, 0),
            else => unreachable,
        }
        // Falls back to the other copy.
        var store = try open(&storage);
        try expect_value(&store, 42, "hello");
        try expect_value(&store, 43, null);
        try store.destroy();
    }
}

test "recovered buffer supports shrinking rewrite" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    try write_two_versions(&storage);
    // Corrupt the newer copy so the next initialization must repair it. The repaired copy
    // must support a shrinking rewrite: a stale tail left behind by recovery would survive
    // the smaller write and poison the next reopen.
    try corrupt(&storage, "left");
    var store = try open(&storage);
    try expect_value(&store, 42, "hello");
    store.clear();
    try store.sync();
    store.deinit();

    store = try open(&storage);
    try expect_value(&store, 42, null);
    try store.destroy();
}

test "both copies corrupted is an error" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    try write_two_versions(&storage);
    try corrupt(&storage, "left");
    try corrupt(&storage, "right");
    // Impossible under a crash (syncs alternate and drain), so reopening fails loudly
    // rather than adopting a fresh store, every time.
    for (0..2) |_| try testing.expectError(error.Corruption, open(&storage));
}

test "unclean shutdown" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    try put(&store, 42, "hello");
    store.deinit(); // Dropped before sync.

    store = try open(&storage);
    try expect_value(&store, 42, null);
    try expect_metrics(&store, 0, 0, 0);
    try store.destroy();
}

test "delta writes" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    defer store.deinit();
    for (0..100) |i| try put_fill(&store, i, @intCast(i), 100);

    // 100 keys * (8 key + 1 length + 100 value) + 8 version + 4 checksum.
    const steps = [_]struct { rewrites: u64, overwrites: u64, bytes: u64 }{
        .{ .rewrites = 1, .overwrites = 0, .bytes = 10912 },
        // One modified key: rewrite everything to the second blob.
        .{ .rewrites = 2, .overwrites = 0, .bytes = 21824 },
        // Only the diff reaches the first blob: 1 + 100 + 8 + 4 bytes.
        .{ .rewrites = 2, .overwrites = 1, .bytes = 21937 },
        // Both blobs already hold the latest state.
        .{ .rewrites = 2, .overwrites = 1, .bytes = 21937 },
        // Removing a key rewrites everything, twice: 99 * 109 + 12 bytes each.
        .{ .rewrites = 3, .overwrites = 1, .bytes = 32740 },
        .{ .rewrites = 4, .overwrites = 1, .bytes = 43543 },
        // An in-place modification overwrites.
        .{ .rewrites = 4, .overwrites = 2, .bytes = 43656 },
    };
    for (steps, 0..) |step, index| {
        if (index == 1) try put_fill(&store, 51, 0xff, 100);
        if (index == 4) gpa.free(store.remove(51).?);
        if (index == 6) try put_fill(&store, 50, 0xff, 100);
        try store.sync();
        try testing.expectEqual(step.rewrites, store.sync_rewrites);
        try testing.expectEqual(step.overwrites, store.sync_overwrites);
        try testing.expectEqual(step.bytes, storage.write_bytes);
    }
}

test "multi key overwrites" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    for (0..100) |i| try put_fill(&store, i, @intCast(i), 100);
    try store.sync();
    try store.sync();
    try testing.expectEqual(@as(u64, 2), store.sync_rewrites);
    try testing.expectEqual(@as(u64, 21824), storage.write_bytes);

    // Six equal-size updates overwrite in place: 6 * 101 + 12 bytes, once per blob.
    for ([_]u64{ 10, 11, 12, 50, 98, 99 }) |key| try put_fill(&store, key, 0xAA, 100);
    try store.sync();
    try expect_metrics(&store, 2, 1, 100);
    try testing.expectEqual(@as(u64, 22442), storage.write_bytes);
    try store.sync();
    try expect_metrics(&store, 2, 2, 100);
    try testing.expectEqual(@as(u64, 23060), storage.write_bytes);
    try store.sync();
    try expect_metrics(&store, 2, 2, 100);
    try testing.expectEqual(@as(u64, 23060), storage.write_bytes);

    // A size change in one of several updates rewrites both blobs.
    try put_fill(&store, 20, 0xBB, 100);
    try put_fill(&store, 30, 0xCC, 150);
    try store.sync();
    try store.sync();
    try expect_metrics(&store, 4, 2, 100);
    store.deinit();

    store = try open(&storage);
    defer store.deinit();
    for (0..100) |i| {
        const value = store.get(i).?.*;
        const expected: struct { byte: u8, len: usize } = switch (i) {
            10, 11, 12, 50, 98, 99 => .{ .byte = 0xAA, .len = 100 },
            20 => .{ .byte = 0xBB, .len = 100 },
            30 => .{ .byte = 0xCC, .len = 150 },
            else => .{ .byte = @intCast(i), .len = 100 },
        };
        try testing.expectEqual(expected.len, value.len);
        for (value) |byte| try testing.expectEqual(expected.byte, byte);
    }
}

test "sync with no changes" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    try store.put_sync(1, try gpa.dupe(u8, "hello"));
    try store.sync();
    for (0..3) |_| {
        try expect_metrics(&store, 2, 0, 1);
        try store.sync();
    }
    store.deinit();
    store = try open(&storage);
    try expect_value(&store, 1, "hello");
    try store.destroy();
}

test "get mut marks modified" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    try store.put_sync(1, try gpa.dupe(u8, "hello"));
    try store.sync();
    const value = (try store.get_mut(1)).?;
    @constCast(value.*)[0] = 'H';
    try store.sync();
    try expect_metrics(&store, 2, 1, 1);
    store.deinit();
    store = try open(&storage);
    try expect_value(&store, 1, "Hello");
    try store.destroy();
}

test "mixed operation sequences" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    try put(&store, 1, "first");
    gpa.free(store.remove(1).?);
    try store.put_sync(1, try gpa.dupe(u8, "second"));
    try expect_value(&store, 1, "second");
    try put(&store, 1, "third");
    @constCast((try store.get_mut(1)).?.*)[0] = 'T';
    gpa.free(store.remove(1).?);
    try store.put_sync(1, try gpa.dupe(u8, "fourth"));
    try expect_value(&store, 1, "fourth");
    store.deinit();
    store = try open(&storage);
    try expect_value(&store, 1, "fourth");
    try store.destroy();
}

test "overwrite vs rewrite" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    defer store.deinit();
    try put_fill(&store, 1, 1, 10);
    try put_fill(&store, 2, 2, 10);
    try store.sync();

    const Step = struct { key: ?u64, byte: u8, len: usize, rewrites: u64, overwrites: u64 };
    const steps = [_]Step{
        // The second blob has never been written: rewrite.
        .{ .key = 1, .byte = 0xFF, .len = 10, .rewrites = 2, .overwrites = 0 },
        // The first blob only misses key 1's value: overwrite.
        .{ .key = null, .byte = 0, .len = 0, .rewrites = 2, .overwrites = 1 },
        .{ .key = 1, .byte = 0xAA, .len = 10, .rewrites = 2, .overwrites = 2 },
        // A size change rewrites.
        .{ .key = 1, .byte = 0xFF, .len = 20, .rewrites = 3, .overwrites = 2 },
        // A new key rewrites, and so does the next sync to catch up the other blob.
        .{ .key = 3, .byte = 3, .len = 10, .rewrites = 4, .overwrites = 2 },
        .{ .key = null, .byte = 0, .len = 0, .rewrites = 5, .overwrites = 2 },
        .{ .key = 2, .byte = 0xAA, .len = 10, .rewrites = 5, .overwrites = 3 },
    };
    for (steps) |step| {
        if (step.key) |key| try put_fill(&store, key, step.byte, step.len);
        try store.sync();
        try testing.expectEqual(step.rewrites, store.sync_rewrites);
        try testing.expectEqual(step.overwrites, store.sync_overwrites);
    }
}

test "blob resize" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    for (0..10) |i| try put_fill(&store, i, @intCast(i), 100);
    try store.sync();
    try store.sync();
    try expect_metrics(&store, 2, 0, 10);
    for (1..10) |i| gpa.free(store.remove(i).?);
    try store.sync();
    try expect_metrics(&store, 3, 0, 1);
    store.deinit();

    // The shrunk blob holds exactly one pair: 8 + 8 + 1 + 100 + 4 bytes.
    const opened = try storage.open("test", "right");
    try testing.expectEqual(@as(u64, 121), opened.len);
    opened.blob.deinit();
    store = try open(&storage);
    try testing.expectEqual(@as(usize, 100), store.get(0).?.len);
    for (1..10) |i| try expect_value(&store, i, null);
    try store.destroy();
}

test "clear and repopulate" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    try put(&store, 1, "first");
    try store.put_sync(2, try gpa.dupe(u8, "second"));
    store.clear();
    try store.sync();
    store.deinit();

    store = try open(&storage);
    try expect_value(&store, 1, null);
    try expect_value(&store, 2, null);
    try put(&store, 3, "third");
    try store.put_sync(4, try gpa.dupe(u8, "fourth"));
    try expect_value(&store, 3, "third");
    try expect_value(&store, 4, "fourth");
    try store.destroy();
}

fn lacks_prefix(prefix: []const u8, key: u64, _: *const []const u8) bool {
    const bytes = codec.encode_fixed(u64, key);
    return !std.mem.startsWith(u8, &bytes, prefix);
}

fn count_prefix(store: *const Store, prefix: []const u8) usize {
    var matches: usize = 0;
    for (store.items()) |entry| {
        if (std.mem.startsWith(u8, &entry.key_bytes, prefix)) matches += 1;
    }
    return matches;
}

test "keys and retain by prefix" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    const keys = [_]u64{ 0x1000, 0x1001, 0x1002, 0x2000, 0x2001, 0x3000 };
    for (keys) |key| try put(&store, key, "value");
    // Keys iterate in order.
    for (store.items(), keys) |entry, key| try testing.expectEqual(key, entry.key);
    const prefix_10 = [_]u8{ 0, 0, 0, 0, 0, 0, 0x10 };
    try testing.expectEqual(@as(usize, 3), count_prefix(&store, &prefix_10));
    try testing.expectEqual(@as(usize, 2), count_prefix(&store, &.{ 0, 0, 0, 0, 0, 0, 0x20 }));
    try testing.expectEqual(@as(usize, 0), count_prefix(&store, &.{ 0, 0, 0, 0, 0, 0, 0x40 }));

    store.retain(@as([]const u8, &prefix_10), lacks_prefix);
    try testing.expectEqual(@as(usize, 3), store.count());
    try expect_value(&store, 0x1000, null);
    try expect_value(&store, 0x2000, "value");
    try store.sync();
    store.deinit();

    store = try open(&storage);
    try testing.expectEqual(@as(usize, 3), store.count());
    try expect_value(&store, 0x1001, null);
    store.retain(@as([]const u8, &.{ 0, 0, 0, 0, 0, 0, 0x40 }), lacks_prefix);
    try testing.expectEqual(@as(usize, 3), store.count());
    store.retain(@as([]const u8, &.{}), lacks_prefix);
    try testing.expectEqual(@as(usize, 0), store.count());
    try store.destroy();
}

test "upsert inserts a default or returns the existing value" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    const inserted = try store.upsert(7, try gpa.dupe(u8, "abc"));
    @constCast(inserted.*)[0] = 'x';
    try store.sync();
    try store.sync();
    const existing = try store.upsert(7, try gpa.dupe(u8, "unused"));
    @constCast(existing.*)[1] = 'y';
    try store.sync();
    try expect_metrics(&store, 2, 1, 1);
    store.deinit();
    store = try open(&storage);
    try expect_value(&store, 7, "xyc");
    try store.destroy();
}

test "full overwrite limit and crash survival" {
    // Version, key, 2-byte value length prefix, value, and checksum.
    for ([_]u64{ memory.blob_page_size, memory.blob_page_size + 1 }) |store_len| {
        const value_len: usize = @intCast(store_len - 8 - 8 - 2 - 4);
        var storage = Storage.init(gpa);
        defer storage.deinit();
        var store = try open(&storage);
        try put_fill(&store, 1, 1, value_len);
        try store.sync();
        try store.sync();

        storage.writes = 0;
        try put_fill(&store, 1, 2, value_len);
        try store.sync();
        // A store larger than a page writes value, version, and checksum separately.
        const writes: u64 = if (store_len > memory.blob_page_size) 3 else 1;
        try testing.expectEqual(writes, storage.writes);
        try expect_metrics(&store, 2, 1, 1);
        store.deinit(); // Crash right after the sync returns.

        const opened = try storage.open("test", "left");
        try testing.expectEqual(store_len, opened.len);
        opened.blob.deinit();
        store = try open(&storage);
        defer store.deinit();
        try testing.expectEqual(value_len, store.get(1).?.len);
        for (store.get(1).?.*) |byte| try testing.expectEqual(@as(u8, 2), byte);
    }
}

test "interrupted destroy keeps newest generation" {
    const Generations = metadata.Metadata(Storage, u64, u64);
    const cfg: metadata.Config(u64) = .{ .partition = "destroy-order", .codec_config = {} };
    for ([_]u64{ 2, 3 }) |generations| {
        var storage = Storage.init(gpa);
        defer storage.deinit();
        var store = try Generations.init(gpa, &storage, cfg);
        for (1..generations + 1) |generation| {
            _ = try store.put(0, generation);
            try store.sync();
        }
        // Destroy stops between its two copy removals.
        storage.remove_failures_after = 1;
        try testing.expectError(error.Io, store.destroy());
        storage.remove_failures_after = null;
        const names = try storage.scan(gpa, "destroy-order");
        defer {
            for (names) |name| gpa.free(name);
            gpa.free(names);
        }
        try testing.expectEqual(@as(usize, 1), names.len);

        store = try Generations.init(gpa, &storage, cfg);
        defer store.deinit();
        try testing.expectEqual(generations, store.get(0).?.*);
    }
}

test "on-disk layout" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    try put(&store, 2, "b");
    try put(&store, 1, "a");
    try store.sync();
    store.deinit();

    // Version 1, then pairs in key order (8-byte big-endian key, varint length, bytes), then
    // the big-endian CRC-32C of everything before it.
    const body = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 } ++ [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1, 1, 'a' } ++
        [_]u8{ 0, 0, 0, 0, 0, 0, 0, 2, 1, 'b' };
    var expected: [body.len + 4]u8 = undefined;
    @memcpy(expected[0..body.len], &body);
    std.mem.writeInt(u32, expected[body.len..], Crc32.checksum(&body), .big);
    const opened = try storage.open("test", "right");
    defer opened.blob.deinit();
    var actual: [expected.len]u8 = undefined;
    try testing.expectEqual(@as(u64, actual.len), opened.len);
    try opened.blob.read_at(0, &actual);
    try testing.expectEqualSlices(u8, &expected, &actual);
}

// `metadata_operations` fuzz target: random operations against a reference map, with syncs,
// restarts, and destroys, checking every value after each restart.

const fuzz_keys = 16;
const fuzz_operations_max = 128;

/// The expected contents; plain values only, so copying it snapshots it.
const Model = struct {
    present: [fuzz_keys]bool = @splat(false),
    lens: [fuzz_keys]usize = @splat(0),
    bytes: [fuzz_keys][64]u8 = undefined,

    fn set(self: *Model, key: u64, value: []const u8) void {
        @memcpy(self.bytes[key][0..value.len], value);
        self.lens[key] = value.len;
        self.present[key] = true;
    }

    fn check(self: *const Model, store: *const Store) !void {
        var present: usize = 0;
        for (0..fuzz_keys) |key| {
            const expected = if (self.present[key]) self.bytes[key][0..self.lens[key]] else null;
            try expect_value(store, key, expected);
            if (self.present[key]) present += 1;
        }
        try testing.expectEqual(present, store.count());
    }
};

fn fuzz_put(store: *Store, model: *Model, reader: *fuzz_bytes.Reader) !void {
    const key = reader.below(fuzz_keys);
    var bytes: [64]u8 = undefined;
    const len: usize = switch (reader.below(4)) {
        0 => 0,
        1 => 64,
        else => @intCast(reader.below(9)),
    };
    for (bytes[0..len]) |*byte| byte.* = reader.int(u8);
    try put(store, key, bytes[0..len]);
    model.set(key, bytes[0..len]);
}

fn fuzz_run(input: []const u8) anyerror!void {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var store = try open(&storage);
    defer store.deinit();
    var model: Model = .{};
    var committed: Model = .{};
    var reader = fuzz_bytes.Reader.init(input);
    var operations: u32 = 0;
    while (!reader.done() and operations < fuzz_operations_max) : (operations += 1) {
        switch (reader.below(8)) {
            0, 1 => try fuzz_put(&store, &model, &reader),
            2 => {
                const key = reader.below(fuzz_keys);
                if (store.remove(key)) |value| gpa.free(value);
                model.present[key] = false;
            },
            3 => {
                store.clear();
                model.present = @splat(false);
            },
            4, 5 => {
                try store.sync();
                committed = model;
                try committed.check(&store);
            },
            6 => {
                // Restart, losing uncommitted changes.
                store.deinit();
                store = try open(&storage);
                model = committed;
                try model.check(&store);
            },
            7 => {
                try store.destroy();
                store = try open(&storage);
                model = .{};
                committed = .{};
                try model.check(&store);
            },
            else => unreachable,
        }
        try model.check(&store);
    }
}

test "fuzz metadata operations (seeded)" {
    try fuzz_bytes.seeded(1024, 0x6d657461, 256, fuzz_run);
}

test "fuzz metadata operations" {
    try testing.fuzz({}, fuzz_bytes.smith(1024, fuzz_run), .{});
}
