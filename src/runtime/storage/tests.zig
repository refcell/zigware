//! The storage conformance suite every backend runs (commonware `storage::tests::
//! run_storage_tests` in `runtime/src/storage/mod.rs`).
//!
//! commonware's `read_at_buf` cases test buffer reuse, which `Blob.read_at` (a caller-provided
//! buffer) always does, so they reduce to the zero-length and insufficient-length reads here.
//! `start_sync` is `sync` in zigware. Shared owners (`Arc<Blob>`) are one handle.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const iface = @import("../storage.zig");
const Storage = iface.Storage;
const Blob = iface.Blob;

/// Runs every storage test against `storage`, which starts empty.
pub fn run_storage_tests(io: Io, gpa: Allocator, storage: Storage) !void {
    try test_open_and_write(storage);
    try test_remove(gpa, storage);
    try test_read_after_remove_blob(gpa, storage);
    try test_read_after_remove_partition(storage);
    try test_recreate_after_remove(storage);
    try test_read_after_remove_unsynced(gpa, storage);
    try test_recreate_generations(storage);
    try test_read_after_remove_partition_multi(gpa, storage);
    try test_scan(gpa, storage);
    try test_concurrent_access(io, storage);
    try test_large_data(gpa, storage);
    try test_overwrite_data(storage);
    try test_read_beyond_bound(storage);
    try test_write_at_large_offset(storage);
    try test_write_at_sync(storage);
    try test_append_data(storage);
    try test_vectored_write_at(gpa, storage);
    try test_vectored_write_at_large_offset(gpa, storage);
    try test_sequential_read_write(storage);
    try test_sequential_chunk_read_write(gpa, storage);
    try test_read_empty_blob(storage);
    try test_overlapping_writes(storage);
    try test_resize_then_open(storage);
    try test_partition_name_validation(gpa, storage);
    try test_blob_version_mismatch(storage);
    try test_aligned_layout(storage);
    try test_read_zero_length(storage);
    try test_read_options(storage);
}

/// Reads `expected.len` bytes at `offset` and compares them with `expected`.
pub fn expect_read(blob: Blob, offset: u64, expected: []const u8) !void {
    var buffer: [256]u8 = undefined;
    var position: usize = 0;
    while (position < expected.len) {
        const length = @min(buffer.len, expected.len - position);
        try blob.read_at(offset + position, buffer[0..length]);
        try testing.expectEqualSlices(u8, expected[position..][0..length], buffer[0..length]);
        position += length;
    }
    assert(position == expected.len);
}

fn ramp(gpa: Allocator, length: usize, reverse: bool) ![]u8 {
    const data = try gpa.alloc(u8, length);
    for (data, 0..) |*byte, i| {
        const value: u8 = @truncate(i);
        byte.* = if (reverse) 255 - value else value;
    }
    return data;
}

fn test_open_and_write(storage: Storage) !void {
    const opened = try storage.open("partition", "test_blob");
    defer opened.blob.close();
    try testing.expectEqual(@as(u64, 0), opened.len);
    try opened.blob.write_at(0, "hello world", .{});
    try expect_read(opened.blob, 0, "hello world");
}

fn test_remove(gpa: Allocator, storage: Storage) !void {
    (try storage.open("partition", "test_blob")).blob.close();
    try storage.remove("partition", "test_blob");
    const names = try storage.scan(gpa, "partition");
    defer names.deinit(gpa);
    try testing.expect(!names.contains("test_blob"));
}

/// An open handle stays fully readable after its blob is removed by name.
fn test_read_after_remove_blob(gpa: Allocator, storage: Storage) !void {
    const blob = (try storage.open("read_after_remove", "by_name")).blob;
    defer blob.close();
    const data = try ramp(gpa, 256, false);
    defer gpa.free(data);
    try blob.write_at(0, data, .{});
    try blob.sync();
    try storage.remove("read_after_remove", "by_name");
    const names = try storage.scan(gpa, "read_after_remove");
    defer names.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), names.items.len);
    try expect_read(blob, 0, data);
    // Out-of-bounds reads still fail after removal.
    var byte: [1]u8 = undefined;
    try testing.expectError(error.BlobInsufficientLength, blob.read_at(data.len, &byte));
}

/// An open handle stays fully readable after its whole partition is removed.
fn test_read_after_remove_partition(storage: Storage) !void {
    const blob = (try storage.open("read_after_remove_partition", "victim")).blob;
    defer blob.close();
    var data: [256]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = 255 - @as(u8, @intCast(i));
    try blob.write_at(0, &data, .{});
    try blob.sync();
    try storage.remove("read_after_remove_partition", null);
    try expect_read(blob, 0, &data);
}

/// Reopening a removed name creates an independent blob; the old handle keeps its contents.
fn test_recreate_after_remove(storage: Storage) !void {
    const old = (try storage.open("recreate_after_remove", "name")).blob;
    defer old.close();
    try old.write_at(0, "old contents", .{});
    try old.sync();
    try storage.remove("recreate_after_remove", "name");
    const new = try storage.open("recreate_after_remove", "name");
    defer new.blob.close();
    try testing.expectEqual(@as(u64, 0), new.len);
    try new.blob.write_at(0, "new contents", .{});
    try new.blob.sync();
    try expect_read(old, 0, "old contents");
    try expect_read(new.blob, 0, "new contents");
}

/// Bytes written but never synced stay readable through an open handle after removal.
fn test_read_after_remove_unsynced(gpa: Allocator, storage: Storage) !void {
    const blob = (try storage.open("read_after_remove_unsynced", "name")).blob;
    defer blob.close();
    const data = try ramp(gpa, 64 * 1024, false);
    defer gpa.free(data);
    try blob.write_at(0, data, .{});
    try expect_read(blob, 0, data[0..16]);
    try storage.remove("read_after_remove_unsynced", "name");
    try expect_read(blob, 0, data);
    try expect_read(blob, data.len - 1, data[data.len - 1 ..]);
}

/// Every removed generation of a name stays readable through its own handle while the name
/// is recreated and removed repeatedly.
fn test_recreate_generations(storage: Storage) !void {
    const partition = "recreate_generations";
    var handles: [3]Blob = undefined;
    var count: usize = 0;
    defer for (handles[0..count]) |blob| blob.close();
    while (count < handles.len) : (count += 1) {
        const opened = try storage.open(partition, "name");
        handles[count] = opened.blob;
        try testing.expectEqual(@as(u64, 0), opened.len);
        const data: [32]u8 = @splat(@intCast(count));
        try opened.blob.write_at(0, &data, .{});
        try opened.blob.sync();
        try storage.remove(partition, "name");
    }
    for (0..5) |_| {
        const blob = (try storage.open(partition, "name")).blob;
        defer blob.close();
        try blob.write_at(0, &@as([8]u8, @splat(0xff)), .{});
        try blob.sync();
        try storage.remove(partition, "name");
    }
    for (handles, 0..) |blob, generation| {
        const data: [32]u8 = @splat(@intCast(generation));
        try expect_read(blob, 0, &data);
    }
}

/// Every handle into a removed partition stays readable, including a large blob at interior
/// offsets, and recreating the partition yields independent blobs.
fn test_read_after_remove_partition_multi(gpa: Allocator, storage: Storage) !void {
    const partition = "read_after_remove_partition_multi";
    const small_a = (try storage.open(partition, "a")).blob;
    defer small_a.close();
    try small_a.write_at(0, "alpha", .{});
    try small_a.sync();
    // Never synced: partition removal must not lose unsynced bytes either.
    const small_b = (try storage.open(partition, "b")).blob;
    defer small_b.close();
    try small_b.write_at(0, "bravo", .{});
    const large_len = 1 << 20;
    const large = (try storage.open(partition, "large")).blob;
    defer large.close();
    const data = try ramp(gpa, large_len, false);
    defer gpa.free(data);
    try large.write_at(0, data, .{});
    try large.sync();
    try storage.remove(partition, null);
    try expect_read(small_a, 0, "alpha");
    try expect_read(small_b, 0, "bravo");
    const ranges = [_][2]usize{ .{ 0, 4096 }, .{ 123_457, 8192 }, .{ large_len - 1, 1 } };
    for (ranges) |range| try expect_read(large, range[0], data[range[0]..][0..range[1]]);
    const fresh = try storage.open(partition, "a");
    defer fresh.blob.close();
    try testing.expectEqual(@as(u64, 0), fresh.len);
    try fresh.blob.write_at(0, "fresh", .{});
    try fresh.blob.sync();
    try expect_read(small_a, 0, "alpha");
}

fn test_scan(gpa: Allocator, storage: Storage) !void {
    (try storage.open("partition", "blob1")).blob.close();
    (try storage.open("partition", "blob2")).blob.close();
    const names = try storage.scan(gpa, "partition");
    defer names.deinit(gpa);
    // Earlier tests leave "test_blob" behind in "partition"; the scan is sorted.
    try testing.expect(names.contains("blob1"));
    try testing.expect(names.contains("blob2"));
    for (names.items[1..], names.items[0 .. names.items.len - 1]) |name, previous| {
        try testing.expect(std.mem.order(u8, previous, name) == .lt);
    }
}

/// Concurrent tasks read and write the same blob.
fn test_concurrent_access(io: Io, storage: Storage) !void {
    const blob = (try storage.open("partition", "test_blob")).blob;
    defer blob.close();
    try blob.write_at(0, "concurrent write", .{});
    const Tasks = struct {
        fn write(handle: Blob) !void {
            try handle.write_at(0, "concurrent write", .{});
        }
        fn read(handle: Blob) ![16]u8 {
            var buffer: [16]u8 = undefined;
            try handle.read_at(0, &buffer);
            return buffer;
        }
    };
    var write_task = try io.concurrent(Tasks.write, .{blob});
    var read_task = try io.concurrent(Tasks.read, .{blob});
    try write_task.await(io);
    const buffer = try read_task.await(io);
    try testing.expectEqualSlices(u8, "concurrent write", &buffer);
}

fn test_large_data(gpa: Allocator, storage: Storage) !void {
    const blob = (try storage.open("partition", "large_blob")).blob;
    defer blob.close();
    const size = 10 * 1024 * 1024;
    const data = try gpa.alloc(u8, size);
    defer gpa.free(data);
    @memset(data, 42);
    try blob.write_at(0, data, .{});
    const read = try gpa.alloc(u8, size);
    defer gpa.free(read);
    try blob.read_at(0, read);
    try testing.expectEqualSlices(u8, data, read);
}

fn test_overwrite_data(storage: Storage) !void {
    const blob = (try storage.open("test_overwrite_data", "test_blob")).blob;
    defer blob.close();
    try blob.write_at(0, "initial data", .{});
    try blob.write_at(8, "overwrite", .{});
    try expect_read(blob, 0, "initial overwrite");
}

fn test_read_beyond_bound(storage: Storage) !void {
    const blob = (try storage.open("test_read_beyond_written_data", "test_blob")).blob;
    defer blob.close();
    try blob.write_at(0, "hello", .{});
    var buffer: [10]u8 = undefined;
    try testing.expectError(error.BlobInsufficientLength, blob.read_at(6, &buffer));
    try testing.expectError(error.BlobInsufficientLength, blob.read_at(0, buffer[0..6]));
}

fn test_write_at_large_offset(storage: Storage) !void {
    const blob = (try storage.open("test_write_at_large_offset", "test_blob")).blob;
    defer blob.close();
    try blob.write_at(10_000, "offset data", .{});
    try expect_read(blob, 10_000, "offset data");
}

/// Writes with `WriteOptions.sync` are visible after a reopen without a separate sync.
fn test_write_at_sync(storage: Storage) !void {
    const partition = "test_write_at_sync";
    var blob = (try storage.open(partition, "test_blob")).blob;
    // Empty synced writes are accepted without extending the blob.
    try blob.write_at(1024, "", .{ .sync = true });
    blob.close();
    var opened = try storage.open(partition, "test_blob");
    try testing.expectEqual(@as(u64, 0), opened.len);
    try opened.blob.write_at(0, "hello", .{ .sync = true });
    try opened.blob.write_at_vectored(5, &.{ " ", "world" }, .{ .sync = true });
    opened.blob.close();
    opened = try storage.open(partition, "test_blob");
    defer opened.blob.close();
    try testing.expectEqual(@as(u64, 11), opened.len);
    try expect_read(opened.blob, 0, "hello world");
}

fn test_append_data(storage: Storage) !void {
    const blob = (try storage.open("test_append_data", "test_blob")).blob;
    defer blob.close();
    try blob.write_at(0, "first", .{});
    try blob.write_at(5, "second", .{});
    try expect_read(blob, 0, "firstsecond");
}

fn expect_vectored(
    gpa: Allocator,
    storage: Storage,
    partition: []const u8,
    chunks: []const []const u8,
    options: iface.WriteOptions,
) !void {
    const expected = try std.mem.concat(gpa, u8, chunks);
    defer gpa.free(expected);
    const blob = (try storage.open(partition, "test_blob")).blob;
    defer blob.close();
    try blob.write_at_vectored(0, chunks, options);
    try expect_read(blob, 0, expected);
}

fn test_vectored_write_at(gpa: Allocator, storage: Storage) !void {
    const basic: []const []const u8 = &.{ "hello", " ", "world" };
    try expect_vectored(gpa, storage, "test_vectored_write_basic", basic, .{});
    const empties: []const []const u8 = &.{ "", "abc", "", "def", "" };
    try expect_vectored(gpa, storage, "test_vectored_write_empty_chunks", empties, .{});
    // Filesystem backends cap one submission at 1024 iovecs.
    const chunk_count = 1025;
    const bytes = try gpa.alloc(u8, chunk_count);
    defer gpa.free(bytes);
    const chunks = try gpa.alloc([]const u8, chunk_count);
    defer gpa.free(chunks);
    for (bytes, chunks, 0..) |*byte, *chunk, i| {
        byte.* = @truncate(i);
        chunk.* = byte[0..1];
    }
    try expect_vectored(gpa, storage, "test_vectored_write_many_chunks", chunks, .{});
    const partition = "test_vectored_sync_write_many_chunks";
    try expect_vectored(gpa, storage, partition, chunks, .{ .sync = true });
}

fn test_vectored_write_at_large_offset(gpa: Allocator, storage: Storage) !void {
    const blob = (try storage.open("test_vectored_write_at_large_offset", "test_blob")).blob;
    defer blob.close();
    const chunk_count = 128;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var chunks: [chunk_count][]const u8 = undefined;
    for (&chunks, 0..) |*chunk, i| {
        const bytes = try arena.allocator().alloc(u8, i);
        @memset(bytes, @intCast(i));
        chunk.* = bytes;
    }
    const expected = try std.mem.concat(arena.allocator(), u8, &chunks);
    try blob.write_at_vectored(5_000, &chunks, .{});
    try expect_read(blob, 5_000, expected);
    // The gap before the offset is zero-filled.
    const zeros: [5_000]u8 = @splat(0);
    try expect_read(blob, 0, &zeros);
}

fn test_sequential_read_write(storage: Storage) !void {
    const blob = (try storage.open("partition", "test_blob")).blob;
    defer blob.close();
    try blob.write_at(0, "first", .{});
    try blob.write_at(10, "second", .{});
    try expect_read(blob, 0, "first");
    try expect_read(blob, 10, "second");
}

fn test_sequential_chunk_read_write(gpa: Allocator, storage: Storage) !void {
    const blob = (try storage.open("test_large_data_in_chunks", "large_blob")).blob;
    defer blob.close();
    const chunk_size = 1024 * 1024;
    const chunk_count = 10;
    const data = try gpa.alloc(u8, chunk_size);
    defer gpa.free(data);
    @memset(data, 7);
    for (0..chunk_count) |i| try blob.write_at(i * chunk_size, data, .{});
    const read = try gpa.alloc(u8, chunk_size);
    defer gpa.free(read);
    for (0..chunk_count) |i| {
        try blob.read_at(i * chunk_size, read);
        try testing.expectEqualSlices(u8, data, read);
    }
}

fn test_read_empty_blob(storage: Storage) !void {
    const blob = (try storage.open("test_read_empty_blob", "empty_blob")).blob;
    defer blob.close();
    var byte: [1]u8 = undefined;
    try testing.expectError(error.BlobInsufficientLength, blob.read_at(0, &byte));
}

fn test_overlapping_writes(storage: Storage) !void {
    const blob = (try storage.open("test_overlapping_writes", "test_blob")).blob;
    defer blob.close();
    try blob.write_at(0, "overlap", .{});
    try blob.write_at(4, "map", .{});
    try expect_read(blob, 0, "overmap");
}

fn test_resize_then_open(storage: Storage) !void {
    {
        const blob = (try storage.open("test_resize_then_open", "test_blob")).blob;
        defer blob.close();
        try blob.write_at(0, "hello world", .{});
        try blob.resize(5);
        try blob.sync();
    }
    const opened = try storage.open("test_resize_then_open", "test_blob");
    defer opened.blob.close();
    try testing.expectEqual(@as(u64, 5), opened.len);
    try expect_read(opened.blob, 0, "hello");
}

fn test_partition_name_validation(gpa: Allocator, storage: Storage) !void {
    const valid = [_][]const u8{
        "partition", "my_partition", "my-partition", "partition123", "A1",
    };
    for (valid) |name| {
        const opened = try storage.open(name, "blob");
        opened.blob.close();
        try storage.remove(name, null);
        try testing.expectError(error.PartitionMissing, storage.scan(gpa, name));
    }
    const invalid = [_][]const u8{
        "my/partition", "my.partition", "my partition", "../escape", "",
    };
    for (invalid) |name| {
        try testing.expectError(error.PartitionNameInvalid, storage.open(name, "blob"));
        try testing.expectError(error.PartitionNameInvalid, storage.remove(name, null));
        try testing.expectError(error.PartitionNameInvalid, storage.scan(gpa, name));
    }
}

fn test_blob_version_mismatch(storage: Storage) !void {
    const partition = "test_version_mismatch";
    const created = try storage.open_versioned(partition, "blob", .only(1));
    try testing.expectEqual(@as(iface.BlobVersion, 1), created.version);
    try created.blob.sync();
    created.blob.close();
    const reopened = try storage.open_versioned(partition, "blob", .{ .min = 0, .max = 2 });
    try testing.expectEqual(@as(iface.BlobVersion, 1), reopened.version);
    reopened.blob.close();
    const result = storage.open_versioned(partition, "blob", .{ .min = 2, .max = 3 });
    try testing.expectError(error.BlobVersionMismatch, result);
}

/// Aligned-layout creation, reopen, and resize through logical offsets.
fn test_aligned_layout(storage: Storage) !void {
    const partition = "test_aligned_layout";
    var opened = try storage.open_versioned(partition, "blob", .only(0));
    try testing.expectEqual(@as(u64, 0), opened.len);
    try opened.blob.write_at(0, "hello world", .{});
    try opened.blob.sync();
    try expect_read(opened.blob, 0, "hello world");
    opened.blob.close();
    opened = try storage.open_versioned(partition, "blob", .only(0));
    try testing.expectEqual(@as(u64, 11), opened.len);
    try expect_read(opened.blob, 6, "world");
    try opened.blob.resize(5);
    try opened.blob.sync();
    opened.blob.close();
    opened = try storage.open_versioned(partition, "blob", .only(0));
    defer opened.blob.close();
    try testing.expectEqual(@as(u64, 5), opened.len);
    try expect_read(opened.blob, 0, "hello");
}

fn test_read_zero_length(storage: Storage) !void {
    const blob = (try storage.open("test_read_at_zero_len", "blob")).blob;
    defer blob.close();
    try blob.write_at(0, "hello", .{});
    try blob.read_at(0, &.{});
    try blob.read_at(5, &.{});
}

/// Read options do not change functional read behavior.
fn test_read_options(storage: Storage) !void {
    const blob = (try storage.open("test_read_options", "blob")).blob;
    defer blob.close();
    try blob.write_at(0, "hello world", .{});
    for ([_]iface.ReadOptions{ .{}, .{ .dont_cache = true } }) |options| {
        var buffer: [12]u8 = undefined;
        try blob.read_at_options(0, buffer[0..11], options);
        try testing.expectEqualSlices(u8, "hello world", buffer[0..11]);
        try blob.read_at_options(0, buffer[0..0], options);
        const result = blob.read_at_options(0, &buffer, options);
        try testing.expectError(error.BlobInsufficientLength, result);
    }
}
