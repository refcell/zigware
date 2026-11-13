//! File storage tests: commonware's `run_storage_tests` suite plus the file-specific cases.

const std = @import("std");
const iface = @import("../storage.zig");
const file_storage = @import("storage.zig");
const testing = std.testing;
const io = testing.io;
const gpa = testing.allocator;

fn open_storage(tmp: *testing.TmpDir, sub_path: []const u8) !file_storage.Storage {
    const root = try tmp.dir.createDirPathOpen(io, sub_path, .{});
    return file_storage.Storage.init(io, gpa, root, .{});
}

test "file storage passes the storage suite (run_storage_tests)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "suite");
    defer storage.deinit();
    try iface.tests.run_storage_tests(io, gpa, storage.storage());
}

const header = @import("../storage/header.zig");

fn read_raw(tmp: *testing.TmpDir, path: []const u8) ![]u8 {
    return tmp.dir.readFileAlloc(io, path, gpa, .unlimited);
}

fn write_raw(tmp: *testing.TmpDir, path: []const u8, data: []const u8) !void {
    const dir = std.fs.path.dirname(path).?;
    try tmp.dir.createDirPath(io, dir);
    try tmp.dir.writeFile(io, .{ .sub_path = path, .data = data });
}

test "blob header handling (test_blob_header_handling)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    const path = "root/partition/74657374"; // hex("test")
    const data_offset = iface.BlobLayout.v1.data_offset();
    var opened = try storage.open_versioned("partition", "test", .only(0));
    try testing.expectEqual(@as(u64, 0), opened.len);
    try testing.expectEqual(data_offset, (try tmp.dir.statFile(io, path, .{})).size);
    try opened.blob.write_at(0, "hello world", .{});
    try opened.blob.sync();
    const raw = try read_raw(&tmp, path);
    defer gpa.free(raw);
    try testing.expectEqual(data_offset + 11, raw.len);
    try testing.expectEqualSlices(u8, &header.magic(.v1), raw[0..header.magic_length]);
    try testing.expectEqual(header.layout_version(.v1), std.mem.readInt(u16, raw[4..6], .big));
    try testing.expectEqualStrings("hello world", raw[@intCast(data_offset)..]);
    try opened.blob.resize(5);
    try opened.blob.sync();
    try testing.expectEqual(data_offset + 5, (try tmp.dir.statFile(io, path, .{})).size);
    try opened.blob.resize(0);
    try testing.expectEqual(data_offset, (try tmp.dir.statFile(io, path, .{})).size);
    try opened.blob.write_at(0, "test data", .{});
    try opened.blob.sync();
    opened.blob.close();
    opened = try storage.open_versioned("partition", "test", .only(0));
    try testing.expectEqual(@as(u64, 9), opened.len);
    try iface.tests.expect_read(opened.blob, 0, "test data");
    opened.blob.close();
    // A file shorter than a header prelude is reset to an empty blob.
    try write_raw(&tmp, "root/partition/636f72727570746564", &.{ 0, 0, 0, 0 });
    opened = try storage.open("partition", "corrupted");
    defer opened.blob.close();
    try testing.expectEqual(@as(u64, 0), opened.len);
    const size = (try tmp.dir.statFile(io, "root/partition/636f72727570746564", .{})).size;
    try testing.expectEqual(data_offset, size);
}

test "torn creations heal and foreign bytes stay corrupt (test_blob_torn_creation_recovers)" {
    const quiet = testing.log_level;
    testing.log_level = .err; // Healing logs a warning.
    defer testing.log_level = quiet;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    const path = "root/partition/746f726e"; // hex("torn")
    const first = try storage.open("partition", "torn");
    try first.blob.sync();
    first.blob.close();
    const region = try read_raw(&tmp, path);
    defer gpa.free(region);
    const torn_full = try gpa.alloc(u8, region.len);
    defer gpa.free(torn_full);
    @memset(torn_full, 0);
    @memcpy(torn_full[0..10], region[0..10]);
    for ([_][]const u8{ region[0..10], torn_full }) |state| {
        try write_raw(&tmp, path, state);
        var opened = try storage.open("partition", "torn");
        try testing.expectEqual(@as(u64, 0), opened.len);
        try opened.blob.write_at(0, "data", .{});
        try opened.blob.sync();
        opened.blob.close();
        opened = try storage.open("partition", "torn");
        try testing.expectEqual(@as(u64, 4), opened.len);
        try iface.tests.expect_read(opened.blob, 0, "data");
        opened.blob.close();
    }
    torn_full[100] = 0xff;
    try write_raw(&tmp, path, torn_full);
    try testing.expectError(error.BlobCorrupt, storage.open("partition", "torn"));
}

test "foreign headers are corrupt (padding and magic)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    const raw = try header.blob_bytes(gpa, .v1, 0, "payload");
    defer gpa.free(raw);
    raw[header.parse_len] = 0xff;
    try write_raw(&tmp, "root/partition/6469727479", raw); // hex("dirty")
    try testing.expectError(error.BlobCorrupt, storage.open("partition", "dirty"));
    try write_raw(&tmp, "root/partition/626164", "XXXXXXXX"); // hex("bad")
    try testing.expectError(error.BlobCorrupt, storage.open("partition", "bad"));
}

test "legacy V0 blobs read and write in place (test_blob_v0_legacy_read)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    const raw = try header.blob_bytes(gpa, .v0, 0, "hello world");
    defer gpa.free(raw);
    try write_raw(&tmp, "root/partition/7630", raw); // hex("v0")
    const opened = try storage.open("partition", "v0");
    try testing.expectEqual(@as(u64, 11), opened.len);
    try iface.tests.expect_read(opened.blob, 0, "hello world");
    try opened.blob.write_at(opened.len, "!", .{});
    try opened.blob.sync();
    opened.blob.close();
    const after = try read_raw(&tmp, "root/partition/7630");
    defer gpa.free(after);
    try testing.expectEqual(header.prelude_size + 12, after.len);
    try testing.expectEqualSlices(u8, &header.magic(.v0), after[0..header.magic_length]);
    try testing.expectEqualStrings("hello world!", after[header.prelude_size..]);
}

test "short files reset to empty blobs (test_blob_partial_header_reset)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    for (0..header.prelude_size) |prefix_len| {
        var name_buffer: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "short_{d}", .{prefix_len});
        var path_buffer: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "root/partition/{x}", .{name});
        const zeros: [header.prelude_size]u8 = @splat(0);
        try write_raw(&tmp, path, zeros[0..prefix_len]);
        const opened = try storage.open("partition", name);
        try testing.expectEqual(@as(u64, 0), opened.len);
        opened.blob.close();
        const raw = try read_raw(&tmp, path);
        defer gpa.free(raw);
        try testing.expectEqual(iface.BlobLayout.v1.data_offset(), raw.len);
        try testing.expectEqualSlices(u8, &header.magic(.v1), raw[0..header.magic_length]);
        (try storage.open("partition", name)).blob.close();
    }
}

test "scan rejects non-canonical hex names (test_scan_rejects_non_canonical_hex_file_names)" {
    for ([_][]const u8{ "0x626c6f62", "0X626C6F62", " 626c6f62", "626C6F62" }) |bad_name| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var storage = try open_storage(&tmp, "root");
        defer storage.deinit();
        var path_buffer: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "root/partition/{s}", .{bad_name});
        try write_raw(&tmp, path, "");
        try testing.expectError(error.PartitionCorrupt, storage.scan(gpa, "partition"));
    }
}

test "partition failures are not absence (test_partition_failures_are_not_absence)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try write_raw(&tmp, "root/partition", "not a directory");
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    try testing.expectError(error.ReadFailed, storage.scan(gpa, "partition"));
    try testing.expectError(error.PartitionMissing, storage.scan(gpa, "missing"));
    try testing.expectError(error.Io, storage.remove("partition", null));
    _ = try tmp.dir.statFile(io, "root/partition", .{});
    try testing.expectError(error.PartitionMissing, storage.remove("missing", null));
}

test "the hold excludes a second storage (test_hold_blocks_second_instance)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var first = try open_storage(&tmp, "root");
    const contender = try tmp.dir.createFile(io, "root/" ++ file_storage.hold_name, .{
        .truncate = false,
    });
    defer contender.close(io);
    try testing.expect(!try contender.tryLock(io, .exclusive));
    first.deinit();
    try testing.expect(try contender.tryLock(io, .exclusive));
    contender.unlock(io);
}

test "files persist across storage instances" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var storage = try open_storage(&tmp, "root");
        defer storage.deinit();
        const opened = try storage.open_versioned("partition", "blob", .only(3));
        defer opened.blob.close();
        try opened.blob.write_at(0, "durable", .{ .sync = true });
    }
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    const opened = try storage.open_versioned("partition", "blob", .{ .min = 1, .max = 5 });
    defer opened.blob.close();
    try testing.expectEqual(@as(iface.BlobVersion, 3), opened.version);
    try testing.expectEqual(@as(u64, 7), opened.len);
    try iface.tests.expect_read(opened.blob, 0, "durable");
    try testing.expectError(error.BlobAlreadyOpen, storage.open("partition", "blob"));
}
