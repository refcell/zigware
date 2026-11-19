//! File storage tests: commonware's `run_storage_tests` suite plus the file-specific cases.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
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

const Ring = @import("ring.zig").Ring;

fn init_ring(ring: *Ring) !void {
    return @import("ring_test.zig").init_or_skip(ring, .{ .entries = 64 });
}

test "io_uring file storage passes the storage suite (run_storage_tests)" {
    var ring: Ring = undefined;
    try init_ring(&ring);
    defer ring.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.createDirPathOpen(io, "suite", .{});
    var storage = try file_storage.Storage.init(io, gpa, root, .{ .ring = &ring });
    defer storage.deinit();
    try iface.tests.run_storage_tests(io, gpa, storage.storage());
}

test "io_uring writes persist across storage instances" {
    var ring: Ring = undefined;
    try init_ring(&ring);
    defer ring.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    for (0..2) |run| {
        const root = try tmp.dir.createDirPathOpen(io, "root", .{});
        var storage = try file_storage.Storage.init(io, gpa, root, .{ .ring = &ring });
        defer storage.deinit();
        const opened = try storage.storage().open("partition", "blob");
        defer opened.blob.close();
        if (run == 0) {
            try opened.blob.write_at(0, "through the ring", .{ .sync = true });
            continue;
        }
        var contents: ["through the ring".len]u8 = undefined;
        try opened.blob.read_at(0, &contents);
        try testing.expectEqualStrings("through the ring", &contents);
        try testing.expectError(error.BlobInsufficientLength, opened.blob.read_at(1, &contents));
    }
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

fn write_until_canceled(blob: *iface.Blob) iface.Error!void {
    // Each pass ends in a syscall, where a cancel request takes effect.
    while (true) {
        try blob.write_at(0, "canceled", .{});
        try blob.sync();
    }
}

test "a write interrupted by cancellation fails with Canceled, not an I/O error" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    var opened = try storage.open_versioned("partition", "canceled", .only(0));
    defer opened.blob.close();
    var task = try io.concurrent(write_until_canceled, .{&opened.blob});
    try io.sleep(.fromMilliseconds(5), .awake);
    try testing.expectError(error.Canceled, task.cancel(io));
}

test "the hold file name is not a partition name (test_hold_name_rejected_as_partition)" {
    try testing.expectError(
        error.PartitionNameInvalid,
        iface.validate_partition_name(file_storage.hold_name),
    );
}

test "scan rejects a subdirectory in a partition (test_scan_rejects_non_file_entries)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    try tmp.dir.createDirPath(io, "root/partition/nested");
    try testing.expectError(error.PartitionCorrupt, storage.scan(gpa, "partition"));
}

test "remove reports a missing partition, then a missing blob" {
    // commonware `test_remove_reports_missing_targets`.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    try testing.expectError(error.PartitionMissing, storage.remove("missing", null));
    try tmp.dir.createDirPath(io, "root/partition");
    try testing.expectError(error.BlobMissing, storage.remove("partition", "missing"));
}

test "scan skips file names that are not UTF-8 (test_scan_ignores_non_utf8_file_names)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    try write_raw(&tmp, "root/partition/\xff\xfe\xfd", "");
    const names = try storage.scan(gpa, "partition");
    defer names.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), names.items.len);
}

test "open fails when the partition path is a file (test_open_reports_partition_creation_failure)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try write_raw(&tmp, "root/partition", "not a directory");
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    try testing.expectError(error.PartitionCreationFailed, storage.open("partition", "blob"));
}

test "open fails when the blob path is a directory" {
    // commonware `test_open_reports_blob_open_failure_for_directory_path`; "626c6f62" is
    // hex("blob").
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "root/partition/626c6f62");
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    try testing.expectError(error.BlobOpenFailed, storage.open("partition", "blob"));
}

test "writes past the signed file extent fail before any I/O" {
    // commonware `test_write_range_overflow_before_registration` (iouring.rs) and
    // `test_invalid_write_range_leaves_open_clean` (tokio/blob.rs), with both layouts.
    const last: u64 = std.math.maxInt(i64);
    const max = std.math.maxInt(u64);
    const ones: [9][]const u8 = @splat("x");
    for ([_]iface.BlobLayout{ .v0, .v1 }) |layout| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const root = try tmp.dir.createDirPathOpen(io, "root", .{});
        var storage = try file_storage.Storage.init(io, gpa, root, .{ .layout = layout });
        defer storage.deinit();
        const blob = (try storage.open("partition", "range")).blob;
        const data_offset = layout.data_offset();
        for ([_]iface.WriteOptions{ .{}, .{ .sync = true } }) |options| {
            try blob.write_at_vectored(max - data_offset, &.{}, options);
            const empty = blob.write_at_vectored(max, &.{}, options);
            try testing.expectError(error.OffsetOverflow, empty);
            for ([_]usize{ 1, 2, ones.len }) |chunks| {
                const bufs = ones[0..chunks];
                for ([_]u64{ last - (chunks - 1), last + 1, max - data_offset }) |physical| {
                    const result = blob.write_at_vectored(physical - data_offset, bufs, options);
                    try testing.expectError(error.OffsetOverflow, result);
                }
            }
        }
        blob.close();
        const reopened = try storage.open("partition", "range");
        defer reopened.blob.close();
        try testing.expectEqual(@as(u64, 0), reopened.len);
        try reopened.blob.write_at(0, "ok", .{ .sync = true });
    }
}

test "reads at overflowing physical offsets fail; empty reads succeed" {
    // commonware `test_read_range_overflow_before_registration`. zigware blobs have no batched
    // reads, so the empty-batch half has no counterpart.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    const blob = (try storage.open("partition", "read_range")).blob;
    defer blob.close();
    const sentinel = std.math.maxInt(u64) - iface.default_blob_layout.data_offset();
    var two: [2]u8 = undefined;
    for ([_]iface.ReadOptions{ .{}, .{ .dont_cache = true } }) |options| {
        try blob.read_at_options(sentinel, two[0..0], options);
        const at_sentinel = blob.read_at_options(sentinel, two[0..1], options);
        try testing.expectError(error.OffsetOverflow, at_sentinel);
        const across = blob.read_at_options(sentinel - 1, &two, options);
        try testing.expectError(error.OffsetOverflow, across);
    }
}

test "logical offset overflow is checked before any I/O (test_blob_offset_overflow_guards)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    const blob = (try storage.open("partition", "overflow")).blob;
    defer blob.close();
    const max = std.math.maxInt(u64);
    var one: [1]u8 = undefined;
    try testing.expectError(error.OffsetOverflow, blob.read_at(max, &one));
    const uncached: iface.ReadOptions = .{ .dont_cache = true };
    try testing.expectError(error.OffsetOverflow, blob.read_at_options(max, one[0..0], uncached));
    // A representable offset past the signed file extent fails like the kernel's rejection.
    const signed_end = blob.read_at_options(std.math.maxInt(i64), &one, uncached);
    try testing.expectError(error.ReadFailed, signed_end);
    try testing.expectError(error.OffsetOverflow, blob.write_at(max, "x", .{}));
    try testing.expectError(error.OffsetOverflow, blob.resize(max));
}

const paged = @import("../buffer/paged/mod.zig");

/// Patterned pages through the paged writer on a V1 blob: each physical page fills one
/// aligned 4096-byte disk page, the tail zero-padded, each with a valid checksum record.
fn expect_v1_paged_alignment(ring: ?*Ring) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.createDirPathOpen(io, "root", .{});
    var storage = try file_storage.Storage.init(io, gpa, root, .{ .ring = ring });
    defer storage.deinit();
    const disk_page: u64 = iface.blob_page_size;
    const logical = paged.page_size(iface.blob_page_size);
    var cache_ref = try paged.CacheRef.init(gpa, logical, 16);
    defer cache_ref.deinit();
    const opened = try storage.storage().open("partition", "aligned");
    var writer = try paged.Writer.init(gpa, opened.blob, opened.len, 1024, &cache_ref);
    var item: [4000]u8 = undefined;
    for (0..1000) |index| std.mem.writeInt(u32, item[index * 4 ..][0..4], @intCast(index), .big);
    for (0..12) |_| _ = try writer.append(&item);
    const logical_size = writer.size();
    try writer.sync();
    writer.deinit();

    // "616c69676e6564" is hex("aligned").
    const raw = try read_raw(&tmp, "root/partition/616c69676e6564");
    defer gpa.free(raw);
    const data_offset = iface.BlobLayout.v1.data_offset();
    const pages = std.math.divCeil(u64, logical_size, logical) catch unreachable;
    try testing.expectEqual(@as(u64, 0), raw.len % disk_page);
    try testing.expectEqual(data_offset + pages * disk_page, raw.len);
    var physical = std.mem.window(u8, raw[@intCast(data_offset)..], disk_page, disk_page);
    while (physical.next()) |page| try testing.expect(paged.Checksum.validate_page(page) != null);
}

test "the paged writer keeps V1 pages on aligned disk pages (test_v1_paged_alignment)" {
    try expect_v1_paged_alignment(null);
    var ring: Ring = undefined;
    try init_ring(&ring);
    defer ring.deinit();
    try expect_v1_paged_alignment(&ring);
}

const linux = std.os.linux;

/// Points blob `opened`'s descriptor at `fd` (dup2), so its next operation reaches whatever
/// the kernel does there; the blob's close then closes the replacement.
fn redirect_blob(opened: iface.Opened, fd: linux.fd_t) !void {
    const handle: *file_storage.Blob = @ptrCast(@alignCast(opened.blob.ptr));
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.dup2(fd, handle.file.handle)));
}

/// A connected Unix socket pair; close both ends.
fn socket_pair() ![2]linux.fd_t {
    var fds: [2]linux.fd_t = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    return fds;
}

fn close_pair(fds: [2]linux.fd_t) void {
    for (fds) |fd| assert(linux.errno(linux.close(fd)) == .SUCCESS);
}

/// A write the kernel fails (ENOSPC on /dev/full) is `WriteFailed`.
fn expect_kernel_write_error(ring: ?*Ring) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.createDirPathOpen(io, "root", .{});
    var storage = try file_storage.Storage.init(io, gpa, root, .{ .ring = ring });
    defer storage.deinit();
    const opened = try storage.storage().open("partition", "large");
    defer opened.blob.close();
    const full = try std.Io.Dir.openFileAbsolute(io, "/dev/full", .{ .mode = .write_only });
    defer full.close(io);
    try redirect_blob(opened, full.handle);
    try testing.expectError(error.WriteFailed, opened.blob.write_at(0, "x", .{}));
}

test "a kernel write error is WriteFailed (test_large_contiguous_write_returns_kernel_error)" {
    // Only the error mapping: writes over u32::MAX bytes split across submissions are the
    // runtime-telemetry lane's (request.rs:2125).
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try expect_kernel_write_error(null);
    var ring: Ring = undefined;
    try init_ring(&ring);
    defer ring.deinit();
    try expect_kernel_write_error(&ring);
}

test "resize of a socket descriptor is BlobResizeFailed (test_resize_reports_kernel_error)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    const opened = try storage.storage().open("partition", "blob");
    defer opened.blob.close();
    const fds = try socket_pair();
    defer close_pair(fds);
    try redirect_blob(opened, fds[0]);
    try testing.expectError(error.BlobResizeFailed, opened.blob.resize(0));
}

test "sync of a socket descriptor is BlobSyncFailed (test_blob_sync_reports_kernel_error)" {
    // Over io_uring only: std.Io reports fsync's EINVAL (which a regular file never returns)
    // as a programmer bug, a panic in Debug builds.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var ring: Ring = undefined;
    try init_ring(&ring);
    defer ring.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.createDirPathOpen(io, "root", .{});
    var storage = try file_storage.Storage.init(io, gpa, root, .{ .ring = &ring });
    defer storage.deinit();
    const opened = try storage.storage().open("partition", "blob");
    defer opened.blob.close();
    const fds = try socket_pair();
    defer close_pair(fds);
    try redirect_blob(opened, fds[0]);
    try testing.expectError(error.BlobSyncFailed, opened.blob.sync());
}

fn expect_flushed(storage: *const file_storage.Storage, keys: []const []const u8) !void {
    try testing.expectEqual(keys.len, storage.flushed.count());
    for (keys) |key| try testing.expect(storage.flushed.contains(key));
}

test "the first open of an existing blob flushes it once (test_first_open_flushes_existing_blob)" {
    // commonware counts the flushes; zigware records each flushed key, and `flushed` asserts a
    // key is never flushed twice.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var previous = try open_storage(&tmp, "root");
        defer previous.deinit();
        const opened = try previous.storage().open("partition", "blob");
        defer opened.blob.close();
        try opened.blob.write_at(0, "hello", .{ .sync = true });
    }
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    try expect_flushed(&storage, &.{});
    const opened = try storage.storage().open("partition", "blob");
    try testing.expectEqual(@as(u64, 5), opened.len);
    opened.blob.close();
    // "626c6f62" is hex("blob"), "6672657368" hex("fresh").
    try expect_flushed(&storage, &.{"partition/626c6f62"});
    (try storage.storage().open("partition", "blob")).blob.close();
    for (0..2) |_| (try storage.storage().open("partition", "fresh")).blob.close();
    try expect_flushed(&storage, &.{ "partition/626c6f62", "partition/6672657368" });
}

test "remove forgets first-open names (test_remove_forgets_first_open_names)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage = try open_storage(&tmp, "root");
    defer storage.deinit();
    const files = [_][2][]const u8{ .{ "a", "1" }, .{ "a", "2" }, .{ "b", "1" } };
    for (files) |file| (try storage.storage().open(file[0], file[1])).blob.close();
    // "31" is hex("1"), "32" hex("2").
    try expect_flushed(&storage, &.{ "a/31", "a/32", "b/31" });
    try storage.remove("a", "1");
    try expect_flushed(&storage, &.{ "a/32", "b/31" });
    for (0..2) |_| (try storage.storage().open("a", "1")).blob.close();
    try expect_flushed(&storage, &.{ "a/31", "a/32", "b/31" });
    try storage.remove("a", null);
    try expect_flushed(&storage, &.{"b/31"});
}
