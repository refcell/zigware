//! Tests for the paged `Writer` and `Replay`, ported from commonware's `paged/writer.rs`
//! (same 103-byte "janky" page size and 206-byte buffer), plus a seeded crash fuzz.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Crc32 = @import("cryptography").crc32.Crc32;
const mocks = @import("../mocks.zig");
const paged = @import("mod.zig");
const writer_mod = @import("writer.zig");
const CacheRef = paged.CacheRef;
const Checksum = paged.Checksum;
const storage_iface = @import("../../storage.zig");
const Blob = storage_iface.Blob;
const ReadOptions = storage_iface.ReadOptions;
const WriteOptions = storage_iface.WriteOptions;
const Error = storage_iface.Error;
const rng = @import("utils").rng;
const FuzzRng = rng.FuzzRng;

const Storage = mocks.Storage;
const W = writer_mod.Writer;
const gpa = testing.allocator;
const page_size: usize = 103;
const physical_page_size: usize = page_size + 12;
const buffer_size: usize = page_size * 2;
const partition = "test_partition";
const dummy_marker = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };

const Harness = struct {
    storage: Storage,
    cache_ref: CacheRef,

    fn init() !Harness {
        return init_cache(buffer_size);
    }

    fn init_cache(cache_pages: u32) !Harness {
        return .{
            .storage = Storage.init(gpa),
            .cache_ref = try CacheRef.init(gpa, page_size, cache_pages),
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn writer(self: *Harness, name: []const u8) !W {
        const opened = try self.storage.open(partition, name);
        errdefer opened.blob.close();
        return W.init(gpa, opened.blob, opened.len, buffer_size, &self.cache_ref);
    }

    fn recovery(self: *Harness, name: []const u8) !W {
        const opened = try self.storage.open(partition, name);
        errdefer opened.blob.close();
        return W.open_recovery(gpa, opened.blob, opened.len, buffer_size, &self.cache_ref);
    }

    /// Append `bytes` to blob `name` in a fresh writer and sync.
    fn append_synced(self: *Harness, name: []const u8, bytes: []const u8) !void {
        var w = try self.writer(name);
        defer w.deinit();
        _ = try w.append(bytes);
        try w.sync();
    }

    /// The raw bytes of blob `name`; caller frees.
    fn raw(self: *Harness, name: []const u8) ![]u8 {
        const opened = try self.storage.open(partition, name);
        defer opened.blob.close();
        const bytes = try gpa.alloc(u8, @intCast(opened.len));
        errdefer gpa.free(bytes);
        try opened.blob.read_at(0, bytes);
        return bytes;
    }

    /// Overwrite raw bytes of blob `name` durably.
    fn mangle(self: *Harness, name: []const u8, offset: u64, bytes: []const u8) !void {
        const opened = try self.storage.open(partition, name);
        defer opened.blob.close();
        try opened.blob.write_at(offset, bytes, .{});
        try opened.blob.sync();
    }

    fn record(self: *Harness, name: []const u8, page: usize) !Checksum {
        const bytes = try self.raw(name);
        defer gpa.free(bytes);
        const start = page * physical_page_size + page_size;
        return Checksum.decode(bytes[start..][0..12]);
    }
};

fn sequence(comptime first: u8, comptime last: u8) [last - first + 1]u8 {
    var bytes: [last - first + 1]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = first + @as(u8, @intCast(index));
    return bytes;
}

fn expect_read(w: *W, offset: u64, expected: []const u8) !void {
    const buf = try gpa.alloc(u8, expected.len);
    defer gpa.free(buf);
    try w.read_into(buf, offset);
    try testing.expectEqualSlices(u8, expected, buf);
}

test "append crc basic" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("test_blob");
    try testing.expectEqual(@as(u64, 0), w.size());
    try testing.expectEqual(@as(u64, 0), try w.append(&sequence(1, 5)));
    try testing.expectEqual(@as(u64, 5), try w.append(&sequence(6, 10)));
    try testing.expectEqual(@as(u64, 10), w.size());
    try expect_read(&w, 0, &sequence(1, 5));
    try expect_read(&w, 5, &sequence(6, 10));
    try w.sync();
    w.deinit();

    // One padded physical page: data, zeros, then the CRC record in slot one.
    const bytes = try h.raw("test_blob");
    defer gpa.free(bytes);
    try testing.expectEqual(physical_page_size, bytes.len);
    try testing.expectEqualSlices(u8, &sequence(1, 10), bytes[0..10]);
    for (bytes[10..page_size]) |byte| try testing.expectEqual(@as(u8, 0), byte);
    const expected = Checksum.init(10, Crc32.checksum(&sequence(1, 10)));
    try testing.expectEqualSlices(u8, &expected.to_bytes(), bytes[page_size..]);

    // Reopen strips the checksum, then cross a page boundary.
    w = try h.writer("test_blob");
    try testing.expectEqual(@as(u64, 10), w.size());
    _ = try w.append(&sequence(11, 110));
    try expect_read(&w, 10, &sequence(11, 110));
    try expect_read(&w, 0, &sequence(1, 110));
    try w.sync();
    w.deinit();
    w = try h.writer("test_blob");
    try testing.expectEqual(@as(u64, 110), w.size());
    try expect_read(&w, 0, &sequence(1, 110));
    w.deinit();
    const raw = try h.raw("test_blob");
    defer gpa.free(raw);
    try testing.expectEqual(2 * physical_page_size, raw.len);
}

test "extending a partial page protects the durable slot" {
    var h = try Harness.init();
    defer h.deinit();
    try h.append_synced("slot1_prot", &sequence(1, 10));
    try h.append_synced("slot1_prot", &sequence(11, 30));
    const record = try h.record("slot1_prot", 0);
    try testing.expectEqual(@as(u16, 10), record.len1);
    try testing.expectEqual(@as(u16, 30), record.len2);

    // Mangle the non-authoritative slot; the next extension writes there and leaves the
    // authoritative slot byte-identical.
    try h.mangle("slot1_prot", page_size, &dummy_marker);
    try h.append_synced("slot1_prot", &sequence(31, 50));
    const after = try h.record("slot1_prot", 0);
    try testing.expectEqual(@as(u16, 50), after.len1);
    try testing.expectEqual(record.len2, after.len2);
    try testing.expectEqual(record.crc2, after.crc2);

    var w = try h.writer("slot1_prot");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 50), w.size());
    try expect_read(&w, 0, &sequence(1, 50));
}

test "data prefix preserved when extending" {
    var h = try Harness.init();
    defer h.deinit();
    try h.append_synced("prefix_test", &sequence(1, 20));
    // Mangle bytes in the padding after the data.
    try h.mangle("prefix_test", 25, &dummy_marker);
    try h.append_synced("prefix_test", &sequence(21, 40));
    const bytes = try h.raw("prefix_test");
    defer gpa.free(bytes);
    try testing.expectEqualSlices(u8, &sequence(1, 40), bytes[0..40]);
}

/// Two physical pages: page 0 full (slot one len 10, slot two len 103), page 1 partial.
fn two_page_blob(h: *Harness, name: []const u8) !void {
    try h.append_synced(name, &sequence(1, 10));
    try h.append_synced(name, &sequence(11, 103));
    const record = try h.record(name, 0);
    try testing.expectEqual(@as(u16, 10), record.len1);
    try testing.expectEqual(@as(u16, 103), record.len2);
    try h.append_synced(name, &sequence(104, 113));
}

test "non-last page rejects partial fallback" {
    var h = try Harness.init();
    defer h.deinit();
    try two_page_blob(&h, "non_last_page");
    // Corrupt page 0's authoritative CRC (slot two): the fallback is partial, which an
    // interior page cannot be.
    try h.mangle("non_last_page", page_size + 8, &.{ 0xDE, 0xAD, 0xBE, 0xEF });
    var w = try h.writer("non_last_page");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 113), w.size());
    var buf: [10]u8 = undefined;
    try testing.expectError(error.InvalidChecksum, w.read_into(&buf, 0));
    // The tail page is still readable.
    try expect_read(&w, 103, &sequence(104, 113));
    // Replay fails on the short interior page too.
    var replay = try w.replay(1024, .{});
    defer replay.deinit();
    try testing.expectError(error.InvalidChecksum, replay.ensure(1));
    // A fill after seeking past the surviving slot's bytes fails the same way
    // (commonware's `test_replay_rejects_short_interior_page`).
    try replay.seek_to(40);
    try testing.expectError(error.InvalidChecksum, replay.ensure(1));
    try testing.expectEqual(@as(usize, 0), replay.remaining());
}

test "corrupted lengths past the page are invalid" {
    var h = try Harness.init();
    defer h.deinit();
    try h.append_synced("len_too_large", &sequence(1, 10));
    // Both slots claim more bytes than the page holds: no valid page remains.
    var bad: [12]u8 = undefined;
    std.mem.writeInt(u16, bad[0..2], 0xFFFF, .big);
    std.mem.writeInt(u32, bad[2..6], 0, .big);
    std.mem.writeInt(u16, bad[6..8], 104, .big);
    std.mem.writeInt(u32, bad[8..12], 0, .big);
    try h.mangle("len_too_large", page_size, &bad);
    var w = try h.writer("len_too_large");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 0), w.size());
}

test "recovery trims an invalid tail and zeroes a stale slot" {
    var h = try Harness.init();
    defer h.deinit();
    try h.append_synced("torn", &sequence(1, 10));
    try h.append_synced("torn", &sequence(11, 20));
    // Corrupt byte 15: the len-20 slot no longer verifies, the len-10 slot still does.
    try h.mangle("torn", 15, &.{0xFF});
    {
        // Also append a truncated physical page of junk.
        const opened = try h.storage.open(partition, "torn");
        defer opened.blob.close();
        try opened.blob.write_at(physical_page_size, "junk", .{});
        try opened.blob.sync();
    }
    var w = try h.writer("torn");
    try testing.expectEqual(@as(u64, 10), w.size());
    try expect_read(&w, 0, &sequence(1, 10));
    w.deinit();
    const bytes = try h.raw("torn");
    defer gpa.free(bytes);
    try testing.expectEqual(physical_page_size, bytes.len);
    // The stale len-20 checksum was zeroed so a torn rewrite cannot complete it.
    const record = Checksum.decode(bytes[page_size..][0..12]);
    try testing.expectEqual(@as(u16, 10), record.len1);
    try testing.expectEqual(@as(u16, 0), record.len2);
    try testing.expectEqual(@as(u32, 0), record.crc2);
}

test "recovery truncate to partial, page boundary, and larger sizes" {
    var h = try Harness.init();
    defer h.deinit();
    var data: [250]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index * 7 + 1);
    try h.append_synced("truncate", &data);

    const Case = struct { target: u64, size: u64 };
    for ([_]Case{
        .{ .target = 300, .size = 250 }, // Larger: unchanged.
        .{ .target = 240, .size = 240 }, // Same page shrink.
        .{ .target = 150, .size = 150 }, // Full page to partial.
        .{ .target = 103, .size = 103 }, // Page boundary.
        .{ .target = 50, .size = 50 },
    }) |case| {
        var w = try h.recovery("truncate");
        try w.truncate(case.target);
        try testing.expectEqual(case.size, w.size());
        w.deinit();
        w = try h.writer("truncate");
        defer w.deinit();
        try testing.expectEqual(case.size, w.size());
        try expect_read(&w, 0, data[0..@intCast(case.size)]);
    }

    // The shrunk partial page's shorter checksum is authoritative and the old slot is zero.
    const record = try h.record("truncate", 0);
    const active = Checksum.validate_page(blk: {
        const bytes = try h.raw("truncate");
        defer gpa.free(bytes);
        var page: [physical_page_size]u8 = undefined;
        @memcpy(&page, bytes[0..physical_page_size]);
        break :blk &page;
    }).?;
    try testing.expectEqual(@as(u16, 50), active.len);
    const other_len, const other_crc = record.get_slot(active.slot.other());
    try testing.expectEqual(@as(u16, 0), other_len);
    try testing.expectEqual(@as(u32, 0), other_crc);

    // Appending after a shrink overwrites the dropped bytes.
    var w = try h.writer("truncate");
    defer w.deinit();
    _ = try w.append("tail");
    try w.sync();
    try expect_read(&w, 46, data[46..50]);
    try expect_read(&w, 50, "tail");
}

test "bulk appends match buffered appends byte for byte" {
    var h = try Harness.init();
    defer h.deinit();
    var data: [1000]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index * 13 + 5);
    var bulk = try h.writer("bulk");
    _ = try bulk.append(data[0..7]);
    _ = try bulk.append(data[7..]); // Bypasses the buffer.
    try bulk.sync();
    try expect_read(&bulk, 0, &data);
    bulk.deinit();
    var small = try h.writer("small");
    var offset: usize = 0;
    while (offset < data.len) : (offset += 9) {
        _ = try small.append(data[offset..@min(data.len, offset + 9)]);
    }
    try small.sync();
    small.deinit();
    const bulk_bytes = try h.raw("bulk");
    defer gpa.free(bulk_bytes);
    const small_bytes = try h.raw("small");
    defer gpa.free(small_bytes);
    try testing.expectEqualSlices(u8, small_bytes, bulk_bytes);
}

test "reads come from the tip, the cache, and the blob" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("reads");
    defer w.deinit();
    _ = try w.append(&sequence(1, 50));
    var buf: [50]u8 = undefined;
    try testing.expect(w.try_read_sync_into(&buf, 0));
    try testing.expectEqualSlices(u8, &sequence(1, 50), &buf);
    _ = try w.append(&sequence(51, 250));
    try w.sync();
    // Flushed pages were cached.
    var big: [200]u8 = undefined;
    try testing.expect(w.try_read_sync_into(&big, 0));
    h.cache_ref.clear();
    try testing.expect(!w.try_read_sync_into(&big, 0));
    try expect_read(&w, 0, &sequence(1, 250));
    try testing.expect(w.try_read_sync_into(&big, 0));
    try testing.expectError(error.BlobInsufficientLength, w.read_into(&buf, 201));
    var up_to: [100]u8 = undefined;
    try testing.expectEqual(@as(usize, 50), try w.read_up_to(200, &up_to));
    try testing.expectError(error.BlobInsufficientLength, w.read_up_to(250, &up_to));
}

test "replay returns every logical byte and seeks" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("replay");
    defer w.deinit();
    var data: [500]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index);
    _ = try w.append(&data);
    var replay = try w.replay(physical_page_size * 2, .{});
    defer replay.deinit();
    try testing.expectEqual(@as(u64, 500), replay.blob_size());
    try testing.expect(try replay.ensure(500));
    try testing.expectEqualSlices(u8, &data, replay.bytes()[0..500]);
    replay.advance(500);
    try testing.expect(!try replay.ensure(1));
    try testing.expect(replay.is_exhausted());
    for ([_]u64{ 0, 1, 102, 103, 250, 412, 499, 500 }) |offset| {
        try replay.seek_to(offset);
        const want: usize = @intCast(500 - offset);
        try testing.expect(try replay.ensure(want));
        try testing.expectEqualSlices(u8, data[@intCast(offset)..], replay.bytes());
    }
    try testing.expectError(error.BlobInsufficientLength, replay.seek_to(501));
}

test "recoverable prefix stops at a torn interior page" {
    var h = try Harness.init();
    defer h.deinit();
    var data: [600]u8 = undefined;
    @memset(&data, 9);
    try h.append_synced("prefix", &data);
    var w = try h.writer("prefix");
    try testing.expectEqual(@as(u64, 600), try w.recoverable_prefix_len(0));
    try testing.expectEqual(@as(u64, 200), try w.recoverable_prefix_len_at_most(0, 200));
    try testing.expectEqual(@as(u64, 0), try w.recoverable_prefix_len_at_most(0, 0));
    w.deinit();

    try paged.corrupt_page(h.storage.interface(), partition, "prefix", 2, page_size);
    w = try h.writer("prefix");
    defer w.deinit();
    // Recovery scans backwards and keeps the size; the forward scan finds the hole.
    try testing.expectEqual(@as(u64, 600), w.size());
    try testing.expectEqual(@as(u64, 2 * page_size), try w.recoverable_prefix_len(0));
    // A proof past the hole is trusted.
    try testing.expectEqual(@as(u64, 600), try w.recoverable_prefix_len(3 * page_size));
}

test "read range and read tail on raw blobs" {
    var h = try Harness.init();
    defer h.deinit();
    var data: [300]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index * 3);
    try h.append_synced("raw", &data);
    const opened = try h.storage.open(partition, "raw");
    defer opened.blob.close();
    var scratch: [physical_page_size]u8 = undefined;
    var buf: [150]u8 = undefined;
    try paged.read_range(opened.blob, page_size, 100, &buf, &scratch);
    try testing.expectEqualSlices(u8, data[100..250], &buf);
    try testing.expectError(
        error.BlobInsufficientLength,
        paged.read_range(opened.blob, page_size, 200, &buf, &scratch),
    );
    var tail: [120]u8 = undefined;
    const size = try paged.read_tail(opened.blob, opened.len, page_size, &tail, &scratch);
    try testing.expectEqual(@as(u64, 300), size);
    try testing.expectEqualSlices(u8, data[180..], &tail);
    var too_much: [301]u8 = undefined;
    try testing.expectError(
        error.BlobInsufficientLength,
        paged.read_tail(opened.blob, opened.len, page_size, &too_much, &scratch),
    );
    try testing.expectError(
        error.BlobInsufficientLength,
        paged.read_tail(opened.blob, opened.len - 1, page_size, &tail, &scratch),
    );
}

test "try append respects capacity" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("try_append");
    defer w.deinit();
    var data: [buffer_size]u8 = @splat(1);
    try testing.expectEqual(@as(?u64, 0), w.try_append(&data));
    try testing.expectEqual(@as(?u64, null), w.try_append("x"));
    try testing.expectEqual(@as(?u64, null), w.try_append_value(u8, 1));
    try w.sync();
    try testing.expectEqual(@as(?u64, buffer_size), w.try_append_value(u16, 0x0102));
    try expect_read(&w, buffer_size, &.{ 1, 2 });
}

// Seeded crash fuzz: random appends, syncs, crashes (close without sync), and recovery
// truncations, checked against a model of the durable and live contents.

const fuzz_bytes_max = 4096;

fn fuzz_crashes(_: void, r: *FuzzRng) !void {
    var h = try Harness.init();
    defer h.deinit();
    var model: std.ArrayList(u8) = .empty;
    defer model.deinit(gpa);
    var durable_len: usize = 0;
    var w = try h.writer("fuzz");
    defer w.deinit();
    const steps = rng.range_at_most(r, u8, 1, 64);
    for (0..steps) |_| {
        switch (rng.range_less_than(r, u8, 0, 6)) {
            0, 1, 2 => {
                const room = @min(400, fuzz_bytes_max - model.items.len);
                const len = rng.range_at_most(r, usize, 0, room);
                const start = model.items.len;
                try model.resize(gpa, start + len);
                r.fill_bytes(model.items[start..]);
                try testing.expectEqual(@as(u64, start), try w.append(model.items[start..]));
            },
            3 => {
                try w.sync();
                durable_len = model.items.len;
            },
            4 => {
                // Crash: unsynced bytes are lost.
                w.deinit();
                w = try h.writer("fuzz");
                model.shrinkRetainingCapacity(durable_len);
            },
            5 => {
                const target = rng.range_at_most(r, usize, 0, model.items.len);
                try w.sync();
                w.deinit();
                w = try h.recovery("fuzz");
                try w.truncate(target);
                w.finish_recovery();
                model.shrinkRetainingCapacity(target);
                durable_len = target;
            },
            else => unreachable,
        }
        try testing.expectEqual(@as(u64, model.items.len), w.size());
        if (model.items.len > 0) try expect_read(&w, 0, model.items);
    }
}

test "fuzz paged writer crashes" {
    try @import("utils").fuzz.run({}, fuzz_crashes, 0x7061676564, 32);
}

test "read_many_into: empty" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("rmany");
    defer w.deinit();
    _ = try w.append(&@as([8]u8, @splat(0)));
    try testing.expectEqual(0, try w.read_many_into(&.{}, &.{}, 4));
    try testing.expectEqual(0, try w.read_ranges_into(&.{}, &.{}));
}

/// Items of 4 bytes at `offsets` read back the matching bytes of `data`, and `served` of them
/// came from the write buffer or page cache.
fn expect_many(w: *W, data: []const u8, offsets: []const u64, served: usize) !void {
    const buf = try gpa.alloc(u8, offsets.len * 4);
    defer gpa.free(buf);
    @memset(buf, 0xEE);
    try testing.expectEqual(served, try w.read_many_into(buf, offsets, 4));
    for (offsets, 0..) |offset, index| {
        const at: usize = @intCast(offset);
        try testing.expectEqualSlices(u8, data[at..][0..4], buf[index * 4 ..][0..4]);
    }
}

test "read_many_into: items in the tip, the cache, and both" {
    var h = try Harness.init();
    defer h.deinit();
    const data = sequence(0, 31);
    // All in the unflushed tip.
    var w = try h.writer("tip");
    _ = try w.append(data[0..20]);
    try expect_many(&w, &data, &.{ 0, 4, 8, 12, 16 }, 5);
    w.deinit();
    // Synced bytes stay readable from the retained partial tip.
    w = try h.writer("cache");
    _ = try w.append(data[0..20]);
    try w.sync();
    try expect_many(&w, &data, &.{ 0, 8, 16 }, 3);
    w.deinit();
    // Offsets spanning synced and unsynced bytes of one partial tip.
    w = try h.writer("mixed");
    defer w.deinit();
    _ = try w.append(data[0..16]);
    try w.sync();
    _ = try w.append(data[16..]);
    try expect_many(&w, &data, &.{ 0, 4, 16, 24 }, 4);
}

test "read_many_into: out of bounds and offset overflow" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("rmany");
    defer w.deinit();
    _ = try w.append(&sequence(0, 19));
    var buf: [8]u8 = undefined;
    try testing.expectError(error.BlobInsufficientLength, w.read_many_into(&buf, &.{ 0, 17 }, 4));
    const max = std.math.maxInt(u64);
    try testing.expectError(error.OffsetOverflow, w.read_many_into(buf[0..4], &.{max - 1}, 4));
    const ranges = [_]W.Range{.{ .offset = 18, .len = 4 }};
    try testing.expectError(error.BlobInsufficientLength, w.read_ranges_into(buf[0..4], &ranges));
}

test "read_many_into: matches read_into after an evicted cache" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("rmany");
    defer w.deinit();
    var data: [page_size * 4 + 17]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index * 7);
    _ = try w.append(&data);
    try w.sync();
    h.cache_ref.clear();
    // Items within pages, straddling pages, and in the tip.
    const offsets = [_]u64{ 0, page_size - 2, page_size * 2 + 5, page_size * 4 + 10 };
    const reads = h.storage.reads;
    try expect_many(&w, &data, &offsets, 1);
    try testing.expect(h.storage.reads > reads);
    // The pages are cached now, so every item is served without a blob read.
    const cached = h.storage.reads;
    try expect_many(&w, &data, &offsets, offsets.len);
    try testing.expectEqual(cached, h.storage.reads);
}

test "read_ranges_into: mixed lengths and the tail" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("ranges");
    defer w.deinit();
    var data: [3 * page_size + 37]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index % 251);
    _ = try w.append(data[0 .. 3 * page_size]);
    try w.sync();
    _ = try w.append(data[3 * page_size ..]);
    // Empty, inside a page, crossing pages, crossing into the tip, inside the tip, empty.
    const ranges = [_]W.Range{
        .{ .offset = 0, .len = 0 },
        .{ .offset = 1, .len = 3 },
        .{ .offset = page_size + 2, .len = 5 },
        .{ .offset = 2 * page_size - 2, .len = 4 },
        .{ .offset = 3 * page_size - 3, .len = 8 },
        .{ .offset = 3 * page_size + 9, .len = 9 },
        .{ .offset = data.len, .len = 0 },
    };
    var expected: [29]u8 = undefined;
    var start: usize = 0;
    for (ranges) |range| {
        const at: usize = @intCast(range.offset);
        @memcpy(expected[start..][0..range.len], data[at..][0..range.len]);
        start += range.len;
    }
    try testing.expectEqual(expected.len, start);
    // With a cold cache only the empty ranges and the one inside the tip are served; caching
    // page 1 adds the range inside it.
    var out: [29]u8 = @splat(0xEE);
    h.cache_ref.clear();
    try testing.expectEqual(3, try w.read_ranges_into(&out, &ranges));
    try testing.expectEqualSlices(u8, &expected, &out);
    h.cache_ref.clear();
    var one: [1]u8 = undefined;
    try w.read_into(&one, page_size + 1);
    out = @splat(0xEE);
    try testing.expectEqual(4, try w.read_ranges_into(&out, &ranges));
    try testing.expectEqualSlices(u8, &expected, &out);
    // The cache-only variant names the ranges that still need a blob read.
    h.cache_ref.clear();
    var misses: [ranges.len]usize = undefined;
    const count = w.try_read_ranges_sync_into(&out, &ranges, &misses);
    try testing.expectEqualSlices(usize, &.{ 1, 2, 3, 4 }, misses[0..count]);
    // Ranges past the writer miss entirely.
    const past = [_]W.Range{.{ .offset = data.len, .len = 1 }};
    try testing.expectEqual(1, w.try_read_ranges_sync_into(out[0..1], &past, &misses));
}

test "recoverable prefix: a proof skips damage it covers and clamps to the blob" {
    var h = try Harness.init();
    defer h.deinit();
    const page: u64 = page_size;
    var data: [page_size * 4]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index);
    var w = try h.writer("prefix_proven");
    defer w.deinit();
    _ = try w.append(&data);
    try w.sync();
    // Tear page 1, leaving pages 0 and 2+ valid.
    const offset = physical_page_size + 7;
    var byte: [1]u8 = undefined;
    try w.blob.read_at(offset, &byte);
    byte[0] ^= 0xFF;
    try w.blob.write_at(offset, &byte, .{});
    try w.blob.sync();
    // An unproven scan stops at the torn page. A proof past it skips the damage, and a
    // mid-page proof rescans the page containing it.
    const cases = [_][2]u64{
        .{ 0, page },
        .{ page, page },
        .{ 2 * page, 4 * page },
        .{ 2 * page + 3, 4 * page },
        .{ data.len, 4 * page },
        .{ 100 * page, 4 * page },
    };
    for (cases) |case| {
        try testing.expectEqual(case[1], try w.recoverable_prefix_len(case[0]));
    }
    // A partial tail still counts its logical length when the proof overshoots the blob.
    _ = try w.append(data[0..20]);
    try w.sync();
    for ([_]u64{ 4 * page + 20, 5 * page, 100 * page }) |proven| {
        try testing.expectEqual(4 * page + 20, try w.recoverable_prefix_len(proven));
    }
}

test "recoverable prefix: a stale short interior page ends the prefix" {
    var h = try Harness.init();
    defer h.deinit();
    var data: [page_size * 2]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index);
    var w = try h.writer("prefix_stale");
    defer w.deinit();
    _ = try w.append(data[0..20]);
    try w.sync();
    var stale: [physical_page_size]u8 = undefined;
    try w.blob.read_at(0, &stale);
    // Extend past the first page, then restore page 0 to its stale partial state as if the
    // extension never reached disk.
    _ = try w.append(data[20..]);
    try w.sync();
    try w.blob.write_at(0, &stale, .{});
    try w.blob.sync();
    try testing.expectEqual(@as(u64, 20), try w.recoverable_prefix_len(0));
}

test "recoverable prefix: a cap bounds the pages read" {
    var h = try Harness.init();
    defer h.deinit();
    const page: u64 = page_size;
    const total = page * 8 + 10;
    var data: [total]u8 = undefined;
    @memset(&data, 7);
    var w = try h.writer("bounded_prefix");
    defer w.deinit();
    _ = try w.append(&data);
    try w.sync();
    const max = std.math.maxInt(u64);
    // Pages are read one at a time, so touching any page beyond the cap is observable.
    const Case = struct { cap: u64, proven: u64, reads: u64 };
    const cases = [_]Case{
        .{ .cap = 0, .proven = 0, .reads = 0 },
        .{ .cap = 1, .proven = 0, .reads = 1 },
        .{ .cap = page, .proven = 0, .reads = 1 },
        .{ .cap = page + 1, .proven = 0, .reads = 2 },
        .{ .cap = page * 3, .proven = page, .reads = 2 },
        .{ .cap = 1, .proven = max, .reads = 0 },
        .{ .cap = total - 1, .proven = 0, .reads = 9 },
        .{ .cap = total, .proven = 0, .reads = 9 },
        .{ .cap = total + 1, .proven = 0, .reads = 9 },
        .{ .cap = max, .proven = 0, .reads = 9 },
        .{ .cap = max, .proven = max, .reads = 1 },
    };
    for (cases) |case| {
        const reads = h.storage.reads;
        const len = try w.recoverable_prefix_len_at_most(case.proven, case.cap);
        try testing.expectEqual(@min(case.cap, total), len);
        try testing.expectEqual(case.reads, h.storage.reads - reads);
    }
}

test "extending protects slot two when slot one is authoritative" {
    var h = try Harness.init();
    defer h.deinit();
    try h.append_synced("slot0_prot", &sequence(1, 10));
    try h.append_synced("slot0_prot", &sequence(11, 30));
    try h.append_synced("slot0_prot", &sequence(31, 50));
    const record = try h.record("slot0_prot", 0);
    try testing.expectEqual(@as(u16, 50), record.len1);
    try testing.expectEqual(@as(u16, 30), record.len2);
    // Mangle slot two (non-authoritative); the extension writes there, leaving slot one.
    try h.mangle("slot0_prot", page_size + 6, &dummy_marker);
    try h.append_synced("slot0_prot", &sequence(51, 70));
    const after = try h.record("slot0_prot", 0);
    try testing.expectEqual(record.len1, after.len1);
    try testing.expectEqual(record.crc1, after.crc1);
    try testing.expectEqual(@as(u16, 70), after.len2);
    var w = try h.writer("slot0_prot");
    defer w.deinit();
    try expect_read(&w, 0, &sequence(1, 70));
}

test "crossing a page boundary protects the durable slot" {
    var h = try Harness.init();
    defer h.deinit();
    try h.append_synced("boundary", &sequence(1, 50));
    try h.append_synced("boundary", &sequence(51, 80));
    const record = try h.record("boundary", 0);
    try testing.expect(record.len2 > record.len1);
    try h.mangle("boundary", page_size, &dummy_marker);
    // 80 + 40 = 120 bytes crosses the 103-byte page.
    try h.append_synced("boundary", &sequence(81, 120));
    const bytes = try h.raw("boundary");
    defer gpa.free(bytes);
    try testing.expectEqual(physical_page_size * 2, bytes.len);
    const after = try h.record("boundary", 0);
    // Slot one holds the full-page checksum; slot two is byte-identical.
    try testing.expectEqual(@as(u16, page_size), after.len1);
    try testing.expectEqual(record.len2, after.len2);
    try testing.expectEqual(record.crc2, after.crc2);
    var w = try h.writer("boundary");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 120), w.size());
    try expect_read(&w, 0, &sequence(1, 120));
}

test "a corrupted authoritative crc falls back to the other slot" {
    var h = try Harness.init();
    defer h.deinit();
    try h.append_synced("crc_fallback", &sequence(1, 10));
    try h.append_synced("crc_fallback", &sequence(11, 30));
    const record = try h.record("crc_fallback", 0);
    try testing.expectEqual(@as(u16, 10), record.len1);
    try testing.expectEqual(@as(u16, 30), record.len2);
    {
        var w = try h.writer("crc_fallback");
        defer w.deinit();
        try testing.expectEqual(@as(u64, 30), w.size());
        try expect_read(&w, 0, &sequence(1, 30));
    }
    // Corrupt only crc2, not len2.
    try h.mangle("crc_fallback", page_size + 8, &.{ 0xDE, 0xAD, 0xBE, 0xEF });
    const corrupted = try h.record("crc_fallback", 0);
    try testing.expectEqual(@as(u16, 30), corrupted.len2);
    try testing.expectEqual(@as(u32, 0xDEADBEEF), corrupted.crc2);
    var w = try h.writer("crc_fallback");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 10), w.size());
    try expect_read(&w, 0, &sequence(1, 10));
    var buf: [11]u8 = undefined;
    try testing.expectError(error.BlobInsufficientLength, w.read_into(&buf, 0));
}

fn cycle_from(comptime first: u8, comptime len: usize) [len]u8 {
    var bytes: [len]u8 = undefined;
    for (&bytes, 0..) |*byte, index| {
        byte.* = @intCast(first + (index % (256 - @as(usize, first))));
    }
    return bytes;
}

test "read_many_into: tip, cached, uncached, and straddling items in one call" {
    // A two-page cache, so page 1 can be left out of it.
    var h = try Harness.init_cache(2);
    defer h.deinit();
    var w = try h.writer("rmany");
    defer w.deinit();
    const item_size = 10;
    const synced = cycle_from(0, page_size * 3);
    _ = try w.append(&synced);
    try w.sync();
    const tip = cycle_from(100, page_size / 2);
    _ = try w.append(&tip);
    var probe: [item_size]u8 = undefined;
    try w.read_into(&probe, 0);
    try w.read_into(&probe, page_size * 2);
    const offsets = [_]u64{
        0,
        page_size,
        page_size * 2,
        synced.len - item_size / 2,
        synced.len + item_size,
    };
    var buf: [offsets.len * item_size]u8 = undefined;
    _ = try w.read_many_into(&buf, &offsets, item_size);
    const all = synced ++ tip;
    for (offsets, 0..) |offset, index| {
        const start: usize = @intCast(offset);
        const item = buf[index * item_size ..][0..item_size];
        try testing.expectEqualSlices(u8, all[start..][0..item_size], item);
    }
}

test "read_many_into: a straddle with an uncached prefix counts as a blob read" {
    var h = try Harness.init_cache(1);
    defer h.deinit();
    var w = try h.writer("rmany_smiss");
    defer w.deinit();
    const item_size = 10;
    const synced = cycle_from(0, page_size * 3);
    _ = try w.append(&synced);
    try w.sync();
    const tip = cycle_from(100, page_size / 2);
    _ = try w.append(&tip);
    // Fault page 0 in, so the straddle's prefix page (page 2) is not cached.
    var probe: [item_size]u8 = undefined;
    try w.read_into(&probe, 0);
    const offsets = [_]u64{ synced.len - item_size / 2, synced.len + item_size };
    var buf: [offsets.len * item_size]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try w.read_many_into(&buf, &offsets, item_size));
    const all = synced ++ tip;
    for (offsets, 0..) |offset, index| {
        const start: usize = @intCast(offset);
        const item = buf[index * item_size ..][0..item_size];
        try testing.expectEqualSlices(u8, all[start..][0..item_size], item);
    }
}

test "try_read_sync_into misses a straddle into an uncached page" {
    var h = try Harness.init_cache(1);
    defer h.deinit();
    var w = try h.writer("try_read_sync_cache_miss");
    defer w.deinit();
    const data = cycle_from(0, page_size * 2);
    _ = try w.append(&data);
    try w.sync();
    var page: [page_size]u8 = undefined;
    try w.read_into(&page, 0);
    var buf: [4]u8 = @splat(0xAA);
    try testing.expect(!w.try_read_sync_into(&buf, page_size - 2));
}

test "an empty writer syncs without writing a checksum" {
    var h = try Harness.init();
    defer h.deinit();
    {
        var w = try h.writer("test_blob");
        defer w.deinit();
        try testing.expectEqual(@as(u64, 0), w.size());
        try w.sync();
    }
    const bytes = try h.raw("test_blob");
    defer gpa.free(bytes);
    try testing.expectEqual(@as(usize, 0), bytes.len);
    var w = try h.writer("test_blob");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 0), w.size());
}

test "needs_sync tracks sync work" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("needs_sync");
    defer w.deinit();
    // A fresh writer starts dirty: earlier pages may hold unsynced writes.
    try testing.expect(w.needs_sync());
    try w.sync();
    try testing.expect(!w.needs_sync());
    // A buffered partial page is flush work even though the blob is clean.
    _ = try w.append(&(@as([20]u8, @splat(1))));
    try testing.expect(w.needs_sync());
    try w.sync();
    try testing.expect(!w.needs_sync());
}

test "read_up_to of zero bytes reads nothing" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("read_up_to_zero_len");
    defer w.deinit();
    _ = try w.append(&.{ 1, 2, 3, 4 });
    var stale = [_]u8{ 9, 8, 7, 6 };
    try testing.expectEqual(@as(usize, 0), try w.read_up_to(0, stale[0..0]));
    try testing.expectEqualSlices(u8, &.{ 9, 8, 7, 6 }, &stale);
}

test "reads see buffered bytes before any flush" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("rdr_buf");
    defer w.deinit();
    const data = cycle_from(0, 50);
    _ = try w.append(&data);
    try testing.expectEqual(@as(u64, 50), w.size());
    try expect_read(&w, 0, &data);
    var buf: [10]u8 = undefined;
    try testing.expect(w.try_read_sync_into(&buf, 20));
    try testing.expectEqualSlices(u8, data[20..30], &buf);
    try testing.expectEqual(@as(u64, 0), h.storage.writes);
}

test "recovery reads past a truncated end fail cleanly" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.recovery("rdr_rsz");
    defer w.deinit();
    const data = cycle_from(0, page_size * 2);
    _ = try w.append(&data);
    try w.sync();
    const new_size = page_size / 2;
    try w.truncate(new_size);
    var buf: [page_size]u8 = undefined;
    try testing.expectError(error.BlobInsufficientLength, w.read_into(&buf, new_size));
    // Reads within the new size return the retained prefix, not stale cached bytes.
    try expect_read(&w, 0, data[0..new_size]);
}

test "unsynced flushes preserve the durable checksum slot" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("replay_torn");
    defer w.deinit();
    // Make a mid-page prefix durable and capture the page's durable image.
    const synced = sequence(1, 24);
    _ = try w.append(&synced);
    try w.sync();
    var durable: [physical_page_size]u8 = undefined;
    try w.blob.read_at(0, &durable);
    // Two unsynced rewrites of the same page (a replay flushes the partial page).
    for ([_]u8{ 25, 26 }) |byte| {
        _ = try w.append(&(@as([8]u8, @splat(byte))));
        var replay = try w.replay(buffer_size, .{});
        replay.deinit();
    }
    var torn: [physical_page_size]u8 = undefined;
    try w.blob.read_at(0, &torn);
    // Crash: only the final rewrite's footer lands; the logical bytes stay durable.
    var crash = durable;
    @memcpy(crash[page_size..], torn[page_size..]);
    try h.mangle("replay_crash", 0, &crash);
    var recovered = try h.writer("replay_crash");
    defer recovered.deinit();
    try testing.expectEqual(@as(u64, synced.len), recovered.size());
    try expect_read(&recovered, 0, &synced);
}

test "recovery truncate at the end preserves the contents" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.recovery("resize_same_size");
    defer w.deinit();
    _ = try w.append("hello world");
    try w.truncate(11);
    try testing.expectEqual(@as(u64, 11), w.size());
    try expect_read(&w, 0, "hello world");
}

test "recovery truncate within a page reopens at the shorter size" {
    var h = try Harness.init();
    defer h.deinit();
    const data = cycle_from(0, 50);
    {
        var w = try h.recovery("same_page_shrink");
        defer w.deinit();
        _ = try w.append(&data);
        try w.sync();
        try w.truncate(45);
    }
    var w = try h.recovery("same_page_shrink");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 45), w.size());
    try expect_read(&w, 0, data[0..45]);
}

test "a torn rewrite after a shrink does not resurrect the old length" {
    var h = try Harness.init();
    defer h.deinit();
    const data = sequence(1, 80);
    {
        var w = try h.recovery("shrink_torn");
        defer w.deinit();
        _ = try w.append(&data);
        try w.sync();
        try w.truncate(50);
    }
    // A rewrite back to 80 bytes torn down to the retired slot's length bytes: the
    // pre-shrink data still on the page must not revalidate.
    var len: [2]u8 = undefined;
    std.mem.writeInt(u16, &len, 80, .big);
    try h.mangle("shrink_torn", page_size, &len);
    var w = try h.recovery("shrink_torn");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 50), w.size());
    try expect_read(&w, 0, data[0..50]);
}

test "recovery open keeps a valid prefix checksum without writing" {
    var h = try Harness.init();
    defer h.deinit();
    const data = sequence(1, 80);
    {
        var w = try h.recovery("prefix_checksum");
        defer w.deinit();
        _ = try w.append(data[0..50]);
        try w.sync();
        _ = try w.append(data[50..]);
        try w.sync();
    }
    const writes = h.storage.writes;
    var w = try h.recovery("prefix_checksum");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 80), w.size());
    try testing.expectEqual(writes, h.storage.writes);
}

test "recovery appends to a partial tail and truncates it" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var cache_ref = try CacheRef.init(gpa, 64, 4);
    defer cache_ref.deinit();
    for (0..2) |round| {
        const opened = try storage.open(partition, "partial_tail_test");
        var w = W.open_recovery(gpa, opened.blob, opened.len, 256, &cache_ref) catch |err| {
            opened.blob.close();
            return err;
        };
        defer w.deinit();
        if (round == 0) {
            _ = try w.append(&.{ 1, 2, 3, 4, 5 });
            try w.sync();
            try testing.expectEqual(@as(u64, 5), w.size());
            continue;
        }
        try testing.expectEqual(@as(u64, 5), w.size());
        _ = try w.append(&.{ 6, 7, 8 });
        try w.truncate(6);
        try w.sync();
        try expect_read(&w, 0, &.{ 1, 2, 3, 4, 5, 6 });
    }
}

/// commonware's `PartialWriteBlob`: write number `fail_on` (from 1) lands only its first
/// `partial_len` bytes durably, then fails.
const PartialWriteBlob = struct {
    inner: Blob,
    fail_on: u64,
    partial_len: usize,
    writes: u64 = 0,
    failed_write_len: usize = 0,

    const vtable: Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize,
        .sync = sync,
        .close = close,
    };

    fn blob(self: *PartialWriteBlob) Blob {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn from(ptr: *anyopaque) *PartialWriteBlob {
        return @ptrCast(@alignCast(ptr));
    }

    fn read_at(ptr: *anyopaque, offset: u64, buf: []u8, options: ReadOptions) Error!void {
        return from(ptr).inner.read_at_options(offset, buf, options);
    }

    fn write_at(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: WriteOptions,
    ) Error!void {
        const self = from(ptr);
        self.writes += 1;
        if (self.writes != self.fail_on) {
            return self.inner.write_at_vectored(offset, chunks, options);
        }
        var len: usize = 0;
        for (chunks) |chunk| len += chunk.len;
        self.failed_write_len = len;
        assert(self.partial_len < len);
        // Land the first `partial_len` bytes durably, chunk by chunk.
        var written: usize = 0;
        for (chunks) |chunk| {
            const count = @min(chunk.len, self.partial_len - written);
            if (count == 0) break;
            try self.inner.write_at(offset + written, chunk[0..count], options);
            written += count;
        }
        try self.inner.sync();
        return error.Io;
    }

    fn resize(ptr: *anyopaque, length: u64) Error!void {
        return from(ptr).inner.resize(length);
    }

    fn sync(ptr: *anyopaque) Error!void {
        return from(ptr).inner.sync();
    }

    fn close(ptr: *anyopaque) void {
        from(ptr).inner.close();
    }
};

/// A recovery writer over blob `name` whose writes go through `faulty`.
fn faulty_recovery(
    h: *Harness,
    name: []const u8,
    faulty: *PartialWriteBlob,
    capacity: usize,
    cache_ref: *CacheRef,
) !W {
    const opened = try h.storage.open(partition, name);
    faulty.inner = opened.blob;
    errdefer opened.blob.close();
    return W.open_recovery(gpa, faulty.blob(), opened.len, capacity, cache_ref);
}

test "a same-page shrink survives an interrupted checksum stage" {
    var h = try Harness.init();
    defer h.deinit();
    const data = cycle_from(0, 50);
    {
        var w = try h.recovery("same_page_shrink_interrupted");
        defer w.deinit();
        _ = try w.append(data[0..40]);
        try w.sync();
        _ = try w.append(data[40..]);
        try w.sync();
    }
    // Tear the staged shorter checksum before its length can be published.
    var faulty: PartialWriteBlob = .{ .inner = undefined, .fail_on = 1, .partial_len = 3 };
    {
        const name = "same_page_shrink_interrupted";
        var w = try faulty_recovery(&h, name, &faulty, buffer_size, &h.cache_ref);
        defer w.deinit();
        try testing.expectError(error.Io, w.truncate(45));
    }
    try testing.expectEqual(@as(u64, 1), faulty.writes);
    try testing.expectEqual(@as(usize, 6), faulty.failed_write_len);
    // The untouched authoritative slot recovers all 50 durable bytes.
    var w = try h.recovery("same_page_shrink_interrupted");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 50), w.size());
    try expect_read(&w, 0, &data);
}

test "a same-page shrink survives an interrupted length stage" {
    // A length above 255, so a one-byte tear changes the decoded length.
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var cache_ref = try CacheRef.init(gpa, 600, 1200);
    defer cache_ref.deinit();
    var data: [300]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index % 251);
    const name = "same_page_shrink_len_stage";
    {
        const opened = try storage.open(partition, name);
        var w = W.open_recovery(gpa, opened.blob, opened.len, 1200, &cache_ref) catch |err| {
            opened.blob.close();
            return err;
        };
        defer w.deinit();
        _ = try w.append(data[0..255]);
        try w.sync();
        _ = try w.append(data[255..]);
        try w.sync();
    }
    var faulty: PartialWriteBlob = .{ .inner = undefined, .fail_on = 2, .partial_len = 1 };
    {
        const opened = try storage.open(partition, name);
        faulty.inner = opened.blob;
        var w = W.open_recovery(gpa, faulty.blob(), opened.len, 1200, &cache_ref) catch |err| {
            opened.blob.close();
            return err;
        };
        defer w.deinit();
        try testing.expectError(error.Io, w.truncate(257));
    }
    try testing.expectEqual(@as(u64, 2), faulty.writes);
    try testing.expectEqual(@as(usize, 2), faulty.failed_write_len);
    // The torn length leaves the original 300-byte slot authoritative.
    const opened = try storage.open(partition, name);
    var w = W.open_recovery(gpa, opened.blob, opened.len, 1200, &cache_ref) catch |err| {
        opened.blob.close();
        return err;
    };
    defer w.deinit();
    try testing.expectEqual(@as(u64, 300), w.size());
    try expect_read(&w, 0, &data);
}

fn mod_251(comptime len: usize) [len]u8 {
    var bytes: [len]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @intCast(index % 251);
    return bytes;
}

test "recovery truncate of a full page to a partial one reopens at the shorter size" {
    var h = try Harness.init();
    defer h.deinit();
    const target = page_size + 45;
    const data = mod_251(page_size * 2);
    {
        var w = try h.recovery("full_page_to_partial");
        defer w.deinit();
        _ = try w.append(&data);
        try w.sync();
        try w.truncate(target);
    }
    var w = try h.recovery("full_page_to_partial");
    defer w.deinit();
    try testing.expectEqual(@as(u64, target), w.size());
    try expect_read(&w, 0, data[0..target]);
}

test "a full-page-to-partial shrink survives an interrupted checksum stage" {
    var h = try Harness.init();
    defer h.deinit();
    const name = "full_page_to_partial_interrupted";
    const data = mod_251(page_size * 3);
    try h.append_synced(name, &data);
    var faulty: PartialWriteBlob = .{ .inner = undefined, .fail_on = 1, .partial_len = 3 };
    {
        var w = try faulty_recovery(&h, name, &faulty, buffer_size, &h.cache_ref);
        defer w.deinit();
        try testing.expectError(error.Io, w.truncate(page_size + 45));
    }
    try testing.expectEqual(@as(u64, 1), faulty.writes);
    try testing.expectEqual(@as(usize, 6), faulty.failed_write_len);
    // The shrunk page lost both checksums; the pages before it survive.
    var w = try h.recovery(name);
    defer w.deinit();
    try testing.expectEqual(@as(u64, page_size * 2), w.size());
    try expect_read(&w, 0, data[0 .. page_size * 2]);
}

test "a same-page shrink survives an interrupted old-length invalidation" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var cache_ref = try CacheRef.init(gpa, 600, 1200);
    defer cache_ref.deinit();
    const data = mod_251(300);
    const name = "same_page_shrink_interrupted_len_invalidation";
    var faulty: PartialWriteBlob = .{ .inner = undefined, .fail_on = 3, .partial_len = 1 };
    for (0..3) |round| {
        const opened = try storage.open(partition, name);
        const blob = if (round == 1) blk: {
            faulty.inner = opened.blob;
            break :blk faulty.blob();
        } else opened.blob;
        var w = W.open_recovery(gpa, blob, opened.len, 1200, &cache_ref) catch |err| {
            opened.blob.close();
            return err;
        };
        defer w.deinit();
        switch (round) {
            0 => {
                _ = try w.append(data[0..255]);
                try w.sync();
                _ = try w.append(data[255..]);
                try w.sync();
            },
            1 => try testing.expectError(error.Io, w.truncate(40)),
            else => {
                // The shorter checksum was published before the old one's invalidation tore.
                try testing.expectEqual(@as(u64, 40), w.size());
                try expect_read(&w, 0, data[0..40]);
            },
        }
    }
    try testing.expectEqual(@as(u64, 3), faulty.writes);
    try testing.expectEqual(@as(usize, 6), faulty.failed_write_len);
}

test "recovery truncate into a corrupted page fails its checksum" {
    var h = try Harness.init();
    defer h.deinit();
    // 250 bytes: two full pages and a 44-byte partial page.
    var data: [250]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index);
    try h.append_synced("resize_crc_test", &data);
    try h.mangle("resize_crc_test", physical_page_size * 2 - 12, &(@as([12]u8, @splat(0xFF))));
    // Recovery validates only the terminal page; truncating into page 1 finds the damage.
    var w = try h.recovery("resize_crc_test");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 250), w.size());
    try testing.expectError(error.InvalidChecksum, w.truncate(150));
}

test "finishing recovery keeps the retained prefix cached" {
    for ([_]?u64{ null, page_size * 2 + 10, page_size + 10 }) |end| {
        var h = try Harness.init();
        defer h.deinit();
        var w = try h.recovery("recovery-cache");
        defer w.deinit();
        _ = try w.append(&(@as([page_size * 2 + 20]u8, @splat(0xA5))));
        try w.sync();
        var page: [page_size]u8 = undefined;
        try w.read_into(&page, 0);
        if (end) |target| try w.truncate(target);
        w.finish_recovery();
        @memset(&page, 0);
        try testing.expect(w.try_read_sync_into(&page, 0));
        try testing.expectEqualSlices(u8, &(@as([page_size]u8, @splat(0xA5))), &page);
    }
}

test "a direct append after a truncate replaces cached pages" {
    var h = try Harness.init_cache(2);
    defer h.deinit();
    var w = try h.recovery("direct");
    defer w.deinit();
    var model: std.ArrayList(u8) = .empty;
    defer model.deinit(gpa);
    try model.appendSlice(gpa, &mod_251(5 * page_size + 20));
    _ = try w.append(model.items);
    try w.sync();
    h.cache_ref.clear();
    var page: [page_size]u8 = undefined;
    try w.read_into(&page, page_size);
    try w.read_into(&page, 2 * page_size);
    // Shorten into a cached page, then bypass the buffer with a multi-page replacement.
    try w.truncate(page_size + 10);
    model.shrinkRetainingCapacity(page_size + 10);
    const replacement: [3 * page_size + 7]u8 = @splat(0xCC);
    _ = try w.append(&replacement);
    try model.appendSlice(gpa, &replacement);
    // Reads use the replacement bytes, not the discarded cached suffix.
    try expect_read(&w, 2 * page_size, model.items[2 * page_size ..][0..page_size]);
    try expect_read(&w, 0, model.items);
    try w.sync();
    w.finish_recovery();
    // A snapshot keeps its prefix while later appends extend the live writer.
    var snapshot = try w.snapshot();
    defer snapshot.deinit();
    const tail: [page_size - 17]u8 = @splat(0xDD);
    _ = try w.append(&tail);
    try w.sync();
    const read = try gpa.alloc(u8, model.items.len);
    defer gpa.free(read);
    try snapshot.read_at(0, read);
    try testing.expectEqualSlices(u8, model.items, read);
    try model.appendSlice(gpa, &tail);
    try expect_read(&w, 0, model.items);
}

test "recovery truncate replaces a cached tail" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.recovery("truncate");
    defer w.deinit();
    _ = try w.append(&(@as([page_size * 2 + 16]u8, @splat(0xAA))));
    try w.sync();
    var cached: [page_size * 2]u8 = undefined;
    try w.read_into(&cached, 0);
    try testing.expect(w.try_read_sync_into(&cached, 0));
    try testing.expectEqualSlices(u8, &(@as([page_size * 2]u8, @splat(0xAA))), &cached);
    try w.truncate(page_size + 16);
    try w.read_into(cached[0..page_size], 0);
    try w.truncate(page_size + 8);
    try testing.expect(w.try_read_sync_into(cached[0..page_size], 0));
    _ = try w.append(&(@as([page_size - 8]u8, @splat(0xBB))));
    try w.sync();
    // Page 1 is now full, so this read comes from cached bytes rather than the tip.
    var rewritten: [page_size]u8 = undefined;
    try testing.expect(w.try_read_sync_into(&rewritten, page_size));
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xAA))), rewritten[0..8]);
    try testing.expectEqualSlices(u8, &(@as([page_size - 8]u8, @splat(0xBB))), rewritten[8..]);
}

test "a recovery sync keeps a truncate and a later append" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var cache_ref = try CacheRef.init(gpa, 64, 4);
    defer cache_ref.deinit();
    var expected: [175]u8 = undefined;
    for (expected[0..129], 0..) |*byte, index| byte.* = @intCast(index);
    @memset(expected[95..], 7);
    {
        const opened = try storage.open(partition, "compact_recovery");
        var w = W.open_recovery(gpa, opened.blob, opened.len, 256, &cache_ref) catch |err| {
            opened.blob.close();
            return err;
        };
        defer w.deinit();
        var initial: [129]u8 = undefined;
        for (&initial, 0..) |*byte, index| byte.* = @intCast(index);
        _ = try w.append(&initial);
        try w.sync();
        // The earlier partial page is larger than the compacted tail.
        try w.truncate(95);
        _ = try w.append(expected[95..]);
        try w.sync();
    }
    const opened = try storage.open(partition, "compact_recovery");
    var w = W.init(gpa, opened.blob, opened.len, 256, &cache_ref) catch |err| {
        opened.blob.close();
        return err;
    };
    defer w.deinit();
    try testing.expectEqual(@as(u64, expected.len), w.size());
    try expect_read(&w, 0, &expected);
}

// read.rs's replay tests.

test "replay of an empty blob is exhausted" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("test_blob");
    defer w.deinit();
    var replay = try w.replay(buffer_size, .{});
    defer replay.deinit();
    try testing.expectEqual(@as(usize, 0), replay.remaining());
    try testing.expect(try replay.ensure(0));
    try testing.expect(!try replay.ensure(1));
    try testing.expect(replay.is_exhausted());
    try testing.expectEqual(@as(usize, 0), replay.bytes().len);
}

test "replay ensures a partial page and crosses single-page batches" {
    var h = try Harness.init();
    defer h.deinit();
    {
        var w = try h.writer("partial");
        defer w.deinit();
        const data = sequence(1, page_size + 10);
        _ = try w.append(&data);
        try w.sync();
        var replay = try w.replay(buffer_size, .{});
        defer replay.deinit();
        try testing.expect(try replay.ensure(data.len));
        try testing.expectEqual(@as(usize, data.len), replay.remaining());
    }
    var w = try h.writer("cross");
    defer w.deinit();
    const data = cycle_from(0, 400);
    _ = try w.append(&data);
    try w.sync();
    // One physical page per batch: four pages need at least four fills.
    var replay = try w.replay(physical_page_size, .{});
    defer replay.deinit();
    try testing.expect(try replay.ensure(400));
    try testing.expectEqual(@as(usize, 400), replay.remaining());
    try testing.expectEqualSlices(u8, &data, replay.bytes()[0..400]);
}

test "replay seeks forward, back, to the end, and not past it" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("test_blob");
    defer w.deinit();
    const data = cycle_from(0, 300);
    _ = try w.append(&data);
    try w.sync();
    var replay = try w.replay(buffer_size, .{});
    defer replay.deinit();
    try replay.seek_to(150);
    try testing.expect(try replay.ensure(50));
    try testing.expectEqual(data[150], replay.bytes()[0]);
    try replay.seek_to(0);
    try testing.expect(try replay.ensure(1));
    try testing.expectEqual(data[0], replay.bytes()[0]);
    try testing.expectError(error.BlobInsufficientLength, replay.seek_to(data.len + 1));
    for ([_]usize{ 150, data.len, 250, 299 }) |offset| {
        try replay.seek_to(offset);
        const remaining = data.len - offset;
        try testing.expect(!try replay.ensure(remaining + 1));
        try testing.expectEqual(remaining, replay.remaining());
        try testing.expectEqualSlices(u8, data[offset..], replay.bytes()[0..remaining]);
    }
}

fn mod_n(comptime len: usize, comptime n: usize) [len]u8 {
    var bytes: [len]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @intCast(index % n);
    return bytes;
}

test "a large append after a synced partial page reopens at every stage" {
    var h = try Harness.init();
    defer h.deinit();
    const all = mod_n(500, 247);
    {
        var w = try h.writer("owned_partial");
        defer w.deinit();
        _ = try w.append(all[0..50]);
        try w.sync();
        // Bypasses the buffer; unsynced, so a reopen sees only the synced prefix.
        _ = try w.append(all[50..]);
        try testing.expectEqual(@as(u64, 500), w.size());
        try expect_read(&w, 0, &all);
    }
    {
        var w = try h.writer("owned_partial");
        defer w.deinit();
        try testing.expectEqual(@as(u64, 50), w.size());
        try expect_read(&w, 0, all[0..50]);
        _ = try w.append(all[50..]);
        try w.sync();
    }
    var w = try h.writer("owned_partial");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 500), w.size());
    try expect_read(&w, 0, &all);
}

test "a large append after a buffered tip and a small one after a page multiple" {
    var h = try Harness.init();
    defer h.deinit();
    const all = mod_n(430, 239);
    {
        var w = try h.writer("owned_buffered");
        defer w.deinit();
        _ = try w.append(all[0..30]);
        _ = try w.append(all[30..]);
        try expect_read(&w, 0, &all);
        try w.sync();
    }
    const bulk = mod_n(412, 233);
    const small = mod_n(10, 229);
    {
        var w = try h.writer("owned_exact");
        defer w.deinit();
        _ = try w.append(&bulk);
        try testing.expectEqual(@as(u64, 412), w.size());
        _ = try w.append(&small);
        try expect_read(&w, 0, &(bulk ++ small));
        try w.sync();
    }
    var buffered = try h.writer("owned_buffered");
    defer buffered.deinit();
    try expect_read(&buffered, 0, &all);
    var exact = try h.writer("owned_exact");
    defer exact.deinit();
    try testing.expectEqual(@as(u64, 422), exact.size());
}

test "try_append_value respects capacity across a snapshot and recovery" {
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var cache_ref = try CacheRef.init(gpa, 16, 4);
    defer cache_ref.deinit();
    {
        const opened = try storage.open("append_value", "blob");
        var w = W.init(gpa, opened.blob, opened.len, 32, &cache_ref) catch |err| {
            opened.blob.close();
            return err;
        };
        defer w.deinit();
        try testing.expectEqual(@as(?u64, 0), w.try_append_value(u64, 0));
        try testing.expectEqual(@as(?u64, null), w.try_append_value([25]u8, @splat(0)));
        var snapshot = try w.snapshot();
        defer snapshot.deinit();
        for (1..4) |value| {
            const offset = w.try_append_value(u64, value);
            try testing.expectEqual(@as(?u64, value * 8), offset);
        }
        try testing.expectEqual(@as(?u64, null), w.try_append_value(u64, 9));
        try testing.expectEqual(@as(u64, 32), w.size());
        var first: [8]u8 = undefined;
        try snapshot.read_at(0, &first);
        try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, &first, .big));
        var four: [8]u8 = undefined;
        std.mem.writeInt(u64, &four, 4, .big);
        try testing.expectEqual(@as(u64, 32), try w.append(&four));
        try w.sync();
    }
    const opened = try storage.open("append_value", "blob");
    var w = W.init(gpa, opened.blob, opened.len, 32, &cache_ref) catch |err| {
        opened.blob.close();
        return err;
    };
    defer w.deinit();
    try testing.expectEqual(@as(u64, 40), w.size());
    var expected: [40]u8 = undefined;
    for (0..5) |value| std.mem.writeInt(u64, expected[value * 8 ..][0..8], value, .big);
    try expect_read(&w, 0, &expected);
}

test "only the seal's flush writes with the uncached hint" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("uncached");
    errdefer w.deinit();
    try w.sync();
    _ = try w.append("first");
    try w.sync();
    try testing.expectEqual(@as(u64, 0), h.storage.dont_cache_writes);
    _ = try w.append("second");
    const sealing = try w.seal();
    var sealed = sealing.sealed;
    defer sealed.deinit();
    try sealing.completion.wait();
    sealing.completion.release();
    try testing.expectEqual(@as(u64, 1), h.storage.dont_cache_writes);
}

test "a recovery shrink reads the retained page uncached" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.recovery("resize_read_options");
    defer w.deinit();
    _ = try w.append(&(@as([page_size]u8, @splat(7))));
    try w.sync();
    // The shrink keeps the prefix in the in-memory tip.
    const reads = h.storage.reads;
    try w.truncate(50);
    try testing.expectEqual(reads + 1, h.storage.reads);
    try testing.expectEqual(@as(u64, 1), h.storage.dont_cache_reads);
}

test "read_many_into and try_read_sync_into from the tip alone, then the cache" {
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("rmany_tip");
    defer w.deinit();
    var data: [20]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index);
    _ = try w.append(&data);
    var buf: [20]u8 = undefined;
    try testing.expect(w.try_read_sync_into(&buf, 0));
    try testing.expectEqualSlices(u8, &data, &buf);
    const offsets = [_]u64{ 0, 4, 8, 12, 16 };
    try testing.expectEqual(@as(usize, 5), try w.read_many_into(&buf, &offsets, 4));
    try testing.expectEqualSlices(u8, &data, &buf);
    try testing.expectEqual(@as(usize, 1), try w.read_many_into(buf[0..8], &.{0}, 8));
    try testing.expectEqualSlices(u8, data[0..8], buf[0..8]);
    // After a sync the bytes sit in a flushed partial page and its cached copy.
    try w.sync();
    const spaced = [_]u64{ 0, 8, 16 };
    _ = try w.read_many_into(buf[0..12], &spaced, 4);
    for (spaced, 0..) |offset, index| {
        const start: usize = @intCast(offset);
        try testing.expectEqualSlices(u8, data[start..][0..4], buf[index * 4 ..][0..4]);
    }
}

test "a large borrowed append takes the direct path and keeps the partial page buffered" {
    var h = try Harness.init();
    defer h.deinit();
    const all = mod_n(530, 241);
    {
        var w = try h.writer("borrowed_large");
        defer w.deinit();
        _ = try w.append(&all);
        try testing.expectEqual(@as(u64, 530), w.size());
        // 530 = 5 full pages + 15 bytes, and only the 15 stay in the buffer.
        try testing.expectEqual(@as(usize, 15), w.buffer.len);
        try expect_read(&w, 0, &all);
        try w.sync();
    }
    var w = try h.writer("borrowed_large");
    defer w.deinit();
    try testing.expectEqual(@as(u64, 530), w.size());
    try expect_read(&w, 0, &all);
}

test "a torn shrink keeps the fallback slot validated from storage" {
    var h = try Harness.init();
    defer h.deinit();
    const data = cycle_from(0, 52);
    const name = "same_page_shrink_fallback_slot";
    var faulty: PartialWriteBlob = .{ .inner = undefined, .fail_on = 4, .partial_len = 3 };
    {
        var w = try faulty_recovery(&h, name, &faulty, buffer_size, &h.cache_ref);
        defer w.deinit();
        for ([_][2]usize{ .{ 0, 48 }, .{ 48, 50 }, .{ 50, 52 } }, 1..) |range, writes| {
            _ = try w.append(data[range[0]..range[1]]);
            try w.sync();
            try testing.expectEqual(@as(u64, writes), faulty.writes);
        }
        // Corrupt the newer authoritative slot: the older one still covers the target, and
        // the torn shrink must preserve it although the writer's footer no longer matches.
        try faulty.inner.write_at(page_size, &dummy_marker, .{});
        try faulty.inner.sync();
        try testing.expectError(error.Io, w.truncate(45));
    }
    try testing.expectEqual(@as(u64, 4), faulty.writes);
    try testing.expectEqual(@as(usize, 6), faulty.failed_write_len);
    var w = try h.recovery(name);
    defer w.deinit();
    try testing.expectEqual(@as(u64, 50), w.size());
    try expect_read(&w, 0, data[0..50]);
}

/// Reads `rounds` pseudo-random pages of `w`, whose page `p` holds bytes `p`, checking each.
fn read_pages(w: *W, pages: u64, seed: u64, rounds: usize, failures: *std.atomic.Value(u32)) void {
    var prng: std.Random.DefaultPrng = .init(seed);
    var buf: [page_size]u8 = undefined;
    for (0..rounds) |_| {
        const page = prng.random().uintLessThan(u64, pages);
        w.read_into(&buf, page * page_size) catch {
            _ = failures.fetchAdd(1, .monotonic);
            continue;
        };
        for (buf) |byte| {
            if (byte != @as(u8, @intCast(page))) {
                _ = failures.fetchAdd(1, .monotonic);
                break;
            }
        }
    }
}

test "readers of one blob on several threads each fetch their own missed pages" {
    // A one-page cache makes nearly every read miss, so every reader fetches pages from the
    // blob at once. Readers sharing one page buffer overwrite each other's page mid-check.
    var h = try Harness.init_cache(1);
    defer h.deinit();
    const pages = 64;
    var data: [pages * page_size]u8 = undefined;
    for (0..pages) |page| @memset(data[page * page_size ..][0..page_size], @intCast(page));
    var w = try h.writer("concurrent_readers");
    defer w.deinit();
    _ = try w.append(&data);
    try w.sync();
    var failures: std.atomic.Value(u32) = .init(0);
    const rounds = 4_000;
    var threads: [3]std.Thread = undefined;
    for (&threads, 1..) |*thread, seed| {
        thread.* = try std.Thread.spawn(.{}, read_pages, .{ &w, pages, seed, rounds, &failures });
    }
    read_pages(&w, pages, 0, rounds, &failures);
    for (threads) |thread| thread.join();
    try testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
}

test "a cleared cache forces a blob read" {
    // commonware `test_cache_clear_forces_uncached_blob_read`: a miss reads the blob once, a
    // hit reads nothing, and after clear the page is read again. commonware also checks the
    // misses pass DONT_CACHE; zigware's page reads use default options, and its backends
    // ignore the hint (runtime-telemetry.md).
    var h = try Harness.init();
    defer h.deinit();
    const data: [page_size]u8 = @splat(7);
    try h.append_synced("clear", &data);
    var w = try h.writer("clear");
    defer w.deinit();
    h.cache_ref.clear();
    const reads = h.storage.reads;
    try expect_read(&w, 0, &data);
    try testing.expectEqual(reads + 1, h.storage.reads);
    try expect_read(&w, 0, &data);
    try testing.expectEqual(reads + 1, h.storage.reads);
    h.cache_ref.clear();
    try expect_read(&w, 0, &data);
    try testing.expectEqual(reads + 2, h.storage.reads);
}

test "read_many_into: a corrupt page fails and is never cached" {
    // commonware `test_read_after_misses_rejects_corruption`.
    var h = try Harness.init();
    defer h.deinit();
    var data: [page_size * 3]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index / page_size);
    try h.append_synced("corrupt", &data);
    try h.mangle("corrupt", physical_page_size + 1, &.{0xff});
    var w = try h.writer("corrupt");
    defer w.deinit();
    h.cache_ref.clear();
    var buf: [3]u8 = undefined;
    const all = [_]u64{ 0, page_size, 2 * page_size };
    try testing.expectError(error.InvalidChecksum, w.read_many_into(&buf, &all, 1));
    var one: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), h.cache_ref.read_cached(w.id, &one, page_size));
    // The intact pages are served on their own.
    const intact = [_]u64{ 0, 2 * page_size };
    _ = try w.read_many_into(buf[0..2], &intact, 1);
    try testing.expectEqualSlices(u8, &.{ 0, 2 }, buf[0..2]);
}

test "read_many_into: reads each missing page once under eviction" {
    // commonware `test_read_many_into_reads_each_missing_page_once`: a 20-page cache, whose
    // probation queue holds only 2 pages, full of pages 20..40 evicts most of the 10 missing
    // pages before they are served.
    var h = try Harness.init_cache(20);
    defer h.deinit();
    var data: [page_size * 40]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index / page_size);
    try h.append_synced("once", &data);
    var w = try h.writer("once");
    defer w.deinit();
    h.cache_ref.clear();
    var byte: [1]u8 = undefined;
    for (20..40) |page| try w.read_into(&byte, page * page_size);
    var offsets: [10]u64 = undefined;
    for (&offsets, 0..) |*offset, page| offset.* = page * page_size;
    const reads = h.storage.reads;
    var buf: [10]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try w.read_many_into(&buf, &offsets, 1));
    for (buf, 0..) |value, page| try testing.expectEqual(@as(u8, @intCast(page)), value);
    try testing.expectEqual(reads + offsets.len, h.storage.reads);
}

test "read_ranges_into: missed ranges on adjacent pages share one blob read" {
    // Cold ranges on pages 0-1 and page 2 form one run; page 5 starts another, and a range
    // in a cached page needs none. A read per range or per page would take more reads.
    var h = try Harness.init();
    defer h.deinit();
    var w = try h.writer("coalesce");
    defer w.deinit();
    var data: [6 * page_size + 5]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index % 253);
    _ = try w.append(&data);
    try w.sync();
    const ranges = [_]W.Range{
        .{ .offset = 3, .len = 4 },
        .{ .offset = page_size - 2, .len = 5 },
        .{ .offset = 2 * page_size + 1, .len = 2 },
        .{ .offset = 4 * page_size, .len = 3 },
        .{ .offset = 5 * page_size + 7, .len = 6 },
    };
    var expected: [20]u8 = undefined;
    var start: usize = 0;
    for (ranges) |range| {
        const at: usize = @intCast(range.offset);
        @memcpy(expected[start..][0..range.len], data[at..][0..range.len]);
        start += range.len;
    }
    h.cache_ref.clear();
    var one: [1]u8 = undefined;
    try w.read_into(&one, 4 * page_size);
    const reads_before = h.storage.reads;
    var out: [20]u8 = @splat(0xEE);
    try testing.expectEqual(1, try w.read_ranges_into(&out, &ranges));
    try testing.expectEqualSlices(u8, &expected, &out);
    try testing.expectEqual(reads_before + 2, h.storage.reads);
    // The run's pages are cached now.
    try testing.expectEqual(ranges.len, try w.read_ranges_into(&out, &ranges));
    try testing.expectEqual(reads_before + 2, h.storage.reads);
}

/// Tears write number `fail_on`: only its first `durable_payload_len` bytes and its trailing
/// checksum footer reach the blob, durably, and the write fails (commonware
/// `TornExtensionBlob`).
const TornExtension = struct {
    inner: Blob,
    writes: u32 = 0,
    fail_on: u32,
    durable_payload_len: usize,

    fn blob(self: *TornExtension) Blob {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize,
        .sync = sync,
        .close = close,
    };

    fn from(ptr: *anyopaque) *TornExtension {
        return @ptrCast(@alignCast(ptr));
    }

    fn read_at(ptr: *anyopaque, offset: u64, out: []u8, options: ReadOptions) Error!void {
        return from(ptr).inner.read_at_options(offset, out, options);
    }

    fn write_at(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: WriteOptions,
    ) Error!void {
        const self = from(ptr);
        self.writes += 1;
        if (self.writes != self.fail_on) {
            return self.inner.vtable.write_at(self.inner.ptr, offset, chunks, options);
        }
        var bytes: [2 * physical_page_size]u8 = undefined;
        var len: usize = 0;
        for (chunks) |chunk| {
            @memcpy(bytes[len..][0..chunk.len], chunk);
            len += chunk.len;
        }
        assert(len >= paged.checksum_size);
        const footer_start = len - paged.checksum_size;
        assert(self.durable_payload_len <= footer_start);
        try self.inner.write_at(offset, bytes[0..self.durable_payload_len], .{});
        try self.inner.write_at(offset + footer_start, bytes[footer_start..len], .{});
        try self.inner.sync();
        return error.Io;
    }

    fn resize(ptr: *anyopaque, length: u64) Error!void {
        return from(ptr).inner.resize(length);
    }

    fn sync(ptr: *anyopaque) Error!void {
        return from(ptr).inner.sync();
    }

    fn close(ptr: *anyopaque) void {
        from(ptr).inner.close();
    }
};

test "a torn extension with its new footer recovers the previous prefix" {
    // commonware `test_torn_extension_with_new_footer_recovers_previous_prefix`.
    var h = try Harness.init();
    defer h.deinit();
    const opened = try h.storage.open(partition, "torn_extension_footer");
    var torn: TornExtension = .{ .inner = opened.blob, .fail_on = 2, .durable_payload_len = 4 };
    var w = try W.init(gpa, torn.blob(), opened.len, buffer_size, &h.cache_ref);
    _ = try w.append("abc");
    try w.sync();
    try testing.expectEqual(1, torn.writes);
    _ = try w.append("def");
    try testing.expectError(error.Io, w.sync());
    try testing.expectEqual(2, torn.writes);
    var page: [physical_page_size]u8 = undefined;
    try torn.inner.read_at(0, &page);
    try testing.expectEqualSlices(u8, "abcd\x00\x00", page[0..6]);
    const checksum = Checksum.decode(page[page_size..][0..paged.checksum_size]);
    try testing.expectEqual(@as(u16, 3), checksum.len1);
    try testing.expectEqual(@as(u16, 6), checksum.len2);
    w.deinit();

    var cache_ref = try CacheRef.init(gpa, page_size, buffer_size);
    defer cache_ref.deinit();
    const reopened = try h.storage.open(partition, "torn_extension_footer");
    var recovered = try W.init(gpa, reopened.blob, reopened.len, buffer_size, &cache_ref);
    defer recovered.deinit();
    try testing.expectEqual(3, recovered.size());
    // The protected slot proves exactly the previously committed boundary: the torn
    // extension cannot make any later byte part of the recoverable prefix.
    try testing.expectEqual(3, try recovered.recoverable_prefix_len(0));
    try expect_read(&recovered, 0, "abc");
}
