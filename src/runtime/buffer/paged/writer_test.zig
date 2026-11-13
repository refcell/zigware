//! Tests for the paged `Writer` and `Replay`, ported from commonware's `paged/writer.rs`
//! (same 103-byte "janky" page size and 206-byte buffer), plus a seeded crash fuzz.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Crc32 = @import("cryptography").crc32.Crc32;
const build_options = @import("build_options");
const mocks = @import("../mocks.zig");
const paged = @import("mod.zig");
const writer_mod = @import("writer.zig");
const CacheRef = paged.CacheRef;
const Checksum = paged.Checksum;

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
        return .{
            .storage = Storage.init(gpa),
            .cache_ref = try CacheRef.init(gpa, page_size, buffer_size),
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
    var replay = try w.replay(1024);
    defer replay.deinit();
    try testing.expectError(error.InvalidChecksum, replay.ensure(1));
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
    var replay = try w.replay(physical_page_size * 2);
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

fn fuzz_run(seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var h = try Harness.init();
    defer h.deinit();
    var model: std.ArrayList(u8) = .empty;
    defer model.deinit(gpa);
    var durable_len: usize = 0;
    var w = try h.writer("fuzz");
    defer w.deinit();
    for (0..64) |_| {
        switch (random.uintLessThan(u8, 6)) {
            0, 1, 2 => {
                const len = random.uintAtMost(usize, @min(400, fuzz_bytes_max - model.items.len));
                const start = model.items.len;
                try model.resize(gpa, start + len);
                random.bytes(model.items[start..]);
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
                const target = random.uintAtMost(usize, model.items.len);
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

test "fuzz paged writer crashes (seeded)" {
    const base: u64 = 0x7061676564 ^ build_options.fuzz_seed;
    for (0..32 * build_options.fuzz_soak) |iteration| {
        fuzz_run(base +% iteration) catch |err| {
            std.debug.print("fuzz failure: seed={d}\n", .{base +% iteration});
            return err;
        };
    }
}
