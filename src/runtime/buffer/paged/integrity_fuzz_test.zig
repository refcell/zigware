//! Blob integrity under a bit flip (commonware `runtime/fuzz/fuzz_targets/blob_integrity.rs`):
//! after one bit of a synced paged blob is flipped, a read through `Writer.read_at` or a
//! `Replay` returns the written bytes, or fails only when it touches the corrupted page.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const utils = @import("utils");
const memory = @import("../../storage/memory.zig");
const paged = @import("mod.zig");

const rng = utils.rng;
const FuzzRng = rng.FuzzRng;
const CacheRef = paged.CacheRef;
const Writer = paged.Writer;
const Storage = memory.Storage;

const partition = "test_partition";
const name = "integrity_test";
/// CRC record size.
const crc_size = 12;
/// Buffer capacity of the writer.
const buffer_capacity = 1024;
/// Buffer capacity of a replay.
const reader_buffer_capacity = 256;
/// Read operations after the corruption.
const reads_max = 20;

const Input = struct {
    seed: u64,
    page_size: u16,
    cache_capacity: u32,
    page_count: u8,
    corrupt_offset: u16,
    corrupt_bit: u3,
};

const Read = struct { offset: u64, len: usize, use_replay: bool };

/// The written data, page geometry, and corrupted page shared by every read.
const Case = struct {
    expected: []const u8,
    page_size: u64,
    corrupted_page: u64,

    /// Pages a read spans, widened by the replay's read-ahead as commonware does.
    fn touches_corruption(case: *const Case, read: Read) bool {
        const start_page = read.offset / case.page_size;
        const end_page = (read.offset + read.len + reader_buffer_capacity) / case.page_size;
        return start_page <= case.corrupted_page and case.corrupted_page <= end_page;
    }
};

fn draw_input(r: *FuzzRng) Input {
    return .{
        .seed = r.next_u64(),
        .page_size = rng.range_at_most(r, u16, 1, 255),
        .cache_capacity = rng.range_at_most(r, u32, 1, 10),
        .page_count = rng.range_at_most(r, u8, 1, 10),
        .corrupt_offset = rng.range_at_most(r, u16, 0, std.math.maxInt(u16)),
        .corrupt_bit = rng.range_at_most(r, u3, 0, 7),
    };
}

/// Write the data through a writer, sync, and flip one bit of the raw blob; returns the
/// corrupted physical offset.
fn write_and_corrupt(storage: *Storage, cache: *CacheRef, input: Input, data: []const u8) !u64 {
    {
        const opened = try storage.open(partition, name);
        const gpa = testing.allocator;
        var writer = Writer.init(gpa, opened.blob, 0, buffer_capacity, cache) catch |err| {
            opened.blob.close();
            return err;
        };
        defer writer.deinit();
        try testing.expectEqual(@as(u64, 0), try writer.append(data));
        try writer.sync();
    }
    // Every page is full, so the blob holds exactly page_count physical pages.
    const physical_size = @as(u64, input.page_count) * (input.page_size + crc_size);
    const offset = input.corrupt_offset % physical_size;
    const opened = try storage.open(partition, name);
    defer opened.blob.close();
    try testing.expectEqual(physical_size, opened.len);
    var byte: [1]u8 = undefined;
    try opened.blob.read_at(offset, &byte);
    byte[0] ^= @as(u8, 1) << input.corrupt_bit;
    try opened.blob.write_at(offset, &byte, .{});
    try opened.blob.sync();
    return offset;
}

fn fuzz_integrity(_: void, r: *FuzzRng) !void {
    const gpa = testing.allocator;
    const input = draw_input(r);
    var storage: Storage = .init(gpa);
    defer storage.deinit();
    var cache = try CacheRef.init(gpa, input.page_size, input.cache_capacity);
    defer cache.deinit();

    const data = try gpa.alloc(u8, @as(usize, input.page_count) * input.page_size);
    defer gpa.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(input.seed +% index);
    const corrupt_offset = try write_and_corrupt(&storage, &cache, input, data);
    const case: Case = .{
        .expected = data,
        .page_size = input.page_size,
        .corrupted_page = corrupt_offset / (input.page_size + crc_size),
    };

    const opened = try storage.open(partition, name);
    // Corruption severe enough to fail recovery of the tail page is acceptable.
    var writer = Writer.init(gpa, opened.blob, opened.len, buffer_capacity, &cache) catch {
        opened.blob.close();
        return;
    };
    defer writer.deinit();
    const size = writer.size();
    const reads = rng.range_at_most(r, u8, 0, reads_max);
    for (0..reads) |_| {
        // Offsets reach a little past the data, so some reads are skipped as out of bounds.
        const offset = rng.range_at_most(r, u64, 0, data.len + 16);
        const len = rng.range_at_most(r, usize, 1, 256);
        const use_replay = rng.boolean(r);
        if (offset >= size) continue;
        const read: Read = .{
            .offset = offset,
            .len = @intCast(@min(len, size - offset)),
            .use_replay = use_replay,
        };
        if (read.use_replay) {
            if (!try read_replay(&writer, &case, read)) return;
        } else {
            try read_writer(&writer, &case, read);
        }
    }
}

fn read_writer(writer: *Writer, case: *const Case, read: Read) !void {
    assert(read.len > 0);
    const buf = try testing.allocator.alloc(u8, read.len);
    defer testing.allocator.free(buf);
    writer.read_at(read.offset, buf) catch {
        // A failed read must touch the corrupted page.
        try testing.expect(case.touches_corruption(read));
        return;
    };
    const start: usize = @intCast(read.offset);
    try testing.expectEqualSlices(u8, case.expected[start..][0..read.len], buf);
}

/// Read through a fresh replay; false when the replay could not be created, which ends
/// the input as in commonware (its replay consumes the writer).
fn read_replay(writer: *Writer, case: *const Case, read: Read) !bool {
    assert(read.len > 0);
    var replay = writer.replay(reader_buffer_capacity, .{}) catch return false;
    defer replay.deinit();
    const skip: usize = @intCast(read.offset);
    if (skip > 0) {
        const skipped = replay.ensure(skip) catch {
            try testing.expect(case.touches_corruption(read) or
                read.offset / case.page_size >= case.corrupted_page);
            return true;
        };
        if (!skipped) return true;
        replay.advance(skip);
    }
    const ready = replay.ensure(read.len) catch |err| {
        try testing.expectEqual(error.InvalidChecksum, err);
        try testing.expect(case.touches_corruption(read));
        return true;
    };
    if (!ready) return true;
    const expected = case.expected[skip..][0..read.len];
    try testing.expectEqualSlices(u8, expected, replay.bytes()[0..read.len]);
    replay.advance(read.len);
    return true;
}

test "fuzz paged blob integrity under a bit flip" {
    const quiet = testing.log_level;
    testing.log_level = .err; // Recovery logs a warning when it repairs a torn tail.
    defer testing.log_level = quiet;
    try utils.fuzz.run({}, fuzz_integrity, 0x696e_7465_6772_6974, 300);
}
