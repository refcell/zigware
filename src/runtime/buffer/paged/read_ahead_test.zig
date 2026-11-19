//! `Replay`'s read-ahead (commonware `PageReader`'s `MAX_READ_AHEAD` batches in flight) on
//! file storage with `read_ahead`, whose blobs then start reads on other tasks: every replay,
//! seek, and buffer size yields exactly the bytes appended, as the inline path does.

const std = @import("std");
const testing = std.testing;
const paged = @import("mod.zig");
const W = @import("writer.zig").Writer;
const Replay = @import("writer.zig").Replay;
const file_storage = @import("../../production/storage.zig");

const io = testing.io;
const gpa = testing.allocator;
const page_size: u16 = 103;

/// Drains `replay` from its position into `out`, consuming at most `step` bytes at a time.
fn drain(replay: *Replay, out: *std.ArrayList(u8), step: usize) !void {
    // Bounded: every pass consumes at least one byte or ends the replay.
    while (try replay.ensure(1)) {
        const available = replay.bytes();
        const count = @min(step, available.len);
        try out.appendSlice(gpa, available[0..count]);
        replay.advance(count);
    }
}

test "replay with reads in flight yields every byte, across seeks and buffer sizes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.createDirPathOpen(io, "root", .{});
    var storage = try file_storage.Storage.init(io, gpa, root, .{ .read_ahead = true });
    defer storage.deinit();
    var cache_ref = try paged.CacheRef.init(gpa, page_size, 8);
    defer cache_ref.deinit();

    // 97 full pages and a partial one, each byte distinct by position.
    const total: usize = 97 * page_size + 40;
    const expected = try gpa.alloc(u8, total);
    defer gpa.free(expected);
    for (expected, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% index / 251);
    const opened = try storage.storage().open("partition", "blob");
    var writer = try W.init(gpa, opened.blob, opened.len, 4 * page_size, &cache_ref);
    defer writer.deinit();
    _ = try writer.append(expected);
    try writer.sync();

    const physical = page_size + paged.checksum_size;
    for ([_]usize{ 1, 3, 4, 7, 16, 200 }) |buffer_pages| {
        var replay = try writer.replay(buffer_pages * physical, .{});
        defer replay.deinit();
        try testing.expect(replay.slot_count == Replay.read_ahead_max + 1);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try drain(&replay, &out, 37);
        try testing.expectEqualSlices(u8, expected, out.items);

        // Seeks discard the batches in flight: back, forward into a page, to the tail.
        for ([_]usize{ 5 * page_size + 11, 60 * page_size, total - 3, 1 }) |offset| {
            try replay.seek_to(offset);
            try testing.expect(replay.inflight_len == 0);
            out.clearRetainingCapacity();
            try drain(&replay, &out, 64);
            try testing.expectEqualSlices(u8, expected[offset..], out.items);
        }
    }
}

test "replay abandoned with reads in flight frees them" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.createDirPathOpen(io, "root", .{});
    var storage = try file_storage.Storage.init(io, gpa, root, .{ .read_ahead = true });
    defer storage.deinit();
    var cache_ref = try paged.CacheRef.init(gpa, page_size, 8);
    defer cache_ref.deinit();
    const opened = try storage.storage().open("partition", "blob");
    var writer = try W.init(gpa, opened.blob, opened.len, 4 * page_size, &cache_ref);
    defer writer.deinit();
    const bytes: [40 * page_size]u8 = @splat(0x5a);
    _ = try writer.append(&bytes);
    try writer.sync();

    var replay = try writer.replay(8 * (page_size + paged.checksum_size), .{});
    try testing.expect(try replay.ensure(1));
    try testing.expect(replay.inflight_len > 0);
    // The allocator's leak check covers the handles and buffers of the reads in flight.
    replay.deinit();
}

test "file storage reads inline by default" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.createDirPathOpen(io, "root", .{});
    var storage = try file_storage.Storage.init(io, gpa, root, .{});
    defer storage.deinit();
    const opened = try storage.storage().open("partition", "blob");
    defer opened.blob.close();
    try testing.expect(!opened.blob.reads_ahead());
}
