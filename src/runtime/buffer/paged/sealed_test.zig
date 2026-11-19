//! Tests for `Sealed`, `Writer.seal`, and `Writer.snapshot`, ported from commonware's
//! `paged/sealed.rs` (same 103-byte page size and 206-byte buffer).

const std = @import("std");
const testing = std.testing;
const mocks = @import("../mocks.zig");
const paged = @import("mod.zig");
const CacheRef = paged.CacheRef;
const Writer = paged.Writer;
const Sealed = paged.Sealed;
const Range = paged.view.Range;

const gpa = testing.allocator;
const page_size: usize = 103;
const physical_page_size: usize = page_size + 12;
const buffer_size: usize = page_size * 2;
const partition = "test_partition";

const Harness = struct {
    storage: mocks.Storage,
    cache_ref: CacheRef,

    fn init(cache_pages: u32) !Harness {
        return .{
            .storage = mocks.Storage.init(gpa),
            .cache_ref = try CacheRef.init(gpa, page_size, cache_pages),
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn writer(self: *Harness, name: []const u8) !Writer {
        const opened = try self.storage.open(partition, name);
        errdefer opened.blob.close();
        return Writer.init(gpa, opened.blob, opened.len, buffer_size, &self.cache_ref);
    }

    /// Append `data` to a fresh writer on blob `name` and seal it.
    fn sealed(self: *Harness, name: []const u8, data: []const u8) !Sealed {
        var w = try self.writer(name);
        errdefer w.deinit();
        _ = try w.append(data);
        return w.seal();
    }
};

/// commonware's `(0u8..=255).cycle().take(len)`; caller frees.
fn cycle(len: usize) ![]u8 {
    const data = try gpa.alloc(u8, len);
    for (data, 0..) |*byte, index| byte.* = @truncate(index);
    return data;
}

/// Drain `replay` into a new buffer; caller frees.
fn drain(replay: *paged.Replay) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    while (try replay.ensure(1)) {
        const chunk = replay.bytes();
        try out.appendSlice(gpa, chunk);
        replay.advance(chunk.len);
    }
    return out.toOwnedSlice(gpa);
}

test "sealed: seal makes the appended bytes durable" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    var w = try h.writer("sync");
    errdefer w.deinit();
    const data = try cycle(300);
    defer gpa.free(data);
    _ = try w.append(data);
    try testing.expectEqual(@as(?u64, 0), try h.storage.durable_len(partition, "sync"));
    var sealed = try w.seal();
    defer sealed.deinit();
    // 300 bytes are two full pages and a 94-byte partial page.
    const durable = try h.storage.durable_len(partition, "sync");
    try testing.expectEqual(@as(?u64, 3 * physical_page_size), durable);
    try testing.expectEqual(@as(u64, 300), sealed.size);
}

test "sealed: seal succeeds with snapshot readers, which agree with it" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    var w = try h.writer("readers");
    errdefer w.deinit();
    _ = try w.append("hello world");
    var reader = try w.snapshot();
    defer reader.deinit();
    try testing.expectEqual(@as(u64, 11), reader.size);
    var sealed = try w.seal();
    defer sealed.deinit();
    try testing.expectEqual(@as(u64, 11), sealed.size);
    var via_reader: [11]u8 = undefined;
    var via_sealed: [11]u8 = undefined;
    try reader.read_at(0, &via_reader);
    try sealed.read_at(0, &via_sealed);
    try testing.expectEqualStrings("hello world", &via_reader);
    try testing.expectEqualStrings(&via_reader, &via_sealed);
}

test "sealed: a snapshot reads full pages and the partial page after the seal" {
    // A single-page cache forces most full-page reads to miss and hit the blob.
    var h = try Harness.init(1);
    defer h.deinit();
    var w = try h.writer("rdr_pages");
    errdefer w.deinit();
    const total = page_size * 3 + 7;
    const data = try cycle(total);
    defer gpa.free(data);
    _ = try w.append(data);
    var reader = try w.snapshot();
    defer reader.deinit();
    var sealed = try w.seal();
    defer sealed.deinit();
    try testing.expectEqual(@as(u64, total), reader.size);
    const cases = [_]struct { u64, usize }{
        .{ 0, total },
        .{ page_size - 3, 6 },
        .{ page_size * 3, 7 },
    };
    const via_reader = try gpa.alloc(u8, total);
    defer gpa.free(via_reader);
    const via_sealed = try gpa.alloc(u8, total);
    defer gpa.free(via_sealed);
    for (cases) |case| {
        const offset, const len = case;
        try reader.read_at(offset, via_reader[0..len]);
        try sealed.read_at(offset, via_sealed[0..len]);
        const start: usize = @intCast(offset);
        try testing.expectEqualSlices(u8, data[start..][0..len], via_reader[0..len]);
        try testing.expectEqualSlices(u8, via_reader[0..len], via_sealed[0..len]);
    }
}

test "sealed: seal preserves the writer's page-cache id" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    var w = try h.writer("cache_id");
    errdefer w.deinit();
    const id = w.cache_id();
    var sealed = try w.seal();
    defer sealed.deinit();
    try testing.expectEqual(id, sealed.cache_id());
}

test "sealed: sealing an empty blob yields an empty view" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    var sealed = try h.sealed("empty", "");
    defer sealed.deinit();
    try testing.expectEqual(@as(u64, 0), sealed.size);
    var buf: [1]u8 = undefined;
    try testing.expectError(error.BlobInsufficientLength, sealed.read_into(&buf, 0));
}

test "sealed: full pages only, partial only, and a straddle" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    for ([_]usize{ page_size * 2, 51, page_size + 17 }, 0..) |total, index| {
        const name: []const u8 = &.{ 'b', '0' + @as(u8, @intCast(index)) };
        const data = try cycle(total);
        defer gpa.free(data);
        var sealed = try h.sealed(name, data);
        defer sealed.deinit();
        try testing.expectEqual(@as(u64, total), sealed.size);
        const buf = try gpa.alloc(u8, total);
        defer gpa.free(buf);
        try sealed.read_into(buf, 0);
        try testing.expectEqualSlices(u8, data, buf);
    }
    // The straddle: 5 bytes before the partial-page boundary and 10 after, within the
    // partial page, and within the first full page.
    const data = try cycle(page_size + 17);
    defer gpa.free(data);
    var sealed = try h.sealed("straddle", data);
    defer sealed.deinit();
    const cases = [_]struct { usize, usize }{
        .{ page_size - 5, 15 },
        .{ page_size, 10 },
        .{ 0, 20 },
    };
    for (cases) |case| {
        const offset, const len = case;
        var buf: [20]u8 = undefined;
        try sealed.read_into(buf[0..len], offset);
        try testing.expectEqualSlices(u8, data[offset..][0..len], buf[0..len]);
    }
}

test "sealed: read_many_into at cached, straddling, and partial offsets" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    const data = try cycle(page_size + 50);
    defer gpa.free(data);
    var sealed = try h.sealed("rmany", data);
    defer sealed.deinit();
    const offsets = [_]u64{ 0, page_size - 2, page_size + 10 };
    var out: [offsets.len * 4]u8 = undefined;
    _ = try sealed.read_many_into(&out, &offsets, 4);
    for (offsets, 0..) |offset, index| {
        const start: usize = @intCast(offset);
        try testing.expectEqualSlices(u8, data[start..][0..4], out[index * 4 ..][0..4]);
    }
}

test "sealed: try_read_many_sync_into maps cache misses to item indices" {
    // A one-page cache holds exactly the last page touched.
    var h = try Harness.init(1);
    defer h.deinit();
    const data = try cycle(page_size * 2 + 50);
    defer gpa.free(data);
    var sealed = try h.sealed("rmany_sync", data);
    defer sealed.deinit();
    const offsets = [_]u64{
        0,
        page_size - 2,
        page_size + 2,
        page_size * 2 - 2,
        page_size * 2 + 10,
    };
    var page: [page_size]u8 = undefined;
    var out: [offsets.len * 4]u8 = undefined;
    var misses: [offsets.len]usize = undefined;
    const Case = struct { cached: u64, misses: []const usize, served: []const usize };
    const cases = [_]Case{
        .{ .cached = 0, .misses = &.{ 1, 2, 3 }, .served = &.{ 0, 4 } },
        .{ .cached = page_size, .misses = &.{ 0, 1 }, .served = &.{ 2, 3, 4 } },
    };
    for (cases) |case| {
        try sealed.read_at(case.cached, &page);
        const count = sealed.try_read_many_sync_into(&out, &offsets, 4, &misses);
        try testing.expectEqualSlices(usize, case.misses, misses[0..count]);
        for (case.served) |index| {
            const start: usize = @intCast(offsets[index]);
            try testing.expectEqualSlices(u8, data[start..][0..4], out[index * 4 ..][0..4]);
        }
    }
}

test "sealed: try_read_ranges_sync_into maps misses past an empty range" {
    var h = try Harness.init(1);
    defer h.deinit();
    const data = try cycle(page_size * 2 + 50);
    defer gpa.free(data);
    var sealed = try h.sealed("rranges_sync", data);
    defer sealed.deinit();
    // A zero-length range shares its offset with the missed range that follows it.
    const ranges = [_]Range{
        .{ .offset = 0, .len = 3 },
        .{ .offset = page_size + 5, .len = 0 },
        .{ .offset = page_size + 5, .len = 7 },
        .{ .offset = page_size * 2 - 2, .len = 4 },
        .{ .offset = page_size * 2 + 10, .len = 4 },
    };
    var page: [page_size]u8 = undefined;
    var out: [18]u8 = undefined;
    var misses: [ranges.len]usize = undefined;
    const Case = struct { cached: u64, misses: []const usize, served: []const usize };
    const cases = [_]Case{
        .{ .cached = 0, .misses = &.{ 2, 3 }, .served = &.{ 0, 4 } },
        .{ .cached = page_size, .misses = &.{0}, .served = &.{ 1, 2, 3, 4 } },
    };
    for (cases) |case| {
        try sealed.read_at(case.cached, &page);
        const count = sealed.try_read_ranges_sync_into(&out, &ranges, &misses);
        try testing.expectEqualSlices(usize, case.misses, misses[0..count]);
        var start: usize = 0;
        for (ranges, 0..) |range, index| {
            defer start += range.len;
            if (std.mem.indexOfScalar(usize, case.served, index) == null) continue;
            const offset: usize = @intCast(range.offset);
            const expected = data[offset..][0..range.len];
            try testing.expectEqualSlices(u8, expected, out[start..][0..range.len]);
        }
    }
}

test "sealed: read_many_into falls back to blob reads on cache misses" {
    var h = try Harness.init(1);
    defer h.deinit();
    const data = try cycle(page_size * 2);
    defer gpa.free(data);
    var sealed = try h.sealed("rmany_miss", data);
    defer sealed.deinit();
    const offsets = [_]u64{ 0, page_size };
    var out: [8]u8 = undefined;
    _ = try sealed.read_many_into(&out, &offsets, 4);
    try testing.expectEqualSlices(u8, data[0..4], out[0..4]);
    try testing.expectEqualSlices(u8, data[page_size..][0..4], out[4..8]);
}

test "sealed: read_ranges_into counts only wholly cached ranges as served" {
    var h = try Harness.init(1);
    defer h.deinit();
    const data = try cycle(page_size * 3);
    defer gpa.free(data);
    var sealed = try h.sealed("ranges", data);
    defer sealed.deinit();
    // Leave only page 1 cached.
    var one: [1]u8 = undefined;
    try sealed.read_at(page_size, &one);
    // Page 0 misses, page 1 hits, the straddle of pages 1 and 2 misses, and page 2 misses.
    const ranges = [_]Range{
        .{ .offset = 1, .len = 3 },
        .{ .offset = page_size + 1, .len = 5 },
        .{ .offset = 2 * page_size - 1, .len = 4 },
        .{ .offset = 2 * page_size + 4, .len = 7 },
    };
    var out: [19]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try sealed.read_ranges_into(&out, &ranges));
    var start: usize = 0;
    for (ranges) |range| {
        const offset: usize = @intCast(range.offset);
        const expected = data[offset..][0..range.len];
        try testing.expectEqualSlices(u8, expected, out[start..][0..range.len]);
        start += range.len;
    }
}

test "sealed: read_many_into validates offsets before reading" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    var sealed = try h.sealed("rmany_bad", &@as([32]u8, @splat(7)));
    defer sealed.deinit();
    var out: [8]u8 = undefined;
    const overflow = [_]u64{ std.math.maxInt(u64) - 1, 8 };
    try testing.expectError(error.OffsetOverflow, sealed.read_many_into(&out, &overflow, 4));
    const past = [_]u64{ 28, 32 };
    try testing.expectError(error.BlobInsufficientLength, sealed.read_many_into(&out, &past, 4));
}

test "sealed: try_read_sync_into serves the partial page and a cached straddle" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    const total = page_size + 30;
    const data = try cycle(total);
    defer gpa.free(data);
    var sealed = try h.sealed("trs", data);
    defer sealed.deinit();
    var buf: [12]u8 = undefined;
    try testing.expect(sealed.try_read_sync_into(buf[0..10], page_size));
    try testing.expectEqualSlices(u8, data[page_size..][0..10], buf[0..10]);
    // The seal's flush cached page 0, so a straddle stitches it to the partial page.
    try testing.expect(sealed.try_read_sync_into(&buf, page_size - 4));
    try testing.expectEqualSlices(u8, data[page_size - 4 ..][0..12], &buf);
    try testing.expect(!sealed.try_read_sync_into(buf[0..10], total));
    try testing.expect(!sealed.try_read_sync_into(buf[0..10], total - 5));
}

test "sealed: replay streams every logical byte, synced first or not" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    const total = page_size * 2 + 25;
    const data = try cycle(total);
    defer gpa.free(data);
    for ([_]bool{ true, false }) |sync_first| {
        const name: []const u8 = if (sync_first) "replay" else "replay_nosync";
        var w = try h.writer(name);
        errdefer w.deinit();
        _ = try w.append(data);
        if (sync_first) try w.sync();
        var sealed = try w.seal();
        defer sealed.deinit();
        var replay = try sealed.replay(buffer_size, .{});
        defer replay.deinit();
        try testing.expectEqual(@as(u64, total), replay.blob_size());
        const out = try drain(&replay);
        defer gpa.free(out);
        try testing.expectEqualSlices(u8, data, out);
    }
}

test "sealed: a snapshot replay stays frozen after the writer grows" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    var w = try h.writer("snapshot_replay_growth");
    defer w.deinit();
    var original: [page_size + 3]u8 = undefined;
    @memset(original[0..page_size], 0xAA);
    original[page_size..].* = "old".*;
    _ = try w.append(&original);
    try w.sync();
    var snapshot = try w.snapshot();
    defer snapshot.deinit();
    var replay = try snapshot.replay(buffer_size, .{});
    defer replay.deinit();
    try testing.expectEqual(@as(u64, original.len), replay.blob_size());
    _ = try w.append("newtail");
    try w.sync();
    const out = try drain(&replay);
    defer gpa.free(out);
    try testing.expectEqualSlices(u8, &original, out);
    var read: [original.len]u8 = undefined;
    try snapshot.read_at(0, &read);
    try testing.expectEqualSlices(u8, &original, &read);
}

test "sealed: try_snapshot waits for unwritten full pages" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    var w = try h.writer("try_snapshot");
    defer w.deinit();
    _ = try w.append("short");
    var first = (try w.try_snapshot()).?;
    defer first.deinit();
    try testing.expectEqual(@as(u64, 5), first.size);
    // A full buffered page must be written first, which only `snapshot` does.
    const page = try cycle(page_size);
    defer gpa.free(page);
    _ = w.try_append(page).?;
    try testing.expect((try w.try_snapshot()) == null);
    var second = try w.snapshot();
    defer second.deinit();
    try testing.expectEqual(@as(u64, page_size + 5), second.size);
    var third = (try w.try_snapshot()).?;
    defer third.deinit();
    try testing.expectEqual(second.size, third.size);
}

test "sealed: sealing a recovered synced partial page does not rewrite it" {
    var h = try Harness.init(buffer_size);
    defer h.deinit();
    const data = try cycle(page_size - 17);
    defer gpa.free(data);
    {
        var w = try h.writer("recovered");
        defer w.deinit();
        _ = try w.append(data);
        try w.sync();
    }
    const writes = h.storage.writes;
    var recovered = try h.writer("recovered");
    errdefer recovered.deinit();
    try testing.expectEqual(@as(u64, data.len), recovered.size());
    try recovered.sync();
    try testing.expectEqual(writes, h.storage.writes);
    var sealed = try recovered.seal();
    defer sealed.deinit();
    try testing.expectEqual(writes, h.storage.writes);
    const read = try gpa.alloc(u8, data.len);
    defer gpa.free(read);
    try sealed.read_at(0, read);
    try testing.expectEqualSlices(u8, data, read);
}

test "sealed: a dont_cache replay leaves the page cache cold, sealed or snapshot" {
    for ([_]bool{ false, true }) |snapshot| {
        var h = try Harness.init(32);
        defer h.deinit();
        var w = try h.writer("review-cold");
        var w_open = true;
        defer if (w_open) w.deinit();
        const total = page_size * 9 + 25;
        const data = try cycle(total);
        defer gpa.free(data);
        _ = try w.append(data);
        try w.sync();
        var sealed = if (snapshot) (try w.try_snapshot()).? else try w.seal();
        w_open = snapshot;
        defer sealed.deinit();
        h.cache_ref.clear();
        var probe: [page_size]u8 = undefined;
        for (0..9) |page| try testing.expect(!sealed.try_read_sync_into(&probe, page * page_size));
        const reads = h.storage.reads;
        var replay = try sealed.replay(buffer_size, .{ .dont_cache = true });
        defer replay.deinit();
        const out = try drain(&replay);
        defer gpa.free(out);
        try testing.expectEqualSlices(u8, data, out);
        try testing.expectEqual(h.storage.reads - reads, h.storage.dont_cache_reads);
        for (0..9) |page| try testing.expect(!sealed.try_read_sync_into(&probe, page * page_size));
        try sealed.read_at(0, &probe);
        try testing.expect(sealed.try_read_sync_into(&probe, 0));
        try testing.expectEqualSlices(u8, data[0..page_size], &probe);
    }
}
