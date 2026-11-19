//! commonware's `journal/contiguous/variable.rs` tests of compressed appends and frames that
//! cross pages, `append_many` past the write buffer, the size limit at the maximum position,
//! and `read_many` and `try_read_many_sync` across cold, warm, and scattered positions.
//!
//! zigware's `read_many` reads item by item (no batched blob read), so commonware's tests of
//! batched-read accounting, probe reuse of offsets, recorded blob reads, and the tampered
//! offsets a batched read must reject have no counterpart. Ownership (`View`) tests, the
//! should-panic ordering tests (assertions here), and snapshot tests are not ported either.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const codec = @import("codec");
const utils = @import("utils");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const contiguous = @import("mod.zig");
const variable = @import("variable.zig");
const frame = @import("../frame.zig");

const gpa = testing.allocator;
const Bounds = contiguous.Bounds;
const max = std.math.maxInt(u64);
const Bytes = []const u8;
const bytes_cfg: codec.Cfg(Bytes) = .{ .range = .full(), .item = {} };
/// 300-byte items, 302-byte frames.
const Wide = [300]u8;

fn bounds(start: u64, end: u64) Bounds {
    return .{ .start = start, .end = end };
}

const Options = struct {
    items_per_section: u64 = 5,
    compression: ?u8 = null,
    page_size: u16 = 512,
    cache_pages: u32 = 10,
    buffer: usize = 1024,
};

fn Harness(comptime V: type, comptime partition: []const u8) type {
    return struct {
        const Self = @This();
        const Journal = variable.Journal(V);

        storage: mocks.Storage,
        cache_ref: paged.CacheRef,
        options: Options,

        fn init(options: Options) !Self {
            return .{
                .storage = mocks.Storage.init(gpa),
                .cache_ref = try paged.CacheRef.init(gpa, options.page_size, options.cache_pages),
                .options = options,
            };
        }

        fn deinit(self: *Self) void {
            self.cache_ref.deinit();
            self.storage.deinit();
        }

        fn cfg(self: *Self) variable.Config(V) {
            return .{
                .partition = partition,
                .items_per_section = self.options.items_per_section,
                .compression = self.options.compression,
                .codec_config = if (V == Bytes) bytes_cfg else {},
                .cache_ref = &self.cache_ref,
                .write_buffer = self.options.buffer,
                .replay_buffer = self.options.buffer,
            };
        }

        fn open(self: *Self) !Journal {
            return Journal.init(gpa, self.storage.interface(), self.cfg());
        }

        /// Reopen with an empty page cache, so sealed pages are cold. Every journal over the
        /// old cache must be closed.
        fn reopen_cold(self: *Self) !Journal {
            self.cache_ref.deinit();
            self.cache_ref = try paged.CacheRef.init(
                gpa,
                self.options.page_size,
                self.options.cache_pages,
            );
            return self.open();
        }
    };
}

fn wide(position: u64) Wide {
    var item: Wide = @splat(@truncate(position));
    std.mem.writeInt(u64, item[0..8], position, .big);
    return item;
}

fn wide_items(comptime count: usize) [count]Wide {
    var items: [count]Wide = undefined;
    for (&items, 0..) |*item, position| item.* = wide(position);
    return items;
}

fn expect_read_many(journal: anytype, positions: []const u64) !void {
    var out: [16]Wide = undefined;
    try journal.read_many(positions, out[0..positions.len]);
    for (positions, out[0..positions.len]) |position, item| {
        try testing.expectEqualSlices(u8, &wide(position), &item);
    }
}

// Compressed batched appends read back in order.
test "variable: append many compressed" {
    const H = Harness([32]u8, "append-many-compressed");
    var h = try H.init(.{ .items_per_section = 3, .compression = 1 });
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    var items: [5][32]u8 = undefined;
    for (&items, 0..) |*item, i| item.* = @splat(@intCast(i));
    try testing.expectEqual(4, try journal.append_many(&items));
    for (items, 0..) |item, position| {
        try testing.expectEqualSlices(u8, &item, &try journal.read(position));
    }
}

// Random items stay larger than a page after compression, so their frames span checksummed
// page boundaries; repeated items compress to a few bytes. Replay, reads, and `read_many`
// after a cold reopen all decode them.
test "variable: compressed frames cross pages" {
    const H = Harness(Bytes, "compressed-cross-pages");
    var h = try H.init(.{ .items_per_section = 3, .compression = 3, .page_size = 1024 });
    defer h.deinit();
    var rng = utils.rng.test_rng();
    var storage: [10][2500]u8 = undefined;
    var items: [10]Bytes = undefined;
    for (&items, &storage, 0..) |*item, *buffer, i| {
        const bytes = buffer[0 .. 1500 + i * 97];
        if (i % 3 == 2) @memset(bytes, @intCast(i)) else rng.fill_bytes(bytes);
        item.* = bytes;
    }
    {
        var journal = try h.open();
        defer journal.deinit();
        for (items) |item| _ = try journal.append(item);
        try journal.sync();
    }
    var journal = try h.reopen_cold();
    defer journal.deinit();
    var replay = try journal.replay(bounds(0, items.len), 64);
    var next: u64 = 0;
    while (try replay.next()) |batch| {
        try testing.expectEqual(next, batch.start);
        for (batch.items, next..) |item, position| {
            try testing.expectEqualSlices(u8, items[position], item);
        }
        next += batch.items.len;
    }
    replay.deinit();
    try testing.expectEqual(items.len, next);
    for (items, 0..) |item, position| {
        const read = try journal.read(position);
        defer codec.free(Bytes, gpa, read);
        try testing.expectEqualSlices(u8, item, read);
    }
    var positions: [10]u64 = undefined;
    for (&positions, 0..) |*position, i| position.* = i;
    var out: [10]Bytes = undefined;
    try journal.read_many(&positions, &out);
    defer for (out) |item| codec.free(Bytes, gpa, item);
    for (items, out) |item, read| try testing.expectEqualSlices(u8, item, read);
}

// One `append_many` larger than the write buffer spans sections and reopens intact.
test "variable: append many exceeding the write buffer reopens across sections" {
    const H = Harness(Wide, "append-many-exceeds-buffer");
    var h = try H.init(.{});
    defer h.deinit();
    const items = wide_items(13);
    {
        var journal = try h.open();
        defer journal.deinit();
        try testing.expectEqual(12, try journal.append_many(&items));
        try journal.sync();
    }
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 13), journal.get_bounds());
    for (items, 0..) |item, position| {
        try testing.expectEqualSlices(u8, &item, &try journal.read(position));
    }
    try expect_read_many(&journal, &.{ 0, 4, 5, 9, 10, 12 });
}

// The append that fills the last representable position succeeds; the next one is a
// recoverable `SizeOverflow`, not a panic. Replay reaches that last position.
test "variable: append and replay at the maximum size" {
    const H = Harness(u64, "append-size-overflow");
    var h = try H.init(.{ .items_per_section = 10 });
    defer h.deinit();
    var journal = try H.Journal.init_at_size(gpa, h.storage.interface(), h.cfg(), max - 1);
    defer journal.deinit();
    try testing.expectEqual(max - 1, try journal.append(7));
    try testing.expectEqual(max, journal.size());
    var replay = try journal.replay(bounds(max - 1, max), 20);
    const batch = (try replay.next()).?;
    try testing.expectEqual(max - 1, batch.start);
    try testing.expectEqualSlices(u64, &.{7}, batch.items);
    try testing.expectEqual(null, try replay.next());
    replay.deinit();
    try testing.expectError(error.SizeOverflow, journal.append(8));
}

// Once `read_many` has warmed both caches, `try_read_many_sync` serves every position with the
// same items; positions out of range are misses that leave valid ones served.
test "variable: try_read_many_sync matches read_many" {
    const H = Harness(Wide, "read-many-sync");
    var h = try H.init(.{});
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    const items = wide_items(13);
    _ = try journal.append_many(&items);
    try journal.sync();
    var positions: [13]u64 = undefined;
    for (&positions, 0..) |*position, i| position.* = i;
    try expect_read_many(&journal, &positions);
    var served: [13]?Wide = undefined;
    journal.try_read_many_sync(&positions, &served);
    for (served, 0..) |item, position| {
        try testing.expectEqualSlices(u8, &wide(position), &item.?);
    }
    const mixed = [_]u64{ 0, 4, 6, 9, 11, 12, 13, max };
    var probed: [mixed.len]?Wide = undefined;
    journal.try_read_many_sync(&mixed, &probed);
    for (mixed, probed) |position, item| {
        if (position < 13) {
            try testing.expectEqualSlices(u8, &wide(position), &item.?);
        } else {
            try testing.expectEqual(null, item);
        }
    }
}

// Completing a probe with one `read_many` over its declined positions matches `read_many`,
// cold and warm.
test "variable: a probe completed by read_many matches read_many" {
    const H = Harness(u64, "read-many-probe-complete");
    var h = try H.init(.{});
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..12) |i| _ = try journal.append(i * 100);
        try journal.sync();
    }
    var journal = try h.reopen_cold();
    defer journal.deinit();
    var positions: [12]u64 = undefined;
    for (&positions, 0..) |*position, i| position.* = i;
    for (0..2) |_| {
        var served: [12]?u64 = undefined;
        journal.try_read_many_sync(&positions, &served);
        var misses: [12]u64 = undefined;
        var count: usize = 0;
        for (positions, served) |position, item| {
            if (item != null) continue;
            misses[count] = position;
            count += 1;
        }
        var fetched: [12]u64 = undefined;
        try journal.read_many(misses[0..count], fetched[0..count]);
        var next: usize = 0;
        for (&served) |*item| {
            if (item.* != null) continue;
            item.* = fetched[next];
            next += 1;
        }
        for (served, 0..) |item, i| try testing.expectEqual(i * 100, item.?);
    }
    var out: [12]u64 = undefined;
    try journal.read_many(&positions, &out);
    for (out, 0..) |item, i| try testing.expectEqual(i * 100, item);
}

// Consecutive positions read after a cold reopen.
test "variable: read_many of consecutive positions after a reopen" {
    const H = Harness(u64, "read-many-consecutive-after-reopen");
    var h = try H.init(.{ .items_per_section = 20 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..20) |i| _ = try journal.append(i * 100);
        try journal.sync();
    }
    var journal = try h.reopen_cold();
    defer journal.deinit();
    var out: [7]u64 = undefined;
    try journal.read_many(&.{ 3, 4, 5, 6, 7, 8, 9 }, &out);
    try testing.expectEqualSlices(u64, &.{ 300, 400, 500, 600, 700, 800, 900 }, &out);
}

// Cache hits interleaved with misses across several blobs land in the right slots, and the
// batch counts every item once as a hit or a miss; a second pass is all hits. zigware reads
// item by item, so a miss can warm a later position (21 after 20) that commonware's batched
// read would still count as a miss.
test "variable: read_many of scattered positions across blobs" {
    const H = Harness(Wide, "read-many-scattered-runs");
    var h = try H.init(.{});
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        const items = wide_items(30);
        for (items) |item| _ = try journal.append(item);
        try journal.sync();
    }
    var journal = try h.reopen_cold();
    defer journal.deinit();
    // Warm blobs 1 and 3 with one read each, which covers their neighbors' pages.
    _ = try journal.read(6);
    _ = try journal.read(16);
    for ([_]u64{ 5, 6, 15, 17 }) |hit| try testing.expect(journal.try_read_sync(hit) != null);
    const misses = [_]u64{ 0, 3, 10, 12, 20, 21, 23 };
    for (misses) |miss| try testing.expectEqual(null, journal.try_read_sync(miss));
    const positions = [_]u64{ 0, 3, 5, 6, 10, 12, 15, 17, 20, 21, 23 };
    const hits = &journal.metrics.cache_hits;
    const missed = &journal.metrics.cache_misses;
    var hits_before = hits.metric().get();
    const misses_before = missed.metric().get();
    try expect_read_many(&journal, &positions);
    const hit_count = hits.metric().get() - hits_before;
    const miss_count = missed.metric().get() - misses_before;
    try testing.expectEqual(positions.len, hit_count + miss_count);
    try testing.expect(hit_count >= 4 and miss_count >= 1 and miss_count <= misses.len);
    hits_before = hits.metric().get();
    try expect_read_many(&journal, &positions);
    try testing.expectEqual(hits_before + positions.len, hits.metric().get());
    try testing.expectEqual(misses_before + miss_count, missed.metric().get());
}

// Adjacent and scattered cold positions, blob-final frames (127, 255), and the journal's
// final frame (257) across three blobs, cold and with one offsets page warm.
test "variable: read_many of cold offsets across blobs" {
    const H = Harness(Wide, "read-many-cold-offsets");
    var h = try H.init(.{ .items_per_section = 128, .cache_pages = 4 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        const items = wide_items(258);
        _ = try journal.append_many(&items);
        try journal.sync();
    }
    var journal = try h.reopen_cold();
    defer journal.deinit();
    const positions = [_]u64{ 0, 1, 3, 62, 63, 64, 65, 126, 127, 128, 129, 255, 256, 257 };
    try expect_read_many(&journal, &positions);
    _ = try journal.read(64);
    try expect_read_many(&journal, &positions);
}

// A blob's last readable frame ends at the blob size: after a reopen capped at four items,
// frame 3 reads back alone and with its predecessor.
test "variable: read_many of a blob's last frame after a capped reopen" {
    const H = Harness(Wide, "read-many-last-frame");
    var h = try H.init(.{ .items_per_section = 128 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        const items = wide_items(6);
        _ = try journal.append_many(&items);
        try journal.sync();
    }
    var journal = try H.Journal.init_at_most(gpa, h.storage.interface(), h.cfg(), 4);
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 4), journal.get_bounds());
    try expect_read_many(&journal, &.{3});
    try expect_read_many(&journal, &.{ 2, 3 });
    try testing.expectError(error.ItemOutOfRange, journal.read(4));
}

// With the offsets partition lost after a prune, the pruned prefix cannot be reconciled.
test "variable: losing the offsets partition after a prune is corruption" {
    const H = Harness(u64, "offsets-loss-after-prune");
    var h = try H.init(.{ .items_per_section = 10 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..40) |i| _ = try journal.append(i * 100);
        _ = try journal.prune(20);
        try testing.expectEqual(bounds(20, 40), journal.get_bounds());
        try journal.sync();
    }
    const offsets = "offsets-loss-after-prune" ++ variable.offsets_suffix;
    try h.storage.interface().remove(offsets ++ "-blobs", null);
    try h.storage.interface().remove(offsets ++ "-metadata", null);
    try testing.expectError(error.Corruption, h.open());
}

// With the data partition lost under intact offsets, init aligns the offsets to the missing
// data: the size survives, every item is pruned, and appends continue at the size.
test "variable: init aligns offsets to a lost data partition" {
    const H = Harness(u64, "data-loss-test");
    var h = try H.init(.{ .items_per_section = 10 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..20) |i| _ = try journal.append(i * 100);
        try journal.sync();
    }
    try h.storage.interface().remove("data-loss-test" ++ variable.data_suffix, null);
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(20, journal.size());
    try testing.expect(journal.get_bounds().is_empty());
    for (0..20) |i| try testing.expectError(error.ItemPruned, journal.read(i));
    try testing.expectEqual(20, try journal.append(999));
    try testing.expectEqual(999, try journal.read(20));
}

// A corrupt page in blob 1 ends a replay over three blobs with an error after blob 0's
// items, and blob 2 is never reached.
test "variable: replay stops at a corrupt blob" {
    const H = Harness(u64, "replay-stops-after-error");
    var h = try H.init(.{ .items_per_section = 10, .page_size = 1024 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..30) |i| _ = try journal.append(i * 100);
        try journal.sync();
    }
    {
        const data = "replay-stops-after-error" ++ variable.data_suffix;
        const name = @import("../segmented/manager.zig").section_name(1);
        const opened = try h.storage.interface().open(data, &name);
        defer opened.blob.close();
        try opened.blob.write_at(0, &.{0xFF}, .{});
        try opened.blob.sync();
    }
    var journal = try h.reopen_cold();
    defer journal.deinit();
    var replay = try journal.replay(bounds(0, 30), 1024);
    defer replay.deinit();
    var next: u64 = 0;
    const failed = while (next < 30) {
        const batch = (replay.next() catch break true).?;
        try testing.expectEqual(next, batch.start);
        for (batch.items, next..) |item, position| try testing.expectEqual(position * 100, item);
        next += batch.items.len;
    } else false;
    try testing.expect(failed);
    try testing.expectEqual(10, next);
}

// Every item of a one-item-per-section journal pruned: the size stays, the tail position
// reads as pruned until the next append, and destroy reopens empty for new writes.
test "variable: single item per section prune all, destroy, and reuse" {
    const H = Harness(u64, "single-item-prune-all");
    var h = try H.init(.{ .items_per_section = 1 });
    defer h.deinit();
    var journal = try h.open();
    for (0..5) |i| _ = try journal.append(i * 100);
    try journal.sync();
    try testing.expect(try journal.prune(5));
    try testing.expectEqual(bounds(5, 5), journal.get_bounds());
    try testing.expectError(error.ItemPruned, journal.read(journal.size() - 1));
    try testing.expectEqual(5, try journal.append(500));
    try testing.expectEqual(500, try journal.read(5));
    try journal.destroy();
    journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 0), journal.get_bounds());
    for (0..10) |i| _ = try journal.append((i + 1000) * 1000);
    try journal.sync();
    for (0..10) |i| try testing.expectEqual((i + 1000) * 1000, try journal.read(i));
}

// A backward `clear_to_size` fails before mutating anything: the journal stays usable and
// reopens with its items.
test "variable: clear_to_size rejects a backward size without mutation" {
    const H = Harness(u64, "clear-to-size-backward");
    var h = try H.init(.{});
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..2) |i| _ = try journal.append(100 + i);
        try journal.sync();
        h.storage.allow_mutations(0);
        try testing.expectError(error.ItemOutOfRange, journal.clear_to_size(1));
        try testing.expect(!h.storage.mutation_refused);
        h.storage.mutations_allowed = null;
        try testing.expectEqual(101, try journal.read(1));
    }
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 2), journal.get_bounds());
    try testing.expectEqual(100, try journal.read(0));
    try testing.expectEqual(101, try journal.read(1));
}

// The journal's gauges and call counters after appends, reads, the three syncs, and a prune.
test "variable: journal metrics" {
    const H = Harness(u64, "metrics");
    var h = try H.init(.{ .items_per_section = 2 });
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    _ = try journal.append_many(&.{ 0, 1, 2, 3, 4 });
    _ = try journal.append(5);
    _ = try journal.read(0);
    var two: [2]u64 = undefined;
    try journal.read_many(&.{ 1, 2 }, &two);
    try testing.expectEqual(3, journal.try_read_sync(3).?);
    try journal.commit();
    try journal.sync();
    try journal.start_sync();
    _ = try journal.prune(2);
    const m = &journal.metrics;
    try testing.expectEqual(6, m.size.metric().get());
    try testing.expectEqual(2, m.pruning_boundary.metric().get());
    try testing.expectEqual(4, m.retained.metric().get());
    try testing.expectEqual(2, m.tail_items.metric().get());
    try testing.expectEqual(1, m.append_calls.metric().get());
    try testing.expectEqual(1, m.append_many_calls.metric().get());
    try testing.expectEqual(1, m.read_calls.metric().get());
    try testing.expectEqual(1, m.read_many_calls.metric().get());
    try testing.expectEqual(4, m.items_read.metric().get());
    try testing.expectEqual(1, m.start_sync_calls.metric().get());
    try testing.expectEqual(1, m.commit_calls.metric().get());
    try testing.expectEqual(1, m.sync_calls.metric().get());
    try testing.expectEqual(4, m.cache_hits.metric().get());
    try testing.expectEqual(0, m.cache_misses.metric().get());
}

/// Replay `range` of a journal of `u64` positions with `options` from a cold cache, checking
/// every item, and return how many backing reads it made and how many were `dont_cache`.
fn replay_reads(
    h: anytype,
    journal: anytype,
    range: Bounds,
    buffer: usize,
    options: runtime.storage.ReadOptions,
) !struct { u64, u64 } {
    h.cache_ref.clear();
    var replay = try journal.replay_options(range, buffer, options);
    defer replay.deinit();
    const reads = h.storage.reads;
    const dont_cache = h.storage.dont_cache_reads;
    var next = range.start;
    while (try replay.next()) |batch| {
        try testing.expectEqual(next, batch.start);
        for (batch.items) |item| {
            try testing.expectEqual(next, item);
            next += 1;
        }
    }
    try testing.expectEqual(range.end, next);
    return .{ h.storage.reads - reads, h.storage.dont_cache_reads - dont_cache };
}

// Replay's read options reach sealed history and the writable tip: sealed sections carry the
// caller's options on every read, and a synced tip's full pages arrive in one read carrying
// them. commonware replays a tip holding an unwritten full page through the page cache, which
// faults pages with `dont_cache` whatever the caller passed; zigware replays the tip's flushed
// pages from the blob and its buffered bytes from memory, so the caller's option still holds.
test "variable: replay read options reach history and tip" {
    const Test = Harness(u64, "variable-replay-read-options");
    var h = try Test.init(.{ .items_per_section = 20, .page_size = 40, .cache_pages = 8 });
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    // The tip section's fifteen 9-byte frames fill three full pages and a partial page.
    for (0..35) |item| try testing.expectEqual(item, try journal.append(item));
    try journal.sync();
    const dont_cache: runtime.storage.ReadOptions = .{ .dont_cache = true };
    const history = try replay_reads(&h, &journal, bounds(0, 35), 32, dont_cache);
    try testing.expect(history[0] > 0);
    try testing.expectEqual(history[0], history[1]);
    for ([_]runtime.storage.ReadOptions{ .{}, dont_cache }) |options| {
        const tip = try replay_reads(&h, &journal, bounds(20, 35), 2048, options);
        try testing.expectEqual(1, tip[0]);
        try testing.expectEqual(@intFromBool(options.dont_cache), tip[1]);
        // The first read faults its page into the cache; the second is served from it.
        h.cache_ref.clear();
        const before = h.storage.reads;
        try testing.expectEqual(20, try journal.read(20));
        try testing.expect(h.storage.reads > before);
        const cached = h.storage.reads;
        try testing.expectEqual(20, try journal.read(20));
        try testing.expectEqual(cached, h.storage.reads);
    }
    // A tip with a buffered full page is still replayed with the caller's options.
    for (35..39) |item| try testing.expectEqual(item, try journal.append(item));
    const buffered = try replay_reads(&h, &journal, bounds(20, 39), 2048, .{});
    try testing.expectEqual(0, buffered[1]);
}

// A prepared compressed append encodes exactly the frames `encode_frame_into` would, with
// each item's start recorded: a highly compressible large record, many small random records,
// and small records followed by a large one. commonware's spare-capacity bound has no
// counterpart: zigware's prepared buffers are exact-size owned slices.
test "variable: prepared compressed appends match their frames" {
    const Test = Harness(Bytes, "prepared-compressed-capacity");
    var h = try Test.init(.{ .items_per_section = 1024, .compression = 3, .page_size = 64 });
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    const large = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(large);
    @memset(large, 0xAB);
    const records = try gpa.alloc([64]u8, 4096);
    defer gpa.free(records);
    var prng = std.Random.DefaultPrng.init(0x5eed);
    for (records) |*record| prng.random().bytes(record);
    const small = try gpa.alloc(Bytes, records.len);
    defer gpa.free(small);
    for (small, records) |*item, *record| item.* = record;
    var mixed: [65]Bytes = undefined;
    @memcpy(mixed[0..64], small[0..64]);
    mixed[64] = large;
    for ([_][]const Bytes{ &.{large}, small, &mixed }) |batch| {
        var prepared = try journal.prepare_append(&.{batch});
        defer prepared.deinit(gpa);
        var expected: std.ArrayList(u8) = .empty;
        defer expected.deinit(gpa);
        try testing.expectEqual(batch.len, prepared.starts.len);
        for (batch, prepared.starts) |record, start| {
            try testing.expectEqual(expected.items.len, start);
            _ = try frame.encode_frame_into(Bytes, gpa, 3, record, &expected);
        }
        try testing.expectEqualSlices(u8, expected.items, prepared.encoded);
        try testing.expect(prepared.compressed);
    }
}
