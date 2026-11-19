//! commonware's `journal/contiguous/variable.rs` recovery tests of rollovers without a
//! commit, torn interior and rewritten pages, damage below the offsets watermark (adopted or
//! rejected), gaps between data blobs, orphaned newer blobs, and unsynced tails.
//!
//! commonware's `test_sync_data_blob` (await one blob's rollover sync) has no counterpart:
//! zigware's rollover syncs the filled blob before it returns, and `commit` makes later blobs
//! durable without advancing the watermark.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const contiguous = @import("mod.zig");
const variable = @import("variable.zig");
const authenticated = @import("../authenticated.zig");
const manager_mod = @import("../segmented/manager.zig");

const gpa = testing.allocator;
const Bounds = contiguous.Bounds;
const checksum_size = 12;
/// 32-byte items, 33-byte frames.
const Wide = [32]u8;

fn bounds(start: u64, end: u64) Bounds {
    return .{ .start = start, .end = end };
}

const Options = struct {
    items_per_section: u64 = 10,
    page_size: u16 = 1024,
    cache_pages: u32 = 10,
    buffer: usize = 1024,
};

fn Harness(comptime V: type, comptime partition: []const u8) type {
    return struct {
        const Self = @This();
        const Journal = variable.Journal(V);
        const data = partition ++ variable.data_suffix;
        const offsets = partition ++ variable.offsets_suffix;

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
                .compression = null,
                .codec_config = {},
                .cache_ref = &self.cache_ref,
                .write_buffer = self.options.buffer,
                .replay_buffer = self.options.buffer,
            };
        }

        fn iface(self: *Self) runtime.storage.Storage {
            return self.storage.interface();
        }

        fn open(self: *Self) !Journal {
            return Journal.init(gpa, self.iface(), self.cfg());
        }

        fn data_blobs(self: *Self) !usize {
            const indices = try contiguous.blobs.indices(gpa, self.iface(), data);
            defer gpa.free(indices);
            return indices.len;
        }

        fn data_len(self: *Self, index: u64) !u64 {
            const opened = try self.iface().open(data, &manager_mod.section_name(index));
            defer opened.blob.close();
            return opened.len;
        }

        fn resize_data(self: *Self, index: u64, len: u64) !void {
            const opened = try self.iface().open(data, &manager_mod.section_name(index));
            defer opened.blob.close();
            try opened.blob.resize(len);
            try opened.blob.sync();
        }

        fn corrupt_data(self: *Self, index: u64, page: u64) !void {
            const name = manager_mod.section_name(index);
            try paged.corrupt_page(self.iface(), data, &name, page, self.options.page_size);
        }

        /// Durably zero byte `offset` of physical page `page`: one lost byte of a rewrite
        /// (commonware's `tear_page_rewrite`).
        fn tear_rewrite(self: *Self, blobs: []const u8, page: u64, offset: u64) !void {
            const physical = @as(u64, self.options.page_size) + checksum_size;
            const opened = try self.iface().open(blobs, &manager_mod.section_name(0));
            defer opened.blob.close();
            var byte: [1]u8 = undefined;
            try opened.blob.read_at(page * physical + offset, &byte);
            try testing.expect(byte[0] != 0);
            try opened.blob.write_at(page * physical + offset, &.{0}, .{ .sync = true });
        }

        /// Remove the offsets journal and its checkpoint, so recovery rebuilds from data.
        fn remove_offsets(self: *Self) !void {
            try self.iface().remove(offsets ++ "-blobs", null);
            try self.iface().remove(offsets ++ "-metadata", null);
        }
    };
}

/// Append `count` items `position * 100` after the current end.
fn fill(journal: anytype, count: u64) !void {
    for (0..count) |_| {
        const position = journal.size();
        try testing.expectEqual(position, try journal.append(position * 100));
    }
}

fn expect_items(journal: anytype, start: u64, end: u64) !void {
    for (start..end) |i| try testing.expectEqual(i * 100, try journal.read(i));
}

/// How many of `[start, end)` fail to read; the rest must hold `position * 100`.
fn damaged_reads(journal: anytype, start: u64, end: u64) !u64 {
    var damaged: u64 = 0;
    for (start..end) |i| {
        if (journal.read(i)) |item| {
            try testing.expectEqual(i * 100, item);
        } else |_| damaged += 1;
    }
    return damaged;
}

test "variable: recovery preserves rolled predecessors without commit" {
    const H = Harness(u64, "recovery-empty-data-tail");
    var h = try H.init(.{ .items_per_section = 1 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try testing.expectEqual(0, try journal.append(10));
        try journal.sync();
        try testing.expectEqual(1, try journal.append(20));
        try testing.expectEqual(2, try journal.append(30));
    }
    try testing.expectEqual(4, try h.data_blobs());
    for (0..3) |i| try testing.expect(try h.data_len(i) > 0);
    try testing.expectEqual(0, try h.data_len(3));
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 3), journal.get_bounds());
    for (0..3) |i| try testing.expectEqual(10 * (i + 1), try journal.read(i));
    try testing.expectEqual(3, try journal.append(42));
    try testing.expectEqual(42, try journal.read(3));
    journal.deinit();
    // The filled predecessors plus the fresh empty tail.
    try testing.expectEqual(5, try h.data_blobs());
    journal = try h.open();
    try journal.destroy();
}

test "variable: recovery preserves the first rollover without commit" {
    const H = Harness(u64, "recovery-empty-data-no-items");
    var h = try H.init(.{ .items_per_section = 1 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try testing.expectEqual(0, try journal.append(10));
        try testing.expectEqual(1, try journal.append(20));
    }
    try testing.expectEqual(3, try h.data_blobs());
    for (0..2) |i| try testing.expect(try h.data_len(i) > 0);
    try testing.expectEqual(0, try h.data_len(2));
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 2), journal.get_bounds());
    try testing.expectEqual(2, try journal.append(42));
    try testing.expectEqual(42, try journal.read(2));
    try journal.destroy();
}

// Data blob 1 holds 20 nine-byte frames across 3 pages; tearing page 1 keeps page 0's 7
// whole frames after blob 0's 30.
test "variable: recovery truncates a torn interior page in the tail" {
    const H = Harness(u64, "variable-torn-interior-tail");
    var h = try H.init(.{ .items_per_section = 30, .page_size = 64 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try fill(&journal, 50);
        try journal.commit();
    }
    try h.corrupt_data(1, 1);
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 37), journal.get_bounds());
    try expect_items(&journal, 0, 37);
    try testing.expectEqual(37, try journal.append(4242));
    try journal.destroy();
}

const TornRewrite = Harness(Wide, "variable-torn-rewrite");
const torn_options: Options = .{
    .items_per_section = 64,
    .page_size = 100,
    .cache_pages = 3,
    .buffer = 2048,
};

/// Acknowledge 33 items, then make five more durable without advancing the watermark: 33
/// frames leave 89 acknowledged bytes in data page 10, and 33 offsets 64 in offsets page 2.
fn torn_rewrite_seed(h: *TornRewrite) !void {
    var journal = try h.open();
    defer journal.deinit();
    for (0..33) |i| _ = try journal.append(@splat(@intCast(i)));
    try journal.sync();
    for (33..38) |i| _ = try journal.append(@splat(@intCast(i)));
    // commonware's lagged `start_sync` writes both journals' pages without advancing the
    // watermark; committing each journal does the same here.
    try journal.commit();
    try journal.offsets.commit();
}

fn match_all(_: void, _: Wide) bool {
    return true;
}

// Reads before publication go through the page cache, which refuses a short interior page,
// so a bounded open repairs the torn data page first.
test "variable: bounded recovery reads a torn rewrite before publication" {
    var h = try TornRewrite.init(torn_options);
    defer h.deinit();
    try torn_rewrite_seed(&h);
    try h.tear_rewrite(TornRewrite.data, 10, 95);
    var recovery = try variable.Recovery(Wide).open(gpa, h.iface(), h.cfg(), 33);
    try testing.expectEqual(bounds(0, 33), recovery.get_bounds());
    try testing.expectEqual(@as(Wide, @splat(32)), try recovery.read(32));
    try testing.expectEqual(33, try authenticated.last_matching(&recovery, 33, {}, match_all));
    var journal = try recovery.publish(33);
    try testing.expectEqual(bounds(0, 33), journal.get_bounds());
    try testing.expectEqual(@as(Wide, @splat(32)), try journal.read(32));
    try journal.destroy();
}

// The offsets journal's bounded open truncates its torn page even though the page's durable
// prefix reaches the cap, so the acknowledged-floor check can read the last offset.
test "variable: a bounded open repairs torn rewrites in both journals" {
    var h = try TornRewrite.init(torn_options);
    defer h.deinit();
    try torn_rewrite_seed(&h);
    try h.tear_rewrite(TornRewrite.data, 10, 95);
    try h.tear_rewrite(TornRewrite.offsets ++ "-blobs", 2, 70);
    var journal = try TornRewrite.Journal.init_at_most(gpa, h.iface(), h.cfg(), 33);
    try testing.expectEqual(bounds(0, 33), journal.get_bounds());
    for (0..33) |i| try testing.expectEqual(@as(Wide, @splat(@intCast(i))), try journal.read(i));
    try journal.destroy();
}

// The watermark (33) anchors recovery in blob 1, so blob 0 is never re-read: a torn page in
// it is adopted unchanged and surfaces as read errors.
test "variable: recovery adopts a torn page below the watermark" {
    const H = Harness(u64, "variable-torn-below-watermark");
    var h = try H.init(.{ .items_per_section = 30, .page_size = 64 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try fill(&journal, 33);
        try journal.sync();
    }
    try h.corrupt_data(0, 2);
    const len_before = try h.data_len(0);
    var journal = try h.open();
    try testing.expect(try damaged_reads(&journal, 0, 30) > 0);
    try expect_items(&journal, 30, 33);
    journal.deinit();
    try testing.expectEqual(len_before, try h.data_len(0));
}

// Blob 0 cut to two whole physical pages (14 whole frames) below the watermark is adopted.
test "variable: recovery adopts a shortened blob below the watermark" {
    const H = Harness(u64, "variable-short-below-watermark");
    var h = try H.init(.{ .items_per_section = 30, .page_size = 64 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try fill(&journal, 33);
        try journal.sync();
    }
    const physical = 64 + checksum_size;
    try testing.expect(try h.data_len(0) > 2 * physical);
    try h.resize_data(0, 2 * physical);
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(33, journal.size());
    try expect_items(&journal, 0, 14);
    try testing.expect(std.meta.isError(journal.read(20)));
    try expect_items(&journal, 30, 33);
}

// Blob 0 is older than both blobs the interior-hole scan reads; cut to one page (7 frames).
test "variable: recovery adopts a shortened old blob below the watermark" {
    const H = Harness(u64, "variable-short-old-below-watermark");
    var h = try H.init(.{ .items_per_section = 10, .page_size = 64 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try fill(&journal, 25);
        try journal.sync();
    }
    const physical = 64 + checksum_size;
    try testing.expect(try h.data_len(0) > physical);
    try h.resize_data(0, physical);
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(25, journal.size());
    try expect_items(&journal, 0, 7);
    try testing.expect(std.meta.isError(journal.read(8)));
    try expect_items(&journal, 10, 25);
}

// The watermark (20) sits mid-blob 0; a torn page beneath it is rejected without truncating
// the acknowledged prefix, and a retry fails the same way.
test "variable: recovery rejects a torn page below a mid-blob watermark" {
    const H = Harness(u64, "variable-torn-mid-blob-watermark");
    var h = try H.init(.{ .items_per_section = 30, .page_size = 64 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try fill(&journal, 20);
        try journal.sync();
    }
    try h.corrupt_data(0, 1);
    const len_before = try h.data_len(0);
    for (0..2) |_| try testing.expectError(error.Corruption, h.open());
    try testing.expectEqual(len_before, try h.data_len(0));
}

// Blob 1 emptied while blob 2 stays durable above the watermark: recovery rolls back to the
// synced prefix and truncates the orphaned blob.
test "variable: recovery rolls back a durable blob after a gap" {
    const H = Harness(u64, "recovery-rollback-after-gap");
    var h = try H.init(.{});
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try fill(&journal, 10);
        try journal.sync();
        try fill(&journal, 20);
        try journal.commit();
    }
    try h.resize_data(1, 0);
    try testing.expectEqual(4, try h.data_blobs());
    try testing.expect(try h.data_len(0) > 0);
    try testing.expectEqual(0, try h.data_len(1));
    try testing.expect(try h.data_len(2) > 0);
    try testing.expectEqual(0, try h.data_len(3));
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 10), journal.get_bounds());
    try expect_items(&journal, 0, 10);
    try testing.expectError(error.ItemOutOfRange, journal.read(10));
    try testing.expectEqual(2, try h.data_blobs());
    try testing.expectEqual(10, try journal.append(1234));
    try testing.expectEqual(1234, try journal.read(10));
    try journal.destroy();
}

// With the offsets gone, an emptied oldest blob leaves blob 1's items orphaned: recovery
// aligns to an empty journal and truncates the orphan.
test "variable: recovery of an empty oldest blob with an orphaned newer blob" {
    const H = Harness(u64, "recovery-empty-oldest-blob");
    var h = try H.init(.{});
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try fill(&journal, 20);
        try journal.sync();
    }
    try testing.expectEqual(3, try h.data_blobs());
    try testing.expect(try h.data_len(0) > 0);
    try h.resize_data(0, 0);
    try h.remove_offsets();
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 0), journal.get_bounds());
    try testing.expectError(error.ItemOutOfRange, journal.read(0));
    try testing.expectEqual(0, try journal.append(42));
    try testing.expectEqual(42, try journal.read(0));
    try testing.expectEqual(1, try h.data_blobs());
    try journal.destroy();
}

// Blob 0 cut at a clean page boundary holds fewer items than a section: replay from the
// start must stop there instead of reading blob 1's items as later positions.
test "variable: recovery of a clean short oldest blob with an orphaned newer blob" {
    const Narrow = [31]u8;
    const H = Harness(Narrow, "recovery-clean-short-oldest-blob");
    var h = try H.init(.{ .items_per_section = 64 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..128) |i| _ = try journal.append(@splat(@intCast(i)));
        try journal.sync();
    }
    const physical = 1024 + checksum_size;
    const items_in_page = 1024 / 32;
    try testing.expectEqual(3, try h.data_blobs());
    try testing.expect(try h.data_len(0) > physical);
    try h.resize_data(0, physical);
    try h.remove_offsets();
    var journal = try h.open();
    try testing.expectEqual(bounds(0, items_in_page), journal.get_bounds());
    const last: Narrow = @splat(items_in_page - 1);
    try testing.expectEqual(last, try journal.read(items_in_page - 1));
    try testing.expectError(error.ItemOutOfRange, journal.read(items_in_page));
    try testing.expectEqual(1, try h.data_blobs());
    try testing.expectEqual(items_in_page, try journal.append(@splat(42)));
    try testing.expectEqual(@as(Narrow, @splat(42)), try journal.read(items_in_page));
    try journal.destroy();
}

// Rollover made blobs 0 and 1 durable; blob 2's items and the offsets were only buffered.
test "variable: recovery of an unsynced tail keeps the contiguous prefix" {
    const H = Harness(u64, "recovery-partial-sync-loop");
    var h = try H.init(.{});
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try fill(&journal, 25);
    }
    h.storage.crash();
    try testing.expectEqual(3, try h.data_blobs());
    try testing.expect(try h.data_len(0) > 0);
    try testing.expect(try h.data_len(1) > 0);
    try testing.expectEqual(0, try h.data_len(2));
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 20), journal.get_bounds());
    try expect_items(&journal, 0, 20);
    try testing.expectError(error.ItemOutOfRange, journal.read(20));
    try testing.expectEqual(3, try h.data_blobs());
    try testing.expectEqual(20, try journal.append(2000));
    try testing.expectEqual(2000, try journal.read(20));
    try journal.destroy();
}

/// The durable logical bytes of blob 0 of `partition`, even while a handle is open, owned by
/// the caller (commonware's `logical_blob`).
fn blob_bytes(h: *TornRewrite, partition: []const u8) ![]u8 {
    const name = manager_mod.section_name(0);
    const bytes = try h.storage.backend.logical_blob(gpa, partition, &name);
    return bytes.?;
}

// A bounded open whose cap lies in a page below the watermark's page truncates the torn data
// page at once, since the data scan covers the whole blob, but repairs the offsets journal only
// through the cap's page. The torn rewrite of the watermark's offsets page stays for a later
// open, and widening the view recovers every acknowledged item. zigware has no `unbounded()`
// recovery, so the capped recovery is dropped and the journal reopened without a cap.
test "variable: bounded open below a torn watermark page, then widened" {
    var h = try TornRewrite.init(torn_options);
    defer h.deinit();
    try torn_rewrite_seed(&h);
    try h.tear_rewrite(TornRewrite.data, 10, 95);
    try h.tear_rewrite(TornRewrite.offsets ++ "-blobs", 2, 70);
    // Cap 10 ends in offsets page 0, while the watermark's last offset is in page 2.
    {
        var recovery = try variable.Recovery(Wide).open(gpa, h.iface(), h.cfg(), 10);
        defer recovery.deinit();
        try testing.expectEqual(bounds(0, 10), recovery.get_bounds());
        try testing.expectEqual(@as(Wide, @splat(9)), try recovery.read(9));
        // The data blob ends at page 10's 89 durable bytes, while offsets page 2 still
        // validates only its 64 durable bytes with page 3 behind it.
        const physical = 100 + checksum_size;
        const data = try blob_bytes(&h, TornRewrite.data);
        defer gpa.free(data);
        try testing.expectEqual(11 * physical, data.len);
        const offsets = try blob_bytes(&h, TornRewrite.offsets ++ "-blobs");
        defer gpa.free(offsets);
        try testing.expect(offsets.len >= 4 * physical);
        try testing.expectEqual(64, paged.page_len(offsets[2 * physical ..][0..physical], 100));
    }
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 33), journal.get_bounds());
    for (0..33) |i| try testing.expectEqual(@as(Wide, @splat(@intCast(i))), try journal.read(i));
    try journal.destroy();
}
