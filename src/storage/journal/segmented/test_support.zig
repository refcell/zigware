//! Shared test drivers for segmented journals (commonware's `segmented::manager::tests`).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const runtime = @import("runtime");
const memory = runtime.buffer.memory;
const paged = runtime.buffer.paged;
const manager_mod = @import("manager.zig");

const Storage = memory.Storage;
const CacheRef = paged.CacheRef;
const gpa = testing.allocator;

/// A section's bound as `(section, logical byte end)`.
pub const Bound = struct { section: u64, end: u64 };

/// Materialize a crash that retains new page bytes but loses their checksum lengths: one
/// acknowledged `page` followed by `suffix_pages` copies whose checksum length slots are zero.
pub fn seed_torn_suffix(
    storage: *Storage,
    partition: []const u8,
    section: u64,
    page: []const u8,
    suffix_pages: usize,
) !void {
    assert(page.len > 0 and page.len <= std.math.maxInt(u16));
    assert(suffix_pages > 0);
    const physical = page.len + paged.checksum_size;
    var cache = try CacheRef.init(gpa, @intCast(page.len), 4);
    defer cache.deinit();
    // Encode the acknowledged page and its suffix the way a writer lays them out.
    var source_partition_buffer: [64]u8 = undefined;
    const source = try std.fmt.bufPrint(&source_partition_buffer, "{s}-source", .{partition});
    const opened = try storage.open(source, "source");
    var writer = try paged.Writer(memory.MemoryBlob).init(
        gpa,
        opened.blob,
        opened.len,
        2 * page.len,
        &cache,
    );
    defer writer.deinit();
    _ = try writer.append(page);
    for (0..suffix_pages) |_| _ = try writer.append(page);
    try writer.sync();
    const image = try gpa.alloc(u8, physical * (suffix_pages + 1));
    defer gpa.free(image);
    try writer.blob.read_at(0, image);
    // Clear the unacknowledged pages' length slots to model torn checksum publication.
    for (1..suffix_pages + 1) |page_index| {
        const footer = page_index * physical + page.len;
        @memset(image[footer..][0..2], 0);
        @memset(image[footer + 6 ..][0..2], 0);
    }
    const target = try storage.open(partition, &manager_mod.section_name(section));
    defer target.blob.deinit();
    try target.blob.write_at(0, image);
    try target.blob.sync();
}

fn expect_seeded(retained: []const u64, section: u64, count: u64) !void {
    try testing.expectEqual(count, retained.len);
    for (retained, 0..) |value, index| try testing.expectEqual(section * 100 + index, value);
}

/// A bounded open stopped before any one of its mutations, followed by a crash, leaves a
/// prefix of the journal that keeps every synced item below the bound, and any later open
/// completes from it.
///
/// `Adapter` drives a segmented journal of u64 items: `item_size`, `open(storage, cache,
/// ?Bound)`, `extend(section, from, to)` (append and sync), `items(section, *list)`,
/// `last_section()`, and `deinit()`.
pub fn check_interrupted_bounded_open(comptime Adapter: type) !void {
    const items: u64 = 16;
    const page_size: u16 = 20;
    const item_size: u64 = Adapter.item_size;
    // Both bounds end inside an item, and the item boundary below each lies inside a page, so
    // reaching either rounds down to an item and rewrites the checksum of the page it ends in.
    const bound = 4 * item_size + 3;
    const larger = 7 * item_size + 3;
    inline for (.{ bound, larger }) |end| {
        const item_end = end - end % item_size;
        comptime assert(item_end != end and item_end % page_size != 0);
    }
    const reopens = [_]?Bound{
        .{ .section = 1, .end = bound },
        .{ .section = 1, .end = larger },
        null,
    };
    // Stop the open before its first mutation, then its second, and so on until one completes.
    var interrupted: u64 = 0;
    while (interrupted < 1024) : (interrupted += 1) {
        var stopped = false;
        for (reopens) |reopen| {
            var storage = Storage.init(gpa);
            defer storage.deinit();
            var cache = try CacheRef.init(gpa, page_size, 4);
            defer cache.deinit();
            var retained: std.ArrayList(u64) = .empty;
            defer retained.deinit(gpa);
            {
                // Sync three sections, then open through the bound and crash.
                var journal = try Adapter.open(&storage, &cache, null);
                defer journal.deinit();
                for (0..3) |section| {
                    try journal.extend(section, section * 100, section * 100 + items);
                }
                for (0..3) |section| {
                    retained.clearRetainingCapacity();
                    try journal.items(section, &retained);
                    try expect_seeded(retained.items, section, items);
                }
                try testing.expectEqual(@as(?u64, 2), journal.last_section());
            }
            storage.allow_mutations(interrupted);
            const first: Bound = .{ .section = 1, .end = bound };
            const completed = if (Adapter.open(&storage, &cache, first)) |opened| blk: {
                var journal = opened;
                journal.deinit();
                break :blk true;
            } else |_| false;
            stopped = storage.mutation_refused;
            storage.mutations_allowed = null;
            try testing.expectEqual(!stopped, completed);
            try check_reopened(Adapter, &storage, &cache, reopen, completed, bound);
        }
        if (!stopped) break;
    }
    // The open removes a section and shortens another, so it can stop in at least two places.
    try testing.expect(interrupted >= 2);
}

fn check_reopened(
    comptime Adapter: type,
    storage: *Storage,
    cache: *CacheRef,
    reopen: ?Bound,
    completed: bool,
    bound: u64,
) !void {
    const items: u64 = 16;
    const item_size: u64 = Adapter.item_size;
    var journal = try Adapter.open(storage, cache, reopen);
    var retained: std.ArrayList(u64) = .empty;
    defer retained.deinit(gpa);
    {
        defer journal.deinit();
        // The section below the bound is intact.
        try journal.items(0, &retained);
        try expect_seeded(retained.items, 0, items);
        // The bound section keeps a prefix of its items: every item below the bound, none
        // above the bound of this open, and none above the first bound once an open completed.
        retained.clearRetainingCapacity();
        try journal.items(1, &retained);
        const len: u64 = retained.items.len;
        var most = if (reopen) |b| b.end / item_size else items;
        if (completed) most = @min(most, bound / item_size);
        try expect_seeded(retained.items, 1, len);
        try testing.expect(bound / item_size <= len and len <= most);
        // Later sections are removed before the bound section is shortened, so a crash leaves a
        // contiguous record: the later section survives only an interrupted open, whole and
        // beside every item of the bound section.
        if (journal.last_section() == 2) {
            try testing.expect(!completed and reopen == null);
            var later: std.ArrayList(u64) = .empty;
            defer later.deinit(gpa);
            try journal.items(2, &later);
            try expect_seeded(later.items, 2, items);
            try testing.expectEqual(items, len);
        } else {
            try testing.expectEqual(@as(?u64, 1), journal.last_section());
        }
        // An append lands at the exact end and survives a restart.
        try journal.extend(1, 999, 1000);
    }
    var restarted = try Adapter.open(storage, cache, null);
    defer restarted.deinit();
    var after: std.ArrayList(u64) = .empty;
    defer after.deinit(gpa);
    try restarted.items(1, &after);
    try testing.expectEqual(retained.items.len + 1, after.items.len);
    try testing.expectEqualSlices(u64, retained.items, after.items[0..retained.items.len]);
    try testing.expectEqual(@as(u64, 999), after.items[retained.items.len]);
}
