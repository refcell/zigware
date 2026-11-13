//! Tests for the variable segmented journal, ported from commonware's
//! `segmented/variable.rs` (same 1024-byte pages and 10-page cache).
//!
//! Faults that commonware injects through the deterministic runtime (failed resizes and
//! writes) use the storage mock's mutation budget. Tests of dropping an in-flight `next`,
//! read options, and metric encodings have no counterpart.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const variable = @import("variable.zig");
const manager_mod = @import("manager.zig");
const frame = @import("../frame.zig");
const test_support = @import("test_support.zig");

const Storage = mocks.Storage;
const CacheRef = paged.CacheRef;
const gpa = testing.allocator;
const page_size: u16 = 1024;
const page_cache_size: u32 = 10;
const partition = "test-partition";
const Bytes = []const u8;
const bytes_cfg: codec.Cfg(Bytes) = .{ .range = .full(), .item = {} };

const Harness = struct {
    storage: Storage,
    cache_ref: CacheRef,

    fn init() !Harness {
        return init_sized(page_size, page_cache_size);
    }

    fn init_sized(page: u16, pages: u32) !Harness {
        return .{
            .storage = Storage.init(gpa),
            .cache_ref = try CacheRef.init(gpa, page, pages),
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg(self: *Harness, comptime V: type) variable.Config(V) {
        return .{
            .partition = partition,
            .codec_config = default_cfg(V),
            .cache_ref = &self.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
    }

    fn open(self: *Harness, comptime V: type) !variable.Journal(V) {
        return open_cfg(V, self.storage.interface(), self.cfg(V));
    }

    /// Open with `config` and collect every replayed item. Caller frees `items`.
    fn replay(
        self: *Harness,
        comptime V: type,
        config: variable.Config(V),
        items: *std.ArrayList(variable.Journal(V).Recovery.Item),
    ) !variable.Journal(V) {
        var recovery = try variable.Journal(V).init(gpa, self.storage.interface(), config);
        {
            errdefer recovery.deinit();
            while (try recovery.next()) |item| try items.append(gpa, item);
        }
        return recovery.finish();
    }

    /// Sync, close, and reopen through `(section, end)` (commonware `test_reopen_at_most`).
    fn reopen_at_most(
        self: *Harness,
        comptime V: type,
        journal: *variable.Journal(V),
        section: u64,
        end: u64,
    ) !variable.Journal(V) {
        try journal.sync_all();
        journal.deinit();
        const store = self.storage.interface();
        return variable.Journal(V).init_at_most(gpa, store, self.cfg(V), section, end);
    }

    /// Write `bytes` durably at `offset` of the raw blob of `section`.
    fn write_raw(self: *Harness, section: u64, offset: ?u64, bytes: []const u8) !void {
        const opened = try self.storage.open(partition, &manager_mod.section_name(section));
        defer opened.blob.close();
        try opened.blob.write_at(offset orelse opened.len, bytes, .{});
        try opened.blob.sync();
    }

    fn resize_blob(self: *Harness, section: u64, shrink: u64) !void {
        const opened = try self.storage.open(partition, &manager_mod.section_name(section));
        defer opened.blob.close();
        try opened.blob.resize(opened.len - shrink);
        try opened.blob.sync();
    }

    fn blob_len(self: *Harness, section: u64) !u64 {
        const opened = try self.storage.open(partition, &manager_mod.section_name(section));
        defer opened.blob.close();
        return opened.len;
    }
};

fn default_cfg(comptime V: type) codec.Cfg(V) {
    return if (V == Bytes) bytes_cfg else {};
}

fn open_cfg(
    comptime V: type,
    storage: runtime.storage.Storage,
    config: variable.Config(V),
) !variable.Journal(V) {
    var recovery = try variable.Journal(V).init(gpa, storage, config);
    try recovery.drain();
    return recovery.finish();
}

fn Items(comptime V: type) type {
    return std.ArrayList(variable.Journal(V).Recovery.Item);
}

test "append and read" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    _ = try journal.append(1, 10);
    try testing.expectEqual(@as(usize, 1), journal.num_sections());
    try journal.sync(&.{1});
    journal.deinit();
    var items: Items(i32) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(i32, h.cfg(i32), &items);
    defer journal.deinit();
    try testing.expectEqual(@as(usize, 1), items.items.len);
    try testing.expectEqual(@as(u64, 1), items.items[0].section);
    try testing.expectEqual(@as(i32, 10), items.items[0].item);
}

test "multiple appends and reads" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(u32);
    const data = [_]struct { u64, u32 }{ .{ 1, 1 }, .{ 1, 2 }, .{ 2, 3 }, .{ 3, 4 } };
    for (data) |entry| {
        _ = try journal.append(entry[0], entry[1]);
        try journal.sync(&.{entry[0]});
    }
    try testing.expectEqual(@as(usize, 3), journal.num_sections());
    try testing.expectEqual(@as(u64, 4), journal.manager.synced);
    journal.deinit();
    var items: Items(u32) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(u32, h.cfg(u32), &items);
    try testing.expectEqual(data.len, items.items.len);
    for (data, items.items) |entry, item| {
        try testing.expectEqual(entry[0], item.section);
        try testing.expectEqual(entry[1], item.item);
    }
    try journal.destroy();
}

test "get many" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(u64);
    var offsets: [5]u64 = undefined;
    for (&offsets, 0..) |*offset, value| offset.* = (try journal.append(0, value)).offset;
    var items: [3]u64 = undefined;
    try journal.get_many(0, &.{ offsets[0], offsets[2], offsets[4] }, &items);
    try testing.expectEqual([3]u64{ 0, 2, 4 }, items);
    try journal.get_many(99, &.{}, &.{});
    try testing.expectError(error.SectionOutOfRange, journal.get_many(99, &.{0}, items[0..1]));
    const max = std.math.maxInt(u64);
    try testing.expect(std.meta.isError(journal.get_many(0, &.{max}, items[0..1])));
    try journal.destroy();
}

test "prune blobs" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(u64);
    for (1..6) |index| {
        _ = try journal.append(index, index);
        try journal.sync(&.{index});
    }
    _ = try journal.append(2, 99);
    try journal.sync(&.{2});
    try testing.expect(try journal.prune(3));
    try testing.expectEqual(@as(u64, 2), journal.manager.pruned_count);
    // A prune below the floor is a no-op.
    try testing.expect(!try journal.prune(2));
    try testing.expectEqual(@as(u64, 2), journal.manager.pruned_count);
    journal.deinit();

    var items: Items(u64) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(u64, h.cfg(u64), &items);
    try testing.expectEqual(@as(usize, 3), items.items.len);
    for (items.items, [_]u64{ 3, 4, 5 }) |item, section| {
        try testing.expectEqual(section, item.section);
    }
    try testing.expect(try journal.prune(6));
    journal.deinit();
    const names = try h.storage.scan(gpa, partition);
    defer names.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), names.items.len);
}

test "prune guard" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    defer journal.deinit();
    for (1..6) |section| {
        _ = try journal.append(section, @intCast(section));
        try journal.sync(&.{section});
    }
    try testing.expect(try journal.prune(3));
    try testing.expect(journal.pruned(1) and journal.pruned(2) and !journal.pruned(3));
    try testing.expectError(error.AlreadyPrunedToSection, journal.append(1, 100));
    try testing.expectError(error.AlreadyPrunedToSection, journal.append(2, 100));
    try testing.expectError(error.AlreadyPrunedToSection, journal.get(1, 0));
    try testing.expectError(error.AlreadyPrunedToSection, journal.size(1));
    for (3..6) |section| _ = try journal.get(section, 0);
    _ = try journal.size(3);
    try journal.sync(&.{4});
    _ = try journal.append(3, 999);
    try testing.expect(try journal.prune(5));
    try testing.expect(journal.pruned(4) and !journal.pruned(5));
    try testing.expectError(error.AlreadyPrunedToSection, journal.get(3, 0));
    try testing.expectError(error.AlreadyPrunedToSection, journal.get(4, 0));
    _ = try journal.get(5, 0);
    try testing.expectError(error.AlreadyPrunedToSection, journal.sync(&.{4}));
}

test "prune guard resets across restart" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    for (1..6) |section| {
        _ = try journal.append(section, @intCast(section));
        try journal.sync(&.{section});
    }
    _ = try journal.prune(3);
    journal.deinit();
    journal = try h.open(i32);
    defer journal.deinit();
    try testing.expect(!journal.pruned(1) and !journal.pruned(2));
    try testing.expectError(error.SectionOutOfRange, journal.get(1, 0));
    try testing.expectError(error.SectionOutOfRange, journal.get(2, 0));
    for (3..6) |section| _ = try journal.get(section, 0);
}

test "invalid blob name" {
    var h = try Harness.init();
    defer h.deinit();
    const opened = try h.storage.open(partition, "invalid");
    try opened.blob.sync();
    opened.blob.close();
    try testing.expectError(
        error.InvalidBlobName,
        variable.Journal(u64).init(gpa, h.storage.interface(), h.cfg(u64)),
    );
}

/// Replays storage that holds no complete item and expects nothing.
fn expect_no_items(h: *Harness) !void {
    var items: Items(u64) = .empty;
    defer items.deinit(gpa);
    var journal = try h.replay(u64, h.cfg(u64), &items);
    journal.deinit();
    try testing.expectEqual(@as(usize, 0), items.items.len);
}

test "missing size, item, or checksum replays nothing" {
    // A truncated varint, a frame shorter than its length, and frames without paging are all
    // torn: raw bytes lack page checksums, so opening drops them.
    var varint: [5]u8 = undefined;
    var writer = codec.Writer.init(&varint);
    codec.varint.write(u32, std.math.maxInt(u32), &writer);
    const short_item = [_]u8{ 10, 2, 2, 2, 2, 2 };
    const raw_item = [_]u8{9} ++ "Test data".*;
    const mismatch = raw_item ++ [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    for ([_][]const u8{ varint[0..1], &short_item, &raw_item, &mismatch }) |bytes| {
        var h = try Harness.init();
        defer h.deinit();
        try h.write_raw(1, 0, bytes);
        try expect_no_items(&h);
        try testing.expectEqual(@as(u64, 0), try h.blob_len(1));
    }
}

test "replay of empty storage finishes immediately" {
    var h = try Harness.init();
    defer h.deinit();
    var recovery = try variable.Journal(i32).init(gpa, h.storage.interface(), h.cfg(i32));
    var journal = try recovery.finish();
    try journal.destroy();
}

test "finishing a replay before it drains fails" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    _ = try journal.append(1, 7);
    try journal.sync(&.{1});
    journal.deinit();
    var recovery = try variable.Journal(i32).init(gpa, h.storage.interface(), h.cfg(i32));
    try testing.expectError(error.ReplayFailed, recovery.finish());
}

const PageItem = [1021]u8;

/// One 1021-byte item (a 1023-byte frame) followed by two trailing 0xFF bytes in section 1.
fn seed_trailing_bytes(h: *Harness) !void {
    const item: PageItem = @splat(10);
    try testing.expectEqual(@as(usize, page_size - 1), codec.varint.size(u32, item.len) + item.len);
    var journal = try h.open(PageItem);
    defer journal.deinit();
    _ = try journal.append(1, item);
    _ = try (try journal.manager.get(1)).?.append(&.{ 0xFF, 0xFF });
    try journal.sync(&.{1});
}

test "a failed trailing-byte repair fails the replay" {
    var h = try Harness.init();
    defer h.deinit();
    try seed_trailing_bytes(&h);
    var recovery = try variable.Journal(PageItem).init(gpa, h.storage.interface(), h.cfg(PageItem));
    h.storage.allow_mutations(0);
    const first = (try recovery.next()).?;
    try testing.expectEqual(@as(u64, 1), first.section);
    try testing.expectEqual(@as(u64, 0), first.offset);
    try testing.expectEqual(@as(u32, 1021), first.size);
    try testing.expectEqual(@as(PageItem, @splat(10)), first.item);
    try testing.expectError(error.Io, recovery.next());
    try testing.expect(try recovery.next() == null);
    h.storage.mutations_allowed = null;
    try testing.expectError(error.ReplayFailed, recovery.finish());
    // Re-initialization repairs from durable state.
    var items: Items(PageItem) = .empty;
    defer items.deinit(gpa);
    var journal = try h.replay(PageItem, h.cfg(PageItem), &items);
    defer journal.deinit();
    try testing.expectEqual(@as(usize, 1), items.items.len);
    try testing.expectEqual(@as(u64, 1023), try journal.size(1));
}

/// Section 0 holds `u64::MAX`; section 1 holds fifteen 9-byte frames on 64-byte pages with
/// page 1 torn; optionally section 2 holds one item.
fn seed_torn_interior_page(h: *Harness, later_section: bool) !variable.Config(u64) {
    var config = h.cfg(u64);
    config.write_buffer = 256;
    var journal = try open_cfg(u64, h.storage.interface(), config);
    _ = try journal.append(0, std.math.maxInt(u64));
    for (0..15) |value| {
        try testing.expectEqual(value * 9, (try journal.append(1, value)).offset);
    }
    if (later_section) _ = try journal.append(2, 0);
    try journal.sync_all();
    journal.deinit();
    try paged.corrupt_page(h.storage.interface(), partition, &manager_mod.section_name(1), 1, 64);
    return config;
}

test "replay repairs a torn interior page when reached" {
    var h = try Harness.init_sized(64, 4);
    defer h.deinit();
    const config = try seed_torn_interior_page(&h, false);
    const name = manager_mod.section_name(1);
    const original = (try h.storage.durable_len(partition, &name)).?;
    var recovery = try variable.Journal(u64).init(gpa, h.storage.interface(), config);
    // Neither setup nor consuming an earlier section repairs a later one.
    try testing.expectEqual(original, (try h.storage.durable_len(partition, &name)).?);
    const first = (try recovery.next()).?;
    try testing.expectEqual(@as(u64, 0), first.section);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), first.item);
    try testing.expectEqual(original, (try h.storage.durable_len(partition, &name)).?);
    var count: u64 = 0;
    while (try recovery.next()) |item| : (count += 1) {
        try testing.expectEqual(@as(u64, 1), item.section);
        try testing.expectEqual(item.item * 9, item.offset);
        try testing.expectEqual(count, item.item);
    }
    try testing.expectEqual(@as(u64, 7), count);
    var journal = try recovery.finish();
    try testing.expectEqual(@as(u64, 63), try journal.size(1));
    try testing.expectEqual(@as(u64, 63), (try journal.append(1, 7)).offset);
    try journal.destroy();
}

test "replay stops after a failed interior repair" {
    var h = try Harness.init_sized(64, 4);
    defer h.deinit();
    const config = try seed_torn_interior_page(&h, true);
    var recovery = try variable.Journal(u64).init(gpa, h.storage.interface(), config);
    h.storage.allow_mutations(0);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), (try recovery.next()).?.item);
    try testing.expectError(error.Io, recovery.next());
    // The failed repair ends the replay, including the later section.
    try testing.expect(try recovery.next() == null);
    h.storage.mutations_allowed = null;
    try testing.expectError(error.ReplayFailed, recovery.finish());
}

test "replay stops after a failed tail repair" {
    var h = try Harness.init_sized(64, 4);
    defer h.deinit();
    const config = try seed_torn_interior_page(&h, true);
    var recovery = try variable.Journal(u64).init(gpa, h.storage.interface(), config);
    for (0..8) |_| _ = try recovery.next();
    // Section 1's torn page was cut back when its first page batch was read; the tail repair
    // that rewrites the partial page's checksum now fails.
    h.storage.allow_mutations(0);
    try testing.expectError(error.Io, recovery.next());
    h.storage.mutations_allowed = null;
    try testing.expect(try recovery.next() == null);
    try testing.expectError(error.ReplayFailed, recovery.finish());
}

test "truncation recovery" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(u32);
    _ = try journal.append(1, 1);
    for ([_]u32{ 2, 3, 4 }) |value| {
        _ = try journal.append(2, value);
        try journal.sync(&.{2});
    }
    try journal.sync_all();
    journal.deinit();
    // Cutting the end of section 2's only page invalidates it.
    try h.resize_blob(2, 4);
    var items: Items(u32) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(u32, h.cfg(u32), &items);
    journal.deinit();
    try testing.expectEqual(@as(usize, 1), items.items.len);
    try testing.expectEqual(@as(u64, 1), items.items[0].section);
    try testing.expectEqual(@as(u32, 1), items.items[0].item);
    try testing.expectEqual(@as(u64, 0), try h.blob_len(2));

    items.clearRetainingCapacity();
    journal = try h.replay(u32, h.cfg(u32), &items);
    try testing.expectEqual(@as(usize, 1), items.items.len);
    // A new item lands at offset zero of the truncated section.
    _ = try journal.append(2, 5);
    try journal.sync(&.{2});
    try testing.expectEqual(@as(u32, 5), try journal.get(2, 0));
    journal.deinit();

    items.clearRetainingCapacity();
    journal = try h.replay(u32, h.cfg(u32), &items);
    defer journal.deinit();
    try testing.expectEqual(@as(usize, 2), items.items.len);
    try testing.expectEqual(@as(u32, 1), items.items[0].item);
    try testing.expectEqual(@as(u64, 2), items.items[1].section);
    try testing.expectEqual(@as(u32, 5), items.items[1].item);
}

test "extra data after the last page" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    _ = try journal.append(1, 1);
    for ([_]i32{ 2, 3, 4 }) |value| {
        _ = try journal.append(2, value);
        try journal.sync(&.{2});
    }
    try journal.sync_all();
    journal.deinit();
    const zeros: [16]u8 = @splat(0);
    try h.write_raw(2, null, &zeros);
    var items: Items(i32) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(i32, h.cfg(i32), &items);
    defer journal.deinit();
    try testing.expectEqual(@as(usize, 4), items.items.len);
}

test "trailing bytes keep the valid prefix" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    for (0..5) |value| _ = try journal.append(1, @intCast(value));
    try journal.sync(&.{1});
    const valid = try journal.size(1);
    journal.deinit();
    const physical_before = try h.blob_len(1);
    try h.write_raw(1, physical_before, &.{ 0xFF, 0xFF });
    var items: Items(i32) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(i32, h.cfg(i32), &items);
    try testing.expectEqual(@as(usize, 5), items.items.len);
    for (items.items, 0..) |item, value| {
        try testing.expectEqual(@as(i32, @intCast(value)), item.item);
    }
    try testing.expectEqual(valid, try journal.size(1));
    journal.deinit();
    try testing.expect(try h.blob_len(1) >= physical_before);
}

test "truncate and truncate section" {
    var h = try Harness.init();
    defer h.deinit();
    for ([_]bool{ false, true }) |section_only| {
        var journal = try h.open(i32);
        try testing.expectEqual(@as(u64, 0), try journal.size(1));
        _ = try journal.append(1, 42);
        const size = try journal.size(1);
        try testing.expect(size > 0);
        _ = try journal.append(1, 43);
        try testing.expect(try journal.size(1) > size);
        try testing.expectEqual(@as(u64, 0), try journal.size(2));
        _ = try journal.append(2, 44);
        try testing.expect(try journal.size(2) > 0);
        if (section_only) {
            try journal.sync_all();
            try journal.truncate_pending_section(1, 0);
        } else {
            journal = try h.reopen_at_most(i32, &journal, 1, 0);
        }
        try testing.expectEqual(@as(u64, 0), try journal.size(1));
        try testing.expectEqual(section_only, try journal.size(2) > 0);
        try journal.destroy();
    }
}

test "truncate the maximal section" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    const max = std.math.maxInt(u64);
    const offset = (try journal.append(max, 42)).offset;
    const size = try journal.size(max);
    journal = try h.reopen_at_most(i32, &journal, max, size);
    defer journal.deinit();
    try testing.expectEqual(size, try journal.size(max));
    try testing.expectEqual(@as(i32, 42), try journal.get(max, offset));
}

test "small items" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(u8);
    var offsets: [100]u64 = undefined;
    for (&offsets, 0..) |*offset, value| {
        const appended = try journal.append(1, @intCast(value));
        try testing.expectEqual(@as(u32, 1), appended.size);
        offset.* = appended.offset;
    }
    for (offsets, 0..) |offset, value| {
        try testing.expectEqual(@as(u8, @intCast(value)), try journal.get(1, offset));
    }
    try journal.sync_all();
    journal.deinit();
    var items: Items(u8) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(u8, h.cfg(u8), &items);
    defer journal.deinit();
    try testing.expectEqual(offsets.len, items.items.len);
    for (items.items, offsets, 0..) |item, offset, value| {
        try testing.expectEqual(@as(u64, 1), item.section);
        try testing.expectEqual(offset, item.offset);
        try testing.expectEqual(@as(u32, 1), item.size);
        try testing.expectEqual(@as(u8, @intCast(value)), item.item);
    }
}

fn expect_sections(h: *Harness, expected: []const struct { u64, i32 }) !void {
    var items: Items(i32) = .empty;
    defer items.deinit(gpa);
    var journal = try h.replay(i32, h.cfg(i32), &items);
    defer journal.deinit();
    try testing.expectEqual(expected.len, items.items.len);
    for (expected, items.items) |entry, item| {
        try testing.expectEqual(entry[0], item.section);
        try testing.expectEqual(entry[1], item.item);
    }
}

test "truncate many sections" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    for (1..11) |section| _ = try journal.append(section, @intCast(section));
    try journal.sync_all();
    journal = try h.reopen_at_most(i32, &journal, 5, try journal.size(5));
    for (1..6) |section| try testing.expect(try journal.size(section) > 0);
    for (6..11) |section| try testing.expectEqual(@as(u64, 0), try journal.size(section));
    journal.deinit();
    try expect_sections(&h, &.{ .{ 1, 1 }, .{ 2, 2 }, .{ 3, 3 }, .{ 4, 4 }, .{ 5, 5 } });
}

test "truncate within a section" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    var sizes: [5]u64 = undefined;
    for (&sizes, 0..) |*size, value| {
        _ = try journal.append(1, @intCast(value));
        try journal.sync(&.{1});
        size.* = try journal.size(1);
    }
    journal = try h.reopen_at_most(i32, &journal, 1, sizes[2]);
    try testing.expectEqual(sizes[2], try journal.size(1));
    journal.deinit();
    try expect_sections(&h, &.{ .{ 1, 0 }, .{ 1, 1 }, .{ 1, 2 } });
}

test "truncate to a missing or empty target removes newer sections" {
    for ([_]u64{ 3, 1 }) |target| {
        var h = try Harness.init();
        defer h.deinit();
        var journal = try h.open(i32);
        const first: u64 = if (target == 3) 5 else 1;
        for (first..first + 3) |section| _ = try journal.append(section, @intCast(section));
        try journal.sync_all();
        journal = try h.reopen_at_most(i32, &journal, target, 0);
        for (first..first + 3) |section| {
            try testing.expectEqual(@as(u64, 0), try journal.size(section));
        }
        journal.deinit();
        try expect_sections(&h, &.{});
    }
}

test "truncate persists" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    for (1..6) |section| _ = try journal.append(section, @intCast(section));
    try journal.sync_all();
    journal = try h.reopen_at_most(i32, &journal, 2, try journal.size(2));
    try journal.sync_all();
    journal.deinit();
    try expect_sections(&h, &.{ .{ 1, 1 }, .{ 2, 2 } });
}

test "large items spanning pages and taking the direct path" {
    const Large = [2048]u8;
    var h = try Harness.init();
    defer h.deinit();
    var config = h.cfg(Large);
    var first: Large = undefined;
    var second: Large = undefined;
    for (&first, &second, 0..) |*a, *b, index| {
        a.* = @truncate(index);
        b.* = @intCast((index + 7) % 251);
    }
    for ([_]usize{ 4096, 1024 }) |write_buffer| {
        config.write_buffer = write_buffer;
        var journal = try open_cfg(Large, h.storage.interface(), config);
        const a = try journal.append(1, first);
        try testing.expectEqual(@as(u32, 2048), a.size);
        const b = try journal.append(1, second);
        try testing.expectEqual(first, try journal.get(1, a.offset));
        try testing.expectEqual(second, try journal.get(1, b.offset));
        try journal.sync_all();
        journal.deinit();
        var items: Items(Large) = .empty;
        defer items.deinit(gpa);
        journal = try h.replay(Large, config, &items);
        try testing.expectEqual(@as(usize, 2), items.items.len);
        try testing.expectEqual(a.offset, items.items[0].offset);
        try testing.expectEqual(first, items.items[0].item);
        try testing.expectEqual(b.offset, items.items[1].offset);
        try testing.expectEqual(second, items.items[1].item);
        try testing.expectEqual(first, try journal.get(1, a.offset));
        try journal.destroy();
    }
}

test "item exactly one page" {
    const Exact = [page_size]u8;
    var h = try Harness.init();
    defer h.deinit();
    var config = h.cfg(Exact);
    config.write_buffer = 4096;
    var data: Exact = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index);
    var journal = try open_cfg(Exact, h.storage.interface(), config);
    const appended = try journal.append(1, data);
    try testing.expectEqual(@as(u32, page_size), appended.size);
    try testing.expectEqual(data, try journal.get(1, appended.offset));
    try journal.sync_all();
    journal.deinit();
    var items: Items(Exact) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(Exact, config, &items);
    try testing.expectEqual(@as(usize, 1), items.items.len);
    try testing.expectEqual(data, items.items[0].item);
    try journal.destroy();
}

test "uncompressed frames fill the write buffer" {
    var h = try Harness.init();
    defer h.deinit();
    var config = h.cfg(Bytes);
    config.write_buffer = 2048;
    const direct: [126]u8 = @splat(7);
    const fallback: [127]u8 = @splat(9);
    var journal = try open_cfg(Bytes, h.storage.interface(), config);
    for (0..16) |index| {
        const appended = try journal.append(1, &direct);
        try testing.expectEqual(index * 128, appended.offset);
        try testing.expectEqual(@as(u32, 127), appended.size);
    }
    const last = try journal.append(1, &fallback);
    try testing.expectEqual(@as(u64, 2048), last.offset);
    try testing.expectEqual(@as(u32, 128), last.size);
    try journal.sync(&.{1});
    journal.deinit();

    var recovery = try variable.Journal(Bytes).init(gpa, h.storage.interface(), config);
    for (0..17) |index| {
        const item = (try recovery.next()).?;
        defer gpa.free(item.item);
        const expected: []const u8 = if (index < 16) &direct else &fallback;
        try testing.expectEqual(index * 128, item.offset);
        try testing.expectEqualSlices(u8, expected, item.item);
    }
    try testing.expect(try recovery.next() == null);
    journal = try recovery.finish();
    const read = try journal.get(1, last.offset);
    defer gpa.free(read);
    try testing.expectEqualSlices(u8, &fallback, read);
    try journal.destroy();
}

test "varint spanning a page boundary" {
    const Item = [128]u8;
    var h = try Harness.init_sized(16, page_cache_size);
    defer h.deinit();
    var config = h.cfg(Item);
    config.replay_buffer = 64;
    var journal = try open_cfg(Item, h.storage.interface(), config);
    var offsets: [3]u64 = undefined;
    for (&offsets, 1..) |*offset, fill| {
        offset.* = (try journal.append(1, @splat(@intCast(fill)))).offset;
    }
    for (offsets, 1..) |offset, fill| {
        try testing.expectEqual(@as(Item, @splat(@intCast(fill))), try journal.get(1, offset));
    }
    try journal.sync_all();
    journal.deinit();
    var items: Items(Item) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(Item, config, &items);
    try testing.expectEqual(@as(usize, 3), items.items.len);
    for (items.items, offsets, 1..) |item, offset, fill| {
        try testing.expectEqual(offset, item.offset);
        try testing.expectEqual(@as(Item, @splat(@intCast(fill))), item.item);
    }
    try journal.destroy();
}

test "non-contiguous and empty middle sections" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(i32);
    const data = [_]struct { u64, i32 }{ .{ 1, 100 }, .{ 5, 500 }, .{ 10, 1000 } };
    var offsets: [3]u64 = undefined;
    for (data, &offsets) |entry, *offset| {
        offset.* = (try journal.append(entry[0], entry[1])).offset;
    }
    for (data, offsets) |entry, offset| {
        try testing.expectEqual(entry[1], try journal.get(entry[0], offset));
    }
    for ([_]u64{ 0, 2, 3, 4, 6, 7, 8, 9, 11 }) |missing| {
        try testing.expectError(error.SectionOutOfRange, journal.get(missing, 0));
    }
    // Empty section 5 durably.
    try journal.sync_all();
    try journal.truncate_pending_section(5, 0);
    try testing.expectEqual(@as(u64, 0), try journal.size(5));
    journal.deinit();
    try expect_sections(&h, &.{ .{ 1, 100 }, .{ 10, 1000 } });
}

test "clear" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open(u64);
    for (0..5) |section| {
        for (0..10) |index| _ = try journal.append(section, section * 1000 + index);
        try journal.sync(&.{section});
    }
    try testing.expectEqual(@as(u64, 0), try journal.get(0, 0));
    try testing.expectEqual(@as(u64, 4000), try journal.get(4, 0));
    try journal.clear();
    for (0..5) |section| try testing.expectError(error.SectionOutOfRange, journal.get(section, 0));
    for (0..5) |index| _ = try journal.append(10, index * 100);
    try journal.sync(&.{10});
    try testing.expectEqual(@as(u64, 0), try journal.get(10, 0));
    try testing.expectError(error.SectionOutOfRange, journal.get(0, 0));
    try journal.destroy();
}

test "try get sync, plain and compressed" {
    for ([_]?u8{ null, 3 }) |compression| {
        var h = try Harness.init();
        defer h.deinit();
        var config = h.cfg(Bytes);
        config.compression = compression;
        var journal = try open_cfg(Bytes, h.storage.interface(), config);
        const short: [3]u8 = @splat(1);
        const long: [32]u8 = @splat(7);
        const short_offset = (try journal.append(1, &short)).offset;
        const long_offset = (try journal.append(1, &long)).offset;
        const Entry = struct { u64, []const u8 };
        for ([_]Entry{ .{ short_offset, &short }, .{ long_offset, &long } }) |entry| {
            const read = journal.try_get_sync(1, entry[0]).?;
            defer gpa.free(read);
            try testing.expectEqualSlices(u8, entry[1], read);
        }
        try testing.expect(journal.try_get_sync(1, try journal.size(1)) == null);
        try journal.destroy();
    }
}

test "compressed items round trip through replay" {
    var h = try Harness.init();
    defer h.deinit();
    var config = h.cfg(Bytes);
    config.compression = 3;
    var journal = try open_cfg(Bytes, h.storage.interface(), config);
    const item: [600]u8 = @splat(42);
    const appended = try journal.append(1, &item);
    try journal.sync_all();
    journal.deinit();
    var recovery = try variable.Journal(Bytes).init(gpa, h.storage.interface(), config);
    const replayed = (try recovery.next()).?;
    defer gpa.free(replayed.item);
    try testing.expectEqual(appended.size, replayed.size);
    try testing.expectEqualSlices(u8, &item, replayed.item);
    try testing.expect(try recovery.next() == null);
    journal = try recovery.finish();
    try journal.destroy();
}

// Bounded initialization.

/// Drives a `u64` journal through `test_support.check_interrupted_bounded_open`.
const BoundedOpen = struct {
    journal: variable.Journal(u64),

    /// A one-byte length prefix precedes the eight-byte item.
    pub const item_size: u64 = 9;

    fn config(cache: *CacheRef) variable.Config(u64) {
        return .{
            .partition = "bounded-open",
            .codec_config = {},
            .cache_ref = cache,
            .write_buffer = 64,
            .replay_buffer = 64,
        };
    }

    pub fn open(storage: *Storage, cache: *CacheRef, bound: ?test_support.Bound) !BoundedOpen {
        const interface = storage.interface();
        if (bound) |b| {
            const J = variable.Journal(u64);
            const journal = try J.init_at_most(gpa, interface, config(cache), b.section, b.end);
            return .{ .journal = journal };
        }
        return .{ .journal = try open_cfg(u64, interface, config(cache)) };
    }

    pub fn deinit(self: *BoundedOpen) void {
        self.journal.deinit();
    }

    pub fn extend(self: *BoundedOpen, section: u64, from: u64, to: u64) !void {
        for (from..to) |value| {
            const appended = try self.journal.append(section, value);
            try testing.expectEqual(@as(u64, 0), appended.offset % item_size);
        }
        try self.journal.sync_all();
    }

    pub fn items(self: *BoundedOpen, section: u64, out: *std.ArrayList(u64)) !void {
        var offset: u64 = 0;
        const size = try self.journal.size(section);
        while (offset < size) : (offset += item_size) {
            try out.append(gpa, try self.journal.get(section, offset));
        }
    }

    pub fn last_section(self: *const BoundedOpen) ?u64 {
        return self.journal.newest_section();
    }
};

test "bounded initialization retries after storage faults" {
    try test_support.check_interrupted_bounded_open(BoundedOpen);
}

test "capped init bounds torn suffix reads" {
    var page: std.ArrayList(u8) = .empty;
    defer page.deinit(gpa);
    for (0..8) |value| _ = try frame.encode_frame_into(u64, gpa, null, value, &page);
    try testing.expectEqual(@as(usize, 72), page.items.len);
    for ([_]u64{ 0, 1 }) |source_section| {
        for ([_]u64{ 0, 9 }) |cap| {
            // Compare a short and long discarded suffix behind the same retained cap.
            var counts: [2]u64 = undefined;
            for ([_]usize{ 16, 4096 }, &counts) |pages, *count| {
                var h = try Harness.init_sized(72, 4);
                defer h.deinit();
                const store = h.storage.interface();
                const source = source_section;
                try test_support.seed_torn_suffix(store, partition, source, page.items, pages);
                var config = h.cfg(u64);
                config.write_buffer = 144;
                config.replay_buffer = 144;
                const reads = h.storage.reads;
                var journal = try variable.Journal(u64).init_at_most(gpa, store, config, 0, cap);
                const retained = if (source_section == 0) cap else 0;
                try testing.expectEqual(retained, try journal.size(0));
                count.* = h.storage.reads - reads;
                // Appending after the cap must not reconnect any discarded items.
                _ = try journal.append(0, 999);
                try journal.sync_all();
                journal.deinit();
                var items: Items(u64) = .empty;
                defer items.deinit(gpa);
                journal = try h.replay(u64, config, &items);
                journal.deinit();
                const expected: []const u64 = if (retained == 0) &.{999} else &.{ 0, 999 };
                try testing.expectEqual(expected.len, items.items.len);
                for (expected, items.items) |value, item| try testing.expectEqual(value, item.item);
            }
            try testing.expectEqual(counts[0], counts[1]);
        }
    }
}

test "bounded initialization recovers a torn page" {
    const max = std.math.maxInt(u64);
    for ([_]u64{ 0, 9, 60, 63, 64, 65, 90, 128, 135, max }) |cap| {
        // Seed two sections so the bound must repair one and remove the later section.
        var h = try Harness.init_sized(64, 4);
        defer h.deinit();
        var config = h.cfg(u64);
        config.write_buffer = 256;
        config.replay_buffer = 256;
        const store = h.storage.interface();
        var journal = try open_cfg(u64, store, config);
        for (0..15) |value| _ = try journal.append(0, value);
        _ = try journal.append(1, 100);
        try journal.sync_all();
        journal.deinit();
        // A valid later page survives after the torn page in section zero.
        try paged.corrupt_page(store, partition, &manager_mod.section_name(0), 1, 64);
        journal = try variable.Journal(u64).init_at_most(gpa, store, config, 0, cap);
        const expected_bytes = @min(cap, 63) / 9 * 9;
        try testing.expectEqual(expected_bytes, try journal.size(0));
        try testing.expectEqual(@as(?u64, 0), journal.newest_section());
        journal.deinit();
        // A normal restart retains the repaired prefix and appends at its exact end.
        var items: Items(u64) = .empty;
        defer items.deinit(gpa);
        journal = try h.replay(u64, config, &items);
        try testing.expectEqual(expected_bytes / 9, items.items.len);
        for (items.items, 0..) |item, value| {
            try testing.expectEqual(@as(u64, 0), item.section);
            try testing.expectEqual(@as(u64, value), item.item);
        }
        try testing.expectEqual(expected_bytes, (try journal.append(0, 99)).offset);
        try journal.destroy();
    }
}

test "bounded initialization bounds its scan" {
    var counts: [2]u64 = undefined;
    for ([_]u64{ 128, 65536 }, &counts) |count, *reads| {
        var h = try Harness.init_sized(64, 4);
        defer h.deinit();
        var config = h.cfg(u64);
        config.write_buffer = 65536;
        config.replay_buffer = 65536;
        const store = h.storage.interface();
        var journal = try open_cfg(u64, store, config);
        for (0..count) |value| _ = try journal.append(0, value);
        try journal.sync_all();
        journal.deinit();
        const before = h.storage.reads;
        journal = try variable.Journal(u64).init_at_most(gpa, store, config, 0, 9);
        defer journal.deinit();
        try testing.expectEqual(@as(u64, 9), try journal.size(0));
        reads.* = h.storage.reads - before;
    }
    try testing.expectEqual(counts[0], counts[1]);
}
