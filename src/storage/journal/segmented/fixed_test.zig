//! Tests for the fixed segmented journal, ported from commonware's `segmented/fixed.rs` (same
//! 44-byte pages, 3-page cache, and SHA-256 test digests).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const runtime = @import("runtime");
const Sha256 = @import("cryptography").sha256.Sha256;
const Digest = @import("cryptography").sha256.Digest;
const memory = runtime.buffer.memory;
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const manager_mod = @import("manager.zig");

const Storage = memory.Storage;
const CacheRef = paged.CacheRef;
const J = fixed.Journal(Storage, Digest);
const Item = J.Recovery.Item;
const gpa = testing.allocator;
const page_size: u16 = 44;
const physical_page_size: u64 = page_size + paged.checksum_size;
const page_cache_size: u32 = 3;
const partition = "test-partition";

fn test_digest(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

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

    fn cfg(self: *Harness) fixed.Config {
        return .{
            .partition = partition,
            .cache_ref = &self.cache_ref,
            .write_buffer = 2048,
            .replay_buffer = 1024,
        };
    }

    fn open(self: *Harness) !J {
        return J.init(gpa, &self.storage, self.cfg());
    }

    /// Open with no floors, collecting every replayed item. Caller frees `items`.
    fn replay(self: *Harness, items: *std.ArrayList(Item)) !J {
        var recovery = try J.preflight_floors(gpa, &self.storage, self.cfg(), &.{});
        return drain(&recovery, items);
    }

    /// Sync, close, and reopen through `(section, end)` (commonware `test_reopen_at_most`).
    fn reopen_at_most(self: *Harness, journal: *J, section: u64, end: u64) !J {
        try journal.sync_all();
        journal.deinit();
        var config = self.cfg();
        config.replay_buffer = config.write_buffer;
        return J.init_at_most(gpa, &self.storage, config, section, end);
    }

    fn resize_blob(self: *Harness, section: u64, delta: i64) !void {
        const opened = try self.storage.open(partition, &manager_mod.section_name(section));
        defer opened.blob.deinit();
        const target: u64 = @intCast(@as(i64, @intCast(opened.len)) + delta);
        try opened.blob.resize(target);
        try opened.blob.sync();
    }

    fn write_blob(self: *Harness, section: u64, offset: u64, bytes: []const u8) !void {
        const opened = try self.storage.open(partition, &manager_mod.section_name(section));
        defer opened.blob.deinit();
        try opened.blob.write_at(offset, bytes);
        try opened.blob.sync();
    }

    fn blob_len(self: *Harness, section: u64) !u64 {
        const opened = try self.storage.open(partition, &manager_mod.section_name(section));
        defer opened.blob.deinit();
        return opened.len;
    }
};

/// Drain `recovery`, appending every item, and return its journal.
fn drain(recovery: *J.Recovery, items: *std.ArrayList(Item)) !J {
    {
        errdefer recovery.deinit();
        while (try recovery.next()) |item| try items.append(gpa, item);
    }
    return recovery.finish();
}

fn append_digests(journal: *J, section: u64, from: u64, to: u64) !void {
    var value = from;
    while (value < to) : (value += 1) {
        _ = try journal.append(section, test_digest(value));
    }
}

test "append and get" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    try testing.expectEqual(@as(u64, 0), try journal.append(1, test_digest(0)));
    try testing.expectEqual(@as(u64, 1), try journal.append(1, test_digest(1)));
    try testing.expectEqual(@as(u64, 0), try journal.append(2, test_digest(2)));
    try testing.expect((try journal.get(1, 0)).eql(test_digest(0)));
    try testing.expect((try journal.get(1, 1)).eql(test_digest(1)));
    try testing.expect((try journal.get(2, 0)).eql(test_digest(2)));
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 2));
    try testing.expectError(error.SectionOutOfRange, journal.get(3, 0));
    try journal.destroy();
    try testing.expectError(error.PartitionMissing, h.storage.scan(gpa, partition));
}

test "synced sections keep partial pages" {
    const sections: u64 = 8;
    for ([_]u64{ 100, 8193, 32769 }) |items| {
        var h = try Harness.init_sized(4096, 4);
        defer h.deinit();
        var config = h.cfg();
        config.write_buffer = 131072;
        config.replay_buffer = 131072;
        var journal = try IntJournal.init(gpa, &h.storage, config);
        defer journal.deinit();
        for (0..sections) |section| {
            for (0..items) |value| _ = try journal.append(section, value);
            try journal.sync_all();
        }
        for (0..sections) |section| {
            try testing.expectEqual(@as(u64, 0), try journal.get(section, 0));
            try testing.expectEqual(items - 1, try journal.get(section, items - 1));
            _ = try journal.append(section, items);
        }
        try journal.sync_all();
        for (0..sections) |section| {
            try testing.expectEqual(items, try journal.get(section, items));
        }
    }
}

test "append across buffer boundaries" {
    // A digest exceeds the two-page buffer, fills it exactly, or crosses it after buffered
    // appends.
    for ([_]u16{ 8, 16, page_size }) |page| {
        var h = try Harness.init_sized(page, page_cache_size);
        defer h.deinit();
        var config = h.cfg();
        config.write_buffer = 1;
        config.replay_buffer = 128;
        var journal = try J.init(gpa, &h.storage, config);
        for ([_]u64{ 1, 3 }) |section| {
            for (0..10) |position| {
                const item = test_digest(section * 100 + position);
                try testing.expectEqual(position, try journal.append(section, item));
                try testing.expectEqual(position + 1, try journal.section_len(section));
                try testing.expect((try journal.get(section, position)).eql(item));
            }
        }
        try journal.sync_all();
        journal.deinit();

        var items: std.ArrayList(Item) = .empty;
        defer items.deinit(gpa);
        var recovery = try J.preflight_floors(gpa, &h.storage, config, &.{});
        journal = try drain(&recovery, &items);
        try testing.expectEqual(@as(usize, 20), items.items.len);
        for (items.items, 0..) |item, index| {
            const section: u64 = if (index < 10) 1 else 3;
            try testing.expectEqual(section, item.section);
            try testing.expectEqual(index % 10, item.position);
            try testing.expect(item.item.eql(test_digest(section * 100 + index % 10)));
        }
        try testing.expectEqual(@as(u64, 10), try journal.append(3, test_digest(310)));
        try testing.expect((try journal.get(3, 10)).eql(test_digest(310)));
        try journal.destroy();
    }
}

test "replay of empty storage finishes immediately" {
    var h = try Harness.init();
    defer h.deinit();
    var recovery = try J.preflight_floors(gpa, &h.storage, h.cfg(), &.{});
    var journal = try recovery.finish();
    try journal.destroy();
}

test "finishing a replay before it drains fails" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    _ = try journal.append(1, test_digest(0));
    try journal.sync_all();
    journal.deinit();
    var recovery = try J.preflight_floors(gpa, &h.storage, h.cfg(), &.{});
    try testing.expectError(error.ReplayFailed, recovery.finish());
}

test "replay" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    try append_digests(&journal, 1, 0, 10);
    try append_digests(&journal, 2, 10, 20);
    try journal.sync_all();
    journal.deinit();

    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(&items);
    try testing.expectEqual(@as(usize, 20), items.items.len);
    for (items.items, 0..) |item, index| {
        try testing.expectEqual(@as(u64, if (index < 10) 1 else 2), item.section);
        try testing.expectEqual(index % 10, item.position);
        try testing.expect(item.item.eql(test_digest(index)));
    }
    try journal.destroy();
}

test "prune" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    for (1..6) |section| _ = try journal.append(section, test_digest(section));
    try journal.sync_all();
    try testing.expect(try journal.prune(3));
    try testing.expectError(error.AlreadyPrunedToSection, journal.get(1, 0));
    try testing.expectError(error.AlreadyPrunedToSection, journal.get(2, 0));
    try testing.expect((try journal.get(3, 0)).eql(test_digest(3)));
    try journal.destroy();
}

test "pruned after full prune" {
    // `pruned` keeps reporting the floor after every blob is removed.
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    for (1..4) |section| _ = try journal.append(section, test_digest(section));
    try journal.sync_all();
    try testing.expect(try journal.prune(10));
    try testing.expectEqual(@as(?u64, null), journal.oldest_section());
    try testing.expect(journal.pruned(3));
    try testing.expect(journal.pruned(9));
    try testing.expect(!journal.pruned(10));
    try journal.destroy();
}

test "truncate" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    for (1..4) |section| _ = try journal.append(section, test_digest(section));
    try journal.sync_all();
    for (1..4) |section| try testing.expect(try journal.size(section) > 0);
    const size = try journal.size(1);
    journal = try h.reopen_at_most(&journal, 1, size);
    try testing.expect(try journal.size(1) > 0);
    for (2..4) |section| try testing.expectEqual(@as(u64, 0), try journal.size(section));
    try testing.expect((try journal.get(1, 0)).eql(test_digest(1)));
    try journal.destroy();
}

test "truncate the maximal section" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    const max = std.math.maxInt(u64);
    _ = try journal.append(max, test_digest(0));
    try journal.sync_all();
    const size = try journal.size(max);
    journal = try h.reopen_at_most(&journal, max, size);
    try testing.expectEqual(size, try journal.size(max));
    try testing.expect((try journal.get(max, 0)).eql(test_digest(0)));
    try journal.destroy();
}

test "truncate many sections" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    for (1..11) |section| _ = try journal.append(section, test_digest(section));
    try journal.sync_all();
    const size = try journal.size(5);
    journal = try h.reopen_at_most(&journal, 5, size);
    for (1..6) |section| try testing.expect(try journal.size(section) > 0);
    for (6..11) |section| try testing.expectEqual(@as(u64, 0), try journal.size(section));
    journal.deinit();

    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(&items);
    try testing.expectEqual(@as(usize, 5), items.items.len);
    for (items.items, 1..) |item, section| {
        try testing.expectEqual(section, item.section);
        try testing.expect(item.item.eql(test_digest(section)));
    }
    try journal.destroy();
}

test "truncate persists" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    for (1..6) |section| _ = try journal.append(section, test_digest(section));
    try journal.sync_all();
    const size = try journal.size(2);
    journal = try h.reopen_at_most(&journal, 2, size);
    try journal.sync_all();
    journal.deinit();

    journal = try h.open();
    for (1..3) |section| try testing.expect(try journal.size(section) > 0);
    for (3..6) |section| try testing.expectEqual(@as(u64, 0), try journal.size(section));
    try testing.expect((try journal.get(1, 0)).eql(test_digest(1)));
    try testing.expect((try journal.get(2, 0)).eql(test_digest(2)));
    try journal.destroy();
}

test "corruption recovery" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    try append_digests(&journal, 1, 0, 5);
    try journal.sync_all();
    journal.deinit();
    try h.resize_blob(1, -1);

    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(&items);
    try testing.expectEqual(@as(usize, 4), items.items.len);
    try journal.destroy();
}

test "persistence" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    try append_digests(&journal, 1, 0, 5);
    try journal.sync_all();
    journal.deinit();
    journal = try h.open();
    for (0..5) |index| try testing.expect((try journal.get(1, index)).eql(test_digest(index)));
    try journal.destroy();
}

test "sync selected sections" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    // One sub-page item per section stays buffered until synced.
    for (1..4) |section| _ = try journal.append(section, test_digest(section));
    // A nonexistent section (99) is skipped, not an error.
    try journal.sync(&.{ 1, 3, 99 });
    journal.deinit();
    // Only the synced sections survive the unclean drop.
    journal = try h.open();
    try testing.expect((try journal.get(1, 0)).eql(test_digest(1)));
    try testing.expect((try journal.get(3, 0)).eql(test_digest(3)));
    if (journal.get(2, 0)) |_| return error.TestUnexpectedResult else |err| {
        try testing.expect(err == error.ItemOutOfRange or err == error.SectionOutOfRange);
    }
    try journal.destroy();
}

test "section len" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    try testing.expectEqual(@as(u64, 0), try journal.section_len(1));
    try append_digests(&journal, 1, 0, 5);
    try testing.expectEqual(@as(u64, 5), try journal.section_len(1));
    try testing.expectEqual(@as(u64, 0), try journal.section_len(2));
    try journal.destroy();
}

test "non-contiguous sections" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    _ = try journal.append(1, test_digest(100));
    _ = try journal.append(5, test_digest(500));
    _ = try journal.append(10, test_digest(1000));
    try journal.sync_all();
    try testing.expect((try journal.get(1, 0)).eql(test_digest(100)));
    try testing.expect((try journal.get(5, 0)).eql(test_digest(500)));
    try testing.expect((try journal.get(10, 0)).eql(test_digest(1000)));
    for ([_]u64{ 0, 2, 3, 4, 6, 7, 8, 9, 11 }) |missing| {
        try testing.expectError(error.SectionOutOfRange, journal.get(missing, 0));
    }
    journal.deinit();

    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(&items);
    try testing.expectEqual(@as(usize, 3), items.items.len);
    for (items.items, [_]u64{ 1, 5, 10 }) |item, section| {
        try testing.expectEqual(section, item.section);
        try testing.expectEqual(@as(u64, 0), item.position);
        try testing.expect(item.item.eql(test_digest(section * 100)));
    }
    try journal.destroy();
}

test "empty section in the middle" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    _ = try journal.append(1, test_digest(100));
    _ = try journal.append(2, test_digest(200));
    try journal.sync(&.{2});
    // commonware's `test_reopen_section(2, 0)`: durably empty section 2, then reopen.
    try journal.sync_all();
    try journal.truncate_pending_section(2, 0);
    journal.deinit();
    journal = try h.open();
    _ = try journal.append(3, test_digest(300));
    try journal.sync_all();
    try testing.expectEqual(@as(u64, 1), try journal.section_len(1));
    try testing.expectEqual(@as(u64, 0), try journal.section_len(2));
    try testing.expectEqual(@as(u64, 1), try journal.section_len(3));
    journal.deinit();

    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    journal = try h.replay(&items);
    try testing.expectEqual(@as(usize, 2), items.items.len);
    try testing.expectEqual(@as(u64, 1), items.items[0].section);
    try testing.expect(items.items[0].item.eql(test_digest(100)));
    try testing.expectEqual(@as(u64, 3), items.items[1].section);
    try testing.expect(items.items[1].item.eql(test_digest(300)));
    try journal.destroy();
}

const IntJournal = fixed.Journal(Storage, u64);

fn int_cfg(h: *Harness) fixed.Config {
    var config = h.cfg();
    config.write_buffer = 128;
    return config;
}

test "pages are validated before trailing bytes" {
    const logical_page_size: u16 = 5;
    var h = try Harness.init_sized(logical_page_size, 4);
    defer h.deinit();
    var journal = try IntJournal.init(gpa, &h.storage, int_cfg(&h));
    for ([_]u64{ 11, 22, 33, 44 }) |value| _ = try journal.append(0, value);
    try journal.sync_all();
    journal.deinit();
    {
        const opened = try h.storage.open(partition, &manager_mod.section_name(0));
        var writer = try paged.Writer(memory.MemoryBlob).open_recovery(
            gpa,
            opened.blob,
            opened.len,
            128,
            &h.cache_ref,
        );
        defer writer.deinit();
        try writer.truncate(30);
        try writer.sync();
    }
    // Five-byte integrity pages crossed by eight-byte journal items:
    //
    // pages: [0..5) [5..10) [10..15) [15..20) [20..25) [25..30)
    // state:    ok      ok       ok       ok       torn      ok
    // items: [0......8) [8.......16) [16......24) [24..30 tail)
    //
    // Backward sizing stops at valid page 5 and reports 30 logical bytes. Item alignment alone
    // selects 24, inside torn page 4. Forward page validation finds 20 contiguous bytes and
    // selects the safe item boundary 16.
    try paged.corrupt_page(&h.storage, partition, &manager_mod.section_name(0), 4, 5);
    journal = try IntJournal.init(gpa, &h.storage, int_cfg(&h));
    try testing.expectEqual(@as(u64, 2), try journal.section_len(0));
    try testing.expectEqual(@as(u64, 11), try journal.get(0, 0));
    try testing.expectEqual(@as(u64, 22), try journal.get(0, 1));
    try journal.destroy();
}

test "repairs a torn interior page" {
    var h = try Harness.init_sized(16, 4);
    defer h.deinit();
    var journal = try IntJournal.init(gpa, &h.storage, int_cfg(&h));
    for (0..6) |value| _ = try journal.append(0, value);
    try journal.sync_all();
    journal.deinit();
    // The three 16-byte pages each hold two items. Tearing the interior page leaves a valid
    // last page, so backward sizing reports 48 bytes; replay must still truncate to 16.
    try paged.corrupt_page(&h.storage, partition, &manager_mod.section_name(0), 1, 16);
    journal = try IntJournal.init(gpa, &h.storage, int_cfg(&h));
    try testing.expectEqual(@as(u64, 2), try journal.section_len(0));
    try testing.expectEqual(@as(u64, 0), try journal.get(0, 0));
    try testing.expectEqual(@as(u64, 1), try journal.get(0, 1));
    try testing.expectError(error.ItemOutOfRange, journal.get(0, 2));
    // The repair is durable: appends resume at the repaired boundary and survive reopen.
    try testing.expectEqual(@as(u64, 2), try journal.append(0, 99));
    try journal.sync_all();
    journal.deinit();
    journal = try IntJournal.init(gpa, &h.storage, int_cfg(&h));
    try testing.expectEqual(@as(u64, 3), try journal.section_len(0));
    try testing.expectEqual(@as(u64, 0), try journal.get(0, 0));
    try testing.expectEqual(@as(u64, 1), try journal.get(0, 1));
    try testing.expectEqual(@as(u64, 99), try journal.get(0, 2));
    try journal.destroy();
}

test "truncation recovery across a page boundary" {
    // With 44-byte pages and 32-byte items, three items span 96 bytes. Cutting one byte leaves
    // 95, and recovery must truncate to the two complete items (64 bytes).
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    try append_digests(&journal, 1, 0, 3);
    try journal.sync_all();
    for (0..3) |index| try testing.expect((try journal.get(1, index)).eql(test_digest(index)));
    journal.deinit();
    try h.resize_blob(1, -1);
    journal = try h.open();
    try testing.expectEqual(@as(u64, 2), try journal.section_len(1));
    try testing.expectEqual(@as(u64, 64), try journal.size(1));
    try testing.expect((try journal.get(1, 0)).eql(test_digest(0)));
    try testing.expect((try journal.get(1, 1)).eql(test_digest(1)));
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 2));
    try journal.destroy();
}

test "clear" {
    var h = try Harness.init();
    defer h.deinit();
    var config = h.cfg();
    config.write_buffer = 1024;
    var journal = try J.init(gpa, &h.storage, config);
    for (0..5) |section| {
        try append_digests(&journal, section, section * 1000, section * 1000 + 10);
        try journal.sync(&.{section});
    }
    try testing.expect((try journal.get(0, 0)).eql(test_digest(0)));
    try testing.expect((try journal.get(4, 0)).eql(test_digest(4000)));
    try journal.clear();
    for (0..5) |section| try testing.expectError(error.SectionOutOfRange, journal.get(section, 0));
    for (0..5) |index| _ = try journal.append(10, test_digest(index * 100));
    try journal.sync(&.{10});
    try testing.expect((try journal.get(10, 0)).eql(test_digest(0)));
    try testing.expectError(error.SectionOutOfRange, journal.get(0, 0));
    try journal.destroy();
}

test "last" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    // A missing section is an error.
    try testing.expectError(error.SectionOutOfRange, journal.last(0));
    try testing.expectError(error.SectionOutOfRange, journal.last(99));
    _ = try journal.append(0, test_digest(0));
    _ = try journal.append(0, test_digest(1));
    try journal.sync(&.{0});
    try testing.expect((try journal.last(0)).?.eql(test_digest(1)));
    // A section truncated to zero is empty, not missing.
    journal = try h.reopen_at_most(&journal, 0, 0);
    try testing.expectEqual(@as(?Digest, null), try journal.last(0));
    // A pruned section is an error.
    _ = try journal.append(1, test_digest(1));
    try journal.sync_all();
    try testing.expect(try journal.prune(1));
    try testing.expectError(error.AlreadyPrunedToSection, journal.last(0));
    try testing.expect((try journal.last(1)) != null);
    try journal.destroy();
}

test "get many" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open();
    var one: [1]Digest = undefined;
    try testing.expectError(error.SectionOutOfRange, journal.get_many(99, &.{0}, &one));
    try append_digests(&journal, 0, 0, 10);
    var none: [0]Digest = .{};
    try testing.expectEqual(@as(usize, 0), try journal.get_many(0, &.{}, &none));
    var all: [10]Digest = undefined;
    _ = try journal.get_many(0, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, &all);
    for (all, 0..) |item, index| try testing.expect(item.eql(test_digest(index)));
    var subset: [4]Digest = undefined;
    const positions = [_]u64{ 1, 4, 7, 9 };
    _ = try journal.get_many(0, &positions, &subset);
    for (subset, positions) |item, position| {
        try testing.expect(item.eql(test_digest(position)));
    }
    // After a sync the batch still matches single reads.
    try journal.sync_all();
    _ = try journal.get_many(0, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, &all);
    for (all, 0..) |item, position| {
        try testing.expect(item.eql(try journal.get(0, position)));
    }
    try journal.destroy();
}

const test_support = @import("test_support.zig");

/// Drives `IntJournal` through `test_support.check_interrupted_bounded_open`.
const BoundedOpen = struct {
    journal: IntJournal,

    pub const item_size: u64 = IntJournal.chunk;

    fn config(cache: *CacheRef) fixed.Config {
        return .{
            .partition = "bounded-open",
            .cache_ref = cache,
            .write_buffer = 64,
            .replay_buffer = 64,
        };
    }

    pub fn open(storage: *Storage, cache: *CacheRef, bound: ?test_support.Bound) !BoundedOpen {
        const config_value = config(cache);
        if (bound) |b| {
            return .{
                .journal = try IntJournal.init_at_most(
                    gpa,
                    storage,
                    config_value,
                    b.section,
                    b.end,
                ),
            };
        }
        return .{ .journal = try IntJournal.init(gpa, storage, config_value) };
    }

    pub fn deinit(self: *BoundedOpen) void {
        self.journal.deinit();
    }

    pub fn extend(self: *BoundedOpen, section: u64, from: u64, to: u64) !void {
        for (from..to) |value| _ = try self.journal.append(section, value);
        try self.journal.sync_all();
    }

    pub fn items(self: *BoundedOpen, section: u64, out: *std.ArrayList(u64)) !void {
        for (0..try self.journal.section_len(section)) |position| {
            try out.append(gpa, try self.journal.get(section, position));
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
    var page: [72]u8 = undefined;
    for (0..9) |value| std.mem.writeInt(u64, page[value * 8 ..][0..8], value, .big);
    for ([_]u64{ 0, 1 }) |source_section| {
        for ([_]u64{ 0, 8 }) |cap| {
            // Compare a short and long discarded suffix behind the same retained cap.
            var counts: [2]u64 = undefined;
            for ([_]usize{ 16, 4096 }, &counts) |pages, *count| {
                var h = try Harness.init_sized(72, 4);
                defer h.deinit();
                const source = source_section;
                try test_support.seed_torn_suffix(&h.storage, partition, source, &page, pages);
                var config = h.cfg();
                config.write_buffer = 144;
                config.replay_buffer = 144;
                // Bounded initialization must read independently of the discarded suffix.
                const reads = h.storage.reads;
                var journal = try IntJournal.init_at_most(gpa, &h.storage, config, 0, cap);
                const retained = if (source_section == 0) cap else 0;
                try testing.expectEqual(retained, try journal.size(0));
                count.* = h.storage.reads - reads;
                // Appending after the cap must not reconnect any discarded items.
                _ = try journal.append(0, 999);
                try journal.sync_all();
                journal.deinit();
                var recovery = try IntJournal.preflight_floors(gpa, &h.storage, config, &.{});
                var values: std.ArrayList(u64) = .empty;
                defer values.deinit(gpa);
                {
                    errdefer recovery.deinit();
                    while (try recovery.next()) |item| try values.append(gpa, item.item);
                }
                journal = try recovery.finish();
                journal.deinit();
                const expected: []const u64 = if (retained == 0) &.{999} else &.{ 0, 999 };
                try testing.expectEqualSlices(u64, expected, values.items);
            }
            // Suffix length must not change the number of reads needed for the same cap.
            try testing.expectEqual(counts[0], counts[1]);
        }
    }
}

test "bounded initialization bounds its scan" {
    // Seed different journal lengths under the same page and buffer configuration.
    var counts: [2]u64 = undefined;
    for ([_]u64{ 128, 65536 }, &counts) |count, *reads| {
        var h = try Harness.init_sized(64, 4);
        defer h.deinit();
        var config = h.cfg();
        config.write_buffer = 65536;
        config.replay_buffer = 65536;
        var journal = try IntJournal.init(gpa, &h.storage, config);
        for (0..count) |value| _ = try journal.append(0, value);
        try journal.sync_all();
        journal.deinit();
        // Record the reads required to reopen at the same one-item boundary.
        const before = h.storage.reads;
        journal = try IntJournal.init_at_most(gpa, &h.storage, config, 0, 8);
        defer journal.deinit();
        try testing.expectEqual(@as(u64, 1), try journal.section_len(0));
        reads.* = h.storage.reads - before;
    }
    // Work below the cap must be independent of the discarded journal length.
    try testing.expectEqual(counts[0], counts[1]);
}

test "bounded initialization recovers a torn page" {
    const max = std.math.maxInt(u64);
    for ([_]u64{ 30, 31, 32 }) |tail| {
        for ([_]u64{ 0, 8, 16, 20, 24, 28, 29, 30, 31, 32, max }) |cap| {
            // Seed two sections so the bound must repair one and remove the later section.
            var h = try Harness.init_sized(5, 4);
            defer h.deinit();
            var config = h.cfg();
            config.write_buffer = 256;
            config.replay_buffer = 256;
            var journal = try IntJournal.init(gpa, &h.storage, config);
            for (0..4) |value| _ = try journal.append(0, value);
            _ = try journal.append(1, 100);
            try journal.sync_all();
            journal.deinit();
            // A valid page prefix may end inside the last item after an interrupted append.
            {
                const opened = try h.storage.open(partition, &manager_mod.section_name(0));
                var writer = try paged.Writer(memory.MemoryBlob).open_recovery(
                    gpa,
                    opened.blob,
                    opened.len,
                    256,
                    &h.cache_ref,
                );
                defer writer.deinit();
                try writer.truncate(tail);
                try writer.sync();
            }
            // A valid later page survives after the torn page in section zero.
            try paged.corrupt_page(&h.storage, partition, &manager_mod.section_name(0), 4, 5);
            journal = try IntJournal.init_at_most(gpa, &h.storage, config, 0, cap);
            const expected_bytes = @min(cap, 16) / 8 * 8;
            try testing.expectEqual(expected_bytes, try journal.size(0));
            try testing.expectEqual(@as(?u64, 0), journal.newest_section());
            journal.deinit();
            // A normal restart retains the repaired prefix and appends at its exact end.
            var recovery = try IntJournal.preflight_floors(gpa, &h.storage, config, &.{});
            var count: u64 = 0;
            {
                errdefer recovery.deinit();
                while (try recovery.next()) |item| {
                    try testing.expectEqual(@as(u64, 0), item.section);
                    try testing.expectEqual(count, item.item);
                    count += 1;
                }
            }
            journal = try recovery.finish();
            try testing.expectEqual(expected_bytes / 8, count);
            try testing.expectEqual(expected_bytes / 8, try journal.append(0, 99));
            try journal.destroy();
        }
    }
}

/// commonware's `lazy_recovery_cfg`: 16-byte pages and a one-byte write buffer.
fn lazy_cfg(h: *Harness) fixed.Config {
    return .{
        .partition = partition,
        .cache_ref = &h.cache_ref,
        .write_buffer = 1,
        .replay_buffer = 1024,
    };
}

/// Seed sections `first..=last` with sixteen durable u64 items each.
fn seed(h: *Harness, first: u64, last: u64) !void {
    var journal = try IntJournal.init(gpa, &h.storage, lazy_cfg(h));
    defer journal.deinit();
    var section = first;
    while (section <= last) : (section += 1) {
        for (0..16) |value| _ = try journal.append(section, value);
    }
    try journal.sync_all();
}

fn drain_count(recovery: *IntJournal.Recovery) !struct { IntJournal, u64 } {
    var count: u64 = 0;
    {
        errdefer recovery.deinit();
        while (try recovery.next()) |_| count += 1;
    }
    return .{ try recovery.finish(), count };
}

fn check_cached_get(comptime size: usize) !void {
    const ArrayJournal = fixed.Journal(Storage, [size]u8);
    var h = try Harness.init();
    defer h.deinit();
    var journal = try ArrayJournal.init(gpa, &h.storage, h.cfg());
    _ = try journal.append(1, @splat(7));
    _ = try journal.append(1, @splat(8));
    try testing.expectEqual(@as(?[size]u8, @splat(7)), journal.try_get_sync(1, 0));
    try testing.expectEqual(@as(?[size]u8, @splat(8)), journal.try_get_sync(1, 1));
    try journal.destroy();
}

test "cached get at the stack buffer boundary" {
    // commonware's `SYNC_READ_STACK_SIZE` (128) and one past it.
    try check_cached_get(128);
    try check_cached_get(129);
}

test "replay leaves the page cache cold" {
    const PageJournal = fixed.Journal(Storage, [16]u8);
    var h = try Harness.init_sized(16, 4);
    defer h.deinit();
    var config = int_cfg(&h);
    config.replay_buffer = 1024;
    var journal = try PageJournal.init(gpa, &h.storage, config);
    // Each item fills one logical page, so a synchronous probe checks each page.
    for (0..2) |value| _ = try journal.append(1, @splat(@intCast(value)));
    try journal.sync(&.{1});
    journal.deinit();
    h.cache_ref.clear();
    journal = try PageJournal.init(gpa, &h.storage, config);
    defer journal.deinit();
    for (0..2) |position| try testing.expect(journal.try_get_sync(1, position) == null);
    var reads = h.storage.reads;
    try testing.expectEqual(@as([16]u8, @splat(0)), try journal.get(1, 0));
    try testing.expect(h.storage.reads > reads);
    try testing.expectEqual(@as(?[16]u8, @splat(0)), journal.try_get_sync(1, 0));
    reads = h.storage.reads;
    try testing.expectEqual(@as([16]u8, @splat(0)), try journal.get(1, 0));
    try testing.expectEqual(reads, h.storage.reads);
}

test "clean recovery uses the replay buffer" {
    var h = try Harness.init_sized(16, 4);
    defer h.deinit();
    // Sixteen u64s occupy eight physical pages; the one-byte write buffer would force an
    // eager recovery scan to read one page at a time.
    try seed(&h, 1, 1);
    var config = lazy_cfg(&h);
    config.replay_buffer = 448;
    // A preflight without floors reads nothing; replay reads in replay-buffer batches.
    const before = h.storage.reads;
    var recovery = try IntJournal.preflight_floors(gpa, &h.storage, config, &.{});
    try testing.expectEqual(before, h.storage.reads);
    var journal, const count = try drain_count(&recovery);
    try testing.expectEqual(@as(u64, 16), count);
    // One read opens the writer's tail page and one reads all eight pages (commonware's replay
    // splits them into two reads).
    try testing.expectEqual(@as(u64, 2), h.storage.reads - before);
    try journal.destroy();
}

test "floor preflight reads only the boundary" {
    var h = try Harness.init_sized(16, 4);
    defer h.deinit();
    try seed(&h, 1, 1);
    // A durable floor proves its prefix: preflight reads only the terminal entry's page.
    const before = h.storage.reads;
    var recovery = try IntJournal.preflight_floors(gpa, &h.storage, lazy_cfg(&h), &.{
        .{ .section = 1, .items = 16 },
    });
    try testing.expectEqual(before + 1, h.storage.reads);
    var journal, const count = try drain_count(&recovery);
    try testing.expectEqual(@as(u64, 16), count);
    try journal.destroy();
}

test "floor preflight reads the terminal entry only" {
    var h = try Harness.init_sized(16, 4);
    defer h.deinit();
    var config = int_cfg(&h);
    config.replay_buffer = 1024;
    var journal = try J.init(gpa, &h.storage, config);
    for (0..2) |value| _ = try journal.append(1, test_digest(value));
    try journal.sync(&.{1});
    journal.deinit();
    // Two 32-byte items occupy four 16-byte pages; the terminal entry spans two of them.
    const before = h.storage.reads;
    var recovery = try J.preflight_floors(gpa, &h.storage, config, &.{
        .{ .section = 1, .items = 2 },
    });
    try testing.expectEqual(before + 2, h.storage.reads);
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    journal = try drain(&recovery, &items);
    try testing.expectEqual(@as(usize, 2), items.items.len);
    try journal.destroy();
}

test "recovery modifies nothing before next" {
    var h = try Harness.init_sized(16, 4);
    defer h.deinit();
    try seed(&h, 1, 1);
    // Tear the terminal page, which opening the writer discards.
    try h.resize_blob(1, -1);
    const torn = try h.blob_len(1);
    // A floor below the tear is proven by reading it; a dropped recovery leaves the torn
    // page in place.
    var recovery = try IntJournal.preflight_floors(gpa, &h.storage, lazy_cfg(&h), &.{
        .{ .section = 1, .items = 14 },
    });
    try testing.expectEqual(@as(usize, 1), recovery.boundary_items().len);
    try testing.expectEqual(@as(?u64, 13), recovery.boundary_items()[0].item);
    recovery.deinit();
    try testing.expectEqual(torn, try h.blob_len(1));
    // The first call opens the writer and discards the torn page: seven 28-byte physical
    // pages remain, holding the fourteen replayed items.
    recovery = try IntJournal.preflight_floors(gpa, &h.storage, lazy_cfg(&h), &.{});
    var journal, const count = try drain_count(&recovery);
    journal.deinit();
    try testing.expectEqual(@as(u64, 14), count);
    try testing.expectEqual(@as(u64, 7 * 28), try h.blob_len(1));
}

test "restore reads only boundaries" {
    var h = try Harness.init_sized(16, 4);
    defer h.deinit();
    try seed(&h, 0, 1);
    // One terminal boundary read per section, independent of the eight pages in each.
    const before = h.storage.reads;
    var recovery = try IntJournal.preflight_restore(gpa, &h.storage, lazy_cfg(&h), 1, 16 * 8);
    try testing.expectEqual(before + 2, h.storage.reads);
    // The checkpoint leaves nothing to replay, and asking opens no writer.
    try testing.expectEqual(@as(?IntJournal.Recovery.Item, null), try recovery.next());
    try testing.expectEqual(before + 2, h.storage.reads);
    var journal = try recovery.finish();
    try journal.destroy();
}

test "restore retains an empty checkpoint section" {
    var h = try Harness.init_sized(16, 4);
    defer h.deinit();
    var journal = try IntJournal.init(gpa, &h.storage, lazy_cfg(&h));
    for (0..3) |section| _ = try journal.append(section, section);
    try journal.sync_all();
    try journal.truncate_pending_section(1, 0);
    try journal.sync(&.{1});
    journal.deinit();
    var recovery = try IntJournal.preflight_restore(gpa, &h.storage, lazy_cfg(&h), 1, 0);
    journal = try recovery.finish();
    const open = journal.open_sections();
    try testing.expectEqual(@as(usize, 2), open.len);
    try testing.expectEqual(@as(u64, 0), open[0].section);
    try testing.expectEqual(@as(u64, 1), open[1].section);
    try testing.expectEqual(@as(u64, 0), try journal.size(1));
    try journal.destroy();
}

test "floors reject repair below the floor" {
    // A torn page under a floor is committed damage, whether the section ends at its floor or
    // keeps a suffix above it.
    for ([_]u64{ 16, 8 }) |floor| {
        var h = try Harness.init_sized(16, 4);
        defer h.deinit();
        try seed(&h, 0, 1);
        // Tear the page holding items four and five; preflight reads only the boundary page.
        try paged.corrupt_page(&h.storage, partition, &manager_mod.section_name(1), 2, 16);
        var recovery = try IntJournal.preflight_floors(gpa, &h.storage, lazy_cfg(&h), &.{
            .{ .section = 1, .items = floor },
        });
        const outcome: anyerror = while (true) {
            const item = recovery.next() catch |err| break err;
            if (item == null) break error.TestUnexpectedResult;
        };
        try testing.expectEqual(error.Corruption, outcome);
        try testing.expectError(error.ReplayFailed, recovery.finish());
        // The floor-proven bytes stay untouched: eight 28-byte physical pages.
        try testing.expectEqual(@as(u64, 8 * 28), try h.blob_len(1));
    }
}

test "restore rejects a damaged earlier boundary" {
    var h = try Harness.init_sized(16, 4);
    defer h.deinit();
    try seed(&h, 0, 1);
    try h.resize_blob(0, -1);
    const torn = try h.blob_len(0);
    // The checkpoint covers earlier sections whole, so one without a valid terminal boundary
    // is committed damage that restore reports and leaves untouched.
    try testing.expectError(
        error.Corruption,
        IntJournal.preflight_restore(gpa, &h.storage, lazy_cfg(&h), 1, 16 * 8),
    );
    try testing.expectEqual(torn, try h.blob_len(0));
}
