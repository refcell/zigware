//! Recovery tests of the oversized journal, ported from commonware's `segmented/oversized.rs`.
//!
//! commonware drops a journal to simulate an unclean shutdown; `deinit` does the same here,
//! discarding unsynced bytes. Raw blob damage goes through the harness's test storage.

const std = @import("std");
const testing = std.testing;
const manager_mod = @import("manager.zig");
const base = @import("oversized_test.zig");

const gpa = testing.allocator;
const Harness = base.Harness;
const Journal = base.Journal;
const TestValue = base.TestValue;
const entry = base.entry;
const chunk: u64 = Journal.Index.chunk;

/// Where an append placed its entry and value.
const Located = struct { position: u64, offset: u64, size: u32 };

fn append(journal: *Journal, section: u64, id: u64, value: TestValue) !Located {
    const appended = try journal.append(section, entry(id), value);
    return .{ .position = appended.position, .offset = appended.offset, .size = appended.size };
}

fn fill(byte: u64) TestValue {
    return @splat(@truncate(byte));
}

/// The value bytes an entry needs: commonware's `byte_end`.
fn byte_end(located: Located) u64 {
    return located.offset + located.size;
}

/// Durably resize the value blob of `section` to `length` bytes.
fn resize_values(h: *Harness, section: u64, length: u64) !void {
    const opened = try h.storage.open("test-values", &manager_mod.section_name(section));
    defer opened.blob.close();
    try opened.blob.resize(length);
    try opened.blob.sync();
}

fn expect_value(journal: *Journal, section: u64, located: Located, value: TestValue) !void {
    const stored = try journal.get_value(section, located.offset, located.size);
    try testing.expectEqual(value, stored);
}

test "oversized recovery: persistence across a checkpoint restore" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_checkpoint(.{ .section = 0, .size = 0 });
    const located = try append(&journal, 1, 123, fill(42));
    try journal.sync(&.{1});
    journal.deinit();
    // Restore at the synced boundary and verify.
    journal = try h.open_checkpoint(.{ .section = 1, .size = chunk });
    try testing.expectEqual(123, (try journal.get(1, located.position)).id);
    try expect_value(&journal, 1, located, fill(42));
    try journal.destroy();
}

test "oversized recovery: sync makes exactly the selected sections durable" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_checkpoint(.{ .section = 0, .size = 0 });
    // One sub-page entry and value per section stays buffered until synced.
    var located: [3]Located = undefined;
    for (&located, 1..) |*slot, section| {
        slot.* = try append(&journal, section, section, fill(section));
    }
    // A nonexistent section (99) is skipped, not an error.
    try journal.sync(&.{ 1, 3, 99 });
    journal.deinit();
    journal = try h.open_checkpoint(.{ .section = 3, .size = chunk });
    for (located, 1..) |slot, section| {
        if (section == 2) {
            // commonware asserts only an error: the unsynced section's blob may exist, empty.
            const lost = journal.get(section, slot.position);
            if (lost) |_| return error.TestUnexpectedResult else |_| {}
            continue;
        }
        try testing.expectEqual(section, (try journal.get(section, slot.position)).id);
        try expect_value(&journal, section, slot, fill(section));
    }
    try journal.destroy();
}

test "oversized recovery: checkpoint restore of the sole section" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_checkpoint(.{ .section = 0, .size = 0 });
    _ = try append(&journal, 2, 1, fill(42));
    try journal.sync(&.{2});
    journal.deinit();
    // A restore at section 2's synced boundary needs no earlier section.
    journal = try h.open_checkpoint(.{ .section = 2, .size = chunk });
    try testing.expectEqual(1, (try journal.get(2, 0)).id);
    try journal.destroy();
}

/// Appending after recovery continues at `position` and reads back.
fn expect_append_at(journal: *Journal, section: u64, position: u64) !void {
    const located = try append(journal, section, 100, fill(99));
    try testing.expectEqual(position, located.position);
    try testing.expectEqual(100, (try journal.get(section, position)).id);
    try expect_value(journal, section, located, fill(99));
}

test "oversized recovery: all entries invalid" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    for (0..5) |i| _ = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    // Truncating the values to 0 bytes invalidates every entry.
    try resize_values(&h, 1, 0);
    journal = try h.open_tracked();
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 0));
    try expect_append_at(&journal, 1, 0);
    try journal.destroy();
}

test "oversized recovery: sections truncate independently at their first lost value" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    var section1: [3]Located = undefined;
    for (&section1, 0..) |*slot, i| slot.* = try append(&journal, 1, i, fill(i));
    var section2: [5]Located = undefined;
    for (&section2, 0..) |*slot, i| slot.* = try append(&journal, 2, 10 + i, fill(10 + i));
    for (0..2) |i| _ = try append(&journal, 3, 20 + i, fill(20 + i));
    // One sync of every section publishes no marker, so the damage lies above every floor.
    try journal.sync_all();
    journal.deinit();
    try resize_values(&h, 1, byte_end(section1[0]));
    try resize_values(&h, 2, byte_end(section2[2]));
    journal = try h.open_tracked();
    errdefer journal.deinit();
    const expected = [_]struct { section: u64, kept: u64, written: u64 }{
        .{ .section = 1, .kept = 1, .written = 3 },
        .{ .section = 2, .kept = 3, .written = 5 },
        .{ .section = 3, .kept = 2, .written = 2 },
    };
    for (expected) |e| {
        for (0..e.written) |position| {
            if (position < e.kept) {
                _ = try journal.get(e.section, position);
            } else {
                try testing.expectError(error.ItemOutOfRange, journal.get(e.section, position));
            }
        }
    }
    try journal.destroy();
}

test "oversized recovery: corrupted last index page" {
    // Each index page holds one entry: 20 logical bytes plus a 12-byte checksum record.
    var h = try Harness.init_page(@intCast(base.TestEntry.fixed_size));
    defer h.deinit();
    var journal = try h.open_tracked();
    for (0..5) |i| _ = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    // Overwrite the last page's checksum record.
    const opened = try h.storage.open("test-index", &manager_mod.section_name(1));
    try testing.expectEqual(160, opened.len);
    try opened.blob.write_at(opened.len - 12, &@as([12]u8, @splat(0xFF)), .{});
    try opened.blob.sync();
    opened.blob.close();
    journal = try h.open_tracked();
    for (0..4) |i| try testing.expectEqual(i, (try journal.get(1, i)).id);
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 4));
    try expect_append_at(&journal, 1, 4);
    try journal.destroy();
}

test "oversized recovery: checkpoint restore keeps every synced entry" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_checkpoint(.{ .section = 0, .size = 0 });
    for (1..4) |section| {
        for (0..10) |i| {
            _ = try append(&journal, section, section * 100 + i, fill(section * 10 + i));
        }
        try journal.sync(&.{section});
    }
    journal.deinit();
    journal = try h.open_checkpoint(.{ .section = 3, .size = 10 * chunk });
    for (1..4) |section| {
        for (0..10) |i| {
            try testing.expectEqual(section * 100 + i, (try journal.get(section, i)).id);
        }
    }
    try journal.destroy();
}

test "oversized recovery: single entry invalid" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    _ = try append(&journal, 1, 1, fill(42));
    try journal.sync(&.{1});
    journal.deinit();
    try resize_values(&h, 1, 0);
    journal = try h.open_tracked();
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 0));
    try journal.destroy();
}

test "oversized recovery: last value one byte short" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    var located: [3]Located = undefined;
    for (&located, 0..) |*slot, i| slot.* = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    try resize_values(&h, 1, byte_end(located[2]) - 1);
    journal = try h.open_tracked();
    _ = try journal.get(1, 0);
    _ = try journal.get(1, 1);
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 2));
    try expect_append_at(&journal, 1, 2);
    try journal.destroy();
}

test "oversized recovery: value blob missing entirely" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    for (0..3) |i| _ = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    try h.storage.remove("test-values", &manager_mod.section_name(1));
    journal = try h.open_tracked();
    for (0..3) |position| {
        try testing.expectError(error.ItemOutOfRange, journal.get(1, position));
    }
    try journal.destroy();
}

test "oversized recovery: appends continue at the truncated position" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    var located: [5]Located = undefined;
    for (&located, 0..) |*slot, i| slot.* = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    try resize_values(&h, 1, byte_end(located[1]));
    journal = try h.open_tracked();
    _ = try journal.get(1, 0);
    _ = try journal.get(1, 1);
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 2));
    for (10..15) |i| _ = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    for (0..5) |i| try testing.expectEqual(10 + i, (try journal.get(1, 2 + i)).id);
    try journal.destroy();
}

/// Append one entry to each of sections 1 to 3, then sync every section, which publishes no
/// marker, so later damage lies above every floor.
fn seed_three_sections(h: *Harness) !void {
    var journal = try h.open_tracked();
    for (1..4) |section| _ = try append(&journal, section, section, fill(section));
    try journal.sync_all();
    journal.deinit();
}

test "oversized recovery: value section lost while its index remains" {
    var h = try Harness.init();
    defer h.deinit();
    try seed_three_sections(&h);
    try h.storage.remove("test-values", &manager_mod.section_name(1));
    var journal = try h.open_tracked();
    // Losing the values removes the corresponding index entries.
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 0));
    _ = try journal.get(2, 0);
    _ = try journal.get(3, 0);
    try journal.destroy();
}

test "oversized recovery: index section lost while its values remain" {
    var h = try Harness.init();
    defer h.deinit();
    try seed_three_sections(&h);
    try h.storage.remove("test-index", &manager_mod.section_name(2));
    var journal = try h.open_tracked();
    _ = try journal.get(1, 0);
    _ = try journal.get(3, 0);
    try testing.expectError(error.SectionOutOfRange, journal.get(2, 0));
    try journal.destroy();
}

test "oversized recovery: index entries outliving unsynced values are truncated" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    var located: [3]Located = undefined;
    for (&located, 0..) |*slot, i| slot.* = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    // Unsynced appends are lost when the journal drops.
    for (10..15) |i| _ = try append(&journal, 1, i, fill(i));
    journal.deinit();
    try resize_values(&h, 1, byte_end(located[2]));
    journal = try h.open_tracked();
    for (0..3) |i| try testing.expectEqual(i, (try journal.get(1, i)).id);
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 3));
    try journal.destroy();
}

test "oversized recovery: values ahead of the index are released and reused" {
    var h = try Harness.init_page(@intCast(base.TestEntry.fixed_size));
    defer h.deinit();
    var journal = try h.open_tracked();
    var located: [3]Located = undefined;
    for (&located, 0..) |*slot, i| slot.* = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    // Keep only the first two index pages (20 logical bytes plus 12 checksum bytes each).
    const opened = try h.storage.open("test-index", &manager_mod.section_name(1));
    try opened.blob.resize(2 * (base.TestEntry.fixed_size + 12));
    try opened.blob.sync();
    opened.blob.close();
    journal = try h.open_tracked();
    for (located[0..2], 0..) |slot, i| {
        try testing.expectEqual(i, (try journal.get(1, slot.position)).id);
        try expect_value(&journal, 1, slot, fill(i));
    }
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 2));
    var appended: [3]Located = undefined;
    for (&appended, 10..) |*slot, i| {
        slot.* = try append(&journal, 1, i, fill(i));
        try testing.expectEqual(i - 8, slot.position);
        try testing.expectEqual(i, (try journal.get(1, slot.position)).id);
        try expect_value(&journal, 1, slot.*, fill(i));
    }
    try journal.sync(&.{1});
    journal.deinit();
    journal = try h.open_tracked();
    for (located[0..2], 0..) |slot, i| try expect_value(&journal, 1, slot, fill(i));
    for (appended, 10..) |slot, i| {
        try testing.expectEqual(i, (try journal.get(1, slot.position)).id);
        try expect_value(&journal, 1, slot, fill(i));
    }
    _ = try journal.get(1, 4);
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 5));
    try journal.destroy();
}

/// Durably resize the index blob of `section` to `length` bytes.
fn resize_index(h: *Harness, section: u64, length: u64) !void {
    const opened = try h.storage.open("test-index", &manager_mod.section_name(section));
    defer opened.blob.close();
    try opened.blob.resize(length);
    try opened.blob.sync();
}

/// One physical index page of a one-entry-per-page harness.
const entry_page: u64 = base.TestEntry.fixed_size + 12;

test "oversized recovery: partial index entry" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    for (0..3) |i| _ = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    // commonware's sizes: three 24-byte entries plus 10 bytes of a partial one.
    try resize_index(&h, 1, 3 * 24 + 10);
    journal = try h.open_tracked();
    for (0..3) |i| try testing.expectEqual(i, (try journal.get(1, i)).id);
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 3));
    try expect_append_at(&journal, 1, 3);
    try journal.destroy();
}

test "oversized recovery: only a partial index entry" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    _ = try append(&journal, 1, 1, fill(42));
    try journal.sync(&.{1});
    journal.deinit();
    // Less than one entry remains.
    try resize_index(&h, 1, 10);
    journal = try h.open_tracked();
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 0));
    try expect_append_at(&journal, 1, 0);
    try journal.destroy();
}

test "oversized recovery: crash with the index truncated ahead of the values" {
    var h = try Harness.init_page(@intCast(base.TestEntry.fixed_size));
    defer h.deinit();
    var journal = try h.open_tracked();
    for (0..5) |i| _ = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    // Keep two index entries and leave the values intact.
    try resize_index(&h, 1, 2 * entry_page);
    journal = try h.open_tracked();
    for (0..2) |i| try testing.expectEqual(i, (try journal.get(1, i)).id);
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 2));
    try expect_append_at(&journal, 1, 2);
    try journal.destroy();
}

test "oversized recovery: crash with the values truncated ahead of the index" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    var located: [5]Located = undefined;
    for (&located, 0..) |*slot, i| slot.* = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    // Keep two values and leave the index intact.
    try resize_values(&h, 1, byte_end(located[1]));
    journal = try h.open_tracked();
    for (0..2) |i| try testing.expectEqual(i, (try journal.get(1, i)).id);
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 2));
    try expect_append_at(&journal, 1, 2);
    try journal.destroy();
}

test "oversized recovery: reading a value with a short size fails" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_checkpoint(.{ .section = 0, .size = 0 });
    defer journal.deinit();
    const located = try append(&journal, 1, 1, fill(42));
    // Sizes 0 through 3 cannot hold the checksum, 4 holds no data, 5 too little; one byte
    // short fails to verify.
    for ([_]u32{ 0, 1, 2, 3, 4, 5, located.size - 1 }) |size| {
        if (journal.get_value(1, located.offset, size)) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    try expect_value(&journal, 1, located, fill(42));
}

const glob_mod = @import("glob.zig");

/// Durably write one orphan value into each of `sections`, without any index entry.
fn write_orphans(h: *Harness, sections: []const u64) !void {
    const cfg: glob_mod.Config(TestValue) = .{
        .partition = "test-values",
        .codec_config = {},
        .write_buffer = 1024,
    };
    var recovery = try glob_mod.Recovery(TestValue).init(gpa, h.storage.interface(), cfg);
    var glob = recovery.finish();
    defer glob.deinit();
    for (sections) |section| {
        _ = try glob.append(section, fill(section));
        try glob.sync(&.{section});
    }
}

/// Append one entry to each of `sections` of a tracked journal, syncing each.
fn seed_sections(h: *Harness, sections: []const u64) !void {
    var journal = try h.open_tracked();
    defer journal.deinit();
    for (sections) |section| {
        _ = try append(&journal, section, section, fill(section));
        try journal.sync(&.{section});
    }
}

test "oversized recovery: an orphan value section is removed" {
    var h = try Harness.init();
    defer h.deinit();
    try seed_sections(&h, &.{ 1, 2 });
    try write_orphans(&h, &.{3});
    var journal = try h.open_tracked();
    _ = try journal.get(1, 0);
    _ = try journal.get(2, 0);
    try testing.expectEqual(2, journal.newest_section());
    try testing.expectEqual(2, journal.values.newest_section());
    try journal.destroy();
}

test "oversized recovery: multiple orphan value sections are removed" {
    var h = try Harness.init();
    defer h.deinit();
    try seed_sections(&h, &.{1});
    try write_orphans(&h, &.{ 2, 3, 4 });
    var journal = try h.open_tracked();
    _ = try journal.get(1, 0);
    try testing.expectEqual(1, journal.newest_section());
    try testing.expectEqual(1, journal.values.newest_section());
    try journal.destroy();
}

test "oversized recovery: values without any index are removed" {
    var h = try Harness.init();
    defer h.deinit();
    try write_orphans(&h, &.{ 1, 2, 3 });
    var journal = try h.open_tracked();
    try testing.expectEqual(null, journal.newest_section());
    try testing.expectEqual(null, journal.oldest_section());
    try testing.expectEqual(null, journal.values.newest_section());
    try journal.destroy();
}

test "oversized recovery: a section freed of orphan values accepts appends from zero" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    const first = try append(&journal, 1, 1, fill(1));
    try journal.sync(&.{1});
    journal.deinit();
    try write_orphans(&h, &.{ 2, 3 });
    journal = try h.open_tracked();
    try testing.expectEqual(1, (try journal.get(1, 0)).id);
    try expect_value(&journal, 1, first, fill(1));
    const located = try append(&journal, 2, 42, fill(42));
    try testing.expectEqual(0, located.position);
    try testing.expectEqual(42, (try journal.get(2, 0)).id);
    try expect_value(&journal, 2, located, fill(42));
    try journal.sync(&.{2});
    journal.deinit();
    journal = try h.open_tracked();
    _ = try journal.get(1, 0);
    _ = try journal.get(2, 0);
    try testing.expectEqual(2, journal.newest_section());
    try journal.destroy();
}

test "oversized recovery: checkpoint restore keeps every synced section" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_checkpoint(.{ .section = 0, .size = 0 });
    for (1..4) |section| {
        _ = try append(&journal, section, section, fill(section));
        try journal.sync(&.{section});
    }
    journal.deinit();
    journal = try h.open_checkpoint(.{ .section = 3, .size = chunk });
    for (1..4) |section| try testing.expectEqual(section, (try journal.get(section, 0)).id);
    try testing.expectEqual(3, journal.newest_section());
    try journal.destroy();
}

test "oversized recovery: an empty index section is kept and its orphan removed" {
    var h = try Harness.init();
    defer h.deinit();
    try seed_sections(&h, &.{1});
    try write_orphans(&h, &.{2});
    try resize_index(&h, 1, 0);
    var journal = try h.open_tracked();
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 0));
    try testing.expectEqual(1, journal.newest_section());
    try testing.expectEqual(1, journal.values.newest_section());
    try journal.destroy();
}

test "oversized recovery: orphan value sections in gaps are removed" {
    var h = try Harness.init();
    defer h.deinit();
    try seed_sections(&h, &.{ 1, 3, 5 });
    try write_orphans(&h, &.{ 2, 4, 6 });
    var journal = try h.open_tracked();
    for ([_]u64{ 1, 3, 5 }) |section| {
        try testing.expectEqual(section, (try journal.get(section, 0)).id);
    }
    try testing.expectEqual(1, journal.oldest_section());
    try testing.expectEqual(5, journal.newest_section());
    var retained = journal.values.sections();
    for ([_]u64{ 1, 3, 5 }) |section| try testing.expectEqual(section, retained.next().?);
    try testing.expectEqual(null, retained.next());
    try journal.destroy();
}

const Crc32 = @import("cryptography").crc32.Crc32;

test "oversized recovery: an index extension after prefix loss is discarded" {
    var h = try Harness.init();
    defer h.deinit();
    try seed_three_sections(&h);
    // Erase section 1's index by truncation and section 2's by removal, then write two pages
    // of bytes with no valid checksum slots in each place.
    for ([_]u64{ 1, 2 }) |section| {
        const name = manager_mod.section_name(section);
        var opened = try h.storage.open("test-index", &name);
        const original = opened.len;
        if (section == 1) {
            try opened.blob.resize(0);
            try opened.blob.sync();
            opened.blob.close();
        } else {
            opened.blob.close();
            try h.storage.remove("test-index", &name);
        }
        opened = try h.storage.open("test-index", &name);
        defer opened.blob.close();
        const zeros = try gpa.alloc(u8, @intCast(original * 2));
        defer gpa.free(zeros);
        @memset(zeros, 0);
        try opened.blob.write_at(0, zeros, .{});
        try opened.blob.sync();
    }
    var journal = try h.open_tracked();
    for ([_]u64{ 1, 2 }) |section| {
        try testing.expectError(error.ItemOutOfRange, journal.get(section, 0));
        const name = manager_mod.section_name(section);
        try testing.expectEqual(0, (try h.storage.durable_len("test-index", &name)).?);
        const located = try append(&journal, section, section, fill(section));
        try testing.expectEqual(0, located.position);
    }
    try journal.sync(&.{ 1, 2 });
    journal.deinit();
    // The sentinel entries written after recovery survive a reopen.
    journal = try h.open_tracked();
    for ([_]u64{ 1, 2 }) |section| {
        const stored = try journal.get(section, 0);
        try testing.expectEqual(section, stored.id);
        const value = try journal.get_value(section, stored.value_offset, stored.value_size);
        try testing.expectEqual(fill(section), value);
    }
    try journal.destroy();
}

test "oversized recovery: trailing value garbage is truncated" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    var located: [2]Located = undefined;
    for (&located, 0..) |*slot, i| slot.* = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    const expected_next = byte_end(located[1]);
    // A value write that crashed before its index entry leaves 100 garbage bytes.
    const opened = try h.storage.open("test-values", &manager_mod.section_name(1));
    try testing.expectEqual(expected_next, opened.len);
    try opened.blob.write_at(opened.len, &@as([100]u8, @splat(0xDE)), .{});
    try opened.blob.sync();
    opened.blob.close();
    journal = try h.open_tracked();
    for (0..2) |i| try testing.expectEqual(i, (try journal.get(1, i)).id);
    const appended = try append(&journal, 1, 99, fill(99));
    try testing.expectEqual(2, appended.position);
    try testing.expectEqual(expected_next, appended.offset);
    try testing.expectEqual(99, (try journal.get(1, 2)).id);
    try journal.destroy();
}

test "oversized recovery: an entry whose value range overflows is dropped" {
    var h = try Harness.init_page(@intCast(base.TestEntry.fixed_size));
    defer h.deinit();
    var journal = try h.open_tracked();
    _ = try append(&journal, 1, 1, fill(1));
    try journal.sync(&.{1});
    journal.deinit();
    // A page with a valid checksum holding an entry whose offset plus size overflows.
    var page: [base.TestEntry.fixed_size + 12]u8 = @splat(0);
    std.mem.writeInt(u64, page[0..8], 1, .big);
    std.mem.writeInt(u64, page[8..16], std.math.maxInt(u64) - 10, .big);
    std.mem.writeInt(u32, page[16..20], 100, .big);
    std.mem.writeInt(u16, page[20..22], base.TestEntry.fixed_size, .big);
    std.mem.writeInt(u32, page[22..26], Crc32.checksum(page[0..20]), .big);
    const opened = try h.storage.open("test-index", &manager_mod.section_name(1));
    try opened.blob.write_at(0, &page, .{});
    try opened.blob.sync();
    opened.blob.close();
    journal = try h.open_tracked();
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 0));
    const appended = try append(&journal, 1, 99, fill(99));
    try testing.expectEqual(0, appended.position);
    // The values were truncated to zero with the entry.
    try testing.expectEqual(0, appended.offset);
    try journal.destroy();
}

test "oversized recovery: an emptied section stays open and reuses offsets from zero" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    for (0..3) |i| _ = try append(&journal, 1, i, fill(i));
    _ = try append(&journal, 2, 10, fill(10));
    // One sync of every section publishes no marker, so the damage lies above every floor.
    try journal.sync_all();
    journal.deinit();
    try resize_index(&h, 1, 0);
    journal = try h.open_tracked();
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 0));
    try testing.expectEqual(10, (try journal.get(2, 0)).id);
    try testing.expectEqual(1, journal.oldest_section());
    // Recovery removed the orphaned value bytes before the section is reused.
    const located = try append(&journal, 1, 99, fill(99));
    try testing.expectEqual(0, located.position);
    try testing.expectEqual(0, located.offset);
    try testing.expectEqual(99, (try journal.get(1, 0)).id);
    try expect_value(&journal, 1, located, fill(99));
    try journal.sync_all();
    journal.deinit();
    journal = try h.open_tracked();
    try testing.expectEqual(99, (try journal.get(1, 0)).id);
    try testing.expectEqual(10, (try journal.get(2, 0)).id);
    try journal.destroy();
}

test "oversized recovery: section numbers near the maximum" {
    var h = try Harness.init();
    defer h.deinit();
    const max = std.math.maxInt(u64);
    const sections = [_]u64{ max - 3, max - 2, max - 1 };
    var journal = try h.open_tracked();
    var located: [3]Located = undefined;
    for (&located, sections) |*slot, section| {
        slot.* = try append(&journal, section, section, fill(section & 0xFF));
    }
    try journal.sync_all();
    journal.deinit();
    // Lose the middle section's value.
    try resize_values(&h, sections[1], byte_end(located[1]) - 1);
    journal = try h.open_tracked();
    try testing.expectEqual(sections[0], (try journal.get(sections[0], 0)).id);
    try testing.expectEqual(sections[2], (try journal.get(sections[2], 0)).id);
    try testing.expectError(error.ItemOutOfRange, journal.get(sections[1], 0));
    const appended = try append(&journal, sections[1], 999, fill(0xAB));
    try testing.expectEqual(0, appended.position);
    try journal.destroy();
}

test "oversized recovery: a crash during recovery's index truncation" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    var located: [5]Located = undefined;
    for (&located, 0..) |*slot, i| slot.* = try append(&journal, 1, i, fill(i));
    try journal.sync(&.{1});
    journal.deinit();
    // The first crash loses the last two values.
    try resize_values(&h, 1, byte_end(located[2]));
    // Recovery was interrupted truncating the index from five entries to three: commonware
    // keeps four chunks of the raw blob as the intermediate state.
    try resize_index(&h, 1, 4 * chunk);
    journal = try h.open_tracked();
    for (located[0..3], 0..) |slot, i| {
        try testing.expectEqual(i, (try journal.get(1, i)).id);
        try expect_value(&journal, 1, slot, fill(i));
    }
    try testing.expectError(error.ItemOutOfRange, journal.get(1, 3));
    const appended = try append(&journal, 1, 100, fill(0xFF));
    try testing.expectEqual(3, appended.position);
    // No gap: the new value starts where entry 2's ended.
    try testing.expectEqual(byte_end(located[2]), appended.offset);
    try journal.destroy();
}

test "oversized recovery: a crash during orphan cleanup" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    const first = try append(&journal, 1, 1, fill(1));
    try journal.sync(&.{1});
    journal.deinit();
    try write_orphans(&h, &.{ 2, 3, 4 });
    // The interrupted cleanup removed section 2 only.
    try h.storage.remove("test-values", &manager_mod.section_name(2));
    journal = try h.open_tracked();
    try testing.expectEqual(1, (try journal.get(1, 0)).id);
    try expect_value(&journal, 1, first, fill(1));
    try testing.expectEqual(1, journal.oldest_section());
    try testing.expectEqual(1, journal.newest_section());
    try testing.expectEqual(1, journal.values.newest_section());
    try testing.expectEqual(0, (try append(&journal, 2, 42, fill(42))).position);
    try journal.destroy();
}

test "oversized recovery: last of a pruned section reports the prune" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_checkpoint(.{ .section = 0, .size = 0 });
    _ = try append(&journal, 0, 1, fill(1));
    _ = try append(&journal, 1, 2, fill(1));
    try journal.sync_all();
    try testing.expect(try journal.prune(1));
    try testing.expectError(error.AlreadyPrunedToSection, journal.last(0));
    try testing.expect((try journal.last(1)) != null);
    try journal.destroy();
}

test "oversized recovery: a tracked open keeps synced entries below a torn rewrite" {
    var h = try Harness.init();
    defer h.deinit();
    // Four synced entries fill index page 0 and leave a 16-byte partial page 1.
    var journal = try h.open_tracked();
    for (0..4) |id| _ = try append(&journal, 1, id, fill(id));
    try journal.sync(&.{1});
    // An empty flush publishes the section's marker.
    try journal.sync(&.{});
    // Five more entries rewrite page 1 in full and write a partial page 2; the values are lost.
    for (4..9) |id| _ = try append(&journal, 1, id, fill(id));
    try journal.index.sync(&.{1});
    journal.deinit();
    h.storage.crash();
    // Lose one byte of the page-1 rewrite beyond its durable 16 bytes, so page 1's short
    // checksum slot still validates while page 2 looks like the tail.
    const opened = try h.storage.open("test-index", &manager_mod.section_name(1));
    try opened.blob.write_at(64 + 12 + 16 + 7, &.{0}, .{});
    try opened.blob.sync();
    opened.blob.close();
    journal = try h.open_tracked();
    try testing.expectEqual(4 * chunk, try journal.size(1));
    const stored = try journal.get(1, 3);
    const value = try journal.get_value(1, stored.value_offset, stored.value_size);
    try testing.expectEqual(fill(3), value);
    try journal.destroy();
}
