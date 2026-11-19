//! Tests of the variable contiguous journal: commonware's shared contiguous suite
//! (`journal/contiguous/tests.rs`, with `items_per_section = 10`, 1024-byte pages, and a
//! 10-page cache) and the variable journal's own tests (`journal/contiguous/variable.rs`).
//!
//! commonware's `start_and_recover` becomes `crash()`. Snapshot readers are not ported, so
//! tests that replay through one replay the journal directly.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const contiguous = @import("mod.zig");
const variable = @import("variable.zig");
const authenticated = @import("../authenticated.zig");

const gpa = testing.allocator;
const Storage = mocks.Storage;
const CacheRef = paged.CacheRef;
const Journal = variable.Journal(u64);
const Bounds = contiguous.Bounds;
const Bytes = []const u8;
const bytes_cfg: codec.Cfg(Bytes) = .{ .range = .full(), .item = {} };

const Harness = struct {
    storage: Storage,
    cache_ref: CacheRef,
    items_per_section: u64,
    partition: []const u8,
    compression: ?u8 = null,

    fn init(partition: []const u8, items_per_section: u64) !Harness {
        return .{
            .storage = Storage.init(gpa),
            .cache_ref = try CacheRef.init(gpa, 1024, 10),
            .items_per_section = items_per_section,
            .partition = partition,
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg_for(self: *Harness, comptime V: type, codec_config: codec.Cfg(V)) variable.Config(V) {
        return .{
            .partition = self.partition,
            .items_per_section = self.items_per_section,
            .compression = self.compression,
            .codec_config = codec_config,
            .cache_ref = &self.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
    }

    fn cfg(self: *Harness) variable.Config(u64) {
        return self.cfg_for(u64, {});
    }

    fn open(self: *Harness) !Journal {
        return Journal.init(gpa, self.storage.interface(), self.cfg());
    }

    fn open_at_most(self: *Harness, max_size: u64) !Journal {
        return Journal.init_at_most(gpa, self.storage.interface(), self.cfg(), max_size);
    }

    fn open_at_size(self: *Harness, size: u64) !Journal {
        return Journal.init_at_size(gpa, self.storage.interface(), self.cfg(), size);
    }
};

/// Replay `range` and check every item is `position * scale`, returning the item count.
fn replay_count(journal: *Journal, range: Bounds, buffer: usize, scale: u64) !u64 {
    var replay = try journal.replay(range, buffer);
    defer replay.deinit();
    var next = range.start;
    while (try replay.next()) |batch| {
        try testing.expectEqual(next, batch.start);
        for (batch.items, 0..) |item, index| {
            try testing.expectEqual((batch.start + index) * scale, item);
        }
        next += batch.items.len;
    }
    try testing.expectEqual(range.end, next);
    return next - range.start;
}

fn append_scaled(journal: *Journal, count: u64, scale: u64) !void {
    for (0..count) |index| {
        try testing.expectEqual(index, try journal.append(index * scale));
    }
}

fn expect_items(journal: *Journal, start: u64, end: u64, scale: u64) !void {
    for (start..end) |position| {
        try testing.expectEqual(position * scale, try journal.read(position));
    }
}

test "variable: empty journal bounds" {
    var h = try Harness.init("empty", 10);
    defer h.deinit();
    var journal = try h.open();
    try testing.expect(journal.get_bounds().is_empty());
    try testing.expectEqual(0, journal.get_bounds().start);
    try journal.destroy();
}

test "variable: bounds after prune" {
    var h = try Harness.init("bounds-after-prune", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 30, 100);
    try testing.expectEqual(Bounds{ .start = 0, .end = 30 }, journal.get_bounds());
    // Pruning is blob-aligned.
    _ = try journal.prune(10);
    try testing.expectEqual(Bounds{ .start = 10, .end = 30 }, journal.get_bounds());
    _ = try journal.prune(25);
    try testing.expectEqual(Bounds{ .start = 20, .end = 30 }, journal.get_bounds());
    _ = try journal.prune(30);
    try testing.expectEqual(Bounds{ .start = 30, .end = 30 }, journal.get_bounds());
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expect(journal.get_bounds().is_empty());
    try testing.expectEqual(30, journal.size());
    try journal.destroy();
}

test "variable: append, read, and sequential positions" {
    var h = try Harness.init("sequential-appends", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 25, 10);
    try testing.expectEqual(25, journal.size());
    try expect_items(&journal, 0, 25, 10);
    try journal.destroy();
}

test "variable: replay from start, middle, and unsealed tail" {
    var h = try Harness.init("replay", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 17, 10);
    try testing.expectEqual(17, try replay_count(&journal, .{ .start = 0, .end = 17 }, 1024, 10));
    try testing.expectEqual(10, try replay_count(&journal, .{ .start = 7, .end = 17 }, 1024, 10));
    try testing.expectEqual(4, try replay_count(&journal, .{ .start = 13, .end = 17 }, 1024, 10));
    // A buffer smaller than one item still yields every item.
    try testing.expectEqual(17, try replay_count(&journal, .{ .start = 0, .end = 17 }, 7, 10));
    try testing.expectEqual(0, try replay_count(&journal, .{ .start = 0, .end = 0 }, 1024, 10));
    try testing.expectEqual(0, try replay_count(&journal, .{ .start = 17, .end = 17 }, 1024, 10));
    try journal.destroy();
}

/// commonware's `check_replay_batches`: batches tile `range`, never cross a blob, and exceed
/// `buffer` by less than one nine-byte frame.
fn check_replay_batches(journal: *Journal, range: Bounds, buffer: usize) !void {
    var replay = try journal.replay(range, buffer);
    defer replay.deinit();
    var next = range.start;
    while (try replay.next()) |batch| {
        try testing.expectEqual(next, batch.start);
        try testing.expect(batch.items.len > 0);
        try testing.expect((batch.items.len - 1) * 9 < buffer);
        const end = batch.start + batch.items.len;
        try testing.expect(end <= range.end);
        try testing.expectEqual(batch.start / 10, (end - 1) / 10);
        for (batch.items, 0..) |item, index| try testing.expectEqual((next + index) * 10, item);
        next = end;
    }
    try testing.expectEqual(range.end, next);
}

test "variable: replay batches" {
    var h = try Harness.init("replay-batches", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 37, 10);
    const ranges = [_]Bounds{
        .{ .start = 0, .end = 37 },  .{ .start = 7, .end = 25 },  .{ .start = 13, .end = 14 },
        .{ .start = 20, .end = 20 }, .{ .start = 30, .end = 37 },
    };
    for ([_]usize{ 9, 40, 4096 }) |buffer| {
        for (ranges) |range| try check_replay_batches(&journal, range, buffer);
    }
    try testing.expectError(error.ItemOutOfRange, journal.replay(.{ .start = 0, .end = 38 }, 40));
    try testing.expectError(error.ItemOutOfRange, journal.replay(.{ .start = 10, .end = 5 }, 40));
    _ = try journal.prune(10);
    try check_replay_batches(&journal, .{ .start = 10, .end = 37 }, 40);
    try testing.expectError(error.ItemPruned, journal.replay(.{ .start = 5, .end = 20 }, 40));
    try journal.destroy();
}

test "variable: prune retains size and positions stay stable" {
    var h = try Harness.init("position-stability", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 20, 100);
    try testing.expect(try journal.prune(10));
    try testing.expect(!try journal.prune(10));
    try testing.expectEqual(20, journal.size());
    for (20..25) |position| try testing.expectEqual(position, try journal.append(position * 100));
    try expect_items(&journal, 10, 25, 100);
    try testing.expectEqual(15, try replay_count(&journal, .{ .start = 10, .end = 25 }, 1024, 100));
    try testing.expectError(error.ItemPruned, journal.read(9));
    try testing.expectError(error.ItemOutOfRange, journal.read(25));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 10, .end = 25 }, journal.get_bounds());
    try expect_items(&journal, 10, 25, 100);
    try journal.destroy();
}

test "variable: prune then append and prune beyond size" {
    var h = try Harness.init("prune-then-append", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 10, 1);
    _ = try journal.prune(100);
    try testing.expect(journal.get_bounds().is_empty());
    try testing.expectEqual(10, try journal.append(999));
    try testing.expectEqual(11, journal.size());
    try testing.expectEqual(999, try journal.read(10));
    try journal.destroy();
}

test "variable: persistence after prune" {
    var h = try Harness.init("persistence-after-prune", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 25, 100);
    try testing.expect(try journal.prune(10));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(25, journal.size());
    for (0..10) |position| try testing.expectError(error.ItemPruned, journal.read(position));
    try expect_items(&journal, 10, 25, 100);
    try testing.expectEqual(25, try journal.append(999));
    try testing.expectEqual(999, try journal.read(25));
    try journal.destroy();
}

test "variable: read by position and read many" {
    var h = try Harness.init("read-by-position", 10);
    defer h.deinit();
    var journal = try h.open();
    for (0..1000) |position| {
        _ = try journal.append(position * 100);
        try testing.expectEqual(position * 100, try journal.read(position));
    }
    try expect_items(&journal, 0, 1000, 100);
    var items: [3]u64 = undefined;
    try journal.read_many(&.{ 1, 4, 12 }, &items);
    try testing.expectEqualSlices(u64, &.{ 100, 400, 1200 }, &items);
    try testing.expectError(error.ItemOutOfRange, journal.read_many(&.{ 1, 1000 }, &items[0..2].*));
    try journal.destroy();
}

test "variable: bounded initialization" {
    var h = try Harness.init("rewind", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 20, 100);
    try journal.sync();
    journal.deinit();
    journal = try h.open_at_most(12);
    try testing.expectEqual(12, journal.size());
    try expect_items(&journal, 0, 12, 100);
    for (12..20) |position| try testing.expectError(error.ItemOutOfRange, journal.read(position));
    try testing.expectEqual(12, try journal.append(999));
    try testing.expectEqual(999, try journal.read(12));
    try journal.sync();
    journal.deinit();
    // A bound above the end does not grow the journal.
    journal = try h.open_at_most(20);
    try testing.expectEqual(13, journal.size());
    journal.deinit();
    journal = try h.open_at_most(0);
    try testing.expect(journal.get_bounds().is_empty());
    try testing.expectEqual(0, try journal.append(42));
    try testing.expectEqual(42, try journal.read(0));
    try journal.destroy();
}

test "variable: bounded initialization after prune" {
    var h = try Harness.init("rewind-after-prune", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 30, 100);
    _ = try journal.prune(10);
    try journal.sync();
    journal.deinit();
    journal = try h.open_at_most(20);
    try testing.expectEqual(Bounds{ .start = 10, .end = 20 }, journal.get_bounds());
    try expect_items(&journal, 10, 20, 100);
    try testing.expectEqual(20, try journal.append(999));
    try journal.sync();
    journal.deinit();
    try testing.expectError(error.ItemPruned, h.open_at_most(5));
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 10, .end = 21 }, journal.get_bounds());
    try journal.destroy();
}

test "variable: section boundary behavior" {
    var h = try Harness.init("section-boundary", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 10, 100);
    try testing.expectEqual(10, try journal.append(999));
    _ = try journal.prune(10);
    try testing.expectEqual(10, journal.pruning_boundary());
    try testing.expectError(error.ItemPruned, journal.read(9));
    try testing.expectEqual(999, try journal.read(10));
    try testing.expectEqual(11, try journal.append(888));
    try journal.sync();
    journal.deinit();
    journal = try h.open_at_most(10);
    try testing.expectEqual(Bounds{ .start = 10, .end = 10 }, journal.get_bounds());
    try testing.expectEqual(10, try journal.append(777));
    try testing.expectEqual(777, try journal.read(10));
    try journal.destroy();
}

test "variable: destroy and reinit" {
    var h = try Harness.init("destroy-and-reinit", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 20, 100);
    _ = try journal.prune(10);
    try journal.destroy();
    journal = try h.open();
    try testing.expect(journal.get_bounds().is_empty());
    try testing.expectEqual(0, journal.size());
    try journal.destroy();
    for ([_][]const u8{ "destroy-and-reinit_data", "destroy-and-reinit_offsets-blobs" }) |name| {
        const indices = try contiguous.blobs.indices(gpa, h.storage.interface(), name);
        defer gpa.free(indices);
        try testing.expectEqual(0, indices.len);
    }
}

test "variable: append many" {
    var h = try Harness.init("append-many", 10);
    defer h.deinit();
    var journal = try h.open();
    try testing.expectError(error.EmptyAppend, journal.append_many(&.{}));
    try testing.expectEqual(0, journal.size());
    try testing.expectEqual(2, try journal.append_many(&.{ 0, 10, 20 }));
    try testing.expectEqual(3, try journal.append(30));
    var items: [25]u64 = undefined;
    for (&items, 4..) |*item, position| item.* = position * 10;
    try testing.expectEqual(28, try journal.append_many(&items));
    try expect_items(&journal, 0, 29, 10);
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try expect_items(&journal, 0, 29, 10);
    try journal.destroy();
}

test "variable: start sync durability" {
    var h = try Harness.init("variable-start-sync", 3);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 7, 10);
    try (try journal.start_sync()).wait_release();
    journal.deinit();
    h.storage.crash();
    journal = try h.open();
    try testing.expectEqual(7, journal.size());
    try expect_items(&journal, 0, 7, 10);
    try testing.expectEqual(7, journal.recovery_watermark());
    try journal.destroy();
}

test "variable: replay range" {
    var h = try Harness.init("replay-range", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 40, 100);
    try testing.expectEqual(18, try replay_count(&journal, .{ .start = 7, .end = 25 }, 20, 100));
    try testing.expectEqual(0, try replay_count(&journal, .{ .start = 5, .end = 5 }, 20, 100));
    try testing.expectError(error.ItemOutOfRange, journal.replay(.{ .start = 0, .end = 41 }, 20));
    try testing.expectError(error.ItemOutOfRange, journal.replay(.{ .start = 10, .end = 5 }, 20));
    // Replay after a prune starts at the boundary.
    _ = try journal.prune(20);
    try testing.expectError(error.ItemPruned, journal.replay(.{ .start = 19, .end = 40 }, 20));
    try testing.expectEqual(20, try replay_count(&journal, .{ .start = 20, .end = 40 }, 20, 100));
    try testing.expectError(error.ItemOutOfRange, journal.replay(.{ .start = 41, .end = 40 }, 20));
    try journal.destroy();
}

test "variable: prune durability survives crash" {
    var h = try Harness.init("variable-prune-durability", 3);
    defer h.deinit();
    var journal = try h.open();
    // Fill two sections plus an unsynced tail, then prune into section 1. The prune's sync is
    // the only durability point covering these items.
    try append_scaled(&journal, 8, 100);
    try testing.expect(try journal.prune(3));
    journal.deinit();
    h.storage.crash();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 3, .end = 8 }, journal.get_bounds());
    try expect_items(&journal, 3, 8, 100);
    try journal.destroy();
}

test "variable: multiple sequential prunes" {
    var h = try Harness.init("sequential-prunes", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 40, 100);
    try testing.expect(try journal.prune(10));
    try testing.expect(try journal.prune(20));
    try testing.expect(try journal.prune(30));
    try testing.expectEqual(Bounds{ .start = 30, .end = 40 }, journal.get_bounds());
    try expect_items(&journal, 30, 40, 100);
    try testing.expectError(error.ItemPruned, journal.read(29));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 30, .end = 40 }, journal.get_bounds());
    try expect_items(&journal, 30, 40, 100);
    try journal.destroy();
}

test "variable: prune all then reinit" {
    var h = try Harness.init("prune-all", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 100, 100);
    try testing.expect(try journal.prune(100));
    try testing.expectEqual(Bounds{ .start = 100, .end = 100 }, journal.get_bounds());
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 100, .end = 100 }, journal.get_bounds());
    try testing.expectEqual(100, try journal.append(10000));
    try testing.expectEqual(10000, try journal.read(100));
    try journal.destroy();
}

test "variable: recovery prunes offsets behind pruned data" {
    var h = try Harness.init("recovery-prune-crash", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 40, 100);
    _ = try journal.prune(10);
    try testing.expectEqual(10, journal.pruning_boundary());
    // Persist data pruning to 20 while the offsets still retain positions 10 to 19.
    try testing.expect(try journal.test_prune_data(2));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 20, .end = 40 }, journal.get_bounds());
    try testing.expectError(error.ItemPruned, journal.read(10));
    try testing.expectEqual(2000, try journal.read(20));
    try testing.expectEqual(3900, try journal.read(39));
    try journal.destroy();
}

test "variable: recovery rejects offsets pruned ahead of data" {
    var h = try Harness.init("recovery-offsets-ahead", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 40, 100);
    // Normal pruning cannot produce offsets ahead of the data floor.
    _ = try journal.test_prune_offsets(20);
    _ = try journal.test_prune_data(1);
    try journal.sync();
    journal.deinit();
    try testing.expectError(error.Corruption, h.open());
}

test "variable: recovery rebuilds offsets behind appended data" {
    var h = try Harness.init("recovery-append-crash", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 15, 100);
    // Append five frames to the data tail only; the offsets keep 15 entries.
    for (15..20) |position| _ = try journal.test_append_data(position * 100);
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 0, .end = 20 }, journal.get_bounds());
    try expect_items(&journal, 0, 20, 100);
    try testing.expectEqual(20, journal.test_offsets_size());
    try journal.destroy();
}

test "variable: recovery after a crash keeps the synced prefix" {
    var h = try Harness.init("recovery-crash-prefix", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 25, 100);
    try journal.sync();
    // Unsynced appends, including a rollover, are lost by the crash.
    for (25..33) |position| _ = try journal.append(position * 100);
    journal.deinit();
    h.storage.crash();
    journal = try h.open();
    const end = journal.size();
    try testing.expect(end >= 25 and end <= 33);
    try expect_items(&journal, 0, end, 100);
    try testing.expectEqual(end, try journal.append(1));
    try journal.destroy();
}

test "variable: recovery truncates a torn trailing frame" {
    var h = try Harness.init("recovery-torn-frame", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 5, 100);
    try journal.sync();
    // Half a frame past the acknowledged end: a torn write.
    _ = try journal.blobs.tail.append(&.{ 0x08, 1, 2, 3 });
    try journal.blobs.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 0, .end = 5 }, journal.get_bounds());
    try testing.expectEqual(45, journal.blobs.tail.size());
    try testing.expectEqual(5, try journal.append(500));
    try expect_items(&journal, 0, 6, 100);
    try journal.destroy();
}

test "variable: init at size zero, at a blob boundary, and mid blob" {
    for ([_]u64{ 0, 10, 7 }) |size| {
        var h = try Harness.init("init-at-size", 5);
        defer h.deinit();
        var journal = try h.open_at_size(size);
        try testing.expectEqual(size, journal.size());
        try testing.expect(journal.get_bounds().is_empty());
        try testing.expectEqual(size, try journal.append(1000));
        try testing.expectEqual(size + 1, try journal.append(1001));
        try testing.expectEqual(1000, try journal.read(size));
        try testing.expectEqual(1001, try journal.read(size + 1));
        try journal.destroy();
    }
}

test "variable: init at size persistence" {
    var h = try Harness.init("init-at-size-persist", 5);
    defer h.deinit();
    var journal = try h.open_at_size(15);
    for (0..5) |index| try testing.expectEqual(15 + index, try journal.append(1500 + index));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 15, .end = 20 }, journal.get_bounds());
    for (0..5) |index| try testing.expectEqual(1500 + index, try journal.read(15 + index));
    try testing.expectEqual(20, try journal.append(9999));
    try journal.destroy();
}

test "variable: init at size persistence without data and mid blob" {
    for ([_]u64{ 15, 7 }) |size| {
        var h = try Harness.init("init-at-size-persist-empty", 5);
        defer h.deinit();
        var journal = try h.open_at_size(size);
        try journal.sync();
        journal.deinit();
        journal = try h.open();
        try testing.expectEqual(Bounds{ .start = size, .end = size }, journal.get_bounds());
        try testing.expectEqual(size, try journal.append(1));
        try testing.expectEqual(size + 1, try journal.append(2));
        try journal.sync();
        journal.deinit();
        journal = try h.open();
        try testing.expectEqual(Bounds{ .start = size, .end = size + 2 }, journal.get_bounds());
        try testing.expectEqual(2, try journal.read(size + 1));
        try journal.destroy();
    }
}

test "variable: init at size clears existing data" {
    var h = try Harness.init("init-at-size-clears", 5);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 12, 100);
    try journal.sync();
    journal.deinit();
    journal = try h.open_at_size(8);
    try testing.expectEqual(Bounds{ .start = 8, .end = 8 }, journal.get_bounds());
    try testing.expectError(error.ItemPruned, journal.read(5));
    try testing.expectEqual(8, try journal.append(800));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 8, .end = 9 }, journal.get_bounds());
    try testing.expectEqual(800, try journal.read(8));
    try journal.destroy();
}

test "variable: init at max size is rejected" {
    var h = try Harness.init("init-at-max", 5);
    defer h.deinit();
    try testing.expectError(error.SizeOverflow, h.open_at_size(std.math.maxInt(u64)));
}

test "variable: clear to size" {
    var h = try Harness.init("clear-test", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 25, 100);
    try journal.sync();
    try testing.expectError(error.ItemOutOfRange, journal.clear_to_size(24));
    try journal.clear_to_size(100);
    try testing.expectEqual(Bounds{ .start = 100, .end = 100 }, journal.get_bounds());
    for (0..25) |position| try testing.expectError(error.ItemPruned, journal.read(position));
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 100, .end = 100 }, journal.get_bounds());
    for (100..105) |position| try testing.expectEqual(position, try journal.append(position * 100));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 100, .end = 105 }, journal.get_bounds());
    try expect_items(&journal, 100, 105, 100);
    try journal.destroy();
}

test "variable: a staged clear completes on init" {
    var h = try Harness.init("clear-crash", 5);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 12, 100);
    try journal.sync();
    // Crash right after staging the intent, before any data is removed.
    try journal.offsets.stage_clear_intent(40);
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 40, .end = 40 }, journal.get_bounds());
    try testing.expectEqual(40, try journal.append(4000));
    try testing.expectEqual(4000, try journal.read(40));
    try journal.destroy();
}

test "variable: single item per section" {
    var h = try Harness.init("single-item", 1);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 10, 7);
    try expect_items(&journal, 0, 10, 7);
    try testing.expect(try journal.prune(5));
    try testing.expectEqual(Bounds{ .start = 5, .end = 10 }, journal.get_bounds());
    try testing.expectEqual(5, try replay_count(&journal, .{ .start = 5, .end = 10 }, 1024, 7));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 5, .end = 10 }, journal.get_bounds());
    try expect_items(&journal, 5, 10, 7);
    try testing.expect(try journal.prune(10));
    try testing.expect(journal.get_bounds().is_empty());
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 10, .end = 10 }, journal.get_bounds());
    try testing.expectEqual(10, try journal.append(70));
    try journal.destroy();
}

test "variable: variable-length items, compressed and uncompressed" {
    for ([_]?u8{ null, 3 }) |compression| {
        var h = try Harness.init("byte-items", 4);
        defer h.deinit();
        h.compression = compression;
        const cfg = h.cfg_for(Bytes, bytes_cfg);
        const J = variable.Journal(Bytes);
        var journal = try J.init(gpa, h.storage.interface(), cfg);
        var buf: [3000]u8 = undefined;
        for (&buf, 0..) |*byte, index| byte.* = @intCast(index % 7);
        // Lengths cross page boundaries and the write buffer.
        const lengths = [_]usize{ 0, 1, 50, 1023, 1024, 2500, 7, 3000, 12, 900 };
        for (lengths, 0..) |len, position| {
            try testing.expectEqual(position, try journal.append(buf[0..len]));
        }
        try journal.sync();
        journal.deinit();
        journal = try J.init(gpa, h.storage.interface(), cfg);
        for (lengths, 0..) |len, position| {
            const item = try journal.read(position);
            defer codec.free(Bytes, gpa, item);
            try testing.expectEqualSlices(u8, buf[0..len], item);
        }
        var replay = try journal.replay(.{ .start = 2, .end = 10 }, 100);
        var next: u64 = 2;
        while (try replay.next()) |batch| {
            for (batch.items, next..) |item, position| {
                try testing.expectEqual(lengths[position], item.len);
            }
            next += batch.items.len;
        }
        replay.deinit();
        try testing.expectEqual(10, next);
        try journal.destroy();
    }
}

test "variable: prepared appends check compression" {
    var h = try Harness.init("prepared", 3);
    defer h.deinit();
    var journal = try h.open();
    var prepared = try journal.prepare_append(&.{ &.{ 1, 2 }, &.{ 3, 4, 5 } });
    try testing.expectEqual(4, try journal.append_prepared(&prepared));
    for (0..5) |position| try testing.expectEqual(position + 1, try journal.read(position));
    var empty = try journal.prepare_append(&.{});
    try testing.expectError(error.EmptyAppend, journal.append_prepared(&empty));
    h.compression = 3;
    h.partition = "prepared-compressed";
    var compressed_journal = try Journal.init(gpa, h.storage.interface(), h.cfg());
    var compressed = try compressed_journal.prepare_append(&.{&.{6}});
    compressed_journal.deinit();
    try testing.expectError(error.InvalidConfiguration, journal.append_prepared(&compressed));
    journal.deinit();
}

test "variable: span" {
    var h = try Harness.init("span", 10);
    defer h.deinit();
    const storage = h.storage.interface();
    const empty = try Journal.span(gpa, storage, h.cfg());
    try testing.expectEqual(Bounds{ .start = 0, .end = 0 }, empty);
    var journal = try h.open();
    try append_scaled(&journal, 25, 1);
    _ = try journal.prune(10);
    try journal.sync();
    journal.deinit();
    // The end is the newest data blob's capacity.
    const span = try Journal.span(gpa, storage, h.cfg());
    try testing.expectEqual(Bounds{ .start = 10, .end = 30 }, span);
}

test "variable: init_sync over a variable backing" {
    var h = try Harness.init("variable-init-sync", 5);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 18, 100);
    try journal.sync();
    journal.deinit();
    const storage = h.storage.interface();
    // Overlapping local data is kept and pruned below the range start.
    const overlap: Bounds = .{ .start = 7, .end = 15 };
    journal = try authenticated.init_sync(Journal, gpa, storage, h.cfg(), overlap);
    try testing.expectEqual(Bounds{ .start = 5, .end = 15 }, journal.get_bounds());
    try expect_items(&journal, 5, 15, 100);
    try journal.sync();
    journal.deinit();
    // A range beyond the local data resets to an empty journal at its start.
    const beyond: Bounds = .{ .start = 40, .end = 50 };
    journal = try authenticated.init_sync(Journal, gpa, storage, h.cfg(), beyond);
    try testing.expectEqual(Bounds{ .start = 40, .end = 40 }, journal.get_bounds());
    try testing.expectEqual(40, try journal.append(4000));
    try journal.destroy();
}

/// Open a harness whose data pages are `page` bytes, for tests that tear specific pages.
fn harness_paged(partition: []const u8, items_per_section: u64, page: u16) !Harness {
    var h = try Harness.init(partition, items_per_section);
    h.cache_ref.deinit();
    h.cache_ref = try CacheRef.init(gpa, page, 10);
    return h;
}

/// Truncate data blob `blob` to `bytes` and remove every newer data blob, leaving stale offsets.
fn truncate_data(h: *Harness, blob: u64, bytes: u64) !void {
    const name = try std.mem.concat(gpa, u8, &.{ h.partition, variable.data_suffix });
    defer gpa.free(name);
    const storage = h.storage.interface();
    var partition = try contiguous.blobs.Partition.init(gpa, storage, name, &h.cache_ref, 1024);
    defer partition.deinit();
    const indices = try contiguous.blobs.indices(gpa, storage, name);
    defer gpa.free(indices);
    for (indices) |index| {
        if (index > blob) try partition.remove(index);
    }
    var writer = try partition.open_recovery(blob);
    defer writer.deinit();
    try writer.truncate(bytes);
    try writer.sync();
}

test "variable: recovery truncates a torn interior page" {
    var h = try harness_paged("variable-torn-interior", 30, 64);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 33, 100);
    try journal.commit();
    journal.deinit();
    const zero_name: [8]u8 = @splat(0);
    // Data blob 0 holds 30 nine-byte frames (270 bytes) across five pages; tear page 2.
    try paged.corrupt_page(h.storage.interface(), "variable-torn-interior_data", &zero_name, 2, 64);
    // Pages 0 and 1 hold 128 bytes, 14 whole frames; the gap makes blob 1 unreachable.
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 0, .end = 14 }, journal.get_bounds());
    try expect_items(&journal, 0, 14, 100);
    try testing.expectEqual(14, try journal.append(4242));
    try testing.expectEqual(4242, try journal.read(14));
    try journal.destroy();
}

test "variable: recovery rejects a watermark beyond the retained data" {
    var h = try Harness.init("recovery-anchor-too-far", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 20, 100);
    try journal.sync();
    // The watermark vouches for acknowledged data that no longer exists.
    try journal.test_set_offsets_recovery_watermark(15);
    journal.deinit();
    try truncate_data(&h, 1, 2 * 9);
    // Missing acknowledged data stays an error on every attempt.
    try testing.expectError(error.Corruption, h.open());
    try testing.expectError(error.Corruption, h.open());
}

test "variable: recovery rejects missing data below the watermark and keeps evidence" {
    var h = try Harness.init("recovery-short-middle", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 30, 100);
    try journal.sync();
    try journal.test_set_offsets_recovery_watermark(15);
    journal.deinit();
    try truncate_data(&h, 1, 2 * 9);
    // An orphaned blob 2 after the short blob 1.
    const storage = h.storage.interface();
    const name = "recovery-short-middle_data";
    var partition = try contiguous.blobs.Partition.init(gpa, storage, name, &h.cache_ref, 1024);
    defer partition.deinit();
    var orphan = try partition.open_recovery(2);
    _ = try orphan.append(&.{ 8, 0, 0, 0, 0, 0, 0, 0x27, 0x0f });
    try orphan.sync();
    orphan.deinit();
    try testing.expectError(error.Corruption, h.open());
    try testing.expectError(error.Corruption, h.open());
    const indices = try contiguous.blobs.indices(gpa, storage, name);
    defer gpa.free(indices);
    try testing.expectEqualSlices(u64, &.{ 0, 1, 2 }, indices);
}

test "variable: recovery rejects an over-capacity blob" {
    var h = try Harness.init("recovery-overlong", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 5, 100);
    try journal.sync();
    // Eleven frames in a ten-item blob: a complete frame beyond a full blob.
    for (5..11) |position| _ = try journal.test_append_data(position * 100);
    try journal.blobs.sync();
    journal.deinit();
    try testing.expectError(error.Corruption, h.open());
}

test "variable: recovery fails on a complete undecodable frame" {
    var h = try Harness.init("recovery-undecodable", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 5, 100);
    try journal.sync();
    // A complete frame whose one-byte payload cannot decode as a u64 is not a torn write.
    _ = try journal.blobs.tail.append(&.{ 1, 0xFF });
    try journal.blobs.sync();
    journal.deinit();
    try testing.expectError(error.EndOfBuffer, h.open());
}

/// One run of the interrupted-destroy regression: destroy a synced, pruned journal whose
/// mutations stop after `interrupted`, and return the reopened bounds (null once the destroy
/// completes). Either way a completed destroy restores empty storage.
fn interrupted_destroy_reopen(interrupted: u64) !?Bounds {
    var h = try Harness.init("interrupted-destroy", 2);
    defer h.deinit();
    const empty = h.storage.backend.audit();
    var journal = try h.open();
    // Sync twice around a prune, leaving seven items in four sections above the boundary.
    try append_scaled(&journal, 7, 1);
    try journal.sync();
    _ = try journal.prune(4);
    for (7..11) |item| try testing.expectEqual(item, try journal.append(item));
    try journal.sync();
    try testing.expectEqual(Bounds{ .start = 4, .end = 11 }, journal.get_bounds());
    const data = "interrupted-destroy" ++ variable.data_suffix;
    const names = try h.storage.interface().scan(gpa, data);
    defer names.deinit(gpa);
    try testing.expectEqual(4, names.items.len);
    // Destroy fails exactly when one of its mutations was refused.
    h.storage.allow_mutations(interrupted);
    const destroyed = if (journal.destroy()) true else |_| false;
    try testing.expectEqual(!destroyed, h.storage.mutation_refused);
    h.storage.mutations_allowed = null;
    h.storage.crash();
    if (destroyed) {
        try testing.expectEqual(empty, h.storage.backend.audit());
        return null;
    }
    // The reopened journal is the synced one or a fresh one.
    journal = try h.open();
    const reopened = journal.get_bounds();
    if (reopened.start == 4) {
        try testing.expectEqual(Bounds{ .start = 4, .end = 11 }, reopened);
        try expect_items(&journal, 4, 11, 1);
    } else {
        try testing.expectEqual(Bounds{ .start = 0, .end = 0 }, reopened);
    }
    // A retried destroy completes and leaves no blob behind.
    try journal.destroy();
    try testing.expectEqual(empty, h.storage.backend.audit());
    return reopened;
}

// Regression test for commonware issue 5668: a destroy interrupted at any point leaves a
// journal that reopens as a crash would recover it or as a fresh journal, and that a retried
// destroy removes. Once a stop leaves the journal empty, no later stop leaves it unchanged.
test "variable: interrupted destroy reopens unchanged or empty" {
    const sections = 4;
    var unchanged: u64 = 0;
    var emptied: u64 = 0;
    var interrupted: u64 = 0;
    while (try interrupted_destroy_reopen(interrupted)) |reopened| : (interrupted += 1) {
        if (reopened.is_empty()) {
            emptied += 1;
        } else {
            try testing.expectEqual(0, emptied);
            unchanged += 1;
        }
    }
    try testing.expect(unchanged > 0 and emptied > 0);
    // Destroy stages the clear, removes every data section and the data partition, then the
    // offsets journal's blobs and checkpoint, so it can stop at least once before each.
    try testing.expect(interrupted >= sections + 4);
}
