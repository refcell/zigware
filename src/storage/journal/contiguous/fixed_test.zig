//! Tests of the fixed contiguous journal: commonware's shared contiguous suite
//! (`journal/contiguous/tests.rs`, with `items_per_blob = 10`) and the fixed journal's own tests
//! (`journal/contiguous/fixed.rs`).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const contiguous = @import("mod.zig");
const fixed = @import("fixed.zig");

const gpa = testing.allocator;
const Storage = mocks.Storage;
const CacheRef = paged.CacheRef;
const Journal = fixed.Journal(u64);
const Bounds = contiguous.Bounds;

const Harness = struct {
    storage: Storage,
    cache_ref: CacheRef,
    items_per_blob: u64,
    partition: []const u8,

    fn init(partition: []const u8, items_per_blob: u64) !Harness {
        return .{
            .storage = Storage.init(gpa),
            .cache_ref = try CacheRef.init(gpa, 44, 3),
            .items_per_blob = items_per_blob,
            .partition = partition,
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg(self: *Harness) fixed.Config {
        return .{
            .partition = self.partition,
            .items_per_blob = self.items_per_blob,
            .cache_ref = &self.cache_ref,
            .write_buffer = 2048,
            .replay_buffer = 2048,
        };
    }

    fn open(self: *Harness) !Journal {
        return Journal.init(gpa, self.storage.interface(), self.cfg());
    }

    fn open_at_most(self: *Harness, max_size: u64) !Journal {
        return Journal.init_at_most(gpa, self.storage.interface(), self.cfg(), max_size);
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

test "contiguous: empty journal bounds" {
    var h = try Harness.init("empty", 10);
    defer h.deinit();
    var journal = try h.open();
    try testing.expect(journal.get_bounds().is_empty());
    try testing.expectEqual(0, journal.get_bounds().start);
    try journal.destroy();
}

test "contiguous: bounds after prune" {
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
    try journal.destroy();
}

test "contiguous: append, read, and sequential positions" {
    var h = try Harness.init("sequential-appends", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 25, 10);
    try testing.expectEqual(25, journal.size());
    for (0..25) |position| try testing.expectEqual(position * 10, try journal.read(position));
    try journal.destroy();
}

test "contiguous: replay from start, middle, and unsealed tail" {
    var h = try Harness.init("replay", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 17, 10);
    try testing.expectEqual(17, try replay_count(&journal, .{ .start = 0, .end = 17 }, 1024, 10));
    try testing.expectEqual(10, try replay_count(&journal, .{ .start = 7, .end = 17 }, 1024, 10));
    try testing.expectEqual(4, try replay_count(&journal, .{ .start = 13, .end = 17 }, 1024, 10));
    // A buffer smaller than one item still yields every item.
    try testing.expectEqual(17, try replay_count(&journal, .{ .start = 0, .end = 17 }, 7, 10));
    // Empty ranges at the start and at the end yield nothing.
    try testing.expectEqual(0, try replay_count(&journal, .{ .start = 0, .end = 0 }, 1024, 10));
    try testing.expectEqual(0, try replay_count(&journal, .{ .start = 17, .end = 17 }, 1024, 10));
    try journal.destroy();
}

/// commonware's `check_replay_batches`: batches tile `range`, never cross a blob, and exceed
/// `buffer` by less than one item.
fn check_replay_batches(journal: *Journal, range: Bounds, buffer: usize) !void {
    var replay = try journal.replay(range, buffer);
    defer replay.deinit();
    var next = range.start;
    while (try replay.next()) |batch| {
        try testing.expectEqual(next, batch.start);
        try testing.expect(batch.items.len > 0);
        try testing.expect((batch.items.len - 1) * 8 < buffer);
        const end = batch.start + batch.items.len;
        try testing.expect(end <= range.end);
        try testing.expectEqual(batch.start / 10, (end - 1) / 10);
        for (batch.items, 0..) |item, index| try testing.expectEqual((next + index) * 10, item);
        next = end;
    }
    try testing.expectEqual(range.end, next);
}

test "contiguous: replay batches" {
    var h = try Harness.init("replay-batches", 10);
    defer h.deinit();
    var journal = try h.open();
    // Three sealed blobs and a partial tail.
    try append_scaled(&journal, 37, 10);
    const ranges = [_]Bounds{
        .{ .start = 0, .end = 37 },  .{ .start = 7, .end = 25 },  .{ .start = 13, .end = 14 },
        .{ .start = 20, .end = 20 }, .{ .start = 30, .end = 37 },
    };
    for ([_]usize{ 9, 40, 4096 }) |buffer| {
        for (ranges) |range| try check_replay_batches(&journal, range, buffer);
    }
    // Ranges outside the bounds are rejected.
    try testing.expectError(error.ItemOutOfRange, journal.replay(.{ .start = 0, .end = 38 }, 40));
    try testing.expectError(error.ItemOutOfRange, journal.replay(.{ .start = 10, .end = 5 }, 40));
    // After pruning, batches start at the boundary and a pruned start is rejected.
    _ = try journal.prune(10);
    try check_replay_batches(&journal, .{ .start = 10, .end = 37 }, 40);
    try testing.expectError(error.ItemPruned, journal.replay(.{ .start = 5, .end = 20 }, 40));
    try journal.destroy();
}

test "contiguous: prune retains size and positions stay stable" {
    var h = try Harness.init("position-stability", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 20, 100);
    try testing.expect(try journal.prune(10));
    // A second prune to the same position prunes nothing.
    try testing.expect(!try journal.prune(10));
    try testing.expectEqual(20, journal.size());
    for (20..25) |position| try testing.expectEqual(position, try journal.append(position * 100));
    for ([_]u64{ 10, 15, 20, 24 }) |position| {
        try testing.expectEqual(position * 100, try journal.read(position));
    }
    try testing.expectEqual(15, try replay_count(&journal, .{ .start = 10, .end = 25 }, 1024, 100));
    try testing.expectError(error.ItemPruned, journal.read(9));
    try testing.expectError(error.ItemOutOfRange, journal.read(25));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 10, .end = 25 }, journal.get_bounds());
    try journal.destroy();
}

test "contiguous: prune then append and prune beyond size" {
    var h = try Harness.init("prune-then-append", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 10, 1);
    // Pruning beyond the size caps at the end.
    _ = try journal.prune(100);
    try testing.expect(journal.get_bounds().is_empty());
    try testing.expectEqual(10, try journal.append(999));
    try testing.expectEqual(11, journal.size());
    try testing.expectEqual(999, try journal.read(10));
    try journal.destroy();
}

test "contiguous: persistence after prune" {
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
    for (10..25) |position| try testing.expectEqual(position * 100, try journal.read(position));
    try testing.expectEqual(15, try replay_count(&journal, .{ .start = 10, .end = 25 }, 1024, 100));
    try testing.expectEqual(25, try journal.append(999));
    try testing.expectEqual(999, try journal.read(25));
    try journal.destroy();
}

test "contiguous: read by position and read many" {
    var h = try Harness.init("read-by-position", 10);
    defer h.deinit();
    var journal = try h.open();
    for (0..1000) |position| {
        _ = try journal.append(position * 100);
        try testing.expectEqual(position * 100, try journal.read(position));
    }
    for (0..1000) |position| try testing.expectEqual(position * 100, try journal.read(position));
    var items: [3]u64 = undefined;
    try journal.read_many(&.{ 1, 4, 12 }, &items);
    try testing.expectEqualSlices(u64, &.{ 100, 400, 1200 }, &items);
    try journal.destroy();
}

test "contiguous: bounded initialization" {
    var h = try Harness.init("rewind", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 20, 100);
    try journal.sync();
    journal.deinit();
    // A bound in the middle selects a prefix.
    journal = try h.open_at_most(12);
    try testing.expectEqual(12, journal.size());
    for (0..12) |position| try testing.expectEqual(position * 100, try journal.read(position));
    for (12..20) |position| try testing.expectError(error.ItemOutOfRange, journal.read(position));
    try testing.expectEqual(12, try journal.append(999));
    try testing.expectEqual(999, try journal.read(12));
    try journal.sync();
    journal.deinit();
    // A bound above the end does not grow the journal.
    journal = try h.open_at_most(20);
    try testing.expectEqual(13, journal.size());
    journal.deinit();
    // A zero bound selects an empty journal.
    journal = try h.open_at_most(0);
    try testing.expect(journal.get_bounds().is_empty());
    try testing.expectEqual(0, journal.size());
    try testing.expectEqual(0, try journal.append(42));
    try testing.expectEqual(42, try journal.read(0));
    try journal.destroy();
}

test "contiguous: bounded initialization after prune" {
    var h = try Harness.init("rewind-after-prune", 10);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 30, 100);
    _ = try journal.prune(10);
    try journal.sync();
    journal.deinit();
    journal = try h.open_at_most(20);
    try testing.expectEqual(Bounds{ .start = 10, .end = 20 }, journal.get_bounds());
    for (10..20) |position| try testing.expectEqual(position * 100, try journal.read(position));
    try testing.expectEqual(20, try journal.append(999));
    try journal.sync();
    journal.deinit();
    // A bound below the retained start fails.
    try testing.expectError(error.ItemPruned, h.open_at_most(5));
    journal = try h.open();
    try journal.destroy();
}

test "contiguous: section boundary behavior" {
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
    // Truncating to the blob boundary leaves the journal fully pruned.
    journal = try h.open_at_most(10);
    try testing.expectEqual(Bounds{ .start = 10, .end = 10 }, journal.get_bounds());
    try testing.expectEqual(10, try journal.append(777));
    try testing.expectEqual(777, try journal.read(10));
    try journal.destroy();
}

test "contiguous: destroy and reinit" {
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
}

test "contiguous: append many" {
    var h = try Harness.init("append-many", 10);
    defer h.deinit();
    var journal = try h.open();
    try testing.expectError(error.EmptyAppend, journal.append_many(&.{}));
    try testing.expectEqual(0, journal.size());
    try testing.expectEqual(2, try journal.append_many(&.{ 0, 10, 20 }));
    try testing.expectEqual(3, try journal.append(30));
    // 25 items in one call cross blob boundaries at 10 and 20.
    var items: [25]u64 = undefined;
    for (&items, 4..) |*item, position| item.* = position * 10;
    try testing.expectEqual(28, try journal.append_many(&items));
    for (0..29) |position| try testing.expectEqual(position * 10, try journal.read(position));
    try journal.destroy();
}

test "contiguous: start sync durability" {
    var h = try Harness.init("fixed-start-sync", 3);
    defer h.deinit();
    var journal = try h.open();
    try append_scaled(&journal, 7, 10);
    try journal.start_sync();
    journal.deinit();
    h.storage.crash();
    journal = try h.open();
    try testing.expectEqual(7, journal.size());
    for (0..7) |position| try testing.expectEqual(position * 10, try journal.read(position));
    try journal.destroy();
}
