//! commonware's `journal/contiguous/fixed.rs` tests of one-item blobs, `init_at_size` (at
//! zero, mid-blob, blob boundaries, large offsets, and near `u64::MAX`), `clear_to_size`,
//! mid-blob pruning boundaries, prune durability, and interrupted clears.
//!
//! Snapshot readers are not ported, so replays run on the journal directly. Crash scenarios
//! stage the checkpoint state an interrupted clear leaves, as commonware does. The two
//! `read_many` tests of unsorted and duplicate positions are death tests in death_test.zig.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const Sha256 = @import("cryptography").sha256.Sha256;
const Digest = @import("cryptography").sha256.Digest;
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const contiguous = @import("mod.zig");
const Checkpoint = @import("checkpoint.zig").Checkpoint;
const manager_mod = @import("../segmented/manager.zig");

const gpa = testing.allocator;
const Journal = fixed.Journal(Digest);
const Bounds = contiguous.Bounds;
const max = std.math.maxInt(u64);

fn test_digest(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

fn bounds(start: u64, end: u64) Bounds {
    return .{ .start = start, .end = end };
}

const Harness = struct {
    storage: mocks.Storage,
    cache_ref: paged.CacheRef,
    items_per_blob: u64,
    partition: []const u8,
    blobs: []const u8,

    fn init(comptime partition: []const u8, items_per_blob: u64) !Harness {
        return .{
            .storage = mocks.Storage.init(gpa),
            .cache_ref = try paged.CacheRef.init(gpa, 44, 3),
            .items_per_blob = items_per_blob,
            .partition = partition,
            .blobs = partition ++ "-blobs",
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

    fn iface(self: *Harness) runtime.storage.Storage {
        return self.storage.interface();
    }

    fn open(self: *Harness) !Journal {
        return Journal.init(gpa, self.iface(), self.cfg());
    }

    fn open_at_size(self: *Harness, size: u64) !Journal {
        return Journal.init_at_size(gpa, self.iface(), self.cfg(), size);
    }

    fn open_at_most(self: *Harness, max_size: u64) !Journal {
        return Journal.init_at_most(gpa, self.iface(), self.cfg(), max_size);
    }

    /// Durably stage the checkpoint an interrupted clear leaves: `target`, and `hint` when set.
    fn stage_clear(self: *Harness, target: u64, hint: ?u64) !void {
        var checkpoint = try Checkpoint.open(gpa, self.iface(), self.partition);
        defer checkpoint.deinit();
        if (hint) |boundary| try checkpoint.set_boundary_hint(boundary);
        try checkpoint.set_clear_target(target);
        try checkpoint.sync();
    }

    /// Durably create (or write `bytes` to) blob `name` of the blobs partition.
    fn touch(self: *Harness, name: []const u8, bytes: []const u8) !void {
        const opened = try self.iface().open(self.blobs, name);
        defer opened.blob.close();
        if (bytes.len > 0) try opened.blob.write_at(0, bytes, .{});
        try opened.blob.sync();
    }
};

/// Append `count` digests of `first + i`, checking positions continue from `size()`.
fn fill(journal: *Journal, first: u64, count: u64) !void {
    for (0..count) |i| {
        const expected = journal.size();
        try testing.expectEqual(expected, try journal.append(test_digest(first + i)));
    }
}

/// Check positions `[start, end)` hold `test_digest(first + position - start)`.
fn expect_digests(journal: *Journal, start: u64, end: u64, first: u64) !void {
    for (start..end) |position| {
        const expected = test_digest(first + (position - start));
        try testing.expectEqual(expected, try journal.read(position));
    }
}

/// Replay `[start, size)` and check it yields `test_digest(first + position - start)`.
fn expect_replay(journal: *Journal, start: u64, first: u64) !void {
    var replay = try journal.replay(bounds(start, journal.size()), 1024);
    defer replay.deinit();
    var next = start;
    while (try replay.next()) |batch| {
        try testing.expectEqual(next, batch.start);
        for (batch.items) |item| {
            try testing.expectEqual(test_digest(first + (next - start)), item);
            next += 1;
        }
    }
    try testing.expectEqual(journal.size(), next);
}

// With one item per blob the tail blob is empty after every sync; appends, tail reads,
// pruning, and a restart keep every retained position readable.
test "fixed: single item per blob" {
    var h = try Harness.init("single-item-per-blob", 1);
    defer h.deinit();
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 0), journal.get_bounds());
    try fill(&journal, 0, 1);
    try journal.sync();
    try testing.expectEqual(test_digest(0), try journal.read(journal.size() - 1));
    for (1..10) |i| {
        try fill(&journal, i, 1);
        try testing.expectEqual(test_digest(i), try journal.read(journal.size() - 1));
    }
    try expect_digests(&journal, 0, 10, 0);
    try journal.sync();
    _ = try journal.prune(5);
    try testing.expectEqual(bounds(5, 10), journal.get_bounds());
    for (0..5) |i| try testing.expectError(error.ItemPruned, journal.read(i));
    try expect_digests(&journal, 5, 10, 5);
    for (10..15) |i| {
        try fill(&journal, i, 1);
        try testing.expectEqual(test_digest(i), try journal.read(journal.size() - 1));
    }
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(5, 15), journal.get_bounds());
    try expect_digests(&journal, 5, 15, 5);
    try journal.destroy();
    try expect_fresh_after_destroy(&h);
}

/// The destroyed journal's config reopens empty and accepts new writes.
fn expect_fresh_after_destroy(h: *Harness) !void {
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 0), journal.get_bounds());
    try fill(&journal, 1000, 10);
    try journal.sync();
    try testing.expectEqual(10, journal.size());
    try expect_digests(&journal, 0, 10, 1000);
    try journal.destroy();
}

test "fixed: single item per blob restarts after a prune" {
    var h = try Harness.init("single-item-per-blob", 1);
    defer h.deinit();
    var journal = try h.open();
    try fill(&journal, 100, 10);
    _ = try journal.prune(5);
    try testing.expectEqual(bounds(5, 10), journal.get_bounds());
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(5, 10), journal.get_bounds());
    try testing.expectEqual(test_digest(109), try journal.read(journal.size() - 1));
    try expect_digests(&journal, 5, 10, 105);
    try journal.destroy();
    try expect_fresh_after_destroy(&h);
}

test "fixed: single item per blob prunes everything" {
    var h = try Harness.init("single-item-per-blob", 1);
    defer h.deinit();
    var journal = try h.open();
    try fill(&journal, 200, 5);
    try journal.sync();
    _ = try journal.prune(5);
    try testing.expectEqual(bounds(5, 5), journal.get_bounds());
    try testing.expectError(error.ItemPruned, journal.read(4));
    try fill(&journal, 205, 1);
    try testing.expectEqual(5, journal.get_bounds().start);
    try testing.expectEqual(test_digest(205), try journal.read(5));
    try journal.destroy();
}

test "fixed: init at size zero" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(0);
    try testing.expectEqual(bounds(0, 0), journal.get_bounds());
    try fill(&journal, 100, 1);
    try testing.expectEqual(test_digest(100), try journal.read(0));
    try journal.destroy();
}

test "fixed: init at the maximum size is rejected" {
    var h = try Harness.init("max-size-rejected", 1);
    defer h.deinit();
    try testing.expectError(error.SizeOverflow, h.open_at_size(max));
}

test "fixed: an append past the maximum size fails" {
    var h = try Harness.init("append-size-overflow", 1);
    defer h.deinit();
    var journal = try h.open_at_size(max - 1);
    defer journal.deinit();
    try testing.expectEqual(max - 1, try journal.append(test_digest(7)));
    try testing.expectEqual(max, journal.size());
    try testing.expectError(error.SizeOverflow, journal.append(test_digest(8)));
}

test "fixed: replay near the maximum size" {
    var h = try Harness.init("replay-near-max-size", 10);
    defer h.deinit();
    var journal = try h.open_at_size(max - 1);
    try testing.expectEqual(max - 1, try journal.append(test_digest(7)));
    try expect_replay(&journal, max - 1, 7);
    try journal.destroy();
}

test "fixed: init at size on a blob boundary" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(10);
    try testing.expectEqual(bounds(10, 10), journal.get_bounds());
    try fill(&journal, 1000, 2);
    try expect_digests(&journal, 10, 12, 1000);
    try journal.destroy();
}

test "fixed: init at size mid-blob" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try testing.expectEqual(bounds(7, 7), journal.get_bounds());
    try testing.expectError(error.ItemPruned, journal.read(5));
    try testing.expectError(error.ItemPruned, journal.read(6));
    try fill(&journal, 700, 1);
    try testing.expectEqual(test_digest(700), try journal.read(7));
    try testing.expectEqual(bounds(7, 8), journal.get_bounds());
    try journal.destroy();
}

test "fixed: append many after a mid-blob start" {
    var h = try Harness.init("test-partition", 100);
    defer h.deinit();
    var journal = try h.open_at_size(150);
    var items: [100]Digest = undefined;
    for (&items, 0..) |*item, i| item.* = test_digest(1500 + i);
    try testing.expectEqual(249, try journal.append_many(&items));
    try testing.expectEqual(bounds(150, 250), journal.get_bounds());
    const checks = [_][2]u64{ .{ 150, 0 }, .{ 199, 49 }, .{ 200, 50 }, .{ 249, 99 } };
    for (checks) |check| try testing.expectEqual(items[check[1]], try journal.read(check[0]));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(150, 250), journal.get_bounds());
    for (checks) |check| try testing.expectEqual(items[check[1]], try journal.read(check[0]));
    try journal.destroy();
}

test "fixed: init at size persists" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(15);
    try fill(&journal, 1500, 5);
    try testing.expectEqual(20, journal.size());
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(15, 20), journal.get_bounds());
    try expect_digests(&journal, 15, 20, 1500);
    try fill(&journal, 9999, 1);
    try testing.expectEqual(test_digest(9999), try journal.read(20));
    try journal.destroy();
}

test "fixed: init at size persists without data" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(15);
    try testing.expectEqual(bounds(15, 15), journal.get_bounds());
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(15, 15), journal.get_bounds());
    try fill(&journal, 1500, 1);
    try testing.expectEqual(test_digest(1500), try journal.read(15));
    try journal.destroy();
}

test "fixed: init at a large size" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(1000);
    try testing.expectEqual(bounds(1000, 1000), journal.get_bounds());
    try fill(&journal, 100_000, 1);
    try testing.expectEqual(test_digest(100_000), try journal.read(1000));
    try journal.destroy();
}

test "fixed: init at size, prune, and append" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(20);
    try fill(&journal, 2000, 10);
    _ = try journal.prune(25);
    try testing.expectEqual(bounds(25, 30), journal.get_bounds());
    try expect_digests(&journal, 25, 30, 2005);
    try fill(&journal, 3000, 1);
    try journal.destroy();
}

test "fixed: clear to size" {
    var h = try Harness.init("test-partition", 10);
    defer h.deinit();
    var journal = try h.open();
    try fill(&journal, 0, 25);
    try journal.sync();
    try journal.clear_to_size(100);
    try testing.expectEqual(100, journal.size());
    for (0..25) |i| try testing.expectError(error.ItemPruned, journal.read(i));
    // The size persists without any data.
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(100, journal.size());
    try fill(&journal, 100, 5);
    try expect_digests(&journal, 100, 105, 100);
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(105, journal.size());
    try expect_digests(&journal, 100, 105, 100);
    try journal.destroy();
}

test "fixed: clear to size rejects the maximum" {
    var h = try Harness.init("test-partition", 10);
    defer h.deinit();
    var journal = try h.open();
    try testing.expectError(error.SizeOverflow, journal.clear_to_size(max));
    journal.deinit();
    journal = try h.open();
    defer journal.deinit();
    try testing.expectError(error.SizeOverflow, journal.stage_clear_intent(max));
}

test "fixed: clear to size rejects going backward without mutation" {
    var h = try Harness.init("test-partition", 10);
    defer h.deinit();
    var journal = try h.open();
    try fill(&journal, 0, 2);
    try journal.sync();
    try testing.expectError(error.ItemOutOfRange, journal.clear_to_size(1));
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(0, 2), journal.get_bounds());
    try expect_digests(&journal, 0, 2, 0);
    try testing.expectError(error.ItemOutOfRange, journal.stage_clear_intent(1));
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(0, 2), journal.get_bounds());
    try expect_digests(&journal, 0, 2, 0);
    try journal.destroy();
}

// Commit-then-reopen with the old pruning hint absent (aligned), unchanged (mid-blob), and
// made stale by a prune to a blob boundary.
test "fixed: commit with no hint and an aligned boundary" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open();
    try fill(&journal, 0, 5);
    try journal.commit();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(0, 5), journal.get_bounds());
    try journal.destroy();
}

// Without any checkpoint, recovery falls back to blob lengths and finds a short non-tail
// blob, which violates the rollover-sync invariant.
test "fixed: missing metadata with a short blob is corruption" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try fill(&journal, 0, 3);
    try journal.sync();
    journal.checkpoint.clear();
    try journal.checkpoint.sync();
    journal.deinit();
    try testing.expectError(error.Corruption, h.open());
}

test "fixed: commit with an unchanged mid-blob hint" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try fill(&journal, 0, 3);
    try journal.commit();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(7, 10), journal.get_bounds());
    try journal.destroy();
}

test "fixed: commit after a mid-blob hint goes stale" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try fill(&journal, 0, 10);
    try testing.expectEqual(17, journal.size());
    _ = try journal.prune(10);
    try journal.commit();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(10, 17), journal.get_bounds());
    try journal.destroy();
}

test "fixed: prune does not move the boundary backward" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try fill(&journal, 0, 5);
    _ = try journal.prune(5);
    try testing.expectEqual(7, journal.get_bounds().start);
    try journal.destroy();
}

// A prune that returns true has made every pre-prune item durable, so a crash that loses
// every unsynced write still recovers the full size.
test "fixed: prune durability survives a crash" {
    var h = try Harness.init("test-partition", 3);
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        try fill(&journal, 0, 8);
        try testing.expect(try journal.prune(3));
    }
    h.storage.crash();
    var journal = try h.open();
    try testing.expectEqual(bounds(3, 8), journal.get_bounds());
    try expect_digests(&journal, 3, 8, 3);
    try journal.destroy();
}

test "fixed: commit after a prune skips the pruned blobs" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open();
    try fill(&journal, 0, 12);
    _ = try journal.prune(5);
    try journal.commit();
    try testing.expectEqual(bounds(5, 12), journal.get_bounds());
    try journal.destroy();
}

test "fixed: replay after init at size spans blobs" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try fill(&journal, 100, 13);
    try testing.expectEqual(20, journal.size());
    try journal.sync();
    try expect_replay(&journal, 7, 100);
    try expect_replay(&journal, 12, 105);
    try journal.destroy();
}

test "fixed: init at most before the retained start" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(10);
    try fill(&journal, 0, 3);
    try testing.expectEqual(13, journal.size());
    for ([_]u64{ 11, 10 }) |cap| {
        try journal.sync();
        journal.deinit();
        journal = try h.open_at_most(cap);
        try testing.expectEqual(cap, journal.size());
    }
    try journal.sync();
    journal.deinit();
    try testing.expectError(error.ItemPruned, h.open_at_most(9));
}

test "fixed: interrupted init at size completes on reopen" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try fill(&journal, 0, 5);
    try journal.sync();
    journal.deinit();
    // The intent is synced and the blobs removed, but no new tail blob exists.
    try h.stage_clear(12, null);
    try h.iface().remove(h.blobs, null);
    journal = try h.open();
    try testing.expectEqual(bounds(12, 12), journal.get_bounds());
    journal.deinit();
    // The new tail blob exists, but the final checkpoint has not replaced the intent.
    try h.stage_clear(2, 7);
    try h.touch(&manager_mod.section_name(0), &.{});
    journal = try h.open();
    try testing.expectEqual(bounds(2, 2), journal.get_bounds());
    try journal.destroy();
}

test "fixed: interrupted clear to size completes on reopen" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open_at_size(12);
    try journal.sync();
    journal.deinit();
    // The intent is synced and blob 0 created, before the final checkpoint.
    try h.stage_clear(2, null);
    try h.iface().remove(h.blobs, null);
    try h.touch(&manager_mod.section_name(0), &.{});
    journal = try h.open();
    try testing.expectEqual(bounds(2, 2), journal.get_bounds());
    try journal.destroy();
}

test "fixed: a clear interrupted after its intent, before blobs change" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    var journal = try h.open();
    try fill(&journal, 0, 12);
    try journal.sync();
    journal.deinit();
    try h.stage_clear(100, null);
    journal = try h.open();
    try testing.expectEqual(bounds(100, 100), journal.get_bounds());
    try fill(&journal, 100, 1);
    try journal.destroy();
}

// A name that is not a blob index would fail blob parsing if init read the stale blobs
// before honoring the clear intent.
test "fixed: a clear intent skips corrupt stale blobs" {
    var h = try Harness.init("test-partition", 5);
    defer h.deinit();
    try h.stage_clear(12, null);
    try h.touch("not-u64", &.{ 1, 2, 3 });
    var journal = try h.open();
    try testing.expectEqual(bounds(12, 12), journal.get_bounds());
    try testing.expectEqual(12, journal.recovery_watermark());
    try journal.destroy();
}

test "fixed: a mid-blob clear intent with old blobs present" {
    var h = try Harness.init("test-partition", 10);
    defer h.deinit();
    var journal = try h.open_at_size(10);
    try fill(&journal, 0, 6);
    try journal.sync();
    journal.deinit();
    try h.stage_clear(15, null);
    journal = try h.open();
    try testing.expectEqual(bounds(15, 15), journal.get_bounds());
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(15, 15), journal.get_bounds());
    try testing.expectError(error.ItemPruned, journal.read(14));
    try fill(&journal, 100, 1);
    try testing.expectEqual(test_digest(100), try journal.read(15));
    try journal.destroy();
}

// A watermark beyond the recovered size: every blob removed and one empty blob left at the
// tail (blob 1) or several blobs short of it (blob 0).
test "fixed: a watermark past an aligned empty tail is corruption" {
    for ([_]u64{ 1, 0 }) |tail| {
        var h = try Harness.init("test-partition", 5);
        defer h.deinit();
        var journal = try h.open();
        try fill(&journal, 0, 10);
        try journal.sync();
        journal.deinit();
        try h.iface().remove(h.blobs, null);
        try h.touch(&manager_mod.section_name(tail), &.{});
        try testing.expectError(error.Corruption, h.open());
    }
}

test "fixed: read many" {
    var h = try Harness.init("test-partition", 3);
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    var out: [3]Digest = undefined;
    try journal.read_many(&.{}, out[0..0]);
    try fill(&journal, 0, 9);
    // One blob, then across blobs [0,1,2] [3,4,5] [6,7,8].
    try journal.read_many(&.{ 0, 1, 2 }, &out);
    for (out, 0..) |item, i| try testing.expectEqual(test_digest(i), item);
    try journal.read_many(&.{ 1, 4, 7 }, &out);
    for (out, [_]u64{ 1, 4, 7 }) |item, i| try testing.expectEqual(test_digest(i), item);
    try journal.sync();
    _ = try journal.prune(3);
    try testing.expectEqual(bounds(3, 9), journal.get_bounds());
    try journal.read_many(&.{ 3, 5, 8 }, &out);
    for (out, [_]u64{ 3, 5, 8 }) |item, i| try testing.expectEqual(test_digest(i), item);
    try testing.expectError(error.ItemPruned, journal.read_many(&.{1}, out[0..1]));
    try testing.expectError(error.ItemOutOfRange, journal.read_many(&.{ 3, 9 }, out[0..2]));
}

test "fixed: read many matches read" {
    var h = try Harness.init("test-partition", 4);
    defer h.deinit();
    var journal = try h.open();
    try fill(&journal, 0, 20);
    try journal.sync();
    var positions: [20]u64 = undefined;
    for (&positions, 0..) |*position, i| position.* = i;
    var out: [20]Digest = undefined;
    try journal.read_many(&positions, &out);
    for (positions) |position| try testing.expectEqual(try journal.read(position), out[position]);
    try journal.destroy();
}

test "fixed: bounded initialization serves cached reads" {
    var h = try Harness.init("test-partition", 4);
    defer h.deinit();
    var journal = try h.open();
    try fill(&journal, 0, 20);
    try journal.sync();
    journal.deinit();
    journal = try h.open_at_most(18);
    try testing.expectEqual(test_digest(17), try journal.read(17));
    var served: [2]?Digest = undefined;
    journal.try_read_many_sync(&.{ 17, 18 }, &served);
    try testing.expectEqual(test_digest(17), served[0].?);
    try testing.expectEqual(null, served[1]);
    try journal.destroy();
}
