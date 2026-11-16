//! The journal a sync writes fetched operations into (commonware's `qmdb/sync/journal.rs`).
//!
//! commonware's `Journal` trait becomes a comptime interface over a contiguous journal `J`:
//! `init(J, ...)` opens it for a sync range (`authenticated.init_sync`), `resize` moves its
//! start, and `append` adds operations; `J.size()` and `J.sync()` are the journal's own.
//! `Memory(Op)` is the in-memory journal that compact databases sync into.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const authenticated = @import("../../journal/authenticated.zig");
const contiguous = @import("../../journal/contiguous/mod.zig");

const Storage = runtime.storage.Storage;
pub const Bounds = contiguous.Bounds;

/// Opens the contiguous journal `J` for syncing `range`: the stored prefix useful for it is
/// kept, the rest cleared, and the journal pruned below `range.start` and capped at its end.
pub fn init(
    comptime J: type,
    gpa: Allocator,
    storage: Storage,
    cfg: J.BackingConfig,
    range: Bounds,
) !J {
    assert(range.start < range.end);
    const journal = try authenticated.init_sync(J, gpa, storage, cfg, range);
    assert(journal.size() <= range.end);
    return journal;
}

/// Moves the journal's start to `start`: clears it to an empty journal there when its end is
/// at or below `start`, else prunes below `start` (whole blobs only).
pub fn resize(journal: anytype, start: u64) !void {
    if (journal.get_bounds().end <= start) {
        try journal.clear_to_size(start);
        assert(journal.size() == start);
    } else {
        _ = try journal.prune(start);
        assert(journal.size() > start);
    }
}

/// Appends `ops` to the journal.
pub fn append(journal: anytype, ops: anytype) !void {
    const before = journal.size();
    if (ops.len == 0) return;
    _ = try journal.append_many(ops);
    assert(journal.size() == before + ops.len);
}

/// An in-memory sync journal of `Op`s from `start` (commonware's `Memory`). Owns `ops`.
pub fn Memory(comptime Op: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        start: u64,
        ops: std.ArrayList(Op) = .empty,

        pub fn init(gpa: Allocator, range: Bounds) Self {
            assert(range.start < range.end);
            return .{ .gpa = gpa, .start = range.start };
        }

        pub fn deinit(self: *Self) void {
            self.ops.deinit(self.gpa);
            self.* = undefined;
        }

        pub fn size(self: *const Self) u64 {
            return self.start + self.ops.items.len;
        }

        pub fn get_bounds(self: *const Self) Bounds {
            return .{ .start = self.start, .end = self.size() };
        }

        /// Moves the start to `start`, keeping the operations from it when it lies inside the
        /// journal and clearing them otherwise.
        pub fn resize(self: *Self, start: u64) void {
            if (start < self.start or start >= self.size()) {
                self.ops.clearRetainingCapacity();
            } else {
                const drop: usize = @intCast(start - self.start);
                const kept = self.ops.items.len - drop;
                std.mem.copyForwards(Op, self.ops.items[0..kept], self.ops.items[drop..]);
                self.ops.shrinkRetainingCapacity(kept);
            }
            self.start = start;
            assert(self.size() >= start);
        }

        pub fn append(self: *Self, ops: []const Op) Allocator.Error!void {
            try self.ops.appendSlice(self.gpa, ops);
        }

        pub fn sync(_: *Self) !void {}
    };
}

const testing = std.testing;

// Commonware's `test_memory_journal`.
test "sync memory journal appends and resizes" {
    const gpa = testing.allocator;
    const Mem = Memory(u64);
    const range: Bounds = .{ .start = 10, .end = 20 };
    var journal = Mem.init(gpa, range);
    defer journal.deinit();
    try testing.expectEqual(@as(u64, 10), journal.size());
    try journal.append(&.{ 1, 2, 3 });
    try testing.expectEqual(@as(u64, 13), journal.size());
    journal.resize(12);
    try testing.expectEqual(@as(u64, 13), journal.size());
    try testing.expectEqual(@as(u64, 12), journal.start);
    try testing.expectEqualSlices(u64, &.{3}, journal.ops.items);
    var cleared = Mem.init(gpa, range);
    defer cleared.deinit();
    try cleared.append(&.{ 1, 2 });
    cleared.resize(15);
    try testing.expectEqual(@as(u64, 15), cleared.size());
    try testing.expectEqual(@as(usize, 0), cleared.ops.items.len);
    var before = Mem.init(gpa, range);
    defer before.deinit();
    try before.append(&.{1});
    before.resize(5);
    try testing.expectEqual(@as(u64, 5), before.size());
    try testing.expectEqual(@as(usize, 0), before.ops.items.len);
}

// Commonware's `test_fixed_sync_journal_caps_ahead_and_discards_pruned_progress` (without the
// read-recording context): the journal is capped at the range end and pruned below its start,
// and progress pruned past the range start is discarded.
test "sync fixed journal caps ahead and discards pruned progress" {
    const gpa = testing.allocator;
    const fixed = @import("../../journal/contiguous/fixed.zig");
    const Item = [32]u8;
    const J = fixed.Journal(Item);
    var storage = runtime.storage.memory.Storage.init(gpa);
    defer storage.deinit();
    var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 44, 3);
    defer cache_ref.deinit();
    const cfg: fixed.Config = .{
        .partition = "sync-journal-test",
        .items_per_blob = 5,
        .cache_ref = &cache_ref,
        .write_buffer = 2048,
        .replay_buffer = 2048,
    };
    var setup = try J.init(gpa, storage.storage(), cfg);
    for (0..60) |value| _ = try setup.append(@splat(@intCast(value)));
    try setup.sync();
    setup.deinit();
    var journal = try init(J, gpa, storage.storage(), cfg, .{ .start = 7, .end = 20 });
    try testing.expectEqual(Bounds{ .start = 5, .end = 20 }, journal.get_bounds());
    for (7..20) |value| {
        const expected: Item = @splat(@intCast(value));
        try testing.expectEqualSlices(u8, &expected, &(try journal.read(value)));
    }
    try journal.destroy();
    var pruned = try J.init(gpa, storage.storage(), cfg);
    for (0..50) |value| _ = try pruned.append(@splat(@intCast(value)));
    try resize(&pruned, 40);
    try pruned.sync();
    try testing.expect(pruned.get_bounds().start > 7);
    pruned.deinit();
    var reopened = try init(J, gpa, storage.storage(), cfg, .{ .start = 7, .end = 60 });
    try testing.expectEqual(Bounds{ .start = 7, .end = 7 }, reopened.get_bounds());
    try reopened.destroy();
}
