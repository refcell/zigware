//! commonware's `journal/contiguous/variable.rs` tests of `authenticated.init_sync` over a
//! variable backing: fresh storage, local data overlapping, matching, exceeding, or wholly
//! below the sync range, ranges at and within blob boundaries, empty journals recovered at a
//! stale position, and the first open after a clear crashed with its intent staged.
//!
//! The reversed-range test expects a panic, which is an assertion here, and is not ported.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const contiguous = @import("mod.zig");
const fixed = @import("fixed.zig");
const variable = @import("variable.zig");
const authenticated = @import("../authenticated.zig");

const gpa = testing.allocator;
const Journal = variable.Journal(u64);
const Bounds = contiguous.Bounds;

fn bounds(start: u64, end: u64) Bounds {
    return .{ .start = start, .end = end };
}

fn Harness(comptime partition: []const u8) type {
    return struct {
        const Self = @This();
        const data = partition ++ variable.data_suffix;
        const offsets = partition ++ variable.offsets_suffix;

        storage: mocks.Storage,
        cache_ref: paged.CacheRef,

        fn init() !Self {
            return .{
                .storage = mocks.Storage.init(gpa),
                .cache_ref = try paged.CacheRef.init(gpa, 1024, 10),
            };
        }

        fn deinit(self: *Self) void {
            self.cache_ref.deinit();
            self.storage.deinit();
        }

        fn cfg(self: *Self) variable.Config(u64) {
            return .{
                .partition = partition,
                .items_per_section = 5,
                .compression = null,
                .codec_config = {},
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            };
        }

        fn iface(self: *Self) runtime.storage.Storage {
            return self.storage.interface();
        }

        fn open(self: *Self) !Journal {
            return Journal.init(gpa, self.iface(), self.cfg());
        }

        fn sync_open(self: *Self, range: Bounds) !Journal {
            return authenticated.init_sync(Journal, gpa, self.iface(), self.cfg(), range);
        }

        /// Durably write `count` items `position * scale`.
        fn seed(self: *Self, count: u64, scale: u64) !void {
            var journal = try self.open();
            defer journal.deinit();
            for (0..count) |i| _ = try journal.append(i * scale);
            try journal.sync();
        }

        /// A durable empty journal at `size`.
        fn seed_empty(self: *Self, size: u64) !void {
            var journal = try Journal.init_at_size(gpa, self.iface(), self.cfg(), size);
            defer journal.deinit();
            try journal.sync();
        }
    };
}

test "variable: init sync without existing data" {
    var h = try Harness("test-fresh-start").init();
    defer h.deinit();
    var journal = try h.sync_open(bounds(10, 26));
    try testing.expectEqual(bounds(10, 10), journal.get_bounds());
    try testing.expectEqual(10, try journal.append(42));
    try testing.expectEqual(42, try journal.read(10));
    try testing.expectEqual(11, try journal.append(43));
    try testing.expectEqual(43, try journal.read(11));
    try journal.destroy();
}

const Overlap = struct {
    /// Items `position * scale` written before the sync open.
    count: u64,
    scale: u64 = 100,
    range: Bounds,
    /// The retained bounds after the sync open.
    expected: Bounds,
};

// Local data overlapping the range is kept from the start's blob boundary, and cut at the
// range end when it runs past it.
test "variable: init sync keeps overlapping local data" {
    const cases = [_]Overlap{
        // Overlapping: blobs 1-3 kept, the range reaching past the data.
        .{ .count = 20, .range = bounds(8, 31), .expected = bounds(5, 20) },
        // Exactly matching.
        .{ .count = 20, .range = bounds(5, 20), .expected = bounds(5, 20) },
        // Exceeding the range end.
        .{ .count = 30, .scale = 1000, .range = bounds(8, 20), .expected = bounds(5, 20) },
        // At blob boundaries.
        .{ .count = 25, .range = bounds(15, 25), .expected = bounds(15, 25) },
        // Within one blob.
        .{ .count = 15, .range = bounds(10, 15), .expected = bounds(10, 15) },
    };
    for (cases) |case| try check_overlap(case);
}

fn check_overlap(case: Overlap) !void {
    var h = try Harness("test-overlap").init();
    defer h.deinit();
    try h.seed(case.count, case.scale);
    var journal = try h.sync_open(case.range);
    defer journal.deinit();
    const expected = case.expected;
    try testing.expectEqual(expected, journal.get_bounds());
    if (expected.start > 0) {
        try testing.expectError(error.ItemPruned, journal.read(0));
        try testing.expectError(error.ItemPruned, journal.read(expected.start - 1));
    }
    for (expected.start..expected.end) |i| {
        try testing.expectEqual(i * case.scale, try journal.read(i));
    }
    try testing.expectError(error.ItemOutOfRange, journal.read(expected.end));
    try testing.expectEqual(expected.end, try journal.append(999));
    try testing.expectEqual(999, try journal.read(expected.end));
}

// Every local item is below the range: the journal restarts empty at the range start.
test "variable: init sync replaces stale local data" {
    var h = try Harness("test-stale").init();
    defer h.deinit();
    try h.seed(10, 100);
    var journal = try h.sync_open(bounds(15, 26));
    defer journal.deinit();
    try testing.expectEqual(bounds(15, 15), journal.get_bounds());
    for ([_]u64{ 0, 9, 14 }) |i| try testing.expectError(error.ItemPruned, journal.read(i));
}

test "variable: init sync repairs an empty journal at a stale position past the range" {
    var h = try Harness("test-empty-stale-position").init();
    defer h.deinit();
    try h.seed_empty(30);
    var journal = try h.sync_open(bounds(10, 26));
    try testing.expectEqual(bounds(10, 10), journal.get_bounds());
    try testing.expectEqual(10, try journal.append(999));
    try testing.expectEqual(999, try journal.read(10));
    try journal.destroy();
}

// A clear_to_size(7) crashed after clearing the data but before re-clearing the offsets,
// which still hold the old empty boundary at 9.
test "variable: init sync recovers from a stale clear to size" {
    const H = Harness("test-stale-clear-to-size");
    var h = try H.init();
    defer h.deinit();
    try h.seed_empty(9);
    try contiguous.blobs.remove_all(h.iface(), H.data);
    var journal = try h.sync_open(bounds(7, 20));
    try testing.expectEqual(bounds(7, 7), journal.get_bounds());
    try journal.destroy();
}

// A clear to 50 crashed after staging its intent, before or after removing the data. A
// staged clear spans only its target, so a start of 50 completes it and starts 7 and 60
// replace it with a clear to the start.
test "variable: init sync after an interrupted clear" {
    for ([_]u64{ 7, 50, 60 }) |start| {
        for ([_]bool{ false, true }) |removed| {
            try check_interrupted_clear(start, removed);
        }
    }
}

fn check_interrupted_clear(start: u64, removed: bool) !void {
    const H = Harness("test-interrupted-clear");
    var h = try H.init();
    defer h.deinit();
    try h.seed(30, 1);
    try fixed.Journal(u64).test_stage_clear(gpa, h.iface(), H.offsets, 50);
    if (removed) try contiguous.blobs.remove_all(h.iface(), H.data);
    {
        var journal = try h.sync_open(bounds(start, start + 20));
        defer journal.deinit();
        try testing.expectEqual(bounds(start, start), journal.get_bounds());
        for (0..3) |i| try testing.expectEqual(start + i, try journal.append(1000 + i));
        try journal.sync();
    }
    var journal = try h.open();
    try testing.expectEqual(bounds(start, start + 3), journal.get_bounds());
    for (0..3) |i| try testing.expectEqual(1000 + i, try journal.read(start + i));
    // No stale item from before the clear is readable.
    for (0..30) |position| {
        const result = journal.read(position);
        if (position < start) {
            try testing.expectError(error.ItemPruned, result);
        } else if (position >= start + 3) {
            try testing.expectError(error.ItemOutOfRange, result);
        }
    }
    try journal.destroy();
}
