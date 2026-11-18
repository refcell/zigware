//! commonware's `journal/contiguous/variable.rs` tests of `init_at_size` and `clear_to_size`:
//! staged resets and their crash points, conflicting offsets partitions, stale data in the
//! reset blob, mid-blob starts across blobs, data-only crashes after a reset, and resets
//! failing on sync or remove faults (on `runtime.storage.faulty`).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const contiguous = @import("mod.zig");
const fixed = @import("fixed.zig");
const variable = @import("variable.zig");
const manager_mod = @import("../segmented/manager.zig");

const gpa = testing.allocator;
const Journal = variable.Journal(u64);
const Bounds = contiguous.Bounds;
const max = std.math.maxInt(u64);

fn bounds(start: u64, end: u64) Bounds {
    return .{ .start = start, .end = end };
}

fn config(partition: []const u8, items: u64, cache_ref: *paged.CacheRef) variable.Config(u64) {
    return .{
        .partition = partition,
        .items_per_section = items,
        .compression = null,
        .codec_config = {},
        .cache_ref = cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
}

fn Harness(comptime partition: []const u8) type {
    return struct {
        const Self = @This();
        const data = partition ++ variable.data_suffix;
        const offsets = partition ++ variable.offsets_suffix;

        storage: mocks.Storage,
        cache_ref: paged.CacheRef,
        items_per_section: u64,

        fn init(items_per_section: u64) !Self {
            return .{
                .storage = mocks.Storage.init(gpa),
                .cache_ref = try paged.CacheRef.init(gpa, 1024, 10),
                .items_per_section = items_per_section,
            };
        }

        fn deinit(self: *Self) void {
            self.cache_ref.deinit();
            self.storage.deinit();
        }

        fn cfg(self: *Self) variable.Config(u64) {
            return config(partition, self.items_per_section, &self.cache_ref);
        }

        fn iface(self: *Self) runtime.storage.Storage {
            return self.storage.interface();
        }

        fn open(self: *Self) !Journal {
            return Journal.init(gpa, self.iface(), self.cfg());
        }

        fn open_at_size(self: *Self, size: u64) !Journal {
            return Journal.init_at_size(gpa, self.iface(), self.cfg(), size);
        }

        /// Durably write `count` items `first + i` from position zero.
        fn seed(self: *Self, first: u64, count: u64) !void {
            var journal = try self.open();
            defer journal.deinit();
            for (0..count) |i| _ = try journal.append(first + i);
            try journal.sync();
        }

        /// Durably stage a clear to `target` in the offsets checkpoint.
        fn stage_clear(self: *Self, target: u64) !void {
            try fixed.Journal(u64).test_stage_clear(gpa, self.iface(), offsets, target);
        }

        fn remove_data(self: *Self) !void {
            try contiguous.blobs.remove_all(self.iface(), data);
        }
    };
}

/// Check positions `[start, start + count)` hold `first + i`.
fn expect_values(journal: *Journal, start: u64, count: u64, first: u64) !void {
    for (0..count) |i| try testing.expectEqual(first + i, try journal.read(start + i));
}

/// Append 700 at `size`, sync, reopen, and check the journal holds exactly it from `size`.
fn expect_reset_at(h: anytype, size: u64, journal: *Journal) !void {
    try testing.expectEqual(bounds(size, size), journal.get_bounds());
    try testing.expectEqual(size, try journal.append(700));
    try journal.sync();
    journal.deinit();
    journal.* = try h.open();
    try testing.expectEqual(bounds(size, size + 1), journal.get_bounds());
    try testing.expectEqual(700, try journal.read(size));
    try journal.destroy();
}

// The consistency check must fail before a reset is staged, which would erase the
// conflicting partitions and their evidence.
test "variable: init at size rejects conflicting offsets partitions" {
    const H = Harness("init-at-size-conflicting-offsets");
    var h = try H.init(5);
    defer h.deinit();
    for ([_][]const u8{ H.offsets, H.offsets ++ "-blobs" }) |name| {
        const opened = try h.iface().open(name, &manager_mod.section_name(0));
        defer opened.blob.close();
        try opened.blob.write_at(0, &.{0}, .{ .sync = true });
    }
    try testing.expectError(error.Corruption, h.open_at_size(7));
    for ([_][]const u8{ H.offsets, H.offsets ++ "-blobs" }) |name| {
        const indices = try contiguous.blobs.indices(gpa, h.iface(), name);
        defer gpa.free(indices);
        try testing.expectEqual(1, indices.len);
    }
}

// A crash mid-init_at_size: the clear intent is staged, with the data untouched or removed.
test "variable: init recovers a staged reset at either crash point" {
    for ([_]bool{ false, true }) |clear_data| {
        const H = Harness("init-at-size-staged-reset-crash");
        var h = try H.init(5);
        defer h.deinit();
        try h.seed(100, 12);
        try h.stage_clear(7);
        if (clear_data) try h.remove_data();
        var journal = try h.open();
        try expect_reset_at(&h, 7, &journal);
    }
}

// A clear_to_size(5) crashed after staging; init_at_size(10) replaces its target.
test "variable: init at size overwrites a pending clear target" {
    const H = Harness("init-at-size-overwrites-pending-target");
    var h = try H.init(5);
    defer h.deinit();
    try h.seed(100, 12);
    try h.stage_clear(5);
    var journal = try h.open_at_size(10);
    try expect_reset_at(&h, 10, &journal);
}

test "variable: init at size discards stale data in the same blob" {
    const H = Harness("init-at-size-discards-same-blob-stale-data");
    var h = try H.init(5);
    defer h.deinit();
    {
        var journal = try h.open_at_size(5);
        defer journal.deinit();
        for (0..4) |i| try testing.expectEqual(5 + i, try journal.append(500 + i));
        try journal.sync();
    }
    {
        var journal = try h.open_at_size(7);
        journal.deinit();
    }
    var journal = try h.open();
    try testing.expectEqual(bounds(7, 7), journal.get_bounds());
    try testing.expectError(error.ItemOutOfRange, journal.read(7));
    try expect_reset_at(&h, 7, &journal);
}

test "variable: init at size mid-blob persists across blobs" {
    const H = Harness("init-at-size-multi-blob");
    var h = try H.init(5);
    defer h.deinit();
    for ([_]u64{ 3, 8 }) |count| {
        {
            var journal = try h.open_at_size(7);
            defer journal.deinit();
            for (0..count) |i| try testing.expectEqual(7 + i, try journal.append(700 + i));
            try testing.expectEqual(bounds(7, 7 + count), journal.get_bounds());
            try journal.sync();
        }
        var journal = try h.open();
        try testing.expectEqual(bounds(7, 7 + count), journal.get_bounds());
        try expect_values(&journal, 7, count, 700);
        try testing.expectError(error.ItemPruned, journal.read(6));
        try journal.destroy();
    }
}

// The data was cleared but the offsets not pruned: recovery keeps the mid-blob boundary at
// 7, and an item whose data alone was synced survives a crash.
test "variable: empty data keeps a mid-blob pruning boundary" {
    const H = Harness("align-journals-mid-blob-pruning-boundary");
    var h = try H.init(5);
    defer h.deinit();
    try h.seed(100, 7);
    try h.remove_data();
    {
        var journal = try h.open();
        defer journal.deinit();
        try testing.expectEqual(bounds(7, 7), journal.get_bounds());
        try testing.expectEqual(7, try journal.append(777));
        try testing.expectEqual(777, try journal.read(7));
        try journal.blobs.sync();
    }
    h.storage.crash();
    var journal = try h.open();
    try testing.expectEqual(bounds(7, 8), journal.get_bounds());
    try testing.expectEqual(777, try journal.read(7));
    try journal.destroy();
}

// Data synced (the rollover sealing blob 1), offsets not: recovery rebuilds the offsets.
test "variable: init at size then a crash with data synced and offsets not" {
    const H = Harness("init-at-size-crash-recovery");
    var h = try H.init(5);
    defer h.deinit();
    {
        var journal = try h.open_at_size(7);
        defer journal.deinit();
        for (0..3) |i| _ = try journal.append(700 + i);
    }
    h.storage.crash();
    var journal = try h.open();
    try testing.expectEqual(bounds(7, 10), journal.get_bounds());
    try expect_values(&journal, 7, 3, 700);
    try journal.destroy();
}

test "variable: recovery near the maximum size with data synced and offsets not" {
    const H = Harness("near-max-data-synced-offsets-not");
    var h = try H.init(10);
    defer h.deinit();
    {
        var journal = try h.open_at_size(max - 1);
        defer journal.deinit();
        try testing.expectEqual(max - 1, try journal.append(7));
        try journal.blobs.sync();
    }
    h.storage.crash();
    var journal = try h.open();
    try testing.expectEqual(bounds(max - 1, max), journal.get_bounds());
    try testing.expectEqual(7, try journal.read(max - 1));
    try journal.destroy();
}

test "variable: prune does not move the oldest retained position backward" {
    const H = Harness("prune-no-backwards");
    var h = try H.init(5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    for (0..3) |i| try testing.expectEqual(7 + i, try journal.append(700 + i));
    _ = try journal.prune(8);
    try testing.expectEqual(7, journal.get_bounds().start);
    try testing.expectError(error.ItemPruned, journal.read(6));
    try testing.expectEqual(700, try journal.read(7));
    try journal.destroy();
}

test "variable: init at a large size, then prune and append" {
    const H = Harness("init-at-size-large");
    var h = try H.init(5);
    defer h.deinit();
    var journal = try h.open_at_size(1000);
    try testing.expectEqual(bounds(1000, 1000), journal.get_bounds());
    try testing.expectEqual(1000, try journal.append(100_000));
    try testing.expectEqual(100_000, try journal.read(1000));
    try journal.destroy();
    journal = try h.open_at_size(20);
    for (0..10) |i| _ = try journal.append(2000 + i);
    _ = try journal.prune(25);
    try testing.expectEqual(bounds(25, 30), journal.get_bounds());
    try expect_values(&journal, 25, 5, 2005);
    try testing.expectEqual(30, try journal.append(3000));
    try journal.destroy();
}

/// A journal over fault-injecting storage, for resets that fail partway.
const FaultyHarness = struct {
    const Faulty = runtime.storage.faulty.Storage(utils.rng.TestRng);

    inner: runtime.storage.memory.Storage,
    rng: utils.rng.TestRng,
    storage: Faulty,
    cache_ref: paged.CacheRef,

    fn init(self: *FaultyHarness) !void {
        self.inner = .init(gpa);
        self.rng = .init(0);
        self.storage = .init(gpa, &self.inner, &self.rng, .{});
        self.cache_ref = try paged.CacheRef.init(gpa, 1024, 10);
    }

    fn deinit(self: *FaultyHarness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
        self.inner.deinit();
    }

    fn cfg(self: *FaultyHarness) variable.Config(u64) {
        return config("reset-faults", 5, &self.cache_ref);
    }

    fn open(self: *FaultyHarness) !Journal {
        return Journal.init(gpa, self.storage.storage(), self.cfg());
    }

    /// A synced journal of the twelve items `100 + i`, left open.
    fn seeded(self: *FaultyHarness) !Journal {
        var journal = try self.open();
        errdefer journal.deinit();
        for (0..12) |i| _ = try journal.append(100 + i);
        try journal.sync();
        return journal;
    }

    fn crash(self: *FaultyHarness) !void {
        try self.storage.crash();
        self.inner.crash();
        self.storage.config = .{};
    }

    /// Reopen after a reset that failed before its intent was durable.
    fn expect_unchanged(self: *FaultyHarness) !void {
        var journal = try self.open();
        try testing.expectEqual(bounds(0, 12), journal.get_bounds());
        try expect_values(&journal, 0, 12, 100);
        try journal.destroy();
    }
};

// A failed sync aborts the reset before its intent is durable, so nothing is cleared.
test "variable: init at size stages its reset before clearing data" {
    var h: FaultyHarness = undefined;
    try h.init();
    defer h.deinit();
    var journal = try h.seeded();
    journal.deinit();
    h.storage.config = .{ .sync_rate = .one };
    const storage = h.storage.storage();
    try testing.expect(std.meta.isError(Journal.init_at_size(gpa, storage, h.cfg(), 7)));
    try h.crash();
    try h.expect_unchanged();
}

test "variable: clear to size stages its reset before clearing data" {
    var h: FaultyHarness = undefined;
    try h.init();
    defer h.deinit();
    var journal = try h.seeded();
    h.storage.config = .{ .sync_rate = .one };
    try testing.expect(std.meta.isError(journal.clear_to_size(17)));
    journal.deinit();
    try h.crash();
    try h.expect_unchanged();
}

// The intent is durable but removing the data fails: init completes the reset.
test "variable: a clear interrupted after staging completes on init" {
    var h: FaultyHarness = undefined;
    try h.init();
    defer h.deinit();
    var journal = try h.seeded();
    h.storage.config = .{ .remove_rate = .one };
    try testing.expect(std.meta.isError(journal.clear_to_size(17)));
    journal.deinit();
    try h.crash();
    journal = try h.open();
    try testing.expectEqual(bounds(17, 17), journal.get_bounds());
    try testing.expectEqual(17, try journal.append(700));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(17, 18), journal.get_bounds());
    try testing.expectEqual(700, try journal.read(17));
    try journal.destroy();
}
