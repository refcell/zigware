//! commonware's `journal/contiguous/variable.rs` tests of recovery when the offsets journal
//! and the data blobs disagree: crashes between a data prune and its offsets prune, offsets
//! ahead of, behind, or in another blob than the data, stale offsets watermarks, and data
//! blobs holding more items than a section.
//!
//! commonware's `test_truncate_offsets` becomes a bounded reopen of the offsets journal alone,
//! and an interrupted prune becomes a data sync and data-only prune before a crash.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const contiguous = @import("mod.zig");
const fixed = @import("fixed.zig");
const variable = @import("variable.zig");
const frame = @import("../frame.zig");
const manager_mod = @import("../segmented/manager.zig");

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
                .items_per_section = 10,
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

        fn open_at_most(self: *Self, cap: u64) !Journal {
            return Journal.init_at_most(gpa, self.iface(), self.cfg(), cap);
        }

        /// A journal of `count` items `position * 100`.
        fn fill(self: *Self, count: u64) !Journal {
            var journal = try self.open();
            errdefer journal.deinit();
            for (0..count) |i| try testing.expectEqual(i, try journal.append(i * 100));
            return journal;
        }

        /// Durably keep only the first `size` offsets entries, leaving the data blobs alone.
        fn truncate_offsets(self: *Self, size: u64) !void {
            const offsets_cfg: fixed.Config = .{
                .partition = offsets,
                .items_per_blob = 10,
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            };
            var journal = try fixed.Journal(u64).init_at_most(gpa, self.iface(), offsets_cfg, size);
            journal.deinit();
        }

        /// Durably append the frame of `item` to data blob `index`, below the journal.
        fn append_raw_frame(self: *Self, index: u64, item: u64) !void {
            const opened = try self.iface().open(data, &manager_mod.section_name(index));
            var writer = try paged.Writer.init(gpa, opened.blob, opened.len, 1024, &self.cache_ref);
            defer writer.deinit();
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(gpa);
            _ = try frame.encode_frame_into(u64, gpa, null, item, &encoded);
            _ = try writer.append(encoded.items);
            try writer.sync();
        }
    };
}

fn expect_items(journal: *Journal, start: u64, end: u64) !void {
    for (start..end) |i| try testing.expectEqual(i * 100, try journal.read(i));
}

// The prune made the data durable and removed blob 0, then crashed before its offsets prune
// made the appended offsets durable: the durable offsets end (7) is below the new data
// start (10).
test "variable: a prune crash leaves the offsets end behind the data" {
    const Test = Harness("recovery-prune-offsets-end-behind");
    var h = try Test.init();
    defer h.deinit();
    {
        var journal = try h.fill(7);
        defer journal.deinit();
        try journal.sync();
        for (7..12) |i| _ = try journal.append(i * 100);
        try journal.blobs.sync();
        try testing.expect(try journal.test_prune_data(1));
    }
    h.storage.crash();
    var journal = try h.open();
    try testing.expectEqual(bounds(10, 12), journal.get_bounds());
    try expect_items(&journal, 10, 12);
    try journal.destroy();
}

test "variable: recovery after several data prunes ahead of the offsets" {
    const Test = Harness("recovery-multiple-prunes");
    var h = try Test.init();
    defer h.deinit();
    {
        var journal = try h.fill(50);
        defer journal.deinit();
        _ = try journal.prune(10);
        try testing.expectEqual(10, journal.get_bounds().start);
        // The data is pruned to 30 while the offsets still start at 10.
        try testing.expect(try journal.test_prune_data(3));
        try journal.sync();
    }
    var journal = try h.open();
    try testing.expectEqual(bounds(30, 50), journal.get_bounds());
    try testing.expectError(error.ItemPruned, journal.read(10));
    try testing.expectError(error.ItemPruned, journal.read(20));
    try testing.expectEqual(3000, try journal.read(30));
    try testing.expectEqual(4900, try journal.read(49));
    try journal.destroy();
}

// init and init_at_size always place both journals in one blob.
test "variable: empty offsets in another blob than the data are corruption" {
    const Test = Harness("offsets-empty-diff-blob");
    var h = try Test.init();
    defer h.deinit();
    {
        var journal = try h.fill(15);
        defer journal.deinit();
        try journal.sync();
        try journal.offsets.clear_to_size(20);
    }
    try testing.expectError(error.Corruption, h.open());
}

// The data is pruned to blob 1 (position 10) and the offsets rewound to 5, so the offsets end
// before the oldest retained data, also under a bound equal to the retained start.
test "variable: offsets ending before the oldest data are corruption" {
    const Test = Harness("offsets-end-behind-data-oldest");
    var h = try Test.init();
    defer h.deinit();
    {
        var journal = try h.fill(15);
        defer journal.deinit();
        try journal.sync();
        try testing.expect(try journal.test_prune_data(1));
    }
    try h.truncate_offsets(5);
    try testing.expectError(error.Corruption, h.open());
    try testing.expectError(error.Corruption, h.open_at_most(10));
}

// init_at_size(7) starts the offsets mid-blob 0, ahead of the data's blob-aligned start.
test "variable: offsets starting mid-blob ahead of the data recover" {
    const Test = Harness("offsets-mid-blob-ahead");
    var h = try Test.init();
    defer h.deinit();
    {
        var journal = try Journal.init_at_size(gpa, h.iface(), h.cfg(), 7);
        defer journal.deinit();
        for (0..5) |i| _ = try journal.append(i * 100);
        try journal.sync();
    }
    var journal = try h.open();
    try testing.expectEqual(bounds(7, 12), journal.get_bounds());
    try testing.expectEqual(0, try journal.read(7));
    try testing.expectEqual(400, try journal.read(11));
    try journal.destroy();
}

// A prune moved the offsets start past a watermark that no sync advanced: recovery rebuilds
// from the offsets start.
test "variable: an offsets watermark below the offsets start is rebuilt" {
    const Test = Harness("watermark-below-start");
    var h = try Test.init();
    defer h.deinit();
    {
        var journal = try h.fill(25);
        defer journal.deinit();
        try journal.sync();
        _ = try journal.prune(10);
        try journal.test_set_offsets_recovery_watermark(5);
    }
    var journal = try h.open();
    try testing.expectEqual(bounds(10, 25), journal.get_bounds());
    try testing.expectEqual(1000, try journal.read(10));
    try testing.expectEqual(2400, try journal.read(24));
    try journal.destroy();
}

test "variable: offsets behind data across blobs are rebuilt" {
    const Test = Harness("recovery-rewind-crash");
    var h = try Test.init();
    defer h.deinit();
    {
        var journal = try h.fill(25);
        defer journal.deinit();
        try journal.sync();
    }
    try h.truncate_offsets(5);
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 25), journal.get_bounds());
    try expect_items(&journal, 0, 25);
    try testing.expectEqual(25, journal.test_offsets_size());
    try testing.expectEqual(25, try journal.append(2500));
    try testing.expectEqual(2500, try journal.read(25));
    try journal.destroy();
}

test "variable: recovery rejects an overlong data blob" {
    const Test = Harness("recovery-overlong-data-blob");
    var h = try Test.init();
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..11) |i| _ = try journal.test_append_data(i * 100);
        try journal.blobs.sync();
    }
    try testing.expectError(error.Corruption, h.open());
}

// The newest-blob preflight passes; the offsets are empty, so the rebuild replays from blob
// 0 and finds it over capacity.
test "variable: recovery rejects an over-capacity blob below the newest" {
    const Test = Harness("recovery-over-capacity-non-newest");
    var h = try Test.init();
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..11) |i| _ = try journal.test_append_data(i * 100);
        try journal.blobs.sync();
    }
    try h.append_raw_frame(1, 9999);
    try testing.expectError(error.Corruption, h.open());
}
