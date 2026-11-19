//! commonware's `journal/contiguous/variable.rs` tests of recovery after lost or damaged data:
//! an `init_at_most` truncation that survives a crash (on `runtime.storage.faulty`) and a
//! commit after it, acknowledged data cut to a blob boundary, a short blob after the replay
//! anchor, trailing offsets and data bytes whose repair must be durable, offsets lost after a
//! prune, offsets rebuilt after a data-only sync, a mid-blob durable anchor, a full newest
//! blob with no successor, a crash between the offsets and data truncation, and a gap in the
//! retained blobs.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const paged = runtime.buffer.paged;
const contiguous = @import("mod.zig");
const fixed = @import("fixed.zig");
const variable = @import("variable.zig");
const manager_mod = @import("../segmented/manager.zig");

const gpa = testing.allocator;
const Journal = variable.Journal(u64);
const Bounds = contiguous.Bounds;

fn bounds(start: u64, end: u64) Bounds {
    return .{ .start = start, .end = end };
}

const Options = struct {
    items_per_section: u64 = 10,
    page_size: u16 = 1024,
    write_buffer: usize = 1024,
};

/// A variable journal over fault-injecting memory storage.
fn Harness(comptime partition: []const u8) type {
    return struct {
        const Self = @This();
        const Faulty = runtime.storage.faulty.Storage(utils.rng.TestRng);
        const data = partition ++ variable.data_suffix;
        const offsets = partition ++ variable.offsets_suffix;
        const offsets_blobs = offsets ++ "-blobs";

        inner: runtime.storage.memory.Storage,
        rng: utils.rng.TestRng,
        storage: Faulty,
        cache_ref: paged.CacheRef,
        options: Options,

        fn init(self: *Self, options: Options) !void {
            self.inner = .init(gpa);
            self.rng = .init(0);
            self.storage = .init(gpa, &self.inner, &self.rng, .{});
            self.cache_ref = try paged.CacheRef.init(gpa, options.page_size, 10);
            self.options = options;
        }

        fn deinit(self: *Self) void {
            self.cache_ref.deinit();
            self.storage.deinit();
            self.inner.deinit();
        }

        fn cfg(self: *Self) variable.Config(u64) {
            return .{
                .partition = partition,
                .items_per_section = self.options.items_per_section,
                .compression = null,
                .codec_config = {},
                .cache_ref = &self.cache_ref,
                .write_buffer = self.options.write_buffer,
                .replay_buffer = 1024,
            };
        }

        fn iface(self: *Self) runtime.storage.Storage {
            return self.storage.storage();
        }

        fn open(self: *Self) !Journal {
            return Journal.init(gpa, self.iface(), self.cfg());
        }

        fn crash(self: *Self) !void {
            try self.storage.crash();
            self.inner.crash();
        }

        /// Durably write `count` items `position * 100`.
        fn seed(self: *Self, count: u64) !void {
            var journal = try self.open();
            defer journal.deinit();
            for (0..count) |i| _ = try journal.append(i * 100);
            try journal.sync();
        }

        fn remove_data(self: *Self, blob: u64) !void {
            try self.iface().remove(data, &manager_mod.section_name(blob));
        }

        /// A paged writer over blob 0 of `blobs`; the caller deinits it.
        fn writer(self: *Self, blobs: []const u8, blob: u64) !paged.Writer {
            const opened = try self.iface().open(blobs, &manager_mod.section_name(blob));
            errdefer opened.blob.close();
            return paged.Writer.open_recovery(gpa, opened.blob, opened.len, 2048, &self.cache_ref);
        }

        fn logical_size(self: *Self, blobs: []const u8) !u64 {
            var w = try self.writer(blobs, 0);
            defer w.deinit();
            return w.size();
        }
    };
}

fn expect_scaled(journal: *Journal, start: u64, end: u64) !void {
    for (start..end) |i| try testing.expectEqual(i * 100, try journal.read(i));
}

// Four nine-byte frames fill a 36-byte page, so the eight-item cap is page aligned. A
// nine-item append after the cap leaves eight items in two full pages and one buffered, and
// the crash keeps unsynced writes but drops unsynced resizes. The recovered history is the
// capped prefix followed by a prefix of the new items, never the old items past the cap.
test "variable: an init_at_most truncation survives a crash" {
    const H = Harness("variable-init-at-most-truncation-crash");
    var h: H = undefined;
    try h.init(.{ .items_per_section = 100, .page_size = 36, .write_buffer = 1 });
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..24) |value| _ = try journal.append(value);
        try journal.sync();
    }
    h.storage.config = .{
        .write_rate = .{ .failure_rate = .zero, .retention_rate = .one, .mode = .prefix },
        .resize_rate = .{ .failure_rate = .zero, .partial_rate = .zero },
    };
    const bound = 8;
    var appended: [9]u64 = undefined;
    for (&appended, 100..) |*value, i| value.* = i;
    {
        var journal = try Journal.init_at_most(gpa, h.iface(), h.cfg(), bound);
        defer journal.deinit();
        try testing.expectEqual(bounds(0, bound), journal.get_bounds());
        _ = try journal.append_many(&appended);
    }
    try h.crash();
    h.storage.config = .{};
    var journal = try h.open();
    defer journal.deinit();
    const recovered = journal.get_bounds();
    try testing.expectEqual(0, recovered.start);
    try testing.expect(recovered.end >= bound and recovered.end <= bound + appended.len);
    for (0..bound) |position| try testing.expectEqual(position, try journal.read(position));
    for (bound..recovered.end) |position| {
        try testing.expectEqual(appended[position - bound], try journal.read(position));
    }
}

// A bounded open followed by a commit reopens at the cap.
test "variable: init_at_most then commit and reopen" {
    const H = Harness("rewind-commit-reopen");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(25);
    {
        var journal = try Journal.init_at_most(gpa, h.iface(), h.cfg(), 12);
        defer journal.deinit();
        try journal.commit();
    }
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 12), journal.get_bounds());
    try expect_scaled(&journal, 0, 12);
    try testing.expectError(error.ItemOutOfRange, journal.read(12));
}

// The watermark acknowledges 20 items, so data ending exactly at the blob boundary 10 lost
// acknowledged items: every open reports corruption.
test "variable: recovery rejects synced data cut to a blob boundary" {
    const H = Harness("recovery-boundary-data-rewind");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(20);
    try h.remove_data(2);
    try h.remove_data(1);
    for (0..2) |_| try testing.expectError(error.Corruption, h.open());
}

// Blob 1 cut to two frames past a watermark of 10 is a crash before its sync: recovery keeps
// the contiguous prefix 0..12 and discards blob 2 instead of reporting the blob jump.
test "variable: recovery truncates a short data blob after the anchor" {
    const H = Harness("recovery-short-blob-after-anchor");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(25);
    {
        var journal = try h.open();
        defer journal.deinit();
        try journal.test_set_offsets_recovery_watermark(10);
    }
    {
        // Nine-byte frames: items 10 and 11 end at byte 18 of blob 1.
        var w = try h.writer(H.data, 1);
        defer w.deinit();
        try w.truncate(18);
    }
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 12), journal.get_bounds());
    try testing.expectEqual(12, journal.test_offsets_size());
    try expect_scaled(&journal, 0, 12);
    try testing.expectError(error.ItemOutOfRange, journal.read(12));
}

// A trailing partial offset (one byte) is trimmed by the open, and the trim survives a crash.
test "variable: init persists an offsets trailing-item repair" {
    const H = Harness("offsets-init-repair-sync");
    try check_trailing_repair(H, H.offsets_blobs, &.{0});
}

// Trailing bytes that are no frame are trimmed from the data by the open, durably.
test "variable: init persists a data tail repair" {
    const H = Harness("data-init-repair-sync");
    try check_trailing_repair(H, H.data, &.{ 0xFF, 0xFF });
}

fn check_trailing_repair(comptime H: type, blobs: []const u8, junk: []const u8) !void {
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        _ = try journal.append(10);
        _ = try journal.append(20);
        try journal.sync();
    }
    const expected = try h.logical_size(blobs);
    {
        var w = try h.writer(blobs, 0);
        defer w.deinit();
        _ = try w.append(junk);
        try w.sync();
    }
    try testing.expectEqual(expected + junk.len, try h.logical_size(blobs));
    {
        var journal = try h.open();
        defer journal.deinit();
        try testing.expectEqual(bounds(0, 2), journal.get_bounds());
    }
    try h.crash();
    try testing.expectEqual(expected, try h.logical_size(blobs));
}

// A journal emptied by a prune, then given data that is synced while its offsets are not,
// recovers the new items from the data.
test "variable: recovery of empty offsets after a prune and append" {
    const H = Harness("recovery-empty-after-prune");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..10) |i| _ = try journal.append(i * 100);
        _ = try journal.prune(10);
        try testing.expectEqual(bounds(10, 10), journal.get_bounds());
        for (10..20) |i| _ = try journal.test_append_data(i * 100);
        try journal.blobs.sync();
    }
    try h.crash();
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(10, 20), journal.get_bounds());
    try expect_scaled(&journal, 10, 20);
    for (0..10) |i| try testing.expectError(error.ItemPruned, journal.read(i));
}

// A data-only sync across a blob boundary leaves the offsets for recovery to rebuild.
test "variable: offsets are rebuilt after a data-only sync" {
    const H = Harness("concurrent-sync-recovery");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..15) |i| _ = try journal.append(i * 100);
        try journal.commit();
    }
    try h.crash();
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(15, journal.size());
    try expect_scaled(&journal, 0, 15);
}

// A journal that starts mid-blob at 7 with only its first item synced recovers the committed
// items after it.
test "variable: recovery from a mid-blob durable anchor" {
    const H = Harness("mid-blob-durable-anchor");
    var h: H = undefined;
    try h.init(.{ .items_per_section = 5 });
    defer h.deinit();
    {
        var journal = try Journal.init_at_size(gpa, h.iface(), h.cfg(), 7);
        defer journal.deinit();
        try testing.expectEqual(7, try journal.append(700));
        try journal.sync();
        for (1..6) |i| try testing.expectEqual(7 + i, try journal.append(700 + i));
        try journal.commit();
    }
    try h.crash();
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(7, 13), journal.get_bounds());
    for (0..6) |i| try testing.expectEqual(700 + i, try journal.read(7 + i));
}

// A full newest blob without its empty successor (the layout before eager tail creation)
// opens and appends into a new blob.
test "variable: recovery of a full newest blob without a successor" {
    const H = Harness("recovery-full-newest-no-successor");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(10);
    try h.remove_data(1);
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 10), journal.get_bounds());
    try expect_scaled(&journal, 0, 10);
    try testing.expectEqual(10, try journal.append(1000));
    try testing.expectEqual(1000, try journal.read(10));
}

// Initialization truncates the offsets (lowering their watermark) before the data. A crash
// in between leaves offsets behind the data, and recovery rebuilds them in full.
test "variable: a crash between the offsets and data truncation" {
    const H = Harness("rewind-crash-offsets-only");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(25);
    {
        const cfg = h.cfg();
        const offsets_cfg: fixed.Config = .{
            .partition = H.offsets,
            .items_per_blob = cfg.items_per_section,
            .cache_ref = cfg.cache_ref,
            .write_buffer = cfg.write_buffer,
            .replay_buffer = cfg.replay_buffer,
        };
        var offsets = try fixed.Journal(u64).init_at_most(gpa, h.iface(), offsets_cfg, 12);
        defer offsets.deinit();
        try testing.expectEqual(bounds(0, 12), offsets.get_bounds());
    }
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 25), journal.get_bounds());
    try expect_scaled(&journal, 0, 25);
}

// Retained data blobs must be contiguous: a missing interior blob is corruption.
test "variable: recovery rejects a gap in the retained blobs" {
    const H = Harness("recovery-gap-in-retained-blobs");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(25);
    try h.remove_data(1);
    try testing.expectError(error.Corruption, h.open());
}
