//! commonware's `journal/contiguous/variable.rs` tests of bounded inspection and
//! initialization: an unpublished bounded open leaves acknowledged offsets and data above the
//! watermark in place, recovery faults never clear durable data, missing acknowledged data is
//! corruption, interrupted empty publications and offset rebuilds stay recoverable, and
//! `init_at_most` retries after storage faults, restarts, and skips discarded blobs. Faults run
//! on `runtime.storage.faulty`.
//!
//! `test_clean_initialization_cap_adds_no_syncs` counts mutations, which include syncs.
//! Not ported: `test_selected_prefix_reuses_known_offsets` and
//! `test_initialization_decodes_each_recovery_frame_once` count decodes through a
//! `Read::Cfg` counter, which is accounting zigware's codec does not expose. The interrupted
//! rebuild test keeps its storage assertions but not its decode count.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const contiguous = @import("mod.zig");
const fixed = @import("fixed.zig");
const variable = @import("variable.zig");
const Checkpoint = @import("checkpoint.zig").Checkpoint;
const authenticated = @import("../authenticated.zig");
const manager_mod = @import("../segmented/manager.zig");

const gpa = testing.allocator;
const Journal = variable.Journal(u64);
const Bounds = contiguous.Bounds;
const max = std.math.maxInt(u64);

fn bounds(start: u64, end: u64) Bounds {
    return .{ .start = start, .end = end };
}

const Options = struct {
    items_per_section: u64 = 5,
    compression: ?u8 = null,
    page_size: u16 = 16,
    cache_pages: u32 = 4,
    write_buffer: usize = 1,
    replay_buffer: usize = 256,
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
            self.cache_ref = try paged.CacheRef.init(gpa, options.page_size, options.cache_pages);
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
                .compression = self.options.compression,
                .codec_config = {},
                .cache_ref = &self.cache_ref,
                .write_buffer = self.options.write_buffer,
                .replay_buffer = self.options.replay_buffer,
            };
        }

        fn iface(self: *Self) runtime.storage.Storage {
            return self.storage.storage();
        }

        fn open(self: *Self) !Journal {
            return Journal.init(gpa, self.iface(), self.cfg());
        }

        fn open_at_most(self: *Self, cap: ?u64) !Journal {
            const c = cap orelse return self.open();
            return Journal.init_at_most(gpa, self.iface(), self.cfg(), c);
        }

        fn recover(self: *Self, cap: ?u64) !variable.Recovery(u64) {
            return Journal.recover(gpa, self.iface(), self.cfg(), cap);
        }

        fn crash(self: *Self) !void {
            try self.storage.crash();
            self.inner.crash();
        }

        /// Durably write items `start..end` at positions `start..end`.
        fn seed(self: *Self, start: u64, end: u64) !void {
            var journal = try Journal.init_at_size(gpa, self.iface(), self.cfg(), start);
            defer journal.deinit();
            for (start..end) |value| _ = try journal.append(value);
            try journal.sync();
        }

        fn watermark(self: *Self) !?u64 {
            return fixed.Journal(u64).persisted_watermark(gpa, self.iface(), offsets);
        }

        fn clear_target(self: *Self) !?u64 {
            var checkpoint = try Checkpoint.open(gpa, self.iface(), offsets);
            defer checkpoint.deinit();
            return checkpoint.clear_target();
        }

        fn scan(self: *Self, name: []const u8) !runtime.storage.Names {
            return self.iface().scan(gpa, name);
        }

        fn remove_data(self: *Self, blob: u64) !void {
            try self.iface().remove(data, &manager_mod.section_name(blob));
        }

        /// The logical size of every data blob, in scan order.
        fn data_sizes(self: *Self, out: []u64) !usize {
            const names = try self.scan(data);
            defer names.deinit(gpa);
            std.mem.sort([]u8, names.items, {}, less_than);
            for (names.items, 0..) |name, i| {
                const opened = try self.iface().open(data, name);
                opened.blob.close();
                out[i] = opened.len;
            }
            return names.items.len;
        }
    };
}

fn less_than(_: void, a: []u8, b: []u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn expect_items(journal: *Journal, start: u64, end: u64) !void {
    for (start..end) |value| try testing.expectEqual(value, try journal.read(value));
}

fn expect_same_names(expected: runtime.storage.Names, actual: runtime.storage.Names) !void {
    try testing.expectEqual(expected.items.len, actual.items.len);
    for (expected.items) |name| try testing.expect(actual.contains(name));
}

// A cap below the watermark rebuilds no offsets, so an unpublished bounded open leaves the
// acknowledged offsets and watermark for publication to trim; the next ordinary open sees the
// full history.
test "variable: bounded inspection preserves acknowledged offsets until publication" {
    const H = Harness("inspection-preserves-offsets");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(0, 20);
    try testing.expectEqual(20, (try h.watermark()).?);
    const before = try h.scan(H.offsets_blobs);
    defer before.deinit(gpa);
    {
        var pending = try h.recover(10);
        defer pending.deinit();
        try testing.expectEqual(bounds(0, 10), pending.bounds);
    }
    const after = try h.scan(H.offsets_blobs);
    defer after.deinit(gpa);
    try expect_same_names(before, after);
    try testing.expectEqual(20, (try h.watermark()).?);
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 20), journal.get_bounds());
    try expect_items(&journal, 0, 20);
    journal.deinit();
    try testing.expectEqual(20, (try h.watermark()).?);
}

// With the watermark lagging at 7, a cap of 12 rebuilds offsets 7..12 from data. Blobs 3 and
// 4 start past the cap and blob 2 holds items past it, but only publication may remove or
// cut them, and the watermark stays at 7 so a retry replays the same frames.
test "variable: bounded inspection preserves data above the watermark until publication" {
    const H = Harness("inspection-preserves-data");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(0, 20);
    {
        var journal = try h.open();
        defer journal.deinit();
        try journal.test_set_offsets_recovery_watermark(7);
    }
    try testing.expectEqual(7, (try h.watermark()).?);
    var sizes: [8]u64 = undefined;
    const count = try h.data_sizes(&sizes);
    try testing.expectEqual(5, count);
    {
        var pending = try h.recover(12);
        defer pending.deinit();
        try testing.expectEqual(bounds(0, 12), pending.bounds);
        try testing.expectEqualSlices(u64, &.{ 3, 4 }, pending.discarded.items);
    }
    var inspected: [8]u64 = undefined;
    try testing.expectEqual(count, try h.data_sizes(&inspected));
    try testing.expectEqualSlices(u64, sizes[0..count], inspected[0..count]);
    try testing.expectEqual(7, (try h.watermark()).?);
    var journal = try h.open();
    try testing.expectEqual(bounds(0, 20), journal.get_bounds());
    try expect_items(&journal, 0, 20);
    journal.deinit();
    try testing.expectEqual(20, (try h.watermark()).?);
}

// Recovery must remove an empty trailing data blob; when that removal fails the open fails,
// and a retry still holds every committed item.
test "variable: a recovery failure does not clear durable data" {
    const H = Harness("initialization-recovery-clear");
    var h: H = undefined;
    try h.init(.{ .items_per_section = 20 });
    defer h.deinit();
    {
        var journal = try Journal.init_at_size(gpa, h.iface(), h.cfg(), 20);
        defer journal.deinit();
        for (0..8) |value| _ = try journal.append(value);
        try (try journal.start_sync()).wait_release();
    }
    const opened = try h.iface().open(H.data, &manager_mod.section_name(2));
    opened.blob.close();
    h.storage.config = .{ .remove_rate = .one };
    try testing.expectError(error.Io, h.open());
    h.storage.config = .{};
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(20, 28), journal.get_bounds());
    for (20..28) |position| try testing.expectEqual(position - 20, try journal.read(position));
}

// Acknowledged data removed under intact offsets and watermark makes recovery fail instead
// of authorizing a reset.
test "variable: sync recovery rejects missing acknowledged data" {
    const H = Harness("initialization-missing-anchor");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(0, 20);
    for (1..5) |blob| try h.remove_data(blob);
    try testing.expectError(error.Corruption, h.recover(40));
}

// With every data blob gone and no clear staged, the span must not collapse to the offsets
// start: init_sync at 7..27 reports corruption and clears nothing.
test "variable: init sync rejects acknowledged offsets without data" {
    const H = Harness("initialization-offsets-without-data");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(0, 20);
    const before = try h.scan(H.offsets_blobs);
    defer before.deinit(gpa);
    try h.iface().remove(H.data, null);
    const result = authenticated.init_sync(Journal, gpa, h.iface(), h.cfg(), bounds(7, 27));
    try testing.expectError(error.Corruption, result);
    const after = try h.scan(H.offsets_blobs);
    defer after.deinit(gpa);
    try expect_same_names(before, after);
    try testing.expectEqual(20, (try h.watermark()).?);
}

// An empty journal pruned to the maximum position opens bounded and ordinarily at that
// position.
test "variable: bounded empty prefix at the maximum position" {
    const H = Harness("maximum-empty-prefix");
    var h: H = undefined;
    try h.init(.{ .items_per_section = 1 });
    defer h.deinit();
    {
        var journal = try Journal.init_at_size(gpa, h.iface(), h.cfg(), max - 1);
        defer journal.deinit();
        _ = try journal.append(99);
        _ = try journal.prune(max);
        try journal.sync();
    }
    var journal = try h.open_at_most(max);
    try testing.expectEqual(bounds(max, max), journal.get_bounds());
    journal.deinit();
    journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(max, max), journal.get_bounds());
}

// A crash between the data and offsets prunes leaves offsets from 0 and data from blob 1.
// A bounded publication of the empty prefix at 10 then stops right after removing the last
// data blob. Every later cap at or above 10, and an ordinary open, recovers 10..10.
test "variable: bounded empty publication retries" {
    for ([_]?u64{ 10, 11, 9, null }) |cap| try check_empty_publish_retry(cap);
}

fn check_empty_publish_retry(cap: ?u64) !void {
    const H = Harness("bounded-empty-publish-floor");
    var h: H = undefined;
    try h.init(.{ .items_per_section = 10 });
    defer h.deinit();
    try h.seed(0, 15);
    {
        var journal = try h.open();
        defer journal.deinit();
        try testing.expect(try journal.test_prune_data(1));
    }
    {
        var pending = try h.recover(10);
        defer pending.deinit();
        try testing.expectEqual(bounds(10, 10), pending.bounds);
        try testing.expectEqual(bounds(0, 10), pending.offsets.?.get_bounds());
        try testing.expectEqualSlices(u64, &.{1}, pending.discarded.items);
        try testing.expectEqual(0, pending.pending.items.len);
        // Publication truncates and prunes the offsets to 10, then removes the data.
        try pending.offsets.?.truncate(10);
        _ = try pending.offsets.?.prune(10);
    }
    try h.remove_data(1);
    const names = try h.scan(H.data);
    try testing.expectEqual(0, names.items.len);
    names.deinit(gpa);
    try testing.expectEqual(10, (try h.watermark()).?);
    try testing.expectEqual(null, try h.clear_target());
    if (cap == 9) return testing.expectError(error.ItemPruned, h.open_at_most(cap));
    var journal = try h.open_at_most(cap);
    defer journal.deinit();
    try testing.expectEqual(bounds(10, 10), journal.get_bounds());
    try testing.expectEqual(10, try journal.append(99));
    try testing.expectEqual(99, try journal.read(10));
}

// A clean open needs no repair, so an initialization cap adds no mutations: each cap opens
// with exactly the mutation allowance an ordinary open needs.
test "variable: a clean initialization cap adds no mutations" {
    var storage = mocks.Storage.init(gpa);
    defer storage.deinit();
    var cache_ref = try paged.CacheRef.init(gpa, 16, 4);
    defer cache_ref.deinit();
    const cfg: variable.Config(u64) = .{
        .partition = "clean-cap-syncs",
        .items_per_section = 5,
        .compression = null,
        .codec_config = {},
        .cache_ref = &cache_ref,
        .write_buffer = 1,
        .replay_buffer = 256,
    };
    {
        var journal = try Journal.init(gpa, storage.interface(), cfg);
        defer journal.deinit();
        for (0..13) |value| _ = try journal.append(value);
        try journal.sync();
    }
    var baseline: ?u64 = null;
    for ([_]?u64{ null, 13, max }) |cap| {
        const needed = try mutations_needed(&storage, cfg, cap);
        try testing.expectEqual(baseline orelse needed, needed);
        baseline = needed;
    }
}

/// The fewest mutations a clean open at `cap` succeeds with.
fn mutations_needed(storage: *mocks.Storage, cfg: variable.Config(u64), cap: ?u64) !u64 {
    defer storage.mutations_allowed = null;
    var allowed: u64 = 0;
    while (allowed < 64) : (allowed += 1) {
        storage.allow_mutations(allowed);
        const opened = if (cap) |c|
            Journal.init_at_most(gpa, storage.interface(), cfg, c)
        else
            Journal.init(gpa, storage.interface(), cfg);
        var journal = opened catch continue;
        defer journal.deinit();
        try testing.expectEqual(bounds(0, 13), journal.get_bounds());
        return allowed;
    }
    return error.TestUnexpectedResult;
}

// Offsets rebuilt from committed data across page-aligned sections and sections ending in a
// partial page read back at every section's first and last item.
test "variable: offset rebuild with a partial final page" {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    for ([_]u64{ 8192, 8193 }) |per_section| try check_partial_page_rebuild(per_section);
}

fn check_partial_page_rebuild(items_per_section: u64) !void {
    const sections = 16;
    const H = Harness("offset-rebuild-buffers");
    var h: H = undefined;
    try h.init(.{
        .items_per_section = items_per_section,
        .page_size = 4096,
        .write_buffer = 131072,
        .replay_buffer = 131072,
    });
    defer h.deinit();
    const size = sections * items_per_section;
    {
        var journal = try h.open();
        defer journal.deinit();
        for (0..size) |value| _ = try journal.append(value);
        try journal.commit();
    }
    try h.crash();
    var pending = try h.recover(null);
    {
        // `publish` consumes the recovery, also on error.
        errdefer pending.deinit();
        try testing.expectEqual(bounds(0, size), pending.bounds);
        try testing.expectEqual(0, pending.offsets.?.recovery_watermark());
    }
    var journal = try pending.publish(size);
    defer journal.deinit();
    for (0..sections) |section| {
        const first = section * items_per_section;
        const last = first + items_per_section - 1;
        try testing.expectEqual(first, try journal.read(first));
        try testing.expectEqual(last, try journal.read(last));
    }
}

// A write fault partway through rebuilding offsets from committed data fails the open, with
// or without the failed bytes retained, and leaves the watermark and items for a retry.
test "variable: an interrupted offset rebuild preserves committed data" {
    for ([_]u64{ 0, 7 }) |start| {
        for ([_]utils.Probability{ .zero, .one }) |retention| {
            try check_interrupted_rebuild(start, retention);
        }
    }
}

fn check_interrupted_rebuild(start: u64, retention: utils.Probability) !void {
    const H = Harness("interrupted-offset-rebuild");
    var h: H = undefined;
    try h.init(.{ .items_per_section = 256 });
    defer h.deinit();
    {
        var journal = try Journal.init_at_size(gpa, h.iface(), h.cfg(), start);
        defer journal.deinit();
        for (start..128) |value| _ = try journal.append(value);
        try journal.commit();
    }
    h.storage.config = .{
        .write_rate = .{ .failure_rate = .one, .retention_rate = retention, .mode = .prefix },
    };
    try testing.expectError(error.Io, h.recover(null));
    try h.crash();
    h.storage.config = .{};
    try testing.expectEqual(start, (try h.watermark()).?);
    try testing.expectEqual(null, try h.clear_target());
    var journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(start, 128), journal.get_bounds());
    try expect_items(&journal, start, 128);
}

// A bounded open that fails on a sync, remove, or resize fault leaves storage that a later
// bounded or ordinary open recovers to the same prefix, which then restarts and appends.
test "variable: bounded initialization retries after storage faults" {
    for ([_]u64{ 0, 7 }) |start| {
        for (0..3) |kind| {
            for ([_]u64{ 1, 3, 7, 10 }) |numerator| {
                try check_fault_retry(start, kind, utils.Probability.init(numerator, 10).?);
            }
        }
    }
}

fn check_fault_retry(start: u64, kind: usize, rate: utils.Probability) !void {
    const H = Harness("capped-faults");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(start, 13);
    h.storage.config = .{
        .sync_rate = if (kind == 0) rate else null,
        .remove_rate = if (kind == 1) rate else null,
        .resize_rate = if (kind == 2) .{ .failure_rate = rate, .partial_rate = rate } else null,
    };
    const succeeded = if (h.open_at_most(7)) |opened| ok: {
        var journal = opened;
        journal.deinit();
        break :ok true;
    } else |_| false;
    try h.crash();
    h.storage.config = .{};
    if (succeeded) {
        var journal = try h.open();
        defer journal.deinit();
        try testing.expectEqual(bounds(start, 7), journal.get_bounds());
    }
    var journal = try h.open_at_most(7);
    try testing.expectEqual(bounds(start, 7), journal.get_bounds());
    try expect_items(&journal, start, 7);
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(start, 7), journal.get_bounds());
    try testing.expectEqual(7, try journal.append(99));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(start, 8), journal.get_bounds());
    try testing.expectEqual(99, try journal.read(7));
}

// Opening at most `cap` durably establishes the selected prefix, compressed or not: a cap
// below the start fails and leaves the journal intact, and appends continue at the cap.
test "variable: init at most restarts and appends" {
    for ([_]?u8{ null, 3 }) |compression| {
        for ([_]u64{ 0, 7 }) |start| {
            for ([_]u64{ 0, 1, 5, 7, 8, 10, 13, 20, max }) |cap| {
                try check_restart_append(compression, start, cap);
            }
        }
    }
}

fn check_restart_append(compression: ?u8, start: u64, cap: u64) !void {
    const H = Harness("variable-cap");
    var h: H = undefined;
    try h.init(.{ .compression = compression, .write_buffer = 1024, .page_size = 1024 });
    defer h.deinit();
    try h.seed(start, 13);
    if (cap < start) {
        try testing.expectError(error.ItemPruned, h.open_at_most(cap));
        var journal = try h.open();
        defer journal.deinit();
        return testing.expectEqual(bounds(start, 13), journal.get_bounds());
    }
    const end: u64 = @min(cap, 13);
    var journal = try h.open_at_most(cap);
    try testing.expectEqual(bounds(start, end), journal.get_bounds());
    try expect_items(&journal, start, end);
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(bounds(start, end), journal.get_bounds());
    for (end..end + 8) |value| try testing.expectEqual(value, try journal.append(value + 100));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    defer journal.deinit();
    for (start..end + 8) |value| {
        const expected = if (value < end) value else value + 100;
        try testing.expectEqual(expected, try journal.read(value));
    }
}

// Data blob 3 lies past the cap, so a bounded open discards it unread even when it is torn,
// and the discard is durable.
test "variable: init at most skips discarded blobs" {
    const H = Harness("variable-cap-discard");
    var h: H = undefined;
    try h.init(.{});
    defer h.deinit();
    try h.seed(0, 23);
    {
        const opened = try h.iface().open(H.data, &manager_mod.section_name(3));
        defer opened.blob.close();
        try opened.blob.resize(1);
        try opened.blob.sync();
    }
    var journal = try h.open_at_most(7);
    try testing.expectEqual(bounds(0, 7), journal.get_bounds());
    journal.deinit();
    journal = try h.open();
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 7), journal.get_bounds());
}
