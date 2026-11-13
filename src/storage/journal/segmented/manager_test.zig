//! Tests for the segmented section manager, ported from commonware's `segmented/manager.rs`.
//!
//! commonware records removal order with a reversing storage wrapper; here a removal fault
//! after the first removal shows which section went first. Tests of in-flight `start_sync`
//! handles have no counterpart: syncs complete synchronously.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const manager_mod = @import("manager.zig");

const Storage = mocks.Storage;
const M = manager_mod.Manager;
const gpa = testing.allocator;
const partition = "test";

const Harness = struct {
    storage: Storage,
    cache_ref: paged.CacheRef,

    fn init() !Harness {
        return .{
            .storage = Storage.init(gpa),
            .cache_ref = try paged.CacheRef.init(gpa, 64, 4),
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn open(self: *Harness, ceiling: u64) !M {
        const cfg: manager_mod.Config = .{
            .partition = partition,
            .write_buffer = 128,
            .cache_ref = &self.cache_ref,
        };
        return M.init(gpa, self.storage.interface(), cfg, ceiling);
    }

    /// Create empty stored sections.
    fn seed(self: *Harness, sections: []const u64) !void {
        var manager = try self.open(std.math.maxInt(u64));
        defer manager.deinit();
        for (sections) |section| _ = try manager.get_or_create(section);
    }

    /// Expect exactly `sections` to be stored.
    fn expect_stored(self: *Harness, sections: []const u64) !void {
        const stored = try manager_mod.stored_sections(gpa, self.storage.interface(), partition);
        defer gpa.free(stored);
        try testing.expectEqualSlices(u64, sections, stored);
    }
};

fn expect_open(manager: *const M, sections: []const u64) !void {
    try testing.expectEqual(sections.len, manager.num_sections());
    for (manager.sections.items, sections) |entry, section| {
        try testing.expectEqual(section, entry.section);
    }
}

test "bounded init leaves later sections unopened" {
    var h = try Harness.init();
    defer h.deinit();
    try h.seed(&.{ 1, 2, 5 });
    // Only sections up to the ceiling are opened; the rest stay stored until truncation.
    var manager = try h.open(2);
    try expect_open(&manager, &.{ 1, 2 });
    try testing.expectEqual(@as(?u64, 2), manager.newest_section());
    try h.expect_stored(&.{ 1, 2, 5 });
    // Truncating to the ceiling removes the unopened section 5 and keeps both opened ones.
    try manager.truncate_pending(2, 0);
    try h.expect_stored(&.{ 1, 2 });
    manager.deinit();
    // A ceiling below every stored section opens nothing, and truncation removes them all.
    // Section 0 has no blob, and truncating to it does not create one.
    manager = try h.open(0);
    defer manager.deinit();
    try testing.expect(manager.is_empty());
    try testing.expectEqual(@as(?u64, null), manager.newest_section());
    try manager.truncate_pending(0, 0);
    try h.expect_stored(&.{});
}

test "truncate pending removes unopened sections newest first" {
    var h = try Harness.init();
    defer h.deinit();
    try h.seed(&.{ 1, 2, 5, 6, 7 });
    var manager = try h.open(2);
    defer manager.deinit();
    try expect_open(&manager, &.{ 1, 2 });
    // Stop after the first removal: a crash mid-removal must leave a prefix of the sections.
    h.storage.remove_failures_after = 1;
    try testing.expectError(error.Io, manager.truncate_pending(2, 0));
    h.storage.remove_failures_after = null;
    try h.expect_stored(&.{ 1, 2, 5, 6 });
}

test "truncate pending removes open sections newest first" {
    var h = try Harness.init();
    defer h.deinit();
    const max = std.math.maxInt(u64);
    var manager = try h.open(max);
    for ([_]u64{ 1, 2, 5, max }) |section| _ = try manager.get_or_create(section);
    try manager.sync_all();
    // Truncating to the maximal section removes nothing: no section lies above it.
    try manager.truncate_pending(max, 0);
    try expect_open(&manager, &.{ 1, 2, 5, max });
    // Truncating to section 1 removes the sections above it newest first.
    h.storage.remove_failures_after = 1;
    try testing.expectError(error.Io, manager.truncate_pending(1, 0));
    h.storage.remove_failures_after = null;
    manager.deinit();
    try h.expect_stored(&.{ 1, 2, 5 });
    manager = try h.open(max);
    defer manager.deinit();
    try manager.truncate_pending(1, 0);
    try expect_open(&manager, &.{1});
    try h.expect_stored(&.{1});
}

test "truncate paged tail removes sections newest first" {
    var h = try Harness.init();
    defer h.deinit();
    for ([_]u64{ 1, 2, 5, 6, 7 }) |section| {
        const opened = try h.storage.open(partition, &manager_mod.section_name(section));
        try opened.blob.sync();
        opened.blob.close();
    }
    h.storage.remove_failures_after = 1;
    try testing.expectError(
        error.Io,
        manager_mod.truncate_paged_tail(gpa, h.storage.interface(), partition, 64, 2, 0),
    );
    h.storage.remove_failures_after = null;
    try h.expect_stored(&.{ 1, 2, 5, 6 });
    // End 0 gives a physical ceiling of zero bytes, and section 2 is empty: only removals run.
    try manager_mod.truncate_paged_tail(gpa, h.storage.interface(), partition, 64, 2, 0);
    try h.expect_stored(&.{ 1, 2 });
}

test "clear removes unopened sections and lifts the ceiling" {
    var h = try Harness.init();
    defer h.deinit();
    try h.seed(&.{ 1, 5 });
    var manager = try h.open(2);
    defer manager.deinit();
    try manager.clear();
    try h.expect_stored(&.{});
    // No stored section remains above the ceiling, so it no longer restricts creation.
    const buffer = try manager.get_or_create(5);
    try testing.expectEqual(@as(u64, 0), buffer.size());
    try expect_open(&manager, &.{5});
}

test "cleanup removes names before dropping owners" {
    // Every cleanup path leaves storage consistent with the manager, section by section.
    for ([_][]const u8{ "prune", "remove_section", "destroy", "clear", "truncate_pending" }) |op| {
        var h = try Harness.init();
        defer h.deinit();
        var manager = try h.open(std.math.maxInt(u64));
        _ = try manager.get_or_create(1);
        _ = try manager.get_or_create(2);
        if (std.mem.eql(u8, op, "prune")) {
            try testing.expect(try manager.prune(3));
        } else if (std.mem.eql(u8, op, "remove_section")) {
            try testing.expect(try manager.remove_section(1));
            try testing.expect(try manager.remove_section(2));
            try testing.expect(!try manager.remove_section(2));
        } else if (std.mem.eql(u8, op, "destroy")) {
            try manager.destroy();
            try testing.expectError(error.PartitionMissing, h.storage.scan(gpa, partition));
            continue;
        } else if (std.mem.eql(u8, op, "clear")) {
            try manager.clear();
        } else {
            try manager.truncate_pending(0, 0);
        }
        defer manager.deinit();
        try testing.expect(manager.is_empty());
        try h.expect_stored(&.{});
    }
}

test "mutations below the prune floor fail" {
    for (0..3) |operation| {
        var h = try Harness.init();
        defer h.deinit();
        var manager = try h.open(std.math.maxInt(u64));
        defer manager.deinit();
        _ = try manager.get_or_create(1);
        _ = try manager.get_or_create(2);
        try testing.expect(try manager.prune(2));
        try testing.expect(manager.pruned(1));
        try testing.expect(!manager.pruned(2));
        const result = switch (operation) {
            0 => manager.sync(&.{1}),
            1 => manager.truncate_pending(1, 0),
            else => manager.truncate_pending_section(1, 0),
        };
        try testing.expectError(error.AlreadyPrunedToSection, result);
        try testing.expectError(error.AlreadyPrunedToSection, manager.get(1));
    }
}

test "sync counts every selected section" {
    var h = try Harness.init();
    defer h.deinit();
    var manager = try h.open(std.math.maxInt(u64));
    defer manager.deinit();
    _ = try manager.get_or_create(1);
    _ = try manager.get_or_create(2);
    try manager.sync_all();
    // Clean sections need no work but still count (commonware's `manager_synced_total`).
    try manager.sync_all();
    try manager.sync(&.{ 1, 2 });
    try manager.start_sync(&.{ 1, 2 });
    const buffer = (try manager.get(1)).?;
    _ = try buffer.append("x");
    try testing.expect(buffer.needs_sync());
    try manager.sync_all();
    try testing.expect(!(try manager.get(1)).?.needs_sync());
    try expect_open(&manager, &.{ 1, 2 });
    try testing.expectEqual(@as(u64, 10), manager.synced);
}
