//! Prunable archive tests of marker publication and interrupted destroys, ported from
//! commonware's `archive/prunable/mod.rs`.
//!
//! Commonware counts the durability operations its `DelayedSyncContext` starts; here
//! `runtime.storage.mocks.Recording` counts blob syncs, which are the same operations because
//! every sync here completes before returning.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const translator = @import("../../translator.zig");
const prunable = @import("mod.zig");
const tests = @import("tests.zig");

const Harness = tests.Harness;
const Key = [64]u8;
const Archive = prunable.Archive(translator.FourCap, Key, i32);
const gpa = testing.allocator;

/// The harness storage behind a sync-counting wrapper.
const Counted = struct {
    recordings: runtime.storage.mocks.Recordings,
    wrapper: runtime.storage.mocks.Recording,

    /// Must not move after `wrap`.
    fn wrap(self: *Counted, harness: *Harness) void {
        self.recordings = .init(gpa);
        self.wrapper = .init(gpa, harness.storage.interface(), &self.recordings);
    }

    fn deinit(self: *Counted) void {
        self.recordings.deinit();
        self.* = undefined;
    }

    fn open(self: *Counted, harness: *Harness, cfg: anytype, name: []const u8) !Archive {
        const scope = metrics.Scope.init(&harness.registry).child(name);
        return Archive.init(gpa, self.wrapper.storage(), scope, cfg);
    }
};

fn key_of(index: u64) Key {
    var name: [20]u8 = undefined;
    return tests.test_key(std.fmt.bufPrint(&name, "{d}", .{index}) catch unreachable);
}

fn expect_index(archive: *Archive, index: u64, expected: ?i32) !void {
    try testing.expectEqual(expected, try archive.get(.{ .index = index }));
}

test "prunable sync delays an immediately ready durable boundary" {
    var harness = try Harness.init();
    defer harness.deinit();
    var counted: Counted = undefined;
    counted.wrap(&harness);
    defer counted.deinit();
    const cfg = harness.config("ready-marker-lag", 4, translator.FourCap);
    var archive = try counted.open(&harness, cfg, "archive");
    defer archive.deinit();
    const initial = counted.recordings.syncs;
    // Call 1: two data syncs, marker absent. Call 2: no new data, one marker sync.
    try archive.put_sync(0, tests.test_key("zero"), 10);
    try testing.expectEqual(@as(u64, 2), counted.recordings.syncs - initial);
    try archive.sync();
    try testing.expectEqual(@as(u64, 3), counted.recordings.syncs - initial);
}

test "prunable sync batches markers by active section" {
    var harness = try Harness.init();
    defer harness.deinit();
    var counted: Counted = undefined;
    counted.wrap(&harness);
    defer counted.deinit();
    const cfg = harness.config("section-marker-batch", 4, translator.FourCap);
    var archive = try counted.open(&harness, cfg, "archive");
    defer archive.deinit();
    const initial = counted.recordings.syncs;
    // Writes in one active section sync only the index and value journals.
    try archive.put_sync(0, tests.test_key("zero"), 10);
    try archive.put_sync(1, tests.test_key("one"), 20);
    try testing.expectEqual(@as(u64, 4), counted.recordings.syncs - initial);
    // Moving to section 4 publishes section 0's boundary beside section 4's two data syncs;
    // an empty sync flushes the final marker once, and another has no durability work.
    try archive.put_sync(4, tests.test_key("four"), 40);
    try testing.expectEqual(@as(u64, 7), counted.recordings.syncs - initial);
    try archive.sync();
    try testing.expectEqual(@as(u64, 8), counted.recordings.syncs - initial);
    try archive.sync();
    try testing.expectEqual(@as(u64, 8), counted.recordings.syncs - initial);
}

test "prunable sync publishes previous durable sections across section changes" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("cross-section-marker-lag", 1, translator.FourCap);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "archive");
        defer archive.deinit();
        // Each sync publishes the previous call's section while syncing the current one.
        try archive.put_sync(0, tests.test_key("zero"), 10);
        try archive.put_sync(1, tests.test_key("one"), 20);
        try archive.put_sync(2, tests.test_key("two"), 30);
    }
    for ([_][]const u8{ "first_reopen", "second_reopen" }) |name| {
        var archive = try harness.open(translator.FourCap, i32, cfg, name);
        defer archive.deinit();
        try expect_index(&archive, 0, 10);
        try expect_index(&archive, 1, 20);
        try expect_index(&archive, 2, 30);
    }
}

test "prunable empty sync publishes the final durable boundary" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("empty-sync-marker", 1, translator.FourCap);
    {
        var counted: Counted = undefined;
        counted.wrap(&harness);
        defer counted.deinit();
        var archive = try counted.open(&harness, cfg, "archive");
        defer archive.deinit();
        const initial = counted.recordings.syncs;
        try archive.put_sync(0, tests.test_key("zero"), 10);
        try testing.expectEqual(@as(u64, 2), counted.recordings.syncs - initial);
        // An empty sync flushes the lagging marker without resyncing the durable section.
        try archive.sync();
        try testing.expectEqual(@as(u64, 3), counted.recordings.syncs - initial);
        try archive.sync();
        try testing.expectEqual(@as(u64, 3), counted.recordings.syncs - initial);
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
    defer archive.deinit();
    try expect_index(&archive, 0, 10);
}

test "prunable sync recreates a settled section barrier" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("marker-recreate", 2, translator.FourCap);
    {
        var counted: Counted = undefined;
        counted.wrap(&harness);
        defer counted.deinit();
        var archive = try counted.open(&harness, cfg, "archive");
        defer archive.deinit();
        const initial = counted.recordings.syncs;
        // Returning to section 0 starts its barrier at the retained one-item prefix.
        const steps = [_]struct { index: u64, value: i32, syncs: u64 }{
            .{ .index = 0, .value = 10, .syncs = 2 },
            .{ .index = 2, .value = 30, .syncs = 5 },
            .{ .index = 1, .value = 20, .syncs = 8 },
        };
        for (steps) |step| {
            try archive.put_sync(step.index, key_of(step.index), step.value);
            try testing.expectEqual(step.syncs, counted.recordings.syncs - initial);
        }
        try archive.sync();
        try testing.expectEqual(@as(u64, 9), counted.recordings.syncs - initial);
        try archive.sync();
        try testing.expectEqual(@as(u64, 9), counted.recordings.syncs - initial);
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
    defer archive.deinit();
    try expect_index(&archive, 0, 10);
    try expect_index(&archive, 1, 20);
    try expect_index(&archive, 2, 30);
}

test "prunable startup publishes the validated marker without a data resync" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("startup-order", 4, translator.FourCap);
    {
        // One durable value with no published marker: the next startup validates it and
        // derives the marker itself.
        var archive = try harness.open(translator.FourCap, i32, cfg, "seed");
        defer archive.deinit();
        try archive.put(0, tests.test_key("zero"), 10);
        try archive.sync();
    }
    {
        var counted: Counted = undefined;
        counted.wrap(&harness);
        defer counted.deinit();
        var archive = try counted.open(&harness, cfg, "reopen");
        defer archive.deinit();
        // Startup-readable bytes are already durable, so only the derived marker syncs.
        try testing.expectEqual(@as(u64, 1), counted.recordings.syncs);
        try archive.sync();
        try expect_index(&archive, 0, 10);
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "marker_reopen");
    defer archive.deinit();
    try expect_index(&archive, 0, 10);
}

test "prunable prune clears the validation marker before section reuse" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("marker-reuse", 2, translator.FourCap);
    {
        // A marked item in section 0, then prune the section away with its marker.
        var archive = try harness.open(translator.FourCap, i32, cfg, "seed");
        defer archive.deinit();
        try archive.put_sync(0, tests.test_key("old"), 10);
        try archive.sync();
        try archive.prune(2);
    }
    {
        // A reopen resets the prune floor, so section 0 is created again. One sync makes the
        // new bytes durable without publishing their marker, so the reopen validates them.
        var archive = try harness.open(translator.FourCap, i32, cfg, "reuse");
        defer archive.deinit();
        try archive.put(0, tests.test_key("new"), 20);
        try archive.sync();
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
    defer archive.deinit();
    try expect_index(&archive, 0, 20);
}

const destroy_sections: u64 = 3;
const destroy_section_items: u64 = 4;

/// The indices `seed_for_destroy` stores: every index of each section but its last.
fn seeded(index: u64) bool {
    return index % destroy_section_items != destroy_section_items - 1;
}

fn destroy_config(harness: *Harness) prunable.Config(translator.FourCap, i32) {
    return harness.config("destroy", destroy_section_items, translator.FourCap);
}

/// Fills and syncs `destroy_sections` sections, publishes their markers, and returns the
/// archive reopened over them.
fn seed_for_destroy(harness: *Harness) !Archive {
    const cfg = destroy_config(harness);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "seed");
        defer archive.deinit();
        for (0..destroy_sections * destroy_section_items) |index| {
            if (seeded(index)) try archive.put(index, key_of(index), @intCast(index));
        }
        try archive.sync();
        // A sync with no new data publishes the marker that trails the last section.
        try archive.sync();
    }
    return harness.open(translator.FourCap, i32, cfg, "seeded");
}

/// The seeded indices the archive holds, as a bitmask, with index and key lookups agreeing.
fn retained_indices(archive: *Archive) !u64 {
    var retained: u64 = 0;
    for (0..destroy_sections * destroy_section_items) |index| {
        if (!seeded(index)) continue;
        const by_index = try archive.get(.{ .index = index });
        if (by_index) |value| try testing.expectEqual(@as(i32, @intCast(index)), value);
        const key = key_of(index);
        try testing.expectEqual(by_index, try archive.get(.{ .key = &key }));
        if (by_index != null) retained |= @as(u64, 1) << @intCast(index);
    }
    return retained;
}

/// Reopens what an interrupted destroy left: a second open sees what the first did, writes
/// to the oldest section and to a new one survive a reopen, and a retried destroy removes
/// every partition. Returns the retained seeded indices.
fn reopen_and_retire(harness: *Harness) !u64 {
    const cfg = destroy_config(harness);
    const retained = retained: {
        var archive = try harness.open(translator.FourCap, i32, cfg, "first");
        defer archive.deinit();
        break :retained try retained_indices(&archive);
    };
    const written = [_]u64{ destroy_section_items - 1, destroy_sections * destroy_section_items };
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "second");
        defer archive.deinit();
        try testing.expectEqual(retained, try retained_indices(&archive));
        // Neither index was seeded, so both puts store a record.
        for (written) |index| try archive.put(index, key_of(index), @intCast(index));
        try archive.sync();
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "third");
    for (written) |index| try expect_index(&archive, index, @intCast(index));
    try testing.expectEqual(retained, try retained_indices(&archive));
    try archive.destroy();
    for ([_][]const u8{ cfg.metadata_partition, cfg.key_partition, cfg.value_partition }) |p| {
        try testing.expectError(error.PartitionMissing, harness.storage.scan(gpa, p));
    }
    return retained;
}

fn all_seeded() u64 {
    var mask: u64 = 0;
    for (0..destroy_sections * destroy_section_items) |index| {
        if (seeded(index)) mask |= @as(u64, 1) << @intCast(index);
    }
    return mask;
}

test "prunable interrupted destroy reopens" {
    // Stop the destroy before its first mutation, then its second, and so on until one
    // destroy completes.
    var interrupted: u64 = 0;
    while (true) : (interrupted += 1) {
        var harness = try Harness.init();
        defer harness.deinit();
        var archive = try seed_for_destroy(&harness);
        harness.storage.allow_mutations(interrupted);
        const destroyed = if (archive.destroy()) true else |_| false;
        const stopped = harness.storage.mutation_refused;
        try testing.expectEqual(destroyed, !stopped);
        harness.storage.mutations_allowed = null;
        harness.storage.crash();
        const retained = try reopen_and_retire(&harness);
        // Nothing is removed before the first mutation; nothing survives a full destroy.
        if (interrupted == 0) try testing.expectEqual(all_seeded(), retained);
        if (destroyed) try testing.expectEqual(@as(u64, 0), retained);
        if (!stopped) break;
    }
    // Destroy removes the markers and every section of both journals, so it stops at least
    // once per section of each.
    try testing.expect(interrupted > 2 * destroy_sections);
}

/// Removes the sections of `partition` that `mask` names (bit k: the k-th section), and the
/// partition itself when `mask` is `everything`.
fn remove_sections(harness: *Harness, partition: []const u8, mask: u8) !void {
    const everything: u8 = 1 << destroy_sections;
    for (0..destroy_sections) |position| {
        if (mask != everything and mask & (@as(u8, 1) << @intCast(position)) == 0) continue;
        var name: [8]u8 = undefined;
        std.mem.writeInt(u64, &name, position * destroy_section_items, .big);
        try harness.storage.remove(partition, &name);
    }
    if (mask == everything) try harness.storage.remove(partition, null);
}

test "prunable destroy interrupted inside the journals reopens" {
    // With the markers gone, the archive reopens holding exactly the sections whose key and
    // value blobs both survive, for every pairing of removed sections.
    const everything: u8 = 1 << destroy_sections;
    var key_mask: u8 = 0;
    while (key_mask <= everything) : (key_mask += 1) {
        var value_mask: u8 = 0;
        while (value_mask <= everything) : (value_mask += 1) {
            var harness = try Harness.init();
            defer harness.deinit();
            const cfg = destroy_config(&harness);
            var archive = try seed_for_destroy(&harness);
            archive.deinit();
            try harness.storage.remove(cfg.metadata_partition, null);
            try remove_sections(&harness, cfg.key_partition, key_mask);
            try remove_sections(&harness, cfg.value_partition, value_mask);
            const gone = (if (key_mask == everything) 0xff else key_mask) |
                (if (value_mask == everything) 0xff else value_mask);
            var expected: u64 = 0;
            for (0..destroy_sections * destroy_section_items) |index| {
                const section_gone = gone & (@as(u8, 1) << @intCast(index / destroy_section_items));
                if (seeded(index) and section_gone == 0) expected |= @as(u64, 1) << @intCast(index);
            }
            try testing.expectEqual(expected, try reopen_and_retire(&harness));
        }
    }
}

/// Raises the prune floor above index 0, buffers a write to retained section 2, and returns
/// the archive (one item per section).
fn below_floor_setup(harness: *Harness, counted: *Counted, multi: bool) !Archive {
    const cfg = harness.config("test", 1, translator.FourCap);
    var archive = try counted.open(harness, cfg, "storage");
    errdefer archive.deinit();
    try archive.prune(1);
    if (multi) {
        try archive.put_multi(2, tests.test_key("pending"), 20);
    } else {
        try archive.put(2, tests.test_key("pending"), 20);
    }
    counted.recordings.clear();
    return archive;
}

test "prunable below-floor put_sync and put_multi_sync cover prior pending writes" {
    for ([_]bool{ false, true }) |multi| {
        var harness = try Harness.init();
        defer harness.deinit();
        var counted: Counted = undefined;
        counted.wrap(&harness);
        defer counted.deinit();
        {
            var archive = try below_floor_setup(&harness, &counted, multi);
            defer archive.deinit();
            // The below-floor put stores nothing, yet its sync covers every earlier write:
            // the two syncs are section 2's index and value journals.
            if (multi) {
                try archive.put_multi_sync(0, tests.test_key("pruned"), 0);
            } else {
                try archive.put_sync(0, tests.test_key("pruned"), 0);
            }
            try testing.expectEqual(@as(u64, 2), counted.recordings.syncs);
            harness.storage.crash();
        }
        // The covered write survived the crash; the below-floor index stays absent.
        const cfg = harness.config("test", 1, translator.FourCap);
        var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
        defer archive.deinit();
        try expect_index(&archive, 2, 20);
        try expect_index(&archive, 0, null);
    }
}
