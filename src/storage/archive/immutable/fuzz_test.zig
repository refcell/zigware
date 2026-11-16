//! The immutable archive's `archive_immutable_recovery` fuzz target (commonware
//! `storage/fuzz`): commit a baseline (unless the archive is virgin), arm a storage fault after
//! a fuzzed number of mutations, put more entries and sync, then crash. A second, also faulted,
//! recovery attempt models commonware's `faulted_recovery`. The clean recovery must hold the
//! baseline if init or a put failed, the baseline or every entry (never a mix) if the sync
//! failed, and every entry if it succeeded; its ranges and stored ordinal sections must match,
//! and a post-recovery put must survive a reopen. Commonware's torn partial writes and sync
//! faults become the storage mock's mutation budget.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const rmap = @import("../../rmap/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const immutable = @import("mod.zig");

const MockStorage = runtime.buffer.mocks.Storage;
const gpa = testing.allocator;
const Key = [16]u8;
const Value = [32]u8;
const A = immutable.Archive(Key, Value);
const ordinal_partition = "immutable-recovery-ordinal";
const items_per_section: u64 = 4;

const Entry = struct { index: u64, key: Key, value: Value };

const Harness = struct {
    storage: MockStorage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,
    opens: u32 = 0,

    fn init() !Harness {
        return .{
            .storage = MockStorage.init(gpa),
            .cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 72, 4),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn open(self: *Harness) !A {
        var name: [16]u8 = undefined;
        const scope_name = try std.fmt.bufPrint(&name, "open{d}", .{self.opens});
        self.opens += 1;
        const scope = metrics.Scope.init(&self.registry).child(scope_name);
        return A.init(gpa, self.storage.interface(), scope, .{
            .metadata_partition = "immutable-recovery-metadata",
            .freezer_table_partition = "immutable-recovery-table",
            .freezer_table_initial_size = 4,
            .freezer_table_resize_frequency = 1,
            .freezer_table_resize_chunk_size = 1,
            .freezer_key_partition = "immutable-recovery-keys",
            .freezer_key_cache_ref = &self.cache_ref,
            .freezer_value_partition = "immutable-recovery-values",
            .freezer_value_target_size = 64,
            .ordinal_partition = ordinal_partition,
            .items_per_section = items_per_section,
            .freezer_key_write_buffer = 1,
            .freezer_value_write_buffer = 1,
            .ordinal_write_buffer = 1,
            .replay_buffer = 512,
            .codec_config = {},
        });
    }
};

fn entry(payload: Value, index: u64, tag: u8) Entry {
    var key: Key = @splat(0);
    std.mem.writeInt(u64, key[0..8], index, .big);
    key[8] = tag;
    var value = payload;
    value[0] = tag;
    return .{ .index = index, .key = key, .value = value };
}

/// The baseline entries, then the candidate's additional ones (the candidate set is both).
fn baseline(payload: Value) [2]Entry {
    return .{ entry(payload, 0, 0x10), entry(payload, 2, 0x12) };
}

fn additions(payload: Value) [3]Entry {
    return .{
        entry(payload, 1, 0x21),
        entry(payload, 3, 0x23),
        entry(payload, items_per_section + 1, 0x25),
    };
}

const Outcome = enum { init_failed, put_failed, sync_failed, synced };

/// Writes the candidate state under a fault budget and reports how far it got.
fn write_phase(harness: *Harness, payload: Value, virgin: bool, budget: ?u64) !Outcome {
    var archive = if (virgin) virgin: {
        if (budget) |operations| harness.storage.allow_mutations(operations);
        break :virgin harness.open() catch return .init_failed;
    } else seeded: {
        var archive = try harness.open();
        errdefer archive.deinit();
        for (baseline(payload)) |item| try archive.put(item.index, item.key, item.value);
        try archive.sync();
        if (budget) |operations| harness.storage.allow_mutations(operations);
        break :seeded archive;
    };
    defer archive.deinit();
    for (additions(payload)) |item| {
        archive.put(item.index, item.key, item.value) catch return .put_failed;
    }
    if (virgin) {
        for (baseline(payload)) |item| {
            archive.put(item.index, item.key, item.value) catch return .put_failed;
        }
    }
    archive.sync() catch return .sync_failed;
    return .synced;
}

/// The entries of `intended` that the archive holds, checking that index and key views agree.
fn snapshot(archive: *A, intended: []const Entry, out: *std.ArrayList(u64)) !void {
    out.clearRetainingCapacity();
    for (intended) |item| {
        const by_index = try archive.get(.{ .index = item.index });
        const by_key = try archive.get(.{ .key = &item.key });
        try testing.expectEqual(by_index, by_key);
        try testing.expectEqual(by_index != null, try archive.has(.{ .index = item.index }));
        try testing.expectEqual(by_key != null, try archive.has(.{ .key = &item.key }));
        if (by_index) |value| {
            try testing.expectEqual(item.value, value);
            try out.append(gpa, item.index);
        }
    }
}

/// Ranges, gaps, and the stored ordinal sections match the recovered indices.
fn check_layout(harness: *Harness, archive: *A, indices: []const u64) !void {
    var model: rmap.RMap = .empty;
    defer model.deinit(gpa);
    for (indices) |index| try model.insert(gpa, index);
    try testing.expectEqualSlices(rmap.Range, model.items(), archive.ranges());
    try testing.expectEqual(model.first_index(), archive.first_index());
    try testing.expectEqual(model.last_index(), archive.last_index());
    for (0..7) |start| {
        const from = archive.ranges_from(start);
        try testing.expectEqualSlices(rmap.Range, model.iter_from(start), from);
        try testing.expectEqual(model.next_gap(start), archive.next_gap(start));
        var want: [5]u64 = undefined;
        var got: [5]u64 = undefined;
        const missing = archive.missing_items(start, &got);
        try testing.expectEqualSlices(u64, model.missing_items(start, &want), missing);
    }
    // Every stored ordinal section holds a recovered index, and every recovered index's
    // section is stored.
    var sections: [8]bool = @splat(false);
    for (indices) |index| sections[index / items_per_section] = true;
    const storage = harness.storage.interface();
    const names = storage.scan(gpa, ordinal_partition) catch |err| switch (err) {
        error.PartitionMissing => runtime.storage.Names{ .items = &.{} },
        else => return err,
    };
    defer names.deinit(gpa);
    var stored: usize = 0;
    for (names.items) |name| {
        try testing.expectEqual(8, name.len);
        const section = std.mem.readInt(u64, name[0..8], .big);
        try testing.expect(section < sections.len and sections[section]);
        stored += 1;
    }
    var expected: usize = 0;
    for (sections) |present| expected += @intFromBool(present);
    try testing.expectEqual(expected, stored);
}

fn sorted_candidate(payload: Value) [5]Entry {
    const base = baseline(payload);
    const more = additions(payload);
    // Ascending by index: 0, 1, 2, 3, 5.
    return .{ base[0], more[0], base[1], more[1], more[2] };
}

fn recovery_run(input: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(input);
    const virgin = reader.boolean();
    const budget: ?u64 = if (reader.below(8) == 0) null else reader.below(64);
    const recovery_budget: ?u64 = if (reader.boolean()) reader.below(32) else null;
    var payload: Value = undefined;
    for (&payload) |*byte| byte.* = reader.int(u8);
    var harness = try Harness.init();
    defer harness.deinit();
    const outcome = try write_phase(&harness, payload, virgin, budget);
    harness.storage.crash();
    // A recovery attempt that may itself fault (commonware's `faulted_recovery`).
    if (recovery_budget) |operations| {
        harness.storage.allow_mutations(operations);
        if (harness.open()) |opened| {
            var archive = opened;
            archive.deinit();
        } else |_| {}
        harness.storage.crash();
    }
    harness.storage.mutations_allowed = null;
    try check_recovered(&harness, payload, virgin, outcome);
}

fn check_recovered(harness: *Harness, payload: Value, virgin: bool, outcome: Outcome) !void {
    const candidate = sorted_candidate(payload);
    var recovered: std.ArrayList(u64) = .empty;
    defer recovered.deinit(gpa);
    var archive = try harness.open();
    var live = true;
    defer if (live) archive.deinit();
    try snapshot(&archive, &candidate, &recovered);
    const floor: []const u64 = if (virgin) &.{} else &.{ 0, 2 };
    const all: []const u64 = &.{ 0, 1, 2, 3, 5 };
    switch (outcome) {
        .init_failed, .put_failed => try testing.expectEqualSlices(u64, floor, recovered.items),
        .sync_failed => {
            const is_floor = std.mem.eql(u64, floor, recovered.items);
            try testing.expect(is_floor or std.mem.eql(u64, all, recovered.items));
        },
        .synced => try testing.expectEqualSlices(u64, all, recovered.items),
    }
    try check_layout(harness, &archive, recovered.items);
    // A post-recovery put survives a reopen.
    const sentinel = entry(payload, 4, 0xEF);
    try archive.put_sync(sentinel.index, sentinel.key, sentinel.value);
    live = false;
    archive.deinit();
    var expected: std.ArrayList(Entry) = .empty;
    defer expected.deinit(gpa);
    for (candidate) |item| {
        if (std.mem.indexOfScalar(u64, recovered.items, item.index) != null) {
            try expected.append(gpa, item);
        }
    }
    try expected.append(gpa, sentinel);
    std.mem.sort(Entry, expected.items, {}, entry_less);
    try recovered.append(gpa, sentinel.index);
    std.mem.sort(u64, recovered.items, {}, std.sort.asc(u64));
    archive = try harness.open();
    live = true;
    var again: std.ArrayList(u64) = .empty;
    defer again.deinit(gpa);
    try snapshot(&archive, expected.items, &again);
    try testing.expectEqualSlices(u64, recovered.items, again.items);
    try check_layout(harness, &archive, recovered.items);
    live = false;
    try archive.destroy();
}

fn entry_less(_: void, a: Entry, b: Entry) bool {
    return a.index < b.index;
}

test "fuzz archive_immutable_recovery (seeded)" {
    try fuzz_bytes.seeded(64, 0x61726972, 96, recovery_run);
}

test "fuzz archive_immutable_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(64, recovery_run), .{});
}
