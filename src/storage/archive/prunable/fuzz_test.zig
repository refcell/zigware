//! The prunable archive's fuzz targets (commonware `storage/fuzz`):
//!
//! - `archive_prunable_operations`: puts, multi puts, gets, prunes, syncs, and gap queries
//!   against a model of the stored items, then a restart that must keep every item.
//! - `archive_prunable_recovery`: puts and multi puts with syncs and prunes, a storage fault
//!   after a fuzzed number of mutations, then a crash. Recovery must keep every synced entry,
//!   keep each section's journal as a prefix of what was appended, report ranges that match
//!   the retained entries, and keep the same view across a second reopen. Commonware's target
//!   also tears partial writes and delays syncs, which the mock storage does not model.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const translator = @import("../../translator.zig");
const rmap = @import("../../rmap/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const prunable = @import("mod.zig");
const tests = @import("tests.zig");

const gpa = testing.allocator;
const Key = [16]u8;
const Value = [32]u8;
const FuzzArchive = prunable.Archive(translator.EightCap, Key, Value);
const operations_max = 64;

fn open(harness: *tests.Harness, items_per_section: u64) !FuzzArchive {
    harness.reset_metrics();
    const scope = metrics.Scope.init(&harness.registry).child("storage");
    return FuzzArchive.init(gpa, harness.storage.interface(), scope, .{
        .translator = .{},
        .metadata_partition = "test-metadata",
        .key_partition = "test-key",
        .key_cache_ref = &harness.cache_ref,
        .value_partition = "test-value",
        .codec_config = {},
        .items_per_section = items_per_section,
        .key_write_buffer = 1024,
        .value_write_buffer = 1024,
        .replay_buffer = 4096,
    });
}

/// Exact duplicate keys and translated-key collisions are vanishingly unlikely in arbitrary
/// bytes: 16 exact keys spread across four `EightCap` translations compose both cases.
fn canonical_key(id: u8) Key {
    var key: Key = @splat(0);
    key[0] = id & 0x03;
    key[8] = (id >> 2) & 0x03;
    return key;
}

const Item = struct { index: u64, key: Key, value: Value };

const Model = struct {
    items: std.ArrayList(Item) = .empty,
    oldest_allowed: ?u64 = null,

    fn deinit(model: *Model) void {
        model.items.deinit(gpa);
    }

    fn has_index(model: *const Model, index: u64) bool {
        for (model.items.items) |item| if (item.index == index) return true;
        return false;
    }

    fn below_floor(model: *const Model, index: u64) bool {
        return index < model.oldest_allowed orelse 0;
    }

    fn prune(model: *Model, min: u64) void {
        if (model.oldest_allowed) |oldest| if (min <= oldest) return;
        model.oldest_allowed = min;
        var kept: usize = 0;
        for (model.items.items) |item| {
            if (item.index < min) continue;
            model.items.items[kept] = item;
            kept += 1;
        }
        model.items.items.len = kept;
    }
};

/// Index lookup and `get_all` match the modeled values in insertion order.
fn check_index(archive: *FuzzArchive, model: *const Model, index: u64) !void {
    var expected: std.ArrayList(Value) = .empty;
    defer expected.deinit(gpa);
    for (model.items.items) |item| {
        if (item.index == index) try expected.append(gpa, item.value);
    }
    const first: ?Value = if (expected.items.len > 0) expected.items[0] else null;
    try testing.expectEqual(first, try archive.get(.{ .index = index }));
    const all = try archive.get_all(gpa, index);
    defer if (all) |values| gpa.free(values);
    if (all) |values| {
        try testing.expectEqualSlices(Value, expected.items, values);
    } else {
        try testing.expectEqual(0, expected.items.len);
    }
}

/// Key lookup returns one of the modeled values, or none when the key is absent.
fn check_key(archive: *FuzzArchive, model: *const Model, key: Key) !void {
    const actual = try archive.get(.{ .key = &key });
    var found = false;
    var stored = false;
    for (model.items.items) |item| {
        if (!std.mem.eql(u8, &item.key, &key)) continue;
        stored = true;
        if (actual) |value| found = found or std.mem.eql(u8, &value, &item.value);
    }
    try testing.expectEqual(stored, actual != null);
    try testing.expect(actual == null or found);
    try testing.expectEqual(stored, try archive.has(.{ .key = &key }));
}

fn fuzz_value(reader: *fuzz_bytes.Reader) Value {
    var value: Value = undefined;
    for (&value) |*byte| byte.* = reader.int(u8);
    return value;
}

fn operations_step(
    reader: *fuzz_bytes.Reader,
    archive: *FuzzArchive,
    model: *Model,
    items_per_section: u64,
) !void {
    switch (reader.below(8)) {
        0 => {
            const index = if (reader.boolean()) reader.below(4096) else reader.int(u64);
            const key = canonical_key(reader.int(u8));
            const value = fuzz_value(reader);
            try archive.put(index, key, value);
            if (!model.below_floor(index) and !model.has_index(index)) {
                try model.items.append(gpa, .{ .index = index, .key = key, .value = value });
            }
            try check_key(archive, model, key);
            try check_index(archive, model, index);
        },
        1 => {
            // Small multi-put domain over two sections: duplicate indices are common.
            const index = reader.below(2) * items_per_section + reader.below(4);
            const key = canonical_key(reader.int(u8));
            const value: Value = @splat(reader.int(u8));
            try archive.put_multi(index, key, value);
            if (!model.below_floor(index)) {
                try model.items.append(gpa, .{ .index = index, .key = key, .value = value });
            }
            try check_key(archive, model, key);
            try check_index(archive, model, index);
        },
        2 => try check_index(archive, model, reader.below(2 * items_per_section)),
        3 => try check_key(archive, model, canonical_key(reader.int(u8))),
        4 => {
            const bounded = reader.boolean();
            const raw = if (bounded) reader.below(4 * items_per_section) else reader.int(u64);
            const min = raw - raw % items_per_section;
            try archive.prune(min);
            model.prune(min);
        },
        5 => try archive.sync(),
        6 => {
            const start = reader.below(4096);
            const gap = archive.next_gap(start);
            if (gap.current_end) |end| try testing.expect(end >= start);
            if (gap.next_start) |next| try testing.expect(next > start);
        },
        7 => try check_all(archive, model),
        else => unreachable,
    }
}

fn check_all(archive: *FuzzArchive, model: *const Model) !void {
    for (0..16) |id| try check_key(archive, model, canonical_key(@intCast(id)));
    for (model.items.items) |item| try check_index(archive, model, item.index);
}

fn operations_run(input: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(input);
    const items_per_section: u64 = 1024;
    var harness = try tests.Harness.init();
    defer harness.deinit();
    var model: Model = .{};
    defer model.deinit();
    {
        var archive = try open(&harness, items_per_section);
        defer archive.deinit();
        var operations: u32 = 0;
        while (!reader.done() and operations < operations_max) : (operations += 1) {
            try operations_step(&reader, &archive, &model, items_per_section);
        }
        try archive.sync();
    }
    // The prune floor is not persisted, but pruned data is gone: the model holds.
    var archive = try open(&harness, items_per_section);
    defer archive.deinit();
    try check_all(&archive, &model);
}

test "fuzz archive_prunable_operations (seeded)" {
    try fuzz_bytes.seeded(512, 0x61727077, 48, operations_run);
}

test "fuzz archive_prunable_operations" {
    try testing.fuzz({}, fuzz_bytes.smith(512, operations_run), .{});
}

/// One journal append: the entry with its id stamped in the value, and whether a completed
/// sync covered it (and no prune was requested for its section since).
const Appended = struct { item: Item, section: u64, synced: bool };

const Recovery = struct {
    appended: std.ArrayList(Appended) = .empty,
    items_per_section: u64,
    oldest_allowed: u64 = 0,

    fn deinit(recovery: *Recovery) void {
        recovery.appended.deinit(gpa);
    }

    fn section(recovery: *const Recovery, index: u64) u64 {
        return index - index % recovery.items_per_section;
    }

    /// Whether `put` (unique) appends at `index`.
    fn appends(recovery: *const Recovery, index: u64, unique: bool) bool {
        if (index < recovery.oldest_allowed) return false;
        if (!unique) return true;
        for (recovery.appended.items) |entry| {
            if (entry.item.index == index and entry.section >= recovery.oldest_allowed) {
                return false;
            }
        }
        return true;
    }
};

/// Applies one fuzzed operation, recording appends before they are attempted so a failed
/// append still counts as possibly stored.
fn recovery_step(reader: *fuzz_bytes.Reader, archive: *FuzzArchive, model: *Recovery) !void {
    const items_per_section = model.items_per_section;
    switch (reader.below(6)) {
        0, 1, 2 => |kind| {
            const unique = kind != 2;
            const index = reader.below(3 * items_per_section);
            const id: u8 = @intCast(model.appended.items.len);
            const item: Item = .{
                .index = index,
                .key = canonical_key(reader.int(u8)),
                .value = @splat(id),
            };
            if (model.appends(index, unique)) {
                try model.appended.append(gpa, .{
                    .item = item,
                    .section = model.section(index),
                    .synced = false,
                });
            }
            if (unique) try archive.put(index, item.key, item.value);
            if (!unique) try archive.put_multi(index, item.key, item.value);
        },
        3, 4 => {
            try archive.sync();
            for (model.appended.items) |*entry| {
                if (entry.section >= model.oldest_allowed) entry.synced = true;
            }
        },
        5 => {
            const min = model.section(reader.below(3 * items_per_section));
            if (min > model.oldest_allowed) {
                model.oldest_allowed = min;
                for (model.appended.items) |*entry| {
                    if (entry.section < min) entry.synced = false;
                }
            }
            try archive.prune(min);
        },
        else => unreachable,
    }
}

/// Whether the entry is retained: its index's values hold its unique value.
fn retained(archive: *FuzzArchive, entry: Appended) !bool {
    const all = try archive.get_all(gpa, entry.item.index) orelse return false;
    defer gpa.free(all);
    for (all) |value| if (std.mem.eql(u8, &value, &entry.item.value)) return true;
    return false;
}

/// Checks the recovered archive against the appended entries. Returns the retained flags.
fn recovery_check(archive: *FuzzArchive, model: *const Recovery, flags: []bool) !void {
    assert(flags.len == model.appended.items.len);
    var expected: rmap.RMap = .empty;
    defer expected.deinit(gpa);
    for (model.appended.items, flags) |entry, *flag| {
        flag.* = try retained(archive, entry);
        if (entry.synced) try testing.expect(flag.*);
        if (flag.*) {
            try expected.insert(gpa, entry.item.index);
            try testing.expect(try archive.has_at(entry.item.index, &entry.item.key));
            try testing.expect(try archive.has(.{ .key = &entry.item.key }));
        }
    }
    // Each section keeps a prefix of its appends.
    for (model.appended.items, flags, 0..) |entry, flag, i| {
        if (flag) continue;
        for (model.appended.items[i + 1 ..], flags[i + 1 ..]) |later, later_flag| {
            if (later.section == entry.section) try testing.expect(!later_flag);
        }
    }
    try testing.expectEqualSlices(rmap.Range, expected.items(), archive.ranges());
    try testing.expectEqual(expected.first_index(), archive.first_index());
    try testing.expectEqual(expected.last_index(), archive.last_index());
    for (0..3 * model.items_per_section + 1) |start| {
        try testing.expectEqual(expected.next_gap(start), archive.next_gap(start));
        var want: [8]u64 = undefined;
        var got: [8]u64 = undefined;
        const missing = archive.missing_items(start, &got);
        try testing.expectEqualSlices(u64, expected.missing_items(start, &want), missing);
    }
}

fn recovery_run(input: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(input);
    var harness = try tests.Harness.init();
    defer harness.deinit();
    var model: Recovery = .{ .items_per_section = 1 + reader.below(4) };
    defer model.deinit();
    const fault: ?u64 = if (reader.boolean()) reader.below(48) else null;
    {
        var archive = try open(&harness, model.items_per_section);
        defer archive.deinit();
        if (fault) |operations| harness.storage.allow_mutations(operations);
        var operations: u32 = 0;
        while (!reader.done() and operations < operations_max) : (operations += 1) {
            recovery_step(&reader, &archive, &model) catch |err| {
                // Only an injected storage fault may fail an operation.
                try testing.expect(harness.storage.mutation_refused);
                try testing.expect(err != error.OutOfMemory);
                break;
            };
        }
        harness.storage.crash();
    }
    harness.storage.mutations_allowed = null;
    const flags = try gpa.alloc(bool, model.appended.items.len);
    defer gpa.free(flags);
    const again = try gpa.alloc(bool, model.appended.items.len);
    defer gpa.free(again);
    {
        var archive = try open(&harness, model.items_per_section);
        defer archive.deinit();
        try recovery_check(&archive, &model, flags);
    }
    // Recovery was durable: a second reopen sees the same entries.
    harness.storage.crash();
    var archive = try open(&harness, model.items_per_section);
    defer archive.deinit();
    try recovery_check(&archive, &model, again);
    try testing.expectEqualSlices(bool, flags, again);
}

test "fuzz archive_prunable_recovery (seeded)" {
    try fuzz_bytes.seeded(256, 0x61727263, 64, recovery_run);
}

test "fuzz archive_prunable_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(256, recovery_run), .{});
}
