//! A partitioned unordered index (port of commonware's
//! `storage/src/index/partitioned/unordered.rs`): commonware keeps one unordered index per
//! partition, which behaves exactly like one unordered index over `(partition, sub-key)`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const partitioned = @import("mod.zig");
const unordered = @import("../unordered.zig");

/// An unordered index whose first `P` key bytes select a partition and translator `T` maps the
/// rest. Initialize with `init(gpa, Translator(T, P).init(t))`.
pub fn Index(comptime T: type, comptime V: type, comptime P: usize) type {
    return unordered.Index(partitioned.Translator(T, P), V);
}

/// A worker's range of an `Index(T, V, P)` (commonware's `RangeIndex`).
pub fn Range(comptime T: type, comptime V: type, comptime P: usize) type {
    return partitioned.Range(Index(T, V, P), Absorb(T, V, P).absorb);
}

/// An empty range over partitions `[offset, offset + count)` of `full`.
pub fn new_range(
    comptime T: type,
    comptime V: type,
    comptime P: usize,
    full: *const Index(T, V, P),
    offset: u32,
    count: u32,
) Range(T, V, P) {
    return .init(full, offset, count);
}

fn Absorb(comptime T: type, comptime V: type, comptime P: usize) type {
    return struct {
        /// Moves every head and overflow chain of `part` into `full`, which holds none of
        /// `part`'s keys. Reserves first, so an error changes nothing.
        fn absorb(full: *Index(T, V, P), part: *Index(T, V, P)) Allocator.Error!void {
            const ctx = full.context();
            const heads = &part.heads.map;
            const chains = &part.overflow;
            try full.heads.map.ensureUnusedCapacityContext(full.gpa, heads.count(), ctx);
            try full.overflow.ensureUnusedCapacityContext(full.gpa, chains.count(), ctx);
            var head_entries = heads.iterator();
            while (head_entries.next()) |entry| {
                const key = entry.key_ptr.*;
                full.heads.map.putAssumeCapacityNoClobberContext(key, entry.value_ptr.*, ctx);
            }
            var chain_entries = chains.iterator();
            while (chain_entries.next()) |entry| {
                assert(entry.value_ptr.items.len > 0);
                full.overflow.putAssumeCapacityNoClobberContext(
                    entry.key_ptr.*,
                    entry.value_ptr.*,
                    ctx,
                );
            }
            // The chains now belong to `full`.
            chains.clearRetainingCapacity();
            heads.clearRetainingCapacity();
            full.counters.keys += part.counters.keys;
            full.counters.items += part.counters.items;
            full.counters.pruned += part.counters.pruned;
            part.counters = .{};
        }
    };
}

const testing = std.testing;
const translators = @import("../../translator.zig");
const test_gpa = testing.allocator;

/// Commonware's test index: `P = 1` over `u64` with a one-byte translator, so keys sharing a
/// partition and the next byte collide into an overflow chain.
const TestIndex = Index(translators.OneCap, u64, 1);

fn new_index() TestIndex {
    return .init(test_gpa, .init(.{}));
}

fn new_test_range(
    full: *const TestIndex,
    offset: u32,
    count: u32,
) Range(translators.OneCap, u64, 1) {
    return new_range(translators.OneCap, u64, 1, full, offset, count);
}

const Seen = std.ArrayList(u64);

fn collect(seen: *Seen, value: *const u64) void {
    seen.appendAssumeCapacity(value.*);
}

fn expect_values(index: *const TestIndex, key: []const u8, expected: []const u64) !void {
    var values = index.get(key);
    var actual: [8]u64 = undefined;
    var count: usize = 0;
    while (values.next()) |value| : (count += 1) actual[count] = value.*;
    try testing.expectEqualSlices(u64, expected, actual[0..count]);
}

test "partitioned unordered range visits every value once" {
    var full = new_index();
    defer full.deinit();
    // Two keys in partition 0x80 that collide on the translated sub-key (an overflow chain),
    // one distinct key beside them, and one key in partition 0x81.
    var range = new_test_range(&full, 0x80, 2);
    defer range.deinit();
    try testing.expect(try range.get_mut_or_insert(&.{ 0x80, 0x01, 0xaa }, 1) == null);
    var existing = (try range.get_mut_or_insert(&.{ 0x80, 0x01, 0xbb }, 2)).?;
    existing.finish();
    {
        var cursor = range.get_mut(&.{ 0x80, 0x01, 0xbb }).?;
        defer cursor.finish();
        _ = cursor.next();
        try cursor.insert(2);
    }
    try testing.expect(try range.get_mut_or_insert(&.{ 0x80, 0x02 }, 3) == null);
    try testing.expect(try range.get_mut_or_insert(&.{ 0x81, 0x07 }, 4) == null);
    var seen: Seen = try .initCapacity(test_gpa, 8);
    defer seen.deinit(test_gpa);
    range.for_each_value(&seen, collect);
    std.mem.sort(u64, seen.items, {}, std.sort.asc(u64));
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3, 4 }, seen.items);
}

test "partitioned unordered install range at a nonzero offset" {
    var full = new_index();
    defer full.deinit();
    // A range over global partitions [0x80, 0x82): two keys in 0x80, one in 0x81.
    {
        var range = new_test_range(&full, 0x80, 2);
        errdefer range.deinit();
        try testing.expect(try range.get_mut_or_insert(&.{ 0x80, 0x01 }, 1) == null);
        try testing.expect(try range.get_mut_or_insert(&.{ 0x80, 0x02 }, 2) == null);
        try testing.expect(try range.get_mut_or_insert(&.{ 0x81, 0x07 }, 3) == null);
        {
            // A colliding key joins the first key's chain through the cursor.
            var cursor = (try range.get_mut_or_insert(&.{ 0x80, 0x01, 0xff }, 4)).?;
            defer cursor.finish();
            while (cursor.next()) |_| {}
            try cursor.insert(4);
        }
        try range.install(&full);
    }
    try testing.expectEqual(@as(u64, 3), full.keys());
    try testing.expectEqual(@as(u64, 4), full.items());
    try expect_values(&full, &.{ 0x80, 0x01 }, &.{ 1, 4 });
    try expect_values(&full, &.{ 0x80, 0x02 }, &.{2});
    try expect_values(&full, &.{ 0x81, 0x07 }, &.{3});
    // A remap that dropped the offset would file the entries at partitions 0x00 and 0x01.
    try expect_values(&full, &.{ 0x00, 0x01 }, &.{});
    try expect_values(&full, &.{ 0x01, 0x07 }, &.{});
}

test "partitioned unordered range prunes count after install" {
    var full = new_index();
    defer full.deinit();
    try testing.expectEqual(@as(u64, 0), full.pruned());
    {
        var range = new_test_range(&full, 0, TestIndex.Translator.partition_count);
        errdefer range.deinit();
        // Give one translated key two values, then delete both through a cursor.
        try testing.expect(try range.get_mut_or_insert(&.{ 0x10, 0x01 }, 1) == null);
        {
            var cursor = (try range.get_mut_or_insert(&.{ 0x10, 0x01, 0xff }, 2)).?;
            defer cursor.finish();
            while (cursor.next()) |_| {}
            try cursor.insert(2);
        }
        {
            var cursor = range.get_mut(&.{ 0x10, 0x01 }).?;
            defer cursor.finish();
            while (cursor.next()) |_| cursor.delete();
        }
        try testing.expectEqual(@as(u64, 2), range.index.pruned());
        // Commonware's ranges count prunes on the full index live; here they land at install.
        try range.install(&full);
    }
    try testing.expectEqual(@as(u64, 2), full.pruned());
    try testing.expectEqual(@as(u64, 0), full.keys());
    try testing.expectEqual(@as(u64, 0), full.items());
}
