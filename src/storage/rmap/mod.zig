//! A collection that manages disjoint, inclusive ranges `[start, end]`.
//!
//! Port of commonware's `storage/src/rmap`. Ranges are stored in ascending order of their
//! start points, never overlap, and adjacent ranges are merged (inserting `5` into `[0, 4]`
//! yields `[0, 5]`). Commonware keeps them in a `BTreeMap<start, end>`; zigware keeps a
//! sorted array of ranges and finds positions by binary search, which has the same lookup
//! cost and better locality for the small range counts storage tracks.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const Range = struct {
    start: u64,
    end: u64,
};

/// The result of `next_gap`: the end of the range containing the value, and the start of
/// the first range beginning strictly after it.
pub const Gap = struct {
    current_end: ?u64,
    next_start: ?u64,
};

pub const RMap = struct {
    ranges: std.ArrayList(Range) = .empty,

    pub const empty: RMap = .{};

    pub fn deinit(self: *RMap, gpa: Allocator) void {
        self.ranges.deinit(gpa);
        self.* = undefined;
    }

    /// The ranges in ascending order.
    pub fn items(self: *const RMap) []const Range {
        return self.ranges.items;
    }

    /// Number of disjoint ranges.
    pub fn count(self: *const RMap) usize {
        return self.ranges.items.len;
    }

    /// Index of the first range whose start is greater than `value`.
    fn upper_bound(self: *const RMap, value: u64) usize {
        var low: usize = 0;
        var high: usize = self.ranges.items.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (self.ranges.items[middle].start <= value) low = middle + 1 else high = middle;
        }
        assert(low == self.ranges.items.len or self.ranges.items[low].start > value);
        assert(low == 0 or self.ranges.items[low - 1].start <= value);
        return low;
    }

    /// Inserts `value`: creates `[value, value]`, extends an adjacent range, bridges two
    /// ranges, or does nothing if `value` is already covered.
    pub fn insert(self: *RMap, gpa: Allocator, value: u64) Allocator.Error!void {
        const next_index = self.upper_bound(value);
        const ranges = self.ranges.items;
        const prev: ?*Range = if (next_index > 0) &ranges[next_index - 1] else null;
        const next: ?*Range = if (next_index < ranges.len) &ranges[next_index] else null;

        if (prev) |p| {
            if (value <= p.end) return; // Already covered.
        }
        const joins_prev = if (prev) |p| p.end + 1 == value else false;
        const joins_next = if (next) |n| value + 1 == n.start else false;
        if (joins_prev and joins_next) {
            prev.?.end = next.?.end;
            _ = self.ranges.orderedRemove(next_index);
        } else if (joins_prev) {
            prev.?.end = value;
        } else if (joins_next) {
            next.?.start = value;
        } else {
            try self.ranges.insert(gpa, next_index, .{ .start = value, .end = value });
        }
        assert(self.get(value) != null);
        self.assert_invariants();
    }

    /// The range that contains `value`, if any.
    pub fn get(self: *const RMap, value: u64) ?Range {
        const next_index = self.upper_bound(value);
        if (next_index == 0) return null;
        const range = self.ranges.items[next_index - 1];
        assert(range.start <= value);
        if (value <= range.end) return range;
        return null;
    }

    /// Removes `[start, end]` (inclusive): drops covered ranges, truncates overlapping ones,
    /// and splits a range that strictly contains the removal. Does nothing if `start > end`.
    pub fn remove(self: *RMap, gpa: Allocator, start: u64, end: u64) Allocator.Error!void {
        if (start > end) return;
        const first = self.iter_from_index(start);
        var last = first;
        while (last < self.ranges.items.len and self.ranges.items[last].start <= end) last += 1;
        if (first == last) return; // No overlap.

        const head = self.ranges.items[first];
        const tail = self.ranges.items[last - 1];
        var keep_buffer: [2]Range = undefined;
        var keep: usize = 0;
        if (head.start < start) {
            keep_buffer[keep] = .{ .start = head.start, .end = start - 1 };
            keep += 1;
        }
        if (tail.end > end) {
            keep_buffer[keep] = .{ .start = end + 1, .end = tail.end };
            keep += 1;
        }
        try self.ranges.replaceRange(gpa, first, last - first, keep_buffer[0..keep]);
        assert(self.get(start) == null and self.get(end) == null);
        self.assert_invariants();
    }

    /// Index of the first range that overlaps or follows `from` (its end >= `from`).
    fn iter_from_index(self: *const RMap, from: u64) usize {
        const next_index = self.upper_bound(from);
        if (next_index > 0 and self.ranges.items[next_index - 1].end >= from) {
            return next_index - 1;
        }
        return next_index;
    }

    /// The ranges that overlap or follow `from`, in ascending order.
    pub fn iter_from(self: *const RMap, from: u64) []const Range {
        const ranges = self.ranges.items[self.iter_from_index(from)..];
        assert(ranges.len == 0 or ranges[0].end >= from);
        return ranges;
    }

    /// The first index in the map.
    pub fn first_index(self: *const RMap) ?u64 {
        if (self.ranges.items.len == 0) return null;
        return self.ranges.items[0].start;
    }

    /// The last index in the map.
    pub fn last_index(self: *const RMap) ?u64 {
        if (self.ranges.items.len == 0) return null;
        return self.ranges.items[self.ranges.items.len - 1].end;
    }

    /// The end of the range containing `value` and the start of the first range strictly
    /// after `value`, for finding the gaps around a point.
    pub fn next_gap(self: *const RMap, value: u64) Gap {
        const next_index = self.upper_bound(value);
        var gap: Gap = .{ .current_end = null, .next_start = null };
        if (next_index > 0) {
            const prev = self.ranges.items[next_index - 1];
            if (prev.end >= value) gap.current_end = prev.end;
        }
        if (next_index < self.ranges.items.len) {
            gap.next_start = self.ranges.items[next_index].start;
            assert(gap.next_start.? > value);
        }
        return gap;
    }

    /// Writes up to `out.len` missing values at or after `start` that lie in gaps before
    /// some range, and returns how many. Values past the last range are never reported.
    pub fn missing_items(self: *const RMap, start: u64, out: []u64) []u64 {
        assert(out.len > 0); // max must be greater than 0.
        var found: usize = 0;
        var current = start;
        for (self.iter_from(start)) |range| {
            while (current < range.start and found < out.len) : (current += 1) {
                out[found] = current;
                found += 1;
            }
            if (found == out.len) break;
            if (range.end == std.math.maxInt(u64)) break;
            current = range.end + 1;
        }
        assert(found <= out.len);
        return out[0..found];
    }

    fn assert_invariants(self: *const RMap) void {
        if (!std.debug.runtime_safety) return;
        const ranges = self.ranges.items;
        for (ranges, 0..) |range, index| {
            assert(range.start <= range.end);
            // Disjoint and not adjacent: adjacent ranges are always merged.
            if (index > 0) assert(ranges[index - 1].end + 1 < range.start);
        }
    }
};

const testing = std.testing;
const fuzz_bytes = @import("../fuzz_bytes.zig");

fn insert_all(map: *RMap, values: []const u64) !void {
    for (values) |value| try map.insert(testing.allocator, value);
}

fn expect_ranges(map: *const RMap, expected: []const Range) !void {
    try testing.expectEqualSlices(Range, expected, map.items());
}

fn expect_get(map: *const RMap, value: u64, expected: ?Range) !void {
    const got = map.get(value);
    if (expected) |range| {
        try testing.expect(got != null);
        try testing.expectEqual(range, got.?);
    } else {
        try testing.expect(got == null);
    }
}

fn expect_gap(map: *const RMap, value: u64, current_end: ?u64, next_start: ?u64) !void {
    try testing.expectEqual(Gap{ .current_end = current_end, .next_start = next_start }, map
        .next_gap(value));
}

fn expect_missing(map: *const RMap, start: u64, limit: usize, expected: []const u64) !void {
    var buffer: [1024]u64 = undefined;
    try testing.expectEqualSlices(u64, expected, map.missing_items(start, buffer[0..limit]));
}

const max = std.math.maxInt(u64);

test "rmap doc examples" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try map.insert(testing.allocator, 1);
    try expect_gap(&map, 0, null, 1);
    try map.insert(testing.allocator, 3);
    try expect_gap(&map, 1, 1, 3);
    try insert_all(&map, &.{ 2, 0, 5, 4 });
    try expect_get(&map, 3, .{ .start = 0, .end = 5 });
    try map.remove(testing.allocator, 2, 4);
    try expect_ranges(&map, &.{ .{ .start = 0, .end = 1 }, .{ .start = 5, .end = 5 } });
    try map.insert(testing.allocator, 7);
    const tail = [_]Range{ .{ .start = 5, .end = 5 }, .{ .start = 7, .end = 7 } };
    try testing.expectEqualSlices(Range, &tail, map.iter_from(2));
    try testing.expectEqual(@as(usize, 3), map.iter_from(1).len);
    try testing.expectEqual(@as(usize, 1), map.iter_from(6).len);
}

test "rmap new and insert empty" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), map.count());
    try map.insert(testing.allocator, 5);
    try expect_get(&map, 5, .{ .start = 5, .end = 5 });
    try expect_ranges(&map, &.{.{ .start = 5, .end = 5 }});
}

test "rmap insert isolated" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 5, 10 });
    try expect_get(&map, 5, .{ .start = 5, .end = 5 });
    try expect_get(&map, 10, .{ .start = 10, .end = 10 });
    try expect_ranges(&map, &.{ .{ .start = 5, .end = 5 }, .{ .start = 10, .end = 10 } });
}

test "rmap insert covered and adjacent" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2, 3, 2 });
    for ([_]u64{ 1, 2, 3 }) |value| try expect_get(&map, value, .{ .start = 1, .end = 3 });
    try expect_ranges(&map, &.{.{ .start = 1, .end = 3 }});

    var start: RMap = .empty;
    defer start.deinit(testing.allocator);
    try insert_all(&start, &.{ 2, 3, 1 });
    try expect_get(&start, 1, .{ .start = 1, .end = 3 });
    try expect_get(&start, 3, .{ .start = 1, .end = 3 });
    try expect_ranges(&start, &.{.{ .start = 1, .end = 3 }});
}

test "rmap insert bridge ranges" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2 });
    try expect_get(&map, 1, .{ .start = 1, .end = 2 });
    try insert_all(&map, &.{ 5, 6 });
    try expect_get(&map, 5, .{ .start = 5, .end = 6 });
    try map.insert(testing.allocator, 3);
    for ([_]u64{ 1, 2, 3 }) |value| try expect_get(&map, value, .{ .start = 1, .end = 3 });
    try expect_get(&map, 5, .{ .start = 5, .end = 6 });
    try expect_ranges(&map, &.{ .{ .start = 1, .end = 3 }, .{ .start = 5, .end = 6 } });
    try map.insert(testing.allocator, 4);
    for ([_]u64{ 1, 3, 4, 6 }) |value| try expect_get(&map, value, .{ .start = 1, .end = 6 });
    try expect_ranges(&map, &.{.{ .start = 1, .end = 6 }});
}

test "rmap insert complex merging and ordering" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 10, 12, 11 });
    for ([_]u64{ 10, 11, 12 }) |value| try expect_get(&map, value, .{ .start = 10, .end = 12 });
    try insert_all(&map, &.{ 15, 13 });
    try expect_get(&map, 13, .{ .start = 10, .end = 13 });
    try expect_get(&map, 12, .{ .start = 10, .end = 13 });
    try expect_get(&map, 15, .{ .start = 15, .end = 15 });
    try map.insert(testing.allocator, 14);
    for ([_]u64{ 10, 14, 15 }) |value| try expect_get(&map, value, .{ .start = 10, .end = 15 });
    try expect_ranges(&map, &.{.{ .start = 10, .end = 15 }});
    try insert_all(&map, &.{ 5, 7, 6 });
    for ([_]u64{ 5, 6, 7 }) |value| try expect_get(&map, value, .{ .start = 5, .end = 7 });
    try expect_ranges(&map, &.{ .{ .start = 5, .end = 7 }, .{ .start = 10, .end = 15 } });
    try map.insert(testing.allocator, 9);
    try expect_get(&map, 9, .{ .start = 9, .end = 15 });
    try expect_get(&map, 10, .{ .start = 9, .end = 15 });
    try expect_ranges(&map, &.{ .{ .start = 5, .end = 7 }, .{ .start = 9, .end = 15 } });
    try map.insert(testing.allocator, 8);
    for ([_]u64{ 5, 8, 15 }) |value| try expect_get(&map, value, .{ .start = 5, .end = 15 });
    try expect_ranges(&map, &.{.{ .start = 5, .end = 15 }});
}

test "rmap insert max value" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try map.insert(testing.allocator, max);
    try expect_get(&map, max, .{ .start = max, .end = max });
    try map.insert(testing.allocator, max - 1);
    try expect_get(&map, max - 1, .{ .start = max - 1, .end = max });
    try expect_get(&map, max, .{ .start = max - 1, .end = max });
}

test "rmap get" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2, 3, 5, 6 });
    for ([_]u64{ 1, 2, 3 }) |value| try expect_get(&map, value, .{ .start = 1, .end = 3 });
    try expect_get(&map, 4, null);
    try expect_get(&map, 5, .{ .start = 5, .end = 6 });
    try expect_get(&map, 6, .{ .start = 5, .end = 6 });
    try expect_get(&map, 0, null);
    try expect_get(&map, 7, null);
}

test "rmap remove empty, invalid, and non-existent" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try map.remove(testing.allocator, 1, 5);
    try testing.expectEqual(@as(usize, 0), map.count());
    try insert_all(&map, &.{ 1, 2 });
    try map.remove(testing.allocator, 5, 1);
    try expect_ranges(&map, &.{.{ .start = 1, .end = 2 }});

    var other: RMap = .empty;
    defer other.deinit(testing.allocator);
    try insert_all(&other, &.{ 5, 6 });
    try other.remove(testing.allocator, 1, 3);
    try expect_ranges(&other, &.{.{ .start = 5, .end = 6 }});
    try other.remove(testing.allocator, 8, 10);
    try expect_ranges(&other, &.{.{ .start = 5, .end = 6 }});
    try other.remove(testing.allocator, 1, 10);
    try testing.expectEqual(@as(usize, 0), other.count());
}

test "rmap remove exact match" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2, 3, 5, 6 });
    try map.remove(testing.allocator, 1, 3);
    try expect_get(&map, 2, null);
    try expect_ranges(&map, &.{.{ .start = 5, .end = 6 }});
    try map.remove(testing.allocator, 5, 6);
    try testing.expectEqual(@as(usize, 0), map.count());
}

test "rmap remove subset split" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2, 3, 4, 5 });
    try map.remove(testing.allocator, 3, 3);
    try expect_get(&map, 2, .{ .start = 1, .end = 2 });
    try expect_get(&map, 3, null);
    try expect_get(&map, 4, .{ .start = 4, .end = 5 });
    try expect_ranges(&map, &.{ .{ .start = 1, .end = 2 }, .{ .start = 4, .end = 5 } });

    var map2: RMap = .empty;
    defer map2.deinit(testing.allocator);
    try insert_all(&map2, &.{ 1, 2, 3, 4, 5 });
    try map2.remove(testing.allocator, 2, 4);
    try expect_get(&map2, 1, .{ .start = 1, .end = 1 });
    for ([_]u64{ 2, 3, 4 }) |value| try expect_get(&map2, value, null);
    try expect_get(&map2, 5, .{ .start = 5, .end = 5 });
    try expect_ranges(&map2, &.{ .{ .start = 1, .end = 1 }, .{ .start = 5, .end = 5 } });
}

test "rmap remove overlap start and end" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2, 3, 4, 5 });
    try map.remove(testing.allocator, 0, 2);
    try expect_get(&map, 1, null);
    try expect_get(&map, 2, null);
    try expect_get(&map, 3, .{ .start = 3, .end = 5 });
    try expect_ranges(&map, &.{.{ .start = 3, .end = 5 }});

    var other: RMap = .empty;
    defer other.deinit(testing.allocator);
    try insert_all(&other, &.{ 1, 2, 3, 4, 5 });
    try other.remove(testing.allocator, 4, 6);
    try expect_get(&other, 3, .{ .start = 1, .end = 3 });
    try expect_get(&other, 4, null);
    try expect_get(&other, 5, null);
    try expect_ranges(&other, &.{.{ .start = 1, .end = 3 }});
}

test "rmap remove cover multiple ranges" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2, 4, 5, 7, 8 });
    try map.remove(testing.allocator, 3, 6);
    try expect_get(&map, 2, .{ .start = 1, .end = 2 });
    try expect_get(&map, 4, null);
    try expect_get(&map, 5, null);
    try expect_get(&map, 7, .{ .start = 7, .end = 8 });
    try expect_ranges(&map, &.{ .{ .start = 1, .end = 2 }, .{ .start = 7, .end = 8 } });
    try map.remove(testing.allocator, 0, 10);
    try testing.expectEqual(@as(usize, 0), map.count());
}

test "rmap remove partial overlap multiple ranges" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    const values = [_]u64{ 1, 2, 3, 5, 6, 7, 9, 10, 11 };
    try insert_all(&map, &values);
    try map.remove(testing.allocator, 2, 6);
    try expect_get(&map, 1, .{ .start = 1, .end = 1 });
    for ([_]u64{ 2, 3, 5, 6 }) |value| try expect_get(&map, value, null);
    try expect_get(&map, 7, .{ .start = 7, .end = 7 });
    try expect_get(&map, 9, .{ .start = 9, .end = 11 });
    try expect_ranges(&map, &.{
        .{ .start = 1, .end = 1 }, .{ .start = 7, .end = 7 }, .{ .start = 9, .end = 11 },
    });

    var map2: RMap = .empty;
    defer map2.deinit(testing.allocator);
    try insert_all(&map2, &values);
    try map2.remove(testing.allocator, 0, 20);
    try testing.expectEqual(@as(usize, 0), map2.count());
}

test "rmap remove touching boundaries does not merge" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 0, 1, 2, 4, 5 });
    try map.remove(testing.allocator, 3, 3);
    try expect_ranges(&map, &.{ .{ .start = 0, .end = 2 }, .{ .start = 4, .end = 5 } });
}

test "rmap remove max value ranges" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ max - 2, max - 1, max });
    try map.remove(testing.allocator, max, max);
    try expect_get(&map, max - 2, .{ .start = max - 2, .end = max - 1 });
    try expect_get(&map, max, null);
    try map.remove(testing.allocator, max - 2, max - 2);
    try expect_get(&map, max - 2, null);
    try expect_get(&map, max - 1, .{ .start = max - 1, .end = max - 1 });
    try map.remove(testing.allocator, max - 1, max - 1);
    try testing.expectEqual(@as(usize, 0), map.count());
    try insert_all(&map, &.{ max - 1, max });
    try map.remove(testing.allocator, 0, max);
    try testing.expectEqual(@as(usize, 0), map.count());
}

test "rmap iter" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), map.items().len);
    try insert_all(&map, &.{ 5, 6, 1, 2 });
    try expect_ranges(&map, &.{ .{ .start = 1, .end = 2 }, .{ .start = 5, .end = 6 } });
}

test "rmap first and last index" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try testing.expectEqual(@as(?u64, null), map.first_index());
    try testing.expectEqual(@as(?u64, null), map.last_index());
    try insert_all(&map, &.{ 5, 6 });
    try testing.expectEqual(@as(?u64, 5), map.first_index());
    try map.insert(testing.allocator, 1);
    try testing.expectEqual(@as(?u64, 1), map.first_index());
    try testing.expectEqual(@as(?u64, 6), map.last_index());
    try map.remove(testing.allocator, 0, 4);
    try testing.expectEqual(@as(?u64, 5), map.first_index());
    try map.remove(testing.allocator, 5, 6);
    try testing.expectEqual(@as(?u64, null), map.first_index());

    try insert_all(&map, &.{ 1, 2 });
    try testing.expectEqual(@as(?u64, 2), map.last_index());
    try map.insert(testing.allocator, 5);
    try testing.expectEqual(@as(?u64, 5), map.last_index());
    try map.insert(testing.allocator, 6);
    try testing.expectEqual(@as(?u64, 6), map.last_index());
    try map.remove(testing.allocator, 5, 10);
    try testing.expectEqual(@as(?u64, 2), map.last_index());
    try map.remove(testing.allocator, 0, 2);
    try testing.expectEqual(@as(?u64, null), map.last_index());
}

test "rmap next gap empty and single range" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try expect_gap(&map, 5, null, null);
    try insert_all(&map, &.{ 5, 6, 7 });
    try expect_gap(&map, 4, null, 5);
    try expect_gap(&map, 5, 7, null);
    try expect_gap(&map, 6, 7, null);
    try expect_gap(&map, 7, 7, null);
    try expect_gap(&map, 8, null, null);
}

test "rmap next gap multiple ranges" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2, 5, 6, 10 });
    try expect_gap(&map, 0, null, 1);
    try expect_gap(&map, 1, 2, 5);
    try expect_gap(&map, 2, 2, 5);
    try expect_gap(&map, 3, null, 5);
    try expect_gap(&map, 4, null, 5);
    try expect_gap(&map, 5, 6, 10);
    try expect_gap(&map, 6, 6, 10);
    try expect_gap(&map, 7, null, 10);
    try expect_gap(&map, 8, null, 10);
    try expect_gap(&map, 9, null, 10);
    try expect_gap(&map, 10, 10, null);
    try expect_gap(&map, 11, null, null);
}

test "rmap next gap value is max" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ max - 5, max - 4, max - 1, max });
    try expect_gap(&map, max - 6, null, max - 5);
    try expect_gap(&map, max - 5, max - 4, max - 1);
    try expect_gap(&map, max - 4, max - 4, max - 1);
    try expect_gap(&map, max - 3, null, max - 1);
    try expect_gap(&map, max - 2, null, max - 1);
    try expect_gap(&map, max - 1, max, null);
    try expect_gap(&map, max, max, null);
}

test "rmap odd ranges" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 10, 11, 14 });
    try expect_gap(&map, 0, null, 1);
    try expect_gap(&map, 1, 1, 10);
    try expect_gap(&map, 10, 11, 14);
    try expect_gap(&map, 11, 11, 14);
    try expect_gap(&map, 12, null, 14);
    try expect_gap(&map, 14, 14, null);
}

test "rmap missing items empty, single gap, and multiple gaps" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try expect_missing(&map, 0, 5, &.{});
    try expect_missing(&map, 100, 10, &.{});
    try insert_all(&map, &.{ 1, 2, 5, 6 });
    try expect_missing(&map, 3, 5, &.{ 3, 4 });
    try expect_missing(&map, 3, 2, &.{ 3, 4 });
    try expect_missing(&map, 3, 1, &.{3});
    try expect_missing(&map, 4, 1, &.{4});
    try map.insert(testing.allocator, 10);
    try expect_missing(&map, 0, 5, &.{ 0, 3, 4, 7, 8 });
    try expect_missing(&map, 0, 6, &.{ 0, 3, 4, 7, 8, 9 });
    try expect_missing(&map, 0, 7, &.{ 0, 3, 4, 7, 8, 9 });
    try expect_missing(&map, 3, 3, &.{ 3, 4, 7 });
    try expect_missing(&map, 4, 2, &.{ 4, 7 });
    try expect_missing(&map, 7, 10, &.{ 7, 8, 9 });
    try expect_missing(&map, 8, 2, &.{ 8, 9 });
    try expect_missing(&map, 11, 5, &.{});
    try expect_missing(&map, 100, 10, &.{});
}

test "rmap missing items starting in range and at boundaries" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2, 3, 7, 8, 9 });
    try expect_missing(&map, 1, 3, &.{ 4, 5, 6 });
    try expect_missing(&map, 2, 4, &.{ 4, 5, 6 });
    try expect_missing(&map, 3, 2, &.{ 4, 5 });
    try expect_missing(&map, 7, 5, &.{});
    try expect_missing(&map, 8, 3, &.{});
    try expect_missing(&map, 9, 1, &.{});

    var other: RMap = .empty;
    defer other.deinit(testing.allocator);
    try insert_all(&other, &.{ 5, 6, 10 });
    try expect_missing(&other, 5, 3, &.{ 7, 8, 9 });
    try expect_missing(&other, 6, 3, &.{ 7, 8, 9 });
    try expect_missing(&other, 10, 5, &.{});
}

test "rmap missing items large gap" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 1000 });
    try expect_missing(&map, 2, 5, &.{ 2, 3, 4, 5, 6 });
    try expect_missing(&map, 995, 5, &.{ 995, 996, 997, 998, 999 });
    var buffer: [998]u64 = undefined;
    const found = map.missing_items(2, &buffer);
    try testing.expectEqual(@as(usize, 998), found.len);
    try testing.expectEqual(@as(u64, 2), found[0]);
    try testing.expectEqual(@as(u64, 999), found[997]);
}

test "rmap missing items near max" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ max - 5, max - 3, max });
    try expect_missing(&map, max - 6, 5, &.{ max - 6, max - 4, max - 2, max - 1 });
    try expect_missing(&map, max - 4, 3, &.{ max - 4, max - 2, max - 1 });
    try expect_missing(&map, max, 5, &.{});

    var other: RMap = .empty;
    defer other.deinit(testing.allocator);
    try insert_all(&other, &.{ max - 2, max - 1, max });
    try expect_missing(&other, max - 2, 3, &.{});
    try expect_missing(&other, max - 1, 3, &.{});
    try expect_missing(&other, max, 3, &.{});
}

test "rmap missing items contiguous ranges" {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    try insert_all(&map, &.{ 1, 2, 3, 4, 5, 6 });
    try expect_ranges(&map, &.{.{ .start = 1, .end = 6 }});
    try expect_missing(&map, 0, 3, &.{0});
    try expect_missing(&map, 7, 5, &.{});
}

// Fuzz: random operations checked against a reference set of values, like commonware's
// `rmap_operations` fuzz target. Values are drawn from a narrow window near 0 or near
// u64::MAX so ranges merge, split, and hit the overflow edges often.

const fuzz_window = 64;
const fuzz_operations_max = 256;

const Reference = struct {
    const Set = std.StaticBitSet(fuzz_window);
    const Slot = struct { set: *Set, i: usize };

    low: Set = .empty,
    high: Set = .empty,

    fn slot(self: *Reference, value: u64) ?Slot {
        if (value < fuzz_window) return .{ .set = &self.low, .i = @intCast(value) };
        if (value >= max - (fuzz_window - 1)) {
            return .{ .set = &self.high, .i = @intCast(max - value) };
        }
        return null;
    }

    fn contains(self: *Reference, value: u64) bool {
        const s = self.slot(value) orelse return false;
        return s.set.isSet(s.i);
    }
};

fn fuzz_value(reader: *fuzz_bytes.Reader) u64 {
    const offset = reader.below(fuzz_window);
    return if (reader.boolean()) offset else max - offset;
}

fn fuzz_check_value(map: *const RMap, reference: *Reference, value: u64) !void {
    const range = map.get(value);
    if (reference.contains(value)) {
        try testing.expect(range != null);
        try testing.expect(range.?.start <= value and value <= range.?.end);
    } else {
        try testing.expect(range == null);
    }
}

fn fuzz_check_all(map: *const RMap, reference: *Reference) !void {
    for (0..fuzz_window) |offset| {
        try fuzz_check_value(map, reference, offset);
        try fuzz_check_value(map, reference, max - offset);
    }
    const ranges = map.items();
    for (ranges, 0..) |range, index| {
        try testing.expect(range.start <= range.end);
        if (index > 0) try testing.expect(ranges[index - 1].end + 1 < range.start);
    }
}

fn fuzz_remove(map: *RMap, reference: *Reference, reader: *fuzz_bytes.Reader) !void {
    var start = fuzz_value(reader);
    var end = fuzz_value(reader);
    if (start > end) std.mem.swap(u64, &start, &end);
    try map.remove(testing.allocator, start, end);
    for (0..fuzz_window) |offset| {
        for ([_]u64{ offset, max - offset }) |value| {
            if (value >= start and value <= end) {
                const s = reference.slot(value).?;
                s.set.unset(s.i);
            }
        }
    }
}

fn fuzz_next_gap(map: *const RMap, value: u64) !void {
    const gap = map.next_gap(value);
    if (gap.current_end) |end| {
        try testing.expect(end >= value);
        if (end < max) try testing.expect(map.get(end + 1) == null);
    }
    if (gap.next_start) |start| {
        try testing.expect(start > value);
        try testing.expect(map.get(start - 1) == null);
        try testing.expect(map.get(start) != null);
    }
}

fn fuzz_missing(map: *const RMap, reference: *Reference, reader: *fuzz_bytes.Reader) !void {
    const start = fuzz_value(reader);
    const limit: usize = @intCast(reader.below(fuzz_window) + 1);
    var buffer: [fuzz_window]u64 = undefined;
    const missing = map.missing_items(start, buffer[0..limit]);
    // Expected: absent values in [start, last) in order, at most `limit`.
    const last = map.last_index() orelse return testing.expectEqual(@as(usize, 0), missing.len);
    // Each step either records a missing value or skips a present one, and at most
    // 2 * fuzz_window values are present, so the loop is bounded.
    var expected_count: usize = 0;
    var value = start;
    var steps: usize = 0;
    while (value < last and expected_count < limit) : (value += 1) {
        steps += 1;
        assert(steps <= limit + 2 * fuzz_window);
        if (reference.contains(value)) continue;
        try testing.expect(expected_count < missing.len);
        try testing.expectEqual(value, missing[expected_count]);
        expected_count += 1;
    }
    try testing.expectEqual(expected_count, missing.len);
}

fn fuzz_run(bytes: []const u8) anyerror!void {
    var map: RMap = .empty;
    defer map.deinit(testing.allocator);
    var reference: Reference = .{};
    var reader = fuzz_bytes.Reader.init(bytes);
    var operations: u32 = 0;
    while (!reader.done() and operations < fuzz_operations_max) : (operations += 1) {
        switch (reader.below(5)) {
            0 => {
                const value = fuzz_value(&reader);
                try map.insert(testing.allocator, value);
                const s = reference.slot(value).?;
                s.set.set(s.i);
            },
            1 => try fuzz_remove(&map, &reference, &reader),
            2 => try fuzz_check_value(&map, &reference, fuzz_value(&reader)),
            3 => try fuzz_next_gap(&map, fuzz_value(&reader)),
            4 => try fuzz_missing(&map, &reference, &reader),
            else => unreachable,
        }
    }
    try fuzz_check_all(&map, &reference);
}

test "fuzz rmap operations (seeded)" {
    try fuzz_bytes.seeded(1024, 0x726d6170, 256, fuzz_run);
}

test "fuzz rmap operations" {
    try testing.fuzz({}, fuzz_bytes.smith(1024, fuzz_run), .{});
}
