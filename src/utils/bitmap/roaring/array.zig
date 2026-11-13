//! Array container for sparse data (commonware `bitmap/roaring/container/array.rs`): up to
//! 4096 sorted, unique `u16` values. Past that, a container converts to a `Bitmap`.
//!
//! Encoding: a `Vec<u16>` (u32 varint length, then big-endian values); decoding rejects more
//! than 4096 values and unsorted or duplicate ones.

const std = @import("std");
const codec = @import("codec");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const MAX_CARDINALITY: usize = 4096;

/// A set result with how many values it holds (Rust's `(Self, usize)`).
pub const Result = struct { array: Array, count: usize };

pub const Array = struct {
    values: std.ArrayList(u16) = .empty,

    pub const empty: Array = .{};
    pub const max_encode_size: usize = codec.varint.max_size(u32) + 2 * MAX_CARDINALITY;

    /// Takes ownership of `values` (allocated by `gpa`), which must be sorted, unique, and at
    /// most `MAX_CARDINALITY` long.
    pub fn from_owned(values: []u16) Array {
        if (!valid(values)) {
            @panic("Array::from requires sorted unique values with len <= MAX_CARDINALITY");
        }
        return .{ .values = .fromOwnedSlice(values) };
    }

    /// Copies sorted, unique `values`; `error.Invalid` otherwise (Rust `try_from`).
    pub fn init(gpa: Allocator, values: []const u16) (Allocator.Error || error{Invalid})!Array {
        if (!valid(values)) return error.Invalid;
        return from_owned(try gpa.dupe(u16, values));
    }

    pub fn clone(self: *const Array, gpa: Allocator) Allocator.Error!Array {
        return .{ .values = try self.values.clone(gpa) };
    }

    pub fn deinit(self: *Array, gpa: Allocator) void {
        self.values.deinit(gpa);
        self.* = undefined;
    }

    pub fn len(self: *const Array) usize {
        // A container converts an array that outgrows `MAX_CARDINALITY` right after it.
        assert(self.values.items.len <= MAX_CARDINALITY + 1 or sorted(self.values.items));
        return self.values.items.len;
    }

    pub fn is_empty(self: *const Array) bool {
        return self.values.items.len == 0;
    }

    pub fn as_slice(self: *const Array) []const u16 {
        return self.values.items;
    }

    pub fn contains(self: *const Array, value: u16) bool {
        const position = lower_bound(self.values.items, value);
        return position < self.values.items.len and self.values.items[position] == value;
    }

    /// Values in `[start, end)`.
    pub fn count_in_range(self: *const Array, start: u16, end: u16) usize {
        if (start >= end) return 0;
        const items = self.values.items;
        return lower_bound(items, end) -| lower_bound(items, start);
    }

    /// Maximal runs of consecutive values.
    pub fn run_count(self: *const Array) usize {
        const items = self.values.items;
        if (items.len == 0) return 0;
        var runs: usize = 1;
        for (items[0 .. items.len - 1], items[1..]) |a, b| {
            runs += @intFromBool(@as(u32, b) != @as(u32, a) + 1);
        }
        return runs;
    }

    pub fn min(self: *const Array) ?u16 {
        if (self.values.items.len == 0) return null;
        return self.values.items[0];
    }

    pub fn max(self: *const Array) ?u16 {
        return self.values.getLastOrNull();
    }

    /// Returns whether `value` was new.
    pub fn insert(self: *Array, gpa: Allocator, value: u16) Allocator.Error!bool {
        const position = lower_bound(self.values.items, value);
        if (position < self.values.items.len and self.values.items[position] == value) {
            return false;
        }
        try self.values.insert(gpa, position, value);
        assert(self.values.items[position] == value);
        return true;
    }

    /// Inserts `[start, end)`; returns how many values were new.
    pub fn insert_range(
        self: *Array,
        gpa: Allocator,
        start: u16,
        end: u16,
    ) Allocator.Error!usize {
        if (start >= end) return 0;
        const items = self.values.items;
        const start_position = lower_bound(items, start);
        const end_position = lower_bound(items, end);
        const range_len: usize = end - start;
        const added = range_len - (end_position - start_position);
        if (added == 0) return 0;
        const old_len = items.len;
        try self.values.resize(gpa, old_len + added);
        const all = self.values.items;
        // Shift the values past the range up, then write the whole range in place: the
        // values already inside it are exactly the range's members.
        std.mem.copyBackwards(
            u16,
            all[start_position + range_len ..],
            all[end_position..old_len],
        );
        for (all[start_position..][0..range_len], start..) |*slot, value| slot.* = @intCast(value);
        assert(sorted(all));
        return added;
    }

    /// The sorted union, truncated to at most `limit` values.
    pub fn @"union"(
        self: *const Array,
        gpa: Allocator,
        other: *const Array,
        limit: usize,
    ) Allocator.Error!Result {
        return merge(gpa, self.values.items, other.values.items, limit, .@"union");
    }

    pub fn intersection(
        self: *const Array,
        gpa: Allocator,
        other: *const Array,
        limit: usize,
    ) Allocator.Error!Result {
        return merge(gpa, self.values.items, other.values.items, limit, .intersection);
    }

    pub fn difference(
        self: *const Array,
        gpa: Allocator,
        other: *const Array,
        limit: usize,
    ) Allocator.Error!Result {
        return merge(gpa, self.values.items, other.values.items, limit, .difference);
    }

    const Operation = enum { @"union", intersection, difference };

    fn merge(
        gpa: Allocator,
        a: []const u16,
        b: []const u16,
        limit: usize,
        comptime operation: Operation,
    ) Allocator.Error!Result {
        const bound = switch (operation) {
            .@"union" => a.len + b.len,
            .intersection => @min(a.len, b.len),
            .difference => a.len,
        };
        var out: std.ArrayList(u16) = try .initCapacity(gpa, @min(bound, limit));
        var i: usize = 0;
        var j: usize = 0;
        // Each pass advances `i` or `j`: at most `a.len + b.len` passes.
        while (out.items.len < limit and (i < a.len or j < b.len)) {
            const take_a = j >= b.len or (i < a.len and a[i] <= b[j]);
            const take_b = i >= a.len or (j < b.len and b[j] <= a[i]);
            const keep = switch (operation) {
                .@"union" => true,
                .intersection => take_a and take_b,
                .difference => take_a and !take_b,
            };
            if (keep) out.appendAssumeCapacity(if (take_a) a[i] else b[j]);
            i += @intFromBool(take_a);
            j += @intFromBool(take_b);
            if (operation != .@"union" and i >= a.len) break;
        }
        assert(out.items.len <= @min(bound, limit));
        return .{ .array = .{ .values = out }, .count = out.items.len };
    }

    pub fn is_subset(self: *const Array, other: *const Array) bool {
        if (self.len() > other.len()) return false;
        var j: usize = 0;
        for (self.values.items) |value| {
            while (j < other.values.items.len and other.values.items[j] < value) j += 1;
            if (j == other.values.items.len or other.values.items[j] != value) return false;
            j += 1;
        }
        return true;
    }

    pub fn intersects(self: *const Array, other: *const Array) bool {
        var i: usize = 0;
        var j: usize = 0;
        const a = self.values.items;
        const b = other.values.items;
        while (i < a.len and j < b.len) {
            if (a[i] == b[j]) return true;
            if (a[i] < b[j]) i += 1 else j += 1;
        }
        return false;
    }

    // Codec.

    pub fn write(self: Array, writer: *codec.Writer) void {
        codec.write([]const u16, self.values.items, writer);
    }

    pub fn encode_size(self: Array) usize {
        return codec.encode_size([]const u16, self.values.items);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Array {
        const count = try codec.read_usize(reader, .to_inclusive(MAX_CARDINALITY));
        const values = try codec.read_items(u16, gpa, reader, count, {});
        if (!valid(values)) {
            gpa.free(values);
            return reader.invalid("Array", "values must be sorted and unique");
        }
        return from_owned(values);
    }

    /// commonware's `Arbitrary`: a length in `0..=4096`, then each value above the last
    /// with room left for the rest.
    pub fn arbitrary(
        gpa: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Array {
        const count = u.int_in_range(usize, 0, MAX_CARDINALITY);
        const values = try gpa.alloc(u16, count);
        var low: u32 = 0;
        for (values, 0..) |*value, index| {
            const high: u32 = std.math.maxInt(u16) - @as(u32, @intCast(count - index - 1));
            value.* = @intCast(u.int_in_range(u32, low, high));
            low = @as(u32, value.*) + 1;
        }
        return from_owned(values);
    }
};

/// The first position whose value is at least `value`.
pub fn lower_bound(items: []const u16, value: u16) usize {
    var low: usize = 0;
    var high: usize = items.len;
    // Each pass halves `high - low`: at most 13 passes for 4096 values.
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (items[middle] < value) low = middle + 1 else high = middle;
    }
    assert(low == items.len or items[low] >= value);
    return low;
}

fn valid(values: []const u16) bool {
    return values.len <= MAX_CARDINALITY and sorted(values);
}

fn sorted(values: []const u16) bool {
    for (1..@max(values.len, 1)) |index| {
        if (values[index - 1] >= values[index]) return false;
    }
    return true;
}

const testing = std.testing;

fn sample(values: []const u16) !Array {
    return Array.init(testing.allocator, values);
}

test "roaring array: insert, contains, order, min, max" {
    const gpa = testing.allocator;
    var array: Array = .empty;
    defer array.deinit(gpa);
    try testing.expect(array.is_empty() and array.min() == null and array.max() == null);
    for ([_]u16{ 5, 3, 7 }) |value| try testing.expect(try array.insert(gpa, value));
    try testing.expect(!try array.insert(gpa, 5));
    try testing.expect(array.contains(3) and array.contains(7) and !array.contains(4));
    for ([_]u16{ 10, 1 }) |value| _ = try array.insert(gpa, value);
    try testing.expectEqualSlices(u16, &.{ 1, 3, 5, 7, 10 }, array.as_slice());
    try testing.expectEqual(@as(?u16, 1), array.min());
    try testing.expectEqual(@as(?u16, 10), array.max());
    try testing.expectEqual(@as(usize, 2), array.count_in_range(3, 7));
    try testing.expectEqual(@as(usize, 5), array.run_count());
}

test "roaring array: insert_range paths" {
    const gpa = testing.allocator;
    var array: Array = .empty;
    defer array.deinit(gpa);
    try testing.expectEqual(@as(usize, 5), try array.insert_range(gpa, 5, 10));
    try testing.expectEqual(@as(usize, 2), try array.insert_range(gpa, 8, 12));
    try testing.expectEqualSlices(u16, &.{ 5, 6, 7, 8, 9, 10, 11 }, array.as_slice());
    try testing.expectEqual(@as(usize, 0), try array.insert_range(gpa, 6, 9));
    try testing.expectEqual(@as(usize, 2), try array.insert_range(gpa, 100, 102));
    try testing.expectEqual(@as(usize, 3), try array.insert_range(gpa, 0, 3));
    const expected = [_]u16{ 0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 100, 101 };
    try testing.expectEqualSlices(u16, &expected, array.as_slice());
    var gaps = try sample(&.{5});
    defer gaps.deinit(gpa);
    try testing.expectEqual(@as(usize, 4), try gaps.insert_range(gpa, 3, 8));
    try testing.expectEqualSlices(u16, &.{ 3, 4, 5, 6, 7 }, gaps.as_slice());
    var adjacent = try sample(&.{5});
    defer adjacent.deinit(gpa);
    try testing.expectEqual(@as(usize, 5), try adjacent.insert_range(gpa, 0, 5));
    try testing.expectEqual(@as(usize, 2), adjacent.run_count() + 1);
}

fn expect_result(result: Result, expected: []const u16) !void {
    var array = result.array;
    defer array.deinit(testing.allocator);
    try testing.expectEqualSlices(u16, expected, array.as_slice());
    try testing.expectEqual(expected.len, result.count);
}

test "roaring array: union, intersection, difference, subset" {
    const gpa = testing.allocator;
    const max = std.math.maxInt(usize);
    var a = try sample(&.{ 1, 3, 5, 7, 9 });
    defer a.deinit(gpa);
    var b = try sample(&.{ 2, 3, 4, 5, 6 });
    defer b.deinit(gpa);
    var none: Array = .empty;
    try expect_result(try a.intersection(gpa, &b, max), &.{ 3, 5 });
    try expect_result(try a.intersection(gpa, &b, 1), &.{3});
    try expect_result(try a.difference(gpa, &none, max), &.{ 1, 3, 5, 7, 9 });
    try expect_result(try a.difference(gpa, &none, 3), &.{ 1, 3, 5 });
    try expect_result(try a.difference(gpa, &b, max), &.{ 1, 7, 9 });
    try expect_result(try a.difference(gpa, &b, 2), &.{ 1, 7 });
    try expect_result(try a.@"union"(gpa, &b, max), &.{ 1, 2, 3, 4, 5, 6, 7, 9 });
    try expect_result(try a.@"union"(gpa, &b, 3), &.{ 1, 2, 3 });
    var one = try sample(&.{1});
    defer one.deinit(gpa);
    try expect_result(try a.@"union"(gpa, &one, 4), &.{ 1, 3, 5, 7 });

    var small = try sample(&.{ 1, 3, 5 });
    defer small.deinit(gpa);
    var wide = try sample(&.{ 0, 1, 2, 3, 4, 5, 6 });
    defer wide.deinit(gpa);
    var other = try sample(&.{ 1, 3, 6 });
    defer other.deinit(gpa);
    try testing.expect(small.is_subset(&wide) and !small.is_subset(&other));
    var evens = try sample(&.{ 2, 4, 6 });
    defer evens.deinit(gpa);
    try testing.expect(!small.intersects(&evens) and small.intersects(&other));
    try testing.expectError(error.Invalid, Array.init(gpa, &.{ 3, 1 }));
}

test "roaring array: codec" {
    const gpa = testing.allocator;
    var array: Array = .empty;
    defer array.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), array.encode_size());
    _ = try array.insert_range(gpa, 0, 1000);
    try testing.expectEqual(@as(usize, 2 + 2000), array.encode_size());
    const encoded = try codec.encode(Array, gpa, array);
    defer gpa.free(encoded);
    var decoded = try codec.decode(Array, gpa, encoded);
    defer decoded.deinit(gpa);
    try testing.expectEqualSlices(u16, array.as_slice(), decoded.as_slice());
    for ([_][]const u16{ &.{ 3, 10, 5 }, &.{ 1, 5, 5, 10 } }) |values| {
        const bytes = try codec.encode([]const u16, gpa, values);
        defer gpa.free(bytes);
        var reader = codec.Reader.init(bytes);
        try testing.expectError(error.Invalid, codec.decode_reader(Array, gpa, &reader, {}));
        try testing.expectEqualStrings("Array", reader.diagnostic.context);
    }
}
