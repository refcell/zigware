//! Linear ranges and cyclic spans (commonware `utils/src/range.rs`).
//!
//! `contains_cyclic` tests membership in a span that wraps around when its start is not
//! below its end. `NonEmptyRange(T)` is a half-open range `[start, end)` with
//! `start < end`. Its codec encoding (start then end, decode rejects `start >= end`)
//! lands with the codec package.

const std = @import("std");
const assert = std.debug.assert;

/// One end of a span, like Rust's `core::ops::Bound`.
pub fn Bound(comptime T: type) type {
    return union(enum) {
        included: T,
        excluded: T,
        unbounded,

        const Self = @This();

        fn value(bound: Self) ?T {
            return switch (bound) {
                .included, .excluded => |v| v,
                .unbounded => null,
            };
        }
    };
}

/// Returns whether `key` lies in the span `start..end` (bounds as given).
///
/// When both ends are bounded and `start >= end`, the span wraps: it covers keys after
/// `start` or before `end`. Otherwise it is the ordinary interval. `T` is any type that
/// `std.math.order` compares.
pub fn contains_cyclic(comptime T: type, start: Bound(T), end: Bound(T), key: T) bool {
    const after_start = switch (start) {
        .included => |s| std.math.order(key, s) != .lt,
        .excluded => |s| std.math.order(key, s) == .gt,
        .unbounded => true,
    };
    const before_end = switch (end) {
        .included => |e| std.math.order(key, e) != .gt,
        .excluded => |e| std.math.order(key, e) == .lt,
        .unbounded => true,
    };
    const start_value = start.value() orelse return after_start and before_end;
    const end_value = end.value() orelse return after_start and before_end;
    if (std.math.order(start_value, end_value) != .lt) return after_start or before_end;
    assert(start_value < end_value);
    return after_start and before_end;
}

pub const EmptyRangeError = error{EmptyRange};

/// A half-open range `[start, end)` that is never empty.
pub fn NonEmptyRange(comptime T: type) type {
    return struct {
        range_start: T,
        range_end: T,

        const Self = @This();

        /// Returns `error.EmptyRange` unless `start < end`.
        pub fn init(start_value: T, end_value: T) EmptyRangeError!Self {
            if (!(start_value < end_value)) return error.EmptyRange;
            const result: Self = .{ .range_start = start_value, .range_end = end_value };
            assert(result.range_start < result.range_end);
            return result;
        }

        pub fn start(range: Self) T {
            assert(range.range_start < range.range_end);
            return range.range_start;
        }

        pub fn end(range: Self) T {
            assert(range.range_start < range.range_end);
            return range.range_end;
        }

        /// Number of values in the range; at least one.
        pub fn len(range: Self) T {
            assert(range.range_start < range.range_end);
            return range.range_end - range.range_start;
        }

        pub fn contains(range: Self, value: T) bool {
            return range.range_start <= value and value < range.range_end;
        }
    };
}

const testing = std.testing;

test "range: contains_cyclic boundaries" {
    const B = Bound(u8);
    const Case = struct { B, B, []const u8 };
    const cases = [_]Case{
        .{ .{ .included = 2 }, .{ .excluded = 6 }, &.{ 2, 3, 4, 5 } },
        .{ .{ .excluded = 2 }, .{ .included = 6 }, &.{ 3, 4, 5, 6 } },
        .{ .{ .included = 2 }, .{ .included = 6 }, &.{ 2, 3, 4, 5, 6 } },
        .{ .{ .excluded = 2 }, .{ .excluded = 6 }, &.{ 3, 4, 5 } },
        .{ .{ .included = 6 }, .{ .excluded = 2 }, &.{ 0, 1, 6, 7 } },
        .{ .{ .excluded = 6 }, .{ .included = 2 }, &.{ 0, 1, 2, 7 } },
        .{ .{ .included = 6 }, .{ .included = 2 }, &.{ 0, 1, 2, 6, 7 } },
        .{ .{ .excluded = 6 }, .{ .excluded = 2 }, &.{ 0, 1, 7 } },
        .{ .{ .included = 3 }, .{ .excluded = 3 }, &.{ 0, 1, 2, 3, 4, 5, 6, 7 } },
        .{ .{ .excluded = 3 }, .{ .included = 3 }, &.{ 0, 1, 2, 3, 4, 5, 6, 7 } },
        .{ .{ .included = 3 }, .{ .included = 3 }, &.{ 0, 1, 2, 3, 4, 5, 6, 7 } },
        .{ .{ .excluded = 3 }, .{ .excluded = 3 }, &.{ 0, 1, 2, 4, 5, 6, 7 } },
        .{ .unbounded, .{ .included = 3 }, &.{ 0, 1, 2, 3 } },
        .{ .unbounded, .{ .excluded = 3 }, &.{ 0, 1, 2 } },
        .{ .{ .included = 3 }, .unbounded, &.{ 3, 4, 5, 6, 7 } },
        .{ .{ .excluded = 3 }, .unbounded, &.{ 4, 5, 6, 7 } },
        .{ .unbounded, .unbounded, &.{ 0, 1, 2, 3, 4, 5, 6, 7 } },
    };
    for (cases) |case| {
        var actual: [8]u8 = undefined;
        var count: usize = 0;
        for (0..8) |k| {
            const key: u8 = @intCast(k);
            if (contains_cyclic(u8, case[0], case[1], key)) {
                actual[count] = key;
                count += 1;
            }
        }
        try testing.expectEqualSlices(u8, case[2], actual[0..count]);
    }
}

test "range: contains_cyclic extremes" {
    const B = Bound(u8);
    const max = std.math.maxInt(u8);
    const wrap_max: [2]B = .{ .{ .included = max }, .{ .excluded = 0 } };
    const wrap_min: [2]B = .{ .{ .excluded = max }, .{ .included = 0 } };
    for (0..256) |k| {
        const key: u8 = @intCast(k);
        try testing.expectEqual(key == max, contains_cyclic(u8, wrap_max[0], wrap_max[1], key));
        try testing.expectEqual(key == 0, contains_cyclic(u8, wrap_min[0], wrap_min[1], key));
        try testing.expect(contains_cyclic(u8, .{ .included = 0 }, .{ .excluded = 0 }, key));
        try testing.expect(contains_cyclic(u8, .{ .included = max }, .{ .excluded = max }, key));
        try testing.expect(!contains_cyclic(u8, .unbounded, .{ .excluded = 0 }, key));
        try testing.expect(!contains_cyclic(u8, .{ .excluded = max }, .unbounded, key));
    }
}

test "range: NonEmptyRange" {
    const R = NonEmptyRange(u32);
    const r = try R.init(0, 5);
    try testing.expectEqual(@as(u32, 0), r.start());
    try testing.expectEqual(@as(u32, 5), r.end());
    try testing.expectEqual(@as(u32, 5), r.len());
    const single = try R.init(3, 4);
    try testing.expectEqual(@as(u32, 1), single.len());
    try testing.expect(single.contains(3));
    try testing.expect(!single.contains(4));
    try testing.expectError(error.EmptyRange, R.init(5, 5));
    try testing.expectError(error.EmptyRange, R.init(5, 3));
}
