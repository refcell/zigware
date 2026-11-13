//! Types for use as a read configuration (codec/src/config.rs).

const std = @import("std");
const assert = std.debug.assert;

/// Configuration limiting the range of a value, most often a decoded length.
///
/// Mirrors Rust's range syntax: `full()` is `..`, `from(a)` is `a..`, `to(b)` is `..b`,
/// `to_inclusive(b)` is `..=b`, `range(a, b)` is `a..b`, `inclusive(a, b)` is `a..=b`.
pub fn RangeCfg(comptime T: type) type {
    comptime assert(@typeInfo(T) == .int);
    return struct {
        const Self = @This();

        /// The lower bound of the range.
        start: Bound,
        /// The upper bound of the range.
        end: Bound,

        pub const Bound = union(enum) {
            included: T,
            excluded: T,
            unbounded,
        };

        /// `..`: every value.
        pub fn full() Self {
            return .{ .start = .unbounded, .end = .unbounded };
        }

        /// `start..`.
        pub fn from(start: T) Self {
            return .{ .start = .{ .included = start }, .end = .unbounded };
        }

        /// `..end` (end excluded).
        pub fn to(end: T) Self {
            return .{ .start = .unbounded, .end = .{ .excluded = end } };
        }

        /// `..=end`.
        pub fn to_inclusive(end: T) Self {
            return .{ .start = .unbounded, .end = .{ .included = end } };
        }

        /// `start..end` (end excluded).
        pub fn range(start: T, end: T) Self {
            return .{ .start = .{ .included = start }, .end = .{ .excluded = end } };
        }

        /// `start..=end`.
        pub fn inclusive(start: T, end: T) Self {
            return .{ .start = .{ .included = start }, .end = .{ .included = end } };
        }

        /// Accepts exactly `value`.
        pub fn exact(value: T) Self {
            return inclusive(value, value);
        }

        /// Returns true if `value` is within this range.
        pub fn contains(self: Self, value: T) bool {
            switch (self.start) {
                .included => |start| if (value < start) return false,
                .excluded => |start| if (value <= start) return false,
                .unbounded => {},
            }
            switch (self.end) {
                .included => |end| if (value > end) return false,
                .excluded => |end| if (value >= end) return false,
                .unbounded => {},
            }
            return true;
        }

        /// Converts both bounds to integer type `U`. Every bound must fit in `U`.
        pub fn cast(self: Self, comptime U: type) RangeCfg(U) {
            const Other = RangeCfg(U);
            const start: Other.Bound = switch (self.start) {
                .included => |value| .{ .included = @intCast(value) },
                .excluded => |value| .{ .excluded = @intCast(value) },
                .unbounded => .unbounded,
            };
            const end: Other.Bound = switch (self.end) {
                .included => |value| .{ .included = @intCast(value) },
                .excluded => |value| .{ .excluded = @intCast(value) },
                .unbounded => .unbounded,
            };
            return .{ .start = start, .end = end };
        }
    };
}

const testing = std.testing;

test "range cfg constructors" {
    const R = RangeCfg(usize);
    try testing.expectEqual(R{ .start = .unbounded, .end = .unbounded }, R.full());
    try testing.expectEqual(R{ .start = .{ .included = 5 }, .end = .unbounded }, R.from(5));
    try testing.expectEqual(R{ .start = .unbounded, .end = .{ .excluded = 10 } }, R.to(10));
    try testing.expectEqual(
        R{ .start = .unbounded, .end = .{ .included = 10 } },
        R.to_inclusive(10),
    );
    try testing.expectEqual(
        R{ .start = .{ .included = 5 }, .end = .{ .excluded = 10 } },
        R.range(5, 10),
    );
    try testing.expectEqual(
        R{ .start = .{ .included = 5 }, .end = .{ .included = 10 } },
        R.inclusive(5, 10),
    );
}

test "range cfg contains" {
    const R = RangeCfg(usize);
    const max = std.math.maxInt(usize);
    try testing.expect(R.full().contains(0) and R.full().contains(100));
    try testing.expect(R.full().contains(max));

    try testing.expect(!R.from(5).contains(4));
    try testing.expect(R.from(5).contains(5) and R.from(5).contains(6));
    try testing.expect(R.from(5).contains(max));

    try testing.expect(R.to(10).contains(0) and R.to(10).contains(9));
    try testing.expect(!R.to(10).contains(10) and !R.to(10).contains(11));

    try testing.expect(R.to_inclusive(10).contains(0) and R.to_inclusive(10).contains(10));
    try testing.expect(!R.to_inclusive(10).contains(11));

    try testing.expect(!R.range(5, 10).contains(4) and R.range(5, 10).contains(5));
    try testing.expect(R.range(5, 10).contains(9) and !R.range(5, 10).contains(10));

    try testing.expect(!R.inclusive(5, 10).contains(4) and R.inclusive(5, 10).contains(5));
    try testing.expect(R.inclusive(5, 10).contains(10) and !R.inclusive(5, 10).contains(11));

    const excluded_included = R{ .start = .{ .excluded = 5 }, .end = .{ .included = 10 } };
    try testing.expect(!excluded_included.contains(4) and !excluded_included.contains(5));
    try testing.expect(excluded_included.contains(6) and excluded_included.contains(10));
    try testing.expect(!excluded_included.contains(11));

    const excluded_excluded = R{ .start = .{ .excluded = 5 }, .end = .{ .excluded = 10 } };
    try testing.expect(!excluded_excluded.contains(5) and excluded_excluded.contains(6));
    try testing.expect(excluded_excluded.contains(9) and !excluded_excluded.contains(10));
}

test "range cfg empty ranges" {
    const R = RangeCfg(usize);
    try testing.expect(!R.range(5, 5).contains(4));
    try testing.expect(!R.range(5, 5).contains(5));
    try testing.expect(!R.range(5, 5).contains(6));
    try testing.expect(!R.inclusive(6, 5).contains(5));
    try testing.expect(!R.inclusive(6, 5).contains(6));
}

test "range cfg integer types" {
    const all_u8 = RangeCfg(u8).inclusive(0, 255);
    try testing.expect(all_u8.contains(0) and all_u8.contains(128) and all_u8.contains(255));
    const partial_u8 = RangeCfg(u8).range(10, 20);
    try testing.expect(!partial_u8.contains(9) and partial_u8.contains(10));
    try testing.expect(partial_u8.contains(19) and !partial_u8.contains(20));

    const r16 = RangeCfg(u16).inclusive(100, 1000);
    try testing.expect(!r16.contains(99) and r16.contains(100) and r16.contains(500));
    try testing.expect(r16.contains(1000) and !r16.contains(1001));

    const r32 = RangeCfg(u32).range(0, 1024);
    try testing.expect(r32.contains(0) and r32.contains(512));
    try testing.expect(!r32.contains(1024) and !r32.contains(2000));

    const r64 = RangeCfg(u64).from(1000);
    try testing.expect(!r64.contains(999) and r64.contains(1000));
    try testing.expect(r64.contains(std.math.maxInt(u64)));
}

test "range cfg cast" {
    const narrow = RangeCfg(u32).inclusive(1, 7);
    const wide = narrow.cast(usize);
    try testing.expect(!wide.contains(0) and wide.contains(1) and wide.contains(7));
    try testing.expect(!wide.contains(8));
    try testing.expectEqual(RangeCfg(usize).full(), RangeCfg(u8).full().cast(usize));
}
