//! Byzantine fault tolerance models for consensus protocols (commonware `utils/src/faults.rs`).
//!
//! - `N3f1`: fault model requiring `n >= 3f + 1` participants.
//! - `N5f1`: fault model requiring `n >= 5f + 1` participants.
//!
//! The Rust `Faults` trait becomes a comptime interface: a model is any type with
//! `max_faults(n) u32` and `quorum(n) u32`; `assert_faults` checks it. Like commonware,
//! every function accepts any integer type for `n` and panics when `n` is zero, negative,
//! or does not fit in a `u32`.

const std = @import("std");
const assert = std.debug.assert;

/// Comptime check that `Model` implements the faults interface.
pub fn assert_faults(comptime Model: type) void {
    comptime {
        assert(@hasDecl(Model, "max_faults"));
        assert(@hasDecl(Model, "quorum"));
    }
}

/// Converts `n` to a participant count, panicking like commonware on invalid input.
fn participants(n: anytype) u32 {
    comptime assert(@typeInfo(@TypeOf(n)) == .int or @TypeOf(n) == comptime_int);
    const count = std.math.cast(u32, n) orelse
        @panic("n must be a non-negative integer that fits in u32");
    if (count == 0) @panic("n must not be zero");
    return count;
}

/// `n - max_faults(n)` for any model whose fault bound is `(n - 1) / divisor`.
fn quorum_for(comptime divisor: u32, count: u32) u32 {
    comptime assert(divisor > 0);
    assert(count > 0);
    const faults = (count - 1) / divisor;
    const quorum = count - faults;
    assert(quorum > faults or count == 1);
    return quorum;
}

/// Fault model requiring `n >= 3f + 1` participants: `f = (n - 1) / 3`, `q = n - f`.
///
/// For any two quorums there is at least one honest participant in their intersection
/// (`2q > n + f`).
pub const N3f1 = struct {
    pub fn max_faults(n: anytype) u32 {
        const count = participants(n);
        const faults = (count - 1) / 3;
        assert(3 * @as(u64, faults) + 1 <= count);
        return faults;
    }

    pub fn quorum(n: anytype) u32 {
        return quorum_for(3, participants(n));
    }
};

/// Fault model requiring `n >= 5f + 1` participants: `f = (n - 1) / 5`, `q = n - f`
/// (also `l_quorum`), and `m_quorum = 2f + 1`.
pub const N5f1 = struct {
    pub fn max_faults(n: anytype) u32 {
        const count = participants(n);
        const faults = (count - 1) / 5;
        assert(5 * @as(u64, faults) + 1 <= count);
        return faults;
    }

    pub fn quorum(n: anytype) u32 {
        return quorum_for(5, participants(n));
    }

    /// Computes `2f + 1`.
    pub fn m_quorum(n: anytype) u32 {
        const count = participants(n);
        const result = 2 * max_faults(count) + 1;
        assert(result <= count);
        return result;
    }

    /// Computes `n - f`; equal to `quorum`.
    pub fn l_quorum(n: anytype) u32 {
        return quorum(n);
    }
};

comptime {
    assert_faults(N3f1);
    assert_faults(N5f1);
}

const testing = std.testing;

test "faults: N3f1 quorum and max_faults" {
    // (n, f, q) from commonware's rstest cases.
    const cases = [_][3]u32{
        .{ 1, 0, 1 },   .{ 2, 0, 2 },   .{ 3, 0, 3 },   .{ 4, 1, 3 },   .{ 5, 1, 4 },
        .{ 6, 1, 5 },   .{ 7, 2, 5 },   .{ 8, 2, 6 },   .{ 9, 2, 7 },   .{ 10, 3, 7 },
        .{ 11, 3, 8 },  .{ 12, 3, 9 },  .{ 13, 4, 9 },  .{ 14, 4, 10 }, .{ 15, 4, 11 },
        .{ 16, 5, 11 }, .{ 17, 5, 12 }, .{ 18, 5, 13 }, .{ 19, 6, 13 }, .{ 20, 6, 14 },
        .{ 21, 6, 15 },
    };
    for (cases) |case| {
        try testing.expectEqual(case[1], N3f1.max_faults(case[0]));
        try testing.expectEqual(case[2], N3f1.quorum(case[0]));
        try testing.expectEqual(case[0], case[1] + case[2]);
    }
}

test "faults: N5f1 quorums" {
    // (n, f, l_quorum, m_quorum) from commonware's rstest cases.
    const cases = [_][4]u32{
        .{ 1, 0, 1, 1 },   .{ 2, 0, 2, 1 },   .{ 3, 0, 3, 1 },   .{ 4, 0, 4, 1 },
        .{ 5, 0, 5, 1 },   .{ 6, 1, 5, 3 },   .{ 7, 1, 6, 3 },   .{ 8, 1, 7, 3 },
        .{ 9, 1, 8, 3 },   .{ 10, 1, 9, 3 },  .{ 11, 2, 9, 5 },  .{ 12, 2, 10, 5 },
        .{ 13, 2, 11, 5 }, .{ 14, 2, 12, 5 }, .{ 15, 2, 13, 5 }, .{ 16, 3, 13, 7 },
        .{ 17, 3, 14, 7 }, .{ 18, 3, 15, 7 }, .{ 19, 3, 16, 7 }, .{ 20, 3, 17, 7 },
        .{ 21, 4, 17, 9 },
    };
    for (cases) |case| {
        try testing.expectEqual(case[1], N5f1.max_faults(case[0]));
        try testing.expectEqual(case[2], N5f1.quorum(case[0]));
        try testing.expectEqual(case[2], N5f1.l_quorum(case[0]));
        try testing.expectEqual(case[3], N5f1.m_quorum(case[0]));
        try testing.expectEqual(case[0], case[1] + case[2]);
        try testing.expectEqual(case[3], 2 * case[1] + 1);
    }
}

test "faults: generic integer types" {
    try testing.expectEqual(@as(u32, 3), N3f1.max_faults(@as(u8, 10)));
    try testing.expectEqual(@as(u32, 3), N3f1.max_faults(@as(u16, 10)));
    try testing.expectEqual(@as(u32, 3), N3f1.max_faults(@as(u64, 10)));
    try testing.expectEqual(@as(u32, 3), N3f1.max_faults(@as(usize, 10)));
    try testing.expectEqual(@as(u32, 3), N3f1.max_faults(@as(i32, 10)));
    try testing.expectEqual(@as(u32, 7), N3f1.quorum(@as(i64, 10)));
    try testing.expectEqual(@as(u32, 7), N3f1.quorum(10));
    try testing.expectEqual(@as(u32, 1), N5f1.max_faults(@as(u64, 10)));
    try testing.expectEqual(@as(u32, 9), N5f1.quorum(@as(usize, 10)));
    try testing.expectEqual(@as(u32, 3), N5f1.m_quorum(@as(i32, 10)));
    try testing.expectEqual(@as(u32, 9), N5f1.l_quorum(@as(i64, 10)));
}

test "faults: quorum relationships and safety for all n below 10000" {
    // Exhaustive version of commonware's proptests.
    var n: u32 = 1;
    while (n < 10_000) : (n += 1) {
        const f3 = N3f1.max_faults(n);
        try testing.expect(2 * N3f1.quorum(n) > n + f3);
        const f5 = N5f1.max_faults(n);
        try testing.expect(2 * N5f1.quorum(n) > n + f5);
        if (n >= 6) {
            const m = N5f1.m_quorum(n);
            const l = N5f1.l_quorum(n);
            try testing.expect(m < l);
            try testing.expect(l <= n);
        }
    }
}
