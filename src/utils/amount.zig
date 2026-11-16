//! Amounts: unsigned integers with overflow-aware arithmetic (commonware
//! `utils/src/amount.rs`).
//!
//! Rust's `Amount` trait covers `u8`..`u128` and the wide `Uint<BITS, LIMBS>` integers; in Zig
//! every unsigned integer type qualifies (so `u256` stands in for `U256`), checked by
//! `assert_amount`.

const std = @import("std");
const assert = std.debug.assert;

/// Checks at comptime that `T` is an amount: an unsigned integer with a fixed codec size.
pub fn assert_amount(comptime T: type) void {
    comptime {
        const info = @typeInfo(T);
        assert(info == .int and info.int.signedness == .unsigned);
        assert(info.int.bits > 0 and info.int.bits % 8 == 0);
    }
}

pub fn zero(comptime T: type) T {
    assert_amount(T);
    return 0;
}

/// The wrapped sum and whether it overflowed.
pub fn overflowing_add(comptime T: type, a: T, b: T) struct { T, bool } {
    assert_amount(T);
    const sum, const overflow = @addWithOverflow(a, b);
    return .{ sum, overflow == 1 };
}

/// The wrapped difference and whether it overflowed.
pub fn overflowing_sub(comptime T: type, a: T, b: T) struct { T, bool } {
    assert_amount(T);
    const difference, const overflow = @subWithOverflow(a, b);
    return .{ difference, overflow == 1 };
}

/// `a + b`, or null when it overflows.
pub fn checked_add(comptime T: type, a: T, b: T) ?T {
    const sum, const overflow = overflowing_add(T, a, b);
    return if (overflow) null else sum;
}

/// `a - b`, or null when it underflows.
pub fn checked_sub(comptime T: type, a: T, b: T) ?T {
    const difference, const overflow = overflowing_sub(T, a, b);
    return if (overflow) null else difference;
}

const testing = std.testing;

test "amount: checked arithmetic follows overflow" {
    try testing.expectEqual(@as(?u8, 255), checked_add(u8, 250, 5));
    try testing.expectEqual(null, checked_add(u8, 250, 6));
    try testing.expectEqual(@as(?u64, 0), checked_sub(u64, 5, 5));
    try testing.expectEqual(null, checked_sub(u64, 5, 6));
    try testing.expectEqual(0, zero(u128));
}

test "amount: wide integers follow overflow" {
    const max = std.math.maxInt(u256);
    try testing.expectEqual(null, checked_add(u256, max, 1));
    try testing.expectEqual(null, checked_sub(u256, 5, 6));
    try testing.expectEqual(@as(?u256, 11), checked_add(u256, 5, 6));
    try testing.expectEqual(.{ @as(u256, 0), true }, overflowing_add(u256, max, 1));
    try testing.expectEqual(.{ max, true }, overflowing_sub(u256, 0, 1));
}
