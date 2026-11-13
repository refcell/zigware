//! Tests for fixed-width unsigned integers of any width (codec/src/uint.rs).
//!
//! commonware's `Uint<BITS, LIMBS>` (and `U256`) is a native Zig `uN`: it encodes big-endian
//! over the fewest bytes that hold its bits, and decoding refuses a bit set beyond the width.
//! The implementation is the integer case of the comptime dispatch in `codec.zig`.

const std = @import("std");
const testing = std.testing;
const codec = @import("../codec.zig");
const Reader = @import("../buf.zig").Reader;

const gpa = testing.allocator;

fn expect_roundtrip(comptime T: type, value: T, expected: []const u8) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, expected, encoded);
    try testing.expectEqual(codec.fixed_size(T).?, encoded.len);
    try testing.expectEqual(value, try codec.decode(T, gpa, encoded));
}

test "u256 round trips as big-endian" {
    const values = [_]u256{ 0, 1, std.math.maxInt(u256), @as(u256, 1 << 8) << 192 };
    for (values) |value| {
        var expected: [32]u8 = undefined;
        std.mem.writeInt(u256, &expected, value, .big);
        try expect_roundtrip(u256, value, &expected);
    }
    const value: u512 = std.math.maxInt(u512) - 7;
    var expected: [64]u8 = undefined;
    std.mem.writeInt(u512, &expected, value, .big);
    try expect_roundtrip(u512, value, &expected);
}

test "partial widths encode their bytes only" {
    try testing.expectEqual(@as(?usize, 5), codec.fixed_size(u40));
    const all: [5]u8 = @splat(0xff);
    try expect_roundtrip(u40, std.math.maxInt(u40), &all);
    const six: [6]u8 = @splat(0xff);
    var reader = Reader.init(&six);
    try testing.expectError(error.ExtraData, codec.decode_reader(u40, gpa, &reader, {}));
    try testing.expectEqual(@as(u64, 1), reader.diagnostic.value);
    try testing.expectError(error.EndOfBuffer, codec.decode(u40, gpa, all[0..4]));

    try testing.expectEqual(@as(?usize, 9), codec.fixed_size(u72));
    const value: u72 = (@as(u72, 0xab) << 64) | 0x0102_0304_0506_0708;
    const expected = [_]u8{ 0xab, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    try expect_roundtrip(u72, value, &expected);
}

test "rejects bits beyond the width" {
    const all: [5]u8 = @splat(0xff);
    var reader = Reader.init(&all);
    try testing.expectError(error.Invalid, codec.decode_reader(u36, gpa, &reader, {}));
    try testing.expectEqualStrings("Uint", reader.diagnostic.context);
    const max = [_]u8{ 0x0f, 0xff, 0xff, 0xff, 0xff };
    try testing.expectEqual(@as(u36, std.math.maxInt(u36)), try codec.decode(u36, gpa, &max));
}

test "wide arithmetic reports overflow" {
    // Rust's `overflowing_add`/`overflowing_sub` are Zig's `@addWithOverflow`/`@subWithOverflow`.
    const max: u256 = std.math.maxInt(u256);
    try testing.expectEqual(@as(u256, 0), @addWithOverflow(max, 1)[0]);
    try testing.expectEqual(@as(u1, 1), @addWithOverflow(max, 1)[1]);
    try testing.expectEqual(@as(u256, 11), @addWithOverflow(@as(u256, 5), 6)[0]);
    try testing.expectEqual(max, @subWithOverflow(@as(u256, 5), 6)[0]);
    try testing.expectEqual(@as(u1, 1), @subWithOverflow(@as(u256, 5), 6)[1]);
}
