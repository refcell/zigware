//! Tests for primitive encodings (codec/src/types/primitives.rs). The implementation is the
//! comptime dispatch in `codec.zig`: fixed-width big-endian integers and floats, one-byte
//! bools, varint `usize`, fixed arrays without a prefix, and bool-tagged optionals.

const std = @import("std");
const testing = std.testing;
const codec = @import("../codec.zig");
const Reader = @import("../buf.zig").Reader;
const Writer = @import("../buf.zig").Writer;
const varint = @import("../varint.zig");
const hex = @import("formatting").hex_literal;

const gpa = testing.allocator;

fn expect_encoding(comptime T: type, value: T, expected: []const u8) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, expected, encoded);
    try testing.expectEqual(expected.len, codec.encode_size(T, value));
}

fn expect_numeric_roundtrip(comptime T: type) !void {
    const values = [_]T{ 0, 1, 42, std.math.floatMax(T), -std.math.floatMax(T) };
    for (values) |value| try expect_value_roundtrip(T, value);
}

fn expect_value_roundtrip(comptime T: type, value: T) !void {
    const size = @sizeOf(T);
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqual(size, encoded.len);
    try testing.expectEqual(value, try codec.decode(T, gpa, encoded));
    try testing.expectEqual(size, codec.encode_size(T, value));
    const fixed = codec.encode_fixed(T, value);
    try testing.expectEqual(value, try codec.decode_fixed(T, &fixed));
}

fn expect_int_roundtrip(comptime T: type) !void {
    const values = [_]T{ 0, 1, 42, std.math.maxInt(T), std.math.minInt(T) };
    for (values) |value| try expect_value_roundtrip(T, value);
}

test "integer and float roundtrips" {
    inline for (.{ u8, u16, u32, u64, u128, i8, i16, i32, i64, i128 }) |T| {
        try expect_int_roundtrip(T);
    }
    try expect_numeric_roundtrip(f32);
    try expect_numeric_roundtrip(f64);
}

test "numeric read errors leave the reader unchanged" {
    var reader = Reader.init(&.{ 0x01, 0x02, 0x03 });
    try testing.expectEqual(@as(u16, 0x0102), try codec.read(u16, gpa, &reader));
    try testing.expectEqual(@as(usize, 1), reader.remaining());
    try testing.expectError(error.EndOfBuffer, codec.read(u16, gpa, &reader));
    try testing.expectEqual(@as(usize, 1), reader.remaining());
}

test "endianness" {
    try expect_encoding(u16, 0x0102, &.{ 0x01, 0x02 });
    try expect_encoding(u32, 0x01020304, &.{ 0x01, 0x02, 0x03, 0x04 });
    try expect_encoding(f32, 1.0, &.{ 0x3f, 0x80, 0x00, 0x00 });
}

test "numeric read_items bounds" {
    // A length whose byte size exceeds the buffer fails before decoding any element.
    var short = Reader.init(&(@as([8]u8, @splat(0))));
    try testing.expectError(error.EndOfBuffer, codec.read_items(u64, gpa, &short, 2, {}));
    try testing.expectEqual(@as(usize, 8), short.remaining());

    // A length whose byte size overflows fails the same way.
    var overflow = Reader.init(&(@as([8]u8, @splat(0))));
    const max = std.math.maxInt(usize);
    try testing.expectError(error.EndOfBuffer, codec.read_items(u64, gpa, &overflow, max, {}));

    // A valid read decodes big-endian values and consumes exactly their bytes.
    var valid = Reader.init(&.{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 });
    const items = try codec.read_items(u16, gpa, &valid, 2, {});
    defer gpa.free(items);
    try testing.expectEqualSlices(u16, &.{ 1, 2 }, items);
    try testing.expectEqual(@as(usize, 2), valid.remaining());
}

test "numeric array bounds" {
    var short = Reader.init(&(@as([8]u8, @splat(0))));
    try testing.expectError(error.EndOfBuffer, codec.read([2]u64, gpa, &short));
    try testing.expectEqual(@as(usize, 8), short.remaining());

    var valid = Reader.init(&.{ 0x00, 0x01, 0x00, 0x02 });
    try testing.expectEqual([2]u16{ 1, 2 }, try codec.read([2]u16, gpa, &valid));
    try testing.expectEqual(@as(usize, 0), valid.remaining());
}

test "bool" {
    for ([_]bool{ true, false }) |value| {
        const encoded = try codec.encode(bool, gpa, value);
        defer gpa.free(encoded);
        try testing.expectEqual(@as(usize, 1), encoded.len);
        try testing.expectEqual(value, try codec.decode(bool, gpa, encoded));
    }
    try testing.expectError(error.InvalidBool, codec.decode(bool, gpa, &.{2}));
}

test "usize" {
    const values = [_]usize{ 0, 1, 42, std.math.maxInt(u32) };
    for (values) |value| {
        const encoded = try codec.encode(usize, gpa, value);
        defer gpa.free(encoded);
        try testing.expectEqual(varint.size(u32, @intCast(value)), codec.encode_size(usize, value));
        try testing.expectEqual(value, try codec.decode_cfg(usize, gpa, encoded, .full()));
    }
    var reader = Reader.init(&.{0x05});
    try testing.expectError(error.InvalidLength, codec.read_cfg(usize, gpa, &reader, .to(5)));
    try testing.expectEqual(@as(u64, 5), reader.diagnostic.value);
}

test "arrays" {
    try testing.expectEqual(@as(?usize, 3), codec.fixed_size([3]u8));
    try testing.expectEqual(@as(?usize, 6), codec.fixed_size([3]u16));

    const bytes = [_]u8{ 1, 2, 3 };
    try expect_encoding([3]u8, bytes, &bytes);
    try testing.expectEqual(bytes, try codec.decode([3]u8, gpa, &bytes));
    try testing.expectError(error.EndOfBuffer, codec.decode([3]u8, gpa, &.{ 1, 2 }));
    var reader = Reader.init(&.{ 1, 2, 3, 4 });
    try testing.expectError(error.ExtraData, codec.decode_reader([3]u8, gpa, &reader, {}));
    try testing.expectEqual(@as(u64, 1), reader.diagnostic.value);

    const words = [_]u16{ 0x0102, 0x0304, 0x0506 };
    try expect_encoding([3]u16, words, &.{ 1, 2, 3, 4, 5, 6 });
    try testing.expectEqual(words, try codec.decode([3]u16, gpa, &.{ 1, 2, 3, 4, 5, 6 }));

    const nested = [2][2]u16{ .{ 0x0102, 0x0304 }, .{ 0x0506, 0x0708 } };
    try expect_encoding([2][2]u16, nested, &.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try testing.expectEqual(nested, try codec.decode([2][2]u16, gpa, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }));

    // Arrays of configurable elements pass the element config to each read.
    const sizes = try codec.decode_cfg([2]usize, gpa, &.{ 0x01, 0x02 }, .full());
    try testing.expectEqual([2]usize{ 1, 2 }, sizes);

    // Arrays of variable-size elements encode each element in turn.
    const variable = [2][]const u8{ &.{ 1, 2 }, &.{ 3, 4, 5 } };
    try expect_encoding([2][]const u8, variable, &.{ 0x02, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05 });
    const encoded = try codec.encode([2][]const u8, gpa, variable);
    defer gpa.free(encoded);
    const decoded = try codec.decode_cfg([2][]const u8, gpa, encoded, .{ .range = .full() });
    defer codec.free([2][]const u8, gpa, decoded);
    try testing.expectEqualSlices(u8, variable[0], decoded[0]);
    try testing.expectEqualSlices(u8, variable[1], decoded[1]);
}

test "optional" {
    for ([_]?u32{ 42, null }) |value| {
        const encoded = try codec.encode(?u32, gpa, value);
        defer gpa.free(encoded);
        try testing.expectEqual(value, try codec.decode(?u32, gpa, encoded));
    }
    try testing.expectEqual(@as(usize, 5), codec.encode_size(?u32, 42));
    try testing.expectEqual(@as(usize, 1), codec.encode_size(?u32, null));
    try testing.expectEqual(@as(?usize, 5), codec.max_encode_size(?u32));
}

test "usize write above u32 panics" {
    // commonware panics with "write: usize value is larger than u32"; zigware asserts. The
    // assertion cannot be caught in-process, so only the boundary value is checked here.
    try testing.expectEqual(@as(usize, 5), codec.encode_size(usize, std.math.maxInt(u32)));
}

test "conformity" {
    try expect_encoding(bool, true, &.{0x01});
    try expect_encoding(bool, false, &.{0x00});

    try expect_encoding(u8, 0, &.{0x00});
    try expect_encoding(u8, 255, &.{0xff});
    try expect_encoding(i8, 0, &.{0x00});
    try expect_encoding(i8, -1, &.{0xff});
    try expect_encoding(i8, 127, &.{0x7f});
    try expect_encoding(i8, -128, &.{0x80});

    try expect_encoding(u16, 0, &.{ 0x00, 0x00 });
    try expect_encoding(u16, 0xabcd, &.{ 0xab, 0xcd });
    try expect_encoding(u16, 0xffff, &.{ 0xff, 0xff });
    try expect_encoding(i16, 0, &.{ 0x00, 0x00 });
    try expect_encoding(i16, -1, &.{ 0xff, 0xff });
    try expect_encoding(i16, 0x1234, &.{ 0x12, 0x34 });

    try expect_encoding(u32, 0, &hex("00000000"));
    try expect_encoding(u32, 0xabcdef01, &hex("abcdef01"));
    try expect_encoding(u32, 0xffffffff, &hex("ffffffff"));
    try expect_encoding(i32, 0, &hex("00000000"));
    try expect_encoding(i32, -1, &hex("ffffffff"));
    try expect_encoding(i32, 0x12345678, &hex("12345678"));

    try expect_encoding(u64, 0, &hex("0000000000000000"));
    try expect_encoding(u64, 0x0123456789abcdef, &hex("0123456789abcdef"));
    try expect_encoding(u64, std.math.maxInt(u64), &hex("ffffffffffffffff"));
    try expect_encoding(i64, 0, &hex("0000000000000000"));
    try expect_encoding(i64, -1, &hex("ffffffffffffffff"));

    const u128_value: u128 = 0x0123456789abcdef0123456789abcdef;
    try expect_encoding(u128, u128_value, &hex("0123456789abcdef0123456789abcdef"));
    try expect_encoding(u128, std.math.maxInt(u128), &(@as([16]u8, @splat(0xff))));
    try expect_encoding(i128, -1, &(@as([16]u8, @splat(0xff))));

    try expect_encoding(f32, 1.0, &hex("3f800000"));
    try expect_encoding(f32, -1.0, &hex("bf800000"));
    try expect_encoding(f32, std.math.inf(f32), &hex("7f800000"));
    try expect_encoding(f32, -std.math.inf(f32), &hex("ff800000"));
    try expect_encoding(f32, std.math.floatMax(f32), &hex("7f7fffff"));
    try expect_encoding(f64, 1.0, &hex("3ff0000000000000"));
    try expect_encoding(f64, -1.0, &hex("bff0000000000000"));
    try expect_encoding(f64, std.math.inf(f64), &hex("7ff0000000000000"));

    try expect_encoding([3]u8, .{ 1, 2, 3 }, &.{ 0x01, 0x02, 0x03 });
    try expect_encoding([0]u8, .{}, &.{});

    try expect_encoding(?u32, 42, &.{ 0x01, 0x00, 0x00, 0x00, 0x2a });
    try expect_encoding(?u32, null, &.{0x00});

    try expect_encoding(usize, 0, &.{0x00});
    try expect_encoding(usize, 1, &.{0x01});
    try expect_encoding(usize, 127, &.{0x7f});
    try expect_encoding(usize, 128, &.{ 0x80, 0x01 });
    try expect_encoding(usize, std.math.maxInt(u32), &.{ 0xff, 0xff, 0xff, 0xff, 0x0f });
}

test "array writes bytes in bulk" {
    var out: [3]u8 = undefined;
    var writer = Writer.init(&out);
    codec.write([3]u8, .{ 1, 2, 3 }, &writer);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, writer.written());
}
