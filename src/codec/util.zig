//! Helpers for reading, validating, and sizing encoded values (codec/src/util.rs).

const std = @import("std");
const assert = std.debug.assert;
const Reader = @import("buf.zig").Reader;
const Error = @import("error.zig").Error;
const varint = @import("varint.zig");

/// Fails with `EndOfBuffer` unless at least `len` bytes remain.
pub fn at_least(reader: *const Reader, len: usize) Error!void {
    return reader.at_least(len);
}

/// Fails with `EndOfBuffer` unless at least `len * item_size` bytes remain, treating
/// multiplication overflow as insufficient.
pub fn at_least_items(reader: *const Reader, len: usize, item_size: usize) Error!void {
    return reader.at_least_items(len, item_size);
}

/// Upper bound on the encoded size of a length-prefixed sequence of `len` items that each
/// encode to at most `item_size` bytes, with the length prefix at its widest.
/// `len` must fit the u32 length prefix.
pub fn max_items_size(len: usize, item_size: usize) usize {
    assert(len <= std.math.maxInt(u32)); // len must fit the u32 length prefix
    const result = len * item_size + varint.max_u32_varint_size;
    assert(result >= varint.max_u32_varint_size);
    return result;
}

/// Consumes the next `size` bytes, failing with `Invalid` unless they are all zero.
pub fn ensure_zeros(reader: *Reader, size: usize) Error!void {
    try reader.at_least(size);
    const region = reader.rest()[0..size];
    if (std.mem.findNone(u8, region, &.{0}) != null) {
        return reader.invalid("codec", "non-zero bytes");
    }
    reader.skip(size) catch unreachable; // Proof: `at_least` checked `size` bytes remain.
}

const testing = std.testing;
const codec = @import("codec.zig");

test "max_items_size" {
    const cases = [_][2]usize{ .{ 0, 5 }, .{ 1, 9 }, .{ 127, 513 }, .{ 128, 517 } };
    for (cases) |case| {
        const items = try testing.allocator.alloc([4]u8, case[0]);
        defer testing.allocator.free(items);
        @memset(items, .{ 0, 0, 0, 0 });
        const size = max_items_size(case[0], 4);
        try testing.expectEqual(case[1], size);
        try testing.expect(codec.encode_size([]const [4]u8, items) <= size);
    }
    const largest: usize = std.math.maxInt(u32);
    try testing.expectEqual(largest + varint.max_u32_varint_size, max_items_size(largest, 1));
}

test "ensure_zeros" {
    var reader = Reader.init(&.{ 0, 0, 0, 0, 7 });
    try ensure_zeros(&reader, 4);
    try testing.expectEqual(@as(usize, 1), reader.remaining());

    var empty = Reader.init(&.{});
    try ensure_zeros(&empty, 0);

    var short = Reader.init(&.{ 0, 0 });
    try testing.expectError(error.EndOfBuffer, ensure_zeros(&short, 3));

    for (0..4) |index| {
        var bytes = @as([4]u8, @splat(0));
        bytes[index] = 1;
        var nonzero = Reader.init(&bytes);
        try testing.expectError(error.Invalid, ensure_zeros(&nonzero, 4));
        try testing.expectEqualStrings("codec", nonzero.diagnostic.context);
    }
}
