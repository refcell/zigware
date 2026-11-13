//! Tests for tuple encodings (codec/src/types/tuple.rs). A Zig tuple `struct { A, B }`
//! encodes each field in order; its config is the tuple of field configs.

const std = @import("std");
const testing = std.testing;
const codec = @import("../codec.zig");

const gpa = testing.allocator;

fn expect_encoding(comptime T: type, value: T, expected: []const u8) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, expected, encoded);
}

test "tuple roundtrip" {
    const T = struct { u16, ?u32 };
    const values = [_]T{ .{ 1, null }, .{ 1, 2 } };
    for (values) |value| {
        const encoded = try codec.encode(T, gpa, value);
        defer gpa.free(encoded);
        try testing.expectEqual(value, try codec.decode(T, gpa, encoded));
    }
    try testing.expectEqual(@as(?usize, 7), codec.max_encode_size(T));
    try testing.expectEqual(@as(usize, 7), codec.encode_size(T, .{ 1, 2 }));
}

test "tuple conformity" {
    try expect_encoding(struct { bool, u8 }, .{ true, 0x42 }, &.{ 0x01, 0x42 });
    try expect_encoding(
        struct { u16, bool, u32 },
        .{ 0xabcd, false, 0xdeadbeef },
        &.{ 0xab, 0xcd, 0x00, 0xde, 0xad, 0xbe, 0xef },
    );
    try expect_encoding(struct { struct { u8, u8 }, u8 }, .{ .{ 1, 2 }, 3 }, &.{ 1, 2, 3 });
    try expect_encoding(struct { ?u16, u8 }, .{ 0x1234, 0xff }, &.{ 0x01, 0x12, 0x34, 0xff });
    try expect_encoding(struct { u8, ?u16 }, .{ 0xff, null }, &.{ 0xff, 0x00 });
}

test "tuple with configured fields frees on error" {
    const T = struct { []const u8, []const u8 };
    const cfg: codec.Cfg(T) = .{ .{ .range = .full() }, .{ .range = .full() } };
    const value = try codec.decode_cfg(T, gpa, &.{ 1, 0xaa, 2, 0xbb, 0xcc }, cfg);
    defer codec.free(T, gpa, value);
    try testing.expectEqualSlices(u8, &.{0xaa}, value[0]);
    try testing.expectEqualSlices(u8, &.{ 0xbb, 0xcc }, value[1]);
    const truncated = &[_]u8{ 1, 0xaa, 2, 0xbb };
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(T, gpa, truncated, cfg));
}
