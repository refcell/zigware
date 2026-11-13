//! Tests for slice encodings (codec/src/types/vec.rs). A slice `[]const T` is commonware's
//! `Vec<T>`: a `usize` length prefix, then each element. Decoding allocates; lengths must fit
//! a u32 and are bounded by a `RangeCfg(usize)`.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("../codec.zig");
const buf = @import("../buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("../error.zig").Error;

const gpa = testing.allocator;

/// One-byte element that goes through the generic per-element path instead of the bulk
/// `u8` path, like commonware's test `Byte`.
pub const Byte = struct {
    value: u8,
    pub const fixed_size = 1;

    pub fn write(self: Byte, writer: *Writer) void {
        writer.write_byte(self.value);
    }

    pub fn read(_: Allocator, reader: *Reader, _: void) Error!Byte {
        return .{ .value = try reader.read_byte() };
    }
};

/// Variable-size element type (no `fixed_size`), so reads take the growable path.
const VarByte = struct {
    value: u8,

    pub fn write(self: VarByte, writer: *Writer) void {
        writer.write_byte(self.value);
    }

    pub fn encode_size(_: VarByte) usize {
        return 1;
    }

    pub fn read(_: Allocator, reader: *Reader, _: void) Error!VarByte {
        return .{ .value = try reader.read_byte() };
    }
};

test "vec roundtrip and ranges" {
    const values = [_][]const u8{ &.{}, &.{1}, &.{ 1, 2, 3 } };
    for (values) |value| {
        const encoded = try codec.encode([]const u8, gpa, value);
        defer gpa.free(encoded);
        try testing.expectEqual(value.len + 1, encoded.len);

        const len = value.len;
        const decoded = try codec.decode_range([]const u8, gpa, encoded, .inclusive(len, len));
        defer gpa.free(decoded);
        try testing.expectEqualSlices(u8, value, decoded);

        try testing.expectError(
            error.InvalidLength,
            codec.decode_range([]const u8, gpa, encoded, .range(0, len)),
        );
        try testing.expectError(
            error.InvalidLength,
            codec.decode_range([]const u8, gpa, encoded, .from(len + 1)),
        );
    }
}

fn expect_decode_error(comptime T: type, expected: anyerror, bytes: []const u8) !void {
    try testing.expectError(expected, codec.decode_range(T, gpa, bytes, .full()));
}

test "vec truncated and extra data" {
    inline for (.{ []const u8, []const Byte, []const VarByte }) |T| {
        // The prefix advertises two items but one byte follows.
        try expect_decode_error(T, error.EndOfBuffer, &.{ 2, 1 });
        // Two items are read and one byte remains.
        try expect_decode_error(T, error.ExtraData, &.{ 2, 1, 2, 3 });
    }
}

test "vec hostile length fails without allocating it" {
    // The length prefix advertises u32::MAX items but one byte follows.
    const hostile = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0x0f, 0x01 };
    inline for (.{ []const Byte, []const VarByte, []const u8, []const u16 }) |T| {
        try expect_decode_error(T, error.EndOfBuffer, hostile);
    }

    // Reading a huge count of variable-size items reserves at most the remaining input.
    var reader = Reader.init(&.{0});
    const max = std.math.maxInt(usize);
    try testing.expectError(error.EndOfBuffer, codec.read_items(VarByte, gpa, &reader, max, {}));
}

test "vec of generic items" {
    const items = [_]Byte{ .{ .value = 1 }, .{ .value = 2 }, .{ .value = 3 } };
    const encoded = try codec.encode([]const Byte, gpa, &items);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 3, 1, 2, 3 }, encoded);
    const decoded = try codec.decode_range([]const Byte, gpa, encoded, .full());
    defer gpa.free(decoded);
    try testing.expectEqualSlices(Byte, &items, decoded);

    const variable = [_]VarByte{ .{ .value = 1 }, .{ .value = 2 }, .{ .value = 3 } };
    const decoded_variable = try codec.decode_range([]const VarByte, gpa, encoded, .full());
    defer gpa.free(decoded_variable);
    try testing.expectEqualSlices(VarByte, &variable, decoded_variable);
}

test "vec frees partial results on error" {
    // The second inner vector is truncated; the first must be freed (testing.allocator
    // reports leaks).
    const bytes = &[_]u8{ 2, 2, 0xaa, 0xbb, 3, 0xcc };
    const cfg: codec.Cfg([]const []const u8) = .{ .range = .full(), .item = .{ .range = .full() } };
    const T = []const []const u8;
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(T, gpa, bytes, cfg));
    const optional_cfg: codec.Cfg([]const ?[]const u8) = .{
        .range = .full(),
        .item = .{ .range = .full() },
    };
    const optional_bytes = &[_]u8{ 2, 1, 1, 0xaa, 1, 3, 0xcc };
    try testing.expectError(
        error.EndOfBuffer,
        codec.decode_cfg([]const ?[]const u8, gpa, optional_bytes, optional_cfg),
    );
}

test "vec decode survives allocation failure" {
    const bytes = &[_]u8{ 2, 2, 0xaa, 0xbb, 1, 0xcc };
    try testing.checkAllAllocationFailures(gpa, struct {
        fn decode_nested(allocator: Allocator, input: []const u8) !void {
            const cfg: codec.Cfg([]const []const u8) = .{
                .range = .full(),
                .item = .{ .range = .full() },
            };
            const value = try codec.decode_cfg([]const []const u8, allocator, input, cfg);
            codec.free([]const []const u8, allocator, value);
        }
    }.decode_nested, .{bytes});
}

fn expect_encoding(comptime T: type, value: T, expected: []const u8) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, expected, encoded);
}

test "vec conformity" {
    try expect_encoding([]const u8, &.{}, &.{0x00});
    try expect_encoding([]const u8, &.{ 1, 2, 3 }, &.{ 0x03, 0x01, 0x02, 0x03 });
    try expect_encoding([]const u16, &.{ 0x1234, 0xabcd }, &.{ 0x02, 0x12, 0x34, 0xab, 0xcd });
    try expect_encoding([]const bool, &.{ true, false, true }, &.{ 0x03, 0x01, 0x00, 0x01 });
    try expect_encoding([]const u32, &.{}, &.{0x00});

    const long: [200]u8 = @splat(0xcc);
    try expect_encoding([]const u8, &long, &([_]u8{ 0xc8, 0x01 } ++ long));
}
