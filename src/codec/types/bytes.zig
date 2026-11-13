//! Codec for borrowed byte strings (codec/src/types/bytes.rs).
//!
//! `Bytes` is commonware's `bytes::Bytes` decoded through `Viewing`: reading returns a view
//! into the input buffer without copying, so it lives as long as that buffer. Decode into
//! `[]const u8` instead to get an owned copy (`Vec<u8>`); both share one wire format:
//! a `usize` length prefix, then the bytes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const buf = @import("../buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("../error.zig").Error;
const RangeCfg = @import("../config.zig").RangeCfg;
const codec = @import("../codec.zig");
const varint = @import("../varint.zig");

/// A length-prefixed byte string that borrows from the decode input.
pub const Bytes = struct {
    data: []const u8,

    pub const Cfg = RangeCfg(usize);

    pub fn init(data: []const u8) Bytes {
        return .{ .data = data };
    }

    pub fn write(self: Bytes, writer: *Writer) void {
        codec.write(usize, self.data.len, writer);
        writer.write_bytes(self.data);
    }

    pub fn encode_size(self: Bytes) usize {
        return codec.encode_size(usize, self.data.len) + self.data.len;
    }

    pub fn order(a: Bytes, b: Bytes) std.math.Order {
        return std.mem.order(u8, a.data, b.data);
    }

    pub fn read(_: Allocator, reader: *Reader, range: Cfg) Error!Bytes {
        const len = try codec.read_usize(reader, range);
        const data = try reader.take(len);
        assert(data.len == len);
        return .{ .data = data };
    }
};

const testing = std.testing;
const formatting = @import("formatting");

test "bytes roundtrip and range" {
    var zeros: [300]u8 = @splat(0);
    const values = [_]Bytes{ .init(&.{}), .init(&.{ 1, 2, 3 }), .init(&zeros) };
    const gpa = testing.allocator;
    for (values) |value| {
        const encoded = try codec.encode(Bytes, gpa, value);
        defer gpa.free(encoded);
        const len = value.data.len;

        const decoded = try codec.decode_cfg(Bytes, gpa, encoded, .inclusive(len, len));
        try testing.expectEqualSlices(u8, value.data, decoded.data);

        try testing.expectError(
            error.InvalidLength,
            codec.decode_cfg(Bytes, gpa, encoded, .range(0, len)),
        );
        try testing.expectError(
            error.InvalidLength,
            codec.decode_cfg(Bytes, gpa, encoded, .from(len + 1)),
        );
        try testing.expectError(
            error.EndOfBuffer,
            codec.decode_cfg(Bytes, gpa, encoded[0 .. encoded.len - 1], .inclusive(len, len)),
        );
    }
}

test "bytes conformity" {
    const gpa = testing.allocator;
    const empty = try codec.encode(Bytes, gpa, .init(&.{}));
    defer gpa.free(empty);
    try testing.expectEqualSlices(u8, &.{0x00}, empty);

    const hello = try codec.encode(Bytes, gpa, .init("hello"));
    defer gpa.free(hello);
    try testing.expectEqualSlices(u8, &.{ 0x05, 'h', 'e', 'l', 'l', 'o' }, hello);

    const long: [150]u8 = @splat(0xaa);
    const long_encoded = try codec.encode(Bytes, gpa, .init(&long));
    defer gpa.free(long_encoded);
    try testing.expectEqualSlices(u8, &(formatting.hex_literal("9601") ++ long), long_encoded);
}

test "bytes decode as views and slices decode as copies" {
    const gpa = testing.allocator;
    var payloads: [64]Bytes = undefined;
    const payload: [17]u8 = @splat(7);
    for (&payloads) |*item| item.* = .init(&payload);
    const source = try codec.encode([]const Bytes, gpa, &payloads);
    defer gpa.free(source);
    const source_start = @intFromPtr(source.ptr);
    const source_end = source_start + source.len;

    const cfg: codec.Cfg([]const Bytes) = .{ .range = .full(), .item = .full() };
    const views = try codec.decode_cfg([]const Bytes, gpa, source, cfg);
    defer codec.free([]const Bytes, gpa, views);
    for (views) |view| {
        try testing.expectEqualSlices(u8, &payload, view.data);
        const address = @intFromPtr(view.data.ptr);
        try testing.expect(address >= source_start and address < source_end);
    }

    const copy_cfg: codec.Cfg([]const []const u8) = .{
        .range = .full(),
        .item = .{ .range = .full() },
    };
    const copies = try codec.decode_cfg([]const []const u8, gpa, source, copy_cfg);
    defer codec.free([]const []const u8, gpa, copies);
    for (copies) |copy| {
        try testing.expectEqualSlices(u8, &payload, copy);
        const address = @intFromPtr(copy.ptr);
        try testing.expect(address < source_start or address >= source_end);
    }
}
