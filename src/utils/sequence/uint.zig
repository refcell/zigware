//! `U32`, `U64`, `prefixed_u64.U64`, `VecU64`, and `Unit` (commonware
//! `utils/src/sequence/{u32,u64,prefixed_u64,vec_u64,unit}.rs`).
//!
//! `U32` and `U64` store the big-endian bytes, so byte order is numeric order; they encode
//! as those bytes. `PrefixedU64` adds a leading context byte. `VecU64` encodes a `u64` with
//! the framing of a `Vec<u8>` of its big-endian bytes (`0x08` then eight bytes). `Unit`
//! encodes as nothing.

const std = @import("std");
const codec = @import("codec");
const assert = std.debug.assert;

/// An `Array` holding the big-endian bytes of an unsigned integer.
fn BigEndian(comptime T: type) type {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    return struct {
        bytes: [@sizeOf(T)]u8,

        const Self = @This();

        pub const fixed_size: usize = @sizeOf(T);

        pub fn init(value: T) Self {
            var result: Self = undefined;
            std.mem.writeInt(T, &result.bytes, value, .big);
            assert(result.get() == value);
            return result;
        }

        pub fn from_bytes(bytes: [@sizeOf(T)]u8) Self {
            return .{ .bytes = bytes };
        }

        pub fn get(self: Self) T {
            return std.mem.readInt(T, &self.bytes, .big);
        }

        pub fn as_slice(self: *const Self) []const u8 {
            return &self.bytes;
        }

        pub fn order(a: Self, b: Self) std.math.Order {
            return std.mem.order(u8, &a.bytes, &b.bytes);
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u8, &a.bytes, &b.bytes);
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("{d}", .{self.get()});
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_bytes(&self.bytes);
        }

        pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{ .bytes = (try reader.take_array(@sizeOf(T))).* };
        }
    };
}

pub const U32 = BigEndian(u32);
pub const U64 = BigEndian(u64);

/// A `u64` key with a prefix byte, so one keyspace can hold several key contexts.
pub const PrefixedU64 = struct {
    bytes: [9]u8,

    pub const fixed_size: usize = 9;

    pub fn init(prefix_byte: u8, value_u64: u64) PrefixedU64 {
        var result: PrefixedU64 = .{ .bytes = undefined };
        result.bytes[0] = prefix_byte;
        std.mem.writeInt(u64, result.bytes[1..9], value_u64, .big);
        assert(result.prefix() == prefix_byte and result.value() == value_u64);
        return result;
    }

    pub fn from_bytes(bytes: [9]u8) PrefixedU64 {
        return .{ .bytes = bytes };
    }

    pub fn prefix(self: PrefixedU64) u8 {
        return self.bytes[0];
    }

    pub fn value(self: PrefixedU64) u64 {
        return std.mem.readInt(u64, self.bytes[1..9], .big);
    }

    pub fn as_slice(self: *const PrefixedU64) []const u8 {
        return &self.bytes;
    }

    pub fn order(a: PrefixedU64, b: PrefixedU64) std.math.Order {
        return std.mem.order(u8, &a.bytes, &b.bytes);
    }

    pub fn eql(a: PrefixedU64, b: PrefixedU64) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    /// `prefix:value`, like commonware's `Debug` and `Display`.
    pub fn format(self: PrefixedU64, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d}:{d}", .{ self.prefix(), self.value() });
    }

    pub fn write(self: PrefixedU64, writer: *codec.Writer) void {
        writer.write_bytes(&self.bytes);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!PrefixedU64 {
        return .{ .bytes = (try reader.take_array(9)).* };
    }
};

/// A `u64` encoded byte-identically to a `Vec<u8>` of its big-endian bytes.
pub const VecU64 = struct {
    value: u64,

    const len_bytes = @sizeOf(u64);

    pub const max_encode_size: usize = 1 + len_bytes;

    pub fn init(value: u64) VecU64 {
        return .{ .value = value };
    }

    pub fn write(self: VecU64, writer: *codec.Writer) void {
        codec.write(usize, len_bytes, writer);
        writer.write_int(u64, self.value);
    }

    pub fn encode_size(_: VecU64) usize {
        const size = codec.encode_size(usize, len_bytes) + len_bytes;
        assert(size == max_encode_size);
        return size;
    }

    /// Rejects any length prefix other than 8 with `InvalidLength`.
    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!VecU64 {
        const len = try codec.read_usize(reader, codec.RangeCfg(usize).exact(len_bytes));
        assert(len == len_bytes);
        return .{ .value = try reader.read_int(u64) };
    }
};

/// The empty `Array`: encodes as zero bytes, displays as `()`.
pub const Unit = struct {
    pub const fixed_size: usize = 0;

    pub fn as_slice(_: *const Unit) []const u8 {
        return &.{};
    }

    pub fn order(_: Unit, _: Unit) std.math.Order {
        return .eq;
    }

    pub fn eql(_: Unit, _: Unit) bool {
        return true;
    }

    pub fn format(_: Unit, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("()");
    }

    pub fn write(_: Unit, _: *codec.Writer) void {}

    pub fn read(_: std.mem.Allocator, _: *codec.Reader, _: void) codec.Error!Unit {
        return .{};
    }
};

const testing = std.testing;
const conformance = @import("../conformance.zig");

test "sequence: U32 and U64" {
    inline for (.{ U32, U64 }) |T| {
        const array = T.init(42);
        try testing.expectEqual(42, (try codec.decode(T, testing.allocator, &array.bytes)).get());
        try testing.expectEqual(42, T.from_bytes(array.bytes).get());
        const encoded = codec.encode_fixed(T, array);
        try testing.expectEqual(T.fixed_size, encoded.len);
        try testing.expectEqualSlices(u8, array.as_slice(), &encoded);
        try testing.expect(array.eql(try codec.decode(T, testing.allocator, &encoded)));
    }
    try testing.expectEqualSlices(u8, &.{ 0, 0, 1, 2 }, U32.init(258).as_slice());
    try testing.expectEqual(std.math.Order.lt, U64.init(255).order(U64.init(256)));
    var buffer: [24]u8 = undefined;
    try testing.expectEqualStrings("42", try std.fmt.bufPrint(&buffer, "{f}", .{U64.init(42)}));
}

test "sequence: prefixed U64" {
    const array = PrefixedU64.init(69, 42);
    const decoded = try codec.decode(PrefixedU64, testing.allocator, &array.bytes);
    try testing.expectEqual(@as(u64, 42), decoded.value());
    try testing.expectEqual(@as(u8, 69), decoded.prefix());
    const from = PrefixedU64.from_bytes(array.bytes);
    try testing.expectEqual(@as(u64, 42), from.value());
    const encoded = codec.encode_fixed(PrefixedU64, array);
    try testing.expectEqualSlices(u8, &.{ 69, 0, 0, 0, 0, 0, 0, 0, 42 }, &encoded);
    var buffer: [32]u8 = undefined;
    try testing.expectEqualStrings("69:42", try std.fmt.bufPrint(&buffer, "{f}", .{array}));
}

test "sequence: VecU64 matches Vec<u8> encoding" {
    const max = std.math.maxInt(u64);
    for ([_]u64{ 0, 1, 8, 42, 255, 256, max - 1, max }) |value| {
        var big_endian: [8]u8 = undefined;
        std.mem.writeInt(u64, &big_endian, value, .big);
        const as_vec = try codec.encode([]const u8, testing.allocator, &big_endian);
        defer testing.allocator.free(as_vec);
        const as_vec_u64 = try codec.encode(VecU64, testing.allocator, VecU64.init(value));
        defer testing.allocator.free(as_vec_u64);
        try testing.expectEqualSlices(u8, as_vec, as_vec_u64);

        const gpa = testing.allocator;
        const decoded_vec = try codec.decode_range([]const u8, gpa, as_vec_u64, .full());
        defer testing.allocator.free(decoded_vec);
        try testing.expectEqualSlices(u8, &big_endian, decoded_vec);
        try testing.expectEqual(value, (try codec.decode(VecU64, testing.allocator, as_vec)).value);
    }
    // Any other length prefix is rejected.
    const wrong = codec.decode(VecU64, testing.allocator, &.{ 7, 1, 2, 3, 4, 5, 6, 7 });
    try testing.expectError(error.InvalidLength, wrong);
    const short = codec.decode(VecU64, testing.allocator, &.{ 8, 1, 2, 3 });
    try testing.expectError(error.EndOfBuffer, short);
}

test "sequence: Unit" {
    const encoded = codec.encode_fixed(Unit, .{});
    try testing.expectEqual(@as(usize, 0), encoded.len);
    var reader = codec.Reader.init(&.{});
    _ = try codec.read(Unit, testing.allocator, &reader);
    try testing.expectEqual(@as(usize, 0), (Unit{}).as_slice().len);
    var buffer: [4]u8 = undefined;
    try testing.expectEqualStrings("()", try std.fmt.bufPrint(&buffer, "{f}", .{Unit{}}));
}

fn arbitrary_bytes(comptime T: type) conformance.Arbitrary(T) {
    return struct {
        fn arbitrary(_: void, u: *conformance.Unstructured) conformance.Error!T {
            var result: T = undefined;
            u.fill_buffer(&result.bytes);
            return result;
        }
    }.arbitrary;
}

fn arbitrary_vec_u64(_: void, u: *conformance.Unstructured) conformance.Error!VecU64 {
    return .init(u.int(u64));
}

fn arbitrary_unit(_: void, _: *conformance.Unstructured) conformance.Error!Unit {
    return .{};
}

test "sequence: conformance" {
    const hashes = .{
        .{ U32, "7e51d52b48539110acf575de847ef8d0c0029c877815f50b6a151db0621f2240" },
        .{ U64, "73102c8e2c269bbe2afd67158252c90a683a347e7ba623e8a1b383197c0d848a" },
        .{ PrefixedU64, "1c7e1a1fc1925835e28cc501d03a83d03085c800a93c0c8788558b3b2b5d409b" },
    };
    inline for (hashes) |entry| {
        try conformance.expect_codec_hash(entry[0], 65536, arbitrary_bytes(entry[0]), entry[1]);
    }
    try conformance.expect_codec_hash(
        VecU64,
        65536,
        arbitrary_vec_u64,
        "b2714bf2d181f332a44e9701d501d0f2d1cadd38d3bd87634c175fcefd8640fc",
    );
    try conformance.expect_codec_hash(
        Unit,
        65536,
        arbitrary_unit,
        "07854d2fef297a06ba81685e660c332de36d5d18d546927d30daad6d7fda1541",
    );
}
