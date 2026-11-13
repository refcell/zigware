//! Variable-length integer encoding and decoding (codec/src/varint.rs).
//!
//! Google Protocol Buffers varints: each byte carries 7 data bits, least significant group
//! first, with the high bit set when more bytes follow. Every value has exactly one valid
//! encoding: a trailing zero byte and bits beyond the type's width are rejected.
//!
//! Works for any unsigned integer width (commonware's `Uint<BITS, LIMBS>` is a native Zig
//! `uN`), and for signed integers through ZigZag encoding.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const buf = @import("buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("error.zig").Error;

/// The number of data-bearing bits in a byte.
const data_bits_per_byte = 7;
/// The mask for the data-bearing bits in a byte.
const data_bits_mask: u8 = 0x7f;
/// The continuation bit: set when more bytes follow.
const continuation_bit_mask: u8 = 0x80;

/// Maximum encoded size of a varint of unsigned type `T`, in bytes.
pub fn max_size(comptime T: type) usize {
    const bits = @bitSizeOf(T);
    return if (bits == 0) 1 else std.math.divCeil(usize, bits, data_bits_per_byte) catch
        unreachable; // Proof: the divisor is the non-zero constant 7.
}

pub const max_u16_varint_size = max_size(u16);
pub const max_u32_varint_size = max_size(u32);
pub const max_u64_varint_size = max_size(u64);
pub const max_u128_varint_size = max_size(u128);

comptime {
    assert(max_u16_varint_size == 3);
    assert(max_u32_varint_size == 5);
    assert(max_u64_varint_size == 10);
    assert(max_u128_varint_size == 19);
}

/// Width of `T` in bytes, the payload commonware reports in `InvalidVarint`.
fn width_bytes(comptime T: type) u64 {
    return std.math.divCeil(u64, @bitSizeOf(T), 8) catch unreachable; // Proof: divisor is 8.
}

fn assert_unsigned(comptime T: type) void {
    const info = @typeInfo(T);
    if (info != .int or info.int.signedness != .unsigned) {
        @compileError("varint: expected an unsigned integer, found " ++ @typeName(T));
    }
}

/// An incremental varint decoder for reading varints byte by byte from streams.
pub fn Decoder(comptime T: type) type {
    comptime assert_unsigned(T);
    return struct {
        const Self = @This();

        result: T = 0,
        bits_read: u32 = 0,

        pub fn init() Self {
            return .{};
        }

        /// Feeds one byte. Returns the value when complete, null when more bytes are needed,
        /// or `InvalidVarint` when the encoding is non-canonical or overflows `T`.
        pub fn feed(self: *Self, byte: u8) Error!?T {
            const max_bits: u32 = @bitSizeOf(T);
            assert(self.bits_read <= max_bits);

            // A later byte with no data bits and no continuation is never needed, so it would
            // give a second encoding of the same value.
            if (byte == 0 and self.bits_read > 0) return error.InvalidVarint;

            // When this must be the last byte, bits beyond the width (including the
            // continuation bit) are an overflow.
            const remaining_bits = max_bits - self.bits_read;
            if (remaining_bits <= data_bits_per_byte) {
                const relevant_bits: u32 = 8 - @as(u32, @clz(byte));
                if (relevant_bits > remaining_bits) return error.InvalidVarint;
            }

            const data = byte & data_bits_mask;
            if (@bitSizeOf(T) > 0) {
                // The checks above prove `data` fits in the bits that remain.
                const Shift = std.math.Log2Int(T);
                self.result |= std.math.shl(T, @as(T, @intCast(data)), @as(Shift, @intCast(
                    self.bits_read,
                )));
            } else {
                assert(data == 0);
            }

            if (byte & continuation_bit_mask == 0) return self.result;
            self.bits_read += data_bits_per_byte;
            assert(self.bits_read < max_bits);
            return null;
        }
    };
}

/// Writes `value` as a varint.
pub fn write(comptime T: type, value: T, writer: *Writer) void {
    comptime assert_unsigned(T);
    // Widen narrow types so the byte extraction below always truncates.
    const Wide = if (@bitSizeOf(T) < 8) u8 else T;
    var bytes: [max_size(T)]u8 = undefined;
    var len: usize = 0;
    var remaining: Wide = value;
    while (remaining >= continuation_bit_mask) {
        assert(len < bytes.len - 1);
        bytes[len] = @as(u8, @truncate(remaining)) | continuation_bit_mask;
        len += 1;
        remaining = std.math.shr(Wide, remaining, data_bits_per_byte);
    }
    bytes[len] = @intCast(remaining);
    len += 1;
    assert(len == size(T, value));
    writer.write_bytes(bytes[0..len]);
}

/// Reads a varint of type `T`.
pub fn read(comptime T: type, reader: *Reader) Error!T {
    comptime assert_unsigned(T);
    var byte = try reader.read_byte();
    // Fast path: one byte without continuation, for widths that hold every 7-bit value.
    if (byte & continuation_bit_mask == 0 and @bitSizeOf(T) >= data_bits_per_byte) {
        return @intCast(byte);
    }
    var decoder: Decoder(T) = .{};
    var index: usize = 0;
    while (index < max_size(T)) : (index += 1) {
        const value = decoder.feed(byte) catch |err| return reader.fail(err, width_bytes(T));
        if (value) |complete| return complete;
        byte = try reader.read_byte();
    }
    unreachable; // Proof: `feed` refuses a continuation once the width is exhausted.
}

/// Number of bytes needed to encode `value` as a varint.
pub fn size(comptime T: type, value: T) usize {
    comptime assert_unsigned(T);
    const data_bits: usize = @bitSizeOf(T) - @as(usize, @clz(value));
    const result = @max(1, std.math.divCeil(usize, data_bits, data_bits_per_byte) catch
        unreachable); // Proof: divisor is the non-zero constant 7.
    assert(result <= max_size(T));
    return result;
}

/// The unsigned integer of the same width as signed `S`.
pub fn Unsigned(comptime S: type) type {
    const info = @typeInfo(S);
    if (info != .int or info.int.signedness != .signed) {
        @compileError("varint: expected a signed integer, found " ++ @typeName(S));
    }
    return @Int(.unsigned, info.int.bits);
}

/// ZigZag-encodes `value`: the sign moves to the least significant bit.
pub fn zigzag(comptime S: type, value: S) Unsigned(S) {
    const U = Unsigned(S);
    const shifted: U = @as(U, @bitCast(value)) << 1;
    const sign: U = @bitCast(value >> (@bitSizeOf(S) - 1));
    return shifted ^ sign;
}

/// Inverts `zigzag`.
pub fn unzigzag(comptime S: type, value: Unsigned(S)) S {
    const U = Unsigned(S);
    const magnitude: U = value >> 1;
    const sign: U = 0 -% (value & 1);
    return @bitCast(magnitude ^ sign);
}

pub fn write_signed(comptime S: type, value: S, writer: *Writer) void {
    write(Unsigned(S), zigzag(S, value), writer);
}

pub fn read_signed(comptime S: type, reader: *Reader) Error!S {
    return unzigzag(S, try read(Unsigned(S), reader));
}

pub fn size_signed(comptime S: type, value: S) usize {
    return size(Unsigned(S), zigzag(S, value));
}

/// Wrapper encoding an unsigned integer as a varint instead of fixed width.
pub fn UInt(comptime T: type) type {
    comptime assert_unsigned(T);
    return struct {
        const Self = @This();
        pub const max_encode_size = max_size(T);

        value: T,

        pub fn write(self: Self, writer: *Writer) void {
            write_unsigned(T, self.value, writer);
        }

        pub fn encode_size(self: Self) usize {
            return size(T, self.value);
        }

        pub fn read(_: Allocator, reader: *Reader, _: void) Error!Self {
            return .{ .value = try read_unsigned(T, reader) };
        }
    };
}

/// Wrapper encoding a signed integer as a ZigZag varint instead of fixed width.
pub fn SInt(comptime S: type) type {
    _ = Unsigned(S);
    return struct {
        const Self = @This();
        pub const max_encode_size = max_size(Unsigned(S));

        value: S,

        pub fn write(self: Self, writer: *Writer) void {
            write_signed(S, self.value, writer);
        }

        pub fn encode_size(self: Self) usize {
            return size_signed(S, self.value);
        }

        pub fn read(_: Allocator, reader: *Reader, _: void) Error!Self {
            return .{ .value = try read_signed(S, reader) };
        }
    };
}

// Aliases so the wrapper methods named `write`/`read` can reach the free functions.
const write_unsigned = write;
const read_unsigned = read;

const testing = std.testing;
const codec = @import("codec.zig");

fn expect_uint_roundtrip(comptime T: type, value: T) !void {
    var out: [max_size(T)]u8 = undefined;
    var writer = Writer.init(&out);
    write(T, value, &writer);
    try testing.expectEqual(size(T, value), writer.end);
    var reader = Reader.init(writer.written());
    try testing.expectEqual(value, try read(T, &reader));
    try testing.expectEqual(@as(usize, 0), reader.remaining());

    const encoded = try codec.encode(UInt(T), testing.allocator, .{ .value = value });
    defer testing.allocator.free(encoded);
    try testing.expectEqual(value, (try codec.decode(UInt(T), testing.allocator, encoded)).value);
}

test "varuint roundtrip" {
    const cases = [_]u128{
        0,                    1,                                       127,
        128,                  129,                                     0xff,
        0x100,                0x3fff,                                  0x4000,
        0x1_ffff,             0xff_ffff,                               0x1_ff_ff_ff_ff,
        0xff_ff_ff_ff_ff_ff,  0x1_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff, std.math.maxInt(u16),
        std.math.maxInt(u32), std.math.maxInt(u64),                    std.math.maxInt(u128),
    };
    inline for (.{ u16, u32, u64, u128 }) |T| {
        for (cases) |raw| {
            const value = std.math.cast(T, raw) orelse continue;
            try expect_uint_roundtrip(T, value);
        }
    }
}

test "varsint roundtrip" {
    const cases = [_]i128{
        0,                    1,                     -1,                     2,
        -2,                   127,                   -127,                   128,
        -128,                 129,                   -129,                   0x7fffffff,
        -0x7fffffff,          std.math.maxInt(i128), -std.math.maxInt(i128), std.math.minInt(i16),
        std.math.maxInt(i16), std.math.minInt(i32),  std.math.maxInt(i32),   std.math.minInt(i64),
        std.math.maxInt(i64),
    };
    inline for (.{ i16, i32, i64, i128 }) |S| {
        for (cases) |raw| {
            const value = std.math.cast(S, raw) orelse continue;
            var out: [max_size(Unsigned(S))]u8 = undefined;
            var writer = Writer.init(&out);
            write_signed(S, value, &writer);
            try testing.expectEqual(size_signed(S, value), writer.end);
            var reader = Reader.init(writer.written());
            try testing.expectEqual(value, try read_signed(S, &reader));
            try testing.expectEqual(@as(usize, 0), reader.remaining());
        }
    }
}

test "varint end of buffer" {
    inline for (.{ &[_]u8{}, &[_]u8{ 0x80, 0x8f }, &[_]u8{ 0xff, 0x8f } }) |bytes| {
        var reader = Reader.init(bytes);
        try testing.expectError(error.EndOfBuffer, read(u32, &reader));
    }
}

test "varint overflow" {
    var max = Reader.init(&.{ 0xff, 0xff, 0xff, 0xff, 0x0f });
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), try read(u32, &max));

    var over = Reader.init(&.{ 0xff, 0xff, 0xff, 0xff, 0x1f });
    try testing.expectError(error.InvalidVarint, read(u32, &over));
    try testing.expectEqual(@as(u64, 4), over.diagnostic.value);

    var over64 = Reader.init(&.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02 });
    try testing.expectError(error.InvalidVarint, read(u64, &over64));
    try testing.expectEqual(@as(u64, 8), over64.diagnostic.value);
}

test "varint overcontinuation and zeroed byte" {
    var over = Reader.init(&.{ 0x80, 0x80, 0x80, 0x80, 0x80 });
    try testing.expectError(error.InvalidVarint, read(u32, &over));
    var zeroed = Reader.init(&.{ 0xff, 0x00 });
    try testing.expectError(error.InvalidVarint, read(u64, &zeroed));
    try testing.expectEqual(@as(u64, 8), zeroed.diagnostic.value);
}

test "varint conformity" {
    const cases = [_]struct { value: u32, bytes: []const u8 }{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 1, .bytes = &.{0x01} },
        .{ .value = 127, .bytes = &.{0x7f} },
        .{ .value = 128, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = 16383, .bytes = &.{ 0xff, 0x7f } },
        .{ .value = 16384, .bytes = &.{ 0x80, 0x80, 0x01 } },
        .{ .value = 2097151, .bytes = &.{ 0xff, 0xff, 0x7f } },
        .{ .value = 2097152, .bytes = &.{ 0x80, 0x80, 0x80, 0x01 } },
        .{ .value = std.math.maxInt(u32), .bytes = &.{ 0xff, 0xff, 0xff, 0xff, 0x0f } },
    };
    for (cases) |case| {
        var out: [5]u8 = undefined;
        var writer = Writer.init(&out);
        write(u32, case.value, &writer);
        try testing.expectEqualSlices(u8, case.bytes, writer.written());
    }
}

test "varint all u16 and i16 values" {
    var value: u32 = 0;
    while (value <= std.math.maxInt(u16)) : (value += 1) {
        const unsigned: u16 = @intCast(value);
        var out: [max_u16_varint_size]u8 = undefined;
        var writer = Writer.init(&out);
        write(u16, unsigned, &writer);
        try testing.expectEqual(size(u16, unsigned), writer.end);
        try testing.expectEqual(writer.end, (UInt(u16){ .value = unsigned }).encode_size());

        const signed: i16 = @bitCast(unsigned);
        var signed_writer = Writer.init(&out);
        write_signed(i16, signed, &signed_writer);
        try testing.expectEqual(size_signed(i16, signed), signed_writer.end);
        try testing.expectEqual(signed_writer.end, (SInt(i16){ .value = signed }).encode_size());
        var reader = Reader.init(signed_writer.written());
        try testing.expectEqual(signed, try read_signed(i16, &reader));
        try testing.expectEqual(@as(usize, 0), reader.remaining());
    }
}

fn expect_size_and_length(comptime T: type, value: T, expected: usize) !void {
    try testing.expectEqual(expected, size(T, value));
    var out: [max_size(T)]u8 = undefined;
    var writer = Writer.init(&out);
    write(T, value, &writer);
    try testing.expectEqual(expected, writer.end);
}

test "varint exact and single bit boundaries" {
    inline for (.{ u16, u32, u64, u128 }) |T| {
        var bits: u32 = 1;
        while (bits <= @bitSizeOf(T)) : (bits += 1) {
            const all_ones: T = @as(T, std.math.maxInt(T)) >> @intCast(@bitSizeOf(T) - bits);
            const expected = std.math.divCeil(u32, bits, 7) catch unreachable;
            try expect_size_and_length(T, all_ones, expected);
            const single: T = std.math.shl(T, 1, bits - 1);
            try expect_size_and_length(T, single, expected);
        }
    }
}

test "varint max size constants" {
    inline for (.{ u16, u32, u64, u128 }) |T| {
        try expect_size_and_length(T, std.math.maxInt(T), max_size(T));
        try testing.expectEqual(max_size(T), UInt(T).max_encode_size);
    }
}

fn decode_uint(comptime T: type, bytes: []const u8) Error!T {
    return (try codec.decode(UInt(T), testing.allocator, bytes)).value;
}

fn encode_uint(comptime T: type, value: T, out: []u8) []u8 {
    return codec.encode_to(UInt(T), .{ .value = value }, out);
}

fn expect_invalid_varint(comptime T: type, bytes: []const u8, width: u64) !void {
    var reader = Reader.init(bytes);
    const result = codec.decode_reader(UInt(T), testing.allocator, &reader, {});
    try testing.expectError(error.InvalidVarint, result);
    try testing.expectEqual(width, reader.diagnostic.value);
}

test "varint u256 round trips at any width" {
    var out: [max_size(u256)]u8 = undefined;
    var narrow_out: [max_size(u64)]u8 = undefined;
    const values = [_]u64{ 0, 1, 127, 128, 300, 0x3fff, 0x4000, std.math.maxInt(u64) };
    for (values) |value| {
        const wide = encode_uint(u256, value, &out);
        try testing.expectEqualSlices(u8, encode_uint(u64, value, &narrow_out), wide);
        try testing.expectEqual(@as(u256, value), try decode_uint(u256, wide));
    }
    const filling: u256 = @as(u256, 1 << 11) << 128;
    const beyond: u256 = (@as(u256, 1 << 63) << 192) | (@as(u256, 1) << 64) | std.math.maxInt(u64);
    for ([_]u256{ filling, beyond, std.math.maxInt(u256) }) |value| {
        const encoded = encode_uint(u256, value, &out);
        try testing.expectEqual(size(u256, value), encoded.len);
        try testing.expectEqual(value, try decode_uint(u256, encoded));
    }
    try testing.expectEqual(@as(usize, 37), size(u256, std.math.maxInt(u256)));
    try testing.expectEqual(@as(usize, 37), UInt(u256).max_encode_size);

    // A bit beyond the width, a trailing zero byte, and a truncated encoding are refused.
    const max_encoded = encode_uint(u256, std.math.maxInt(u256), &out);
    max_encoded[max_encoded.len - 1] |= 0x10;
    try expect_invalid_varint(u256, max_encoded, 32);
    try expect_invalid_varint(u256, &.{ 0xff, 0x00 }, 32);
    const all_ff: [36]u8 = @splat(0xff);
    try testing.expectError(error.EndOfBuffer, decode_uint(u256, &all_ff));
}

test "varint partial widths" {
    var out: [8]u8 = undefined;
    // Eight bits spill their top bit into a second byte that holds nothing more.
    try testing.expectEqualSlices(u8, &.{ 0xff, 0x01 }, encode_uint(u8, 0xff, &out));
    try testing.expectEqual(@as(u8, 0xff), try decode_uint(u8, &.{ 0xff, 0x01 }));
    try expect_invalid_varint(u8, &.{ 0xff, 0x02 }, 1);

    // Thirty-six bits leave one bit for a sixth byte.
    try testing.expectEqual(@as(usize, 6), UInt(u36).max_encode_size);
    const max36 = encode_uint(u36, std.math.maxInt(u36), &out);
    try testing.expectEqual(@as(usize, 6), max36.len);
    try testing.expectEqual(@as(u36, std.math.maxInt(u36)), try decode_uint(u36, max36));
    try expect_invalid_varint(u36, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f }, 5);

    // A multiple of seven bits fills its last byte; a continuation there is refused before
    // another byte is read.
    const max14 = encode_uint(u14, std.math.maxInt(u14), &out);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0x7f }, max14);
    try testing.expectEqual(@as(u14, std.math.maxInt(u14)), try decode_uint(u14, &.{ 0xff, 0x7f }));
    var reader = Reader.init(&.{ 0xff, 0xff, 0x01 });
    try testing.expectError(error.InvalidVarint, codec.read(UInt(u14), testing.allocator, &reader));
    try testing.expectEqual(@as(u64, 2), reader.diagnostic.value);
    try testing.expectEqual(@as(usize, 1), reader.remaining());
}

test "varint narrow widths" {
    var out: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), UInt(u4).max_encode_size);
    try testing.expectEqualSlices(u8, &.{0x0f}, encode_uint(u4, 0xf, &out));
    try testing.expectEqual(@as(u4, 0xf), try decode_uint(u4, &.{0x0f}));
    try expect_invalid_varint(u4, &.{0x10}, 1);
    try expect_invalid_varint(u4, &.{ 0x8f, 0x01 }, 1);

    try testing.expectEqual(@as(usize, 1), UInt(u7).max_encode_size);
    try testing.expectEqualSlices(u8, &.{0x7f}, encode_uint(u7, 0x7f, &out));
    try testing.expectEqual(@as(u7, 0x7f), try decode_uint(u7, &.{0x7f}));
    try expect_invalid_varint(u7, &.{ 0xff, 0x01 }, 1);

    // Zero bits hold only zero, which still takes a byte.
    try testing.expectEqual(@as(usize, 1), UInt(u0).max_encode_size);
    try testing.expectEqual(@as(usize, 1), size(u0, 0));
    try testing.expectEqualSlices(u8, &.{0x00}, encode_uint(u0, 0, &out));
    try testing.expectEqual(@as(u0, 0), try decode_uint(u0, &.{0x00}));
    try expect_invalid_varint(u0, &.{0x01}, 0);

    // The byte-at-a-time decoder applies the same bound.
    var decoder = Decoder(u4).init();
    try testing.expectEqual(@as(?u4, 0xf), try decoder.feed(0x0f));
    var refused = Decoder(u4).init();
    try testing.expectError(error.InvalidVarint, refused.feed(0x10));
}

test "varint fragmented decoder" {
    var decoder = Decoder(u32).init();
    try testing.expectEqual(@as(?u32, null), try decoder.feed(0xac));
    try testing.expectEqual(@as(?u32, 300), try decoder.feed(0x02));
}
