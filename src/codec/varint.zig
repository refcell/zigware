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
