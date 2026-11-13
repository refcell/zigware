//! Input and output buffers for codec reads and writes (codec/src/buf.rs).
//!
//! commonware reads from `bytes::Buf` (possibly non-contiguous chains) and writes to
//! `bytes::BufMut`. zigware reads from one contiguous slice through `Reader` and writes into
//! one caller-provided slice through `Writer`. Decoded byte fields can borrow the input
//! (`codec.Bytes`, like commonware's `Viewing`) or copy it (`[]const u8`, like `Vec<u8>`).

const std = @import("std");
const assert = std.debug.assert;
const error_mod = @import("error.zig");
const Error = error_mod.Error;
const Diagnostic = error_mod.Diagnostic;

/// A cursor over a contiguous input slice. Every read is bounds-checked and fails with
/// `error.EndOfBuffer` instead of panicking, leaving the cursor unchanged on failure.
pub const Reader = struct {
    buffer: []const u8,
    position: usize = 0,
    /// Payload of the most recent error, see `Diagnostic`.
    diagnostic: Diagnostic = .{},

    pub fn init(buffer: []const u8) Reader {
        return .{ .buffer = buffer };
    }

    /// Bytes not yet consumed.
    pub fn remaining(self: *const Reader) usize {
        assert(self.position <= self.buffer.len);
        return self.buffer.len - self.position;
    }

    /// The unconsumed input.
    pub fn rest(self: *const Reader) []const u8 {
        assert(self.position <= self.buffer.len);
        return self.buffer[self.position..];
    }

    /// Fails with `EndOfBuffer` unless at least `len` bytes remain.
    pub fn at_least(self: *const Reader, len: usize) Error!void {
        if (self.remaining() < len) return error.EndOfBuffer;
    }

    /// Fails with `EndOfBuffer` unless at least `len * item_size` bytes remain, treating
    /// multiplication overflow as insufficient.
    pub fn at_least_items(self: *const Reader, len: usize, item_size: usize) Error!void {
        const total = std.math.mul(usize, len, item_size) catch return error.EndOfBuffer;
        return self.at_least(total);
    }

    /// Consumes and returns the next `len` bytes as a view into the input.
    pub fn take(self: *Reader, len: usize) Error![]const u8 {
        try self.at_least(len);
        const start = self.position;
        self.position += len;
        assert(self.position <= self.buffer.len);
        return self.buffer[start..self.position];
    }

    /// Consumes the next `len` bytes as a fixed-size array view.
    pub fn take_array(self: *Reader, comptime len: usize) Error!*const [len]u8 {
        const bytes = try self.take(len);
        return bytes[0..len];
    }

    /// Advances past `len` bytes.
    pub fn skip(self: *Reader, len: usize) Error!void {
        _ = try self.take(len);
    }

    /// Consumes one byte.
    pub fn read_byte(self: *Reader) Error!u8 {
        if (self.position >= self.buffer.len) return error.EndOfBuffer;
        const byte = self.buffer[self.position];
        self.position += 1;
        return byte;
    }

    /// Consumes a big-endian integer of type `T` (whose width is a whole number of bytes).
    pub fn read_int(self: *Reader, comptime T: type) Error!T {
        comptime assert(@bitSizeOf(T) % 8 == 0);
        const bytes = try self.take_array(@bitSizeOf(T) / 8);
        return std.mem.readInt(T, bytes, .big);
    }

    /// Records `context` and `message` and returns `error.Invalid`.
    pub fn invalid(self: *Reader, context: []const u8, message: []const u8) Error {
        self.diagnostic = .{ .context = context, .message = message };
        return error.Invalid;
    }

    /// Records `context` and returns `error.Wrapped`.
    pub fn wrapped(self: *Reader, context: []const u8) Error {
        self.diagnostic = .{ .context = context };
        return error.Wrapped;
    }

    /// Records the payload `value` and returns `err` (for `InvalidLength`, `InvalidEnum`,
    /// `InvalidVarint`, and `ExtraData`).
    pub fn fail(self: *Reader, err: Error, value: u64) Error {
        self.diagnostic = .{ .value = value };
        return err;
    }
};

/// A cursor over a caller-provided output slice. Writes are infallible: like commonware,
/// running out of capacity is a programming error (callers size the buffer with
/// `encode_size`), so it is asserted rather than returned.
pub const Writer = struct {
    buffer: []u8,
    end: usize = 0,

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    /// The bytes written so far.
    pub fn written(self: *const Writer) []u8 {
        assert(self.end <= self.buffer.len);
        return self.buffer[0..self.end];
    }

    /// Bytes that can still be written.
    pub fn unused_capacity(self: *const Writer) usize {
        assert(self.end <= self.buffer.len);
        return self.buffer.len - self.end;
    }

    pub fn write_bytes(self: *Writer, bytes: []const u8) void {
        assert(self.unused_capacity() >= bytes.len);
        @memcpy(self.buffer[self.end..][0..bytes.len], bytes);
        self.end += bytes.len;
    }

    pub fn write_byte(self: *Writer, byte: u8) void {
        assert(self.unused_capacity() >= 1);
        self.buffer[self.end] = byte;
        self.end += 1;
    }

    /// Writes `count` copies of `byte`.
    pub fn write_byte_n(self: *Writer, byte: u8, count: usize) void {
        assert(self.unused_capacity() >= count);
        @memset(self.buffer[self.end..][0..count], byte);
        self.end += count;
    }

    /// Writes a big-endian integer of type `T` (whose width is a whole number of bytes).
    pub fn write_int(self: *Writer, comptime T: type, value: T) void {
        comptime assert(@bitSizeOf(T) % 8 == 0);
        const size = @bitSizeOf(T) / 8;
        assert(self.unused_capacity() >= size);
        std.mem.writeInt(T, self.buffer[self.end..][0..size], value, .big);
        self.end += size;
    }
};

const testing = std.testing;

test "reader reads and bounds" {
    var reader = Reader.init(&.{ 0x01, 0x02, 0x03, 0x04, 0x05 });
    try testing.expectEqual(@as(u16, 0x0102), try reader.read_int(u16));
    try testing.expectEqual(@as(usize, 3), reader.remaining());
    try testing.expectError(error.EndOfBuffer, reader.read_int(u32));
    try testing.expectEqual(@as(usize, 3), reader.remaining());
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x04 }, try reader.take(2));
    try testing.expectEqual(@as(u8, 0x05), try reader.read_byte());
    try testing.expectError(error.EndOfBuffer, reader.read_byte());
    try testing.expectEqual(@as(usize, 0), reader.remaining());
}

test "reader at_least_items overflow is end of buffer" {
    const reader = Reader.init(&@as([8]u8, @splat(0)));
    try testing.expectError(error.EndOfBuffer, reader.at_least_items(2, 8));
    try testing.expectError(
        error.EndOfBuffer,
        reader.at_least_items(std.math.maxInt(usize), 8),
    );
    try reader.at_least_items(1, 8);
}

test "writer writes big-endian" {
    var buffer: [7]u8 = undefined;
    var writer = Writer.init(&buffer);
    writer.write_int(u32, 0x01020304);
    writer.write_byte(0x05);
    writer.write_bytes(&.{0x06});
    writer.write_byte_n(0x07, 1);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7 }, writer.written());
    try testing.expectEqual(@as(usize, 0), writer.unused_capacity());
}
