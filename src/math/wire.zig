//! Minimal codec primitives for math's variable-size encodings, byte-identical to
//! commonware-codec: lengths are canonical LEB128 varints of a u32, items follow in order.
//!
//! This stands in for the `codec` package until its core API lands; the error names match
//! codec's error set so callers can switch without changing their handling.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{ EndOfBuffer, InvalidVarint, InvalidLength, Invalid, ExtraData };

pub const varint_u32_size_max = 5;

/// Encoded size of `value` as a varint.
pub fn varint_size(value: u32) usize {
    const data_bits: usize = 32 - @clz(value);
    const size = @max(1, std.math.divCeil(usize, data_bits, 7) catch unreachable); // 7 != 0.
    assert(size <= varint_u32_size_max);
    return size;
}

/// Bounded output cursor; writing past the end is a caller bug (sizes are computed first).
pub const Writer = struct {
    buffer: []u8,
    position: usize = 0,

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    pub fn put(w: *Writer, bytes: []const u8) void {
        assert(w.position + bytes.len <= w.buffer.len);
        @memcpy(w.buffer[w.position..][0..bytes.len], bytes);
        w.position += bytes.len;
    }

    pub fn put_varint(w: *Writer, value: u32) void {
        var remaining = value;
        const start = w.position;
        while (remaining >= 0x80) : (remaining >>= 7) {
            w.put(&.{@as(u8, @truncate(remaining)) | 0x80});
        }
        w.put(&.{@as(u8, @truncate(remaining))});
        assert(w.position - start == varint_size(value));
    }

    pub fn written(w: *const Writer) []const u8 {
        return w.buffer[0..w.position];
    }
};

/// Input cursor over a byte slice.
pub const Reader = struct {
    data: []const u8,
    position: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn remaining(r: *const Reader) usize {
        assert(r.position <= r.data.len);
        return r.data.len - r.position;
    }

    pub fn take(r: *Reader, count: usize) Error![]const u8 {
        if (r.remaining() < count) return error.EndOfBuffer;
        const out = r.data[r.position..][0..count];
        r.position += count;
        return out;
    }

    pub fn take_array(r: *Reader, comptime count: usize) Error!*const [count]u8 {
        const bytes = try r.take(count);
        return bytes[0..count];
    }

    /// Canonical varint: no zero continuation bytes, no bits beyond 32.
    pub fn read_varint(r: *Reader) Error!u32 {
        var result: u32 = 0;
        var bits_read: u32 = 0;
        while (true) {
            const byte = (try r.take(1))[0];
            if (byte == 0 and bits_read > 0) return error.InvalidVarint;
            const remaining_bits = 32 - bits_read;
            if (remaining_bits <= 7 and 8 - @as(u32, @clz(byte)) > remaining_bits) {
                return error.InvalidVarint;
            }
            result |= @as(u32, byte & 0x7f) << @intCast(bits_read);
            if (byte & 0x80 == 0) return result;
            bits_read += 7;
            assert(bits_read < 32);
        }
    }

    /// A length in `[min, max]` (commonware `RangeCfg`).
    pub fn read_length(r: *Reader, min: u32, max: u32) Error!u32 {
        assert(min <= max);
        const value = try r.read_varint();
        if (value < min or value > max) return error.InvalidLength;
        return value;
    }

    pub fn finish(r: *const Reader) Error!void {
        if (r.remaining() != 0) return error.ExtraData;
    }
};

const testing = std.testing;

test "varint round trip and canonical rejection" {
    const cases = [_]u32{ 0, 1, 127, 128, 300, 16383, 16384, std.math.maxInt(u32) };
    for (cases) |value| {
        var buffer: [varint_u32_size_max]u8 = undefined;
        var w = Writer.init(&buffer);
        w.put_varint(value);
        var r = Reader.init(w.written());
        try testing.expectEqual(value, try r.read_varint());
        try r.finish();
    }
    var r = Reader.init(&.{ 0x80, 0x00 });
    try testing.expectError(error.InvalidVarint, r.read_varint());
    r = Reader.init(&.{ 0xff, 0xff, 0xff, 0xff, 0x1f });
    try testing.expectError(error.InvalidVarint, r.read_varint());
    r = Reader.init(&.{0x80});
    try testing.expectError(error.EndOfBuffer, r.read_varint());
    r = Reader.init(&.{ 0x80, 0x01, 0x07 });
    try testing.expectEqual(@as(u32, 128), try r.read_varint());
    try testing.expectEqual(@as(u32, 7), try r.read_varint());
}
