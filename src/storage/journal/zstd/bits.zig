//! Bit writer for zstd's two bitstream kinds (RFC 8878 §4.1).
//!
//! Bits accumulate little-endian, least significant first. FSE table descriptions are read
//! forward, so they end at the next byte boundary (`finish_aligned`). FSE and Huffman payload
//! streams are read backward from their last byte, so they end with a 1 marker bit before the
//! padding (`finish_marked`): a value added with `add(value, n)` reads back as the same
//! `n`-bit number, and the value added last reads back first.
//!
//! The writer never writes past its buffer: once the output does not fit it sets `overflow`
//! and drops the rest, so callers size the buffer by their budget and fall back on overflow.

const std = @import("std");
const assert = std.debug.assert;

pub const Writer = struct {
    out: []u8,
    len: usize = 0,
    container: u64 = 0,
    /// Pending bits in `container`, always below 8 between calls.
    count: u6 = 0,
    overflow: bool = false,

    pub fn init(out: []u8) Writer {
        return .{ .out = out };
    }

    /// Appends the low `bits` bits of `value`, which must have no higher bits set.
    pub fn add(self: *Writer, value: u64, bits: u6) void {
        assert(bits <= 56);
        assert(value >> bits == 0);
        assert(self.count < 8);
        self.container |= value << self.count;
        self.count += bits;
        self.flush_bytes();
    }

    fn flush_bytes(self: *Writer) void {
        assert(self.count <= 63);
        while (self.count >= 8) {
            self.put(@truncate(self.container));
            self.container >>= 8;
            self.count -= 8;
        }
        assert(self.count < 8);
    }

    fn put(self: *Writer, byte: u8) void {
        if (self.len < self.out.len) {
            self.out[self.len] = byte;
            self.len += 1;
        } else {
            self.overflow = true;
        }
        assert(self.len <= self.out.len);
    }

    /// Pads to a byte boundary with zeros and returns the bytes written, or null on overflow.
    pub fn finish_aligned(self: *Writer) ?[]u8 {
        assert(self.count < 8);
        if (self.count > 0) {
            self.put(@truncate(self.container));
            self.container = 0;
            self.count = 0;
        }
        assert(self.count == 0);
        return if (self.overflow) null else self.out[0..self.len];
    }

    /// Appends the 1 marker bit of a backward stream, pads, and returns the bytes written, or
    /// null on overflow.
    pub fn finish_marked(self: *Writer) ?[]u8 {
        self.add(1, 1);
        const bytes = self.finish_aligned() orelse return null;
        assert(bytes.len > 0 and bytes[bytes.len - 1] != 0);
        return bytes;
    }
};

const testing = std.testing;

test "bits accumulate least significant first and overflow is sticky" {
    var buffer: [3]u8 = undefined;
    var writer: Writer = .init(&buffer);
    writer.add(0b101, 3);
    writer.add(0b11111, 5);
    writer.add(0xABC, 12);
    const bytes = writer.finish_marked().?;
    try testing.expectEqualSlices(u8, &.{ 0b1111_1101, 0xBC, 0b0001_1010 }, bytes);

    var small: [1]u8 = undefined;
    var full: Writer = .init(&small);
    full.add(0xFFFF, 16);
    try testing.expect(full.overflow);
    try testing.expectEqual(@as(?[]u8, null), full.finish_aligned());
}
