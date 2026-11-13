//! Compact encoding for ordered, extensible mode values (codec/src/mode.rs).
//!
//! A mode value is seven bits (`u7`, commonware's `Mode`). `Modes(N)` packs up to `N` of them:
//! each byte carries one mode, the high bit says another follows, and trailing zero modes
//! are omitted, so appending a new zero-valued mode keeps existing encodings. An all-zero
//! list is no packet at all (`init` returns null).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const buf = @import("buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("error.zig").Error;

/// The high bit is packet framing, not mode data.
const continuation_bit: u8 = 1 << 7;

/// A seven-bit mode value, or null when the reserved high bit is set (`Mode::new`).
pub fn mode(value: u8) ?u7 {
    return std.math.cast(u7, value);
}

/// A canonical packet of up to `N` ordered mode values.
pub fn Modes(comptime N: usize) type {
    comptime assert(N > 0);
    return struct {
        const Self = @This();

        encoded: [N]u8,
        len: usize,

        pub const max_encode_size = N;

        /// Builds the canonical packet, or null when every mode is zero.
        pub fn init(modes: [N]u7) ?Self {
            var encoded: [N]u8 = undefined;
            var len: usize = 0;
            for (modes, 0..) |value, index| {
                encoded[index] = value;
                if (value != 0) len = index + 1;
            }
            if (len == 0) return null;
            for (encoded[0 .. len - 1]) |*byte| byte.* |= continuation_bit;
            assert(encoded[len - 1] & continuation_bit == 0 and encoded[len - 1] != 0);
            return .{ .encoded = encoded, .len = len };
        }

        /// The mode at `index` (zero beyond the encoded packet).
        pub fn get(self: Self, index: usize) u7 {
            assert(index < N);
            if (index >= self.len) return 0;
            return @truncate(self.encoded[index]);
        }

        pub fn write(self: Self, writer: *Writer) void {
            assert(self.len > 0 and self.len <= N);
            writer.write_bytes(self.encoded[0..self.len]);
        }

        pub fn encode_size(self: Self) usize {
            assert(self.len > 0 and self.len <= N);
            return self.len;
        }

        pub fn read(_: Allocator, reader: *Reader, _: void) Error!Self {
            var encoded: [N]u8 = @splat(0);
            for (0..N) |index| {
                const byte = try reader.read_byte();
                encoded[index] = byte;
                if (byte & continuation_bit == 0) {
                    if (byte == 0) return reader.invalid("Modes", "trailing mode must be non-zero");
                    return .{ .encoded = encoded, .len = index + 1 };
                }
            }
            return reader.invalid("Modes", "too many mode values");
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.len == b.len and std.mem.eql(u8, a.encoded[0..a.len], b.encoded[0..b.len]);
        }
    };
}

const testing = std.testing;
const codec = @import("codec.zig");
const gpa = testing.allocator;

fn expect_encoding(comptime N: usize, modes: [N]u7, expected: []const u8) !void {
    const packet = Modes(N).init(modes).?;
    try testing.expectEqual(expected.len, codec.encode_size(Modes(N), packet));
    const encoded = try codec.encode(Modes(N), gpa, packet);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, expected, encoded);
    const decoded = try codec.decode(Modes(N), gpa, encoded);
    try testing.expect(decoded.eql(packet));
    for (modes, 0..) |value, index| try testing.expectEqual(value, decoded.get(index));
}

test "modes encode continuations" {
    try testing.expect(Modes(2).init(.{ 0, 0 }) == null);
    try expect_encoding(2, .{ 1, 0 }, &.{0x01});
    try expect_encoding(2, .{ 0, 1 }, &.{ 0x80, 0x01 });
    try expect_encoding(3, .{ 1, 0, 1 }, &.{ 0x81, 0x80, 0x01 });
    try expect_encoding(2, .{ 0x7f, 0x7f }, &.{ 0xff, 0x7f });
    try expect_encoding(2, .{ 1, 1 }, &.{ 0x81, 0x01 });
}

test "mode enforces seven bit values" {
    try testing.expectEqual(@as(?u7, 0), mode(0));
    try testing.expectEqual(@as(?u7, 0x7f), mode(0x7f));
    try testing.expectEqual(@as(?u7, null), mode(0x80));
    try testing.expectEqual(@as(?u7, null), mode(0xff));
}

fn expect_decode_error(comptime N: usize, bytes: []const u8, expected: anyerror) !void {
    var reader = Reader.init(bytes);
    try testing.expectError(expected, codec.decode_reader(Modes(N), gpa, &reader, {}));
    if (expected == error.Invalid) {
        try testing.expectEqualStrings("Modes", reader.diagnostic.context);
    }
}

test "modes reject truncated and oversized packets" {
    try expect_decode_error(2, &.{}, error.EndOfBuffer);
    try expect_decode_error(2, &.{0x80}, error.EndOfBuffer);
    try expect_decode_error(1, &.{0x80}, error.Invalid);
    try expect_decode_error(2, &.{ 0x80, 0x80 }, error.Invalid);
    try expect_decode_error(2, &.{ 0x80, 0x80, 0x01 }, error.Invalid);
}

test "modes reject non-canonical packets" {
    try expect_decode_error(1, &.{0x00}, error.Invalid);
    try expect_decode_error(2, &.{ 0x80, 0x00 }, error.Invalid);
    try expect_decode_error(2, &.{ 0x81, 0x00 }, error.Invalid);
}

test "modes read stops at packet boundary" {
    var reader = Reader.init(&.{ 0x01, 0x02 });
    const packet = try codec.read(Modes(2), gpa, &reader);
    try testing.expectEqual(@as(usize, 1), packet.len);
    try testing.expectEqualSlices(u8, &.{0x02}, reader.rest());
    var whole = Reader.init(&.{ 0x01, 0x02 });
    try testing.expectError(error.ExtraData, codec.decode_reader(Modes(2), gpa, &whole, {}));
    try testing.expectEqual(@as(u64, 1), whole.diagnostic.value);
}
