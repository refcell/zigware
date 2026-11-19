//! `FixedBytes(N)`: an `Array` of `N` bytes (commonware `utils/src/sequence/fixed_bytes.rs`).
//!
//! Encodes as its `N` bytes with no prefix. Orders lexicographically, displays as lowercase
//! hex. `FixedBytes(N).from_hex("0x...")` is commonware's `fixed_bytes!` macro.

const std = @import("std");
const codec = @import("codec");
const formatting = @import("formatting");
const assert = std.debug.assert;

pub fn FixedBytes(comptime N: usize) type {
    return struct {
        bytes: [N]u8,

        const Self = @This();

        pub const fixed_size: usize = N;

        pub fn init(bytes: [N]u8) Self {
            return .{ .bytes = bytes };
        }

        /// Parses a comptime hex literal; a length other than `N` bytes is a compile error.
        pub fn from_hex(comptime literal: []const u8) Self {
            return .{ .bytes = comptime formatting.hex_literal(literal) };
        }

        pub fn as_slice(self: *const Self) []const u8 {
            return &self.bytes;
        }

        /// Lexicographic, a big-endian 64-bit word at a time (commonware's `Ord`, which keeps
        /// the derived compare, a memcmp, up to 16 and past 64 bytes; `std.mem.order` compares
        /// byte by byte, so zigware takes the words at every size from 8).
        pub fn order(a: Self, b: Self) std.math.Order {
            if (N < 8) return std.mem.order(u8, &a.bytes, &b.bytes);
            const words = N / 8;
            for (0..words) |index| {
                const left = std.mem.readInt(u64, a.bytes[index * 8 ..][0..8], .big);
                const right = std.mem.readInt(u64, b.bytes[index * 8 ..][0..8], .big);
                if (left != right) return std.math.order(left, right);
            }
            if (N % 8 == 0) return .eq;
            // Every earlier byte is equal, so the last 8 bytes (overlapping the last whole
            // word) decide.
            const left = std.mem.readInt(u64, a.bytes[N - 8 ..][0..8], .big);
            const right = std.mem.readInt(u64, b.bytes[N - 8 ..][0..8], .big);
            return std.math.order(left, right);
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u8, &a.bytes, &b.bytes);
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try formatting.fmt_hex(&self.bytes).format(writer);
        }

        /// Overwrites the bytes with zeros in a way the optimizer keeps (`Zeroize`).
        pub fn zeroize(self: *Self) void {
            std.crypto.secureZero(u8, &self.bytes);
            assert(std.mem.allEqual(u8, &self.bytes, 0));
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_bytes(&self.bytes);
        }

        pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const bytes = try reader.take_array(N);
            return .{ .bytes = bytes.* };
        }
    };
}

const testing = std.testing;
const rng = @import("../rng.zig");

test "fixed_bytes: codec" {
    const original = FixedBytes(4).init(.{ 1, 2, 3, 4 });
    const encoded = codec.encode_fixed(FixedBytes(4), original);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, &encoded);
    try testing.expect(original.eql(try codec.decode(FixedBytes(4), testing.allocator, &encoded)));

    const short = codec.decode(FixedBytes(4), testing.allocator, &.{ 1, 2, 3 });
    try testing.expectError(error.EndOfBuffer, short);
    var reader = codec.Reader.init(&.{ 1, 2, 3, 4, 5 });
    const long = codec.decode_reader(FixedBytes(4), testing.allocator, &reader, {});
    try testing.expectError(error.ExtraData, long);
    try testing.expectEqual(@as(u64, 1), reader.diagnostic.value);
}

test "fixed_bytes: read leaves the rest" {
    var reader = codec.Reader.init(&.{ 1, 2, 3, 4, 5 });
    const bytes = try codec.read(FixedBytes(4), testing.allocator, &reader);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, bytes.as_slice());
    try testing.expectEqualSlices(u8, &.{5}, reader.rest());
}

test "fixed_bytes: display and hex literal" {
    const bytes = FixedBytes(4).from_hex("0x01020304");
    var buffer: [16]u8 = undefined;
    try testing.expectEqualStrings("01020304", try std.fmt.bufPrint(&buffer, "{f}", .{bytes}));
}

test "fixed_bytes: zeroize" {
    var bytes = FixedBytes(3).init(.{ 7, 8, 9 });
    bytes.zeroize();
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, bytes.as_slice());
}

fn expect_order_matches(comptime N: usize, a: [N]u8, b: [N]u8) !void {
    // Independent lexicographic comparison.
    var expected: std.math.Order = .eq;
    for (a, b) |x, y| {
        if (x != y) {
            expected = if (x < y) .lt else .gt;
            break;
        }
    }
    try testing.expectEqual(expected, FixedBytes(N).init(a).order(FixedBytes(N).init(b)));
    try testing.expectEqual(expected.invert(), FixedBytes(N).init(b).order(FixedBytes(N).init(a)));
}

fn check_order(comptime N: usize) !void {
    const boundaries = [_]u8{ 0x00, 0x7f, 0x80, 0xff };
    var generator = rng.test_rng();
    for (0..8) |_| {
        var a: [N]u8 = undefined;
        for (&a) |*byte| byte.* = @truncate(generator.next_u32());
        try expect_order_matches(N, a, a);
        for (0..N) |k| {
            var b = a;
            b[k] = a[k] ^ rng.range_at_most(&generator, u8, 1, 255);
            for (b[k + 1 ..]) |*byte| byte.* = @truncate(generator.next_u32());
            try expect_order_matches(N, a, b);
            for (boundaries) |x| {
                for (boundaries) |y| {
                    var left = a;
                    var right = a;
                    left[k] = x;
                    right[k] = y;
                    @memset(left[k + 1 ..], 0xff);
                    @memset(right[k + 1 ..], 0x00);
                    try expect_order_matches(N, left, right);
                }
            }
        }
    }
}

test "fixed_bytes: order matches byte order" {
    inline for (.{ 0, 5, 16, 17, 18, 19, 20, 21, 22, 23, 24, 31, 32, 33, 40, 63, 64, 65 }) |n| {
        try check_order(n);
    }
}
