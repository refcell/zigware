//! Fixed-size digests: the `Digest` concept of commonware's `lib.rs`.
//!
//! Every hasher has its own digest type (a SHA-256 digest is not a BLAKE3 digest even though
//! both are 32 bytes), so `Digest` takes a name that makes each instantiation distinct. A
//! digest encodes as its raw bytes with no length prefix, byte-identical to commonware's
//! `FixedArray` derive, and orders lexicographically by those bytes.

const std = @import("std");
const assert = std.debug.assert;

/// Errors from decoding a fixed-size value from bytes.
pub const DecodeError = error{
    /// The input is shorter than the encoding.
    EndOfBuffer,
    /// The input continues past the encoding.
    ExtraData,
    /// The bytes do not encode a valid value.
    Invalid,
};

/// Returns the digest type `name` of `length` bytes.
pub fn Digest(comptime length: usize, comptime name: []const u8) type {
    comptime assert(length > 0);
    comptime assert(name.len > 0);
    return struct {
        const Self = @This();

        bytes: [length]u8,

        /// Encoded size in bytes (commonware `FixedSize::SIZE`).
        pub const size = length;
        /// The hasher family this digest belongs to.
        pub const label = name;
        /// The all-zero digest (commonware `Digest::EMPTY`).
        pub const empty: Self = .{ .bytes = @splat(0) };

        /// A digest whose every byte is `byte`; recognizable in tests.
        pub fn fill(byte: u8) Self {
            return .{ .bytes = @splat(byte) };
        }

        /// Draws a uniformly random digest. Meant for tests: real digests come from hashing.
        pub fn random(rng: std.Random) Self {
            var self: Self = undefined;
            rng.bytes(&self.bytes);
            return self;
        }

        /// Decodes a digest from exactly `size` bytes.
        pub fn decode(bytes: []const u8) DecodeError!Self {
            if (bytes.len < length) return error.EndOfBuffer;
            if (bytes.len > length) return error.ExtraData;
            return .{ .bytes = bytes[0..length].* };
        }

        /// Writes the encoding (the raw bytes) into `out`, which must hold `size` bytes.
        pub fn encode(self: *const Self, out: []u8) void {
            assert(out.len >= length);
            @memcpy(out[0..length], &self.bytes);
        }

        /// The digest as a byte slice (commonware `AsRef<[u8]>`).
        pub fn as_slice(self: *const Self) []const u8 {
            return &self.bytes;
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u8, &a.bytes, &b.bytes);
        }

        /// Lexicographic order of the bytes, as commonware's `Ord`.
        pub fn order(a: Self, b: Self) std.math.Order {
            return std.mem.order(u8, &a.bytes, &b.bytes);
        }

        /// Comparator for `std.sort`.
        pub fn less_than(_: void, a: Self, b: Self) bool {
            return order(a, b) == .lt;
        }

        /// Overwrites the digest with zeroes in a way the optimizer keeps.
        pub fn zeroize(self: *Self) void {
            std.crypto.secureZero(u8, &self.bytes);
            assert(self.eql(empty));
        }

        /// The big-endian `u32` of a 4-byte digest (commonware `crc32::Digest::as_u32`).
        pub fn as_u32(self: Self) u32 {
            comptime assert(length == 4);
            return std.mem.readInt(u32, &self.bytes, .big);
        }

        /// The 4-byte digest of `value`, big-endian (commonware `From<u32>`).
        pub fn from_u32(value: u32) Self {
            comptime assert(length == 4);
            var self: Self = undefined;
            std.mem.writeInt(u32, &self.bytes, value, .big);
            return self;
        }

        /// Formats as lowercase hex, as commonware's `Debug` and `Display`.
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("{x}", .{&self.bytes});
        }
    };
}

test "digest decode, order, and hex" {
    const D = Digest(4, "test");
    try std.testing.expectError(error.EndOfBuffer, D.decode(&.{ 1, 2, 3 }));
    try std.testing.expectError(error.ExtraData, D.decode(&.{ 1, 2, 3, 4, 5 }));
    const d = try D.decode(&.{ 0xde, 0xad, 0xbe, 0xef });
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), d.as_u32());
    try std.testing.expect(D.from_u32(0xdeadbeef).eql(d));
    var buffer: [16]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{d});
    try std.testing.expectEqualStrings("deadbeef", text);

    // The first byte decides even when the remaining bytes order the other way.
    const c = D{ .bytes = .{ 0x7f, 0xff, 0xff, 0xff } };
    const e = D{ .bytes = .{ 0x80, 0, 0, 0 } };
    try std.testing.expectEqual(std.math.Order.lt, c.order(e));
    try std.testing.expectEqual(std.math.Order.gt, e.order(c));
    try std.testing.expectEqual(std.math.Order.eq, c.order(c));
}
