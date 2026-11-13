//! utils: Leverage common functionality across multiple primitives.
//!
//! Zig port of commonware's `commonware-utils` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/utils). The lane file
//! docs/lanes/utils.md tracks what is ported.
//!
//! Rust traits become comptime interfaces; `NZ*!` macros become `nz`/`NonZero`.

const std = @import("std");
const codec = @import("codec");
const assert = std.debug.assert;

pub const faults = @import("faults.zig");
pub const N3f1 = faults.N3f1;
pub const N5f1 = faults.N5f1;

pub const rng = @import("rng.zig");
pub const TestRng = rng.TestRng;
pub const ScriptedRng = rng.ScriptedRng;
pub const FuzzRng = rng.FuzzRng;
pub const test_rng = rng.test_rng;

pub const range = @import("range.zig");

pub const bitmap = @import("bitmap.zig");
pub const BitMap = bitmap.BitMap;

pub const sequence = @import("sequence.zig");
pub const Array = sequence.assert_array;
pub const Span = sequence.assert_span;

pub const time = @import("time.zig");
pub const Duration = time.Duration;
pub const SystemTime = time.SystemTime;

/// 64-bit golden-ratio-derived odd mixing constant, `floor(2^64 / phi)`.
pub const GOLDEN_RATIO: u64 = rng.GOLDEN_RATIO;

/// Maximum byte size of one allocation (Rust `isize::MAX`).
pub const MAX_ALLOCATION_BYTES: usize = std.math.maxInt(isize);

/// A participant (validator) index within a consensus committee: the position of the
/// validator's public key in the ordered participant set. Encoded as a `u32` varint.
pub const Participant = struct {
    index: u32,

    pub fn init(index: u32) Participant {
        return .{ .index = index };
    }

    /// Panics if `index` exceeds `u32` max, like commonware's `from_usize`.
    pub fn from_usize(index: usize) Participant {
        const value = std.math.cast(u32, index) orelse
            @panic("participant index exceeds u32::MAX");
        return .{ .index = value };
    }

    pub fn get(participant: Participant) u32 {
        return participant.index;
    }

    pub fn order(a: Participant, b: Participant) std.math.Order {
        return std.math.order(a.index, b.index);
    }

    pub fn format(participant: Participant, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d}", .{participant.index});
    }

    /// Encoded as `UInt<u32>`, like commonware.
    pub const max_encode_size: usize = codec.varint.max_size(u32);

    pub fn write(participant: Participant, writer: *codec.Writer) void {
        codec.varint.write(u32, participant.index, writer);
    }

    pub fn encode_size(participant: Participant) usize {
        return codec.varint.size(u32, participant.index);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!Participant {
        return .{ .index = try codec.varint.read(u32, reader) };
    }
};

/// A value of integer type `T` that is never zero (Rust `core::num::NonZero*`).
pub fn NonZero(comptime T: type) type {
    comptime assert(@typeInfo(T) == .int);
    return struct {
        value: T,

        const Self = @This();

        /// Returns null when `value` is zero.
        pub fn init(value: T) ?Self {
            if (value == 0) return null;
            return .{ .value = value };
        }

        pub fn get(self: Self) T {
            assert(self.value != 0);
            return self.value;
        }
    };
}

/// Returns `value` as `NonZero(T)`, panicking when it is zero (commonware's `NZU32!` etc.).
/// Called at comptime (`comptime nz(u32, 0)`), a zero is a compile error.
pub fn nz(comptime T: type, value: T) NonZero(T) {
    return NonZero(T).init(value) orelse @panic("value must be non-zero");
}

/// Concatenates two byte slices into a new allocation owned by the caller.
pub fn @"union"(allocator: std.mem.Allocator, a: []const u8, b: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, a.len + b.len);
    @memcpy(result[0..a.len], a);
    @memcpy(result[a.len..], b);
    assert(result.len == a.len + b.len);
    return result;
}

/// Concatenates a namespace and a message, prefixed by the varint of the namespace length
/// (codec's `usize` encoding). Produces a unique byte sequence for each `(namespace, msg)`.
pub fn union_unique(
    allocator: std.mem.Allocator,
    namespace: []const u8,
    msg: []const u8,
) ![]u8 {
    const prefix_len = codec.encode_size(usize, namespace.len);
    const result = try allocator.alloc(u8, prefix_len + namespace.len + msg.len);
    var writer = codec.Writer.init(result);
    codec.write(usize, namespace.len, &writer);
    writer.write_bytes(namespace);
    writer.write_bytes(msg);
    assert(writer.written().len == result.len);
    return result;
}

/// The bytes interpreted as a big-endian integer, modulo `n`. Used to pick an entry from
/// an array with a random seed. Panics when `n` is zero.
pub fn modulo(bytes: []const u8, n: u64) u64 {
    if (n == 0) @panic("modulus must be non-zero");
    const modulus: u128 = n;
    var result: u128 = 0;
    for (bytes) |byte| {
        result = ((result << 8) | byte) % modulus;
    }
    assert(result < modulus);
    return @intCast(result);
}

const testing = std.testing;

test {
    std.testing.refAllDecls(@This());
    _ = @import("conformance_test.zig");
    _ = @import("fuzz.zig");
}

test "utils: union" {
    const gpa = testing.allocator;
    const empty = try @"union"(gpa, &.{}, &.{});
    defer gpa.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);
    const one = try @"union"(gpa, &.{}, &.{ 1, 2, 3 });
    defer gpa.free(one);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, one);
    const both = try @"union"(gpa, &.{ 1, 2, 3 }, &.{ 4, 5, 6 });
    defer gpa.free(both);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6 }, both);
}

test "utils: union_unique" {
    const gpa = testing.allocator;
    const result = try union_unique(gpa, "namespace", "message");
    defer gpa.free(result);
    try testing.expectEqualSlices(u8, "\x09namespacemessage", result);

    const zero = try union_unique(gpa, "", "message");
    defer gpa.free(zero);
    try testing.expectEqualSlices(u8, "\x00message", zero);

    const long_namespace: [256]u8 = @splat('n');
    const long = try union_unique(gpa, &long_namespace, "message");
    defer gpa.free(long);
    try testing.expectEqualSlices(u8, &.{ 0b1000_0000, 0b0000_0010 }, long[0..2]);
    try testing.expectEqualSlices(u8, &long_namespace, long[2..258]);
    try testing.expectEqualSlices(u8, "message", long[258..]);
}

test "utils: modulo" {
    try testing.expectEqual(@as(u64, 0), modulo(&.{}, 1));
    try testing.expectEqual(@as(u64, 0), modulo(&.{0x01}, 1));
    try testing.expectEqual(@as(u64, 1), modulo(&.{ 0x01, 0x02, 0x03 }, 10));

    // Equivalence with big-integer arithmetic on commonware's seeded inputs.
    for (0..100) |seed| {
        var generator = TestRng.init(seed);
        var bytes: [32]u8 = undefined;
        for (&bytes) |*byte| byte.* = @truncate(generator.next_u32());
        const big = std.mem.readInt(u256, &bytes, .big);
        for ([_]u64{ 11, 11_111, 0xDFFFFFFFFFFFFFFD }) |n| {
            try testing.expectEqual(@as(u64, @intCast(big % n)), modulo(&bytes, n));
        }
    }
}

test "utils: non-zero helpers" {
    try testing.expectEqual(@as(u8, 2), nz(u8, 2).get());
    try testing.expectEqual(@as(u16, 3), nz(u16, 3).get());
    try testing.expectEqual(@as(u32, 4), nz(u32, 4).get());
    try testing.expectEqual(@as(u64, 5), nz(u64, 5).get());
    try testing.expectEqual(@as(usize, 1), nz(usize, 1).get());
    try testing.expect(NonZero(u32).init(0) == null);
    const runtime_zero: u64 = 0;
    try testing.expect(NonZero(u64).init(runtime_zero) == null);
}

test "utils: participant" {
    try testing.expectEqual(@as(u32, 0), Participant.init(0).get());
    try testing.expectEqual(@as(u32, 42), Participant.from_usize(42).get());
    const max = std.math.maxInt(u32);
    try testing.expectEqual(@as(u32, max), Participant.from_usize(max).get());
    try testing.expectEqual(std.math.Order.lt, Participant.init(5).order(Participant.init(10)));
    try testing.expectEqual(std.math.Order.eq, Participant.init(42).order(Participant.init(42)));
    var buffer: [16]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{Participant.init(1000)});
    try testing.expectEqualStrings("1000", text);
}

test "utils: participant encode and decode" {
    const cases = [_]u32{ 0, 1, 127, 128, 255, 256, std.math.maxInt(u32) };
    for (cases) |value| {
        const participant = Participant.init(value);
        var buffer: [codec.varint.max_size(u32)]u8 = undefined;
        const encoded = codec.encode_to(Participant, participant, &buffer);
        try testing.expectEqual(codec.encode_size(Participant, participant), encoded.len);
        const decoded = try codec.decode(Participant, testing.allocator, encoded);
        try testing.expectEqual(participant, decoded);
    }
    // 128 is the varint 0x80 0x01; u32::MAX takes five bytes.
    var buffer: [5]u8 = undefined;
    const encoded = codec.encode_to(Participant, Participant.init(128), &buffer);
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, encoded);
    try testing.expectEqual(@as(?usize, 5), codec.max_encode_size(Participant));
    const truncated = codec.decode(Participant, testing.allocator, &.{0x80});
    try testing.expectError(error.EndOfBuffer, truncated);
}
