//! arbitrary 1.4's `Unstructured`: turns raw fuzzer bytes into structured values.
//!
//! Values come from the front of the data and lengths from the back, exactly as in Rust,
//! so a byte slice decodes to the same values here as there. `arbitrary(T)` covers
//! bool, integers, floats, arrays, optionals, tuples, structs, and enums; a type with a
//! `pub fn arbitrary(*Unstructured) Error!Self` declaration uses that instead.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The data ran out before the value was complete.
    NotEnoughData,
    /// The data does not describe a valid value (rejected by the generator).
    IncorrectFormat,
    /// `choose` or `choose_index` was given no choices.
    EmptyChoose,
};

pub const Unstructured = struct {
    data: []const u8,

    pub fn init(data: []const u8) Unstructured {
        return .{ .data = data };
    }

    /// The number of bytes left.
    pub fn len(self: *const Unstructured) usize {
        return self.data.len;
    }

    pub fn is_empty(self: *const Unstructured) bool {
        return self.data.len == 0;
    }

    /// Copies the next bytes into `out`, zero-filling past the end of the data
    /// (`fill_buffer`). Never fails.
    pub fn fill(self: *Unstructured, out: []u8) void {
        const count = @min(out.len, self.data.len);
        @memcpy(out[0..count], self.data[0..count]);
        @memset(out[count..], 0);
        self.data = self.data[count..];
        assert(count == out.len or self.data.len == 0);
    }

    /// Takes exactly `size` bytes, or fails with `NotEnoughData`.
    pub fn bytes(self: *Unstructured, size: usize) Error![]const u8 {
        if (self.data.len < size) return error.NotEnoughData;
        const taken = self.data[0..size];
        self.data = self.data[size..];
        assert(taken.len == size);
        return taken;
    }

    /// The next `size` bytes without consuming them, if there are that many.
    pub fn peek_bytes(self: *const Unstructured, size: usize) ?[]const u8 {
        return if (self.data.len < size) null else self.data[0..size];
    }

    /// Takes all remaining bytes.
    pub fn take_rest(self: *Unstructured) []const u8 {
        const rest = self.data;
        self.data = self.data[rest.len..];
        assert(self.data.len == 0);
        return rest;
    }

    /// An integer in `start..=end`, from as few big-endian bytes as the range needs.
    /// Signed or unsigned. Runs out of data gracefully: missing bytes count as zero.
    pub fn int_in_range(self: *Unstructured, comptime T: type, start: T, end: T) T {
        const result, const consumed = int_in_range_impl(T, start, end, self.data);
        self.data = self.data[consumed..];
        return result;
    }

    /// An index in `0..count`; `EmptyChoose` when `count` is zero.
    pub fn choose_index(self: *Unstructured, count: usize) Error!usize {
        if (count == 0) return error.EmptyChoose;
        const index = self.int_in_range(usize, 0, count - 1);
        assert(index < count);
        return index;
    }

    /// One of `choices`; `EmptyChoose` when there are none.
    pub fn choose(self: *Unstructured, comptime T: type, choices: []const T) Error!T {
        return choices[try self.choose_index(choices.len)];
    }

    /// True with probability `numerator / denominator`.
    pub fn ratio(self: *Unstructured, comptime T: type, numerator: T, denominator: T) bool {
        assert(0 < numerator);
        assert(numerator <= denominator);
        return self.int_in_range(T, 1, denominator) <= numerator;
    }

    /// `arbitrary_byte_size`: a byte length read from the back of the data.
    pub fn byte_size(self: *Unstructured) usize {
        if (self.data.len <= 1) {
            self.data = self.data[0..0];
            return 0;
        }
        inline for (.{ u8, u16, u32, u64 }) |T| {
            if (self.data.len <= @as(u128, std.math.maxInt(T)) + @sizeOf(T)) {
                const max_size = self.data.len - @sizeOf(T);
                const tail = self.data[max_size..];
                self.data = self.data[0..max_size];
                const result, _ = int_in_range_impl(T, 0, @intCast(max_size), tail);
                assert(result <= max_size);
                return result;
            }
        }
        unreachable; // Proof: every usize length fits the u64 case.
    }

    /// `arbitrary_len::<T>()`: how many `T` to generate, sized by `T`'s size hint.
    pub fn arbitrary_len(self: *Unstructured, comptime T: type) usize {
        const lower, const upper = comptime size_hint(T);
        const element_size = @max(1, upper orelse lower * 2);
        return self.byte_size() / element_size;
    }

    /// The `Arbitrary` value of `T`.
    pub fn arbitrary(self: *Unstructured, comptime T: type) Error!T {
        if (comptime has_arbitrary(T)) return T.arbitrary(self);
        switch (@typeInfo(T)) {
            .bool => {
                var byte: [1]u8 = undefined;
                self.fill(&byte);
                return byte[0] & 1 == 1;
            },
            .int => |info| {
                comptime assert(info.bits % 8 == 0);
                var buffer: [@sizeOf(T)]u8 = undefined;
                self.fill(&buffer);
                return std.mem.readInt(T, &buffer, .little);
            },
            .float => |info| {
                const Bits = @Int(.unsigned, info.bits);
                return @bitCast(try self.arbitrary(Bits));
            },
            .optional => |info| {
                if (!try self.arbitrary(bool)) return null;
                return try self.arbitrary(info.child);
            },
            .array => |info| {
                var out: T = undefined;
                for (&out) |*element| element.* = try self.arbitrary(info.child);
                return out;
            },
            .@"struct" => |info| {
                var out: T = undefined;
                inline for (info.field_names, info.field_types) |name, Field| {
                    @field(out, name) = try self.arbitrary(Field);
                }
                return out;
            },
            .@"enum" => |info| {
                // derive(Arbitrary): a u32 scaled into the variant count.
                const raw: u64 = try self.arbitrary(u32);
                const index = (raw * info.field_names.len) >> 32;
                assert(index < info.field_names.len);
                return std.enums.values(T)[index];
            },
            else => @compileError("no Arbitrary for " ++ @typeName(T)),
        }
    }
};

fn has_arbitrary(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum" => @hasDecl(T, "arbitrary"),
        else => false,
    };
}

/// `Arbitrary::size_hint(0)`: lower and optional upper byte bound for one `T`.
fn size_hint(comptime T: type) struct { usize, ?usize } {
    if (has_arbitrary(T)) {
        if (@hasDecl(T, "size_hint")) return T.size_hint;
        return .{ 0, null };
    }
    return switch (@typeInfo(T)) {
        .bool => .{ 1, 1 },
        .int, .float => .{ @sizeOf(T), @sizeOf(T) },
        .@"enum" => .{ 4, 4 },
        .optional => |info| .{ 1, if (size_hint(info.child)[1]) |upper| upper + 1 else null },
        .array => |info| scale_hint(size_hint(info.child), info.len),
        .@"struct" => |info| {
            var lower: usize = 0;
            var upper: ?usize = 0;
            for (info.field_types) |Field| {
                const field_lower, const field_upper = size_hint(Field);
                lower += field_lower;
                const both = upper != null and field_upper != null;
                upper = if (both) upper.? + field_upper.? else null;
            }
            return .{ lower, upper };
        },
        else => .{ 0, null },
    };
}

fn scale_hint(hint: struct { usize, ?usize }, count: usize) struct { usize, ?usize } {
    return .{ hint[0] * count, if (hint[1]) |upper| upper * count else null };
}

/// arbitrary's `int_in_range_impl`, reading bytes in order from `source`. Returns the
/// value and the number of bytes consumed.
fn int_in_range_impl(comptime T: type, start: T, end: T, source: []const u8) struct { T, usize } {
    const info = @typeInfo(T).int;
    comptime assert(info.bits % 8 == 0);
    assert(start <= end);
    if (start == end) return .{ start, 0 };
    const U = @Int(.unsigned, info.bits);
    const start_bits: U = @bitCast(start);
    const delta: U = @as(U, @bitCast(end)) -% start_bits;
    assert(delta != 0);
    var raw: U = 0;
    var consumed: usize = 0;
    while (consumed < @sizeOf(T) and (delta >> @intCast(consumed * 8)) > 0) {
        if (consumed == source.len) break;
        const byte = source[consumed];
        consumed += 1;
        raw = if (@sizeOf(T) == 1) byte else (raw << 8) | byte;
    }
    const offset = if (delta == std.math.maxInt(U)) raw else raw % (delta + 1);
    return .{ @bitCast(start_bits +% offset), consumed };
}

const testing = std.testing;

test "int_in_range matches arbitrary's byte consumption" {
    // One byte covers 0..=255; the bytes are big-endian and reduced modulo the range.
    var u: Unstructured = .init(&.{ 7, 1, 2, 3, 4 });
    try testing.expectEqual(@as(u32, 17), u.int_in_range(u32, 10, 20));
    try testing.expectEqual(@as(usize, 4), u.len());
    try testing.expectEqual(@as(u16, 0x0102), u.int_in_range(u16, 0, 0xffff));
    // Signed ranges work on the unsigned representation.
    try testing.expectEqual(@as(i8, -128 + 3), u.int_in_range(i8, -128, 127));
    try testing.expectEqual(@as(i64, -5), u.int_in_range(i64, -5, -5));
    // Out of data: missing bytes contribute nothing.
    try testing.expectEqual(@as(u32, 4), u.int_in_range(u32, 0, 1000));
    try testing.expect(u.is_empty());
    try testing.expectEqual(@as(u32, 0), u.int_in_range(u32, 0, 1000));
}

test "arbitrary primitives, bytes, and lengths" {
    var u: Unstructured = .init(&.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 3, 7, 2 });
    try testing.expectEqual(@as(u32, 0x04030201), try u.arbitrary(u32));
    try testing.expect(try u.arbitrary(bool));
    try testing.expectEqual(@as(?u8, null), try u.arbitrary(?u8));
    // Length from the back: one size byte (2), reduced modulo 3 (lengths 0..=2).
    try testing.expectEqual(@as(usize, 2), u.byte_size());
    try testing.expectEqualSlices(u8, &.{3}, u.peek_bytes(1).?);
    try testing.expectError(error.NotEnoughData, u.bytes(3));
    try testing.expectEqualSlices(u8, &.{3}, try u.bytes(1));
    // Integers zero-fill once the data runs out.
    try testing.expectEqual(@as(u64, 7), try u.arbitrary(u64));
    try testing.expect(u.is_empty());
    try testing.expectError(error.EmptyChoose, u.choose_index(0));
}

test "arbitrary enums and structs follow derive(Arbitrary)" {
    const Color = enum { red, green, blue };
    const Pair = struct { a: u8, b: Color };
    // 0xaaaaaaaa * 3 >> 32 = 1.
    var u: Unstructured = .init(&.{ 9, 0xaa, 0xaa, 0xaa, 0xaa });
    try testing.expectEqual(Pair{ .a = 9, .b = .green }, try u.arbitrary(Pair));
    try testing.expectEqual(@as(usize, 5), comptime size_hint(Pair)[1].?);
    var v: Unstructured = .init(&.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 });
    // byte_size reads the last byte: 0 % 10 = 0.
    try testing.expectEqual(@as(usize, 0), v.arbitrary_len(u32));
    try testing.expect(v.ratio(u8, 1, 1));
}
