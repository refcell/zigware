//! Non-zero unsigned integers (codec/src/types/primitives.rs `NonZeroU16/32/64`).
//!
//! `NonZero(T)` encodes exactly like `T`; decoding refuses zero with
//! `Invalid("NonZeroU<bits>", "value must not be zero")`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const buf = @import("../buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("../error.zig").Error;

pub fn NonZero(comptime T: type) type {
    comptime assert(@typeInfo(T).int.signedness == .unsigned and @bitSizeOf(T) % 8 == 0);
    return struct {
        const Self = @This();
        const name = std.fmt.comptimePrint("NonZeroU{d}", .{@bitSizeOf(T)});

        value: T,

        pub const fixed_size = @bitSizeOf(T) / 8;

        /// Returns null for zero, like Rust's `NonZero::new`.
        pub fn init(value: T) ?Self {
            if (value == 0) return null;
            return .{ .value = value };
        }

        pub fn write(self: Self, writer: *Writer) void {
            assert(self.value != 0);
            writer.write_int(T, self.value);
        }

        pub fn read(_: Allocator, reader: *Reader, _: void) Error!Self {
            const value = try reader.read_int(T);
            if (value == 0) return reader.invalid(name, "value must not be zero");
            return .{ .value = value };
        }

        pub fn order(a: Self, b: Self) std.math.Order {
            return std.math.order(a.value, b.value);
        }
    };
}

const testing = std.testing;
const codec = @import("../codec.zig");
const test_gpa = testing.allocator;

fn expect_nonzero(comptime T: type) !void {
    const N = NonZero(T);
    for ([_]T{ 1, 42, std.math.maxInt(T) }) |raw| {
        const value = N.init(raw).?;
        const encoded = codec.encode_fixed(N, value);
        try testing.expectEqual(codec.encode_fixed(T, raw), encoded);
        try testing.expectEqual(value, try codec.decode_fixed(N, &encoded));
    }
    try testing.expectEqual(@as(?N, null), N.init(0));
    var reader = Reader.init(&codec.encode_fixed(T, 0));
    try testing.expectError(error.Invalid, codec.decode_reader(N, test_gpa, &reader, {}));
    try testing.expectEqualStrings(N.name, reader.diagnostic.context);
}

test "nonzero u16, u32, u64" {
    try expect_nonzero(u16);
    try expect_nonzero(u32);
    try expect_nonzero(u64);
    try testing.expectEqualStrings("NonZeroU32", NonZero(u32).name);
}

test "nonzero read_items bounds" {
    const N = NonZero(u32);
    var short = Reader.init(&@as([4]u8, @splat(0)));
    try testing.expectError(error.EndOfBuffer, codec.read_items(N, test_gpa, &short, 2, {}));
    try testing.expectEqual(@as(usize, 4), short.remaining());

    var zero = Reader.init(&@as([4]u8, @splat(0)));
    try testing.expectError(error.Invalid, codec.read_items(N, test_gpa, &zero, 1, {}));

    var valid = Reader.init(&.{ 0, 0, 0, 1, 0, 0, 0, 2 });
    const items = try codec.read_items(N, test_gpa, &valid, 2, {});
    defer test_gpa.free(items);
    try testing.expectEqualSlices(N, &.{ .{ .value = 1 }, .{ .value = 2 } }, items);
}
