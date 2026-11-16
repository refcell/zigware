//! Fuzz for the sequence types (commonware `utils/fuzz/fuzz_targets/sequence.rs`).

const std = @import("std");
const codec = @import("codec");
const sequence = @import("../sequence.zig");
const fuzz = @import("../fuzz.zig");
const rng = @import("../rng.zig");
const testing = std.testing;
const gpa = testing.allocator;
const expectEqual = testing.expectEqual;
const expectEqualSlices = testing.expectEqualSlices;
const expectEqualStrings = testing.expectEqualStrings;

fn check_fixed_bytes(comptime N: usize, generator: *rng.FuzzRng) !void {
    var bytes: [N]u8 = undefined;
    generator.fill_bytes(&bytes);
    const Fixed = sequence.FixedBytes(N);
    const fixed = Fixed.init(bytes);
    try expectEqualSlices(u8, &bytes, fixed.as_slice());
    var buffer: [2 * N + 16]u8 = undefined;
    const display = try std.fmt.bufPrint(&buffer, "{f}", .{fixed});
    try testing.expect(display.len > 0);
    const encoded = codec.encode_fixed(Fixed, fixed);
    try expectEqualSlices(u8, &bytes, &encoded);
    const decoded = try codec.decode(Fixed, gpa, &encoded);
    try testing.expect(fixed.eql(decoded));
    try testing.expectError(error.EndOfBuffer, codec.decode(Fixed, gpa, encoded[0 .. N - 1]));
}

fn check_uint(comptime U: type, comptime T: type, generator: *rng.FuzzRng) !void {
    const value: T = @truncate(generator.next_u64());
    const array = U.init(value);
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try testing.expect(U.from_bytes(bytes).eql(array));
    try expectEqualSlices(u8, &bytes, array.as_slice());
    try expectEqual(value, array.get());
    const encoded = codec.encode_fixed(U, array);
    try expectEqualSlices(u8, &bytes, &encoded);
    try testing.expect((try codec.decode(U, gpa, &encoded)).eql(array));
    const short = encoded[0 .. encoded.len - 1];
    try testing.expectError(error.EndOfBuffer, codec.decode(U, gpa, short));
    var buffer: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    try expectEqualStrings(
        try std.fmt.bufPrint(&expected, "{d}", .{value}),
        try std.fmt.bufPrint(&buffer, "{f}", .{array}),
    );
}

fn check_prefixed(generator: *rng.FuzzRng) !void {
    const prefix: u8 = @truncate(generator.next_u32());
    const value = generator.next_u64();
    const prefixed = sequence.PrefixedU64.init(prefix, value);
    try expectEqual(prefix, prefixed.prefix());
    try expectEqual(value, prefixed.value());
    const slice = prefixed.as_slice();
    try expectEqual(9, slice.len);
    try expectEqual(prefix, slice[0]);
    try expectEqual(value, std.mem.readInt(u64, slice[1..9], .big));
    const encoded = codec.encode_fixed(sequence.PrefixedU64, prefixed);
    try expectEqualSlices(u8, slice, &encoded);
    const decoded = try codec.decode(sequence.PrefixedU64, gpa, &encoded);
    try testing.expect(decoded.eql(prefixed));
    try testing.expect(sequence.PrefixedU64.from_bytes(encoded).eql(prefixed));
    const short = encoded[0..8];
    try testing.expectError(error.EndOfBuffer, codec.decode(sequence.PrefixedU64, gpa, short));
    var buffer: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    try expectEqualStrings(
        try std.fmt.bufPrint(&expected, "{d}:{d}", .{ prefix, value }),
        try std.fmt.bufPrint(&buffer, "{f}", .{prefixed}),
    );
}

fn fuzz_sequence(_: void, generator: *rng.FuzzRng) !void {
    switch (rng.range_less_than(generator, u8, 0, 13)) {
        0 => try check_fixed_bytes(1, generator),
        1 => try check_fixed_bytes(2, generator),
        2 => try check_fixed_bytes(4, generator),
        3 => try check_fixed_bytes(8, generator),
        4 => try check_fixed_bytes(16, generator),
        5 => try check_fixed_bytes(32, generator),
        6 => try check_fixed_bytes(64, generator),
        7 => try check_fixed_bytes(128, generator),
        8 => try check_fixed_bytes(256, generator),
        9 => try check_fixed_bytes(512, generator),
        10 => try check_uint(sequence.U64, u64, generator),
        11 => try check_uint(sequence.U32, u32, generator),
        12 => try check_prefixed(generator),
        else => unreachable,
    }
}

test "fuzz sequence" {
    try fuzz.run({}, fuzz_sequence, 0x7365_7175, 500);
}
