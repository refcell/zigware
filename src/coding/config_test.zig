//! Config tests and its `CodecConformance` hash (commonware's `coding::test::conformance`).

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const coding = @import("root.zig");

const Config = coding.Config;
const arbitrary = codec.arbitrary;
const gpa = testing.allocator;

test "config encodes as two big-endian non-zero u16s" {
    const config: Config = .{ .minimum_shards = 0x0102, .extra_shards = 0xfffe };
    const encoded = codec.encode_fixed(Config, config);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0xff, 0xfe }, &encoded);
    try testing.expect((try codec.decode_fixed(Config, &encoded)).eql(config));
    try testing.expectEqual(@as(u32, 0x0102 + 0xfffe), config.total_shards());
    try testing.expectEqual(@as(?usize, 4), codec.fixed_size(Config));

    // A zero count is invalid, as for `NonZeroU16`.
    for ([_][4]u8{ .{ 0, 0, 0, 1 }, .{ 0, 1, 0, 0 } }) |bytes| {
        try testing.expectError(error.Invalid, codec.decode(Config, gpa, &bytes));
    }
    try testing.expectError(error.EndOfBuffer, codec.decode(Config, gpa, &.{ 0, 1, 0 }));
    try testing.expectError(error.ExtraData, codec.decode(Config, gpa, &.{ 0, 1, 0, 1, 0 }));
}

test "config orders by minimum, then extra shards" {
    const a: Config = .{ .minimum_shards = 2, .extra_shards = 9 };
    const b: Config = .{ .minimum_shards = 3, .extra_shards = 1 };
    const c: Config = .{ .minimum_shards = 3, .extra_shards = 2 };
    try testing.expectEqual(std.math.Order.lt, a.order(b));
    try testing.expectEqual(std.math.Order.lt, b.order(c));
    try testing.expectEqual(std.math.Order.gt, c.order(a));
    try testing.expectEqual(std.math.Order.eq, c.order(c));
}

/// `Config::arbitrary`: each count from `int_in_range(1..=u16::MAX)`.
fn gen_config(_: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!Config {
    const minimum = u.int_in_range(u16, 1, std.math.maxInt(u16));
    const extra = u.int_in_range(u16, 1, std.math.maxInt(u16));
    assert(minimum > 0 and extra > 0);
    return .{ .minimum_shards = minimum, .extra_shards = extra };
}

const ConfigConformance = struct {
    pub fn commit(allocator: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const config = try arbitrary.generate(Config, gen_config, arena.allocator(), seed);
        return codec.encode(Config, allocator, config);
    }
};

test "conformance CodecConformance<Config>" {
    try conformance.verify(
        ConfigConformance,
        std.heap.smp_allocator,
        "commonware_coding::test::conformance::CodecConformance<Config>",
        conformance.default_cases,
        @embedFile("conformance.toml"),
    );
}
