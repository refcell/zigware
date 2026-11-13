//! Tests for the Bloom filter (commonware `bloomfilter/mod.rs`) and the `bloomfilter` fuzz
//! target's `New` constructor (`WithRate` waits for `utils.rational`).

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const codec = @import("codec");
const fuzz = @import("fuzz.zig");
const BloomFilter = @import("bloomfilter.zig").Default;

const gpa = testing.allocator;

test "bloomfilter insert and contains" {
    var filter = try BloomFilter.init(gpa, 10, 1000);
    defer filter.deinit(gpa);
    try testing.expectEqual(1024, filter.bit_count());
    filter.insert("hello");
    filter.insert("world");
    try testing.expect(filter.contains("hello"));
    try testing.expect(filter.contains("world"));
    try testing.expect(!filter.contains("bloomfilter"));
}

test "bloomfilter empty" {
    var filter = try BloomFilter.init(gpa, 5, 100);
    defer filter.deinit(gpa);
    try testing.expect(!filter.contains("anything"));
}

test "bloomfilter false positives" {
    var filter = try BloomFilter.init(gpa, 10, 100);
    defer filter.deinit(gpa);
    var item: [8]u8 = undefined;
    for (0..10) |i| {
        std.mem.writeInt(u64, &item, i, .big);
        filter.insert(&item);
    }
    for (0..10) |i| {
        std.mem.writeInt(u64, &item, i, .big);
        try testing.expect(filter.contains(&item));
    }
    // A small filter holding many items has some false positives, but not only those.
    var false_positives: u32 = 0;
    for (100..1100) |i| {
        std.mem.writeInt(u64, &item, i, .big);
        if (filter.contains(&item)) false_positives += 1;
    }
    try testing.expect(false_positives > 0);
    try testing.expect(false_positives < 1000);
}

fn expect_round_trip(filter: *const BloomFilter, cfg: BloomFilter.Cfg) !void {
    const encoded = try codec.encode(BloomFilter, gpa, filter.*);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(BloomFilter, filter.*), encoded.len);
    var decoded = try codec.decode_cfg(BloomFilter, gpa, encoded, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(filter));
}

test "bloomfilter codec round trip" {
    var filter = try BloomFilter.init(gpa, 5, 128);
    defer filter.deinit(gpa);
    filter.insert("test1");
    filter.insert("test2");
    try expect_round_trip(&filter, .{ .hashers = 5, .bits = 128 });

    var empty = try BloomFilter.init(gpa, 4, 128);
    defer empty.deinit(gpa);
    try expect_round_trip(&empty, .{ .hashers = 4, .bits = 128 });
}

test "bloomfilter codec rejects invalid hashers and bits" {
    var filter = try BloomFilter.init(gpa, 5, 128);
    defer filter.deinit(gpa);
    filter.insert("test1");
    const encoded = try codec.encode(BloomFilter, gpa, filter);
    defer gpa.free(encoded);
    // Hasher counts above and below the encoded one.
    for ([_]u8{ 10, 4 }) |hashers| {
        const cfg: BloomFilter.Cfg = .{ .hashers = hashers, .bits = 128 };
        try testing.expectError(error.Invalid, codec.decode_cfg(BloomFilter, gpa, encoded, cfg));
    }
    // Bit counts other than the encoded one, and one that is not a power of two.
    for ([_]u64{ 64, 256 }) |bits| {
        const cfg: BloomFilter.Cfg = .{ .hashers = 5, .bits = bits };
        const result = codec.decode_cfg(BloomFilter, gpa, encoded, cfg);
        try testing.expectError(error.InvalidLength, result);
    }
    const odd: BloomFilter.Cfg = .{ .hashers = 5, .bits = 100 };
    try testing.expectError(error.Invalid, codec.decode_cfg(BloomFilter, gpa, encoded, odd));
}

test "bloomfilter rounds bits up to a power of two" {
    var one = try BloomFilter.init(gpa, 1, 1);
    defer one.deinit(gpa);
    try testing.expectEqual(1, one.bit_count());
    one.insert("x");
    try testing.expect(one.contains("anything"));
    var odd = try BloomFilter.init(gpa, 3, 129);
    defer odd.deinit(gpa);
    try testing.expectEqual(256, odd.bit_count());
}

const operations_max = 64;
const items_max = operations_max;

/// The `bloomfilter` fuzz target with the `New` constructor: inserted items are always
/// contained, and every encoding decodes back to the same filter.
fn fuzz_filter(bytes: []const u8) !void {
    var input = fuzz.Input.init(bytes);
    const hashers: u8 = @intCast(input.int_in_range(1, std.math.maxInt(u8)));
    const raw = input.int_in_range(0, std.math.maxInt(u16));
    const bits = std.math.ceilPowerOfTwo(u64, @max(raw, 1)) catch unreachable;
    var filter = try BloomFilter.init(gpa, hashers, @min(bits, 1 << 15));
    defer filter.deinit(gpa);
    const cfg: BloomFilter.Cfg = .{ .hashers = hashers, .bits = filter.bit_count() };
    var model: [items_max][]const u8 = undefined;
    var inserted: usize = 0;
    const operations = input.int_in_range(1, operations_max);
    for (0..operations) |_| {
        const item = input.take(input.int_in_range(0, 32));
        switch (input.int_in_range(0, 3)) {
            0 => {
                filter.insert(item);
                assert(inserted < items_max);
                model[inserted] = item;
                inserted += 1;
            },
            1 => for (model[0..inserted]) |stored| {
                if (std.mem.eql(u8, stored, item)) try testing.expect(filter.contains(item));
            },
            2 => {
                const other: BloomFilter.Cfg = .{
                    .hashers = @intCast(input.int_in_range(1, std.math.maxInt(u8))),
                    .bits = input.int_in_range(1, std.math.maxInt(u16)),
                };
                if (codec.decode_cfg(BloomFilter, gpa, item, other)) |value| {
                    var decoded = value;
                    decoded.deinit(gpa);
                } else |_| {}
            },
            else => try expect_round_trip(&filter, cfg),
        }
    }
    for (model[0..inserted]) |item| try testing.expect(filter.contains(item));
}

test "bloomfilter fuzz (seeded)" {
    var random = fuzz.prng(0xb100f);
    var bytes: [1024]u8 = undefined;
    for (0..fuzz.iterations(64)) |_| {
        random.random().bytes(&bytes);
        try fuzz_filter(bytes[0..random.random().uintAtMost(usize, bytes.len)]);
    }
}

test "bloomfilter fuzz (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [1024]u8 = undefined;
            const length = smith.slice(&bytes);
            try fuzz_filter(bytes[0..length]);
        }
    }.run, .{});
}
