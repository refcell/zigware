//! Tests for the Bloom filter (commonware `bloomfilter/mod.rs`), its `RationalOptimalBits`
//! conformance hash, and the `bloomfilter` fuzz target (`New` and `WithRate` constructors).

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const codec = @import("codec");
const fuzz = @import("fuzz.zig");
const utils = @import("utils");
const conformance = @import("conformance");
const BloomFilter = @import("bloomfilter.zig").Default;
const BigRational = utils.BigRational;
const slow = @import("conformance.zig");

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

/// The fuzz target's constructor: `New` (hashers and a power-of-two bit count up to 2^15) or
/// `WithRate` (up to 65535 items at a rate `numerator / denominator` in (0, 1)).
fn fuzz_constructor(input: *fuzz.Input, with_rate: bool) !BloomFilter {
    if (input.boolean() or !with_rate) {
        const hashers: u8 = @intCast(input.int_in_range(1, std.math.maxInt(u8)));
        const raw = input.int_in_range(0, std.math.maxInt(u16));
        const bits = std.math.ceilPowerOfTwo(u64, @max(raw, 1)) catch unreachable;
        return BloomFilter.init(gpa, hashers, @min(bits, 1 << 15));
    }
    const expected_items = input.int_in_range(1, std.math.maxInt(u16));
    const denominator = input.int_in_range(2, 10_000);
    const numerator = input.int_in_range(1, denominator - 1);
    var fp_rate = try BigRational.from_frac_u64(gpa, numerator, denominator);
    defer fp_rate.deinit();
    return BloomFilter.with_rate(gpa, expected_items, &fp_rate);
}

/// The `bloomfilter` fuzz target: inserted items are always contained, and every encoding
/// decodes back to the same filter.
fn fuzz_filter(bytes: []const u8, with_rate: bool) !void {
    var input = fuzz.Input.init(bytes);
    var filter = try fuzz_constructor(&input, with_rate);
    defer filter.deinit(gpa);
    const cfg: BloomFilter.Cfg = .{ .hashers = filter.hashers, .bits = filter.bit_count() };
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
    for (0..fuzz.iterations(64)) |iteration| {
        random.random().bytes(&bytes);
        // `with_rate` takes about a second in Debug (exact log2 squares ~1M-bit integers),
        // so only the first iterations may draw it.
        const length = random.random().uintAtMost(usize, bytes.len);
        try fuzz_filter(bytes[0..length], iteration < 4);
    }
}

test "bloomfilter fuzz (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [1024]u8 = undefined;
            const length = smith.slice(&bytes);
            try fuzz_filter(bytes[0..length], true);
        }
    }.run, .{});
}

fn frac(numerator: u64, denominator: u64) !BigRational {
    return BigRational.from_frac_u64(gpa, numerator, denominator);
}

fn insert_index(filter: *BloomFilter, index: u64) void {
    var item: [8]u8 = undefined;
    std.mem.writeInt(u64, &item, index, .big);
    filter.insert(&item);
}

fn contains_index(filter: *const BloomFilter, index: u64) bool {
    var item: [8]u8 = undefined;
    std.mem.writeInt(u64, &item, index, .big);
    return filter.contains(&item);
}

test "bloomfilter statistics" {
    var filter = try BloomFilter.init(gpa, 7, 1024);
    defer filter.deinit(gpa);
    var count = try filter.estimated_count(gpa);
    try testing.expect(count.is_zero());
    count.deinit();
    var rate = try filter.estimated_false_positive_rate(gpa);
    try testing.expect(rate.is_zero());
    rate.deinit();

    for (0..100) |i| insert_index(&filter, i);
    count = try filter.estimated_count(gpa);
    defer count.deinit();
    var lower = try BigRational.from_u64(gpa, 75);
    defer lower.deinit();
    var upper = try BigRational.from_u64(gpa, 125);
    defer upper.deinit();
    try testing.expectEqual(.gt, try count.order(&lower));
    try testing.expectEqual(.lt, try count.order(&upper));
    rate = try filter.estimated_false_positive_rate(gpa);
    defer rate.deinit();
    var one = try BigRational.one(gpa);
    defer one.deinit();
    try testing.expect(rate.is_positive());
    try testing.expectEqual(.lt, try rate.order(&one));
}

test "bloomfilter estimated count saturates when full" {
    var filter = try BloomFilter.init(gpa, 1, 1);
    defer filter.deinit(gpa);
    insert_index(&filter, 0);
    var count = try filter.estimated_count(gpa);
    defer count.deinit();
    var expected = try BigRational.from_u64(gpa, std.math.maxInt(u64));
    defer expected.deinit();
    try testing.expect(count.eql(&expected));
}

test "bloomfilter with_rate" {
    var fp_rate = try frac(1, 100);
    defer fp_rate.deinit();
    var filter = try BloomFilter.with_rate(gpa, 1000, &fp_rate);
    defer filter.deinit(gpa);
    const bits = try BloomFilter.optimal_bits(gpa, 1000, &fp_rate);
    try testing.expectEqual(bits, filter.bit_count());
    try testing.expectEqual(try BloomFilter.optimal_hashers(gpa, 1000, bits), filter.hashers);
    for (0..1000) |i| insert_index(&filter, i);
    for (0..1000) |i| try testing.expect(contains_index(&filter, i));
    var false_positives: u32 = 0;
    for (1000..2000) |i| {
        if (contains_index(&filter, i)) false_positives += 1;
    }
    // A 1% target gives about 10 of 1000; allow some variance.
    try testing.expect(false_positives < 20);

    var again = try BloomFilter.with_rate(gpa, 1000, &fp_rate);
    defer again.deinit(gpa);
    try testing.expectEqual(filter.bit_count(), again.bit_count());
    try testing.expectEqual(filter.hashers, again.hashers);
}

test "bloomfilter optimal hashers" {
    const optimal = BloomFilter.optimal_hashers;
    // (m / n) ln(2) = 6.93 truncates to 6.
    try testing.expectEqual(6, try optimal(gpa, 1000, 10000));
    try testing.expectEqual(6, try optimal(gpa, 100, 1000));
    try testing.expectEqual(1, try optimal(gpa, 1000, 100)); // Clamped up to 1.
    try testing.expectEqual(16, try optimal(gpa, 100, 100000)); // Clamped down to 16.
    try testing.expectEqual(1, try optimal(gpa, 0, 1000));
    try testing.expectEqual(1, try optimal(gpa, 1 << 48, 1000));
    const max = std.math.maxInt(u64);
    const k = try optimal(gpa, max, max);
    try testing.expect(k >= 1 and k <= 16);
}

test "bloomfilter optimal bits" {
    // -1000 log2(0.01) / ln(2) = 9585, rounded up to 16384.
    var fp_1pct = try frac(1, 100);
    defer fp_1pct.deinit();
    try testing.expectEqual(16384, try BloomFilter.optimal_bits(gpa, 1000, &fp_1pct));
    // -10000 log2(0.00001) / ln(2) = 239627, rounded up to 262144.
    var fp_low = try frac(1, 100_000);
    defer fp_low.deinit();
    try testing.expectEqual(262144, try BloomFilter.optimal_bits(gpa, 10000, &fp_low));
}

test "bloomfilter optimal bits at extreme values" {
    var fp_001pct = try frac(1, 10_000);
    defer fp_001pct.deinit();
    var fp_1pct = try frac(1, 100);
    defer fp_1pct.deinit();
    const huge = try BloomFilter.optimal_bits(gpa, std.math.maxInt(u64) / 2, &fp_001pct);
    try testing.expect(std.math.isPowerOfTwo(huge));
    const large = try BloomFilter.optimal_bits(gpa, 1_000_000_000, &fp_001pct);
    try testing.expect(std.math.isPowerOfTwo(large));
    try testing.expectEqual(1, try BloomFilter.optimal_bits(gpa, 0, &fp_1pct));
}

/// commonware's `RationalOptimalBits`: sizes for `seed % 1_000_000 + 1` items at several
/// rates, logged big-endian.
const RationalOptimalBits = struct {
    pub fn commit(allocator: std.mem.Allocator, seed: u64) ![]u8 {
        var log: std.ArrayList(u8) = .empty;
        errdefer log.deinit(allocator);
        const expected_items = seed % 1_000_000 + 1;
        const rates = [_][2]u64{ .{ 1, 10_000 }, .{ 1, 1_000 }, .{ 1, 100 }, .{ 1, 10 } };
        for (rates) |rate| {
            var fp_rate = try BigRational.from_frac_u64(allocator, rate[0], rate[1]);
            defer fp_rate.deinit();
            const bits = try BloomFilter.optimal_bits(allocator, expected_items, &fp_rate);
            const hashers = try BloomFilter.optimal_hashers(allocator, expected_items, bits);
            try append_u64(allocator, &log, expected_items);
            try append_u64(allocator, &log, bits);
            try log.append(allocator, hashers);
            var filter = try BloomFilter.with_rate(allocator, expected_items, &fp_rate);
            defer filter.deinit(allocator);
            try append_u64(allocator, &log, filter.bit_count());
            try log.append(allocator, filter.hashers);
        }
        const boundaries = [_][2]u64{ .{ 1, 7_000 }, .{ 1, 500 }, .{ 1, 50 }, .{ 3, 100 } };
        for (boundaries) |rate| {
            var fp_rate = try BigRational.from_frac_u64(allocator, rate[0], rate[1]);
            defer fp_rate.deinit();
            const bits = try BloomFilter.optimal_bits(allocator, expected_items, &fp_rate);
            try append_u64(allocator, &log, bits);
        }
        return log.toOwnedSlice(allocator);
    }

    fn append_u64(allocator: std.mem.Allocator, log: *std.ArrayList(u8), value: u64) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
        try log.appendSlice(allocator, &bytes);
    }
};

test "conformance: bloomfilter RationalOptimalBits" {
    try slow.skip_slow();
    const name = "commonware_cryptography::bloomfilter::conformance::RationalOptimalBits";
    const file = @embedFile("conformance.toml");
    const entry = (try conformance.find(file, name)).?;
    try conformance.verify(RationalOptimalBits, std.heap.smp_allocator, name, entry.n_cases, file);
}
