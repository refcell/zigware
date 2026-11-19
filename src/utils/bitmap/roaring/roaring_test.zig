//! Tests for the roaring `Bitmap` (commonware `utils/src/bitmap/roaring/mod.rs` tests).

const std = @import("std");
const codec = @import("codec");
const roaring = @import("../roaring.zig");
const Bitmap = roaring.Bitmap;
const Container = roaring.Container;

const testing = std.testing;
const gpa = testing.allocator;

fn from(values: []const u64) !Bitmap {
    return Bitmap.from_values(gpa, values);
}

fn expect_values(iterator: Bitmap.Iterator, expected: []const u64) !void {
    var it = iterator;
    for (expected) |value| try testing.expectEqual(@as(?u64, value), it.next());
    try testing.expectEqual(@as(?u64, null), it.next());
}

fn roundtrip(bitmap: *const Bitmap, cfg: Bitmap.Cfg) !void {
    const encoded = try codec.encode(Bitmap, gpa, bitmap.*);
    defer gpa.free(encoded);
    try testing.expectEqual(bitmap.encode_size(), encoded.len);
    var decoded = try codec.decode_cfg(Bitmap, gpa, encoded, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(bitmap));
}

test "roaring: insert, contains, iterate, min, max, clear" {
    var bitmap: Bitmap = .empty;
    defer bitmap.deinit(gpa);
    try testing.expect(bitmap.is_empty() and bitmap.min() == null and bitmap.max() == null);
    for ([_]u64{ 42, 100, 1_000_000 }) |value| try testing.expect(try bitmap.insert(gpa, value));
    try testing.expect(!try bitmap.insert(gpa, 42));
    try testing.expectEqual(@as(u64, 3), bitmap.len());
    try testing.expect(bitmap.contains(1_000_000) and !bitmap.contains(50));
    _ = try bitmap.insert(gpa, 5);
    try expect_values(bitmap.iter(), &.{ 5, 42, 100, 1_000_000 });
    try testing.expectEqual(@as(?u64, 5), bitmap.min());
    try testing.expectEqual(@as(?u64, 1_000_000), bitmap.max());
    bitmap.clear(gpa);
    try testing.expect(bitmap.is_empty());

    const large = @as(u64, 1) << 40;
    var big = try from(&.{ large, large + 1, large + 1000, std.math.maxInt(u64) });
    defer big.deinit(gpa);
    try testing.expect(big.contains(large + 1) and !big.contains(large + 2));
    try expect_values(big.iter(), &.{ large, large + 1, large + 1000, std.math.maxInt(u64) });
    var multi = try from(&.{ 1, 65_537, 131_073, 1_000_000, 100, 5, 100 });
    defer multi.deinit(gpa);
    try testing.expectEqual(@as(usize, 4), multi.container_count());
    try testing.expectEqual(@as(u64, 6), multi.len());
}

test "roaring: insert_range and iter_range" {
    var bitmap: Bitmap = .empty;
    defer bitmap.deinit(gpa);
    try testing.expectEqual(@as(u64, 100), try bitmap.insert_range(gpa, 100, 200));
    try testing.expect(bitmap.contains(100) and bitmap.contains(199) and !bitmap.contains(200));
    var spanning: Bitmap = .empty;
    defer spanning.deinit(gpa);
    try testing.expectEqual(@as(u64, 20), try spanning.insert_range(gpa, 65530, 65550));
    for (65530..65550) |value| try testing.expect(spanning.contains(value));

    var hundred: Bitmap = .empty;
    defer hundred.deinit(gpa);
    _ = try hundred.insert_range(gpa, 0, 100);
    var it = hundred.iter_range(25, 75);
    var count: u64 = 0;
    while (it.next()) |value| : (count += 1) try testing.expectEqual(25 + count, value);
    try testing.expectEqual(@as(u64, 50), count);

    var two = try from(&.{ 1, 70_000 });
    defer two.deinit(gpa);
    try expect_values(two.iter_range(70_000, 10), &.{});
    try expect_values(two.iter_range(1, 70_001), &.{ 1, 70_000 });
    try expect_values(two.iter_range(2, 70_000), &.{});
}

test "roaring: insert_range at container boundaries" {
    const cases = [_][2]u64{ .{ 0, 65536 }, .{ 65000, 65536 }, .{ 65530, 131072 } };
    for (cases) |case| {
        var bitmap: Bitmap = .empty;
        defer bitmap.deinit(gpa);
        try testing.expectEqual(case[1] - case[0], try bitmap.insert_range(gpa, case[0], case[1]));
        try testing.expectEqual(case[1] - case[0], bitmap.len());
        try testing.expect(bitmap.contains(case[0]) and bitmap.contains(case[1] - 1));
        try testing.expect(!bitmap.contains(case[1]));
    }
    const start: u64 = 18446744071497449473;
    const end = start +| 65535;
    var crash: Bitmap = .empty;
    defer crash.deinit(gpa);
    try testing.expectEqual(end - start, try crash.insert_range(gpa, start, end));
    try testing.expectEqual(end - start, crash.len());
}

test "roaring: codec roundtrips" {
    var empty: Bitmap = .empty;
    try roundtrip(&empty, .full());
    var sparse = try from(&.{ 42, 100, 1_000_000 });
    defer sparse.deinit(gpa);
    try roundtrip(&sparse, .full());
    var dense: Bitmap = .empty;
    defer dense.deinit(gpa);
    _ = try dense.insert_range(gpa, 0, 5000);
    try roundtrip(&dense, .full());

    var mixed: Bitmap = .empty;
    defer mixed.deinit(gpa);
    for (0..20) |shelf| {
        for (0..100) |i| _ = try mixed.insert(gpa, shelf * 65_536 + i * 500);
    }
    for (20..40) |shelf| {
        for (0..5_000) |i| _ = try mixed.insert(gpa, shelf * 65_536 + i * 2);
    }
    for (40..60) |shelf| _ = try mixed.insert_range(gpa, shelf * 65_536, shelf * 65_536 + 50_000);
    try testing.expectEqual(@as(usize, 60), mixed.container_count());
    const counts = mixed.container_variant_counts();
    try testing.expect(counts[0] > 0 and counts[1] > 0 and counts[2] > 0);
    try roundtrip(&mixed, .to_inclusive(1000));
    try testing.expect(mixed.encode_size() >= 8192);
}

test "roaring: codec container limit and invalid keys" {
    var three = try from(&.{ 0, 65536, 131072 });
    defer three.deinit(gpa);
    try roundtrip(&three, .to_inclusive(3));
    const encoded = try codec.encode(Bitmap, gpa, three);
    defer gpa.free(encoded);
    const limited = codec.decode_cfg(Bitmap, gpa, encoded, .to_inclusive(2));
    try testing.expectError(error.InvalidLength, limited);

    // Key 2^48: one container holding 0 (array).
    const out_of_range = [_]u8{ 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 };
    var reader = codec.Reader.init(&out_of_range);
    const bad_key = codec.decode_reader(Bitmap, gpa, &reader, .to_inclusive(10));
    try testing.expectError(error.Invalid, bad_key);
    try testing.expectEqualStrings("container key exceeds 48-bit range", reader.diagnostic.message);

    const empty_container = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    reader = codec.Reader.init(&empty_container);
    const empty = codec.decode_reader(Bitmap, gpa, &reader, .full());
    try testing.expectError(error.Invalid, empty);
    try testing.expectEqualStrings("empty container", reader.diagnostic.message);

    // The largest key is accepted.
    const max_key = [_]u8{ 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 0, 42 };
    var decoded = try codec.decode_cfg(Bitmap, gpa, &max_key, .full());
    defer decoded.deinit(gpa);
    try testing.expect(decoded.contains(roaring.combine(roaring.MAX_KEY, 42)));
}

test "roaring: high and low bits" {
    try testing.expectEqual(@as(u64, 0), roaring.high_bits(65535));
    try testing.expectEqual(@as(u16, 65535), roaring.low_bits(65535));
    try testing.expectEqual(@as(u64, 1), roaring.high_bits(65536));
    try testing.expectEqual(roaring.MAX_KEY, roaring.high_bits(std.math.maxInt(u64)));
    try testing.expectEqual(@as(u16, 65535), roaring.low_bits(std.math.maxInt(u64)));
    try testing.expectEqual(@as(u64, 65537), roaring.combine(1, 1));
}

test "roaring: collect from values (test_from_iter_*)" {
    // commonware `test_from_iter_empty`, `test_from_iter_basic`,
    // `test_from_iter_unsorted_with_duplicates`, `test_from_iter_multi_container`.
    var empty = try from(&.{});
    defer empty.deinit(gpa);
    try testing.expect(empty.is_empty());
    var basic = try from(&.{ 5, 10, 15, 100 });
    defer basic.deinit(gpa);
    try testing.expectEqual(@as(u64, 4), basic.len());
    try expect_values(basic.iter(), &.{ 5, 10, 15, 100 });
    var unsorted = try from(&.{ 100, 5, 100, 50, 5, 10 });
    defer unsorted.deinit(gpa);
    try testing.expectEqual(@as(u64, 4), unsorted.len());
    try expect_values(unsorted.iter(), &.{ 5, 10, 50, 100 });
    var multi = try from(&.{ 1, 65_537, 131_073, 1_000_000 });
    defer multi.deinit(gpa);
    try testing.expectEqual(@as(u64, 4), multi.len());
    try testing.expectEqual(@as(usize, 4), multi.container_count());
}

test "roaring: collect a range expression (test_from_iter_range_expression)" {
    var values: [1000]u64 = undefined;
    for (&values, 0..) |*value, index| value.* = index;
    var bitmap = try from(&values);
    defer bitmap.deinit(gpa);
    try testing.expectEqual(@as(u64, 1000), bitmap.len());
    try testing.expect(bitmap.contains(0) and bitmap.contains(999) and !bitmap.contains(1000));
}

test "roaring: extend into an existing bitmap (test_extend_into_existing)" {
    var bitmap = try from(&.{ 1, 2, 3 });
    defer bitmap.deinit(gpa);
    try bitmap.extend(gpa, &.{ 3, 4, 5 });
    try expect_values(bitmap.iter(), &.{ 1, 2, 3, 4, 5 });
}
