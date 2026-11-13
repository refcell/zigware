//! Tests for the roaring `Prunable` (commonware `utils/src/bitmap/roaring/prunable.rs`).
//! commonware's `should_panic` tests (insert, contains, insert_range, iter_range, and
//! extend below the watermark) are assertions here and are not run.

const std = @import("std");
const codec = @import("codec");
const roaring = @import("../roaring.zig");
const Prunable = roaring.Prunable;
const Bitmap = roaring.Bitmap;

const testing = std.testing;
const gpa = testing.allocator;

fn expect_values(iterator: Prunable.Iterator, expected: []const u64) !void {
    var it = iterator;
    for (expected) |value| try testing.expectEqual(@as(?u64, value), it.next());
    try testing.expectEqual(@as(?u64, null), it.next());
}

fn roundtrip(p: *const Prunable) !void {
    const encoded = try codec.encode(Prunable, gpa, p.*);
    defer gpa.free(encoded);
    try testing.expectEqual(p.encode_size(), encoded.len);
    var decoded = try codec.decode_cfg(Prunable, gpa, encoded, .full());
    defer decoded.deinit(gpa);
    try testing.expect(p.eql(&decoded));
}

test "roaring prunable: new and empty" {
    const p: Prunable = .empty;
    try testing.expect(p.is_empty());
    try testing.expectEqual(0, p.len());
    try testing.expectEqual(0, p.pruned_below());
}

test "roaring prunable: insert and contains" {
    var p: Prunable = .empty;
    defer p.deinit(gpa);
    try testing.expect(try p.insert(gpa, 42));
    try testing.expect(try p.insert(gpa, 1_000_000));
    try testing.expect(!try p.insert(gpa, 42));
    try testing.expect(p.contains(42));
    try testing.expect(p.contains(1_000_000));
    try testing.expect(!p.contains(43));
    try testing.expectEqual(2, p.len());
}

test "roaring prunable: prune drops containers" {
    var p = try Prunable.from_values(gpa, &.{ 100, 70_000, 140_000, 330_000 });
    defer p.deinit(gpa);
    try testing.expectEqual(4, p.len());
    try testing.expectEqual(131_072, p.prune(gpa, 131_072));
    try testing.expectEqual(131_072, p.pruned_below());
    try testing.expectEqual(2, p.len());
    try testing.expect(p.contains(140_000));
    try testing.expect(p.contains(330_000));
}

test "roaring prunable: prune rounds down and the boundary container lingers" {
    var p = try Prunable.from_values(gpa, &.{ 100, 70_000 });
    defer p.deinit(gpa);
    try testing.expectEqual(65_536, p.prune(gpa, 70_000));
    try testing.expectEqual(65_536, p.pruned_below());
    try testing.expectEqual(1, p.len());
    try testing.expect(p.contains(70_000));

    var q = try Prunable.from_values(gpa, &.{ 65_500, 70_000 });
    defer q.deinit(gpa);
    _ = q.prune(gpa, 70_000);
    try testing.expect(!q.bitmap.contains(65_500));
    try testing.expect(q.contains(70_000));
}

test "roaring prunable: prune below the watermark and prune zero are no-ops" {
    var p = try Prunable.from_values(gpa, &.{70_000});
    defer p.deinit(gpa);
    _ = p.prune(gpa, 65_536);
    try testing.expectEqual(65_536, p.pruned_below());
    try testing.expectEqual(65_536, p.prune(gpa, 0));
    try testing.expectEqual(65_536, p.pruned_below());

    var q = try Prunable.from_values(gpa, &.{100});
    defer q.deinit(gpa);
    try testing.expectEqual(0, q.prune(gpa, 0));
    try testing.expectEqual(0, q.pruned_below());
    try testing.expectEqual(1, q.len());
}

test "roaring prunable: prune then insert above" {
    var p: Prunable = .empty;
    defer p.deinit(gpa);
    _ = p.prune(gpa, 131_072);
    _ = try p.insert(gpa, 200_000);
    try testing.expect(p.contains(200_000));
    try testing.expectEqual(1, p.len());
}

test "roaring prunable: empty ranges below the watermark" {
    var p = try Prunable.from_values(gpa, &.{200_000});
    defer p.deinit(gpa);
    _ = p.prune(gpa, 131_072);
    try testing.expectEqual(0, try p.insert_range(gpa, 50, 50));
    try testing.expectEqual(0, try p.insert_range(gpa, 50, 10));
    try testing.expectEqual(1, p.len());
    try expect_values(p.iter_range(50, 50), &.{});
    try expect_values(p.iter_range(50, 10), &.{});
}

test "roaring prunable: iter, clear, from_values, and extend" {
    var p = try Prunable.from_values(gpa, &.{ 200_000, 100, 70_000, 5 });
    defer p.deinit(gpa);
    _ = p.prune(gpa, 131_072);
    try expect_values(p.iter(), &.{200_000});
    try expect_values(p.iter_range(131_072, 200_001), &.{200_000});

    try p.extend(gpa, &.{ 200_001, 300_000 });
    try testing.expectEqual(3, p.len());
    try testing.expect(p.contains(200_001));

    p.clear(gpa);
    try testing.expect(p.is_empty());
    try testing.expectEqual(131_072, p.pruned_below());

    var q = try Prunable.from_values(gpa, &.{ 5, 10, 100, 65_537 });
    defer q.deinit(gpa);
    try testing.expectEqual(4, q.len());
    try testing.expectEqual(0, q.pruned_below());
    try testing.expect(q.contains(5) and q.contains(65_537));

    var none = try Prunable.from_values(gpa, &.{});
    defer none.deinit(gpa);
    try testing.expect(none.is_empty());
}

test "roaring prunable: codec roundtrip" {
    const empty: Prunable = .empty;
    try roundtrip(&empty);
    var p = try Prunable.from_values(gpa, &.{ 200_000, 300_000, 1_000_000 });
    defer p.deinit(gpa);
    _ = p.prune(gpa, 131_072);
    try roundtrip(&p);

    // The watermark comes first, big-endian.
    const encoded = try codec.encode(Prunable, gpa, p);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 2, 0, 0 }, encoded[0..8]);
}

fn expect_invalid(watermark: u64, values: []const u64, message: []const u8) !void {
    var bitmap: Bitmap = .empty;
    defer bitmap.deinit(gpa);
    for (values) |value| _ = try bitmap.insert(gpa, value);
    const tail = try codec.encode(Bitmap, gpa, bitmap);
    defer gpa.free(tail);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, watermark, .big);
    const encoded = try std.mem.concat(gpa, u8, &.{ &bytes, tail });
    defer gpa.free(encoded);

    var reader = codec.Reader.init(encoded);
    const result = codec.decode_reader(Prunable, gpa, &reader, .full());
    try testing.expectError(error.Invalid, result);
    try testing.expectEqualStrings(message, reader.diagnostic.message);
}

test "roaring prunable: codec rejects a misaligned watermark or a container below it" {
    try expect_invalid(100, &.{}, "pruned_below must be a multiple of 65536");
    try expect_invalid(131_072, &.{50}, "container key below pruned_below");
}

test "roaring prunable: encode size" {
    const empty: Prunable = .empty;
    const bitmap_empty: Bitmap = .empty;
    try testing.expectEqual(8 + bitmap_empty.encode_size(), empty.encode_size());

    var p = try Prunable.from_values(gpa, &.{ 100, 65_537, 131_073 });
    defer p.deinit(gpa);
    try testing.expect(p.encode_size() > empty.encode_size());

    var q = try Prunable.from_values(gpa, &.{200_000});
    defer q.deinit(gpa);
    const before = q.encode_size();
    _ = q.prune(gpa, 0);
    try testing.expectEqual(before, q.encode_size());
}
