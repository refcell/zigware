//! Tests for the roaring set operations (commonware `utils/src/bitmap/roaring/ops.rs`).
//! Each result is checked against a dense bitset reference.

const std = @import("std");
const codec = @import("codec");
const roaring = @import("../roaring.zig");
const Bitmap = roaring.Bitmap;
const Kind = roaring.container.Kind;

const testing = std.testing;
const gpa = testing.allocator;
const unlimited = std.math.maxInt(u64);
const Reference = std.DynamicBitSetUnmanaged;

fn from(values: []const u64) !Bitmap {
    var result: Bitmap = .empty;
    errdefer result.deinit(gpa);
    for (values) |value| _ = try result.insert(gpa, value);
    return result;
}

/// `count` values `value_first + index * step`.
fn strided(value_first: u64, step: u64, count: u64) !Bitmap {
    var result: Bitmap = .empty;
    errdefer result.deinit(gpa);
    for (0..count) |index| _ = try result.insert(gpa, value_first + index * step);
    return result;
}

fn expect_kind(bitmap: *const Bitmap, kind: Kind) !void {
    try testing.expectEqual(kind, std.meta.activeTag(bitmap.get(0).?.*));
}

fn reference_len(a: *const Bitmap, b: *const Bitmap) usize {
    const top = @max(a.max() orelse 0, b.max() orelse 0);
    return if (a.is_empty() and b.is_empty()) 0 else @intCast(top + 1);
}

fn build_reference(bitmap: *const Bitmap, len: usize) !Reference {
    var reference = try Reference.initEmpty(gpa, len);
    var it = bitmap.iter();
    while (it.next()) |value| reference.set(@intCast(value));
    return reference;
}

const Op = enum { @"union", intersection, difference };

/// Runs `op` and checks it against the reference; returns the result.
fn check(a: *const Bitmap, b: *const Bitmap, comptime op: Op, limit: u64) !Bitmap {
    const len = reference_len(a, b);
    var reference = try build_reference(a, len);
    defer reference.deinit(gpa);
    var other = try build_reference(b, len);
    defer other.deinit(gpa);
    switch (op) {
        .@"union" => reference.setUnion(other),
        .intersection => reference.setIntersection(other),
        .difference => {
            other.toggleAll();
            reference.setIntersection(other);
        },
    }
    var result = switch (op) {
        .@"union" => try a.@"union"(b, gpa, limit),
        .intersection => try a.intersection(b, gpa, limit),
        .difference => try a.difference(b, gpa, limit),
    };
    errdefer result.deinit(gpa);

    var it = result.iter();
    var expected = reference.iterator(.{});
    var count: u64 = 0;
    while (count < limit) : (count += 1) {
        const value = expected.next() orelse break;
        try testing.expectEqual(@as(?u64, value), it.next());
    }
    try testing.expectEqual(@as(?u64, null), it.next());
    try testing.expectEqual(count, result.len());
    return result;
}

fn check_free(a: *const Bitmap, b: *const Bitmap, comptime op: Op, limit: u64) !void {
    var result = try check(a, b, op, limit);
    result.deinit(gpa);
}

fn check_subset(a: *const Bitmap, b: *const Bitmap) !bool {
    var it = a.iter();
    var expected = true;
    while (it.next()) |value| expected = expected and b.contains(value);
    try testing.expectEqual(expected, a.is_subset(b));
    return expected;
}

fn check_intersects(a: *const Bitmap, b: *const Bitmap) !bool {
    var it = a.iter();
    var expected = false;
    while (it.next()) |value| expected = expected or b.contains(value);
    try testing.expectEqual(expected, a.intersects(b));
    return expected;
}

test "roaring ops: union" {
    var a = try from(&.{ 1, 2, 3 });
    defer a.deinit(gpa);
    var b = try from(&.{ 2, 3, 4, 5 });
    defer b.deinit(gpa);
    var c = try from(&.{ 4, 5, 6 });
    defer c.deinit(gpa);
    var high = try from(&.{ 65_536, 65_537, 65_538 });
    defer high.deinit(gpa);
    const none: Bitmap = .empty;
    try check_free(&a, &b, .@"union", unlimited);
    try check_free(&a, &c, .@"union", 4);
    try check_free(&none, &a, .@"union", unlimited);
    try check_free(&a, &high, .@"union", unlimited);
    try check_free(&high, &a, .@"union", unlimited);
    try check_free(&a, &high, .@"union", 2);

    var d = try from(&.{ 10, 2 * 65_536 + 10 });
    defer d.deinit(gpa);
    var e = try from(&.{ 65_536 + 20, 3 * 65_536 + 20 });
    defer e.deinit(gpa);
    var alternating = try check(&d, &e, .@"union", unlimited);
    defer alternating.deinit(gpa);
    try testing.expectEqual(4, alternating.container_count());

    var f = try from(&.{ 100, 65_536 + 100 });
    defer f.deinit(gpa);
    var g = try from(&.{ 200, 65_536 + 200 });
    defer g.deinit(gpa);
    try check_free(&f, &g, .@"union", unlimited);
}

test "roaring ops: oversized array union promotes to a bitmap container" {
    var a = try strided(0, 4, 4000);
    defer a.deinit(gpa);
    var b = try strided(1, 4, 4000);
    defer b.deinit(gpa);
    try expect_kind(&a, .array);
    try expect_kind(&b, .array);
    var result = try check(&a, &b, .@"union", unlimited);
    defer result.deinit(gpa);
    try expect_kind(&result, .bitmap);

    const encoded = try codec.encode(Bitmap, gpa, result);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(Bitmap, gpa, encoded, .to_inclusive(10));
    defer decoded.deinit(gpa);
    try testing.expect(result.eql(&decoded));
}

test "roaring ops: bitmap-bitmap and mixed container paths" {
    var evens = try strided(0, 2, 4097);
    defer evens.deinit(gpa);
    var odds = try strided(1, 2, 4097);
    defer odds.deinit(gpa);
    var fours = try strided(0, 4, 4097);
    defer fours.deinit(gpa);
    var shifted = try strided(200, 2, 4097);
    defer shifted.deinit(gpa);
    var small = try from(&.{ 1, 50, 100 });
    defer small.deinit(gpa);
    var small_overlap = try from(&.{ 1, 50, 200 });
    defer small_overlap.deinit(gpa);
    try expect_kind(&evens, .bitmap);
    try expect_kind(&odds, .bitmap);
    try expect_kind(&fours, .bitmap);
    try expect_kind(&shifted, .bitmap);
    try expect_kind(&small, .array);

    try check_free(&evens, &odds, .@"union", unlimited);
    try check_free(&evens, &odds, .@"union", 100);
    try check_free(&small, &shifted, .@"union", unlimited);
    try check_free(&evens, &fours, .intersection, unlimited);
    try check_free(&evens, &fours, .intersection, 50);
    try check_free(&small_overlap, &shifted, .intersection, unlimited);
    try check_free(&evens, &fours, .difference, unlimited);
    try check_free(&evens, &fours, .difference, 30);
    try check_free(&small_overlap, &shifted, .difference, unlimited);
}

test "roaring ops: intersection and difference" {
    var a = try from(&.{ 1, 2, 3, 4 });
    defer a.deinit(gpa);
    var b = try from(&.{ 2, 3, 4, 5 });
    defer b.deinit(gpa);
    var five = try from(&.{ 1, 2, 3, 4, 5 });
    defer five.deinit(gpa);
    var low = try from(&.{ 1, 2, 3 });
    defer low.deinit(gpa);
    var high = try from(&.{ 4, 5, 6 });
    defer high.deinit(gpa);
    var pair = try from(&.{ 2, 3 });
    defer pair.deinit(gpa);
    var even_pair = try from(&.{ 2, 4 });
    defer even_pair.deinit(gpa);
    try check_free(&a, &b, .intersection, unlimited);
    try check_free(&five, &five, .intersection, 3);
    try check_free(&low, &high, .intersection, unlimited);
    try check_free(&a, &pair, .difference, unlimited);
    try check_free(&five, &even_pair, .difference, 2);
    try check_free(&low, &five, .difference, unlimited);

    var c = try from(&.{ 100, 200, 65_536 + 100 });
    defer c.deinit(gpa);
    var d = try from(&.{ 200, 300, 65_536 + 100 });
    defer d.deinit(gpa);
    try check_free(&c, &d, .intersection, unlimited);
}

test "roaring ops: zero limit" {
    var a = try from(&.{ 1, 2, 3 });
    defer a.deinit(gpa);
    var b = try from(&.{ 2, 3, 4 });
    defer b.deinit(gpa);
    try check_free(&a, &b, .@"union", 0);
    try check_free(&a, &b, .intersection, 0);
    try check_free(&a, &b, .difference, 0);
}

test "roaring ops: is_subset" {
    var a = try from(&.{ 1, 2, 3 });
    defer a.deinit(gpa);
    var b = try from(&.{ 1, 2, 3, 4, 5 });
    defer b.deinit(gpa);
    var same = try from(&.{ 1, 2, 3 });
    defer same.deinit(gpa);
    var gap = try from(&.{ 1, 3 });
    defer gap.deinit(gpa);
    var other_container = try from(&.{ 1, 65_536 + 100 });
    defer other_container.deinit(gpa);
    var pair = try from(&.{ 1, 2 });
    defer pair.deinit(gpa);
    const none: Bitmap = .empty;
    try testing.expect(try check_subset(&a, &b));
    try testing.expect(!try check_subset(&b, &a));
    try testing.expect(try check_subset(&a, &same));
    try testing.expect(try check_subset(&none, &a));
    try testing.expect(try check_subset(&none, &none));
    try testing.expect(!try check_subset(&a, &none));
    try testing.expect(!try check_subset(&a, &gap));
    try testing.expect(!try check_subset(&other_container, &a));
    try testing.expect(!try check_subset(&b, &pair));

    var c = try from(&.{ 100, 65_536 + 50, 131_072 + 7 });
    defer c.deinit(gpa);
    var d = try from(&.{ 50, 100, 65_536 + 50, 65_536 + 100, 131_072 + 7, 131_072 + 8 });
    defer d.deinit(gpa);
    try testing.expect(try check_subset(&c, &d));
    try testing.expect(!try check_subset(&d, &c));
}

test "roaring ops: intersects" {
    var a = try from(&.{ 1, 2, 3 });
    defer a.deinit(gpa);
    var b = try from(&.{ 3, 4, 5 });
    defer b.deinit(gpa);
    var c = try from(&.{ 4, 5, 6 });
    defer c.deinit(gpa);
    const none: Bitmap = .empty;
    try testing.expect(try check_intersects(&a, &b));
    try testing.expect(try check_intersects(&b, &a));
    try testing.expect(!try check_intersects(&a, &c));
    try testing.expect(!try check_intersects(&c, &a));
    try testing.expect(!try check_intersects(&none, &a));
    try testing.expect(!try check_intersects(&a, &none));
    try testing.expect(!try check_intersects(&none, &none));
    try testing.expect(try check_intersects(&a, &a));

    var d = try from(&.{ 100, 65_536 + 50 });
    defer d.deinit(gpa);
    var e = try from(&.{ 200, 65_536 + 50 });
    defer e.deinit(gpa);
    var f = try from(&.{ 200, 65_536 + 99 });
    defer f.deinit(gpa);
    var g = try from(&.{100});
    defer g.deinit(gpa);
    var h = try from(&.{65_536 + 50});
    defer h.deinit(gpa);
    try testing.expect(try check_intersects(&d, &e));
    try testing.expect(try check_intersects(&e, &d));
    try testing.expect(!try check_intersects(&d, &f));
    try testing.expect(!try check_intersects(&f, &d));
    try testing.expect(!try check_intersects(&g, &h));
}

const Case = struct { a: []const u64, b: []const u64 };

test "roaring ops: intersects iff the intersection is non-empty" {
    const cases = [_]Case{
        .{ .a = &.{ 1, 2, 3 }, .b = &.{ 3, 4, 5 } },
        .{ .a = &.{ 1, 2, 3 }, .b = &.{ 4, 5, 6 } },
        .{ .a = &.{}, .b = &.{ 1, 2, 3 } },
        .{ .a = &.{ 1, 65_536 + 50 }, .b = &.{ 100, 65_536 + 50 } },
        .{ .a = &.{ 1, 65_536 + 50 }, .b = &.{ 100, 65_536 + 99 } },
    };
    for (cases) |case| {
        var a = try from(case.a);
        defer a.deinit(gpa);
        var b = try from(case.b);
        defer b.deinit(gpa);
        var result = try check(&a, &b, .intersection, unlimited);
        defer result.deinit(gpa);
        try testing.expectEqual(!result.is_empty(), try check_intersects(&a, &b));
    }
}

test "roaring ops: is_subset iff the difference is empty" {
    const cases = [_]Case{
        .{ .a = &.{ 1, 2 }, .b = &.{ 1, 2, 3 } },
        .{ .a = &.{ 1, 2, 3 }, .b = &.{ 1, 2 } },
        .{ .a = &.{}, .b = &.{ 1, 2, 3 } },
        .{ .a = &.{ 1, 2, 3 }, .b = &.{} },
        .{ .a = &.{ 1, 65_536 + 50 }, .b = &.{ 1, 65_536 + 50, 131_072 } },
    };
    for (cases) |case| {
        var a = try from(case.a);
        defer a.deinit(gpa);
        var b = try from(case.b);
        defer b.deinit(gpa);
        var result = try check(&a, &b, .difference, unlimited);
        defer result.deinit(gpa);
        try testing.expectEqual(result.is_empty(), try check_subset(&a, &b));
    }
}
