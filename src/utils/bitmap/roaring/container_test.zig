//! Tests for roaring `Container` (commonware `bitmap/roaring/container/mod.rs` tests),
//! including the `ContainerTransitionsConformance` commit.

const std = @import("std");
const codec = @import("codec");
const Container = @import("container.zig").Container;
const container_mod = @import("container.zig");
const MAX_CARDINALITY = @import("array.zig").MAX_CARDINALITY;

const testing = std.testing;
const gpa = testing.allocator;

fn expect_roundtrip(container: *const Container) ![]u8 {
    const encoded = try codec.encode(Container, gpa, container.*);
    errdefer gpa.free(encoded);
    var decoded = try codec.decode(Container, gpa, encoded);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(container));
    try testing.expectEqual(container.encode_size(), encoded.len);
    return encoded;
}

test "roaring container: transitions" {
    var container: Container = .empty;
    defer container.deinit(gpa);
    for (0..MAX_CARDINALITY) |i| _ = try container.insert(gpa, @intCast(i * 2));
    try testing.expect(container == .array);
    _ = try container.insert(gpa, 9000);
    try testing.expect(container == .bitmap);
    _ = try container.insert_range(gpa, 0, 65535);
    try testing.expect(container == .run);
    try testing.expectEqual(@as(u32, 65535), container.len());
    _ = try container.insert(gpa, 65535);
    try testing.expectEqual(@as(u32, 65536), container.len());

    var long: Container = .empty;
    defer long.deinit(gpa);
    try testing.expectEqual(@as(u32, 100), try long.insert_range(gpa, 0, 100));
    try testing.expect(long == .run);
    var short: Container = .empty;
    defer short.deinit(gpa);
    try testing.expectEqual(@as(u32, 10), try short.insert_range(gpa, 0, 10));
    try testing.expect(short == .array);
    try testing.expectEqual(@as(u32, 4100), try short.insert_range(gpa, 0, 4100) + 10);
}

test "roaring container: set operations across kinds" {
    var sparse: Container = .empty;
    defer sparse.deinit(gpa);
    for ([_]u16{ 1, 5, 9, 70 }) |value| _ = try sparse.insert(gpa, value);
    var runs: Container = .empty;
    defer runs.deinit(gpa);
    _ = try runs.insert_range(gpa, 0, 64);
    try testing.expect(runs == .run);
    const max = std.math.maxInt(u64);
    var union_result = try Container.combine(&sparse, &runs, gpa, max, .@"union");
    defer union_result.container.deinit(gpa);
    try testing.expectEqual(@as(u64, 65), union_result.count);
    var inter = try Container.combine(&sparse, &runs, gpa, max, .intersection);
    defer inter.container.deinit(gpa);
    try testing.expectEqual(@as(u64, 3), inter.count);
    var diff = try Container.combine(&sparse, &runs, gpa, 1, .difference);
    defer diff.container.deinit(gpa);
    try testing.expectEqual(@as(u64, 1), diff.count);
    try testing.expect(diff.container.contains(70));
    try testing.expect(inter.container.is_subset(&sparse) and !sparse.is_subset(&runs));
    try testing.expect(sparse.intersects(&runs));
    var limited = try runs.limit(gpa, 10);
    defer limited.container.deinit(gpa);
    try testing.expectEqual(@as(u32, 10), limited.container.len());
    try testing.expectEqual(@as(?u16, 9), limited.container.max());
}

test "roaring container: canonical encoding and rejection" {
    var sparse: Container = .empty;
    defer sparse.deinit(gpa);
    _ = try sparse.insert(gpa, 3);
    const encoded = try expect_roundtrip(&sparse);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 0, 3 }, encoded);

    // A run of 1000 values encodes as a run even when held as an array.
    var array: Container = .empty;
    defer array.deinit(gpa);
    for (0..1000) |i| _ = try array.insert(gpa, @intCast(i));
    try testing.expect(array == .array);
    try testing.expectEqual(container_mod.Kind.run, array.canonical_kind());
    const as_run = try expect_roundtrip(&array);
    defer gpa.free(as_run);
    try testing.expectEqualSlices(u8, &.{ 2, 1, 0, 0, 3, 0xE7 }, as_run);

    // The same values written as an array are not canonical.
    const values = try gpa.alloc(u16, 1000);
    defer gpa.free(values);
    for (values, 0..) |*value, i| value.* = @intCast(i);
    const payload = try codec.encode([]const u16, gpa, values);
    defer gpa.free(payload);
    const bytes = try std.mem.concat(gpa, u8, &.{ &.{0}, payload });
    defer gpa.free(bytes);
    var reader = codec.Reader.init(bytes);
    try testing.expectError(error.Invalid, codec.decode_reader(Container, gpa, &reader, {}));
    try testing.expectEqualStrings("Container", reader.diagnostic.context);
    try testing.expectError(error.InvalidEnum, codec.decode(Container, gpa, &.{ 3, 0 }));
    // 2049 runs need more than 8192 bytes: rejected from the count alone.
    var huge = [_]u8{ 2, 0x81, 0x10 };
    try testing.expectError(error.Invalid, codec.decode(Container, gpa, &huge));
}

fn append_snapshot(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    container: *const Container,
) !void {
    const encoded = try expect_roundtrip(container);
    defer gpa.free(encoded);
    try out.append(allocator, @backingInt(container.*));
    var length: [4]u8 = undefined;
    std.mem.writeInt(u32, &length, @intCast(encoded.len), .big);
    try out.appendSlice(allocator, &length);
    try out.appendSlice(allocator, encoded);
}

/// commonware's `ContainerTransitionsConformance`: walks containers through every
/// transition and records each snapshot's kind and canonical encoding.
pub const TransitionsConformance = struct {
    pub fn commit(allocator: std.mem.Allocator, seed: u64) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        var up: Container = .empty;
        defer up.deinit(gpa);
        _ = try up.insert_range(gpa, 0, @intCast(5000 + seed % 1000));
        try std.testing.expect(up == .run);
        try append_snapshot(allocator, &out, &up);
        const extra_runs = container_mod.RUN_TO_BITMAP_THRESHOLD + 64 + seed % 128;
        var value: u16 = 10_001;
        for (0..extra_runs) |_| {
            _ = try up.insert(gpa, value);
            value += 2;
        }
        try std.testing.expect(up == .bitmap);
        try append_snapshot(allocator, &out, &up);
        _ = try up.insert_range(gpa, 0, 65535);
        try std.testing.expect(up == .run);
        try append_snapshot(allocator, &out, &up);

        var down: Container = .empty;
        defer down.deinit(gpa);
        for (0..MAX_CARDINALITY + 1) |i| _ = try down.insert(gpa, @intCast(i * 2));
        try std.testing.expect(down == .bitmap);
        try append_snapshot(allocator, &out, &down);
        _ = try down.insert_range(gpa, 0, 65535);
        try std.testing.expect(down == .run);
        try append_snapshot(allocator, &out, &down);
        return out.toOwnedSlice(allocator);
    }
};

const Bitmap = @import("bitmap.zig").Bitmap;
const WORDS = @import("bitmap.zig").WORDS;
const Array = @import("array.zig").Array;
const Run = @import("run.zig").Run;

/// A container holding `bitmap` as its bitmap kind, whatever its contents.
fn bitmap_container(bitmap: Bitmap) !Container {
    const boxed = try gpa.create(Bitmap);
    boxed.* = bitmap;
    return .{ .bitmap = boxed };
}

fn expect_values(container: *const Container, expected: []const u16) !void {
    var it = container.iter();
    for (expected) |value| try testing.expectEqual(@as(?u16, value), it.next());
    try testing.expectEqual(@as(?u16, null), it.next());
}

/// Decodes `container`'s encoding and checks its kind and values.
fn expect_decoded(container: *const Container, kind: container_mod.Kind) !Container {
    const encoded = try codec.encode(Container, gpa, container.*);
    defer gpa.free(encoded);
    var decoded = try codec.decode(Container, gpa, encoded);
    errdefer decoded.deinit(gpa);
    try testing.expectEqual(kind, @as(container_mod.Kind, decoded));
    try testing.expect(decoded.eql(container));
    return decoded;
}

test "roaring container: a new container is an empty array (test_new_container)" {
    const container: Container = .empty;
    try testing.expect(container.is_empty());
    try testing.expectEqual(@as(u32, 0), container.len());
    try testing.expect(container == .array);
}

test "roaring container: equality ignores the representation" {
    // commonware `test_equality_ignores_representation`.
    var array: Container = .empty;
    defer array.deinit(gpa);
    var bitmap_values: Bitmap = .{};
    var run: Container = .{ .run = .empty };
    defer run.deinit(gpa);
    for ([_]u16{ 1, 3, 5 }) |value| {
        _ = try array.array.insert(gpa, value);
        _ = bitmap_values.insert(value);
        _ = try run.run.insert(gpa, value);
    }
    var bitmap = try bitmap_container(bitmap_values);
    defer bitmap.deinit(gpa);
    try testing.expect(array.eql(&bitmap));
    try testing.expect(array.eql(&run));
    _ = bitmap.bitmap.insert(7);
    try testing.expect(!array.eql(&bitmap));
}

/// A bitmap-kind encoding of `bitmap`, which is never canonical for these payloads.
fn expect_bitmap_payload_rejected(bitmap: Bitmap) !void {
    const payload = try codec.encode(Bitmap, gpa, bitmap);
    defer gpa.free(payload);
    const bytes = try std.mem.concat(gpa, u8, &.{ &.{1}, payload });
    defer gpa.free(bytes);
    var reader = codec.Reader.init(bytes);
    try testing.expectError(error.Invalid, codec.decode_reader(Container, gpa, &reader, {}));
    try testing.expectEqualStrings("Container", reader.diagnostic.context);
}

test "roaring container: decode rejects sparse and full bitmap payloads" {
    // commonware `test_decode_rejects_noncanonical_{sparse,full}_bitmap_container`.
    var sparse: Bitmap = .{};
    for ([_]u16{ 1, 3, 5 }) |value| _ = sparse.insert(value);
    try expect_bitmap_payload_rejected(sparse);
    try expect_bitmap_payload_rejected(Bitmap.from_words(@splat(~@as(u64, 0))));
}

test "roaring container: encode canonicalizes sparse and full bitmaps" {
    // commonware `test_encode_canonicalizes_{sparse,full}_bitmap_container`.
    var sparse_values: Bitmap = .{};
    for ([_]u16{ 1, 3, 5 }) |value| _ = sparse_values.insert(value);
    var sparse = try bitmap_container(sparse_values);
    defer sparse.deinit(gpa);
    var as_array = try expect_decoded(&sparse, .array);
    as_array.deinit(gpa);
    var full = try bitmap_container(Bitmap.from_words(@splat(~@as(u64, 0))));
    defer full.deinit(gpa);
    var as_run = try expect_decoded(&full, .run);
    defer as_run.deinit(gpa);
    try testing.expectEqual(@as(u32, 65536), as_run.len());
}

test "roaring container: sparse bitmap and run encodings span the value space" {
    // commonware `test_encode_sparse_bitmap_container_spanning_first_to_last_word` and
    // `test_encode_sparse_run_container_ending_at_max`.
    const spread = [_]u16{ 0, 64, 1000, 65471, 65472, 65535 };
    var bitmap_values: Bitmap = .{};
    for (spread) |value| _ = bitmap_values.insert(value);
    var bitmap = try bitmap_container(bitmap_values);
    defer bitmap.deinit(gpa);
    var from_bitmap = try expect_decoded(&bitmap, .array);
    defer from_bitmap.deinit(gpa);
    try expect_values(&from_bitmap, &spread);

    const ends = [_]u16{ 0, 2, 65534, 65535 };
    var run: Container = .{ .run = .empty };
    defer run.deinit(gpa);
    for (ends) |value| _ = try run.run.insert(gpa, value);
    var from_run = try expect_decoded(&run, .array);
    defer from_run.deinit(gpa);
    try expect_values(&from_run, &ends);
}

test "roaring container: re-encoding a decoded run past the bitmap threshold is stable" {
    // commonware `test_decode_normalization_is_idempotent_after_run_to_bitmap`.
    var run: Container = .{ .run = .empty };
    defer run.deinit(gpa);
    for (0..container_mod.RUN_TO_BITMAP_THRESHOLD + 1) |i| {
        try testing.expect(try run.run.insert(gpa, @intCast(i * 2)));
    }
    try testing.expectEqual(container_mod.RUN_TO_BITMAP_THRESHOLD + 1, run.run_count());
    const first = try codec.encode(Container, gpa, run);
    defer gpa.free(first);
    var once = try codec.decode(Container, gpa, first);
    defer once.deinit(gpa);
    const second = try codec.encode(Container, gpa, once);
    defer gpa.free(second);
    var twice = try codec.decode(Container, gpa, second);
    defer twice.deinit(gpa);
    const third = try codec.encode(Container, gpa, twice);
    defer gpa.free(third);
    try testing.expectEqualSlices(u8, second, third);
    try testing.expect(twice.eql(&run));
}

test "roaring container: a 4096-value array serializes as a bitmap" {
    // commonware `test_max_cardinality_serializes_as_bitmap`.
    var container: Container = .empty;
    defer container.deinit(gpa);
    for (0..MAX_CARDINALITY) |i| try testing.expect(try container.insert(gpa, @intCast(i * 2)));
    try testing.expect(container == .array);
    var decoded = try expect_decoded(&container, .bitmap);
    decoded.deinit(gpa);
}

test "roaring container: a no-op range insert keeps an array" {
    // commonware `test_insert_range_overlap_noop_does_not_force_bitmap_conversion`.
    var container: Container = .empty;
    defer container.deinit(gpa);
    try testing.expect(try container.insert(gpa, 0));
    try testing.expectEqual(@as(u32, 3999), try container.insert_range(gpa, 1, 4000));
    try testing.expect(container == .array);
    try testing.expectEqual(@as(u32, 0), try container.insert_range(gpa, 0, 1000));
    try testing.expect(container == .array);
    try testing.expectEqual(@as(u32, 4000), container.len());
}

test "roaring container: a bitmap in the hysteresis band stays a bitmap" {
    // commonware `test_no_thrash_in_hysteresis_band`.
    var c: Container = .empty;
    defer c.deinit(gpa);
    for (0..5_000) |i| _ = try c.insert(gpa, @intCast(i * 3));
    try testing.expect(c == .bitmap);
    for (0..3_000) |i| {
        _ = try c.insert(gpa, @intCast(i * 3 + 1));
        _ = try c.insert(gpa, @intCast(i * 3 + 2));
    }
    // One run over 0..=9000 plus 1999 singletons: 2000 runs, inside [1500, 2500].
    try testing.expectEqual(@as(usize, 2000), c.run_count());
    try testing.expect(c == .bitmap);
    for (3_000..3_010) |i| _ = try c.insert(gpa, @intCast(i * 3 + 1));
    try testing.expect(c == .bitmap);
    for (6_000..6_010) |i| _ = try c.insert(gpa, @intCast(i * 3));
    try testing.expect(c == .bitmap);
}

/// `a op b` over bitmap kinds, expecting `count` values in a `kind` result.
fn expect_bitmap_combine(
    a: Bitmap,
    b: Bitmap,
    comptime operation: Container.Operation,
    kind: container_mod.Kind,
    expected: ?[]const u16,
    count: u64,
) !void {
    var left = try bitmap_container(a);
    defer left.deinit(gpa);
    var right = try bitmap_container(b);
    defer right.deinit(gpa);
    var result = try Container.combine(&left, &right, gpa, std.math.maxInt(u64), operation);
    defer result.container.deinit(gpa);
    try testing.expectEqual(count, result.count);
    try testing.expectEqual(kind, @as(container_mod.Kind, result.container));
    if (expected) |values| try expect_values(&result.container, values);
}

test "roaring container: bitmap fast paths normalize their results" {
    // commonware `test_union_bitmap_fast_path_normalizes_to_run`,
    // `test_intersection_bitmap_fast_path_normalizes_to_array_when_sparse`, and
    // `test_difference_bitmap_fast_path_normalizes_to_array_when_sparse`.
    var dense: Bitmap = .{};
    try testing.expectEqual(@as(u32, 5_000), dense.insert_range(0, 5_000));
    try expect_bitmap_combine(dense, dense, .@"union", .run, null, 5_000);

    var evens: Bitmap = .{};
    var odds: Bitmap = .{};
    for (0..MAX_CARDINALITY + 1) |i| {
        try testing.expect(evens.insert(@intCast(i * 2)));
        try testing.expect(odds.insert(@intCast(i * 2 + 1)));
    }
    var with_42 = odds;
    try testing.expect(with_42.insert(42));
    try expect_bitmap_combine(evens, with_42, .intersection, .array, &.{42}, 1);

    var with_9999 = evens;
    try testing.expect(with_9999.insert(9_999));
    try expect_bitmap_combine(with_9999, evens, .difference, .array, &.{9_999}, 1);
}
