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
