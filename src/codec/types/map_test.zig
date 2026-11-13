//! Tests for canonical maps and sets (btree_map.rs, btree_set.rs, hash_map.rs, hash_set.rs).

const std = @import("std");
const testing = std.testing;
const codec = @import("../codec.zig");
const Reader = @import("../buf.zig").Reader;
const Bytes = @import("bytes.zig").Bytes;
const map = @import("map.zig");

const gpa = testing.allocator;

fn encode_owned(comptime T: type, value: T) ![]u8 {
    return codec.encode(T, gpa, value);
}

fn expect_map_roundtrip(comptime M: type, value: M, cfg: M.Cfg) !void {
    const encoded = try encode_owned(M, value);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(M, value), encoded.len);
    var decoded = try codec.decode_cfg(M, gpa, encoded, cfg);
    defer decoded.deinit(gpa);
    try testing.expectEqual(value.entries.len, decoded.entries.len);
    const reencoded = try encode_owned(M, decoded);
    defer gpa.free(reencoded);
    try testing.expectEqualSlices(u8, encoded, reencoded);
}

fn expect_set_roundtrip(comptime S: type, value: S, cfg: S.Cfg) !void {
    const encoded = try encode_owned(S, value);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(S, value), encoded.len);
    var decoded = try codec.decode_cfg(S, gpa, encoded, cfg);
    defer decoded.deinit(gpa);
    try testing.expectEqual(value.items.len, decoded.items.len);
    const reencoded = try encode_owned(S, decoded);
    defer gpa.free(reencoded);
    try testing.expectEqualSlices(u8, encoded, reencoded);
}

fn expect_invalid(
    comptime T: type,
    bytes: []const u8,
    cfg: codec.Cfg(T),
    message: []const u8,
    context: []const u8,
) !void {
    var reader = Reader.init(bytes);
    try testing.expectError(error.Invalid, codec.decode_reader(T, gpa, &reader, cfg));
    try testing.expectEqualStrings(context, reader.diagnostic.context);
    try testing.expectEqualStrings(message, reader.diagnostic.message);
}

test "empty map and set" {
    const M = map.Map(u32, u64);
    try expect_map_roundtrip(M, .init(&.{}), .{ .range = .full() });
    try testing.expectEqual(@as(usize, 1), codec.encode_size(M, .init(&.{})));
    const encoded = try encode_owned(M, .init(&.{}));
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{0}, encoded);

    const S = map.Set(u32);
    try expect_set_roundtrip(S, .init(&.{}), .{ .range = .full() });
    try testing.expectEqual(@as(usize, 1), codec.encode_size(S, .init(&.{})));
}

test "simple map encodes sorted keys" {
    const M = map.Map(u32, u64);
    var entries = [_]M.Entry{
        .{ .key = 1, .value = 100 }, .{ .key = 5, .value = 500 }, .{ .key = 2, .value = 200 },
    };
    M.sort(&entries);
    const value = M.init(&entries);
    try expect_map_roundtrip(M, value, .{ .range = .full() });
    try testing.expectEqual(@as(usize, 1 + 3 * (4 + 8)), codec.encode_size(M, value));
    try testing.expectEqual(@as(?u64, 200), value.get(2));
    try testing.expectEqual(@as(?u64, null), value.get(3));

    const encoded = try encode_owned(M, value);
    defer gpa.free(encoded);
    const Expected = struct { usize, u32, u64, u32, u64, u32, u64 };
    const expected = try encode_owned(Expected, .{ 3, 1, 100, 2, 200, 5, 500 });
    defer gpa.free(expected);
    try testing.expectEqualSlices(u8, expected, encoded);
}

test "large maps and sets" {
    const M16 = map.Map(u16, u64);
    var fixed: [1000]M16.Entry = undefined;
    for (&fixed, 0..) |*entry, index| entry.* = .{ .key = @intCast(index), .value = index * 2 };
    try expect_map_roundtrip(M16, .init(&fixed), .{ .range = .inclusive(0, 1000) });

    const MUsize = map.Map(usize, usize);
    var variable: [1000]MUsize.Entry = undefined;
    for (&variable, 0..) |*entry, index| entry.* = .{ .key = index, .value = 1000 + index };
    try expect_map_roundtrip(MUsize, .init(&variable), .{
        .range = .inclusive(0, 1000),
        .key = .to_inclusive(1000),
        .value = .inclusive(1000, 2000),
    });

    var items16: [1000]u16 = undefined;
    for (&items16, 0..) |*item, index| item.* = @intCast(index);
    try expect_set_roundtrip(map.Set(u16), .init(&items16), .{ .range = .exact(1000) });

    var items: [1000]usize = undefined;
    for (&items, 0..) |*item, index| item.* = index;
    try expect_set_roundtrip(map.Set(usize), .init(&items), .{
        .range = .exact(1000),
        .item = .to_inclusive(1000),
    });
}

test "map with variable keys and values" {
    const M = map.HashMap(Bytes, []const u8);
    var entries = [_]M.Entry{
        .{ .key = .init("banana"), .value = &.{ 3, 4, 5 } },
        .{ .key = .init("cherry"), .value = &.{} },
        .{ .key = .init("apple"), .value = &.{ 1, 2 } },
    };
    M.sort(&entries);
    try testing.expectEqualStrings("apple", entries[0].key.data);
    try expect_map_roundtrip(M, .init(&entries), .{
        .range = .to_inclusive(3),
        .key = .to_inclusive(10),
        .value = .{ .range = .to_inclusive(3) },
    });

    // A value longer than its configured limit fails with the value's length.
    const long_entries = [_]M.Entry{.{ .key = .init("key1"), .value = &.{ 1, 2, 3, 4, 5 } }};
    const encoded = try encode_owned(M, .init(&long_entries));
    defer gpa.free(encoded);
    var reader = Reader.init(encoded);
    const cfg: M.Cfg = .{
        .range = .full(),
        .key = .to_inclusive(10),
        .value = .{ .range = .to_inclusive(4) },
    };
    try testing.expectError(error.InvalidLength, codec.decode_reader(M, gpa, &reader, cfg));
    try testing.expectEqual(@as(u64, 5), reader.diagnostic.value);
}

test "map and set length limits" {
    const M = map.Map(u32, u64);
    const entries = [_]M.Entry{ .{ .key = 1, .value = 100 }, .{ .key = 5, .value = 500 } };
    const encoded = try encode_owned(M, .init(&entries));
    defer gpa.free(encoded);
    var reader = Reader.init(encoded);
    const one: M.Cfg = .{ .range = .inclusive(0, 1) };
    try testing.expectError(error.InvalidLength, codec.decode_reader(M, gpa, &reader, one));
    try testing.expectEqual(@as(u64, 2), reader.diagnostic.value);

    const S = map.HashSet(u32);
    const set_encoded = try encode_owned(S, .init(&.{ 1, 5 }));
    defer gpa.free(set_encoded);
    var set_reader = Reader.init(set_encoded);
    const set_one: S.Cfg = .{ .range = .inclusive(0, 1) };
    const set_result = codec.decode_reader(S, gpa, &set_reader, set_one);
    try testing.expectError(error.InvalidLength, set_result);
    try testing.expectEqual(@as(u64, 2), set_reader.diagnostic.value);

    // An item longer than its limit fails with the item's length.
    const B = map.HashSet(Bytes);
    const long = try encode_owned(B, .init(&.{.init("too long")}));
    defer gpa.free(long);
    var long_reader = Reader.init(long);
    const short_items: B.Cfg = .{ .range = .full(), .item = .to_inclusive(5) };
    const long_result = codec.decode_reader(B, gpa, &long_reader, short_items);
    try testing.expectError(error.InvalidLength, long_result);
    try testing.expectEqual(@as(u64, 8), long_reader.diagnostic.value);
}

test "maps reject unsorted and duplicate keys" {
    const Unsorted = struct { usize, u32, u64, u32, u64 };
    const unsorted = try encode_owned(Unsorted, .{ 2, 5, 500, 2, 200 });
    defer gpa.free(unsorted);
    const duplicate = try encode_owned(Unsorted, .{ 2, 1, 100, 1, 200 });
    defer gpa.free(duplicate);
    const cfg: map.Map(u32, u64).Cfg = .{ .range = .full() };
    try expect_invalid(map.Map(u32, u64), unsorted, cfg, "Keys must ascend", "BTreeMap");
    try expect_invalid(map.Map(u32, u64), duplicate, cfg, "Duplicate key", "BTreeMap");
    try expect_invalid(map.HashMap(u32, u64), unsorted, cfg, "Keys must ascend", "HashMap");
    try expect_invalid(map.HashMap(u32, u64), duplicate, cfg, "Duplicate key", "HashMap");
}

test "sets reject unsorted and duplicate items" {
    const Pair = struct { usize, u32, u32 };
    const unsorted = try encode_owned(Pair, .{ 2, 5, 2 });
    defer gpa.free(unsorted);
    const duplicate = try encode_owned(Pair, .{ 2, 1, 1 });
    defer gpa.free(duplicate);
    const cfg: map.Set(u32).Cfg = .{ .range = .full() };
    try expect_invalid(map.Set(u32), unsorted, cfg, "Items must ascend", "BTreeSet");
    try expect_invalid(map.Set(u32), duplicate, cfg, "Duplicate item", "BTreeSet");
    try expect_invalid(map.HashSet(u32), unsorted, cfg, "Items must ascend", "HashSet");
    try expect_invalid(map.HashSet(u32), duplicate, cfg, "Duplicate item", "HashSet");
}

test "map truncation and extra data" {
    const M = map.HashMap(u32, u64);
    const entries = [_]M.Entry{ .{ .key = 1, .value = 100 }, .{ .key = 5, .value = 500 } };
    const encoded = try encode_owned(M, .init(&entries));
    defer gpa.free(encoded);
    const cfg: M.Cfg = .{ .range = .full() };
    // Truncated inside the second key, then inside the second value.
    const in_key = encoded[0 .. 1 + 12 + 2];
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(M, gpa, in_key, cfg));
    const in_value = encoded[0 .. encoded.len - 4];
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(M, gpa, in_value, cfg));

    const single = try encode_owned(M, .init(entries[0..1]));
    defer gpa.free(single);
    const extended = try std.mem.concat(gpa, u8, &.{ single, &.{0xff} });
    defer gpa.free(extended);
    var reader = Reader.init(extended);
    try testing.expectError(error.ExtraData, codec.decode_reader(M, gpa, &reader, cfg));
    try testing.expectEqual(@as(u64, 1), reader.diagnostic.value);

    var partial = Reader.init(extended);
    var value = try codec.read_cfg(M, gpa, &partial, cfg);
    defer value.deinit(gpa);
    try testing.expectEqual(@as(?u64, 100), value.get(1));
}

test "set truncation, extra data, and hostile length" {
    const S = map.HashSet(u32);
    const encoded = try encode_owned(S, .init(&.{ 1, 5 }));
    defer gpa.free(encoded);
    const cfg: S.Cfg = .{ .range = .full() };
    const truncated = encoded[0 .. encoded.len - 1];
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(S, gpa, truncated, cfg));
    const extended = try std.mem.concat(gpa, u8, &.{ encoded, &.{0} });
    defer gpa.free(extended);
    try testing.expectError(error.ExtraData, codec.decode_cfg(S, gpa, extended, cfg));

    // A count of u32::MAX with almost no payload fails before allocating.
    const hostile = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0x0f, 0x00 };
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(S, gpa, hostile, cfg));
    const V = map.HashSet(usize);
    const usize_cfg: V.Cfg = .{ .range = .full(), .item = .full() };
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(V, gpa, hostile, usize_cfg));
}

test "maps and sets free partial results on error" {
    const M = map.Map(Bytes, []const u8);
    // Second key "b" is fine, its value is truncated: the first entry must be freed.
    const bytes = &[_]u8{ 2, 1, 'a', 1, 0xaa, 1, 'b', 3, 0xbb };
    const cfg: M.Cfg = .{ .range = .full(), .key = .full(), .value = .{ .range = .full() } };
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(M, gpa, bytes, cfg));
    // Second key sorts before the first: the first entry and the rejected key are freed.
    const S = map.Set([]const u8);
    const unsorted = &[_]u8{ 2, 1, 'b', 1, 'a' };
    const set_cfg: S.Cfg = .{ .range = .full(), .item = .{ .range = .full() } };
    try testing.expectError(error.Invalid, codec.decode_cfg(S, gpa, unsorted, set_cfg));
}

test "deterministic encoding regardless of insertion order" {
    const M = map.HashMap(u32, u32);
    var forward: [1001]M.Entry = undefined;
    var reverse: [1001]M.Entry = undefined;
    for (0..1001) |index| {
        const key: u32 = @intCast(index);
        forward[index] = .{ .key = key, .value = key * 2 };
        reverse[1000 - index] = .{ .key = key, .value = key * 2 };
    }
    M.sort(&reverse);
    const a = try encode_owned(M, .init(&forward));
    defer gpa.free(a);
    const b = try encode_owned(M, .init(&reverse));
    defer gpa.free(b);
    try testing.expectEqualSlices(u8, a, b);
}

test "map and set conformity" {
    const M8 = map.HashMap(u8, u16);
    var entries = [_]M8.Entry{ .{ .key = 2, .value = 0xbbbb }, .{ .key = 1, .value = 0xaaaa } };
    M8.sort(&entries);
    const encoded = try encode_owned(M8, .init(&entries));
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x01, 0xaa, 0xaa, 0x02, 0xbb, 0xbb }, encoded);

    const M16 = map.HashMap(u16, bool);
    var bool_entries = [_]M16.Entry{
        .{ .key = 0x0303, .value = true },
        .{ .key = 0x0101, .value = false },
        .{ .key = 0x0202, .value = true },
    };
    M16.sort(&bool_entries);
    const bool_encoded = try encode_owned(M16, .init(&bool_entries));
    defer gpa.free(bool_encoded);
    const expected = [_]u8{ 0x03, 0x01, 0x01, 0x00, 0x02, 0x02, 0x01, 0x03, 0x03, 0x01 };
    try testing.expectEqualSlices(u8, &expected, bool_encoded);

    var items = [_]u32{ 5, 1, 2 };
    map.Set(u32).sort(&items);
    const set = map.Set(u32).init(&items);
    try testing.expect(set.contains(5) and !set.contains(3));
    const set_encoded = try encode_owned(map.Set(u32), set);
    defer gpa.free(set_encoded);
    try testing.expectEqualSlices(u8, &.{ 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 5 }, set_encoded);
}

test "decode_range fills unit item configs" {
    const S = map.Set(u8);
    const set = try codec.decode_range(S, gpa, &.{ 2, 1, 9 }, .full());
    defer codec.free(S, gpa, set);
    try testing.expectEqualSlices(u8, &.{ 1, 9 }, set.items);
    const M = map.Map(u8, bool);
    const value = try codec.decode_range(M, gpa, &.{ 1, 4, 1 }, .exact(1));
    defer codec.free(M, gpa, value);
    try testing.expectEqual(@as(?bool, true), value.get(4));
}

test "codec order" {
    try testing.expectEqual(std.math.Order.lt, codec.order(?u8, null, 0));
    try testing.expectEqual(std.math.Order.gt, codec.order([]const u8, "ab", "a"));
    try testing.expectEqual(std.math.Order.lt, codec.order([2]u16, .{ 1, 9 }, .{ 2, 0 }));
    const Pair = struct { u8, bool };
    try testing.expectEqual(std.math.Order.gt, codec.order(Pair, .{ 1, true }, .{ 1, false }));
    try testing.expectEqual(std.math.Order.eq, codec.order(Bytes, .init("x"), .init("x")));
}
