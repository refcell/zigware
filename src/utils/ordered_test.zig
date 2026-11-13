//! Tests for `ordered` (commonware `utils/src/ordered.rs` tests and the `utils/fuzz` set
//! target).

const std = @import("std");
const codec = @import("codec");
const ordered = @import("ordered.zig");
const faults = @import("faults.zig");
const Participant = @import("root.zig").Participant;
const rng = @import("rng.zig");
const fuzz = @import("fuzz.zig");
const Set = ordered.Set;
const Map = ordered.Map;
const BiMap = ordered.BiMap;

const testing = std.testing;
const gpa = testing.allocator;

const Example = struct {
    value: u8,

    pub fn order(a: Example, b: Example) std.math.Order {
        return std.math.order(a.value, b.value);
    }

    pub fn format(example: Example, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("ex({d})", .{example.value});
    }
};

/// A key that owns memory, to check that collections release what they drop.
const Owned = struct {
    bytes: []u8,

    fn init(value: u8) !Owned {
        const bytes = try gpa.alloc(u8, 1);
        bytes[0] = value;
        return .{ .bytes = bytes };
    }

    pub fn order(a: Owned, b: Owned) std.math.Order {
        return std.mem.order(u8, a.bytes, b.bytes);
    }

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }
};

fn expect_set(set: Set(u8), expected: []const u8) !void {
    try testing.expectEqualSlices(u8, expected, set.as_slice());
}

test "ordered: set construct, dedup, duplicates" {
    var sorted = try Set(u8).from_dedup(gpa, &.{ 1, 3, 2, 5, 4, 3, 1, 7, 9, 6, 8, 4 });
    defer sorted.deinit(gpa);
    try expect_set(sorted, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 });

    var small = try Set(u8).from_dedup(gpa, &.{ 3, 1, 2, 2 });
    defer small.deinit(gpa);
    try expect_set(small, &.{ 1, 2, 3 });
    try testing.expectError(error.DuplicateKey, Set(u8).init(gpa, &.{ 3, 1, 2, 2 }));

    var empty = try Set(u8).init(gpa, &.{});
    defer empty.deinit(gpa);
    try testing.expect(empty.is_empty());
    try testing.expectEqual(@as(?usize, null), empty.position(1));
}

test "ordered: set get, position, order" {
    var set = try Set(u32).init(gpa, &.{ 40, 10, 30, 20 });
    defer set.deinit(gpa);
    try testing.expectEqual(@as(usize, 4), set.len());
    try testing.expectEqual(@as(u32, 10), set.get(0).?.*);
    try testing.expectEqual(@as(?*const u32, null), set.get(4));
    for ([_]u32{ 10, 20, 30, 40 }, 0..) |item, index| {
        try testing.expectEqual(@as(?usize, index), set.position(item));
    }
    for ([_]u32{ 0, 15, 25, 35, 45 }) |missing| {
        try testing.expectEqual(@as(?usize, null), set.position(missing));
    }
    var prefix = try Set(u32).init(gpa, &.{ 10, 20 });
    defer prefix.deinit(gpa);
    try testing.expectEqual(std.math.Order.lt, prefix.order(set));
    try testing.expect(set.eql(set) and !set.eql(prefix));
}

test "ordered: set codec roundtrip and wire bytes" {
    var sorted = try Set(u8).init(gpa, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 });
    defer sorted.deinit(gpa);
    const encoded = try codec.encode(Set(u8), gpa, sorted);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 9, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, encoded);
    var decoded = try codec.decode_cfg(Set(u8), gpa, encoded, .{ .range = .to_inclusive(9) });
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(sorted));
    const short = codec.decode_cfg(Set(u8), gpa, encoded, .{ .range = .to_inclusive(8) });
    try testing.expectError(error.InvalidLength, short);
    var words = try Set(u32).init(gpa, &.{ 2, 1 });
    defer words.deinit(gpa);
    const word_bytes = try codec.encode(Set(u32), gpa, words);
    defer gpa.free(word_bytes);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0, 1, 0, 0, 0, 2 }, word_bytes);
    try testing.expectEqual(@as(usize, 5 + 3 * 4), Set(u32).encode_size_max(3));
}

fn expect_set_decode(items: []const u8) !Set(u8) {
    const encoded = try codec.encode([]const u8, gpa, items);
    defer gpa.free(encoded);
    var reader = codec.Reader.init(encoded);
    const result = codec.decode_reader(Set(u8), gpa, &reader, .{ .range = .to_inclusive(10) });
    if (result) |set| return set else |err| {
        try testing.expectEqualStrings("Set", reader.diagnostic.context);
        return err;
    }
}

test "ordered: set decode rejects duplicates and unsorted" {
    try testing.expectError(error.Invalid, expect_set_decode(&.{ 1, 2, 2, 3 }));
    try testing.expectError(error.Invalid, expect_set_decode(&.{ 1, 3, 2, 4 }));
    var valid = try expect_set_decode(&.{ 1, 2, 3, 4 });
    defer valid.deinit(gpa);
    try expect_set(valid, &.{ 1, 2, 3, 4 });
}

test "ordered: set display" {
    var items: [9]Example = undefined;
    for (&items, 1..) |*item, value| item.* = .{ .value = @intCast(value) };
    std.mem.reverse(Example, &items);
    var sorted = try Set(Example).init(gpa, &items);
    defer sorted.deinit(gpa);
    var buffer: [128]u8 = undefined;
    const shown = try std.fmt.bufPrint(&buffer, "{f}", .{sorted});
    const expected = "[ex(1), ex(2), ex(3), ex(4), ex(5), ex(6), ex(7), ex(8), ex(9)]";
    try testing.expectEqualStrings(expected, shown);
    var numbers = try Set(u32).init(gpa, &.{ 3, 1 });
    defer numbers.deinit(gpa);
    try testing.expectEqualStrings("[1, 3]", try std.fmt.bufPrint(&buffer, "{f}", .{numbers}));
}

test "ordered: set quorum" {
    var participants = try Set(u32).init(gpa, &.{ 50, 10, 40, 20, 30, 60, 70 });
    defer participants.deinit(gpa);
    try testing.expectEqual(@as(u32, 5), participants.quorum(faults.N3f1));
    try testing.expectEqual(@as(u32, 2), participants.max_faults(faults.N3f1));
    try testing.expectEqual(@as(u32, 30), participants.key(.init(2)).?.*);
    try testing.expectEqual(@as(?*const u32, null), participants.key(.init(7)));
    try testing.expectEqual(@as(u32, 3), participants.index(40).?.get());
    try testing.expectEqual(@as(?Participant, null), participants.index(45));
}

test "ordered: owned items are released" {
    var items: [4]Owned = undefined;
    for (&items, [_]u8{ 3, 1, 2, 2 }) |*item, value| item.* = try Owned.init(value);
    var set = try Set(Owned).from_dedup(gpa, &items);
    defer set.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), set.len());
    try testing.expectEqual(@as(u8, 1), set.get(0).?.bytes[0]);

    var duplicate: [2]Owned = .{ try Owned.init(1), try Owned.init(1) };
    try testing.expectError(error.DuplicateKey, Set(Owned).init(gpa, &duplicate));
}

fn sample_map() !Map(u8, u8) {
    return Map(u8, u8).init(gpa, &.{ .{ 3, 30 }, .{ 1, 10 }, .{ 2, 20 } });
}

test "ordered: map construct, dedup, duplicates" {
    const pairs = [_]Map(u8, u8).Pair{ .{ 3, 'c' }, .{ 1, 'a' }, .{ 2, 'b' }, .{ 1, 'd' } };
    var dedup = try Map(u8, u8).from_dedup(gpa, &pairs);
    defer dedup.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), dedup.len());
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, dedup.keys.as_slice());
    try testing.expectEqual(@as(u8, 'a'), dedup.get_value(1).?.*);
    try testing.expectEqual(@as(?*const u8, null), dedup.get_value(4));
    try testing.expectEqual(@as(u8, 'b'), dedup.value(1).?.*);
    try testing.expectEqual(@as(u8, 2), dedup.get(1).?.*);
    try testing.expectError(error.DuplicateKey, Map(u8, u8).init(gpa, &pairs));

    var map = try Map(u8, u8).init(gpa, pairs[0..3]);
    defer map.deinit(gpa);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, map.keys.as_slice());
    try testing.expectEqual(@as(u8, 'b'), map.get_value(2).?.*);
    try testing.expectEqual(@as(?usize, 2), map.position(3));

    // Duplicate values are fine in a map.
    var same = try Map(u8, u8).init(gpa, &.{ .{ 1, 'a' }, .{ 2, 'b' }, .{ 3, 'a' } });
    defer same.deinit(gpa);
    try testing.expectEqual(same.get_value(1).?.*, same.get_value(3).?.*);
}

test "ordered: map from_parts, into_keys, values" {
    const keys = try Set(u8).init(gpa, &.{ 3, 1, 2 });
    const values = try gpa.dupe(u8, &.{ 30, 10, 10 });
    var map = Map(u8, u8).from_parts(keys, values).?;
    defer map.deinit(gpa);
    try testing.expectEqual(keys.items.ptr, map.keys.items.ptr);
    try testing.expectEqual(values.ptr, map.values.ptr);
    try testing.expectEqualSlices(u8, &.{ 30, 10, 10 }, map.values);
    for (map.values) |*value| value.* += 1;
    try testing.expectEqualSlices(u8, &.{ 31, 11, 11 }, map.values);
    map.get_value_mut(2).?.* = 0;
    try testing.expectEqual(@as(u8, 0), map.get_value(2).?.*);

    for ([_]usize{ 0, 1, 3 }) |key_count| {
        for ([_]usize{ 0, 1, 3 }) |value_count| {
            var range_keys: [3]u8 = .{ 0, 1, 2 };
            var set = try Set(u8).init(gpa, range_keys[0..key_count]);
            const parts = try gpa.alloc(u8, value_count);
            if (Map(u8, u8).from_parts(set, parts)) |built| {
                var owned = built;
                try testing.expectEqual(key_count, value_count);
                try testing.expectEqual(key_count, owned.len());
                owned.deinit(gpa);
            } else {
                try testing.expect(key_count != value_count);
                set.deinit(gpa);
                gpa.free(parts);
            }
        }
    }

    var other = try sample_map();
    var only_keys = other.into_keys(gpa);
    defer only_keys.deinit(gpa);
    try expect_set(only_keys, &.{ 1, 2, 3 });
}

const Pairs = struct { offset: u8 };

fn add_key(context: Pairs, key: *const u8, value: *const u8) u16 {
    return @as(u16, key.*) + value.* + context.offset;
}

fn fail_at(context: u8, key: *const u8, value: u8) error{Failed}!u16 {
    if (key.* == context) return error.Failed;
    return @as(u16, key.*) + value;
}

test "ordered: map_values and map_values_into" {
    var map = try sample_map();
    defer map.deinit(gpa);
    var mapped = try map.map_values(gpa, u16, Pairs{ .offset = 1 }, add_key);
    defer mapped.deinit(gpa);
    try testing.expect(mapped.keys.eql(map.keys));
    try testing.expectEqualSlices(u16, &.{ 12, 23, 34 }, mapped.values);

    var owned = try sample_map();
    const keys_ptr = owned.keys.items.ptr;
    var into = try owned.map_values_into(gpa, u16, @as(u8, 0), fail_at);
    defer into.deinit(gpa);
    try testing.expectEqual(keys_ptr, into.keys.items.ptr);
    try testing.expectEqualSlices(u16, &.{ 11, 22, 33 }, into.values);

    for ([_]u8{ 1, 2, 3 }) |failed_key| {
        var failing = try sample_map();
        const into_failed = failing.map_values_into(gpa, u16, failed_key, fail_at);
        try testing.expectError(error.Failed, into_failed);
        var borrowed = try sample_map();
        defer borrowed.deinit(gpa);
        try testing.expectError(error.Failed, borrowed.map_values(gpa, u16, failed_key, fail_ref));
    }

    var empty: Map(u8, u8) = .empty;
    var mapped_empty = try empty.map_values(gpa, u16, Pairs{ .offset = 0 }, add_key);
    defer mapped_empty.deinit(gpa);
    try testing.expect(mapped_empty.is_empty());
}

fn fail_ref(context: u8, key: *const u8, value: *const u8) error{Failed}!u16 {
    return fail_at(context, key, value.*);
}

test "ordered: map truncate and pair iterators" {
    var map = try sample_map();
    defer map.deinit(gpa);
    var pairs = map.iter_pairs();
    try testing.expectEqual(@as(usize, 3), pairs.len());
    try testing.expectEqual(@as(u8, 10), pairs.next().?[1].*);
    try testing.expectEqual(@as(usize, 2), pairs.len());
    try testing.expectEqual(@as(u8, 3), pairs.next_back().?[0].*);
    try testing.expectEqual(@as(u8, 2), pairs.next_back().?[0].*);
    try testing.expectEqual(@as(usize, 0), pairs.len());
    try testing.expect(pairs.next() == null and pairs.next_back() == null);

    try map.truncate(gpa, 5);
    try testing.expectEqual(@as(usize, 3), map.len());
    try map.truncate(gpa, 2);
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, map.keys.as_slice());
    try testing.expectEqualSlices(u8, &.{ 10, 20 }, map.values);

    var buffer: [64]u8 = undefined;
    const shown = try std.fmt.bufPrint(&buffer, "{f}", .{map});
    try testing.expectEqualStrings("[(1, 10), (2, 20)]", shown);
}

fn encode_parts(keys: []const u8, values: []const u8) ![]u8 {
    const key_bytes = try codec.encode([]const u8, gpa, keys);
    defer gpa.free(key_bytes);
    const value_bytes = try codec.encode([]const u8, gpa, values);
    defer gpa.free(value_bytes);
    return std.mem.concat(gpa, u8, &.{ key_bytes, value_bytes });
}

fn decode_map(comptime M: type, keys: []const u8, values: []const u8) !M {
    const encoded = try encode_parts(keys, values);
    defer gpa.free(encoded);
    return codec.decode_cfg(M, gpa, encoded, .{ .range = .to_inclusive(10) });
}

test "ordered: map codec" {
    var map = try sample_map();
    defer map.deinit(gpa);
    const encoded = try codec.encode(Map(u8, u8), gpa, map);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 3, 1, 2, 3, 3, 10, 20, 30 }, encoded);
    var decoded = try codec.decode_cfg(Map(u8, u8), gpa, encoded, .{ .range = .full() });
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(map));
    try testing.expectEqual(Set(u8).encode_size_max(3) + 5 + 3, Map(u8, u8).encode_size_max(3, 1));

    const values = [_]u8{ 10, 20, 30, 40 };
    try testing.expectError(error.Invalid, decode_map(Map(u8, u8), &.{ 1, 2, 2, 3 }, &values));
    try testing.expectError(error.Invalid, decode_map(Map(u8, u8), &.{ 1, 3, 2, 4 }, &values));
    try testing.expectError(error.InvalidLength, decode_map(Map(u8, u8), &.{ 1, 2 }, &values));
    var valid = try decode_map(Map(u8, u8), &.{ 1, 2, 3, 4 }, &values);
    defer valid.deinit(gpa);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, valid.keys.as_slice());
    try testing.expectEqualSlices(u8, &values, valid.values);
}

test "ordered: bimap" {
    const unique = [_]BiMap(u8, u8).Pair{ .{ 1, 'a' }, .{ 2, 'b' }, .{ 3, 'c' } };
    var bimap = try BiMap(u8, u8).init(gpa, &unique);
    defer bimap.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), bimap.len());
    try testing.expectEqual(@as(u8, 'a'), bimap.get_value(1).?.*);
    try testing.expectEqual(@as(u8, 3), bimap.get_key('c').?.*);
    try testing.expectEqual(@as(u8, 1), bimap.get_key('a').?.*);
    try testing.expectEqual(@as(?*const u8, null), bimap.get_key('d'));
    var pairs = bimap.iter_pairs();
    try testing.expectEqual(@as(u8, 'c'), pairs.next_back().?[1].*);

    const repeated = [_]BiMap(u8, u8).Pair{ .{ 1, 'a' }, .{ 2, 'b' }, .{ 3, 'a' } };
    try testing.expectError(error.DuplicateValue, BiMap(u8, u8).init(gpa, &repeated));
    const map = try Map(u8, u8).init(gpa, &repeated);
    try testing.expectError(error.DuplicateValue, BiMap(u8, u8).from_map(gpa, map));
    var from_map = try BiMap(u8, u8).from_map(gpa, try Map(u8, u8).init(gpa, &unique));
    defer from_map.deinit(gpa);
    try testing.expect(from_map.eql(bimap));

    const result = decode_map(BiMap(u8, u8), &.{ 1, 2, 3 }, &.{ 10, 20, 10 });
    try testing.expectError(error.Invalid, result);
    var decoded = try decode_map(BiMap(u8, u8), &.{ 1, 2, 3 }, &.{ 10, 20, 30 });
    defer decoded.deinit(gpa);
    try testing.expectEqual(@as(u8, 2), decoded.get_key(20).?.*);
}

/// Fuzz (commonware utils/fuzz set.rs), extended: sets built from random items match a sorted,
/// deduplicated model, answer `position` correctly, and roundtrip through the codec; corrupt
/// encodings either fail or decode to a valid set.
fn fuzz_set(_: void, generator: *rng.FuzzRng) !void {
    var items: [64]u16 = undefined;
    const count = rng.range_at_most(generator, usize, 0, items.len);
    for (items[0..count]) |*item| item.* = rng.range_less_than(generator, u16, 0, 128);
    var set = try Set(u16).from_dedup(gpa, items[0..count]);
    defer set.deinit(gpa);
    var model: [128]bool = @splat(false);
    for (items[0..count]) |item| model[item] = true;
    var expected_len: usize = 0;
    for (model, 0..) |present, value| {
        const found = set.position(@intCast(value));
        try testing.expectEqual(present, found != null);
        if (found) |index| try testing.expectEqual(expected_len, index);
        expected_len += @intFromBool(present);
    }
    try testing.expectEqual(expected_len, set.len());
    if (Set(u16).init(gpa, items[0..count])) |valid| {
        var owned = valid;
        owned.deinit(gpa);
        try testing.expectEqual(count, expected_len);
    } else |err| {
        try testing.expectEqual(error.DuplicateKey, err);
        try testing.expect(count != expected_len);
    }

    const encoded = try codec.encode(Set(u16), gpa, set);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(Set(u16), gpa, encoded, .{ .range = .full() });
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(set));
    const position = rng.range_less_than(generator, usize, 0, encoded.len);
    encoded[position] ^= @truncate(generator.next_u32() | 1);
    var corrupt = codec.decode_cfg(Set(u16), gpa, encoded, .{ .range = .full() }) catch return;
    defer corrupt.deinit(gpa);
    for (1..@max(corrupt.len(), 1)) |index| {
        try testing.expect(corrupt.items[index - 1] < corrupt.items[index]);
    }
}

test "fuzz ordered set" {
    try fuzz.run({}, fuzz_set, 0x7365_7473, 500);
}
