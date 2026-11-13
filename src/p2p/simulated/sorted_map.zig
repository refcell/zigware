//! An ordered map over a sorted array (Rust `BTreeMap` for the simulator's small maps).
//!
//! Iteration is in ascending key order, so code that walks a map makes the same decisions in
//! the same order as commonware's `BTreeMap` walks. Lookups are binary searches; inserts and
//! removals shift the array, which is cheap at simulation sizes. Pointers returned by `get`
//! and `get_or_put` are valid until the next insertion or removal.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// `K` is an integer or has `order(a, b) std.math.Order`.
pub fn key_order(comptime K: type, a: K, b: K) std.math.Order {
    if (@typeInfo(K) == .int) return std.math.order(a, b);
    return K.order(a, b);
}

pub fn SortedMap(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { key: K, value: V };

        /// Strictly ascending by key.
        entries: std.ArrayList(Entry) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(map: *Self, gpa: Allocator) void {
            map.entries.deinit(gpa);
            map.* = undefined;
        }

        pub fn count(map: *const Self) usize {
            return map.entries.items.len;
        }

        pub fn items(map: *const Self) []Entry {
            return map.entries.items;
        }

        pub fn get(map: *const Self, key: K) ?*V {
            const index = map.index_of(key) orelse return null;
            return &map.entries.items[index].value;
        }

        pub fn contains(map: *const Self, key: K) bool {
            return map.index_of(key) != null;
        }

        /// The value for `key`, inserting `default` first when absent.
        pub fn get_or_put(map: *Self, gpa: Allocator, key: K, default: V) Allocator.Error!*V {
            const index = map.lower_bound(key);
            const present = index < map.entries.items.len and
                key_order(K, map.entries.items[index].key, key) == .eq;
            if (!present) try map.entries.insert(gpa, index, .{ .key = key, .value = default });
            assert(key_order(K, map.entries.items[index].key, key) == .eq);
            return &map.entries.items[index].value;
        }

        /// Inserts or replaces the value for `key`, returning the replaced value.
        pub fn put(map: *Self, gpa: Allocator, key: K, value: V) Allocator.Error!?V {
            const index = map.lower_bound(key);
            const items_now = map.entries.items;
            if (index < items_now.len and key_order(K, items_now[index].key, key) == .eq) {
                const previous = items_now[index].value;
                items_now[index].value = value;
                return previous;
            }
            try map.entries.insert(gpa, index, .{ .key = key, .value = value });
            return null;
        }

        /// Removes `key`, returning its value when present.
        pub fn remove(map: *Self, key: K) ?V {
            const index = map.index_of(key) orelse return null;
            const removed = map.entries.orderedRemove(index);
            assert(map.index_of(key) == null);
            return removed.value;
        }

        fn index_of(map: *const Self, key: K) ?usize {
            const index = map.lower_bound(key);
            if (index == map.entries.items.len) return null;
            if (key_order(K, map.entries.items[index].key, key) != .eq) return null;
            return index;
        }

        fn lower_bound(map: *const Self, key: K) usize {
            return std.sort.lowerBound(Entry, map.entries.items, key, compare);
        }

        fn compare(key: K, entry: Entry) std.math.Order {
            return key_order(K, key, entry.key);
        }
    };
}

test "sorted map keeps keys ascending" {
    const gpa = std.testing.allocator;
    var map: SortedMap(u32, u8) = .empty;
    defer map.deinit(gpa);
    for ([_]u32{ 5, 1, 9, 3 }) |key| try std.testing.expect(try map.put(gpa, key, 0) == null);
    try std.testing.expectEqual(@as(?u8, 0), try map.put(gpa, 3, 7));
    (try map.get_or_put(gpa, 4, 2)).* += 1;
    var previous: ?u32 = null;
    for (map.items()) |entry| {
        if (previous) |p| try std.testing.expect(p < entry.key);
        previous = entry.key;
    }
    try std.testing.expectEqual(@as(u8, 7), map.get(3).?.*);
    try std.testing.expectEqual(@as(u8, 3), map.get(4).?.*);
    try std.testing.expectEqual(@as(?u8, 0), map.remove(9));
    try std.testing.expect(map.remove(9) == null);
    try std.testing.expect(!map.contains(9));
    try std.testing.expectEqual(@as(usize, 4), map.count());
}
