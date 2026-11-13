//! A set iterated in priority-ascending order (commonware `utils/src/priority_set.rs`).
//!
//! Entries are ordered by priority, then item (commonware's `BTreeSet<Entry>`), in a sorted
//! array; a second array sorted by item maps each item to its priority (commonware's
//! `HashMap`). Lookups bisect, and insertions and removals shift, so operations are `O(n)` in
//! the worst case with no hashing: the sets resolvers keep are bounded by their in-flight work.
//!
//! Items and priorities are plain values compared with `compare`: a `pub fn order(a, b)` decl,
//! a byte slice, or an integer.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");

/// Rust `Ord` for set items and priorities.
pub fn compare(comptime T: type, a: T, b: T) std.math.Order {
    switch (@typeInfo(T)) {
        .int => return std.math.order(a, b),
        .@"struct", .@"union", .@"enum" => if (comptime @hasDecl(T, "order")) return T.order(a, b),
        .pointer => |info| if (info.size == .slice and info.child == u8) {
            return std.mem.order(u8, a, b);
        },
        else => {},
    }
    return codec.order(T, a, b);
}

pub fn PrioritySet(comptime I: type, comptime P: type) type {
    return struct {
        const Self = @This();

        pub const Entry = struct { item: I, priority: P };

        /// Ascending by (priority, item).
        entries: std.ArrayList(Entry) = .empty,
        /// Ascending by item; same contents as `entries`.
        keys: std.ArrayList(Entry) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.entries.deinit(gpa);
            self.keys.deinit(gpa);
            self.* = undefined;
        }

        /// Insert an item with a priority, replacing the item's previous priority.
        pub fn put(self: *Self, gpa: Allocator, item: I, priority: P) Allocator.Error!void {
            try self.entries.ensureUnusedCapacity(gpa, 1);
            try self.keys.ensureUnusedCapacity(gpa, 1);
            const key = self.find_key(item);
            if (key.found) {
                const old = self.keys.items[key.index];
                const position = self.find_entry(old).?;
                _ = self.entries.orderedRemove(position);
                self.keys.items[key.index].priority = priority;
            } else {
                self.keys.insertAssumeCapacity(key.index, .{ .item = item, .priority = priority });
            }
            const entry: Entry = .{ .item = item, .priority = priority };
            const index = std.sort.lowerBound(Entry, self.entries.items, entry, order_entry);
            self.entries.insertAssumeCapacity(index, entry);
            assert(self.entries.items.len == self.keys.items.len);
        }

        /// The current priority of an item.
        pub fn get(self: *const Self, item: I) ?P {
            const key = self.find_key(item);
            if (!key.found) return null;
            return self.keys.items[key.index].priority;
        }

        /// Remove an item. Returns true if it was present.
        pub fn remove(self: *Self, item: I) bool {
            const key = self.find_key(item);
            if (!key.found) return false;
            const old = self.keys.orderedRemove(key.index);
            const position = self.find_entry(old).?;
            _ = self.entries.orderedRemove(position);
            assert(self.entries.items.len == self.keys.items.len);
            return true;
        }

        /// Remove every item not in `keep`, and add the items of `keep` not yet present with
        /// priority `default`.
        pub fn reconcile(
            self: *Self,
            gpa: Allocator,
            keep: []const I,
            default: P,
        ) Allocator.Error!void {
            var index = self.keys.items.len;
            while (index > 0) {
                index -= 1;
                const item = self.keys.items[index].item;
                if (contains_item(keep, item)) continue;
                assert(self.remove(item));
            }
            for (keep) |item| {
                if (self.contains(item)) continue;
                try self.put(gpa, item, default);
            }
        }

        /// Retain only the items for which `predicate.call(item)` is true.
        pub fn retain(self: *Self, predicate: anytype) void {
            retain_list(&self.entries, predicate);
            retain_list(&self.keys, predicate);
            assert(self.entries.items.len == self.keys.items.len);
        }

        pub fn contains(self: *const Self, item: I) bool {
            return self.find_key(item).found;
        }

        /// The entry with the lowest priority (commonware's "highest priority").
        pub fn peek(self: *const Self) ?Entry {
            if (self.entries.items.len == 0) return null;
            return self.entries.items[0];
        }

        /// Remove and return the entry with the lowest priority.
        pub fn pop(self: *Self) ?Entry {
            if (self.entries.items.len == 0) return null;
            const entry = self.entries.orderedRemove(0);
            const key = self.find_key(entry.item);
            assert(key.found);
            _ = self.keys.orderedRemove(key.index);
            return entry;
        }

        pub fn clear(self: *Self) void {
            self.entries.clearRetainingCapacity();
            self.keys.clearRetainingCapacity();
        }

        /// Every entry in priority-ascending order (valid until the set changes).
        pub fn items(self: *const Self) []const Entry {
            return self.entries.items;
        }

        pub fn len(self: *const Self) usize {
            return self.entries.items.len;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.entries.items.len == 0;
        }

        const Position = struct { index: usize, found: bool };

        fn find_key(self: *const Self, item: I) Position {
            const index = std.sort.lowerBound(Entry, self.keys.items, item, order_item_key);
            const found = index < self.keys.items.len and
                compare(I, self.keys.items[index].item, item) == .eq;
            return .{ .index = index, .found = found };
        }

        fn find_entry(self: *const Self, entry: Entry) ?usize {
            const index = std.sort.lowerBound(Entry, self.entries.items, entry, order_entry);
            if (index >= self.entries.items.len) return null;
            if (order_entry(entry, self.entries.items[index]) != .eq) return null;
            return index;
        }

        fn order_item_key(item: I, entry: Entry) std.math.Order {
            return compare(I, item, entry.item);
        }

        fn order_entry(a: Entry, b: Entry) std.math.Order {
            const by_priority = compare(P, a.priority, b.priority);
            if (by_priority != .eq) return by_priority;
            return compare(I, a.item, b.item);
        }

        fn contains_item(list: []const I, item: I) bool {
            for (list) |candidate| if (compare(I, candidate, item) == .eq) return true;
            return false;
        }

        fn retain_list(list: *std.ArrayList(Entry), predicate: anytype) void {
            var kept: usize = 0;
            for (list.items) |entry| {
                if (!predicate.call(entry.item)) continue;
                list.items[kept] = entry;
                kept += 1;
            }
            list.shrinkRetainingCapacity(kept);
        }
    };
}

const testing = std.testing;
const Set = PrioritySet([]const u8, u64);

fn expect_items(set: *const Set, expected: []const []const u8) !void {
    try testing.expectEqual(expected.len, set.len());
    for (expected, set.items()) |item, entry| try testing.expectEqualStrings(item, entry.item);
}

test "put remove and iter" {
    const gpa = testing.allocator;
    var set: Set = .empty;
    defer set.deinit(gpa);
    try set.put(gpa, "key1", 10);
    try set.put(gpa, "key2", 5);
    try expect_items(&set, &.{ "key2", "key1" });
    try testing.expect(set.remove("key1"));
    try expect_items(&set, &.{"key2"});
    try testing.expect(!set.remove("key1"));
    try expect_items(&set, &.{"key2"});
}

test "update" {
    const gpa = testing.allocator;
    var set: Set = .empty;
    defer set.deinit(gpa);
    try set.put(gpa, "key", 10);
    try testing.expectEqual(@as(?u64, 10), set.get("key"));
    try set.put(gpa, "key", 5);
    try testing.expectEqual(@as(?u64, 5), set.get("key"));
    try testing.expectEqual(@as(usize, 1), set.len());
    try testing.expectEqual(@as(u64, 5), set.items()[0].priority);
}

test "reconcile" {
    const gpa = testing.allocator;
    var set: Set = .empty;
    defer set.deinit(gpa);
    try set.put(gpa, "key1", 10);
    try set.put(gpa, "key2", 5);
    try set.reconcile(gpa, &.{ "key1", "key3" }, 2);
    try testing.expectEqual(@as(usize, 2), set.len());
    try testing.expectEqual(@as(?u64, 10), set.get("key1"));
    try testing.expectEqual(@as(?u64, 2), set.get("key3"));
    try testing.expect(!set.contains("key2"));
}

test "retain" {
    const gpa = testing.allocator;
    var set: Set = .empty;
    defer set.deinit(gpa);
    try set.put(gpa, "key1", 10);
    try set.put(gpa, "key2", 5);
    try set.put(gpa, "item3", 15);
    const StartsWithKey = struct {
        pub fn call(_: @This(), item: []const u8) bool {
            return std.mem.startsWith(u8, item, "key");
        }
    };
    set.retain(StartsWithKey{});
    try testing.expect(set.contains("key1") and set.contains("key2"));
    try testing.expect(!set.contains("item3"));
    try expect_items(&set, &.{ "key2", "key1" });
}

test "clear" {
    const gpa = testing.allocator;
    var set: Set = .empty;
    defer set.deinit(gpa);
    try set.put(gpa, "key1", 10);
    try set.put(gpa, "key2", 5);
    set.clear();
    try testing.expect(set.is_empty());
    try testing.expect(set.peek() == null);
    try testing.expect(set.pop() == null);
}

test "equal priorities order by item, and pop follows the order" {
    const gpa = testing.allocator;
    var set: PrioritySet(u8, u64) = .empty;
    defer set.deinit(gpa);
    try set.put(gpa, 3, 1);
    try set.put(gpa, 1, 1);
    try set.put(gpa, 2, 0);
    try testing.expectEqual(@as(u8, 2), set.pop().?.item);
    try testing.expectEqual(@as(u8, 1), set.pop().?.item);
    try testing.expectEqual(@as(u8, 3), set.peek().?.item);
}

/// Model check against a naive list over random operations.
fn priority_set_model(_: void, random: *@import("rng.zig").FuzzRng) anyerror!void {
    const rng = @import("rng.zig");
    const gpa = testing.allocator;
    var set: PrioritySet(u8, u8) = .empty;
    defer set.deinit(gpa);
    var model: [16]?u8 = @splat(null);
    for (0..32) |_| {
        const item = rng.range_less_than(random, u8, 0, 16);
        switch (rng.range_less_than(random, u8, 0, 3)) {
            0 => {
                const priority = rng.range_less_than(random, u8, 0, 4);
                try set.put(gpa, item, priority);
                model[item] = priority;
            },
            1 => {
                try testing.expectEqual(model[item] != null, set.remove(item));
                model[item] = null;
            },
            else => if (set.pop()) |entry| {
                try testing.expectEqual(model[entry.item].?, entry.priority);
                for (model, 0..) |priority, other| {
                    const value = priority orelse continue;
                    const before = value < entry.priority or
                        (value == entry.priority and other < entry.item);
                    try testing.expect(!before);
                }
                model[entry.item] = null;
            },
        }
        var count: usize = 0;
        for (model, 0..) |priority, index| {
            try testing.expectEqual(priority, set.get(@intCast(index)));
            count += @intFromBool(priority != null);
        }
        try testing.expectEqual(count, set.len());
    }
}

test "fuzz: priority set matches a model" {
    try @import("fuzz.zig").run({}, priority_set_model, 0x7072696f72697479, 1000);
}
