//! A map from heights to values in ascending height order (commonware's
//! `BTreeMap<Height, V>` for the engine's pending and confirmed heights), over a sorted array.
//! The engine keeps at most `window + activity_timeout` heights, so shifting is cheap.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Height = @import("../types.zig").Height;

pub fn HeightMap(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { height: Height, value: V };

        entries: std.ArrayList(Entry) = .empty,

        pub const empty: Self = .{};

        /// Releases the array; the caller releases the values first.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        fn search(self: *const Self, height: Height) struct { usize, bool } {
            var low: usize = 0;
            var high: usize = self.entries.items.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (Height.order(self.entries.items[middle].height, height)) {
                    .lt => low = middle + 1,
                    .gt => high = middle,
                    .eq => return .{ middle, true },
                }
            }
            return .{ low, false };
        }

        pub fn get(self: *const Self, height: Height) ?*V {
            const index, const found = self.search(height);
            return if (found) &self.entries.items[index].value else null;
        }

        pub fn contains(self: *const Self, height: Height) bool {
            return self.search(height)[1];
        }

        /// Inserts `value` at `height`, which must be absent.
        pub fn put_new(self: *Self, gpa: Allocator, height: Height, value: V) Allocator.Error!void {
            const index, const found = self.search(height);
            assert(!found);
            try self.entries.insert(gpa, index, .{ .height = height, .value = value });
            assert(self.contains(height));
        }

        /// The highest height, or null when empty.
        pub fn last(self: *const Self) ?Height {
            const all = self.entries.items;
            return if (all.len == 0) null else all[all.len - 1].height;
        }

        pub fn items(self: *const Self) []Entry {
            return self.entries.items;
        }

        pub fn len(self: *const Self) usize {
            return self.entries.items.len;
        }

        /// The entries below `min`, which `remove_below` drops; release their values first.
        pub fn below(self: *const Self, min: Height) []Entry {
            const index, _ = self.search(min);
            return self.entries.items[0..index];
        }

        /// Drops every entry below `min`, without releasing values.
        pub fn remove_below(self: *Self, min: Height) void {
            const count = self.below(min).len;
            const items_all = self.entries.items;
            std.mem.copyForwards(Entry, items_all[0 .. items_all.len - count], items_all[count..]);
            self.entries.shrinkRetainingCapacity(items_all.len - count);
            if (self.entries.items.len > 0) assert(self.entries.items[0].height.get() >= min.get());
        }
    };
}

test "height map keeps heights in order" {
    const gpa = std.testing.allocator;
    var map: HeightMap(u8) = .empty;
    defer map.deinit(gpa);
    try map.put_new(gpa, .new(5), 50);
    try map.put_new(gpa, .new(1), 10);
    try map.put_new(gpa, .new(3), 30);
    try std.testing.expectEqual(Height.new(5), map.last().?);
    try std.testing.expectEqual(30, map.get(.new(3)).?.*);
    try std.testing.expectEqual(null, map.get(.new(2)));
    try std.testing.expectEqual(1, map.below(.new(3)).len);
    map.remove_below(.new(3));
    try std.testing.expectEqual(2, map.len());
    try std.testing.expect(!map.contains(.new(1)));
    map.remove_below(.new(9));
    try std.testing.expectEqual(null, map.last());
}
