//! Sorted view collections for the voter state (commonware's `BTreeSet<View>` and
//! `BTreeMap<View, Round>`). Both keep their items in ascending view order; the voter tracks a
//! bounded window of views, so binary search over a contiguous list is enough.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const View = @import("../../../types.zig").View;

fn before(view: View, item: View) bool {
    return item.get() < view.get();
}

/// A sorted set of views.
pub const ViewSet = struct {
    items: std.ArrayList(View) = .empty,

    pub const empty: ViewSet = .{};

    pub fn deinit(self: *ViewSet, gpa: Allocator) void {
        self.items.deinit(gpa);
        self.* = undefined;
    }

    /// The index of the first view at or above `view`.
    pub fn lower_bound(self: *const ViewSet, view: View) usize {
        return std.sort.partitionPoint(View, self.items.items, view, struct {
            fn below(target: View, item: View) bool {
                return before(target, item);
            }
        }.below);
    }

    pub fn contains(self: *const ViewSet, view: View) bool {
        const index = self.lower_bound(view);
        return index < self.items.items.len and self.items.items[index] == view;
    }

    pub fn insert(self: *ViewSet, gpa: Allocator, view: View) Allocator.Error!void {
        const index = self.lower_bound(view);
        if (index < self.items.items.len and self.items.items[index] == view) return;
        try self.items.insert(gpa, index, view);
        assert(self.contains(view));
    }

    pub fn remove(self: *ViewSet, view: View) void {
        const index = self.lower_bound(view);
        if (index == self.items.items.len or self.items.items[index] != view) return;
        _ = self.items.orderedRemove(index);
        assert(!self.contains(view));
    }

    /// Removes every view below `min` (commonware `split_off(&min)` keeping the upper half).
    pub fn retain_from(self: *ViewSet, min: View) void {
        const index = self.lower_bound(min);
        self.items.replaceRangeAssumeCapacity(0, index, &.{});
        assert(self.items.items.len == 0 or self.items.items[0].get() >= min.get());
    }

    /// The highest view in `[low, high]`.
    pub fn highest_in(self: *const ViewSet, low: View, high: View) ?View {
        if (high.get() < low.get()) return null;
        const end = self.lower_bound(high.next());
        if (end == 0) return null;
        const candidate = self.items.items[end - 1];
        if (candidate.get() < low.get()) return null;
        assert(candidate.get() <= high.get());
        return candidate;
    }

    /// The highest view in `[low, high)`.
    pub fn highest_below(self: *const ViewSet, low: View, high: View) ?View {
        if (high.get() <= low.get()) return null;
        return self.highest_in(low, high.previous().?);
    }

    pub fn len(self: *const ViewSet) usize {
        return self.items.items.len;
    }
};

/// Heap-allocated values keyed by view, in ascending order. Values have stable addresses.
pub fn ViewMap(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { view: View, value: *T };

        entries: std.ArrayList(Entry) = .empty,

        pub const empty: Self = .{};

        /// Frees the map; `release` runs on each value before it is destroyed.
        pub fn deinit(self: *Self, gpa: Allocator, release: fn (*T, Allocator) void) void {
            for (self.entries.items) |entry| {
                release(entry.value, gpa);
                gpa.destroy(entry.value);
            }
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        pub fn lower_bound(self: *const Self, view: View) usize {
            return std.sort.partitionPoint(Entry, self.entries.items, view, struct {
                fn below(target: View, entry: Entry) bool {
                    return before(target, entry.view);
                }
            }.below);
        }

        pub fn get(self: *const Self, view: View) ?*T {
            const index = self.lower_bound(view);
            if (index == self.entries.items.len) return null;
            const entry = self.entries.items[index];
            return if (entry.view == view) entry.value else null;
        }

        /// The value for `view`, created with `init` when absent.
        pub fn get_or_put(self: *Self, gpa: Allocator, view: View, init: T) Allocator.Error!*T {
            const index = self.lower_bound(view);
            if (index < self.entries.items.len and self.entries.items[index].view == view) {
                return self.entries.items[index].value;
            }
            const value = try gpa.create(T);
            errdefer gpa.destroy(value);
            value.* = init;
            try self.entries.insert(gpa, index, .{ .view = view, .value = value });
            assert(self.get(view) == value);
            return value;
        }

        /// The lowest view at or above `view`.
        pub fn next_view(self: *const Self, view: View) ?View {
            const index = self.lower_bound(view);
            if (index == self.entries.items.len) return null;
            return self.entries.items[index].view;
        }

        /// Entries with views in `[low, high]`.
        pub fn range(self: *const Self, low: View, high: View) []const Entry {
            if (high.get() < low.get()) return &.{};
            const start = self.lower_bound(low);
            var end = start;
            while (end < self.entries.items.len and
                self.entries.items[end].view.get() <= high.get()) end += 1;
            assert(end >= start);
            return self.entries.items[start..end];
        }

        /// Removes and releases every value below `min`, appending the removed views.
        pub fn prune_below(
            self: *Self,
            gpa: Allocator,
            min: View,
            release: fn (*T, Allocator) void,
            removed: *std.ArrayList(View),
        ) Allocator.Error!void {
            const index = self.lower_bound(min);
            try removed.ensureUnusedCapacity(gpa, index);
            for (self.entries.items[0..index]) |entry| {
                removed.appendAssumeCapacity(entry.view);
                release(entry.value, gpa);
                gpa.destroy(entry.value);
            }
            self.entries.replaceRangeAssumeCapacity(0, index, &.{});
            assert(self.entries.items.len == 0 or self.entries.items[0].view.get() >= min.get());
        }

        pub fn len(self: *const Self) usize {
            return self.entries.items.len;
        }
    };
}

const testing = std.testing;

test "view set keeps sorted unique views and answers ranges" {
    var set: ViewSet = .empty;
    defer set.deinit(testing.allocator);
    for ([_]u64{ 5, 1, 9, 5, 3 }) |view| try set.insert(testing.allocator, .new(view));
    try testing.expectEqual(4, set.len());
    try testing.expect(set.contains(.new(3)));
    try testing.expect(!set.contains(.new(4)));
    try testing.expectEqual(View.new(5), set.highest_in(.new(2), .new(8)).?);
    try testing.expectEqual(View.new(9), set.highest_in(.new(2), .new(9)).?);
    try testing.expectEqual(null, set.highest_in(.new(6), .new(8)));
    try testing.expectEqual(View.new(3), set.highest_below(.new(1), .new(5)).?);
    try testing.expectEqual(null, set.highest_below(.new(5), .new(5)));
    set.retain_from(.new(4));
    try testing.expect(!set.contains(.new(3)));
    try testing.expect(set.contains(.new(5)));
    set.remove(.new(5));
    try testing.expectEqual(1, set.len());
}

fn release_noop(_: *u32, _: Allocator) void {}

test "view map orders values and prunes below a floor" {
    const gpa = testing.allocator;
    var map: ViewMap(u32) = .empty;
    defer map.deinit(gpa, release_noop);
    for ([_]u64{ 7, 2, 4 }) |view| _ = try map.get_or_put(gpa, .new(view), @intCast(view));
    const again = try map.get_or_put(gpa, .new(4), 99);
    try testing.expectEqual(4, again.*);
    try testing.expectEqual(View.new(4), map.next_view(.new(3)).?);
    try testing.expectEqual(2, map.range(.new(3), .new(7)).len);
    try testing.expectEqual(null, map.next_view(.new(8)));
    var removed: std.ArrayList(View) = .empty;
    defer removed.deinit(gpa);
    try map.prune_below(gpa, .new(4), release_noop, &removed);
    try testing.expectEqual(1, removed.items.len);
    try testing.expectEqual(null, map.get(.new(2)));
    try testing.expectEqual(2, map.len());
}
