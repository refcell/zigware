//! An ordered map over a sorted array, the reference roles' `BTreeMap`. The roles hold a few
//! entries per account or epoch, so lookups search and inserts shift.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Orders epochs and other integers.
pub fn order_int(comptime K: type) fn (*const K, *const K) std.math.Order {
    return struct {
        fn order(a: *const K, b: *const K) std.math.Order {
            return std.math.order(a.*, b.*);
        }
    }.order;
}

/// Orders keys with an `order` method, such as public keys.
pub fn order_method(comptime K: type) fn (*const K, *const K) std.math.Order {
    return struct {
        fn order(a: *const K, b: *const K) std.math.Order {
            return a.order(b.*);
        }
    }.order;
}

/// A map from `K` to `V` in increasing key order under `order`. It owns its array, not its
/// values: the role that holds it frees values it removes.
pub fn Map(K: type, V: type, comptime order: fn (*const K, *const K) std.math.Order) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { key: K, value: V };

        entries: std.ArrayList(Entry) = .empty,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        /// The position of `key`, or where it would be inserted.
        fn search(self: *const Self, key: *const K) struct { usize, bool } {
            var low: usize = 0;
            var high: usize = self.entries.items.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (order(&self.entries.items[middle].key, key)) {
                    .lt => low = middle + 1,
                    .gt => high = middle,
                    .eq => return .{ middle, true },
                }
            }
            assert(low <= self.entries.items.len);
            return .{ low, false };
        }

        pub fn count(self: *const Self) usize {
            return self.entries.items.len;
        }

        pub fn items(self: *const Self) []Entry {
            return self.entries.items;
        }

        pub fn get(self: *const Self, key: *const K) ?*V {
            const index, const found = self.search(key);
            return if (found) &self.entries.items[index].value else null;
        }

        pub fn contains(self: *const Self, key: *const K) bool {
            return self.search(key)[1];
        }

        /// The entry with the largest key.
        pub fn last(self: *const Self) ?*Entry {
            const len = self.entries.items.len;
            return if (len == 0) null else &self.entries.items[len - 1];
        }

        /// Inserts or replaces `key`'s value, returning the value it replaced.
        pub fn put(self: *Self, gpa: Allocator, key: K, value: V) Allocator.Error!?V {
            const index, const found = self.search(&key);
            if (found) {
                const old = self.entries.items[index].value;
                self.entries.items[index].value = value;
                return old;
            }
            try self.entries.insert(gpa, index, .{ .key = key, .value = value });
            assert(order(&self.entries.items[index].key, &key) == .eq);
            return null;
        }

        /// Removes `key`, returning its value.
        pub fn remove(self: *Self, key: *const K) ?V {
            const index, const found = self.search(key);
            if (!found) return null;
            return self.entries.orderedRemove(index).value;
        }

        /// The number of entries whose key is less than `key`.
        pub fn below(self: *const Self, key: *const K) usize {
            return self.search(key)[0];
        }

        /// Drops the first `n` entries; the caller freed their values.
        pub fn drop_front(self: *Self, n: usize) void {
            assert(n <= self.entries.items.len);
            const rest = self.entries.items.len - n;
            std.mem.copyForwards(Entry, self.entries.items[0..rest], self.entries.items[n..]);
            self.entries.shrinkRetainingCapacity(rest);
        }

        /// Removes every entry; the caller freed their values.
        pub fn clear(self: *Self) void {
            self.entries.clearRetainingCapacity();
        }

        /// A copy of the array, sharing the values.
        pub fn clone_shallow(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return .{ .entries = try self.entries.clone(gpa) };
        }
    };
}
