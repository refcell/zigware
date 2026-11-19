//! A partitioned ordered index (port of commonware's `storage/src/index/partitioned/ordered`).
//!
//! Unlike the flat indices, a key's values form a run in insertion order: `insert` appends to
//! the run, `get` yields it front to back, and the cursor walks it by offset (commonware's
//! partition cursor). Runs live in one treap over the composite key `(partition, sub-key)`, so
//! ordered navigation crosses partitions in prefix order, as commonware's partition scans do.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const partitioned = @import("mod.zig");
const storage = @import("../storage.zig");

/// A key's values, front to back.
pub fn Run(comptime V: type) type {
    return struct {
        items: []const V = &.{},

        pub fn next(self: *@This()) ?*const V {
            if (self.items.len == 0) return null;
            const value = &self.items[0];
            self.items = self.items[1..];
            return value;
        }

        pub fn count(self: *const @This()) usize {
            return self.items.len;
        }
    };
}

/// A worker's range of an `Index(T, V, P)` (commonware's `RangeIndex`).
pub fn Range(comptime T: type, comptime V: type, comptime P: usize) type {
    return partitioned.Range(Index(T, V, P), Index(T, V, P).absorb);
}

/// An empty range over partitions `[offset, offset + count)` of `full`.
pub fn new_range(
    comptime T: type,
    comptime V: type,
    comptime P: usize,
    full: *const Index(T, V, P),
    offset: u32,
    count: u32,
) Range(T, V, P) {
    return .init(full, offset, count);
}

/// A partitioned ordered index whose first `P` key bytes select a partition and translator
/// `T` (which must preserve key order) maps the rest.
pub fn Index(comptime T: type, comptime V: type, comptime P: usize) type {
    return struct {
        const Self = @This();
        const Tr = partitioned.Translator(T, P);
        const Tree = std.Treap(Tr.Key, Tr.order);
        const List = std.ArrayList(V);
        const Item = struct { node: Tree.Node, values: List };
        const Pool = std.heap.MemoryPool(Item);

        pub const Translator = Tr;
        pub const Key = Tr.Key;
        pub const Value = V;
        pub const Values = Run(V);
        pub const lookup_warms_update = false;

        gpa: Allocator,
        translator: Tr,
        tree: Tree = .{},
        pool: Pool = .empty,
        counters: storage.Counters = .{},

        pub fn init(gpa: Allocator, translator: Tr) Self {
            comptime assert(T.ordered); // A partitioned ordered index needs an ordered translator.
            return .{ .gpa = gpa, .translator = translator };
        }

        pub fn deinit(self: *Self) void {
            var current = self.tree.getMin();
            while (current) |node| : (current = node.next()) item(node).values.deinit(self.gpa);
            self.pool.deinit(self.gpa);
            self.* = undefined;
        }

        fn item(node: *Tree.Node) *Item {
            return @fieldParentPtr("node", node);
        }

        fn find(self: *const Self, key: Key) ?*Item {
            var current = self.tree.root;
            while (current) |node| {
                current = switch (Tr.order(key, node.key)) {
                    .eq => return item(node),
                    .lt => node.children[0],
                    .gt => node.children[1],
                };
            }
            return null;
        }

        /// The run of `key`, created empty if missing.
        fn find_or_create(self: *Self, key: Key) Allocator.Error!*Item {
            var slot = self.tree.getEntryFor(key);
            if (slot.node) |node| return item(node);
            const created = try self.pool.create(self.gpa);
            created.values = .empty;
            slot.set(&created.node);
            return created;
        }

        fn destroy(self: *Self, run: *Item) void {
            assert(run.values.items.len == 0);
            run.values.deinit(self.gpa);
            var slot = self.tree.getEntryForExisting(&run.node);
            slot.set(null);
            self.pool.destroy(run);
        }

        fn values_of(run: ?*const Item) Values {
            const found = run orelse return .{};
            return .{ .items = found.values.items };
        }

        /// The values whose keys translate like `key`, in insertion order.
        pub fn get(self: *const Self, key: []const u8) Values {
            return values_of(self.find(self.translator.transform(key)));
        }

        pub fn get_many(
            self: *const Self,
            lookups: []const []const u8,
            visit_context: anytype,
            comptime visit: fn (@TypeOf(visit_context), usize, *const V) void,
        ) void {
            for (lookups, 0..) |key, index| {
                var values = self.get(key);
                while (values.next()) |value| visit(visit_context, index, value);
            }
        }

        /// A cursor over the values of `key`, or null if it has none. Call `finish` when done.
        pub fn get_mut(self: *Self, key: []const u8) ?Cursor {
            const run = self.find(self.translator.transform(key)) orelse return null;
            assert(run.values.items.len > 0);
            return .{ .index = self, .run = run };
        }

        /// A cursor over the values of `key`, or, if it has none, inserts `value` and returns
        /// null.
        pub fn get_mut_or_insert(self: *Self, key: []const u8, value: V) Allocator.Error!?Cursor {
            if (self.get_mut(key)) |cursor| return cursor;
            try self.insert(key, value);
            return null;
        }

        /// Appends `value` to the run of `key`.
        pub fn insert(self: *Self, key: []const u8, value: V) Allocator.Error!void {
            const run = try self.find_or_create(self.translator.transform(key));
            const created = run.values.items.len == 0;
            run.values.append(self.gpa, value) catch |err| {
                if (created) self.destroy(run);
                return err;
            };
            self.counters.keys += @intFromBool(created);
            self.counters.items += 1;
        }

        /// Removes the values of `key` that `should_retain` rejects, then appends `value` if it
        /// is retained.
        pub fn insert_and_retain(
            self: *Self,
            key: []const u8,
            value: V,
            retain_context: anytype,
            comptime should_retain: fn (@TypeOf(retain_context), *const V) bool,
        ) Allocator.Error!void {
            if (self.get_mut(key)) |found| {
                var cursor = found;
                defer cursor.finish();
                cursor.retain(retain_context, should_retain);
                if (should_retain(retain_context, &value)) try cursor.insert(value);
            } else if (should_retain(retain_context, &value)) {
                try self.insert(key, value);
            }
        }

        pub fn retain(
            self: *Self,
            key: []const u8,
            retain_context: anytype,
            comptime should_retain: fn (@TypeOf(retain_context), *const V) bool,
        ) void {
            var cursor = self.get_mut(key) orelse return;
            defer cursor.finish();
            cursor.retain(retain_context, should_retain);
        }

        /// Removes every value of `key`.
        pub fn remove(self: *Self, key: []const u8) void {
            const run = self.find(self.translator.transform(key)) orelse return;
            const count = run.values.items.len;
            assert(count > 0);
            run.values.clearRetainingCapacity();
            self.destroy(run);
            self.counters.keys -= 1;
            self.counters.items -= count;
            self.counters.pruned += count;
        }

        /// Moves every run of `other` into `self`, which holds none of `other`'s keys (the
        /// `install_range` half of commonware's `Partitioned`). Reserves first, so an error
        /// changes nothing.
        pub fn absorb(self: *Self, other: *Self) Allocator.Error!void {
            assert(self != other);
            var runs: usize = 0;
            var counting = other.tree.getMin();
            while (counting) |node| : (counting = node.next()) runs += 1;
            assert(runs == other.counters.keys);
            try self.pool.addCapacity(self.gpa, runs);
            var current = other.tree.getMin();
            while (current) |node| : (current = node.next()) {
                const moved = item(node);
                assert(moved.values.items.len > 0);
                // Proof: `addCapacity` above put `runs` free items in the pool.
                const created = self.pool.create(self.gpa) catch unreachable;
                created.values = moved.values;
                moved.values = .empty;
                var slot = self.tree.getEntryFor(node.key);
                assert(slot.node == null);
                slot.set(&created.node);
            }
            self.counters.keys += other.counters.keys;
            self.counters.items += other.counters.items;
            self.counters.pruned += other.counters.pruned;
            // `other`'s runs are empty now; drop them so it reads as an empty index.
            other.deinit();
            other.* = .init(self.gpa, self.translator);
        }

        pub fn for_each_value(
            self: *const Self,
            visit_context: anytype,
            comptime visit: fn (@TypeOf(visit_context), *const V) void,
        ) void {
            var current = self.tree.getMin();
            while (current) |node| : (current = node.next()) {
                for (item(node).values.items) |*value| visit(visit_context, value);
            }
        }

        pub const Neighbor = storage.NeighborOf(Values);

        /// The values of the largest translated key below `key`'s, or of the largest key if
        /// there is none (`cycled`). Null when the index is empty.
        pub fn prev_translated_key(self: *const Self, key: []const u8) ?Neighbor {
            const translated = self.translator.transform(key);
            var best: ?*Tree.Node = null;
            var current = self.tree.root;
            while (current) |node| {
                const below = Tr.order(node.key, translated) == .lt;
                if (below) best = node;
                current = node.children[@intFromBool(below)];
            }
            if (best) |node| return .{ .values = values_of(item(node)), .cycled = false };
            const values = self.last_translated_key() orelse return null;
            return .{ .values = values, .cycled = true };
        }

        /// The values of the smallest translated key above `key`'s, or of the smallest key if
        /// there is none (`cycled`). Null when the index is empty.
        pub fn next_translated_key(self: *const Self, key: []const u8) ?Neighbor {
            const translated = self.translator.transform(key);
            var best: ?*Tree.Node = null;
            var current = self.tree.root;
            while (current) |node| {
                const above = Tr.order(node.key, translated) == .gt;
                if (above) best = node;
                current = node.children[@intFromBool(!above)];
            }
            if (best) |node| return .{ .values = values_of(item(node)), .cycled = false };
            const values = self.first_translated_key() orelse return null;
            return .{ .values = values, .cycled = true };
        }

        pub fn first_translated_key(self: *const Self) ?Values {
            return values_of(item(self.tree.getMin() orelse return null));
        }

        pub fn last_translated_key(self: *const Self) ?Values {
            return values_of(item(self.tree.getMax() orelse return null));
        }

        pub fn keys(self: *const Self) u64 {
            return self.counters.keys;
        }

        pub fn items(self: *const Self) u64 {
            return self.counters.items;
        }

        pub fn pruned(self: *const Self) u64 {
            return self.counters.pruned;
        }

        const State = union(enum) {
            /// `next` must be called; it returns the value at this offset.
            need_next: usize,
            active: usize,
            done,
        };

        /// Walks and edits one key's run by offset (commonware's partition `Cursor`). End it
        /// with `finish`, which removes the key if its run is empty; no other index method may
        /// run in between.
        pub const Cursor = struct {
            index: *Self,
            run: *Item,
            state: State = .{ .need_next = 0 },

            pub fn next(self: *Cursor) ?*V {
                const offset = switch (self.state) {
                    .done => return null,
                    .need_next => |from| from,
                    .active => |offset| offset + 1,
                };
                if (offset >= self.run.values.items.len) {
                    self.state = .done;
                    return null;
                }
                self.state = .{ .active = offset };
                return &self.run.values.items[offset];
            }

            fn active(self: *const Cursor) usize {
                return switch (self.state) {
                    .need_next => @panic("must call Cursor::next()"),
                    .done => @panic("no active item in Cursor"),
                    .active => |offset| offset,
                };
            }

            pub fn update(self: *Cursor, value: V) void {
                self.run.values.items[self.active()] = value;
            }

            /// Inserts `value` after the current one (`next` skips it), or appends it once
            /// every value was visited.
            pub fn insert(self: *Cursor, value: V) Allocator.Error!void {
                const values = &self.run.values;
                const gpa = self.index.gpa;
                switch (self.state) {
                    .need_next => @panic("must call Cursor::next()"),
                    .active => |offset| {
                        try values.insert(gpa, offset + 1, value);
                        self.state = .{ .need_next = offset + 2 };
                    },
                    .done => {
                        try values.append(gpa, value);
                        self.index.counters.keys += @intFromBool(values.items.len == 1);
                    },
                }
                self.index.counters.items += 1;
            }

            /// Removes the current value; `next` then returns the one after it.
            pub fn delete(self: *Cursor) void {
                const offset = self.active();
                const counters = &self.index.counters;
                _ = self.run.values.orderedRemove(offset);
                counters.keys -= @intFromBool(self.run.values.items.len == 0);
                counters.items -= 1;
                counters.pruned += 1;
                self.state = .{ .need_next = offset };
            }

            pub fn retain(
                self: *Cursor,
                retain_context: anytype,
                comptime should_retain: fn (@TypeOf(retain_context), *const V) bool,
            ) void {
                while (self.next()) |value| {
                    if (!should_retain(retain_context, value)) self.delete();
                }
            }

            pub fn find(
                self: *Cursor,
                find_context: anytype,
                comptime predicate: fn (@TypeOf(find_context), *const V) bool,
            ) bool {
                while (self.next()) |value| {
                    if (predicate(find_context, value)) return true;
                }
                return false;
            }

            /// Removes the key if its run is empty.
            pub fn finish(self: *Cursor) void {
                if (self.run.values.items.len == 0) self.index.destroy(self.run);
                self.* = undefined;
            }
        };
    };
}

const testing = std.testing;
const translators = @import("../../translator.zig");
const test_gpa = testing.allocator;

/// `P = 1` over `u64` with a one-byte translator, so keys sharing a partition and the next
/// byte share a run.
const TestIndex = Index(translators.OneCap, u64, 1);

fn new_test_range(
    full: *const TestIndex,
    offset: u32,
    count: u32,
) Range(translators.OneCap, u64, 1) {
    return new_range(translators.OneCap, u64, 1, full, offset, count);
}

const Seen = std.ArrayList(u64);

fn collect(seen: *Seen, value: *const u64) void {
    seen.appendAssumeCapacity(value.*);
}

fn expect_values(index: *const TestIndex, key: []const u8, expected: []const u64) !void {
    var values = index.get(key);
    var actual: [8]u64 = undefined;
    var count: usize = 0;
    while (values.next()) |value| : (count += 1) actual[count] = value.*;
    try testing.expectEqualSlices(u64, expected, actual[0..count]);
}

test "partitioned ordered range visits every value once" {
    var full: TestIndex = .init(test_gpa, .init(.{}));
    defer full.deinit();
    // A translated-key collision appends a second value to a run in partition 0x80; partition
    // 0x81 holds one key.
    var range = new_test_range(&full, 0x80, 2);
    defer range.deinit();
    try testing.expect(try range.get_mut_or_insert(&.{ 0x80, 0x01 }, 1) == null);
    try testing.expect(try range.get_mut_or_insert(&.{ 0x80, 0x02, 0xaa }, 2) == null);
    var existing = (try range.get_mut_or_insert(&.{ 0x80, 0x02, 0xbb }, 3)).?;
    existing.finish();
    {
        var cursor = range.get_mut(&.{ 0x80, 0x02, 0xbb }).?;
        defer cursor.finish();
        _ = cursor.next();
        try cursor.insert(3);
    }
    try testing.expect(try range.get_mut_or_insert(&.{ 0x81, 0x07 }, 4) == null);
    var seen: Seen = try .initCapacity(test_gpa, 8);
    defer seen.deinit(test_gpa);
    range.for_each_value(&seen, collect);
    std.mem.sort(u64, seen.items, {}, std.sort.asc(u64));
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3, 4 }, seen.items);
}

test "partitioned ordered install range at a nonzero offset" {
    var full: TestIndex = .init(test_gpa, .init(.{}));
    defer full.deinit();
    // Something already in the full index outside the range stays.
    try full.insert(&.{ 0x7f, 0x01 }, 9);
    {
        // A range over global partitions [0x80, 0x82): two keys in 0x80, one in 0x81.
        var range = new_test_range(&full, 0x80, 2);
        errdefer range.deinit();
        try testing.expect(try range.get_mut_or_insert(&.{ 0x80, 0x01 }, 1) == null);
        try testing.expect(try range.get_mut_or_insert(&.{ 0x80, 0x02 }, 2) == null);
        try testing.expect(try range.get_mut_or_insert(&.{ 0x81, 0x07 }, 3) == null);
        try testing.expectEqual(@as(u64, 3), range.index.keys());
        try range.install(&full);
    }
    try testing.expectEqual(@as(u64, 4), full.keys());
    try testing.expectEqual(@as(u64, 4), full.items());
    try expect_values(&full, &.{ 0x80, 0x01 }, &.{1});
    try expect_values(&full, &.{ 0x80, 0x02 }, &.{2});
    try expect_values(&full, &.{ 0x81, 0x07 }, &.{3});
    try expect_values(&full, &.{ 0x7f, 0x01 }, &.{9});
    // A remap that dropped the offset would file the entries at partitions 0x00 and 0x01.
    try expect_values(&full, &.{ 0x00, 0x01 }, &.{});
    try expect_values(&full, &.{ 0x01, 0x07 }, &.{});
    // Ordered navigation crosses the installed partitions in prefix order.
    var next = full.next_translated_key(&.{ 0x7f, 0x01 }).?;
    try testing.expectEqual(@as(u64, 1), next.values.next().?.*);
}
