//! An index whose translated keys live in a balanced search tree, so it can also walk keys in
//! order (port of commonware's `storage/src/index/ordered.rs`, which uses a `BTreeMap`).
//!
//! The tree is a B-tree of the same order as Rust's `BTreeMap` (B = 6: 5 to 11 keys per node
//! below the root), with nodes from memory pools. A treap kept one key per node and cost a
//! cache miss per level (index::insert ordered read 1.33× commonware's `BTreeMap`). Values
//! move when nodes split or merge, so a value pointer is valid only until the next insert or
//! remove, as `storage.Index` uses it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const storage = @import("storage.zig");
const translator_module = @import("../translator.zig");

/// Rust's `BTreeMap` order: nodes hold `b - 1` to `2b - 1` keys (the root as few as one).
const b = 6;
const capacity = 2 * b - 1;
/// A tree of `n` keys is at most `1 + log_b(n)` levels deep: 26 levels exceed any `u64` count.
const height_max = 32;

/// The heads of an ordered index: a B-tree keyed by the translated key.
fn Heads(comptime T: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const Key = T.Key;

        const Node = struct {
            keys: [capacity]Key = undefined,
            values: [capacity]V = undefined,
            len: u8 = 0,
            leaf: bool,
        };

        const Internal = struct {
            node: Node = .{ .leaf = false },
            children: [capacity + 1]*Node = undefined,
        };

        root: ?*Node = null,
        leaves: std.heap.MemoryPool(Node) = .empty,
        internals: std.heap.MemoryPool(Internal) = .empty,

        /// Lookups do not warm the entry for a following update (commonware's
        /// `LOOKUP_WARMS_UPDATE = false` for its `BTreeMap`).
        pub const lookup_warms_update = false;

        pub const Entry = struct { key: Key, value: *V };

        pub fn init(_: T) Self {
            return .{};
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.leaves.deinit(gpa);
            self.internals.deinit(gpa);
        }

        fn children(node: *Node) *[capacity + 1]*Node {
            assert(!node.leaf);
            return &@as(*Internal, @fieldParentPtr("node", node)).children;
        }

        /// The number of keys of `node` ordered before `key`, and whether the next one is it.
        fn search(node: *const Node, key: Key) struct { usize, bool } {
            var index: usize = 0;
            while (index < node.len) : (index += 1) {
                switch (T.order(key, node.keys[index])) {
                    .lt => return .{ index, false },
                    .eq => return .{ index, true },
                    .gt => {},
                }
            }
            return .{ node.len, false };
        }

        pub fn get(self: *const Self, key: Key) ?*V {
            var current = self.root orelse return null;
            for (0..height_max) |_| {
                const index, const found = search(current, key);
                if (found) return &current.values[index];
                if (current.leaf) return null;
                current = children(current)[index];
            }
            unreachable; // The tree is at most `height_max` levels deep.
        }

        fn create(self: *Self, gpa: Allocator, leaf: bool) Allocator.Error!*Node {
            if (leaf) {
                const node = try self.leaves.create(gpa);
                node.* = .{ .leaf = true };
                return node;
            }
            const internal = try self.internals.create(gpa);
            internal.* = .{};
            return &internal.node;
        }

        fn destroy(self: *Self, node: *Node) void {
            if (node.leaf) return self.leaves.destroy(node);
            self.internals.destroy(@fieldParentPtr("node", node));
        }

        /// Splits the full child `index` of `parent` in two around its middle key, which moves
        /// up into `parent` at `index`.
        fn split(self: *Self, gpa: Allocator, parent: *Node, index: usize) Allocator.Error!void {
            const left = children(parent)[index];
            assert(left.len == capacity and parent.len < capacity);
            const right = try self.create(gpa, left.leaf);
            right.len = b - 1;
            @memcpy(right.keys[0 .. b - 1], left.keys[b..capacity]);
            @memcpy(right.values[0 .. b - 1], left.values[b..capacity]);
            if (!left.leaf) @memcpy(children(right)[0..b], children(left)[b .. capacity + 1]);
            left.len = b - 1;
            insert_at(parent, index, left.keys[b - 1], left.values[b - 1]);
            const links = children(parent);
            const tail = links[index + 1 .. parent.len];
            std.mem.copyBackwards(*Node, links[index + 2 .. parent.len + 1], tail);
            links[index + 1] = right;
            assert(left.len == b - 1 and right.len == b - 1);
        }

        /// Puts `key` and `value` at `index` of `node`, shifting the later keys right (but not
        /// the children).
        fn insert_at(node: *Node, index: usize, key: Key, value: V) void {
            assert(node.len < capacity and index <= node.len);
            const len = node.len;
            std.mem.copyBackwards(Key, node.keys[index + 1 .. len + 1], node.keys[index..len]);
            std.mem.copyBackwards(V, node.values[index + 1 .. len + 1], node.values[index..len]);
            node.keys[index] = key;
            node.values[index] = value;
            node.len += 1;
        }

        /// Removes the key at `index` of `node`, shifting the later keys left (but not the
        /// children).
        fn remove_at(node: *Node, index: usize) void {
            assert(index < node.len);
            const len = node.len;
            std.mem.copyForwards(Key, node.keys[index .. len - 1], node.keys[index + 1 .. len]);
            std.mem.copyForwards(V, node.values[index .. len - 1], node.values[index + 1 .. len]);
            node.len -= 1;
        }

        /// Removes child `index` of `node`, shifting the later children left.
        fn remove_child(node: *Node, index: usize) void {
            const links = children(node);
            assert(index <= node.len + 1);
            std.mem.copyForwards(*Node, links[index .. node.len + 1], links[index + 1 .. node.len +
                2]);
        }

        /// Splits full nodes on the way down (preemptively), so the leaf reached has room.
        pub fn get_or_put(self: *Self, gpa: Allocator, key: Key) !storage.GetOrPut(V) {
            if (self.root == null) self.root = try self.create(gpa, true);
            if (self.root.?.len == capacity) {
                const top = try self.create(gpa, false);
                children(top)[0] = self.root.?;
                self.root = top;
                errdefer {
                    self.root = children(top)[0];
                    self.destroy(top);
                }
                try self.split(gpa, top, 0);
            }
            var current = self.root.?;
            for (0..height_max) |_| {
                var index, const found = search(current, key);
                if (found) return .{ .value_ptr = &current.values[index], .found_existing = true };
                if (current.leaf) {
                    insert_at(current, index, key, undefined);
                    return .{ .value_ptr = &current.values[index], .found_existing = false };
                }
                if (children(current)[index].len == capacity) {
                    try self.split(gpa, current, index);
                    switch (T.order(key, current.keys[index])) {
                        .eq => {
                            const value = &current.values[index];
                            return .{ .value_ptr = value, .found_existing = true };
                        },
                        .lt => {},
                        .gt => index += 1,
                    }
                }
                current = children(current)[index];
            }
            unreachable; // The tree is at most `height_max` levels deep.
        }

        /// Merges child `index + 1` of `node` and the key between into child `index`.
        fn merge(self: *Self, node: *Node, index: usize) void {
            const links = children(node);
            const left = links[index];
            const right = links[index + 1];
            assert(left.len + right.len + 1 <= capacity);
            const at = left.len;
            left.keys[at] = node.keys[index];
            left.values[at] = node.values[index];
            @memcpy(left.keys[at + 1 ..][0..right.len], right.keys[0..right.len]);
            @memcpy(left.values[at + 1 ..][0..right.len], right.values[0..right.len]);
            if (!left.leaf) {
                const moved = children(right)[0 .. right.len + 1];
                @memcpy(children(left)[at + 1 ..][0..moved.len], moved);
            }
            left.len += right.len + 1;
            remove_at(node, index);
            remove_child(node, index + 1);
            self.destroy(right);
        }

        /// Moves the last key of child `index - 1` up and the key between down into child
        /// `index`, which has `b - 1` keys.
        fn rotate_right(node: *Node, index: usize) void {
            const links = children(node);
            const left = links[index - 1];
            const right = links[index];
            assert(left.len >= b and right.len == b - 1);
            insert_at(right, 0, node.keys[index - 1], node.values[index - 1]);
            if (!right.leaf) {
                const moved = children(right);
                std.mem.copyBackwards(*Node, moved[1 .. right.len + 1], moved[0..right.len]);
                moved[0] = children(left)[left.len];
            }
            node.keys[index - 1] = left.keys[left.len - 1];
            node.values[index - 1] = left.values[left.len - 1];
            left.len -= 1;
        }

        /// Moves the first key of child `index + 1` up and the key between down into child
        /// `index`, which has `b - 1` keys.
        fn rotate_left(node: *Node, index: usize) void {
            const links = children(node);
            const left = links[index];
            const right = links[index + 1];
            assert(right.len >= b and left.len == b - 1);
            left.keys[left.len] = node.keys[index];
            left.values[left.len] = node.values[index];
            left.len += 1;
            if (!left.leaf) children(left)[left.len] = children(right)[0];
            node.keys[index] = right.keys[0];
            node.values[index] = right.values[0];
            remove_at(right, 0);
            if (!right.leaf) remove_child(right, 0);
        }

        /// Gives child `index` of `node` at least `b` keys, by a rotation or a merge. Returns
        /// the index of the child that now covers the keys child `index` covered.
        fn fill(self: *Self, node: *Node, index: usize) usize {
            const links = children(node);
            if (links[index].len >= b) return index;
            if (index > 0 and links[index - 1].len >= b) {
                rotate_right(node, index);
                return index;
            }
            if (index < node.len and links[index + 1].len >= b) {
                rotate_left(node, index);
                return index;
            }
            if (index < node.len) {
                self.merge(node, index);
                return index;
            }
            self.merge(node, index - 1);
            return index - 1;
        }

        /// The largest key and its value below child `index` of `node`.
        fn predecessor(node: *Node, index: usize) struct { Key, V } {
            var current = children(node)[index];
            for (0..height_max) |_| {
                const at = current.len - 1;
                if (current.leaf) return .{ current.keys[at], current.values[at] };
                current = children(current)[current.len];
            }
            unreachable; // The tree is at most `height_max` levels deep.
        }

        /// The smallest key and its value below child `index` of `node`.
        fn successor(node: *Node, index: usize) struct { Key, V } {
            var current = children(node)[index];
            for (0..height_max) |_| {
                if (current.leaf) return .{ current.keys[0], current.values[0] };
                current = children(current)[0];
            }
            unreachable; // The tree is at most `height_max` levels deep.
        }

        /// Removes `key`, which must be present. Descends so that every node it leaves has at
        /// least `b` keys (CLRS's one-pass delete).
        pub fn remove(self: *Self, _: Allocator, key: Key) void {
            var target = key;
            var current = self.root.?;
            for (0..height_max) |_| {
                const index, const found = search(current, target);
                if (current.leaf) {
                    assert(found); // The key must be present.
                    remove_at(current, index);
                    break;
                }
                const next = if (found)
                    self.remove_internal(current, index, &target)
                else
                    self.fill(current, index);
                current = children(current)[next];
            } else unreachable; // The tree is at most `height_max` levels deep.
            self.shrink();
        }

        /// Removes the key at `index` of the internal `node`: replaces it with its predecessor
        /// or successor (then deleted below as `target`), or merges it into a child. Returns
        /// the child to descend into.
        fn remove_internal(self: *Self, node: *Node, index: usize, target: *Key) usize {
            const links = children(node);
            if (links[index].len >= b) {
                const key, const value = predecessor(node, index);
                node.keys[index] = key;
                node.values[index] = value;
                target.* = key;
                return index;
            }
            if (links[index + 1].len >= b) {
                const key, const value = successor(node, index + 1);
                node.keys[index] = key;
                node.values[index] = value;
                target.* = key;
                return index + 1;
            }
            self.merge(node, index);
            return index;
        }

        /// Drops an empty root: a leaf root empties the tree, an internal one hands over to its
        /// only child.
        fn shrink(self: *Self) void {
            const top = self.root.?;
            if (top.len > 0) return;
            self.root = if (top.leaf) null else children(top)[0];
            self.destroy(top);
        }

        pub fn for_each_value(
            self: *const Self,
            visit_context: anytype,
            comptime visit: fn (@TypeOf(visit_context), *const V) void,
        ) void {
            const top = self.root orelse return;
            // Each frame is a node and the next of its keys to visit, its children before.
            var stack: [height_max]struct { node: *Node, next: usize } = undefined;
            var depth: usize = 0;
            var current: ?*Node = top;
            while (true) {
                while (current) |node| {
                    assert(depth < height_max);
                    stack[depth] = .{ .node = node, .next = 0 };
                    depth += 1;
                    current = if (node.leaf) null else children(node)[0];
                }
                if (depth == 0) return;
                const frame = &stack[depth - 1];
                if (frame.next == frame.node.len) {
                    depth -= 1;
                    continue;
                }
                visit(visit_context, &frame.node.values[frame.next]);
                frame.next += 1;
                current = if (frame.node.leaf) null else children(frame.node)[frame.next];
            }
        }

        fn entry(node: *Node, index: usize) Entry {
            assert(index < node.len);
            return .{ .key = node.keys[index], .value = &node.values[index] };
        }

        pub fn first(self: *const Self) ?Entry {
            var current = self.root orelse return null;
            while (!current.leaf) current = children(current)[0];
            return entry(current, 0);
        }

        pub fn last(self: *const Self) ?Entry {
            var current = self.root orelse return null;
            while (!current.leaf) current = children(current)[current.len];
            return entry(current, current.len - 1);
        }

        /// The entry with the largest key below `key`.
        pub fn before(self: *const Self, key: Key) ?Entry {
            var best: ?Entry = null;
            var current = self.root orelse return null;
            for (0..height_max) |_| {
                // Keys below `key` come before `index`; children(index) holds the gap or the
                // keys just below an equal one.
                const index, _ = search(current, key);
                if (index > 0) best = entry(current, index - 1);
                if (current.leaf) return best;
                current = children(current)[index];
            }
            unreachable; // The tree is at most `height_max` levels deep.
        }

        /// The entry with the smallest key above `key`.
        pub fn after(self: *const Self, key: Key) ?Entry {
            var best: ?Entry = null;
            var current = self.root orelse return null;
            for (0..height_max) |_| {
                const below, const found = search(current, key);
                const index = below + @intFromBool(found);
                if (index < current.len) best = entry(current, index);
                if (current.leaf) return best;
                current = children(current)[index];
            }
            unreachable; // The tree is at most `height_max` levels deep.
        }

        /// Asserts the B-tree's shape: sorted keys, node sizes, and leaves at one depth.
        /// Returns the number of keys.
        fn check(self: *const Self) !usize {
            const top = self.root orelse return 0;
            var count: usize = 0;
            var leaf_depth: ?usize = null;
            const Frame = struct { node: *Node, depth: usize };
            var stack: [height_max * (capacity + 1)]Frame = undefined;
            var len: usize = 1;
            stack[0] = .{ .node = top, .depth = 0 };
            while (len > 0) {
                len -= 1;
                const frame = stack[len];
                const node = frame.node;
                try std.testing.expect(node.len >= 1 and node.len <= capacity);
                if (node != top) try std.testing.expect(node.len >= b - 1);
                for (1..node.len) |i| {
                    try std.testing.expect(T.order(node.keys[i - 1], node.keys[i]) == .lt);
                }
                count += node.len;
                if (node.leaf) {
                    if (leaf_depth) |d| try std.testing.expectEqual(d, frame.depth);
                    leaf_depth = frame.depth;
                    continue;
                }
                for (children(node)[0 .. node.len + 1], 0..) |child, i| {
                    const low = child.keys[0];
                    const high = child.keys[child.len - 1];
                    if (i > 0) try std.testing.expect(T.order(node.keys[i - 1], low) == .lt);
                    if (i < node.len) try std.testing.expect(T.order(high, node.keys[i]) == .lt);
                    assert(len < stack.len);
                    stack[len] = .{ .node = child, .depth = frame.depth + 1 };
                    len += 1;
                }
            }
            return count;
        }
    };
}

/// An ordered index from keys (through translator `T`, which must preserve key order) to
/// values `V`.
pub fn Index(comptime T: type, comptime V: type) type {
    translator_module.check(T);
    return storage.Index(T, V, Heads(T, V));
}

const testing = std.testing;

fn collect(value_list: *std.ArrayList(u64), value: *const u64) void {
    value_list.appendAssumeCapacity(value.*);
}

test "ordered heads B-tree against a sorted model" {
    // Thousands of distinct keys make a tree three levels deep, so splits, rotations both
    // ways, merges, and root growth and shrinkage all run. Checked against a sorted array.
    const gpa = testing.allocator;
    const TwoCap = translator_module.TwoCap;
    const H = Heads(TwoCap, u64);
    var heads = H.init(.{});
    defer heads.deinit(gpa);
    var model: std.ArrayList(u16) = .empty;
    defer model.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(0x6274_7265_65);
    const random = prng.random();
    var seen: std.ArrayList(u64) = .empty;
    defer seen.deinit(gpa);
    for (0..40_000) |step| {
        const key = random.uintLessThan(u16, 6000);
        const at = std.sort.lowerBound(u16, model.items, key, order_u16);
        const present = at < model.items.len and model.items[at] == key;
        // Grow for the first half, then shrink to empty.
        const removing = present and (step > 20_000 or random.uintLessThan(u8, 4) == 0);
        if (removing) {
            heads.remove(gpa, key);
            _ = model.orderedRemove(at);
        } else {
            const slot = try heads.get_or_put(gpa, key);
            try testing.expectEqual(present, slot.found_existing);
            slot.value_ptr.* = key;
            if (!present) try model.insert(gpa, at, key);
        }
        const checkpoint = step % 997 == 0 or step >= 39_990;
        if (checkpoint) try expect_matches(&heads, model.items, &seen, random);
    }
    while (model.items.len > 0) {
        const index = random.uintLessThan(usize, model.items.len);
        heads.remove(gpa, model.orderedRemove(index));
        if (model.items.len % 499 == 0) try expect_matches(&heads, model.items, &seen, random);
    }
    try testing.expect(heads.root == null);
}

fn order_u16(a: u16, b_key: u16) std.math.Order {
    return std.math.order(a, b_key);
}

fn expect_matches(
    heads: anytype,
    model: []const u16,
    seen: *std.ArrayList(u64),
    random: std.Random,
) !void {
    try testing.expectEqual(model.len, try heads.check());
    seen.clearRetainingCapacity();
    try seen.ensureTotalCapacity(testing.allocator, model.len);
    heads.for_each_value(seen, collect);
    try testing.expectEqual(model.len, seen.items.len);
    for (model, seen.items) |key, value| try testing.expectEqual(@as(u64, key), value);
    if (model.len == 0) {
        try testing.expect(heads.first() == null and heads.last() == null);
        return;
    }
    try testing.expectEqual(model[0], heads.first().?.key);
    try testing.expectEqual(model[model.len - 1], heads.last().?.key);
    for (0..64) |_| {
        const query = random.uintLessThan(u16, 6002);
        const at = std.sort.lowerBound(u16, model, query, order_u16);
        const hit = at < model.len and model[at] == query;
        try testing.expectEqual(hit, heads.get(query) != null);
        const before = heads.before(query);
        try testing.expectEqual(at > 0, before != null);
        if (at > 0) try testing.expectEqual(model[at - 1], before.?.key);
        const next = at + @intFromBool(hit);
        const after = heads.after(query);
        try testing.expectEqual(next < model.len, after != null);
        if (next < model.len) try testing.expectEqual(model[next], after.?.key);
    }
}
