//! An index whose translated keys live in a balanced search tree, so it can also walk keys in
//! order (port of commonware's `storage/src/index/ordered.rs`, which uses a `BTreeMap`).
//!
//! The tree is a `std.Treap` whose nodes come from a memory pool. Its shape depends on node
//! addresses, but no result does: every query is by key order.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const storage = @import("storage.zig");
const translator_module = @import("../translator.zig");

/// The heads of an ordered index: a treap keyed by the translated key.
fn Heads(comptime T: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const Tree = std.Treap(T.Key, T.order);
        const Item = struct { node: Tree.Node, value: V };
        const Pool = std.heap.MemoryPool(Item);

        tree: Tree = .{},
        pool: Pool = .empty,

        /// Lookups do not warm the entry for a following update (commonware's
        /// `LOOKUP_WARMS_UPDATE = false` for its `BTreeMap`).
        pub const lookup_warms_update = false;

        pub const Entry = struct { key: T.Key, value: *V };

        pub fn init(_: T) Self {
            return .{};
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.pool.deinit(gpa);
        }

        fn item(node: *Tree.Node) *Item {
            return @fieldParentPtr("node", node);
        }

        fn entry(node: *Tree.Node) Entry {
            return .{ .key = node.key, .value = &item(node).value };
        }

        pub fn get(self: *const Self, key: T.Key) ?*V {
            var current = self.tree.root;
            // Each step descends one level, so this runs at most the tree's height.
            while (current) |node| {
                current = switch (T.order(key, node.key)) {
                    .eq => return &item(node).value,
                    .lt => node.children[0],
                    .gt => node.children[1],
                };
            }
            return null;
        }

        pub fn get_or_put(self: *Self, gpa: Allocator, key: T.Key) !storage.GetOrPut(V) {
            var slot = self.tree.getEntryFor(key);
            if (slot.node) |node| {
                return .{ .value_ptr = &item(node).value, .found_existing = true };
            }
            const created = try self.pool.create(gpa);
            slot.set(&created.node);
            assert(T.eql(created.node.key, key));
            return .{ .value_ptr = &created.value, .found_existing = false };
        }

        pub fn remove(self: *Self, _: Allocator, key: T.Key) void {
            var slot = self.tree.getEntryFor(key);
            const node = slot.node.?; // The key must be present.
            slot.set(null);
            self.pool.destroy(item(node));
        }

        pub fn for_each_value(
            self: *const Self,
            visit_context: anytype,
            comptime visit: fn (@TypeOf(visit_context), *const V) void,
        ) void {
            var current = self.tree.getMin();
            while (current) |node| : (current = node.next()) {
                visit(visit_context, &item(node).value);
            }
        }

        pub fn first(self: *const Self) ?Entry {
            return entry(self.tree.getMin() orelse return null);
        }

        pub fn last(self: *const Self) ?Entry {
            return entry(self.tree.getMax() orelse return null);
        }

        /// The entry with the largest key below `key`.
        pub fn before(self: *const Self, key: T.Key) ?Entry {
            var best: ?*Tree.Node = null;
            var current = self.tree.root;
            while (current) |node| {
                if (T.order(node.key, key) == .lt) {
                    best = node;
                    current = node.children[1];
                } else {
                    current = node.children[0];
                }
            }
            return entry(best orelse return null);
        }

        /// The entry with the smallest key above `key`.
        pub fn after(self: *const Self, key: T.Key) ?Entry {
            var best: ?*Tree.Node = null;
            var current = self.tree.root;
            while (current) |node| {
                if (T.order(node.key, key) == .gt) {
                    best = node;
                    current = node.children[0];
                } else {
                    current = node.children[1];
                }
            }
            return entry(best orelse return null);
        }
    };
}

/// An ordered index from keys (through translator `T`, which must preserve key order) to
/// values `V`.
pub fn Index(comptime T: type, comptime V: type) type {
    translator_module.check(T);
    return storage.Index(T, V, Heads(T, V));
}
