//! A partitioned ordered index (port of commonware's `storage/src/index/partitioned/ordered`).
//!
//! Unlike the flat indices, a key's values form a run in insertion order: `insert` appends to
//! the run, `get` yields it front to back, and the cursor walks it by offset. As commonware's,
//! each of the `256^P` partitions keeps its translated keys and values as two parallel sorted
//! arrays, a run being adjacent equal keys, so a lookup is an array index and a short binary
//! search. A partition whose arrays reach `spill_threshold` entries moves to a side table of
//! ordered trees (commonware's `BTreeMap`) on its next access, which bounds the cost of inserts
//! into a partition that grinding keys fill; it returns to arrays once emptied. The partition
//! array is allocated on the first insert, so `init` does not allocate.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const partitioned = @import("mod.zig");
const storage = @import("../storage.zig");

/// Array entries at which a partition spills to the side table (commonware's
/// `SPILL_THRESHOLD`).
pub const spill_threshold: usize = 512;

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

/// One partition's runs as parallel sorted arrays (commonware's `Partition`).
fn Partition(comptime K: type, comptime V: type, comptime order: fn (K, K) std.math.Order) type {
    return struct {
        const Self = @This();
        pub const Span = struct { start: usize, end: usize };

        keys: std.ArrayList(K) = .empty,
        vals: std.ArrayList(V) = .empty,

        fn deinit(self: *Self, gpa: Allocator) void {
            self.keys.deinit(gpa);
            self.vals.deinit(gpa);
        }

        fn len(self: *const Self) usize {
            assert(self.keys.items.len == self.vals.items.len);
            return self.keys.items.len;
        }

        /// The first entry whose key is not below `key` (`strict`: not at or below).
        fn bound(self: *const Self, key: K, comptime strict: bool) usize {
            var low: usize = 0;
            var high: usize = self.keys.items.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                const relation = order(self.keys.items[middle], key);
                const before = relation == .lt or (strict and relation == .eq);
                if (before) low = middle + 1 else high = middle;
            }
            assert(low <= self.keys.items.len);
            return low;
        }

        /// The entries of `key`'s run; empty at its insertion point when absent.
        fn run_range(self: *const Self, key: K) Span {
            const start = self.bound(key, false);
            var end = start;
            while (end < self.keys.items.len and order(self.keys.items[end], key) == .eq) end += 1;
            return .{ .start = start, .end = end };
        }

        fn run_of(self: *const Self, at: usize) Span {
            assert(at < self.len());
            const key = self.keys.items[at];
            var span: Span = .{ .start = at, .end = at + 1 };
            while (span.start > 0 and order(self.keys.items[span.start - 1], key) == .eq) {
                span.start -= 1;
            }
            while (span.end < self.len() and order(self.keys.items[span.end], key) == .eq) {
                span.end += 1;
            }
            return span;
        }

        fn values(self: *const Self, span: Span) []const V {
            return self.vals.items[span.start..span.end];
        }

        /// Inserts at `at`; on error the arrays are unchanged.
        fn insert_at(
            self: *Self,
            gpa: Allocator,
            at: usize,
            key: K,
            value: V,
        ) Allocator.Error!void {
            try self.keys.ensureUnusedCapacity(gpa, 1);
            try self.vals.ensureUnusedCapacity(gpa, 1);
            self.keys.insertAssumeCapacity(at, key);
            self.vals.insertAssumeCapacity(at, value);
            assert(self.keys.items.len == self.vals.items.len);
        }

        fn remove_span(self: *Self, span: Span) void {
            assert(span.start <= span.end and span.end <= self.len());
            self.keys.replaceRangeAssumeCapacity(span.start, span.end - span.start, &.{});
            self.vals.replaceRangeAssumeCapacity(span.start, span.end - span.start, &.{});
        }
    };
}

/// A partitioned ordered index whose first `P` key bytes select a partition and translator
/// `T` (which must preserve key order) maps the rest.
pub fn Index(comptime T: type, comptime V: type, comptime P: usize) type {
    return IndexSpillAt(T, V, P, spill_threshold);
}

/// `Index` spilling at `threshold` array entries (commonware's `with_threshold`; tests use a
/// small one to exercise spilled partitions cheaply).
pub fn IndexSpillAt(comptime T: type, comptime V: type, comptime P: usize, comptime n: usize) type {
    const threshold = n;
    comptime assert(threshold > 0); // The spill threshold must be at least 1.
    return struct {
        const Self = @This();
        const Tr = partitioned.Translator(T, P);
        const K = T.Key;
        const Slots = Partition(K, V, T.order);
        const Tree = std.Treap(K, T.order);
        const List = std.ArrayList(V);
        const Item = struct { node: Tree.Node, values: List };
        const Pool = std.heap.MemoryPool(Item);
        const Located = struct { slot: u32, key: K };

        pub const Translator = Tr;
        pub const Key = Tr.Key;
        pub const Value = V;
        pub const Values = Run(V);
        pub const lookup_warms_update = false;

        gpa: Allocator,
        translator: Tr,
        /// The first global partition held (nonzero only for a worker's range).
        offset: u32 = 0,
        /// The partitions held.
        count: u32 = Tr.partition_count,
        /// `count` partitions, allocated by the first insert.
        partitions: []Slots = &.{},
        /// Spilled partitions by slot; a spilled partition's arrays are empty.
        spilled: std.AutoHashMapUnmanaged(u32, Tree) = .empty,
        /// Items of the spilled trees.
        pool: Pool = .empty,
        /// Pools of absorbed ranges whose spilled trees `absorb` took over. They live as long
        /// as `self`; a destroyed item goes to `pool`'s free list, which is safe because every
        /// pool is an arena freed only by `deinit`.
        adopted: std.ArrayList(Pool) = .empty,
        counters: storage.Counters = .{},
        spill_total: u64 = 0,

        pub fn init(gpa: Allocator, translator: Tr) Self {
            comptime assert(T.ordered); // A partitioned ordered index needs an ordered translator.
            return .{ .gpa = gpa, .translator = translator };
        }

        /// An empty index over partitions `[offset, offset + count)` (a worker's range).
        pub fn init_range(gpa: Allocator, translator: Tr, offset: u32, count: u32) Self {
            assert(count > 0);
            assert(@as(u64, offset) + count <= Tr.partition_count);
            var index = init(gpa, translator);
            index.offset = offset;
            index.count = count;
            return index;
        }

        pub fn deinit(self: *Self) void {
            for (self.partitions) |*part| part.deinit(self.gpa);
            self.gpa.free(self.partitions);
            var trees = self.spilled.valueIterator();
            while (trees.next()) |tree| {
                var current = tree.getMin();
                while (current) |node| : (current = node.next()) item(node).values.deinit(self.gpa);
            }
            self.spilled.deinit(self.gpa);
            self.pool.deinit(self.gpa);
            for (self.adopted.items) |*pool| pool.deinit(self.gpa);
            self.adopted.deinit(self.gpa);
            self.* = undefined;
        }

        fn item(node: *Tree.Node) *Item {
            return @fieldParentPtr("node", node);
        }

        fn locate(self: *const Self, key: []const u8) Located {
            const split = partitioned.partition_index_and_sub_key(P, key);
            assert(split.partition >= self.offset);
            const slot = split.partition - self.offset;
            assert(slot < self.count);
            return .{ .slot = slot, .key = self.translator.inner.transform(split.sub_key) };
        }

        /// Allocates the partition array now; otherwise the first insert does (commonware
        /// allocates it in `new`).
        pub fn ensure_partitions(self: *Self) Allocator.Error!void {
            if (self.partitions.len > 0) return;
            const partitions = try self.gpa.alloc(Slots, self.count);
            @memset(partitions, .{});
            self.partitions = partitions;
            assert(self.partitions.len == self.count);
        }

        fn tree_of(self: *const Self, slot: u32) ?*Tree {
            if (self.spilled.count() == 0) return null;
            return self.spilled.getPtr(slot);
        }

        fn find(tree: *const Tree, key: K) ?*Item {
            var current = tree.root;
            while (current) |node| {
                current = switch (T.order(key, node.key)) {
                    .eq => return item(node),
                    .lt => node.children[0],
                    .gt => node.children[1],
                };
            }
            return null;
        }

        /// The run of `key` in slot `slot`, empty when absent.
        fn values_at(self: *const Self, at: Located) Values {
            if (self.partitions.len == 0) return .{};
            const part = &self.partitions[at.slot];
            if (part.len() > 0) return .{ .items = part.values(part.run_range(at.key)) };
            const tree = self.tree_of(at.slot) orelse return .{};
            const run = find(tree, at.key) orelse return .{};
            assert(run.values.items.len > 0);
            return .{ .items = run.values.items };
        }

        /// The values whose keys translate like `key`, in insertion order.
        pub fn get(self: *const Self, key: []const u8) Values {
            return self.values_at(self.locate(key));
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

        /// Moves slot `slot`'s runs to a spilled tree once its arrays reach the threshold
        /// (commonware's `maybe_spill`). Spilling only changes the representation, so when it
        /// runs out of memory the partition stays in its arrays, which hold the same runs.
        fn maybe_spill(self: *Self, slot: u32) void {
            if (self.partitions.len == 0) return;
            if (self.partitions[slot].len() < threshold) return;
            self.spill(slot) catch |err| switch (err) {
                error.OutOfMemory => return,
            };
            assert(self.partitions[slot].len() == 0);
        }

        fn spill(self: *Self, slot: u32) Allocator.Error!void {
            const part = &self.partitions[slot];
            assert(self.tree_of(slot) == null);
            try self.spilled.ensureUnusedCapacity(self.gpa, 1);
            var tree: Tree = .{};
            errdefer self.free_tree(&tree);
            var at: usize = 0;
            while (at < part.len()) {
                const span = part.run_of(at);
                const created = try self.pool.create(self.gpa);
                created.values = .empty;
                var entry = tree.getEntryFor(part.keys.items[at]);
                assert(entry.node == null);
                entry.set(&created.node);
                try created.values.appendSlice(self.gpa, part.values(span));
                at = span.end;
            }
            self.spilled.putAssumeCapacityNoClobber(slot, tree);
            part.deinit(self.gpa);
            part.* = .{};
            self.spill_total += 1;
        }

        fn free_tree(self: *Self, tree: *Tree) void {
            while (tree.getMin()) |node| {
                const run = item(node);
                run.values.deinit(self.gpa);
                var entry = tree.getEntryForExisting(node);
                entry.set(null);
                self.pool.destroy(run);
            }
        }

        /// Frees the emptied run of a spilled key, and the partition's tree if that was its
        /// last key (the partition is back to empty arrays).
        fn destroy_spilled(self: *Self, slot: u32, run: *Item) void {
            assert(run.values.items.len == 0);
            const tree = self.tree_of(slot).?;
            run.values.deinit(self.gpa);
            var entry = tree.getEntryForExisting(&run.node);
            entry.set(null);
            self.pool.destroy(run);
            if (tree.root == null) assert(self.spilled.remove(slot));
        }

        /// Appends `value` to the run of `at`; returns whether it created the key.
        fn insert_located(self: *Self, at: Located, value: V) Allocator.Error!bool {
            const part = &self.partitions[at.slot];
            if (part.len() == 0) {
                if (self.tree_of(at.slot)) |tree| return self.insert_spilled(tree, at.key, value);
            }
            const span = part.run_range(at.key);
            try part.insert_at(self.gpa, span.end, at.key, value);
            return span.start == span.end;
        }

        fn insert_spilled(self: *Self, tree: *Tree, key: K, value: V) Allocator.Error!bool {
            if (find(tree, key)) |run| {
                try run.values.append(self.gpa, value);
                return false;
            }
            const created = try self.pool.create(self.gpa);
            created.values = .empty;
            created.values.append(self.gpa, value) catch |err| {
                self.pool.destroy(created);
                return err;
            };
            var entry = tree.getEntryFor(key);
            assert(entry.node == null);
            entry.set(&created.node);
            return true;
        }

        /// A cursor over the run of `at`, or null if the key has none.
        fn cursor_at(self: *Self, at: Located) ?Cursor {
            const part = &self.partitions[at.slot];
            if (part.len() > 0) {
                const span = part.run_range(at.key);
                if (span.start == span.end) return null;
                const run: Cursor.Array = .{
                    .key = at.key,
                    .start = span.start,
                    .len = span.end - span.start,
                };
                return .{ .index = self, .slot = at.slot, .backing = .{ .array = run } };
            }
            const tree = self.tree_of(at.slot) orelse return null;
            const run = find(tree, at.key) orelse return null;
            return .{ .index = self, .slot = at.slot, .backing = .{ .spilled = run } };
        }

        /// A cursor over the values of `key`, or null if it has none. Call `finish` when done.
        pub fn get_mut(self: *Self, key: []const u8) ?Cursor {
            const at = self.locate(key);
            if (self.partitions.len == 0) return null;
            self.maybe_spill(at.slot);
            return self.cursor_at(at);
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
            const at = self.locate(key);
            try self.ensure_partitions();
            self.maybe_spill(at.slot);
            const created = try self.insert_located(at, value);
            self.counters.keys += @intFromBool(created);
            self.counters.items += 1;
            self.maybe_spill(at.slot);
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
            self.maybe_spill(self.locate(key).slot);
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
            const at = self.locate(key);
            if (self.partitions.len == 0) return;
            self.maybe_spill(at.slot);
            const part = &self.partitions[at.slot];
            var count: usize = 0;
            if (part.len() > 0) {
                const span = part.run_range(at.key);
                count = span.end - span.start;
                if (count == 0) return;
                part.remove_span(span);
            } else {
                const tree = self.tree_of(at.slot) orelse return;
                const run = find(tree, at.key) orelse return;
                count = run.values.items.len;
                run.values.clearRetainingCapacity();
                self.destroy_spilled(at.slot, run);
            }
            assert(count > 0);
            self.counters.keys -= 1;
            self.counters.items -= count;
            self.counters.pruned += count;
        }

        /// Moves every run of `other`, a range within `self`'s partitions, into `self`, which
        /// holds none of `other`'s keys (the `install_range` half of commonware's
        /// `Partitioned`): partitions move slot by slot and spilled trees with their pools, so
        /// no run is copied. Reserves first, so an error changes nothing.
        pub fn absorb(self: *Self, other: *Self) Allocator.Error!void {
            assert(self != other);
            assert(self.gpa.ptr == other.gpa.ptr);
            assert(other.offset >= self.offset);
            assert(other.offset + other.count <= self.offset + self.count);
            const base = other.offset - self.offset;
            const trees = other.spilled.count();
            if (other.partitions.len > 0) try self.ensure_partitions();
            try self.spilled.ensureUnusedCapacity(self.gpa, trees);
            const pools = 1 + other.adopted.items.len;
            if (trees > 0) try self.adopted.ensureUnusedCapacity(self.gpa, pools);
            for (other.partitions, 0..) |*part, local| {
                if (part.len() == 0) continue;
                const target = &self.partitions[base + local];
                assert(target.len() == 0 and self.tree_of(@intCast(base + local)) == null);
                target.deinit(self.gpa);
                target.* = part.*;
                part.* = .{};
            }
            var moved = other.spilled.iterator();
            while (moved.next()) |entry| {
                const slot = base + entry.key_ptr.*;
                assert(self.partitions[slot].len() == 0);
                self.spilled.putAssumeCapacityNoClobber(slot, entry.value_ptr.*);
            }
            other.spilled.clearRetainingCapacity();
            if (trees > 0) {
                self.adopted.appendAssumeCapacity(other.pool);
                self.adopted.appendSliceAssumeCapacity(other.adopted.items);
                other.pool = .empty;
                other.adopted.clearRetainingCapacity();
            }
            self.counters.keys += other.counters.keys;
            self.counters.items += other.counters.items;
            self.counters.pruned += other.counters.pruned;
            self.spill_total += other.spill_total;
            const offset, const count = .{ other.offset, other.count };
            other.deinit();
            other.* = .init_range(self.gpa, self.translator, offset, count);
        }

        pub fn for_each_value(
            self: *const Self,
            visit_context: anytype,
            comptime visit: fn (@TypeOf(visit_context), *const V) void,
        ) void {
            for (self.partitions, 0..) |*part, slot| {
                for (part.vals.items) |*value| visit(visit_context, value);
                const tree = self.tree_of(@intCast(slot)) orelse continue;
                var current = tree.getMin();
                while (current) |node| : (current = node.next()) {
                    for (item(node).values.items) |*value| visit(visit_context, value);
                }
            }
        }

        fn values_of(run: *const Item) Values {
            return .{ .items = run.values.items };
        }

        /// The first (`last`: the last) run of slot `slot`, or null when it is empty.
        fn edge_in(self: *const Self, slot: u32, comptime last: bool) ?Values {
            const part = &self.partitions[slot];
            if (part.len() > 0) {
                return .{ .items = part.values(part.run_of(if (last) part.len() - 1 else 0)) };
            }
            const tree = self.tree_of(slot) orelse return null;
            const node = (if (last) tree.getMax() else tree.getMin()).?;
            return values_of(item(node));
        }

        /// The run of the smallest key above `key` in slot `slot` (`below`: the largest key
        /// below it).
        fn neighbor_in(self: *const Self, at: Located, comptime below: bool) ?Values {
            const part = &self.partitions[at.slot];
            if (part.len() > 0) {
                if (below) {
                    const lower = part.bound(at.key, false);
                    if (lower == 0) return null;
                    return .{ .items = part.values(part.run_of(lower - 1)) };
                }
                const upper = part.bound(at.key, true);
                if (upper == part.len()) return null;
                return .{ .items = part.values(part.run_of(upper)) };
            }
            const tree = self.tree_of(at.slot) orelse return null;
            var best: ?*Tree.Node = null;
            var current = tree.root;
            while (current) |node| {
                const relation = T.order(node.key, at.key);
                const wanted = if (below) relation == .lt else relation == .gt;
                if (wanted) best = node;
                current = node.children[@intFromBool(wanted == below)];
            }
            return values_of(item(best orelse return null));
        }

        pub const Neighbor = storage.NeighborOf(Values);

        /// The values of the largest translated key below `key`'s, or of the largest key if
        /// there is none (`cycled`). Null when the index is empty.
        pub fn prev_translated_key(self: *const Self, key: []const u8) ?Neighbor {
            if (self.counters.keys == 0) return null;
            const at = self.locate(key);
            if (self.neighbor_in(at, true)) |values| return .{ .values = values, .cycled = false };
            var slot = at.slot;
            while (slot > 0) {
                slot -= 1;
                const values = self.edge_in(slot, true) orelse continue;
                return .{ .values = values, .cycled = false };
            }
            return .{ .values = self.last_translated_key().?, .cycled = true };
        }

        /// The values of the smallest translated key above `key`'s, or of the smallest key if
        /// there is none (`cycled`). Null when the index is empty.
        pub fn next_translated_key(self: *const Self, key: []const u8) ?Neighbor {
            if (self.counters.keys == 0) return null;
            const at = self.locate(key);
            if (self.neighbor_in(at, false)) |values| return .{ .values = values, .cycled = false };
            var slot = at.slot + 1;
            while (slot < self.count) : (slot += 1) {
                const values = self.edge_in(slot, false) orelse continue;
                return .{ .values = values, .cycled = false };
            }
            return .{ .values = self.first_translated_key().?, .cycled = true };
        }

        pub fn first_translated_key(self: *const Self) ?Values {
            if (self.counters.keys == 0) return null;
            for (0..self.count) |slot| {
                if (self.edge_in(@intCast(slot), false)) |values| return values;
            }
            unreachable; // A key is held, so some partition holds a run.
        }

        pub fn last_translated_key(self: *const Self) ?Values {
            if (self.counters.keys == 0) return null;
            var slot = self.count;
            while (slot > 0) {
                slot -= 1;
                if (self.edge_in(slot, true)) |values| return values;
            }
            unreachable; // A key is held, so some partition holds a run.
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

        /// Partitions currently spilled (commonware's `spilled_count`).
        pub fn spilled_count(self: *const Self) usize {
            return self.spilled.count();
        }

        /// Spills so far (commonware's `spills` counter).
        pub fn spills(self: *const Self) u64 {
            return self.spill_total;
        }

        const State = union(enum) {
            /// `next` must be called; it returns the value at this offset.
            need_next: usize,
            active: usize,
            done,
        };

        /// Walks and edits one key's run by offset (commonware's partition `Cursor`), in the
        /// partition's arrays or its spilled tree. End it with `finish`, which frees the key's
        /// spilled run once it is empty; no other index method may run in between.
        pub const Cursor = struct {
            pub const Array = struct { key: K, start: usize, len: usize };

            index: *Self,
            slot: u32,
            backing: union(enum) { array: Array, spilled: *Item },
            state: State = .{ .need_next = 0 },

            fn len(self: *const Cursor) usize {
                return switch (self.backing) {
                    .array => |run| run.len,
                    .spilled => |run| run.values.items.len,
                };
            }

            fn value_at(self: *Cursor, offset: usize) *V {
                assert(offset < self.len());
                return switch (self.backing) {
                    .array => |run| {
                        const vals = self.index.partitions[self.slot].vals.items;
                        return &vals[run.start + offset];
                    },
                    .spilled => |run| &run.values.items[offset],
                };
            }

            fn insert_at(self: *Cursor, offset: usize, value: V) Allocator.Error!void {
                assert(offset <= self.len());
                const gpa = self.index.gpa;
                switch (self.backing) {
                    .array => |*run| {
                        const part = &self.index.partitions[self.slot];
                        try part.insert_at(gpa, run.start + offset, run.key, value);
                        run.len += 1;
                    },
                    .spilled => |run| try run.values.insert(gpa, offset, value),
                }
            }

            fn remove_at(self: *Cursor, offset: usize) void {
                assert(offset < self.len());
                switch (self.backing) {
                    .array => |*run| {
                        const at = run.start + offset;
                        const part = &self.index.partitions[self.slot];
                        part.remove_span(.{ .start = at, .end = at + 1 });
                        run.len -= 1;
                    },
                    .spilled => |run| _ = run.values.orderedRemove(offset),
                }
            }

            pub fn next(self: *Cursor) ?*V {
                const offset = switch (self.state) {
                    .done => return null,
                    .need_next => |from| from,
                    .active => |offset| offset + 1,
                };
                if (offset >= self.len()) {
                    self.state = .done;
                    return null;
                }
                self.state = .{ .active = offset };
                return self.value_at(offset);
            }

            fn active(self: *const Cursor) usize {
                return switch (self.state) {
                    .need_next => @panic("must call Cursor::next()"),
                    .done => @panic("no active item in Cursor"),
                    .active => |offset| offset,
                };
            }

            pub fn update(self: *Cursor, value: V) void {
                self.value_at(self.active()).* = value;
            }

            /// Inserts `value` after the current one (`next` skips it), or appends it once
            /// every value was visited.
            pub fn insert(self: *Cursor, value: V) Allocator.Error!void {
                switch (self.state) {
                    .need_next => @panic("must call Cursor::next()"),
                    .active => |offset| {
                        try self.insert_at(offset + 1, value);
                        self.state = .{ .need_next = offset + 2 };
                    },
                    .done => {
                        try self.insert_at(self.len(), value);
                        self.index.counters.keys += @intFromBool(self.len() == 1);
                    },
                }
                self.index.counters.items += 1;
            }

            /// Removes the current value; `next` then returns the one after it.
            pub fn delete(self: *Cursor) void {
                const offset = self.active();
                const counters = &self.index.counters;
                self.remove_at(offset);
                counters.keys -= @intFromBool(self.len() == 0);
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

            /// Frees the key's spilled run if it is empty (an emptied array run is already
            /// gone from the arrays).
            pub fn finish(self: *Cursor) void {
                switch (self.backing) {
                    .array => {},
                    .spilled => |run| if (run.values.items.len == 0) {
                        self.index.destroy_spilled(self.slot, run);
                    },
                }
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

fn expect_same(serial: *const TestIndex, joined: *const TestIndex) !void {
    try testing.expectEqual(serial.keys(), joined.keys());
    try testing.expectEqual(serial.items(), joined.items());
    try testing.expectEqual(serial.pruned(), joined.pruned());
    var expected: Seen = try .initCapacity(test_gpa, serial.items());
    defer expected.deinit(test_gpa);
    var actual: Seen = try .initCapacity(test_gpa, joined.items());
    defer actual.deinit(test_gpa);
    // In-order walks follow parent links, so a join that misses one reorders or drops runs.
    serial.for_each_value(&expected, collect);
    joined.for_each_value(&actual, collect);
    try testing.expectEqualSlices(u64, expected.items, actual.items);
    for (0..0x10000) |raw| {
        const key: [2]u8 = @bitCast(@as(u16, @intCast(raw)));
        var want = serial.get(&key);
        var got = joined.get(&key);
        try testing.expectEqual(want.count(), got.count());
        while (want.next()) |value| try testing.expectEqual(value.*, got.next().?.*);
        const want_next = serial.next_translated_key(&key);
        const got_next = joined.next_translated_key(&key);
        try testing.expectEqual(want_next == null, got_next == null);
        if (want_next) |found| {
            try testing.expectEqual(found.cycled, got_next.?.cycled);
            var a = found.values;
            var b = got_next.?.values;
            try testing.expectEqual(a.next().?.*, b.next().?.*);
        }
    }
}

fn random_key(random: std.Random, lo: u32, len: u32) [2]u8 {
    // A narrow second byte makes runs collide, so some hold several values.
    return .{ @intCast(lo + random.uintLessThan(u32, len)), random.uintLessThan(u8, 6) };
}

test "partitioned ordered installs in partition order match serial inserts" {
    for (0..24) |seed| {
        var prng: std.Random.DefaultPrng = .init(seed);
        const random = prng.random();
        var serial: TestIndex = .init(test_gpa, .init(.{}));
        defer serial.deinit();
        var joined: TestIndex = .init(test_gpa, .init(.{}));
        defer joined.deinit();
        // Up to five contiguous ranges; some get no keys, so empty joins happen too.
        var cuts = [_]u32{ 0, 0, 0, 0, 0, 256 };
        for (cuts[1..5]) |*cut| cut.* = 1 + random.uintLessThan(u32, 255);
        std.mem.sort(u32, &cuts, {}, std.sort.asc(u32));
        var value: u64 = 0;
        for (cuts[0..5], cuts[1..6]) |lo, hi| {
            if (lo == hi) continue;
            var range = new_test_range(&joined, lo, hi - lo);
            errdefer range.deinit();
            for (0..random.uintLessThan(usize, 300)) |_| {
                const key = random_key(random, lo, hi - lo);
                try serial.insert(&key, value);
                try range.index.insert(&key, value);
                value += 1;
            }
            try range.install(&joined);
        }
        try expect_same(&serial, &joined);
        // Prunes and inserts after the joins reuse adopted items through the free list.
        for (0..200) |_| {
            const key = random_key(random, 0, 256);
            if (random.boolean()) {
                serial.remove(&key);
                joined.remove(&key);
            } else {
                try serial.insert(&key, value);
                try joined.insert(&key, value);
                value += 1;
            }
        }
        try expect_same(&serial, &joined);
    }
}

test "partitioned ordered install below existing keys reinserts" {
    var serial: TestIndex = .init(test_gpa, .init(.{}));
    defer serial.deinit();
    var joined: TestIndex = .init(test_gpa, .init(.{}));
    defer joined.deinit();
    // The high range installs first, so the low one interleaves and cannot join.
    const spans = [_][2]u32{ .{ 0x80, 0x80 }, .{ 0, 0x80 } };
    var value: u64 = 0;
    for (spans) |span| {
        var range = new_test_range(&joined, span[0], span[1]);
        errdefer range.deinit();
        for (0..40) |i| {
            const key: [2]u8 = .{ @intCast(span[0] + i * 3 % span[1]), @intCast(i % 4) };
            try serial.insert(&key, value);
            try range.index.insert(&key, value);
            value += 1;
        }
        try range.install(&joined);
    }
    try expect_same(&serial, &joined);
}

/// Commonware's `new_index_spilling`: a partition spills at two entries.
const SpillIndex = IndexSpillAt(translators.OneCap, u64, 1, 2);

fn expect_run(index: *const SpillIndex, key: []const u8, expected: []const u64) !void {
    var values = index.get(key);
    try testing.expectEqual(expected.len, values.count());
    for (expected) |value| try testing.expectEqual(value, values.next().?.*);
}

test "partitioned ordered spill transition" {
    var index: SpillIndex = .init(test_gpa, .init(.{}));
    defer index.deinit();
    try index.insert(&.{ 0x10, 0x01 }, 1);
    try testing.expectEqual(@as(usize, 0), index.spilled_count());
    try index.insert(&.{ 0x10, 0x02 }, 2); // The second entry reaches the threshold.
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    try index.insert(&.{ 0x10, 0x03 }, 3); // Routed into the spilled tree.
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    try testing.expectEqual(@as(u64, 3), index.keys());
    try expect_run(&index, &.{ 0x10, 0x01 }, &.{1});
    try index.insert(&.{ 0x10, 0x02 }, 22);
    try expect_run(&index, &.{ 0x10, 0x02 }, &.{ 2, 22 });
    try testing.expectEqual(@as(u64, 4), index.items());
    try index.insert(&.{ 0x20, 0x05 }, 5);
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    try expect_run(&index, &.{ 0x20, 0x05 }, &.{5});
}

fn expect_neighbor(found: ?SpillIndex.Neighbor, value: u64, cycled: bool) !void {
    var neighbor = found.?;
    try testing.expectEqual(cycled, neighbor.cycled);
    try testing.expectEqual(value, neighbor.values.next().?.*);
}

test "partitioned ordered spill navigation" {
    var index: SpillIndex = .init(test_gpa, .init(.{}));
    defer index.deinit();
    // 0x10 and 0x30 spill; 0x20 stays in its arrays.
    const entries = [_][3]u8{
        .{ 0x10, 0x01, 1 }, .{ 0x10, 0x02, 2 }, .{ 0x20, 0x05, 5 },
        .{ 0x30, 0x07, 7 }, .{ 0x30, 0x08, 8 },
    };
    for (entries) |entry| {
        try index.insert(entry[0..2], entry[2]);
    }
    try testing.expectEqual(@as(usize, 2), index.spilled_count());
    var first = index.first_translated_key().?;
    try testing.expectEqual(@as(u64, 1), first.next().?.*);
    var last = index.last_translated_key().?;
    try testing.expectEqual(@as(u64, 8), last.next().?.*);
    try expect_neighbor(index.next_translated_key(&.{ 0x10, 0x01 }), 2, false);
    try expect_neighbor(index.next_translated_key(&.{ 0x10, 0x02 }), 5, false);
    try expect_neighbor(index.next_translated_key(&.{ 0x20, 0x05 }), 7, false);
    try expect_neighbor(index.prev_translated_key(&.{ 0x30, 0x07 }), 5, false);
    try expect_neighbor(index.prev_translated_key(&.{ 0x20, 0x05 }), 2, false);
    try expect_neighbor(index.next_translated_key(&.{ 0x30, 0x08 }), 1, true);
}

test "partitioned ordered spill reverts on a full drain" {
    var index: SpillIndex = .init(test_gpa, .init(.{}));
    defer index.deinit();
    try index.insert(&.{ 0x10, 0x01 }, 1);
    try index.insert(&.{ 0x10, 0x02 }, 2);
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    index.remove(&.{ 0x10, 0x01 });
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    index.remove(&.{ 0x10, 0x02 });
    try testing.expectEqual(@as(usize, 0), index.spilled_count());
    try testing.expectEqual(@as(u64, 0), index.keys());
    try index.insert(&.{ 0x10, 0x09 }, 9);
    try testing.expectEqual(@as(usize, 0), index.spilled_count());
    try expect_run(&index, &.{ 0x10, 0x09 }, &.{9});
}

fn delete_only(index: *SpillIndex, key: []const u8, value: u64) !void {
    var cursor = index.get_mut(key).?;
    defer cursor.finish();
    try testing.expectEqual(value, cursor.next().?.*);
    cursor.delete();
}

test "partitioned ordered spill full lifecycle through a cursor" {
    var index: SpillIndex = .init(test_gpa, .init(.{}));
    defer index.deinit();
    try index.insert(&.{ 0x10, 0x01 }, 1);
    try index.insert(&.{ 0x10, 0x02 }, 2);
    try testing.expectEqual(@as(u64, 1), index.spills());
    try delete_only(&index, &.{ 0x10, 0x01 }, 1);
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    try delete_only(&index, &.{ 0x10, 0x02 }, 2);
    try testing.expectEqual(@as(usize, 0), index.spilled_count());
    try testing.expectEqual(@as(u64, 1), index.spills()); // Cumulative.
    try testing.expectEqual(@as(u64, 0), index.items());
    try testing.expectEqual(@as(u64, 2), index.pruned());
    try index.insert(&.{ 0x10, 0x03 }, 3);
    try index.insert(&.{ 0x10, 0x04 }, 4);
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    try testing.expectEqual(@as(u64, 2), index.spills());
    try expect_run(&index, &.{ 0x10, 0x03 }, &.{3});
}

test "partitioned ordered spill after cursor growth" {
    var index: SpillIndex = .init(test_gpa, .init(.{}));
    defer index.deinit();
    const key = [_]u8{ 0x10, 0x01 };
    try index.insert(&key, 1);
    {
        var cursor = index.get_mut(&key).?;
        defer cursor.finish();
        try testing.expectEqual(@as(u64, 1), cursor.next().?.*);
        try testing.expect(cursor.next() == null);
        try cursor.insert(2);
    }
    try testing.expectEqual(@as(usize, 0), index.spilled_count());
    // The next mutation spills the over-full partition first.
    try index.insert(&key, 3);
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    try expect_run(&index, &key, &.{ 1, 2, 3 });
    // `get_mut` spills before handing out a cursor, which then serves the spilled tree.
    const other = [_]u8{ 0x30, 0x01 };
    try index.insert(&other, 6);
    {
        var cursor = index.get_mut(&other).?;
        defer cursor.finish();
        _ = cursor.next();
        try testing.expect(cursor.next() == null);
        try cursor.insert(7);
    }
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    var cursor = index.get_mut(&other).?;
    cursor.finish();
    try testing.expectEqual(@as(usize, 2), index.spilled_count());
    try expect_run(&index, &other, &.{ 6, 7 });
}

test "partitioned ordered spill get_mut_or_insert" {
    var index: SpillIndex = .init(test_gpa, .init(.{}));
    defer index.deinit();
    try index.insert(&.{ 0x10, 0x01 }, 1);
    try index.insert(&.{ 0x10, 0x02 }, 2);
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    {
        // An existing key in a spilled partition: a cursor, and the value is not inserted.
        var cursor = (try index.get_mut_or_insert(&.{ 0x10, 0x01 }, 99)).?;
        defer cursor.finish();
        try testing.expectEqual(@as(u64, 1), cursor.next().?.*);
        try testing.expect(cursor.next() == null);
    }
    try testing.expectEqual(@as(u64, 2), index.items());
    try expect_run(&index, &.{ 0x10, 0x01 }, &.{1});
    // An absent key in a spilled partition is inserted, and the partition stays spilled.
    try testing.expect(try index.get_mut_or_insert(&.{ 0x10, 0x03 }, 3) == null);
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    try testing.expectEqual(@as(u64, 3), index.keys());
    try testing.expectEqual(@as(u64, 3), index.items());
    try expect_run(&index, &.{ 0x10, 0x03 }, &.{3});
}

test "partitioned ordered spill after get_mut_or_insert cursor growth" {
    var index: SpillIndex = .init(test_gpa, .init(.{}));
    defer index.deinit();
    const key = [_]u8{ 0x10, 0x01 };
    try index.insert(&key, 1);
    {
        var cursor = (try index.get_mut_or_insert(&key, 2)).?;
        defer cursor.finish();
        try testing.expectEqual(@as(u64, 1), cursor.next().?.*);
        try testing.expect(cursor.next() == null);
        try cursor.insert(2);
    }
    try testing.expectEqual(@as(usize, 0), index.spilled_count());
    // The next replay-style update spills before returning another collision cursor.
    var cursor = (try index.get_mut_or_insert(&key, 3)).?;
    cursor.finish();
    try testing.expectEqual(@as(usize, 1), index.spilled_count());
    try expect_run(&index, &key, &.{ 1, 2 });
}

fn order_u16(a: u16, b: u16) std.math.Order {
    return std.math.order(a, b);
}

const TestPartition = Partition(u16, u64, order_u16);

fn partition_insert(part: *TestPartition, key: u16, value: u64) !void {
    try part.insert_at(test_gpa, part.run_range(key).end, key, value);
}

fn expect_partition_values(part: *const TestPartition, key: u16, expected: []const u64) !void {
    try testing.expectEqualSlices(u64, expected, part.values(part.run_range(key)));
}

test "partitioned ordered partition empty and sorted insert" {
    var part: TestPartition = .{};
    defer part.deinit(test_gpa);
    try expect_partition_values(&part, 5, &.{});
    try testing.expectEqual(TestPartition.Span{ .start = 0, .end = 0 }, part.run_range(5));
    // Inserted out of order, the arrays stay sorted by key.
    for ([_][2]u16{ .{ 30, 300 }, .{ 10, 100 }, .{ 20, 200 } }) |entry| {
        try partition_insert(&part, entry[0], entry[1]);
    }
    try testing.expectEqualSlices(u16, &.{ 10, 20, 30 }, part.keys.items);
    try testing.expectEqualSlices(u64, &.{ 100, 200, 300 }, part.vals.items);
    try expect_partition_values(&part, 20, &.{200});
    try expect_partition_values(&part, 25, &.{});
}

test "partitioned ordered partition collision runs append in order" {
    var part: TestPartition = .{};
    defer part.deinit(test_gpa);
    for ([_][2]u16{ .{ 10, 1 }, .{ 20, 2 }, .{ 10, 11 }, .{ 10, 111 } }) |entry| {
        try partition_insert(&part, entry[0], entry[1]);
    }
    try expect_partition_values(&part, 10, &.{ 1, 11, 111 });
    try expect_partition_values(&part, 20, &.{2});
    try testing.expectEqualSlices(u16, &.{ 10, 10, 10, 20 }, part.keys.items);
    try testing.expectEqual(TestPartition.Span{ .start = 0, .end = 3 }, part.run_range(10));
    try testing.expectEqual(TestPartition.Span{ .start = 3, .end = 4 }, part.run_range(20));
    try testing.expectEqual(TestPartition.Span{ .start = 0, .end = 3 }, part.run_of(1));
}

test "partitioned ordered partition remove keeps alignment" {
    var part: TestPartition = .{};
    defer part.deinit(test_gpa);
    for ([_][2]u16{ .{ 10, 1 }, .{ 10, 11 }, .{ 20, 2 } }) |entry| {
        try partition_insert(&part, entry[0], entry[1]);
    }
    part.remove_span(.{ .start = 1, .end = 2 }); // The newer value of key 10.
    try testing.expectEqualSlices(u16, &.{ 10, 20 }, part.keys.items);
    try testing.expectEqualSlices(u64, &.{ 1, 2 }, part.vals.items);
    try expect_partition_values(&part, 10, &.{1});
}
