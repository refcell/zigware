//! The storage shared by every index: one head value per translated key, displaced values in
//! an overflow chain, and the cursor that walks and edits a key's values.
//!
//! Port of commonware's `storage/src/index/storage.rs` plus the operations its `unordered` and
//! `ordered` indices share. The values of a key, in the order `get` and the cursor visit them,
//! are the head followed by the overflow chain from its end to its start: `insert` makes the new
//! value the head and pushes the old head onto the chain, so the newest value comes first. A key
//! with one value needs no chain allocation.
//!
//! Heads live in a `Heads` type (a hash map or a treap) with
//! `get(*const Heads, Key) ?*V`, `get_or_put(*Heads, Allocator, Key) !GetOrPut(V)`,
//! `remove(*Heads, Allocator, Key) void`, and `deinit(*Heads, Allocator) void`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const translator_module = @import("../translator.zig");

/// The hash map context of a translator: its bucket hash and key equality.
pub fn Context(comptime T: type) type {
    translator_module.check(T);
    return struct {
        translator: T,

        pub fn hash(self: @This(), key: T.Key) u64 {
            return self.translator.hash(key);
        }

        pub fn eql(_: @This(), a: T.Key, b: T.Key) bool {
            return T.eql(a, b);
        }
    };
}

/// A key's displaced values, oldest displaced first.
pub fn Overflow(comptime T: type, comptime V: type) type {
    return std.HashMapUnmanaged(T.Key, std.ArrayList(V), Context(T), 80);
}

pub fn GetOrPut(comptime V: type) type {
    return struct { value_ptr: *V, found_existing: bool };
}

/// Commonware's `keys`, `items`, and `pruned` metrics.
pub const Counters = struct {
    /// Translated keys in the index.
    keys: u64 = 0,
    /// Values in the index.
    items: u64 = 0,
    /// Values removed from the index.
    pruned: u64 = 0,
};

/// The values of one key, head first (commonware's `Values`).
pub fn Values(comptime V: type) type {
    return struct {
        head: ?*const V = null,
        chain: []const V = &.{},

        pub fn next(self: *@This()) ?*const V {
            if (self.head) |head| {
                self.head = null;
                return head;
            }
            if (self.chain.len == 0) return null;
            const value = &self.chain[self.chain.len - 1];
            self.chain = self.chain[0 .. self.chain.len - 1];
            return value;
        }

        /// The number of values left.
        pub fn count(self: *const @This()) usize {
            return @intFromBool(self.head != null) + self.chain.len;
        }
    };
}

/// Where a cursor is in a key's values: the head or an index into the chain.
const Position = union(enum) { head, overflow: usize };

const State = union(enum) {
    /// `next` must be called before the current item can be read or edited.
    need_next: ?Position,
    active: Position,
    /// Every value was visited; `insert` appends.
    done,
    /// The last value was deleted; the key is removed when the cursor finishes.
    entry_removed,
};

/// An index over translator `T` with values `V`, its heads stored in `Heads`.
pub fn Index(comptime T: type, comptime V: type, comptime Heads: type) type {
    translator_module.check(T);
    return struct {
        const Self = @This();
        const Chain = std.ArrayList(V);

        pub const Key = T.Key;
        pub const Value = V;

        gpa: Allocator,
        translator: T,
        heads: Heads,
        overflow: Overflow(T, V) = .empty,
        counters: Counters = .{},

        pub const lookup_warms_update: bool = Heads.lookup_warms_update;

        pub fn init(gpa: Allocator, translator: T) Self {
            return .{ .gpa = gpa, .translator = translator, .heads = .init(translator) };
        }

        pub fn deinit(self: *Self) void {
            var chains = self.overflow.valueIterator();
            while (chains.next()) |chain| chain.deinit(self.gpa);
            self.overflow.deinit(self.gpa);
            self.heads.deinit(self.gpa);
            self.* = undefined;
        }

        pub fn context(self: *const Self) Context(T) {
            return .{ .translator = self.translator };
        }

        /// The values of the translated key `key`, given its head.
        pub fn values_of(self: *const Self, key: Key, head: ?*const V) Values(V) {
            const head_value = head orelse return .{};
            const chain = self.overflow.getContext(key, self.context()) orelse Chain.empty;
            return .{ .head = head_value, .chain = chain.items };
        }

        /// The values whose keys translate like `key`, newest first.
        pub fn get(self: *const Self, key: []const u8) Values(V) {
            return self.get_translated(self.translator.transform(key));
        }

        pub fn get_translated(self: *const Self, key: Key) Values(V) {
            return self.values_of(key, self.heads.get(key));
        }

        /// A cursor over the values of `key`, or null if it has none. Call `finish` when done.
        pub fn get_mut(self: *Self, key: []const u8) ?Cursor {
            const translated = self.translator.transform(key);
            const head = self.heads.get(translated) orelse return null;
            return Cursor.init(self, translated, head);
        }

        /// A cursor over the values of `key`, or, if it has none, inserts `value` and returns
        /// null.
        pub fn get_mut_or_insert(self: *Self, key: []const u8, value: V) Allocator.Error!?Cursor {
            const translated = self.translator.transform(key);
            const entry = try self.heads.get_or_put(self.gpa, translated);
            if (entry.found_existing) return Cursor.init(self, translated, entry.value_ptr);
            entry.value_ptr.* = value;
            self.counters.keys += 1;
            self.counters.items += 1;
            return null;
        }

        /// Adds `value` under `key`, as its first value.
        pub fn insert(self: *Self, key: []const u8, value: V) Allocator.Error!void {
            const translated = self.translator.transform(key);
            const entry = try self.heads.get_or_put(self.gpa, translated);
            if (!entry.found_existing) {
                entry.value_ptr.* = value;
                self.counters.keys += 1;
                self.counters.items += 1;
                return;
            }
            const ctx = self.context();
            const chain = try self.overflow.getOrPutContext(self.gpa, translated, ctx);
            if (!chain.found_existing) chain.value_ptr.* = .empty;
            chain.value_ptr.append(self.gpa, entry.value_ptr.*) catch |err| {
                // Keep the overflow map free of empty chains.
                if (!chain.found_existing) assert(self.overflow.removeContext(translated, ctx));
                return err;
            };
            entry.value_ptr.* = value;
            self.counters.items += 1;
        }

        /// Removes the values of `key` that `should_retain` rejects, then adds `value` (if it
        /// is retained) after the survivors.
        pub fn insert_and_retain(
            self: *Self,
            key: []const u8,
            value: V,
            retain_context: anytype,
            comptime should_retain: fn (@TypeOf(retain_context), *const V) bool,
        ) Allocator.Error!void {
            const translated = self.translator.transform(key);
            const ctx = self.context();
            const head = self.heads.get(translated) orelse {
                if (!should_retain(retain_context, &value)) return;
                const cursor = try self.get_mut_or_insert(key, value);
                assert(cursor == null);
                return;
            };
            if (!self.overflow.containsContext(translated, ctx)) {
                const single = Self.insert_and_retain_single;
                return single(self, translated, head, value, retain_context, should_retain);
            }
            var cursor = Cursor.init(self, translated, head);
            defer cursor.finish();
            cursor.retain(retain_context, should_retain);
            if (should_retain(retain_context, &value)) try cursor.insert(value);
        }

        fn insert_and_retain_single(
            self: *Self,
            translated: Key,
            head: *V,
            value: V,
            retain_context: anytype,
            comptime should_retain: fn (@TypeOf(retain_context), *const V) bool,
        ) Allocator.Error!void {
            const keep_old = should_retain(retain_context, head);
            const keep_new = should_retain(retain_context, &value);
            if (keep_old and keep_new) {
                var chain: Chain = .empty;
                try chain.append(self.gpa, value);
                errdefer chain.deinit(self.gpa);
                try self.overflow.putNoClobberContext(self.gpa, translated, chain, self.context());
                self.counters.items += 1;
            } else if (keep_new) {
                head.* = value;
                self.counters.pruned += 1;
            } else if (!keep_old) {
                self.heads.remove(self.gpa, translated);
                self.counters.keys -= 1;
                self.counters.items -= 1;
                self.counters.pruned += 1;
            }
        }

        /// Removes the values of `key` that `should_retain` rejects.
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
            const translated = self.translator.transform(key);
            if (self.heads.get(translated) == null) return;
            self.heads.remove(self.gpa, translated);
            self.counters.keys -= 1;
            self.counters.items -= 1;
            self.counters.pruned += 1;
            if (self.overflow.fetchRemoveContext(translated, self.context())) |removed| {
                var chain = removed.value;
                self.counters.items -= chain.items.len;
                self.counters.pruned += chain.items.len;
                chain.deinit(self.gpa);
            }
        }

        /// Calls `visit(visit_context, i, value)` for every value of every key `lookups[i]`.
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

        /// Calls `visit(visit_context, value)` for every value in the index.
        pub fn for_each_value(
            self: *const Self,
            visit_context: anytype,
            comptime visit: fn (@TypeOf(visit_context), *const V) void,
        ) void {
            self.heads.for_each_value(visit_context, visit);
            var chains = self.overflow.valueIterator();
            while (chains.next()) |chain| {
                for (chain.items) |*value| visit(visit_context, value);
            }
        }

        /// The values of a translated key and whether finding it wrapped around the ends.
        pub const Neighbor = struct { values: Values(V), cycled: bool };

        /// The values of the largest translated key below `key`'s, or of the largest key if
        /// there is none (`cycled`). Null when the index is empty. Ordered indices only.
        pub fn prev_translated_key(self: *const Self, key: []const u8) ?Neighbor {
            comptime assert(T.ordered);
            const translated = self.translator.transform(key);
            if (self.heads.before(translated)) |entry| {
                return .{ .values = self.values_of(entry.key, entry.value), .cycled = false };
            }
            const values = self.last_translated_key() orelse return null;
            return .{ .values = values, .cycled = true };
        }

        /// The values of the smallest translated key above `key`'s, or of the smallest key if
        /// there is none (`cycled`). Null when the index is empty. Ordered indices only.
        pub fn next_translated_key(self: *const Self, key: []const u8) ?Neighbor {
            comptime assert(T.ordered);
            const translated = self.translator.transform(key);
            if (self.heads.after(translated)) |entry| {
                return .{ .values = self.values_of(entry.key, entry.value), .cycled = false };
            }
            const values = self.first_translated_key() orelse return null;
            return .{ .values = values, .cycled = true };
        }

        pub fn first_translated_key(self: *const Self) ?Values(V) {
            const entry = self.heads.first() orelse return null;
            return self.values_of(entry.key, entry.value);
        }

        pub fn last_translated_key(self: *const Self) ?Values(V) {
            const entry = self.heads.last() orelse return null;
            return self.values_of(entry.key, entry.value);
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

        /// Walks and edits the values of one key (commonware's `Cursor`). End it with `finish`,
        /// which removes the key if its last value was deleted; no other index method may run
        /// in between. The chain is edited in place in the overflow map, which never holds an
        /// empty chain.
        pub const Cursor = struct {
            index: *Self,
            key: Key,
            head: *V,
            state: State = .{ .need_next = null },

            fn init(index: *Self, key: Key, head: *V) Cursor {
                return .{ .index = index, .key = key, .head = head };
            }

            fn chain(self: *const Cursor) ?*Chain {
                return self.index.overflow.getPtrContext(self.key, self.index.context());
            }

            /// The key's chain, created empty if it has none; `drop_if_empty` undoes that.
            fn chain_or_create(self: *Cursor) Allocator.Error!*Chain {
                const index = self.index;
                const ctx = index.context();
                const entry = try index.overflow.getOrPutContext(index.gpa, self.key, ctx);
                if (!entry.found_existing) entry.value_ptr.* = .empty;
                return entry.value_ptr;
            }

            fn drop_if_empty(self: *Cursor, chain_ptr: *Chain) void {
                if (chain_ptr.items.len > 0) return;
                chain_ptr.deinit(self.index.gpa);
                assert(self.index.overflow.removeContext(self.key, self.index.context()));
            }

            /// The next value, or null once every value was visited.
            pub fn next(self: *Cursor) ?*V {
                const from: ?Position = switch (self.state) {
                    .done, .entry_removed => return null,
                    .need_next => |from| from,
                    .active => |position| position,
                };
                const position: Position = if (from) |previous| switch (previous) {
                    .head => head: {
                        const chain_ptr = self.chain() orelse return self.mark_done();
                        assert(chain_ptr.items.len > 0);
                        break :head .{ .overflow = chain_ptr.items.len - 1 };
                    },
                    .overflow => |i| overflow: {
                        if (i == 0) return self.mark_done();
                        break :overflow .{ .overflow = i - 1 };
                    },
                } else .head;
                self.state = .{ .active = position };
                return switch (position) {
                    .head => self.head,
                    .overflow => |i| &self.chain().?.items[i],
                };
            }

            fn mark_done(self: *Cursor) ?*V {
                self.state = .done;
                return null;
            }

            fn active(self: *const Cursor) Position {
                return switch (self.state) {
                    .need_next => @panic("must call Cursor::next()"),
                    .done, .entry_removed => @panic("no active item in Cursor"),
                    .active => |position| position,
                };
            }

            /// Replaces the current value.
            pub fn update(self: *Cursor, value: V) void {
                switch (self.active()) {
                    .head => self.head.* = value,
                    .overflow => |i| self.chain().?.items[i] = value,
                }
            }

            /// Inserts `value` after the current one (`next` skips it), or appends it once
            /// every value was visited.
            pub fn insert(self: *Cursor, value: V) Allocator.Error!void {
                switch (self.state) {
                    .need_next => @panic("must call Cursor::next()"),
                    .active => |position| {
                        const chain_ptr = try self.chain_or_create();
                        const at = switch (position) {
                            .head => chain_ptr.items.len,
                            .overflow => |i| i,
                        };
                        chain_ptr.insert(self.index.gpa, at, value) catch |err| {
                            self.drop_if_empty(chain_ptr);
                            return err;
                        };
                        self.state = .{ .need_next = .{ .overflow = at } };
                    },
                    .entry_removed => {
                        self.head.* = value;
                        self.state = .done;
                    },
                    .done => {
                        const chain_ptr = try self.chain_or_create();
                        chain_ptr.insert(self.index.gpa, 0, value) catch |err| {
                            self.drop_if_empty(chain_ptr);
                            return err;
                        };
                    },
                }
                self.index.counters.items += 1;
            }

            /// Removes the current value; `next` then returns the one after it.
            pub fn delete(self: *Cursor) void {
                const position = self.active();
                assert(self.index.counters.items > 0);
                self.index.counters.pruned += 1;
                self.index.counters.items -= 1;
                switch (position) {
                    .head => {
                        const chain_ptr = self.chain() orelse {
                            self.state = .entry_removed;
                            return;
                        };
                        // Promote the next value to the head.
                        self.head.* = chain_ptr.pop().?;
                        self.drop_if_empty(chain_ptr);
                        self.state = .{ .need_next = null };
                    },
                    .overflow => |i| {
                        const chain_ptr = self.chain().?;
                        _ = chain_ptr.orderedRemove(i);
                        self.drop_if_empty(chain_ptr);
                        self.state = .{ .need_next = .{ .overflow = i } };
                    },
                }
            }

            /// Removes the values `should_retain` rejects among those not yet visited.
            pub fn retain(
                self: *Cursor,
                retain_context: anytype,
                comptime should_retain: fn (@TypeOf(retain_context), *const V) bool,
            ) void {
                while (self.next()) |value| {
                    if (!should_retain(retain_context, value)) self.delete();
                }
            }

            /// Advances to the first value `predicate` accepts; false if there is none.
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

            /// Removes the key if its last value was deleted.
            pub fn finish(self: *Cursor) void {
                const index = self.index;
                if (self.state == .entry_removed) {
                    assert(self.chain() == null);
                    index.heads.remove(index.gpa, self.key);
                    assert(index.counters.keys > 0);
                    index.counters.keys -= 1;
                }
                self.* = undefined;
            }
        };
    };
}
