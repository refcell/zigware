//! Ordered collections that guarantee sorted, deduplicated items (commonware
//! `utils/src/ordered.rs`): `Set(T)`, `Map(K, V)`, and `BiMap(K, V)`, plus the `Quorum`
//! helpers on `Set` (`quorum`, `max_faults`, `key`, `index`).
//!
//! Items are ordered the way commonware's `Ord` orders them: a type's own `order(a, b)`
//! declaration, else `codec.order`. A collection owns its slices and the items in them. As in
//! Rust, constructors take ownership of the items passed in, releasing them on error, and
//! `deinit` releases them (`deinit` of items that declare it, `codec.free` otherwise).
//!
//! Encodings match commonware: a `Set` is a `Vec<T>` (u32 varint length, then the items) and
//! decoding rejects unsorted or duplicate items; a `Map` is its keys as a `Set` followed by its
//! values as a `Vec<V>` of the same length; a `BiMap` encodes as a `Map` and decoding rejects
//! duplicate values.

const std = @import("std");
const codec = @import("codec");
const Participant = @import("root.zig").Participant;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Error = error{
    /// A key was duplicated.
    DuplicateKey,
    /// A value was duplicated.
    DuplicateValue,
};

/// The order commonware's `Ord` gives `T`.
pub fn order(comptime T: type, a: T, b: T) std.math.Order {
    if (comptime has_decl(T, "order")) return T.order(a, b);
    return codec.order(T, a, b);
}

/// `order` under a name the containers below do not shadow.
const compare = order;

fn less_than(comptime T: type) fn (void, T, T) bool {
    return struct {
        fn less(_: void, a: T, b: T) bool {
            return compare(T, a, b) == .lt;
        }
    }.less;
}

fn has_decl(comptime T: type, comptime name: []const u8) bool {
    return switch (@typeInfo(T)) {
        .@"struct" => |info| !info.is_tuple and @hasDecl(T, name),
        .@"union", .@"enum", .@"opaque" => @hasDecl(T, name),
        else => false,
    };
}

/// Whether items of `T` own memory that the collection must release.
fn owns_memory(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct" => |info| if (info.is_tuple) codec.owns_memory(T) else @hasDecl(T, "deinit"),
        .@"union", .@"enum", .@"opaque" => @hasDecl(T, "deinit"),
        else => codec.owns_memory(T),
    };
}

fn free_items(comptime T: type, gpa: Allocator, items: []const T) void {
    if (comptime !owns_memory(T)) return;
    for (items) |item| {
        var copy = item;
        if (comptime has_decl(T, "deinit")) copy.deinit(gpa) else codec.free(T, gpa, copy);
    }
}

/// Shrinks `items` (allocated by `gpa`) to `new_len` without releasing the dropped items.
fn shrink(comptime T: type, gpa: Allocator, items: []T, new_len: usize) Allocator.Error![]T {
    assert(new_len <= items.len);
    if (gpa.resize(items, new_len)) return items[0..new_len];
    return gpa.realloc(items, new_len);
}

/// Releases `items` and the slice holding them.
fn free_slice(comptime T: type, gpa: Allocator, items: []const T) void {
    free_items(T, gpa, items);
    gpa.free(items);
}

/// Writes `item` with `{f}` when it formats itself and `{any}` otherwise.
fn format_item(comptime T: type, item: T, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    if (comptime has_decl(T, "format")) return writer.print("{f}", .{item});
    switch (@typeInfo(T)) {
        .int, .comptime_int => return writer.print("{d}", .{item}),
        else => return writer.print("{any}", .{item}),
    }
}

pub fn Set(comptime T: type) type {
    return struct {
        items: []T = &.{},

        const Self = @This();

        /// Commonware's `(RangeCfg<usize>, T::Cfg)`.
        pub const Cfg = codec.SliceCfg(codec.Cfg(T));
        pub const Item = T;
        pub const empty: Self = .{};

        /// Sorts and deduplicates `items` into a new set, releasing discarded duplicates
        /// (Rust `from_iter_dedup`).
        pub fn from_dedup(gpa: Allocator, items: []const T) Allocator.Error!Self {
            const copy = gpa.dupe(T, items) catch |err| {
                free_items(T, gpa, items);
                return err;
            };
            return from_owned_dedup(gpa, copy);
        }

        /// `from_dedup` over a slice allocated by `gpa`, whose allocation the set reuses.
        pub fn from_owned_dedup(gpa: Allocator, items: []T) Allocator.Error!Self {
            std.mem.sort(T, items, {}, less_than(T));
            var kept: usize = @min(items.len, 1);
            for (1..@max(items.len, 1)) |cursor| {
                if (compare(T, items[kept - 1], items[cursor]) == .eq) {
                    free_items(T, gpa, items[cursor..][0..1]);
                } else {
                    items[kept] = items[cursor];
                    kept += 1;
                }
            }
            // The tail holds moved or released items: shrink without releasing them again.
            const kept_items = shrink(T, gpa, items, kept) catch |err| {
                free_items(T, gpa, items[0..kept]);
                gpa.free(items);
                return err;
            };
            const result: Self = .{ .items = kept_items };
            result.assert_sorted();
            return result;
        }

        /// Sorts `items` into a new set; fails with `DuplicateKey` on a duplicate (Rust
        /// `try_from`).
        pub fn init(gpa: Allocator, items: []const T) (Allocator.Error || Error)!Self {
            const copy = gpa.dupe(T, items) catch |err| {
                free_items(T, gpa, items);
                return err;
            };
            errdefer free_slice(T, gpa, copy);
            std.mem.sort(T, copy, {}, less_than(T));
            for (1..@max(copy.len, 1)) |cursor| {
                if (compare(T, copy[cursor - 1], copy[cursor]) == .eq) return error.DuplicateKey;
            }
            const result: Self = .{ .items = copy };
            result.assert_sorted();
            return result;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            free_slice(T, gpa, self.items);
            self.* = undefined;
        }

        /// A copy sharing nothing with `self` (items must not own memory).
        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            comptime assert(!owns_memory(T));
            return .{ .items = try gpa.dupe(T, self.items) };
        }

        pub fn len(self: Self) usize {
            return self.items.len;
        }

        pub fn is_empty(self: Self) bool {
            return self.items.len == 0;
        }

        pub fn get(self: *const Self, offset: usize) ?*const T {
            return if (offset < self.items.len) &self.items[offset] else null;
        }

        /// The index of `item`, by binary search.
        pub fn position(self: Self, item: T) ?usize {
            var low: usize = 0;
            var high: usize = self.items.len;
            // Each pass halves `high - low`: at most 64 passes.
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (compare(T, self.items[middle], item)) {
                    .eq => return middle,
                    .lt => low = middle + 1,
                    .gt => high = middle,
                }
            }
            assert(low == high);
            return null;
        }

        pub fn as_slice(self: Self) []const T {
            return self.items;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.order(b) == .eq;
        }

        /// Lexicographic, as Rust derives `Ord` for the wrapped `Vec`.
        pub fn order(a: Self, b: Self) std.math.Order {
            const common = @min(a.items.len, b.items.len);
            for (a.items[0..common], b.items[0..common]) |left, right| {
                const item_order = compare(T, left, right);
                if (item_order != .eq) return item_order;
            }
            return std.math.order(a.items.len, b.items.len);
        }

        fn assert_sorted(self: Self) void {
            if (self.items.len < 2) return;
            const last = self.items.len - 1;
            assert(compare(T, self.items[0], self.items[1]) == .lt);
            assert(compare(T, self.items[last - 1], self.items[last]) == .lt);
        }

        /// `[a, b, c]` (Rust `Display`).
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.writeByte('[');
            for (self.items, 0..) |item, offset| {
                if (offset > 0) try writer.writeAll(", ");
                try format_item(T, item, writer);
            }
            try writer.writeByte(']');
        }

        // Quorum.

        /// The quorum of this participant set under the fault model `M` (such as `N3f1`).
        pub fn quorum(self: Self, comptime M: type) u32 {
            const count = std.math.cast(u32, self.items.len) orelse @panic("too many participants");
            return M.quorum(count);
        }

        pub fn max_faults(self: Self, comptime M: type) u32 {
            return M.max_faults(self.items.len);
        }

        pub fn key(self: *const Self, participant: Participant) ?*const T {
            return self.get(participant.get());
        }

        pub fn index(self: Self, item: T) ?Participant {
            const found = self.position(item) orelse return null;
            return Participant.from_usize(found);
        }

        // Codec.

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write([]const T, self.items, writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size([]const T, self.items);
        }

        /// Upper bound on the encoded size of a set of at most `count` items (Rust
        /// `Set::max_encode_size`).
        pub fn encode_size_max(count: usize) usize {
            return codec.util.max_items_size(count, codec.max_encode_size(T).?);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const count = try codec.read_usize(reader, cfg.range);
            const items = try codec.read_items(T, gpa, reader, count, cfg.item);
            errdefer free_slice(T, gpa, items);
            for (1..@max(items.len, 1)) |cursor| {
                if (compare(T, items[cursor - 1], items[cursor]) != .lt) {
                    return reader.invalid("Set", "items must be sorted and unique");
                }
            }
            return .{ .items = items };
        }

        /// commonware's `Arbitrary`: an arbitrary `Vec<T>`, sorted and deduplicated.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return from_owned_dedup(gpa, try codec.arbitrary.collect(T, gpa, u));
        }
    };
}

pub fn Map(comptime K: type, comptime V: type) type {
    return struct {
        keys: Set(K) = .empty,
        /// `values[i]` belongs to `keys.items[i]`.
        values: []V = &.{},

        const Self = @This();

        pub const Pair = struct { K, V };
        /// Commonware's `(RangeCfg<usize>, K::Cfg, V::Cfg)`.
        pub const Cfg = codec.MapCfg(codec.Cfg(K), codec.Cfg(V));
        pub const empty: Self = .{};

        /// Sorts `pairs` by key (stable) into a new map, keeping the first of each duplicate
        /// key and releasing the rest (Rust `from_iter_dedup`).
        pub fn from_dedup(gpa: Allocator, pairs: []const Pair) Allocator.Error!Self {
            const sorted = try sorted_pairs(gpa, pairs);
            defer gpa.free(sorted);
            var kept: usize = @min(sorted.len, 1);
            for (1..@max(sorted.len, 1)) |cursor| {
                if (compare(K, sorted[kept - 1][0], sorted[cursor][0]) == .eq) {
                    free_items(Pair, gpa, sorted[cursor..][0..1]);
                } else {
                    sorted[kept] = sorted[cursor];
                    kept += 1;
                }
            }
            errdefer free_items(Pair, gpa, sorted[0..kept]);
            return split(gpa, sorted[0..kept]);
        }

        /// Sorts `pairs` by key into a new map; fails with `DuplicateKey` on a duplicate key
        /// (Rust `try_from`).
        pub fn init(gpa: Allocator, pairs: []const Pair) (Allocator.Error || Error)!Self {
            const sorted = try sorted_pairs(gpa, pairs);
            defer gpa.free(sorted);
            errdefer free_items(Pair, gpa, sorted);
            for (1..@max(sorted.len, 1)) |cursor| {
                if (compare(K, sorted[cursor - 1][0], sorted[cursor][0]) == .eq) {
                    return error.DuplicateKey;
                }
            }
            return split(gpa, sorted);
        }

        /// A stable by-key sort of a copy of `pairs`; releases `pairs` if the copy fails.
        fn sorted_pairs(gpa: Allocator, pairs: []const Pair) Allocator.Error![]Pair {
            const sorted = gpa.dupe(Pair, pairs) catch |err| {
                free_items(Pair, gpa, pairs);
                return err;
            };
            std.mem.sort(Pair, sorted, {}, struct {
                fn less(_: void, a: Pair, b: Pair) bool {
                    return compare(K, a[0], b[0]) == .lt;
                }
            }.less);
            return sorted;
        }

        /// Splits sorted pairs with unique keys into a map, moving the items; on error the
        /// pairs keep them.
        fn split(gpa: Allocator, pairs: []const Pair) Allocator.Error!Self {
            const keys = try gpa.alloc(K, pairs.len);
            errdefer gpa.free(keys);
            const values = try gpa.alloc(V, pairs.len);
            for (pairs, keys, values) |pair, *key_out, *value_out| {
                key_out.* = pair[0];
                value_out.* = pair[1];
            }
            const result: Self = .{ .keys = .{ .items = keys }, .values = values };
            result.keys.assert_sorted();
            return result;
        }

        /// A map from ordered keys and their values (`values[i]` for `keys[i]`), taking
        /// ownership of both; null (nothing taken) when the lengths differ.
        pub fn from_parts(keys: Set(K), values: []V) ?Self {
            if (keys.len() != values.len) return null;
            return .{ .keys = keys, .values = values };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.keys.deinit(gpa);
            free_slice(V, gpa, self.values);
            self.* = undefined;
        }

        pub fn len(self: Self) usize {
            assert(self.keys.len() == self.values.len);
            return self.values.len;
        }

        pub fn is_empty(self: Self) bool {
            return self.len() == 0;
        }

        pub fn get(self: *const Self, index: usize) ?*const K {
            return self.keys.get(index);
        }

        pub fn position(self: Self, key: K) ?usize {
            return self.keys.position(key);
        }

        /// The value at `index`.
        pub fn value(self: *const Self, index: usize) ?*const V {
            return if (index < self.values.len) &self.values[index] else null;
        }

        pub fn get_value(self: *const Self, key: K) ?*const V {
            return &self.values[self.position(key) orelse return null];
        }

        pub fn get_value_mut(self: *Self, key: K) ?*V {
            return &self.values[self.position(key) orelse return null];
        }

        /// Consumes the map, releasing its values, and returns its keys.
        pub fn into_keys(self: *Self, gpa: Allocator) Set(K) {
            const keys = self.keys;
            free_slice(V, gpa, self.values);
            self.* = undefined;
            return keys;
        }

        /// Truncates to at most `new_len` entries, releasing the rest.
        pub fn truncate(self: *Self, gpa: Allocator, new_len: usize) Allocator.Error!void {
            if (new_len >= self.len()) return;
            // Copy first so a failed allocation leaves the map unchanged.
            const keys = try gpa.dupe(K, self.keys.items[0..new_len]);
            errdefer gpa.free(keys);
            const values = try gpa.dupe(V, self.values[0..new_len]);
            free_items(K, gpa, self.keys.items[new_len..]);
            gpa.free(self.keys.items);
            free_items(V, gpa, self.values[new_len..]);
            gpa.free(self.values);
            self.keys.items = keys;
            self.values = values;
            assert(self.len() == new_len);
        }

        /// Maps every value in key order through `transform(context, *const K, *const V)`,
        /// which returns `U` or an error union of `U`; the keys are copied (they must not own
        /// memory). On error, the values mapped so far are released.
        pub fn map_values(
            self: *const Self,
            gpa: Allocator,
            comptime U: type,
            context: anytype,
            comptime transform: anytype,
        ) !Map(K, U) {
            const values = try gpa.alloc(U, self.values.len);
            errdefer gpa.free(values);
            var done: usize = 0;
            errdefer free_items(U, gpa, values[0..done]);
            while (done < values.len) : (done += 1) {
                const result = transform(context, &self.keys.items[done], &self.values[done]);
                values[done] = if (comptime is_error_union(@TypeOf(result))) try result else result;
            }
            return .{ .keys = try self.keys.clone(gpa), .values = values };
        }

        /// `map_values` consuming the map: the keys move into the result and each value
        /// moves into `transform(context, *const K, V)`, which owns it from then on (it
        /// releases the value itself if it fails). On error, the rest of the map is released.
        pub fn map_values_into(
            self: *Self,
            gpa: Allocator,
            comptime U: type,
            context: anytype,
            comptime transform: anytype,
        ) !Map(K, U) {
            // Values before `consumed` moved into `transform`; the first `produced` results
            // are in `values`.
            var consumed: usize = 0;
            var produced: usize = 0;
            errdefer {
                free_items(V, gpa, self.values[consumed..]);
                gpa.free(self.values);
                self.keys.deinit(gpa);
                self.* = undefined;
            }
            const values = try gpa.alloc(U, self.values.len);
            errdefer gpa.free(values);
            errdefer free_items(U, gpa, values[0..produced]);
            while (consumed < values.len) {
                consumed += 1;
                const index = consumed - 1;
                const result = transform(context, &self.keys.items[index], self.values[index]);
                const is_fallible = comptime is_error_union(@TypeOf(result));
                values[index] = if (is_fallible) try result else result;
                produced = consumed;
            }
            assert(produced == values.len);
            gpa.free(self.values);
            const mapped: Map(K, U) = .{ .keys = self.keys, .values = values };
            self.* = undefined;
            return mapped;
        }

        fn is_error_union(comptime R: type) bool {
            return @typeInfo(R) == .error_union;
        }

        pub const Entry = struct { *const K, *const V };

        /// Key/value pairs in key order, from either end.
        pub const Iterator = struct {
            map: *const Self,
            front: usize,
            back: usize,

            pub fn next(it: *Iterator) ?Entry {
                if (it.front == it.back) return null;
                it.front += 1;
                return .{ &it.map.keys.items[it.front - 1], &it.map.values[it.front - 1] };
            }

            pub fn next_back(it: *Iterator) ?Entry {
                if (it.front == it.back) return null;
                it.back -= 1;
                return .{ &it.map.keys.items[it.back], &it.map.values[it.back] };
            }

            pub fn len(it: Iterator) usize {
                assert(it.front <= it.back);
                return it.back - it.front;
            }
        };

        pub fn iter_pairs(self: *const Self) Iterator {
            return .{ .map = self, .front = 0, .back = self.len() };
        }

        pub fn eql(a: Self, b: Self) bool {
            if (!a.keys.eql(b.keys)) return false;
            for (a.values, b.values) |left, right| {
                if (compare(V, left, right) != .eq) return false;
            }
            return true;
        }

        /// `[(k, v), ...]` (Rust `Display`).
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.writeByte('[');
            for (self.keys.items, self.values, 0..) |key, item, index| {
                if (index > 0) try writer.writeAll(", ");
                try writer.writeByte('(');
                try format_item(K, key, writer);
                try writer.writeAll(", ");
                try format_item(V, item, writer);
                try writer.writeByte(')');
            }
            try writer.writeByte(']');
        }

        // Codec.

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.keys.write(writer);
            codec.write([]const V, self.values, writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.keys.encode_size() + codec.encode_size([]const V, self.values);
        }

        /// Upper bound on the encoded size of at most `count` entries whose values encode to
        /// at most `value_size` bytes (Rust `Map::max_encode_size`).
        pub fn encode_size_max(count: usize, value_size: usize) usize {
            return Set(K).encode_size_max(count) + codec.util.max_items_size(count, value_size);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            var keys = try Set(K).read(gpa, reader, .{ .range = cfg.range, .item = cfg.key });
            errdefer keys.deinit(gpa);
            const count = try codec.read_usize(reader, .exact(keys.len()));
            const values = try codec.read_items(V, gpa, reader, count, cfg.value);
            return .{ .keys = keys, .values = values };
        }

        /// commonware's `Arbitrary`: an arbitrary `Vec<(K, V)>` through `from_dedup`.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const pairs = try codec.arbitrary.collect(Pair, gpa, u);
            defer gpa.free(pairs);
            return from_dedup(gpa, pairs);
        }
    };
}

pub fn BiMap(comptime K: type, comptime V: type) type {
    return struct {
        inner: Map(K, V) = .empty,

        const Self = @This();
        const Inner = Map(K, V);

        pub const Pair = Inner.Pair;
        pub const Cfg = Inner.Cfg;
        pub const empty: Self = .{};

        /// Sorts `pairs` by key into a new map; fails on a duplicate key or value.
        pub fn init(gpa: Allocator, pairs: []const Pair) (Allocator.Error || Error)!Self {
            return from_map(gpa, try Inner.init(gpa, pairs));
        }

        /// Takes ownership of `map`, releasing it on a duplicate value (Rust `try_from`).
        pub fn from_map(gpa: Allocator, map: Inner) (Allocator.Error || Error)!Self {
            var owned = map;
            errdefer owned.deinit(gpa);
            if (try has_duplicate_value(gpa, owned.values)) return error.DuplicateValue;
            return .{ .inner = owned };
        }

        fn has_duplicate_value(gpa: Allocator, items: []const V) Allocator.Error!bool {
            if (items.len < 2) return false;
            const sorted = try gpa.dupe(V, items);
            defer gpa.free(sorted);
            std.mem.sort(V, sorted, {}, less_than(V));
            for (1..@max(sorted.len, 1)) |cursor| {
                if (compare(V, sorted[cursor - 1], sorted[cursor]) == .eq) return true;
            }
            return false;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.inner.deinit(gpa);
            self.* = undefined;
        }

        pub fn len(self: Self) usize {
            return self.inner.len();
        }

        pub fn is_empty(self: Self) bool {
            return self.inner.is_empty();
        }

        pub fn keys(self: *const Self) *const Set(K) {
            return &self.inner.keys;
        }

        pub fn values(self: Self) []const V {
            return self.inner.values;
        }

        pub fn get(self: *const Self, index: usize) ?*const K {
            return self.inner.get(index);
        }

        pub fn position(self: Self, key: K) ?usize {
            return self.inner.position(key);
        }

        pub fn value(self: *const Self, index: usize) ?*const V {
            return self.inner.value(index);
        }

        pub fn get_value(self: *const Self, key: K) ?*const V {
            return self.inner.get_value(key);
        }

        /// The key whose value is `item` (a linear scan, as in commonware).
        pub fn get_key(self: *const Self, item: V) ?*const K {
            for (self.inner.values, 0..) |candidate, index| {
                if (compare(V, candidate, item) == .eq) return &self.inner.keys.items[index];
            }
            return null;
        }

        pub fn iter_pairs(self: *const Self) Inner.Iterator {
            return self.inner.iter_pairs();
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.inner.eql(b.inner);
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            return self.inner.format(writer);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.inner.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.inner.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            var map = try Inner.read(gpa, reader, cfg);
            errdefer map.deinit(gpa);
            if (try has_duplicate_value(gpa, map.values)) {
                return reader.invalid("BiMap", "duplicate value detected during deserialization");
            }
            return .{ .inner = map };
        }

        /// commonware's `Arbitrary`: an arbitrary `Vec<(K, V)>`, deduplicated by key (first
        /// kept), then by value (stable sort by value, first kept).
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const pairs = try codec.arbitrary.collect(Pair, gpa, u);
            defer gpa.free(pairs);
            const by_key = dedup_by(pairs, 0);
            const by_value = dedup_by(by_key, 1);
            return init(gpa, by_value) catch |err| switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.DuplicateKey, error.DuplicateValue => error.IncorrectFormat,
            };
        }

        /// Stable-sorts `pairs` by field `field` and keeps the first of each run of equals.
        fn dedup_by(pairs: []Pair, comptime field: usize) []Pair {
            const F = @typeInfo(Pair).@"struct".field_types[field];
            std.mem.sort(Pair, pairs, {}, struct {
                fn less(_: void, a: Pair, b: Pair) bool {
                    return compare(F, a[field], b[field]) == .lt;
                }
            }.less);
            var kept: usize = @min(pairs.len, 1);
            for (1..@max(pairs.len, 1)) |cursor| {
                if (compare(F, pairs[kept - 1][field], pairs[cursor][field]) != .eq) {
                    pairs[kept] = pairs[cursor];
                    kept += 1;
                }
            }
            return pairs[0..kept];
        }
    };
}
