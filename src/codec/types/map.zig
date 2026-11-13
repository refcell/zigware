//! Canonical maps and sets (codec/src/types/{btree_map,btree_set,hash_map,hash_set}.rs).
//!
//! Wire format: a `usize` count, then each key (and value) in strictly ascending key order.
//! Decoding rejects unsorted and duplicate keys, so every map has exactly one encoding.
//! commonware's `BTreeMap` and `HashMap` (and the two sets) share this format and differ only
//! in the context of their decode errors, so zigware has one implementation for both:
//! `Map`/`Set` use the `BTreeMap`/`BTreeSet` context, `HashMap`/`HashSet` the hash ones.
//!
//! Values hold a slice sorted by `codec.order`; `sort` puts an unsorted slice in order.
//! Writing asserts the order (a map with duplicate keys is a programming error).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const buf = @import("../buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("../error.zig").Error;
const RangeCfg = @import("../config.zig").RangeCfg;
const codec = @import("../codec.zig");

pub fn Map(comptime K: type, comptime V: type) type {
    return OrderedMap(K, V, "BTreeMap");
}

pub fn HashMap(comptime K: type, comptime V: type) type {
    return OrderedMap(K, V, "HashMap");
}

pub fn Set(comptime K: type) type {
    return OrderedSet(K, "BTreeSet");
}

pub fn HashSet(comptime K: type) type {
    return OrderedSet(K, "HashSet");
}

/// Config for reading a map: the permitted count, and the key and value configs.
pub fn MapCfg(comptime KeyCfg: type, comptime ValueCfg: type) type {
    const unit: void = {};
    return @Struct(.auto, null, &.{ "range", "key", "value" }, &.{
        RangeCfg(usize), KeyCfg, ValueCfg,
    }, &.{
        .{},
        .{ .default_value_ptr = if (KeyCfg == void) &unit else null },
        .{ .default_value_ptr = if (ValueCfg == void) &unit else null },
    });
}

/// Initial capacity for `len` decoded items: all of them when the input provably holds them,
/// otherwise at most one per remaining input byte.
fn reserve_count(reader: *const Reader, len: usize, comptime item_size: ?usize) Error!usize {
    if (item_size) |size| {
        try reader.at_least_items(len, size);
        return len;
    }
    return @min(len, reader.remaining());
}

/// Reads one key (or item) and fails with `Invalid` unless it sorts strictly after `previous`.
fn read_ascending(
    comptime K: type,
    gpa: Allocator,
    reader: *Reader,
    cfg: codec.Cfg(K),
    previous: ?*const K,
    comptime messages: Messages,
) Error!K {
    const key = try codec.read_cfg(K, gpa, reader, cfg);
    const last = previous orelse return key;
    errdefer codec.free(K, gpa, key);
    return switch (codec.order(K, key, last.*)) {
        .gt => key,
        .eq => reader.invalid(messages.context, messages.duplicate),
        .lt => reader.invalid(messages.context, messages.unsorted),
    };
}

const Messages = struct { context: []const u8, duplicate: []const u8, unsorted: []const u8 };

pub fn OrderedMap(comptime K: type, comptime V: type, comptime name: []const u8) type {
    return struct {
        const Self = @This();

        entries: []const Entry,

        const messages = Messages{
            .context = name,
            .duplicate = "Duplicate key",
            .unsorted = "Keys must ascend",
        };

        pub const Entry = struct { key: K, value: V };
        pub const Cfg = MapCfg(codec.Cfg(K), codec.Cfg(V));

        /// Wraps entries that are already strictly ascending by key.
        pub fn init(entries: []const Entry) Self {
            const self = Self{ .entries = entries };
            assert(self.is_sorted());
            return self;
        }

        /// Sorts `entries` by key so they can be wrapped with `init`.
        pub fn sort(entries: []Entry) void {
            std.sort.pdq(Entry, entries, {}, less_than);
        }

        fn less_than(_: void, a: Entry, b: Entry) bool {
            return codec.order(K, a.key, b.key) == .lt;
        }

        /// Whether keys are strictly ascending (sorted and free of duplicates).
        pub fn is_sorted(self: Self) bool {
            if (self.entries.len < 2) return true;
            for (self.entries[0 .. self.entries.len - 1], self.entries[1..]) |a, b| {
                if (codec.order(K, a.key, b.key) != .lt) return false;
            }
            return true;
        }

        /// Looks up `key` by binary search.
        pub fn get(self: Self, key: K) ?V {
            const index = std.sort.binarySearch(Entry, self.entries, key, compare_key) orelse
                return null;
            return self.entries[index].value;
        }

        fn compare_key(key: K, entry: Entry) std.math.Order {
            return codec.order(K, key, entry.key);
        }

        pub fn write(self: Self, writer: *Writer) void {
            assert(self.is_sorted());
            codec.write(usize, self.entries.len, writer);
            for (self.entries) |entry| {
                codec.write(K, entry.key, writer);
                codec.write(V, entry.value, writer);
            }
        }

        pub fn encode_size(self: Self) usize {
            var size = codec.encode_size(usize, self.entries.len);
            for (self.entries) |entry| {
                size += codec.encode_size(K, entry.key) + codec.encode_size(V, entry.value);
            }
            return size;
        }

        pub fn read(gpa: Allocator, reader: *Reader, cfg: Cfg) Error!Self {
            const len = try codec.read_usize(reader, cfg.range);
            const entry_size: ?usize = comptime if (codec.fixed_size(K)) |key_size|
                if (codec.fixed_size(V)) |value_size| key_size + value_size else null
            else
                null;
            var list = try std.ArrayList(Entry).initCapacity(
                gpa,
                try reserve_count(reader, len, entry_size),
            );
            errdefer free_entries(gpa, &list);
            var index: usize = 0;
            while (index < len) : (index += 1) {
                const last = if (list.items.len > 0) &list.items[list.items.len - 1] else null;
                const previous = if (last) |entry| &entry.key else null;
                const key = try read_ascending(K, gpa, reader, cfg.key, previous, messages);
                const value = codec.read_cfg(V, gpa, reader, cfg.value) catch |err| {
                    codec.free(K, gpa, key);
                    return err;
                };
                list.append(gpa, .{ .key = key, .value = value }) catch |err| {
                    codec.free(K, gpa, key);
                    codec.free(V, gpa, value);
                    return err;
                };
            }
            const entries = try list.toOwnedSlice(gpa);
            assert(entries.len == len);
            return .{ .entries = entries };
        }

        fn free_entries(gpa: Allocator, list: *std.ArrayList(Entry)) void {
            for (list.items) |entry| {
                codec.free(K, gpa, entry.key);
                codec.free(V, gpa, entry.value);
            }
            list.deinit(gpa);
        }

        /// Frees a decoded map.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.entries) |entry| {
                codec.free(K, gpa, entry.key);
                codec.free(V, gpa, entry.value);
            }
            gpa.free(self.entries);
            self.* = undefined;
        }
    };
}

pub fn OrderedSet(comptime K: type, comptime name: []const u8) type {
    return struct {
        const Self = @This();

        items: []const K,

        const messages = Messages{
            .context = name,
            .duplicate = "Duplicate item",
            .unsorted = "Items must ascend",
        };

        pub const Cfg = codec.SliceCfg(codec.Cfg(K));

        /// Wraps items that are already strictly ascending.
        pub fn init(items: []const K) Self {
            const self = Self{ .items = items };
            assert(self.is_sorted());
            return self;
        }

        /// Sorts `items` so they can be wrapped with `init`.
        pub fn sort(items: []K) void {
            std.sort.pdq(K, items, {}, less_than);
        }

        fn less_than(_: void, a: K, b: K) bool {
            return codec.order(K, a, b) == .lt;
        }

        /// Whether items are strictly ascending (sorted and free of duplicates).
        pub fn is_sorted(self: Self) bool {
            if (self.items.len < 2) return true;
            for (self.items[0 .. self.items.len - 1], self.items[1..]) |a, b| {
                if (codec.order(K, a, b) != .lt) return false;
            }
            return true;
        }

        pub fn contains(self: Self, item: K) bool {
            return std.sort.binarySearch(K, self.items, item, compare_item) != null;
        }

        fn compare_item(item: K, other: K) std.math.Order {
            return codec.order(K, item, other);
        }

        pub fn write(self: Self, writer: *Writer) void {
            assert(self.is_sorted());
            codec.write(usize, self.items.len, writer);
            codec.write_items(K, self.items, writer);
        }

        pub fn encode_size(self: Self) usize {
            const prefix_size = codec.encode_size(usize, self.items.len);
            return prefix_size + codec.encode_size_items(K, self.items);
        }

        pub fn read(gpa: Allocator, reader: *Reader, cfg: Cfg) Error!Self {
            const len = try codec.read_usize(reader, cfg.range);
            const capacity = try reserve_count(reader, len, comptime codec.fixed_size(K));
            var list = try std.ArrayList(K).initCapacity(gpa, capacity);
            errdefer {
                codec.free_items(K, gpa, list.items);
                list.deinit(gpa);
            }
            var index: usize = 0;
            while (index < len) : (index += 1) {
                const previous = if (list.items.len > 0) &list.items[list.items.len - 1] else null;
                const item = try read_ascending(K, gpa, reader, cfg.item, previous, messages);
                list.append(gpa, item) catch |err| {
                    codec.free(K, gpa, item);
                    return err;
                };
            }
            const items = try list.toOwnedSlice(gpa);
            assert(items.len == len);
            return .{ .items = items };
        }

        /// Frees a decoded set.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            codec.free_items(K, gpa, self.items);
            gpa.free(self.items);
            self.* = undefined;
        }
    };
}
