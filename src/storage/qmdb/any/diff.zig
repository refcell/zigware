//! Key-level batch diffs of an `any` database (the diff parts of commonware's
//! `qmdb/any/batch.rs`): what each batch did to each key, sorted by key, shared by the batches
//! merkleized after it while they live.
//!
//! Keys order by their encoded bytes, which is Rust's `Ord` for the fixed-size keys QMDB uses
//! (digests and big-endian integers).

const std = @import("std");
const assert = std.debug.assert;
const refcount = @import("../../refcount.zig");
const RefCount = refcount.RefCount;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const value_mod = @import("../value.zig");

/// The order of two keys: their encoded bytes, lexicographically.
pub fn order(comptime K: type, a: *const K, b: *const K) std.math.Order {
    const x = value_mod.bytes(K, a);
    const y = value_mod.bytes(K, b);
    const fixed = comptime fixed_length(K);
    if (fixed == null) return std.mem.order(u8, x, y);
    const length = fixed.?;
    assert(x.len == length and y.len == length);
    // Big-endian words order as their bytes do, so most keys settle in one compare instead of
    // `std.mem.order`'s byte loop.
    const words = length / 8;
    inline for (0..words) |word| {
        const p = std.mem.readInt(u64, x[word * 8 ..][0..8], .big);
        const q = std.mem.readInt(u64, y[word * 8 ..][0..8], .big);
        if (p != q) return if (p < q) .lt else .gt;
    }
    return std.mem.order(u8, x[words * 8 .. length], y[words * 8 .. length]);
}

/// The encoded length of `K` when every key has the same one: byte arrays and digests.
fn fixed_length(comptime K: type) ?usize {
    switch (@typeInfo(K)) {
        .array => |info| return if (info.child == u8) info.len else null,
        .@"struct" => {
            if (!@hasField(K, "bytes")) return null;
            const Bytes = @FieldType(K, "bytes");
            if (@typeInfo(Bytes) != .array) return null;
            if (@sizeOf(K) != @sizeOf(Bytes)) return null;
            return @typeInfo(Bytes).array.len;
        },
        else => return null,
    }
}

/// What a batch did to a key.
pub fn Entry(comptime V: type) type {
    return union(enum) {
        const Self = @This();

        /// The key was updated or created.
        active: struct {
            value: V,
            /// Where this batch writes it.
            loc: u64,
            /// The key's location in the database snapshot, null if it was not there.
            base_old_loc: ?u64,
        },
        /// The key was deleted.
        deleted: struct {
            /// The key's location in the database snapshot, null if it was not there.
            base_old_loc: ?u64,
        },

        pub fn base_old_loc(self: *const Self) ?u64 {
            return switch (self.*) {
                .active => |a| a.base_old_loc,
                .deleted => |d| d.base_old_loc,
            };
        }

        /// The location this batch writes, null for a delete.
        pub fn loc(self: *const Self) ?u64 {
            return switch (self.*) {
                .active => |a| a.loc,
                .deleted => null,
            };
        }

        /// The value if active, null for a delete.
        pub fn value(self: *const Self) ?V {
            return switch (self.*) {
                .active => |a| a.value,
                .deleted => null,
            };
        }
    };
}

pub fn Pair(comptime K: type, comptime V: type) type {
    return struct { key: K, entry: Entry(V) };
}

/// A batch's diff: entries sorted by key without duplicates, reference counted so descendants
/// can hold it after the batch is released.
pub fn Diff(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Item = Pair(K, V);

        references: RefCount,
        entries: []Item,

        /// Takes ownership of `entries` and their values; they must be sorted by key without
        /// duplicates.
        pub fn create(gpa: Allocator, entries: []Item) Allocator.Error!*Self {
            assert(is_sorted(K, V, entries));
            const self = try gpa.create(Self);
            self.* = .{ .references = .init(), .entries = entries };
            return self;
        }

        pub fn retain(self: *Self) *Self {
            self.references.retain();
            return self;
        }

        pub fn release(self: *Self, gpa: Allocator) void {
            if (!self.references.release()) return;
            free_entries(K, V, gpa, self.entries);
            gpa.destroy(self);
        }

        /// The entry for `key`, if this diff holds one.
        pub fn lookup(self: *const Self, key: *const K) ?*const Entry(V) {
            return lookup_sorted(K, V, self.entries, key);
        }
    };
}

/// Frees `entries` and their values.
pub fn free_entries(
    comptime K: type,
    comptime V: type,
    gpa: Allocator,
    entries: []Pair(K, V),
) void {
    for (entries) |*pair| {
        if (pair.entry == .active) codec.free(V, gpa, pair.entry.active.value);
    }
    gpa.free(entries);
}

pub fn is_sorted(comptime K: type, comptime V: type, entries: []const Pair(K, V)) bool {
    if (entries.len < 2) return true;
    for (entries[1..], entries[0 .. entries.len - 1]) |b, a| {
        if (order(K, &a.key, &b.key) != .lt) return false;
    }
    return true;
}

/// The indices of `items` (keys, or items with a `key: K` field) in key order, equal keys in index
/// order: the order a stable sort by key gives, without moving the items. A stable LSD radix
/// sort orders slots by each key's first eight bytes (big-endian, zero-padded), skipping
/// passes whose byte is the same in every key; runs that share a prefix are then sorted by the
/// whole key. The caller owns the result.
pub fn key_order(comptime K: type, comptime T: type, gpa: Allocator, items: []const T) ![]u32 {
    assert(items.len <= std.math.maxInt(u32));
    const slots = try gpa.alloc(PrefixSlot, items.len * 2);
    defer gpa.free(slots);
    var source = slots[0..items.len];
    var target = slots[items.len..];
    var counts: [8][256]u32 = @splat(@splat(0));
    for (source, items, 0..) |*slot, *item, index| {
        const prefix = key_prefix(K, item_key(K, T, item));
        slot.* = .{ .prefix = prefix, .index = @intCast(index) };
        inline for (0..8) |digit| counts[digit][@as(u8, @truncate(prefix >> (digit * 8)))] += 1;
    }
    for (&counts, 0..) |*count, digit| {
        if (items.len == 0) break;
        const shift: u6 = @intCast(digit * 8);
        if (count[@as(u8, @truncate(source[0].prefix >> shift))] == items.len) continue;
        var offset: u32 = 0;
        for (count) |*bucket| {
            const size = bucket.*;
            bucket.* = offset;
            offset += size;
        }
        for (source) |slot| {
            const bucket = &count[@as(u8, @truncate(slot.prefix >> shift))];
            target[bucket.*] = slot;
            bucket.* += 1;
        }
        std.mem.swap([]PrefixSlot, &source, &target);
    }
    sort_prefix_runs(K, T, items, source);
    const indices = try gpa.alloc(u32, items.len);
    for (indices, source) |*index, slot| index.* = slot.index;
    assert(indices.len == items.len);
    return indices;
}

const PrefixSlot = struct { prefix: u64, index: u32 };

/// Sorts `values` ascending: a stable LSD radix sort on bytes, skipping each byte that is the
/// same in every value (database locations differ in their low two or three bytes only).
pub fn sort_u64(gpa: Allocator, values: []u64) !void {
    if (values.len < 2) return;
    // Superseded locations usually arrive in emission order, which is already ascending.
    for (values[1..], values[0 .. values.len - 1]) |value, previous| {
        if (value < previous) break;
    } else return;
    const scratch = try gpa.alloc(u64, values.len);
    defer gpa.free(scratch);
    var counts: [8][256]u32 = @splat(@splat(0));
    for (values) |value| {
        inline for (0..8) |digit| counts[digit][@as(u8, @truncate(value >> (digit * 8)))] += 1;
    }
    var source = values;
    var target = scratch;
    for (&counts, 0..) |*count, digit| {
        const shift: u6 = @intCast(digit * 8);
        if (count[@as(u8, @truncate(source[0] >> shift))] == values.len) continue;
        var offset: u32 = 0;
        for (count) |*bucket| {
            const size = bucket.*;
            bucket.* = offset;
            offset += size;
        }
        for (source) |value| {
            const bucket = &count[@as(u8, @truncate(value >> shift))];
            target[bucket.*] = value;
            bucket.* += 1;
        }
        std.mem.swap([]u64, &source, &target);
    }
    if (source.ptr != values.ptr) @memcpy(values, source);
    assert(!std.debug.runtime_safety or std.sort.isSorted(u64, values, {}, std.sort.asc(u64)));
}

/// The key of `item`: the item itself when `T` is `K`, else its `key` field.
fn item_key(comptime K: type, comptime T: type, item: *const T) *const K {
    if (T == K) return item;
    return &item.key;
}

/// Stably sorts `items` (keys, or items with a `key: K` field) by key through `key_order`.
pub fn sort_by_key(comptime K: type, comptime T: type, gpa: Allocator, items: []T) !void {
    if (items.len < 2) return;
    // Items often arrive in order already (a walk in location order over keys created in key
    // order), which one linear check settles.
    for (1..items.len) |at| {
        if (order(K, item_key(K, T, &items[at - 1]), item_key(K, T, &items[at])) == .gt) break;
    } else return;
    const indices = try key_order(K, T, gpa, items);
    defer gpa.free(indices);
    const copy = try gpa.dupe(T, items);
    defer gpa.free(copy);
    for (items, indices) |*item, index| item.* = copy[index];
    assert(indices.len == items.len);
}

/// The first eight bytes of `key`, big-endian and zero-padded, which order as the key does
/// whenever they differ.
pub fn key_prefix(comptime K: type, key: *const K) u64 {
    const bytes = value_mod.bytes(K, key);
    if (bytes.len >= 8) return std.mem.readInt(u64, bytes[0..8], .big);
    var head: [8]u8 = @splat(0);
    @memcpy(head[0..bytes.len], bytes);
    return std.mem.readInt(u64, &head, .big);
}

/// Sorts each run of prefix-sorted `slots` that shares a prefix by the whole key, then by
/// index (the radix passes left equal keys in index order).
fn sort_prefix_runs(
    comptime K: type,
    comptime T: type,
    items: []const T,
    slots: []PrefixSlot,
) void {
    const Context = struct {
        items: []const T,
        fn less(context: @This(), a: PrefixSlot, b: PrefixSlot) bool {
            const ka = item_key(K, T, &context.items[a.index]);
            const kb = item_key(K, T, &context.items[b.index]);
            return switch (order(K, ka, kb)) {
                .lt => true,
                .gt => false,
                .eq => a.index < b.index,
            };
        }
    };
    var start: usize = 0;
    while (start < slots.len) {
        var end = start + 1;
        while (end < slots.len and slots[end].prefix == slots[start].prefix) end += 1;
        // Every slot differs (ties fall to the index), so the unstable sort is deterministic.
        if (end - start > 1) std.sort.pdq(PrefixSlot, slots[start..end], Context{
            .items = items,
        }, Context.less);
        start = end;
    }
    assert(start == slots.len);
}

/// Binary-searches key-sorted `entries` for `key`.
pub fn lookup_sorted(
    comptime K: type,
    comptime V: type,
    entries: []const Pair(K, V),
    key: *const K,
) ?*const Entry(V) {
    const index = find_sorted(K, Pair(K, V), entries, key) orelse return null;
    return &entries[index].entry;
}

/// The index of `key` in `items` (keys, or items with a `key: K` field; sorted by key with
/// unique keys), or null.
pub fn find_sorted(comptime K: type, comptime T: type, items: []const T, key: *const K) ?usize {
    const index = lower_bound(K, T, items, key);
    if (index == items.len) return null;
    if (order(K, item_key(K, T, &items[index]), key) != .eq) return null;
    return index;
}

/// The index of the first of key-sorted `items` at or above `key` (`items.len` if none).
pub fn lower_bound(comptime K: type, comptime T: type, items: []const T, key: *const K) usize {
    return bound(K, T, items, key, .lt);
}

/// The index of the first of key-sorted `items` above `key` (`items.len` if none).
pub fn upper_bound(comptime K: type, comptime T: type, items: []const T, key: *const K) usize {
    return bound(K, T, items, key, .eq);
}

/// The first index past the items ordering at most `skip` against `key`: a branchless lower
/// bound on the keys' eight-byte prefixes, then a scan of the equal prefixes by whole key, so
/// random keys settle without the mispredicted branch per step a byte-order binary search takes.
fn bound(
    comptime K: type,
    comptime T: type,
    items: []const T,
    key: *const K,
    comptime skip: std.math.Order,
) usize {
    comptime assert(skip != .gt);
    if (items.len == 0) return 0;
    const prefix = key_prefix(K, key);
    var base: usize = 0;
    var length = items.len;
    while (length > 1) {
        const half = length / 2;
        const below = key_prefix(K, item_key(K, T, &items[base + half])) < prefix;
        base = if (below) base + half else base;
        length -= half;
    }
    base += @intFromBool(key_prefix(K, item_key(K, T, &items[base])) < prefix);
    assert(base <= items.len);
    while (base < items.len and key_prefix(K, item_key(K, T, &items[base])) == prefix) {
        const relation = order(K, item_key(K, T, &items[base]), key);
        if (relation == .gt or (skip == .lt and relation == .eq)) break;
        base += 1;
    }
    return base;
}

/// The first entry for `key` among `diffs`, ordered nearest first.
pub fn resolve(
    comptime K: type,
    comptime V: type,
    diffs: []const []const Pair(K, V),
    key: *const K,
) ?*const Entry(V) {
    for (diffs) |entries| {
        if (lookup_sorted(K, V, entries, key)) |entry| return entry;
    }
    return null;
}

/// Resolves ascending keys against diffs ordered nearest first, one advancing cursor per diff
/// (commonware's `DiffCursors`).
pub fn Cursors(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        diffs: []const []const Pair(K, V),
        positions: []usize,

        pub fn init(gpa: Allocator, diffs: []const []const Pair(K, V)) Allocator.Error!Self {
            const positions = try gpa.alloc(usize, diffs.len);
            @memset(positions, 0);
            return .{ .diffs = diffs, .positions = positions };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.positions);
            self.* = undefined;
        }

        /// Rewinds every cursor, for another ascending run of queries.
        pub fn reset(self: *Self) void {
            @memset(self.positions, 0);
        }

        /// The nearest entry for `key`. Queries must not decrease.
        pub fn resolve(self: *Self, key: *const K) ?*const Entry(V) {
            for (self.diffs, self.positions) |entries, *position| {
                assert(position.* == 0 or order(K, &entries[position.* - 1].key, key) == .lt);
                while (position.* < entries.len and
                    order(K, &entries[position.*].key, key) == .lt) position.* += 1;
                if (position.* < entries.len and
                    order(K, &entries[position.*].key, key) == .eq)
                {
                    return &entries[position.*].entry;
                }
            }
            return null;
        }
    };
}

/// A k-way merge of key-sorted diffs in priority order: each key once, from the
/// lowest-indexed diff holding it (commonware's `DiffMerge`).
pub fn Merge(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        streams: []const []const Pair(K, V),
        positions: []usize,

        pub fn init(gpa: Allocator, streams: []const []const Pair(K, V)) Allocator.Error!Self {
            const positions = try gpa.alloc(usize, streams.len);
            @memset(positions, 0);
            return .{ .streams = streams, .positions = positions };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.positions);
            self.* = undefined;
        }

        fn peek(self: *const Self, level: usize) ?*const K {
            const entries = self.streams[level];
            const position = self.positions[level];
            return if (position < entries.len) &entries[position].key else null;
        }

        /// The next entry in key order: the nearest stream's on equal keys, which advances every
        /// stream holding that key. One and two streams, the common chain depths, take
        /// commonware's fast paths: one key comparison per entry instead of a scan and a pass.
        pub fn next(self: *Self) ?*const Pair(K, V) {
            return switch (self.streams.len) {
                0 => null,
                1 => self.next_one(),
                2 => self.next_two(),
                else => self.next_general(),
            };
        }

        fn next_one(self: *Self) ?*const Pair(K, V) {
            assert(self.streams.len == 1);
            _ = self.peek(0) orelse return null;
            self.positions[0] += 1;
            return &self.streams[0][self.positions[0] - 1];
        }

        fn next_two(self: *Self) ?*const Pair(K, V) {
            assert(self.streams.len == 2);
            const level: usize = level: {
                const near = self.peek(0) orelse break :level 1;
                const far = self.peek(1) orelse break :level 0;
                switch (order(K, near, far)) {
                    .lt => break :level 0,
                    .gt => break :level 1,
                    .eq => {
                        self.positions[1] += 1; // The nearer stream's entry shadows this one.
                        break :level 0;
                    },
                }
            };
            _ = self.peek(level) orelse return null;
            self.positions[level] += 1;
            return &self.streams[level][self.positions[level] - 1];
        }

        fn next_general(self: *Self) ?*const Pair(K, V) {
            var winner: ?usize = null;
            for (0..self.streams.len) |level| {
                const key = self.peek(level) orelse continue;
                if (winner) |w| {
                    if (order(K, key, self.peek(w).?) != .lt) continue;
                }
                winner = level;
            }
            const level = winner orelse return null;
            const pair = &self.streams[level][self.positions[level]];
            for (0..self.streams.len) |other| {
                const key = self.peek(other) orelse continue;
                if (order(K, key, &pair.key) == .eq) self.positions[other] += 1;
            }
            assert(self.positions[level] > 0);
            return pair;
        }
    };
}

const testing = std.testing;
const Key = [2]u8;
const P = Pair(Key, u32);

fn active(k: u8, loc: u64) P {
    const entry: Entry(u32) = .{ .active = .{ .value = k, .loc = loc, .base_old_loc = null } };
    return .{ .key = .{ 0, k }, .entry = entry };
}

fn deleted(k: u8) P {
    return .{ .key = .{ 0, k }, .entry = .{ .deleted = .{ .base_old_loc = 7 } } };
}

test "diff lookup, cursors, and merge prefer the nearest diff" {
    const gpa = testing.allocator;
    const near = [_]P{ active(2, 20), deleted(5) };
    const far = [_]P{ active(1, 10), active(2, 11), active(5, 12), active(9, 13) };
    const diffs = [_][]const P{ &near, &far };
    try testing.expectEqual(@as(?u64, 20), resolve(Key, u32, &diffs, &.{ 0, 2 }).?.loc());
    try testing.expectEqual(@as(?u64, null), resolve(Key, u32, &diffs, &.{ 0, 5 }).?.loc());
    try testing.expect(resolve(Key, u32, &diffs, &.{ 0, 3 }) == null);
    var cursors = try Cursors(Key, u32).init(gpa, &diffs);
    defer cursors.deinit(gpa);
    try testing.expectEqual(@as(?u64, 10), cursors.resolve(&.{ 0, 1 }).?.loc());
    try testing.expectEqual(@as(?u64, 20), cursors.resolve(&.{ 0, 2 }).?.loc());
    try testing.expect(cursors.resolve(&.{ 0, 4 }) == null);
    try testing.expectEqual(@as(?u64, 7), cursors.resolve(&.{ 0, 5 }).?.base_old_loc());
    const mid = [_]P{ active(2, 15), active(3, 16), active(9, 17) };
    // One, two, and three streams: the fast paths and the general merge.
    try expect_merge(&.{&far}, &.{ .{ 1, 10 }, .{ 2, 11 }, .{ 5, 12 }, .{ 9, 13 } });
    try expect_merge(&diffs, &.{ .{ 1, 10 }, .{ 2, 20 }, .{ 5, null }, .{ 9, 13 } });
    try expect_merge(&.{ &near, &mid, &far }, &.{
        .{ 1, 10 }, .{ 2, 20 }, .{ 3, 16 }, .{ 5, null }, .{ 9, 17 },
    });
    try expect_merge(&.{ &mid, &near }, &.{ .{ 2, 15 }, .{ 3, 16 }, .{ 5, null }, .{ 9, 17 } });
}

fn expect_merge(streams: []const []const P, expected: []const struct { u8, ?u64 }) !void {
    var merge = try Merge(Key, u32).init(testing.allocator, streams);
    defer merge.deinit(testing.allocator);
    for (expected) |want| {
        const pair = merge.next().?;
        try testing.expectEqual(want[0], pair.key[1]);
        try testing.expectEqual(want[1], pair.entry.loc());
    }
    try testing.expect(merge.next() == null);
}

// commonware `diff_cursors_rejects_out_of_order_query` (`#[should_panic]`): an out-of-order
// query, which would return a wrong result, panics instead.
test "diff cursors reject an out-of-order query" {
    try @import("utils").death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            const diff = [_]P{ active(1, 1), active(5, 5) };
            const diffs = [_][]const P{&diff};
            var cursors = try Cursors(Key, u32).init(testing.allocator, &diffs);
            defer cursors.deinit(testing.allocator);
            try testing.expect(cursors.resolve(&.{ 0, 5 }) != null);
            _ = cursors.resolve(&.{ 0, 1 });
        }
    }.body);
}

// `key_order`, `sort_by_key`, `find_sorted`, and the word-wise `order` against a byte-order
// stable sort and a linear scan, on 2-byte keys (below the 8-byte prefix) and 12-byte keys
// whose first eight bytes are drawn from few values, so runs share a prefix and differ only
// past it, with duplicate keys whose write order must survive.
test "diff key order matches a stable byte-order sort" {
    var prng: std.Random.DefaultPrng = .init(0x5eed_0f_04de);
    const random = prng.random();
    try expect_key_order([2]u8, random);
    try expect_key_order([12]u8, random);
    try expect_key_order([32]u8, random);
    for (0..100) |round| {
        const values = try testing.allocator.alloc(u64, random.uintAtMost(usize, 500));
        defer testing.allocator.free(values);
        // Few high bits set, so most passes are skipped, and some values span every byte.
        for (values) |*value| {
            value.* = if (round % 4 == 0) random.int(u64) else random.uintAtMost(u64, 70_000);
        }
        const reference = try testing.allocator.dupe(u64, values);
        defer testing.allocator.free(reference);
        std.mem.sort(u64, reference, {}, std.sort.asc(u64));
        try sort_u64(testing.allocator, values);
        try testing.expectEqualSlices(u64, reference, values);
    }
}

fn expect_key_order(comptime K: type, random: std.Random) !void {
    const gpa = testing.allocator;
    const Item = struct { key: K, index: u32 };
    for (0..200) |round| {
        const items = try gpa.alloc(Item, random.uintAtMost(usize, 300));
        defer gpa.free(items);
        for (items, 0..) |*item, index| {
            for (&item.key, 0..) |*byte, at| {
                // Few distinct bytes near the front, so prefixes collide often.
                const front = random.uintAtMost(u8, @intCast(round % 3 + 1));
                byte.* = if (at < 9) front else random.int(u8);
            }
            if (index > 0 and random.boolean()) {
                item.key = items[random.uintLessThan(usize, index)].key;
            }
            item.index = @intCast(index);
        }
        const reference = try gpa.dupe(Item, items);
        defer gpa.free(reference);
        std.mem.sort(Item, reference, {}, struct {
            fn less(_: void, a: Item, b: Item) bool {
                return std.mem.order(u8, &a.key, &b.key) == .lt;
            }
        }.less);
        const indices = try key_order(K, Item, gpa, items);
        defer gpa.free(indices);
        for (reference, indices) |want, got| try testing.expectEqual(want.index, got);
        const sorted = try gpa.dupe(Item, items);
        defer gpa.free(sorted);
        try sort_by_key(K, Item, gpa, sorted);
        for (reference, sorted) |want, got| try testing.expectEqual(want.index, got.index);
        try expect_find_sorted(K, Item, reference, random);
    }
}

/// `find_sorted`, the bounds, and `order` on `sorted` (duplicates dropped) against linear scans.
fn expect_find_sorted(
    comptime K: type,
    comptime Item: type,
    sorted: []const Item,
    random: std.Random,
) !void {
    var unique: std.ArrayList(Item) = .empty;
    defer unique.deinit(testing.allocator);
    for (sorted) |item| {
        if (unique.items.len > 0 and std.mem.eql(u8, &unique.getLast().key, &item.key)) continue;
        try unique.append(testing.allocator, item);
    }
    for (0..unique.items.len + 8) |_| {
        var key: K = undefined;
        if (unique.items.len > 0 and random.boolean()) {
            key = unique.items[random.uintLessThan(usize, unique.items.len)].key;
        } else {
            for (&key, 0..) |*byte, at| {
                byte.* = if (at < 9) random.uintAtMost(u8, 2) else random.int(u8);
            }
        }
        var want: ?usize = null;
        var below: usize = 0;
        var at_most: usize = 0;
        for (unique.items, 0..) |item, at| {
            const relation = std.mem.order(u8, &item.key, &key);
            try testing.expectEqual(relation, order(K, &item.key, &key));
            if (relation == .eq) want = at;
            below += @intFromBool(relation == .lt);
            at_most += @intFromBool(relation != .gt);
        }
        try testing.expectEqual(want, find_sorted(K, Item, unique.items, &key));
        try testing.expectEqual(below, lower_bound(K, Item, unique.items, &key));
        try testing.expectEqual(at_most, upper_bound(K, Item, unique.items, &key));
    }
}
