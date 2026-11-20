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
    return std.mem.order(u8, value_mod.bytes(K, a), value_mod.bytes(K, b));
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

/// Binary-searches key-sorted `entries` for `key`.
pub fn lookup_sorted(
    comptime K: type,
    comptime V: type,
    entries: []const Pair(K, V),
    key: *const K,
) ?*const Entry(V) {
    var low: usize = 0;
    var high: usize = entries.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        switch (order(K, &entries[mid].key, key)) {
            .lt => low = mid + 1,
            .gt => high = mid,
            .eq => return &entries[mid].entry,
        }
    }
    assert(low == high);
    return null;
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
