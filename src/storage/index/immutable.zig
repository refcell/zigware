//! An index for keys that are set once at increasing positions and retired only by position
//! (port of commonware's `storage/src/index/immutable.rs`).
//!
//! Positions are inserted at or above the index's start and retired in prefix order by
//! `prune`, which suits append-only logs. The translated key of each position from `start`
//! through the last indexed one sits in a ring, so pruning retires exactly the pruned positions
//! without a pass over the live entries: each retired slot names the key whose positions lose
//! it. Positions never indexed hold a copy of a neighboring key and retire nothing.
//!
//! As in commonware, the table holds only positions, in `utils.handles.Table`, under the hash of
//! their translated key. It stores no keys: a lookup confirms each candidate position against
//! its ring slot, and growth rehashes each held position through the ring.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const handles = @import("utils").handles;
const translator_module = @import("../translator.zig");

/// Positions of retained keys by translated key.
pub fn Index(comptime T: type) type {
    translator_module.check(T);
    return struct {
        const Self = @This();

        gpa: Allocator,
        translator: T,
        /// Every indexed position, under the hash of its translated key.
        table: handles.Table(u64) = .empty,
        /// The translated key at each position from `start` through the last indexed one.
        /// Positions never indexed hold a copy of some key that is never resolved.
        keys: std.Deque(T.Key) = .empty,
        /// Positions below this were never indexed or have been retired.
        start: u64,
        /// Positions retired by `prune` (commonware's `pruned` counter).
        pruned: u64 = 0,

        /// An empty index for positions at or above `start`, with room for `capacity` positions
        /// before the table or the key ring grows.
        pub fn init(gpa: Allocator, translator: T, start: u64, capacity: usize) !Self {
            var table: handles.Table(u64) = try .init_capacity(gpa, capacity);
            errdefer table.deinit(gpa);
            var self: Self = .{
                .gpa = gpa,
                .translator = translator,
                .table = table,
                .start = start,
            };
            try self.keys.ensureTotalCapacity(gpa, capacity);
            assert(self.table.capacity() >= capacity);
            assert(self.is_empty());
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.table.deinit(self.gpa);
            self.keys.deinit(self.gpa);
            self.* = undefined;
        }

        fn offset(self: *const Self, position: u64) usize {
            assert(position >= self.start); // Retained positions are at or above the start.
            const result: usize = @intCast(position - self.start);
            assert(self.start + result == position);
            return result;
        }

        /// The translated key at `position`, which must be within the ring.
        fn key_at(self: *const Self, position: u64) T.Key {
            const slot = self.offset(position);
            assert(slot < self.keys.len);
            return self.keys.at(slot);
        }

        /// Resolves a held position back to its key's hash when the table grows.
        const Rehash = struct {
            index: *const Self,

            pub fn rehash(ctx: Rehash, position: u64) u64 {
                return ctx.index.translator.hash(ctx.index.key_at(position));
            }
        };

        /// Indexes `key` at `position`, which must be at or above the start and not indexed.
        pub fn insert(self: *Self, key: []const u8, position: u64) Allocator.Error!void {
            assert(position >= self.start); // position must be at or above the index start
            const translated = self.translator.transform(key);
            const len_before = self.table.len;
            // Record the key in the ring, extending it through this position (filling skipped
            // slots with this key) when the position is further ahead. A failed table insert
            // below leaves only unindexed slots changed, which retire nothing.
            const slot = self.offset(position);
            if (slot < self.keys.len) {
                self.keys.atPtr(slot).* = translated;
            } else {
                const missing = slot + 1 - self.keys.len;
                try self.keys.ensureUnusedCapacity(self.gpa, missing);
                for (0..missing) |_| self.keys.pushBackAssumeCapacity(translated);
            }
            const hash = self.translator.hash(translated);
            try self.table.insert(self.gpa, hash, position, Rehash{ .index = self });
            assert(self.keys.len > slot);
            assert(self.table.len == len_before + 1);
        }

        /// The positions indexed under a translated key, in no particular order.
        pub const Positions = struct {
            index: *const Self,
            translated: T.Key,
            candidates: handles.Table(u64).Candidates,

            pub fn next(it: *Positions) ?u64 {
                while (it.candidates.next()) |position| {
                    assert(position >= it.index.start);
                    if (T.eql(it.index.key_at(position), it.translated)) return position;
                }
                return null;
            }
        };

        /// The indexed positions whose translated key is that of `key`, in no particular order.
        pub fn get(self: *const Self, key: []const u8) Positions {
            const translated = self.translator.transform(key);
            const hash = self.translator.hash(translated);
            assert(self.table.len <= self.keys.len);
            return .{ .index = self, .translated = translated, .candidates = self.table.get(hash) };
        }

        /// Retires every indexed position below `start`.
        pub fn prune(self: *Self, start: u64) void {
            if (start <= self.start) return;
            // Remove each retired position under the key its slot holds. A slot that was never
            // indexed holds a key whose entries all carry other positions, so it removes nothing.
            const retired = @min(self.offset(start), self.keys.len);
            const len_before = self.table.len;
            var removed: u64 = 0;
            for (0..retired) |slot| {
                const key = self.keys.popFront().?;
                const hash = self.translator.hash(key);
                removed += @intFromBool(self.table.remove(hash, self.start + slot));
            }
            self.start = start;
            self.pruned += removed;
            assert(self.table.len + removed == len_before);
            assert(self.table.len <= self.keys.len);
        }

        /// The number of indexed positions.
        pub fn len(self: *const Self) u64 {
            return self.table.len;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.table.len == 0;
        }
    };
}

const testing = std.testing;
const test_gpa = testing.allocator;

fn expect_positions(index: anytype, key: []const u8, expected: []const u64) !void {
    var actual: std.ArrayList(u64) = .empty;
    defer actual.deinit(test_gpa);
    var positions = index.get(key);
    while (positions.next()) |position| try actual.append(test_gpa, position);
    std.mem.sort(u64, actual.items, {}, std.sort.asc(u64));
    try testing.expectEqualSlices(u64, expected, actual.items);
}

test "get confirms translated key" {
    var index = try Index(translator_module.TwoCap).init(test_gpa, .{}, 0, 0);
    defer index.deinit();
    // Two keys collide under TwoCap and the third does not.
    try index.insert("aa1", 1);
    try index.insert("aa2", 3);
    try index.insert("bb1", 4);
    try expect_positions(&index, "aa1", &.{ 1, 3 });
    try expect_positions(&index, "aa9", &.{ 1, 3 });
    try expect_positions(&index, "bb1", &.{4});
    try expect_positions(&index, "cc1", &.{});
    try testing.expectEqual(@as(u64, 3), index.len());
}

test "get rejects candidates sharing slot and fingerprint" {
    // The golden ratio's inverse mod 2^64: adding `inverse << 16` to a key adds `1 << 16` to
    // its hash, so commonware's table yields each key as a candidate for the other.
    const inverse: u64 = 0xf1de_83e1_9937_733d;
    try testing.expectEqual(@as(u64, 1), @import("utils").GOLDEN_RATIO *% inverse);
    const k1: u64 = 0x1234_5678_9abc_def0;
    const k2 = k1 +% (inverse << 16);
    var index = try Index(translator_module.EightCap).init(test_gpa, .{}, 0, 0);
    defer index.deinit();
    const h1 = index.translator.hash(k1);
    const h2 = index.translator.hash(k2);
    try testing.expectEqual(h1 +% (1 << 16), h2);
    try testing.expectEqual(h1 >> 56, h2 >> 56);
    var b1: [8]u8 = undefined;
    var b2: [8]u8 = undefined;
    std.mem.writeInt(u64, &b1, k1, .big);
    std.mem.writeInt(u64, &b2, k2, .big);
    try index.insert(&b1, 1);
    try index.insert(&b2, 3);
    try expect_positions(&index, &b1, &.{1});
    try expect_positions(&index, &b2, &.{3});
}

test "prune retires exactly the pruned positions" {
    var index = try Index(translator_module.EightCap).init(test_gpa, .{}, 0, 0);
    defer index.deinit();
    // Keys at positions 1, 3, 4, 9, and 20 interleave with unindexed positions.
    for ([_]u64{ 1, 3, 4, 9, 20 }, 0..) |position, i| {
        const key: [8]u8 = @splat(@intCast(i));
        try index.insert(&key, position);
    }
    try testing.expectEqual(@as(u64, 5), index.len());
    try testing.expectEqual(@as(usize, 21), index.keys.len);
    index.prune(2);
    try testing.expectEqual(@as(u64, 4), index.len());
    try testing.expectEqual(@as(usize, 19), index.keys.len);
    try expect_positions(&index, &@as([8]u8, @splat(0)), &.{});
    try expect_positions(&index, &@as([8]u8, @splat(1)), &.{3});
    try testing.expectEqual(@as(u64, 1), index.pruned);
    index.prune(1); // A start below the retired start does nothing.
    try testing.expectEqual(@as(u64, 4), index.len());
    index.prune(9); // A start at an indexed position keeps it.
    try testing.expectEqual(@as(u64, 2), index.len());
    try expect_positions(&index, &@as([8]u8, @splat(3)), &.{9});
    try expect_positions(&index, &@as([8]u8, @splat(4)), &.{20});
    index.prune(100);
    try testing.expect(index.is_empty());
    try testing.expectEqual(@as(usize, 0), index.keys.len);
    try testing.expectEqual(@as(u64, 5), index.pruned);
    try index.insert(&@as([8]u8, @splat(9)), 101);
    try expect_positions(&index, &@as([8]u8, @splat(9)), &.{101});
    try testing.expectEqual(@as(usize, 2), index.keys.len);
}

test "start above zero" {
    const start = 40_967;
    var index = try Index(translator_module.EightCap).init(test_gpa, .{}, start, 0);
    defer index.deinit();
    try index.insert("first___", start);
    try index.insert("second__", start + 5_000);
    try expect_positions(&index, "first___", &.{start});
    index.prune(start + 1);
    try expect_positions(&index, "first___", &.{});
    try expect_positions(&index, "second__", &.{start + 5_000});
    try testing.expectEqual(@as(u64, 1), index.len());
}

fn growth_key(i: u32) [3]u8 {
    var key: [3]u8 = undefined;
    std.mem.writeInt(u16, key[0..2], @intCast(i % 5_000), .big);
    key[2] = @intCast(i / 5_000);
    return key;
}

fn contains(index: anytype, key: []const u8, position: u64) bool {
    var positions = index.get(key);
    while (positions.next()) |candidate| if (candidate == position) return true;
    return false;
}

test "growth rehashes through the keys" {
    // Enough keys to grow the table several times, four per translated key under TwoCap.
    var index = try Index(translator_module.TwoCap).init(test_gpa, .{}, 0, 0);
    defer index.deinit();
    for (0..20_000) |i| try index.insert(&growth_key(@intCast(i)), 2 * i + 1);
    try testing.expectEqual(@as(u64, 20_000), index.len());
    var i: u32 = 0;
    while (i < 20_000) : (i += 997) try testing.expect(contains(&index, &growth_key(i), 2 * i + 1));
    index.prune(20_001); // Retire the first half exactly.
    try testing.expectEqual(@as(u64, 10_000), index.len());
    try testing.expect(!contains(&index, &growth_key(0), 1));
    try testing.expect(contains(&index, &growth_key(10_000), 20_001));
    try testing.expect(contains(&index, &growth_key(19_999), 39_999));
    try testing.expectEqual(@as(u64, 10_000), index.pruned);
}

// Fuzz: inserts at increasing positions (with gaps, and a later position sometimes indexed
// before an earlier one) and prunes, checked against a list of live (position, key) pairs.

const fuzz_bytes = @import("../fuzz_bytes.zig");

fn fuzz_check(index: anytype, live: []const [2]u64) !void {
    try testing.expectEqual(@as(u64, live.len), index.len());
    for (0..4) |key_byte| {
        const key = [1]u8{@intCast(key_byte)};
        var expected: [256]u64 = undefined;
        var count: usize = 0;
        for (live) |pair| {
            if (pair[1] != key_byte) continue;
            expected[count] = pair[0];
            count += 1;
        }
        std.mem.sort(u64, expected[0..count], {}, std.sort.asc(u64));
        try expect_positions(index, &key, expected[0..count]);
    }
}

fn fuzz_run(bytes: []const u8) anyerror!void {
    var index = try Index(translator_module.OneCap).init(test_gpa, .{}, 3, 4);
    defer index.deinit();
    var live: std.ArrayList([2]u64) = .empty;
    defer live.deinit(test_gpa);
    var reader = fuzz_bytes.Reader.init(bytes);
    var next: u64 = 3;
    var operations: u32 = 0;
    while (!reader.done() and operations < 128) : (operations += 1) {
        if (reader.below(4) == 0) {
            const start = index.start + reader.below(8);
            index.prune(start);
            var kept: usize = 0;
            for (live.items) |pair| {
                if (pair[0] < start) continue;
                live.items[kept] = pair;
                kept += 1;
            }
            live.shrinkRetainingCapacity(kept);
            next = @max(next, start);
        } else {
            // Skip ahead by up to 3, then index two positions in either order.
            const first = next + reader.below(4);
            const keys = [2]u8{ @intCast(reader.below(4)), @intCast(reader.below(4)) };
            const swap = reader.boolean();
            for (0..2) |i| {
                const j = if (swap) 1 - i else i;
                try index.insert(&.{keys[j]}, first + j);
                try live.append(test_gpa, .{ first + j, keys[j] });
            }
            next = first + 2;
        }
        try fuzz_check(&index, live.items);
    }
}

test "fuzz immutable index (seeded)" {
    try fuzz_bytes.seeded(512, 0x696d6d75, 128, fuzz_run);
}

test "fuzz immutable index" {
    try testing.fuzz({}, fuzz_bytes.smith(512, fuzz_run), .{});
}
