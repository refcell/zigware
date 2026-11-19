//! Tests for the indices, ported from commonware's `storage/src/index/{mod,ordered}.rs`, plus
//! the `index_unordered_operations` and `index_ordered_operations` fuzz targets (storage/fuzz)
//! checked against a reference model. Every generic test runs against both indices.
//!
//! Commonware's `should_panic` tests (cursor `update`/`delete`/`insert` before `next` or after
//! the last value, a double delete) check panics, which a Zig test cannot catch; the panics are
//! in `Cursor.active` and `Cursor.insert`. The cross-thread cursor test shares an index behind
//! a `std.Io.Mutex`, as commonware's behind an `Arc<Mutex<_>>`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const utils = @import("utils");
const translator = @import("../translator.zig");
const unordered = @import("unordered.zig");
const ordered = @import("ordered.zig");
const partitioned = @import("partitioned/mod.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");

const gpa = testing.allocator;
const TwoCap = translator.TwoCap;

const OneCap = translator.OneCap;
const PartitionedUnordered = partitioned.unordered.Index(OneCap, u64, 1);
const PartitionedOrdered = partitioned.ordered.Index(OneCap, u64, 1);

/// Every index the generic checks run against. A one-byte prefix with `OneCap` translates keys
/// like `TwoCap` on a flat index, so every index sees the same collisions.
const indices = .{
    unordered.Index(TwoCap, u64), ordered.Index(TwoCap, u64),
    PartitionedUnordered,         PartitionedOrdered,
};

/// An empty index of type `I` with its default translator.
fn new(comptime I: type) I {
    const Tr = I.Translator;
    const tr: Tr = if (@hasDecl(Tr, "partition_count")) .init(.{}) else .{};
    return I.init(gpa, tr);
}

/// The values of `key` in index order. Caller owns the slice.
fn values(index: anytype, key: []const u8) ![]u64 {
    var list: std.ArrayList(u64) = .empty;
    errdefer list.deinit(gpa);
    var iterator = index.get(key);
    while (iterator.next()) |value| try list.append(gpa, value.*);
    return list.toOwnedSlice(gpa);
}

fn expect_values_ordered(index: anytype, key: []const u8, expected: []const u64) !void {
    const actual = try values(index, key);
    defer gpa.free(actual);
    try testing.expectEqualSlices(u64, expected, actual);
}

/// The values of `key`, in any order, are `expected`.
fn expect_values(index: anytype, key: []const u8, expected: []const u64) !void {
    const actual = try values(index, key);
    defer gpa.free(actual);
    const sorted = try gpa.dupe(u64, expected);
    defer gpa.free(sorted);
    std.mem.sort(u64, actual, {}, std.sort.asc(u64));
    std.mem.sort(u64, sorted, {}, std.sort.asc(u64));
    try testing.expectEqualSlices(u64, sorted, actual);
}

fn expect_counters(index: anytype, keys: u64, items: u64, pruned: ?u64) !void {
    try testing.expectEqual(keys, index.keys());
    try testing.expectEqual(items, index.items());
    if (pruned) |count| try testing.expectEqual(count, index.pruned());
}

fn not_equal(target: u64, value: *const u64) bool {
    return value.* != target;
}

fn equal(target: u64, value: *const u64) bool {
    return value.* == target;
}

fn constant(result: bool, _: *const u64) bool {
    return result;
}

fn insert_all(index: anytype, key: []const u8, items: []const u64) !void {
    for (items) |value| try index.insert(key, value);
}

fn run_basic(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    const key = "duplicate";
    try insert_all(&index, key, &.{ 1, 2, 3 });
    try testing.expectEqual(@as(u64, 1), index.keys());
    try expect_values(&index, key, &.{ 1, 2, 3 });
    {
        var cursor = index.get_mut(key).?;
        defer cursor.finish();
        var seen: usize = 0;
        while (cursor.next()) |_| seen += 1;
        try testing.expectEqual(@as(usize, 3), seen);
        try testing.expect(cursor.next() == null);
    }
    try insert_all(&index, key, &.{ 3, 4 });
    index.retain(key, @as(u64, 3), not_equal);
    try expect_values(&index, key, &.{ 1, 2, 4 });
    index.retain(key, false, constant);
    try expect_values(&index, key, &.{});
    try testing.expectEqual(@as(u64, 0), index.keys());
    try testing.expect(index.get_mut(key) == null);
    index.retain(key, false, constant);
}

test "index basic" {
    inline for (indices) |I| try run_basic(I);
}

const Visits = struct {
    lists: [4]std.ArrayList(u64) = @splat(.empty),

    fn visit(self: *Visits, key_index: usize, value: *const u64) void {
        self.lists[key_index].append(gpa, value.*) catch @panic("out of memory");
    }

    fn deinit(self: *Visits) void {
        for (&self.lists) |*list| list.deinit(gpa);
    }
};

fn no_visit(_: void, _: usize, _: *const u64) void {
    @panic("no visits expected");
}

fn run_get_many(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "ab", &.{ 1, 2 });
    try index.insert("abX", 3);
    try index.insert("zz", 4);
    const keys = [_][]const u8{ "zz", "missing", "ab", "zz" };
    var visits: Visits = .{};
    defer visits.deinit();
    index.get_many(&keys, &visits, Visits.visit);
    std.mem.sort(u64, visits.lists[2].items, {}, std.sort.asc(u64));
    try testing.expectEqualSlices(u64, &.{4}, visits.lists[0].items);
    try testing.expectEqual(@as(usize, 0), visits.lists[1].items.len);
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3 }, visits.lists[2].items);
    try testing.expectEqualSlices(u64, &.{4}, visits.lists[3].items);
    index.get_many(&.{}, {}, no_visit);
}

test "index get many" {
    inline for (indices) |I| try run_get_many(I);
}

fn run_cursor_find(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    const key = "test_key";
    try insert_all(&index, key, &.{ 10, 20, 30, 40 });
    {
        var cursor = index.get_mut(key).?;
        defer cursor.finish();
        try testing.expect(cursor.find(@as(u64, 30), equal));
        cursor.update(35);
    }
    try expect_values(&index, key, &.{ 10, 20, 35, 40 });
    {
        var cursor = index.get_mut(key).?;
        defer cursor.finish();
        try testing.expect(!cursor.find(@as(u64, 100), equal));
        try testing.expect(cursor.next() == null);
    }
    {
        var cursor = index.get_mut(key).?;
        defer cursor.finish();
        try testing.expect(cursor.find(@as(u64, 20), equal));
        cursor.delete();
    }
    try expect_values(&index, key, &.{ 10, 35, 40 });
}

test "index cursor find" {
    inline for (indices) |I| try run_cursor_find(I);
}

/// An index behind a mutex, as commonware's `Arc<Mutex<I>>`.
fn Shared(comptime I: type) type {
    return struct {
        mutex: std.Io.Mutex = .init,
        index: I,

        /// On another thread: finds value 200 of `test_key2` through a cursor and updates it to
        /// 250, holding the lock for the cursor's lifetime.
        fn update(shared: *@This(), updated: *bool) void {
            const io = testing.io;
            shared.mutex.lockUncancelable(io);
            defer shared.mutex.unlock(io);
            var cursor = shared.index.get_mut("test_key2") orelse return;
            defer cursor.finish();
            if (!cursor.find(@as(u64, 200), equal)) return;
            cursor.update(250);
            updated.* = true;
        }
    };
}

fn run_cursor_across_threads(comptime I: type) !void {
    const io = testing.io;
    var shared: Shared(I) = .{ .index = new(I) };
    defer shared.index.deinit();
    {
        shared.mutex.lockUncancelable(io);
        defer shared.mutex.unlock(io);
        try shared.index.insert("test_key1", 100);
        try shared.index.insert("test_key2", 200);
    }
    var updated = false;
    const thread = try std.Thread.spawn(.{}, Shared(I).update, .{ &shared, &updated });
    thread.join();
    try testing.expect(updated);
    // The update applied and the colliding value stayed.
    shared.mutex.lockUncancelable(io);
    defer shared.mutex.unlock(io);
    try expect_values(&shared.index, "test_key2", &.{ 100, 250 });
}

test "index cursor across threads" {
    inline for (indices) |I| try run_cursor_across_threads(I);
}

fn run_many_keys(comptime I: type) !void {
    const key_count = 2000;
    var index = new(I);
    defer index.deinit();
    var rng = utils.test_rng();
    var keys: [key_count][32]u8 = undefined;
    var translated = std.AutoHashMap(u16, void).init(gpa);
    defer translated.deinit();
    for (&keys, 0..) |*key, location| {
        rng.fill_bytes(key);
        try translated.put(std.mem.readInt(u16, key[0..2], .big), {});
        try index.insert(key, location);
    }
    try expect_counters(&index, translated.count(), key_count, null);
    for (&keys, 0..) |*key, location| {
        var found = false;
        var iterator = index.get(key);
        while (iterator.next()) |value| found = found or value.* == location;
        try testing.expect(found);
    }
}

test "index many keys" {
    inline for (indices) |I| try run_many_keys(I);
}

fn run_key_lengths_and_metrics(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try index.insert("a", 1);
    try index.insert("ab", 2);
    try index.insert("abc", 3);
    try expect_values(&index, "ab", &.{ 2, 3 });
    try expect_values(&index, "abc", &.{ 2, 3 });
    try index.insert("ab", 4);
    try expect_values(&index, "ab", &.{ 2, 3, 4 });
    try expect_counters(&index, 2, 4, null);
    index.retain("ab", @as(u64, 4), not_equal);
    try expect_values(&index, "ab", &.{ 2, 3 });
    try expect_counters(&index, 2, 3, null);
    index.retain("ab", false, constant);
    try expect_values(&index, "ab", &.{});
    try expect_counters(&index, 1, 1, null);
    try expect_values(&index, "a", &.{1});
}

test "index key lengths and key item metrics" {
    inline for (indices) |I| try run_key_lengths_and_metrics(I);
}

fn run_values_and_remove_specific(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "key", &.{ 1, 2, 3 });
    try expect_values(&index, "key", &.{ 1, 2, 3 });
    index.retain("key", @as(u64, 2), not_equal);
    try expect_values(&index, "key", &.{ 1, 3 });
    index.retain("key", @as(u64, 1), not_equal);
    try expect_values(&index, "key", &.{3});
}

test "index values and remove specific" {
    inline for (indices) |I| try run_values_and_remove_specific(I);
}

fn run_empty_key(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try index.insert("", 0);
    try index.insert("\x00", 1);
    try index.insert("\x00\x00", 2);
    for ([_][]const u8{ "", "\x00", "\x00\x00" }) |key| {
        try expect_values(&index, key, &.{ 0, 1, 2 });
    }
    index.retain("", @as(u64, 1), not_equal);
    try expect_values(&index, "", &.{ 0, 2 });
}

test "index empty key" {
    inline for (indices) |I| try run_empty_key(I);
}

fn run_mutate(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "key", &.{ 1, 2, 3 });
    {
        var cursor = index.get_mut("key").?;
        defer cursor.finish();
        while (cursor.next()) |old| cursor.update(old.* + 10);
    }
    try expect_values(&index, "key", &.{ 11, 12, 13 });
    try index.insert("key", 4);
    const expected = try values(&index, "key");
    defer gpa.free(expected);
    {
        var cursor = index.get_mut("key").?;
        defer cursor.finish();
        try testing.expectEqual(expected[0], cursor.next().?.*);
        try testing.expectEqual(expected[1], cursor.next().?.*);
        _ = cursor.next().?;
        cursor.update(99);
    }
    expected[2] = 99;
    try expect_values_ordered(&index, "key", expected);
}

test "index mutate through iterator and middle of four" {
    inline for (indices) |I| try run_mutate(I);
}

/// Deletes the value at `position` (in index order) through a cursor.
fn delete_at(index: anytype, key: []const u8, position: usize) !void {
    const expected = try values(index, key);
    defer gpa.free(expected);
    var cursor = index.get_mut(key).?;
    defer cursor.finish();
    for (expected[0 .. position + 1]) |value| try testing.expectEqual(value, cursor.next().?.*);
    cursor.delete();
}

/// Removes `expected[position]` from `expected` and checks the index matches it.
fn expect_deleted(index: anytype, expected: *std.ArrayList(u64), position: usize) !void {
    try delete_at(index, "key", position);
    _ = expected.orderedRemove(position);
    try expect_values_ordered(index, "key", expected.items);
}

fn reload(index: anytype, expected: *std.ArrayList(u64)) !void {
    const current = try values(index, "key");
    defer gpa.free(current);
    expected.clearRetainingCapacity();
    try expected.appendSlice(gpa, current);
}

fn run_remove_through_iterator(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "key", &.{ 10, 20, 30, 40 });
    try expect_values(&index, "key", &.{ 10, 20, 30, 40 });
    try testing.expectEqual(@as(u64, 0), index.pruned());
    var expected: std.ArrayList(u64) = .empty;
    defer expected.deinit(gpa);
    try reload(&index, &expected);
    try expect_deleted(&index, &expected, 0);
    try testing.expectEqual(@as(u64, 1), index.pruned());
    try index.insert("key", 50);
    try expected.append(gpa, 50);
    try expect_values(&index, "key", expected.items);
    try reload(&index, &expected);
    try expect_deleted(&index, &expected, 2);
    try testing.expectEqual(@as(u64, 2), index.pruned());
    try index.insert("key", 60);
    try expected.append(gpa, 60);
    try expect_values(&index, "key", expected.items);
    try reload(&index, &expected);
    try expect_deleted(&index, &expected, 3);
    try testing.expectEqual(@as(u64, 3), index.pruned());
    index.remove("key");
    try expect_counters(&index, 0, 0, 6);
}

test "index remove through iterator" {
    inline for (indices) |I| try run_remove_through_iterator(I);
}

fn run_insert_through_iterator(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try index.insert("key", 1);
    {
        var cursor = index.get_mut("key").?;
        defer cursor.finish();
        try testing.expectEqual(@as(u64, 1), cursor.next().?.*);
        try cursor.insert(3);
    }
    try expect_values_ordered(&index, "key", &.{ 1, 3 });
    try expect_counters(&index, 1, 2, null);
    {
        var cursor = index.get_mut("key").?;
        defer cursor.finish();
        try testing.expectEqual(@as(u64, 1), cursor.next().?.*);
        try cursor.insert(42);
    }
    try expect_counters(&index, 1, 3, null);
    try expect_values_ordered(&index, "key", &.{ 1, 42, 3 });
    try index.insert("key", 100);
    try expect_values(&index, "key", &.{ 1, 3, 42, 100 });
    // Inserting after the last value appends.
    var other = new(I);
    defer other.deinit();
    try other.insert("key", 10);
    {
        var cursor = other.get_mut("key").?;
        defer cursor.finish();
        try testing.expectEqual(@as(u64, 10), cursor.next().?.*);
        try testing.expect(cursor.next() == null);
        try cursor.insert(20);
    }
    try expect_values_ordered(&other, "key", &.{ 10, 20 });
}

test "index insert through iterator and after done" {
    inline for (indices) |I| try run_insert_through_iterator(I);
}

fn run_remove_to_nothing(comptime I: type, then_add: bool) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "key", &.{ 0, 1, 2, 3 });
    {
        var cursor = index.get_mut("key").?;
        defer cursor.finish();
        var removed: [4]u64 = undefined;
        var count: usize = 0;
        while (cursor.next()) |value| : (count += 1) {
            removed[count] = value.*;
            cursor.delete();
        }
        std.mem.sort(u64, &removed, {}, std.sort.asc(u64));
        try testing.expectEqualSlices(u64, &.{ 0, 1, 2, 3 }, removed[0..count]);
        try testing.expect(cursor.next() == null);
        if (then_add) {
            try cursor.insert(4);
            try testing.expect(cursor.next() == null);
            try cursor.insert(5);
        }
    }
    if (then_add) {
        try expect_values_ordered(&index, "key", &.{ 4, 5 });
        try expect_counters(&index, 1, 2, null);
    } else {
        try expect_counters(&index, 0, 0, 4);
    }
}

test "index remove to nothing, then add" {
    inline for (indices) |I| {
        try run_remove_to_nothing(I, false);
        try run_remove_to_nothing(I, true);
    }
}

fn run_insert_and_remove_cursor(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try index.insert("key", 0);
    {
        var cursor = index.get_mut("key").?;
        defer cursor.finish();
        try testing.expectEqual(@as(u64, 0), cursor.next().?.*);
        cursor.delete();
    }
    index.remove("key");
    try expect_values(&index, "key", &.{});
}

test "index insert and remove cursor" {
    inline for (indices) |I| try run_insert_and_remove_cursor(I);
}

fn run_insert_and_retain(comptime I: type) !void {
    {
        var index = new(I);
        defer index.deinit();
        try index.insert_and_retain("key", 1, true, constant);
        try expect_values_ordered(&index, "key", &.{1});
        try expect_counters(&index, 1, 1, 0);
    }
    {
        var index = new(I);
        defer index.deinit();
        try index.insert_and_retain("key", 1, false, constant);
        try expect_values(&index, "key", &.{});
        try expect_counters(&index, 0, 0, 0);
    }
    {
        var index = new(I);
        defer index.deinit();
        try index.insert("key", 1);
        try index.insert_and_retain("key", 2, @as(u64, 1), not_equal);
        try expect_values_ordered(&index, "key", &.{2});
        try expect_counters(&index, 1, 1, 1);
    }
    {
        var index = new(I);
        defer index.deinit();
        try insert_all(&index, "key", &.{ 10, 20 });
        try index.insert_and_retain("key", 30, false, constant);
        try expect_values(&index, "key", &.{});
        try expect_counters(&index, 0, 0, 2);
    }
}

test "index insert and retain vacant, replace one, and dead insert" {
    inline for (indices) |I| try run_insert_and_retain(I);
}

fn run_insert_and_retain_single_value(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try index.insert("both", 1);
    try index.insert_and_retain("both", 2, true, constant);
    try expect_values_ordered(&index, "both", &.{ 1, 2 });
    try index.insert("keep", 1);
    try index.insert_and_retain("keep", 2, @as(u64, 1), equal);
    try expect_values_ordered(&index, "keep", &.{1});
    try index.insert("drop", 1);
    try index.insert_and_retain("drop", 2, false, constant);
    try expect_values(&index, "drop", &.{});
    try expect_counters(&index, 2, 3, 1);
}

test "index insert and retain single value" {
    inline for (indices) |I| try run_insert_and_retain_single_value(I);
}

fn run_delete_sequences(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    // Delete the middle two of four, then continue.
    try insert_all(&index, "a", &.{ 0, 1, 2, 3 });
    const four = try values(&index, "a");
    defer gpa.free(four);
    {
        var cursor = index.get_mut("a").?;
        defer cursor.finish();
        try testing.expectEqual(four[0], cursor.next().?.*);
        try testing.expectEqual(four[1], cursor.next().?.*);
        cursor.delete();
        try testing.expectEqual(four[2], cursor.next().?.*);
        cursor.delete();
    }
    try expect_values_ordered(&index, "a", &.{ four[0], four[3] });
    // Delete the last of two; the cursor stays done.
    try insert_all(&index, "b", &.{ 1, 2 });
    {
        var cursor = index.get_mut("b").?;
        defer cursor.finish();
        _ = cursor.next().?;
        _ = cursor.next().?;
        cursor.delete();
        try testing.expect(cursor.next() == null);
        try testing.expect(cursor.next() == null);
    }
    try expect_counters(&index, 2, 3, null);
}

test "index remove middle then next and delete last then next" {
    inline for (indices) |I| try run_delete_sequences(I);
}

fn run_delete_first(comptime I: type, and_insert: bool) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "key", &.{ 1, 2, 3 });
    const expected = try values(&index, "key");
    defer gpa.free(expected);
    {
        var cursor = index.get_mut("key").?;
        defer cursor.finish();
        try testing.expectEqual(expected[0], cursor.next().?.*);
        cursor.delete();
        try testing.expectEqual(expected[1], cursor.next().?.*);
        if (and_insert) try cursor.insert(4);
        try testing.expectEqual(expected[2], cursor.next().?.*);
        try testing.expect(cursor.next() == null);
        try testing.expect(cursor.next() == null);
    }
    if (and_insert) {
        try expect_values_ordered(&index, "key", &.{ expected[1], 4, expected[2] });
    } else {
        try expect_values_ordered(&index, "key", expected[1..]);
    }
}

test "index delete first, and then insert" {
    inline for (indices) |I| {
        try run_delete_first(I, false);
        try run_delete_first(I, true);
    }
}

fn run_cursor_insert_with_next(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "key", &.{ 1, 2 });
    const expected = try values(&index, "key");
    defer gpa.free(expected);
    {
        var cursor = index.get_mut("key").?;
        defer cursor.finish();
        try testing.expectEqual(expected[0], cursor.next().?.*);
        try cursor.insert(99);
        try testing.expectEqual(expected[1], cursor.next().?.*);
        try testing.expect(cursor.next() == null);
        try cursor.insert(999);
    }
    try expect_values(&index, "key", &.{ 1, 2, 99, 999 });
}

test "index insert at entry then next, and insert with next" {
    inline for (indices) |I| try run_cursor_insert_with_next(I);
}

fn run_delete_last_then_insert_while_done(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try index.insert("k", 7);
    {
        var cursor = index.get_mut("k").?;
        defer cursor.finish();
        try testing.expectEqual(@as(u64, 7), cursor.next().?.*);
        cursor.delete();
        try testing.expect(cursor.next() == null);
        try cursor.insert(8);
        try testing.expect(cursor.next() == null);
        try cursor.insert(9);
        try testing.expect(cursor.next() == null);
    }
    try expect_counters(&index, 1, 2, null);
    try expect_values_ordered(&index, "k", &.{ 8, 9 });
    // Replacing the only value is not a collision.
    var other = new(I);
    defer other.deinit();
    try other.insert("a", 1);
    {
        var cursor = other.get_mut("a").?;
        defer cursor.finish();
        _ = cursor.next();
        cursor.delete();
        _ = cursor.next();
        try cursor.insert(2);
    }
    try expect_counters(&other, 1, 1, null);
}

test "index delete last then insert while done" {
    inline for (indices) |I| try run_delete_last_then_insert_while_done(I);
}

fn run_drop_mid_iteration(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "z", &.{ 0, 1, 2, 3, 4 });
    const expected = try values(&index, "z");
    defer gpa.free(expected);
    {
        var cursor = index.get_mut("z").?;
        defer cursor.finish();
        _ = cursor.next();
        _ = cursor.next();
    }
    try expect_values_ordered(&index, "z", expected);
}

test "index drop mid iteration preserves chain" {
    inline for (indices) |I| try run_drop_mid_iteration(I);
}

fn run_large_collision_chain(comptime I: type) !void {
    const count = 50_000;
    var index = new(I);
    defer index.deinit();
    for (0..count) |i| try index.insert("", i);
    try expect_counters(&index, 1, count, null);
    const actual = try values(&index, "");
    defer gpa.free(actual);
    std.mem.sort(u64, actual, {}, std.sort.asc(u64));
    for (actual, 0..) |value, i| try testing.expectEqual(@as(u64, i), value);
}

test "index large collision chain" {
    inline for (indices) |I| try run_large_collision_chain(I);
}

fn expect_neighbor(neighbor: anytype, cycled: bool, expected: []const u64) !void {
    var result = neighbor.?;
    try testing.expectEqual(cycled, result.cycled);
    for (expected) |value| try testing.expectEqual(value, result.values.next().?.*);
    try testing.expect(result.values.next() == null);
}

fn expect_next_values(maybe: anytype, expected: []const u64) !void {
    var iterator = maybe.?;
    for (expected) |value| try testing.expectEqual(value, iterator.next().?.*);
    try testing.expect(iterator.next() == null);
}

test "ordered empty index" {
    var index = ordered.Index(translator.OneCap, u64).init(gpa, .{});
    defer index.deinit();
    try testing.expect(index.first_translated_key() == null);
    try testing.expect(index.last_translated_key() == null);
    try testing.expect(index.prev_translated_key("key") == null);
    try testing.expect(index.next_translated_key("key") == null);
}

test "ordered index ordering" {
    var index = ordered.Index(translator.OneCap, u64).init(gpa, .{});
    defer index.deinit();
    try testing.expectEqual(@as(u64, 0), index.keys());
    const k1 = "\x0b\x02\xaa";
    const k3 = "\x2d\x06\xee";
    try index.insert(k1, 1);
    try index.insert("\x1c\x04\xcc", 21);
    try index.insert("\x1c\x03\x11", 22);
    try index.insert(k3, 3);
    try testing.expectEqual(@as(u64, 3), index.keys());
    try expect_next_values(index.first_translated_key(), &.{1});
    try expect_neighbor(index.next_translated_key("\x00"), false, &.{1});
    try expect_neighbor(index.next_translated_key("\x0b\x01\x02"), false, &.{ 22, 21 });
    try expect_neighbor(index.next_translated_key("\x1b\x01\x02\x03"), false, &.{ 22, 21 });
    try expect_neighbor(index.next_translated_key("\x2a\x01\x02\x03\x04"), false, &.{3});
    try expect_neighbor(index.next_translated_key(k3), true, &.{1});
    try expect_neighbor(index.next_translated_key("\x2e\xff"), true, &.{1});
    try expect_neighbor(index.prev_translated_key(k1), true, &.{3});
    try expect_neighbor(index.prev_translated_key("\x0c\x01\x02"), false, &.{1});
    try expect_neighbor(index.prev_translated_key("\x1d\x01\x02"), false, &.{ 22, 21 });
    try expect_neighbor(index.prev_translated_key("\xcc\x01\x02"), false, &.{3});
    try expect_next_values(index.last_translated_key(), &.{3});
}

test "ordered short keys" {
    // `[0x01]` and `[0x03]` are shorter than the cap and must still sort between their
    // neighbors. Each key's value is its lexicographic rank.
    var index = ordered.Index(translator.EightCap, u64).init(gpa, .{});
    defer index.deinit();
    const keys = [_][]const u8{ "\x00\x05", "\x01", "\x02\x09\xab", "\x03", "\xff\xff" };
    for (keys, 0..) |key, rank| try index.insert(key, rank);
    try expect_next_values(index.first_translated_key(), &.{0});
    try expect_next_values(index.last_translated_key(), &.{4});
    const n = keys.len;
    for (keys, 0..) |key, i| {
        const next_rank = (i + 1) % n;
        try expect_neighbor(index.next_translated_key(key), i + 1 == n, &.{next_rank});
        const prev_rank = (i + n - 1) % n;
        try expect_neighbor(index.prev_translated_key(key), i == 0, &.{prev_rank});
    }
}

// Fuzz: the `index_unordered_operations` and `index_ordered_operations` targets. The same
// operations drive both indices and a reference model (each translated key's values in index
// order), and every key's values and the counters must match the model after each operation.

const fuzz_operations_max = 128;
const Model = struct {
    lists: std.AutoArrayHashMapUnmanaged(u16, std.ArrayList(u64)) = .empty,
    pruned: u64 = 0,

    fn deinit(self: *Model) void {
        for (self.lists.values()) |*values_list| values_list.deinit(gpa);
        self.lists.deinit(gpa);
    }

    fn list_of(self: *Model, key: []const u8) !*std.ArrayList(u64) {
        const entry = try self.lists.getOrPut(gpa, TwoCap.transform(.{}, key));
        if (!entry.found_existing) entry.value_ptr.* = .empty;
        return entry.value_ptr;
    }

    /// Removes the values equal to `target` (every value when null), counting them as pruned.
    fn filter(self: *Model, values_list: *std.ArrayList(u64), target: ?u64) void {
        var kept: usize = 0;
        for (values_list.items) |value| {
            if (target == null or value == target.?) continue;
            values_list.items[kept] = value;
            kept += 1;
        }
        self.pruned += values_list.items.len - kept;
        values_list.shrinkRetainingCapacity(kept);
    }
};

fn fuzz_key(reader: *fuzz_bytes.Reader, buffer: *[3]u8) []const u8 {
    // Short keys from a small alphabet so translated keys collide often.
    const len = reader.below(4);
    for (buffer[0..len]) |*byte| byte.* = @intCast(reader.below(3));
    return buffer[0..len];
}

fn fuzz_cursor_op(index: anytype, kind: u64, key: []const u8, value: u64) !void {
    switch (kind) {
        0 => if (index.get_mut(key)) |found| {
            var cursor = found;
            defer cursor.finish();
            while (cursor.next()) |_| {}
        },
        1 => if (index.get_mut(key)) |found| {
            var cursor = found;
            defer cursor.finish();
            if (cursor.next() != null) cursor.update(value);
        },
        2 => if (index.get_mut(key)) |found| {
            var cursor = found;
            defer cursor.finish();
            if (cursor.next() != null) cursor.delete();
        },
        3 => if (try index.get_mut_or_insert(key, value)) |found| {
            var cursor = found;
            defer cursor.finish();
            _ = cursor.next();
            try cursor.insert(value);
        },
        else => unreachable,
    }
}

fn fuzz_model_cursor_op(model: *Model, kind: u64, key: []const u8, value: u64) !void {
    const values_list = try model.list_of(key);
    const items = values_list.items;
    switch (kind) {
        0 => {},
        1 => if (items.len > 0) {
            items[0] = value;
        },
        2 => if (items.len > 0) {
            _ = values_list.orderedRemove(0);
            model.pruned += 1;
        },
        3 => if (items.len == 0) {
            try values_list.append(gpa, value);
        } else {
            try values_list.insert(gpa, 1, value);
        },
        else => unreachable,
    }
}

fn fuzz_apply(index: anytype, op: u64, key: []const u8, value: u64, target: u64) !void {
    switch (op) {
        0 => try index.insert(key, value),
        1 => index.remove(key),
        2 => index.retain(key, target, not_equal),
        3 => try index.insert_and_retain(key, value, target, not_equal),
        4 => for (0..value % 16) |i| try index.insert(key, i),
        5 => index.retain(key, false, constant),
        6...9 => try fuzz_cursor_op(index, op - 6, key, value),
        else => unreachable,
    }
}

fn fuzz_model_apply(model: *Model, op: u64, key: []const u8, value: u64, target: u64) !void {
    const values_list = try model.list_of(key);
    switch (op) {
        0 => try values_list.insert(gpa, 0, value),
        1 => model.filter(values_list, null),
        2 => model.filter(values_list, target),
        3 => {
            model.filter(values_list, target);
            if (value != target) try values_list.append(gpa, value);
        },
        4 => for (0..value % 16) |i| try values_list.insert(gpa, 0, i),
        5 => model.filter(values_list, null),
        6...9 => try fuzz_model_cursor_op(model, op - 6, key, value),
        else => unreachable,
    }
}

fn fuzz_check(index: anytype, model: *const Model) !void {
    var keys: u64 = 0;
    var items: u64 = 0;
    for (model.lists.keys(), model.lists.values()) |translated, list| {
        var key: [2]u8 = undefined;
        std.mem.writeInt(u16, &key, translated, .big);
        try expect_values_ordered(index, &key, list.items);
        keys += @intFromBool(list.items.len > 0);
        items += list.items.len;
    }
    try expect_counters(index, keys, items, model.pruned);
}

fn fuzz_run(bytes: []const u8) anyerror!void {
    var model: Model = .{};
    defer model.deinit();
    var hashed = unordered.Index(TwoCap, u64).init(gpa, .{});
    defer hashed.deinit();
    var tree = ordered.Index(TwoCap, u64).init(gpa, .{});
    defer tree.deinit();
    var reader = fuzz_bytes.Reader.init(bytes);
    var operations: u32 = 0;
    while (!reader.done() and operations < fuzz_operations_max) : (operations += 1) {
        const op = reader.below(10);
        var key_buffer: [3]u8 = undefined;
        const key = fuzz_key(&reader, &key_buffer);
        const value = reader.below(8);
        const target = reader.below(8);
        try fuzz_apply(&hashed, op, key, value, target);
        try fuzz_apply(&tree, op, key, value, target);
        try fuzz_model_apply(&model, op, key, value, target);
        try fuzz_check(&hashed, &model);
        try fuzz_check(&tree, &model);
    }
    // The tree's first and last keys bound every model key.
    var first: ?u16 = null;
    var last: ?u16 = null;
    for (model.lists.keys(), model.lists.values()) |translated, list| {
        if (list.items.len == 0) continue;
        first = if (first) |f| @min(f, translated) else translated;
        last = if (last) |l| @max(l, translated) else translated;
    }
    try testing.expectEqual(first == null, tree.first_translated_key() == null);
    if (first) |f| {
        var key: [2]u8 = undefined;
        std.mem.writeInt(u16, &key, f, .big);
        const expected = try values(&tree, &key);
        defer gpa.free(expected);
        try expect_next_values(tree.first_translated_key(), expected);
    }
    if (last) |l| {
        var key: [2]u8 = undefined;
        std.mem.writeInt(u16, &key, l, .big);
        const expected = try values(&tree, &key);
        defer gpa.free(expected);
        try expect_next_values(tree.last_translated_key(), expected);
    }
}

test "fuzz index operations (seeded)" {
    try fuzz_bytes.seeded(1024, 0x696e646578, 128, fuzz_run);
}

test "fuzz index operations" {
    try testing.fuzz({}, fuzz_bytes.smith(1024, fuzz_run), .{});
}

test "ordered short keys partitioned" {
    // P=2 with EightCap on the remainder orders by the same full key as the flat EightCap index.
    const I = partitioned.ordered.Index(translator.EightCap, u64, 2);
    var index = I.init(gpa, .init(.{}));
    defer index.deinit();
    const keys = [_][]const u8{ "\x00\x05", "\x01", "\x02\x09\xab", "\x03", "\xff\xff" };
    for (keys, 0..) |key, rank| try index.insert(key, rank);
    try expect_next_values(index.first_translated_key(), &.{0});
    try expect_next_values(index.last_translated_key(), &.{4});
    const n = keys.len;
    for (keys, 0..) |key, i| {
        try expect_neighbor(index.next_translated_key(key), i + 1 == n, &.{(i + 1) % n});
        try expect_neighbor(index.prev_translated_key(key), i == 0, &.{(i + n - 1) % n});
    }
}

test "partitioned ordered empty and sparse navigation" {
    var index = new(PartitionedOrdered);
    defer index.deinit();
    try testing.expect(index.first_translated_key() == null);
    try testing.expect(index.last_translated_key() == null);
    try testing.expect(index.prev_translated_key(&.{ 0x80, 0x00 }) == null);
    try testing.expect(index.next_translated_key(&.{ 0x80, 0x00 }) == null);
    try index.insert(&.{ 0x05, 0x01 }, 1);
    try index.insert(&.{ 0xf0, 0x02 }, 2);
    try testing.expectEqual(@as(u64, 2), index.keys());
    try expect_next_values(index.first_translated_key(), &.{1});
    try expect_next_values(index.last_translated_key(), &.{2});
    try expect_neighbor(index.next_translated_key(&.{ 0x05, 0x01 }), false, &.{2});
    try expect_neighbor(index.next_translated_key(&.{ 0xf0, 0x02 }), true, &.{1});
    try expect_neighbor(index.prev_translated_key(&.{ 0xf0, 0x02 }), false, &.{1});
    try expect_neighbor(index.prev_translated_key(&.{ 0x05, 0x01 }), true, &.{2});
    try expect_neighbor(index.prev_translated_key(&.{ 0x80, 0x00 }), false, &.{1});
    try expect_neighbor(index.next_translated_key(&.{ 0x80, 0x00 }), false, &.{2});
    index.remove(&.{ 0x05, 0x01 });
    index.remove(&.{ 0xf0, 0x02 });
    try testing.expectEqual(@as(u64, 0), index.keys());
    try testing.expect(index.prev_translated_key(&.{ 0x80, 0x00 }) == null);
    try testing.expect(index.next_translated_key(&.{ 0x80, 0x00 }) == null);
}

test "partitioned ordered values in insertion order" {
    var index = new(PartitionedOrdered);
    defer index.deinit();
    const k1 = "\x0b\x02\xaa";
    const k3 = "\x2d\x06\xee";
    try index.insert(k1, 1);
    try index.insert("\x1c\x04\xcc", 21);
    try index.insert("\x1c\x04\x11", 22);
    try index.insert(k3, 3);
    try testing.expectEqual(@as(u64, 3), index.keys());
    try expect_next_values(index.first_translated_key(), &.{1});
    try expect_next_values(index.last_translated_key(), &.{3});
    try expect_neighbor(index.next_translated_key("\x00"), false, &.{1});
    try expect_neighbor(index.next_translated_key("\x0b\x02\xf2"), false, &.{ 21, 22 });
    try expect_neighbor(index.next_translated_key(k3), true, &.{1});
    try expect_neighbor(index.prev_translated_key(k1), true, &.{3});
    try expect_neighbor(index.prev_translated_key("\x1d\x01\x02"), false, &.{ 21, 22 });
    var basic = new(PartitionedOrdered);
    defer basic.deinit();
    try insert_all(&basic, "duplicate", &.{ 1, 2, 3 });
    try expect_values_ordered(&basic, "duplicate", &.{ 1, 2, 3 });
}

test "partitioned ordered exhaustive traversal" {
    var index = new(PartitionedOrdered);
    defer index.deinit();
    const prefixes = [_]u8{ 0x00, 0x05, 0xaa, 0xff };
    const subkeys = [_]u8{ 0x00, 0x80, 0xff };
    var keys: [prefixes.len * subkeys.len][2]u8 = undefined;
    for (prefixes, 0..) |p, i| {
        for (subkeys, 0..) |s, j| keys[i * subkeys.len + j] = .{ p, s };
    }
    const n = keys.len;
    // Insert scrambled (reversed, then rotated left by 5).
    for (0..n) |i| {
        const key = &keys[n - 1 - (i + 5) % n];
        try index.insert(key, std.mem.readInt(u16, key, .big));
    }
    try testing.expectEqual(@as(u64, n), index.keys());
    for (&keys, 0..) |*key, i| {
        const next_value = std.mem.readInt(u16, &keys[(i + 1) % n], .big);
        try expect_neighbor(index.next_translated_key(key), i + 1 == n, &.{next_value});
        const prev_value = std.mem.readInt(u16, &keys[(i + n - 1) % n], .big);
        try expect_neighbor(index.prev_translated_key(key), i == 0, &.{prev_value});
    }
}

/// commonware's `run_index_cursor_insert_with_next`: inserting while on the last value leaves
/// `next` at the end.
fn run_cursor_insert_on_last(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "key", &.{ 123, 456 });
    const expected = try values(&index, "key");
    defer gpa.free(expected);
    {
        var cursor = index.get_mut("key").?;
        defer cursor.finish();
        try testing.expectEqual(expected[0], cursor.next().?.*);
        try testing.expectEqual(expected[1], cursor.next().?.*);
        try cursor.insert(789);
        try testing.expect(cursor.next() == null);
        try cursor.insert(999);
    }
    try expect_values(&index, "key", &.{ 123, 456, 789, 999 });
}

test "index cursor insert on the last value" {
    inline for (indices) |I| try run_cursor_insert_on_last(I);
}

fn run_delete_in_middle_then_continue(comptime I: type) !void {
    var index = new(I);
    defer index.deinit();
    try insert_all(&index, "key", &.{ 1, 2, 3 });
    const expected = try values(&index, "key");
    defer gpa.free(expected);
    var cursor = index.get_mut("key").?;
    defer cursor.finish();
    try testing.expectEqual(expected[0], cursor.next().?.*);
    try testing.expectEqual(expected[1], cursor.next().?.*);
    cursor.delete();
    try testing.expectEqual(expected[2], cursor.next().?.*);
    try testing.expect(cursor.next() == null);
    try testing.expect(cursor.next() == null);
}

test "index delete in middle then continue" {
    inline for (indices) |I| try run_delete_in_middle_then_continue(I);
}

test "partitioned ordered keeps insertion order through cursor, retain, and get_many" {
    // commonware's `test_soa_basic` and `test_soa_get_many_and_partitions`.
    var index = new(PartitionedOrdered);
    defer index.deinit();
    const key = "duplicate";
    try insert_all(&index, key, &.{ 1, 2, 3 });
    try expect_counters(&index, 1, 3, null);
    try expect_values_ordered(&index, key, &.{ 1, 2, 3 });
    {
        var cursor = index.get_mut(key).?;
        defer cursor.finish();
        for ([_]u64{ 1, 2, 3 }) |value| try testing.expectEqual(value, cursor.next().?.*);
        try testing.expect(cursor.next() == null);
    }
    try insert_all(&index, key, &.{ 3, 4 });
    index.retain(key, @as(u64, 3), not_equal);
    try expect_values_ordered(&index, key, &.{ 1, 2, 4 });
    var other = new(PartitionedOrdered);
    defer other.deinit();
    try insert_all(&other, "ab", &.{ 1, 2 });
    try other.insert("abX", 3);
    try other.insert("zz", 4);
    var visits: Visits = .{};
    defer visits.deinit();
    other.get_many(&.{ "zz", "missing", "ab", "zz" }, &visits, Visits.visit);
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3 }, visits.lists[2].items);
}

test "partitioned ordered get_mut_or_insert" {
    // commonware's `test_spill_get_mut_or_insert`, without the spill (one tree here).
    var index = new(PartitionedOrdered);
    defer index.deinit();
    try index.insert(&.{ 0x10, 0x01 }, 1);
    try index.insert(&.{ 0x10, 0x02 }, 2);
    {
        // An existing key returns a cursor over its values; the passed value is not inserted.
        var cursor = (try index.get_mut_or_insert(&.{ 0x10, 0x01 }, 99)).?;
        defer cursor.finish();
        try testing.expectEqual(@as(u64, 1), cursor.next().?.*);
        try testing.expect(cursor.next() == null);
    }
    try expect_counters(&index, 2, 2, null);
    try expect_values_ordered(&index, &.{ 0x10, 0x01 }, &.{1});
    // An absent key is inserted and returns null.
    try testing.expect(try index.get_mut_or_insert(&.{ 0x10, 0x03 }, 3) == null);
    try expect_counters(&index, 3, 3, null);
    try expect_values_ordered(&index, &.{ 0x10, 0x03 }, &.{3});
}

const ProbeVisits = struct {
    lists: []std.ArrayList(u64),

    fn visit(self: *ProbeVisits, probe: usize, value: *const u64) void {
        self.lists[probe].append(gpa, value.*) catch @panic("out of memory");
    }
};

test "partitioned ordered get_many matches get" {
    // commonware's `test_soa_get_many_matches_get` (its inline case; nothing spills here).
    var index = new(PartitionedOrdered);
    defer index.deinit();
    // Partitions 0..128 hold 32 down to 1 keys; translated keys repeat every 24 entries.
    var value: u64 = 0;
    for (0..128) |partition| {
        for (0..32 - partition % 32) |j| {
            try index.insert(&.{ @intCast(partition), @intCast(j * 7 % 24) }, value);
            value += 1;
        }
    }
    var probes: [1550][2]u8 = undefined;
    for (probes[0..1500], 0..) |*probe, i| {
        const hash = std.mem.toBytes(std.mem.nativeToBig(u64, i *% 0x9e37_79b9_7f4a_7c15));
        probe.* = .{ hash[0], hash[1] % 32 };
    }
    @memcpy(probes[1500..], probes[0..50]);
    var keys: [probes.len][]const u8 = undefined;
    for (&keys, &probes) |*key, *probe| key.* = probe;
    const lists = try gpa.alloc(std.ArrayList(u64), probes.len);
    defer gpa.free(lists);
    @memset(lists, .empty);
    defer for (lists) |*list| list.deinit(gpa);
    var visits: ProbeVisits = .{ .lists = lists };
    index.get_many(&keys, &visits, ProbeVisits.visit);
    var misses: usize = 0;
    var collisions: usize = 0;
    for (&keys, lists) |key, list| {
        try expect_values_ordered(&index, key, list.items);
        misses += @intFromBool(list.items.len == 0);
        collisions += @intFromBool(list.items.len > 1);
    }
    try testing.expect(misses > 0);
    try testing.expect(collisions > 0);
}
