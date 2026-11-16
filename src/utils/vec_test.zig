//! Tests for `vec` (commonware `utils/src/vec.rs`). Rust's `should_panic` cases
//! (`from_unchecked` and `mutate` on empty) are panics here and are not run.

const std = @import("std");
const codec = @import("codec");
const vec = @import("vec.zig");
const testing = std.testing;
const gpa = testing.allocator;
const expectEqual = testing.expectEqual;
const expectEqualSlices = testing.expectEqualSlices;
const NonEmptyVec = vec.NonEmptyVec;

fn collect(bounded: *const vec.Bounded(i32)) ![]i32 {
    var out: std.ArrayList(i32) = .empty;
    errdefer out.deinit(gpa);
    var iterator = bounded.iterator();
    while (iterator.next()) |value| try out.append(gpa, value);
    return out.toOwnedSlice(gpa);
}

test "vec: bounded push evicts the oldest" {
    var deque = try vec.Bounded(i32).init(gpa, 3);
    defer deque.deinit(gpa);
    try expectEqual(null, deque.push(1));
    try expectEqual(null, deque.push(2));
    try expectEqual(null, deque.push(3));
    try expectEqual(@as(?i32, 1), deque.push(4));
    try expectEqual(3, deque.capacity());
    const items = try collect(&deque);
    defer gpa.free(items);
    try expectEqualSlices(i32, &.{ 2, 3, 4 }, items);
}

test "vec: bounded pop_front reuses capacity" {
    var deque = try vec.Bounded(i32).init(gpa, 2);
    defer deque.deinit(gpa);
    try expectEqual(null, deque.push(1));
    try expectEqual(null, deque.push(2));
    try expectEqual(@as(?i32, 1), deque.pop_front());
    try expectEqual(null, deque.push(3));
    const items = try collect(&deque);
    defer gpa.free(items);
    try expectEqualSlices(i32, &.{ 2, 3 }, items);
}

test "vec: bounded into_inner" {
    var deque = try vec.Bounded(i32).init(gpa, 2);
    _ = deque.push(1);
    _ = deque.push(2);
    var inner = deque.into_inner();
    defer inner.deinit(gpa);
    try expectEqual(@as(?i32, 1), inner.popFront());
    try expectEqual(@as(?i32, 2), inner.popFront());
    try expectEqual(null, inner.popFront());
}

test "vec: new, singleton, first and last" {
    var single = try NonEmptyVec(i32).init(gpa, 42);
    defer single.deinit(gpa);
    try expectEqual(1, single.len());
    try expectEqual(42, single.first().*);
    try expectEqual(42, single.last().*);
    try testing.expect(single.is_singleton());

    var pair = try NonEmptyVec(i32).from_slice(gpa, &.{ 1, 2 });
    defer pair.deinit(gpa);
    try testing.expect(!pair.is_singleton());

    var three = try NonEmptyVec(i32).from_slice(gpa, &.{ 1, 2, 3 });
    defer three.deinit(gpa);
    try testing.expect(!three.is_singleton());
    try expectEqual(1, three.first().*);
    try expectEqual(3, three.last().*);
    three.first_mut().* = 10;
    three.last_mut().* = 30;
    try expectEqualSlices(i32, &.{ 10, 2, 30 }, three.items());
}

test "vec: macro forms" {
    var repeated = try NonEmptyVec(i32).repeat(gpa, 42, 5);
    defer repeated.deinit(gpa);
    try expectEqualSlices(i32, &.{ 42, 42, 42, 42, 42 }, repeated.items());

    var one = try NonEmptyVec(i32).repeat(gpa, 0, 1);
    defer one.deinit(gpa);
    try expectEqualSlices(i32, &.{0}, one.items());

    var list: std.ArrayList(i32) = .empty;
    try list.appendSlice(gpa, &.{ 1, 2, 3 });
    var wrapped = NonEmptyVec(i32).from_unchecked(list);
    defer wrapped.deinit(gpa);
    try expectEqualSlices(i32, &.{ 1, 2, 3 }, wrapped.items());
}

test "vec: try_from rejects empty collections" {
    var list: std.ArrayList(i32) = .empty;
    try testing.expectError(error.Empty, NonEmptyVec(i32).from_list(list));
    try list.appendSlice(gpa, &.{ 1, 2, 3 });
    var from_list = try NonEmptyVec(i32).from_list(list);
    defer from_list.deinit(gpa);
    try expectEqual(3, from_list.len());
    try testing.expectError(error.Empty, NonEmptyVec(i32).from_slice(gpa, &.{}));
}

test "vec: push, insert, and extend" {
    var v = try NonEmptyVec(i32).init(gpa, 1);
    defer v.deinit(gpa);
    try v.push(gpa, 3);
    try v.insert(gpa, 1, 2);
    try expectEqualSlices(i32, &.{ 1, 2, 3 }, v.items());
    try v.extend(gpa, &.{ 4, 5 });
    try expectEqualSlices(i32, &.{ 1, 2, 3, 4, 5 }, v.items());
}

const Counter = struct {
    count: *i32,

    pub fn make(counter: Counter) i32 {
        counter.count.* += 1;
        return counter.count.* * 10;
    }
};

const Never = struct {
    pub fn make(_: Never) i32 {
        @panic("the factory must not be called");
    }
};

test "vec: resize and resize_with" {
    var v = try NonEmptyVec(i32).from_slice(gpa, &.{ 1, 2 });
    defer v.deinit(gpa);
    try v.resize(gpa, 5, 0);
    try expectEqualSlices(i32, &.{ 1, 2, 0, 0, 0 }, v.items());
    try v.resize(gpa, 2, 0);
    try expectEqualSlices(i32, &.{ 1, 2 }, v.items());
    try v.resize(gpa, 1, 0);
    try expectEqualSlices(i32, &.{1}, v.items());

    var count: i32 = 0;
    try v.resize_with(gpa, 4, Counter{ .count = &count });
    try expectEqualSlices(i32, &.{ 1, 10, 20, 30 }, v.items());
    try v.resize_with(gpa, 2, Never{});
    try expectEqualSlices(i32, &.{ 1, 10 }, v.items());
}

test "vec: pop and remove keep one item" {
    var v = try NonEmptyVec(i32).from_slice(gpa, &.{ 1, 2, 3 });
    defer v.deinit(gpa);
    try expectEqual(@as(?i32, 3), v.pop());
    try expectEqual(@as(?i32, 2), v.pop());
    try expectEqual(null, v.pop());
    try expectEqualSlices(i32, &.{1}, v.items());

    var w = try NonEmptyVec(i32).from_slice(gpa, &.{ 1, 2, 3 });
    defer w.deinit(gpa);
    try expectEqual(@as(?i32, 2), w.remove(1));
    try expectEqualSlices(i32, &.{ 1, 3 }, w.items());
    try expectEqual(@as(?i32, 1), w.remove(0));
    try expectEqual(null, w.remove(0));
    try expectEqualSlices(i32, &.{3}, w.items());
}

fn sort_dedup(_: void, list: *std.ArrayList(i32)) void {
    std.mem.sort(i32, list.items, {}, std.sort.asc(i32));
    var kept: usize = 1;
    for (list.items[1..]) |value| {
        if (value == list.items[kept - 1]) continue;
        list.items[kept] = value;
        kept += 1;
    }
    list.shrinkRetainingCapacity(kept);
}

fn sum(_: void, list: *std.ArrayList(i32)) i32 {
    var total: i32 = 0;
    for (list.items) |value| total += value;
    return total;
}

test "vec: mutate returns the operation's result" {
    var v = try NonEmptyVec(i32).from_slice(gpa, &.{ 3, 1, 2, 1 });
    defer v.deinit(gpa);
    v.mutate({}, sort_dedup);
    try expectEqualSlices(i32, &.{ 1, 2, 3 }, v.items());
    try expectEqual(6, v.mutate({}, sum));
}

fn double(_: void, value: *const i32) i32 {
    return value.* * 2;
}

fn double_owned(_: void, value: i32) i64 {
    return value * 2;
}

test "vec: slice access, map, map_into, and into_list" {
    var v = try NonEmptyVec(i32).from_slice(gpa, &.{ 3, 1, 2 });
    defer v.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(i32, v.items(), 2) != null);
    try expectEqual(1, v.items()[1]);
    std.mem.sort(i32, v.items(), {}, std.sort.asc(i32));
    try expectEqualSlices(i32, &.{ 1, 2, 3 }, v.items());
    std.mem.reverse(i32, v.items());
    try expectEqualSlices(i32, &.{ 3, 2, 1 }, v.items());
    v.items()[1..3].* = .{ 20, 10 };
    try expectEqualSlices(i32, &.{ 3, 20, 10 }, v.items());

    var doubled = try v.map(gpa, i32, {}, double);
    defer doubled.deinit(gpa);
    try expectEqualSlices(i32, &.{ 6, 40, 20 }, doubled.items());
    try expectEqualSlices(i32, &.{ 3, 20, 10 }, v.items());

    var moved = try NonEmptyVec(i32).from_slice(gpa, doubled.items());
    var widened = try moved.map_into(gpa, i64, {}, double_owned);
    defer widened.deinit(gpa);
    try expectEqualSlices(i64, &.{ 12, 80, 40 }, widened.items());

    var owned = try NonEmptyVec(i32).from_slice(gpa, &.{ 1, 2, 3 });
    var list = owned.into_list();
    defer list.deinit(gpa);
    try expectEqualSlices(i32, &.{ 1, 2, 3 }, list.items);
}

test "vec: order is lexicographic" {
    var a = try NonEmptyVec(u8).from_slice(gpa, &.{ 1, 2 });
    defer a.deinit(gpa);
    var b = try NonEmptyVec(u8).from_slice(gpa, &.{ 1, 2, 0 });
    defer b.deinit(gpa);
    var c = try NonEmptyVec(u8).from_slice(gpa, &.{2});
    defer c.deinit(gpa);
    try expectEqual(.lt, a.order(b));
    try expectEqual(.lt, b.order(c));
    try testing.expect(a.eql(a) and !a.eql(b));
}

test "vec: codec round trip" {
    var v = try NonEmptyVec(u8).from_slice(gpa, &.{ 1, 2, 3 });
    defer v.deinit(gpa);
    const bytes = try codec.encode(NonEmptyVec(u8), gpa, v);
    defer gpa.free(bytes);
    // Byte-identical to `Vec<u8>`.
    try expectEqualSlices(u8, &.{ 3, 1, 2, 3 }, bytes);
    const cfg: NonEmptyVec(u8).Cfg = .{ .range = .inclusive(1, 10) };
    var decoded = try codec.decode_cfg(NonEmptyVec(u8), gpa, bytes, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(v.eql(decoded));
}

test "vec: codec rejects an empty vector" {
    const empty = [_]u8{0};
    const Vec = NonEmptyVec(u8);
    try testing.expectError(error.Invalid, codec.decode_cfg(Vec, gpa, &empty, .{
        .range = .full(),
    }));
    try testing.expectError(error.Invalid, codec.decode_cfg(Vec, gpa, &empty, .{
        .range = .to(10),
    }));
    try testing.expectError(error.InvalidLength, codec.decode_cfg(Vec, gpa, &empty, .{
        .range = .range(1, 10),
    }));
}

test "vec: items are released on resize and deinit" {
    const Bytes = []const u8;
    var v = try NonEmptyVec(Bytes).init(gpa, try gpa.dupe(u8, "first"));
    defer v.deinit(gpa);
    try v.push(gpa, try gpa.dupe(u8, "second"));
    try v.push(gpa, try gpa.dupe(u8, "third"));
    try v.resize(gpa, 1, &.{});
    try testing.expectEqualStrings("first", v.first().*);
}

test "vec: arbitrary is never empty" {
    for (0..32) |seed| {
        var stream = codec.arbitrary.Keystream.init(seed, 64);
        var u = codec.arbitrary.Unstructured.init(&stream);
        var v = try NonEmptyVec(u16).arbitrary(gpa, &u);
        defer v.deinit(gpa);
        try testing.expect(v.len() >= 1);
    }
}
