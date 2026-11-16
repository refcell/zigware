//! Iterator types with additional invariants (commonware `utils/src/iter.rs`).
//!
//! An iterator is any type with `next(*Self) ?Item`. Rust's `non_empty![a, b]` is `NonEmpty.init`
//! with a rest iterator, and `non_empty![@items]` is `NonEmpty.try_init(...).?`.

const std = @import("std");
const assert = std.debug.assert;

/// The item type of iterator `I` (the child of `I.next`'s optional result).
pub fn Item(comptime I: type) type {
    const Return = @typeInfo(@TypeOf(I.next)).@"fn".return_type.?;
    return @typeInfo(Return).optional.child;
}

/// An iterator source guaranteed to yield at least one item.
pub fn NonEmpty(comptime I: type) type {
    return struct {
        const Self = @This();

        first: Item(I),
        rest: I,
        /// Whether `first` was yielded.
        started: bool = false,

        /// A non-empty iterator of `first` followed by `rest`.
        pub fn init(first: Item(I), rest: I) Self {
            return .{ .first = first, .rest = rest };
        }

        /// A non-empty iterator over `items`, or null when it is empty.
        pub fn try_init(items: I) ?Self {
            var rest = items;
            const first = rest.next() orelse return null;
            return init(first, rest);
        }

        /// The first item and the remaining iterator.
        pub fn into_parts(self: Self) struct { Item(I), I } {
            assert(!self.started);
            return .{ self.first, self.rest };
        }

        /// The first item, then the rest.
        pub fn next(self: *Self) ?Item(I) {
            if (self.started) return self.rest.next();
            self.started = true;
            return self.first;
        }
    };
}

/// Zips two iterators, panicking if one ends before the other (Rust `zip_eq`). Unlike a plain
/// zip, unequal lengths are never silently truncated.
pub fn zip_eq(a: anytype, b: anytype) ZipEq(@TypeOf(a), @TypeOf(b)) {
    return .{ .a = a, .b = b };
}

pub fn ZipEq(comptime A: type, comptime B: type) type {
    return struct {
        const Self = @This();

        a: A,
        b: B,

        pub const Pair = struct { Item(A), Item(B) };

        pub fn next(self: *Self) ?Pair {
            const left = self.a.next();
            const right = self.b.next();
            if (left == null and right == null) return null;
            if (right == null) @panic("zip_eq: right iterator exhausted first");
            if (left == null) @panic("zip_eq: left iterator exhausted first");
            return .{ left.?, right.? };
        }
    };
}

/// An iterator over a slice's items (a convenience for `NonEmpty` and `zip_eq`).
pub fn SliceIterator(comptime T: type) type {
    return struct {
        items: []const T,
        index: usize = 0,

        pub fn next(self: *@This()) ?T {
            assert(self.index <= self.items.len);
            if (self.index == self.items.len) return null;
            defer self.index += 1;
            return self.items[self.index];
        }
    };
}

pub fn slice(comptime T: type, items: []const T) SliceIterator(T) {
    return .{ .items = items };
}

const testing = std.testing;

fn drain(iterator: anytype, out: []i32) ![]i32 {
    var count: usize = 0;
    while (iterator.next()) |value| : (count += 1) {
        try testing.expect(count < out.len);
        out[count] = value;
    }
    return out[0..count];
}

test "iter: try_init rejects empty" {
    try testing.expectEqual(null, NonEmpty(SliceIterator(u8)).try_init(slice(u8, &.{})));
}

test "iter: iteration preserves every item" {
    var items = NonEmpty(SliceIterator(i32)).try_init(slice(i32, &.{ 1, 2, 3 })).?;
    var buffer: [8]i32 = undefined;
    try testing.expectEqualSlices(i32, &.{ 1, 2, 3 }, try drain(&items, &buffer));
}

test "iter: into_parts separates first from rest" {
    const items = NonEmpty(SliceIterator(i32)).init(1, slice(i32, &.{ 2, 3 }));
    const first, var rest = items.into_parts();
    try testing.expectEqual(1, first);
    var buffer: [8]i32 = undefined;
    try testing.expectEqualSlices(i32, &.{ 2, 3 }, try drain(&rest, &buffer));
}

test "iter: the macro forms construct non-empty iterators" {
    var buffer: [8]i32 = undefined;
    var single = NonEmpty(SliceIterator(i32)).init(1, slice(i32, &.{}));
    try testing.expectEqualSlices(i32, &.{1}, try drain(&single, &buffer));
    var many = NonEmpty(SliceIterator(i32)).init(1, slice(i32, &.{ 2, 3 }));
    try testing.expectEqualSlices(i32, &.{ 1, 2, 3 }, try drain(&many, &buffer));
}

test "iter: zip_eq pairs equal lengths" {
    var pairs = zip_eq(slice(i32, &.{ 1, 2, 3 }), slice(u8, "abc"));
    for ([_]i32{ 1, 2, 3 }, "abc") |left, right| {
        const pair = pairs.next().?;
        try testing.expectEqual(left, pair[0]);
        try testing.expectEqual(right, pair[1]);
    }
    try testing.expectEqual(null, pairs.next());
}
