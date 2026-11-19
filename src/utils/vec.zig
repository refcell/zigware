//! Vector-backed collections with additional invariants (commonware `utils/src/vec.rs`).
//!
//! `Bounded(T)` keeps at most `capacity` items and evicts the oldest on overflow; its storage is
//! allocated once at `init`. `NonEmptyVec(T)` always holds at least one item and encodes exactly
//! like `Vec<T>`. Rust's `non_empty_vec!` forms are `from_slice` (list and `@vec`) and
//! `repeat` (`elem; N`).
//!
//! A `NonEmptyVec` owns its items: items dropped by `resize`, and every item on `deinit`, are
//! released with their `deinit(gpa)` decl, or `codec.free` when they own memory.

const std = @import("std");
const codec = @import("codec");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// The collection was empty.
pub const Error = error{Empty};

pub fn Bounded(comptime T: type) type {
    return struct {
        const Self = @This();

        deque: std.Deque(T),
        capacity_max: usize,

        /// An empty deque that retains at most `capacity` items (> 0).
        pub fn init(gpa: Allocator, capacity_max: usize) Allocator.Error!Self {
            assert(capacity_max > 0);
            const deque: std.Deque(T) = try .initCapacity(gpa, capacity_max);
            return .{ .deque = deque, .capacity_max = capacity_max };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.deque.deinit(gpa);
            self.* = undefined;
        }

        /// The maximum number of items retained.
        pub fn capacity(self: *const Self) usize {
            return self.capacity_max;
        }

        pub fn len(self: *const Self) usize {
            assert(self.deque.len <= self.capacity_max);
            return self.deque.len;
        }

        /// Pushes `value` at the back, returning the oldest item if it was evicted.
        pub fn push(self: *Self, value: T) ?T {
            assert(self.deque.len <= self.capacity_max);
            const full = self.deque.len == self.capacity_max;
            const evicted = if (full) self.deque.popFront() else null;
            self.deque.pushBackAssumeCapacity(value);
            assert(self.deque.len <= self.capacity_max);
            return evicted;
        }

        /// Removes the oldest item.
        pub fn pop_front(self: *Self) ?T {
            return self.deque.popFront();
        }

        /// The item `index` positions from the oldest.
        pub fn at(self: *const Self, index: usize) T {
            assert(index < self.deque.len);
            return self.deque.at(index);
        }

        /// Items from oldest to newest.
        pub fn iterator(self: *const Self) std.Deque(T).Iterator {
            return self.deque.iterator();
        }

        /// The underlying deque; the caller owns it.
        pub fn into_inner(self: *Self) std.Deque(T) {
            const deque = self.deque;
            self.* = undefined;
            return deque;
        }
    };
}

fn has_decl(comptime T: type, comptime name: []const u8) bool {
    return switch (@typeInfo(T)) {
        .@"struct" => |info| !info.is_tuple and @hasDecl(T, name),
        .@"union", .@"enum", .@"opaque" => @hasDecl(T, name),
        else => false,
    };
}

fn release_items(comptime T: type, gpa: Allocator, items: []T) void {
    if (comptime has_decl(T, "deinit")) {
        for (items) |*item| item.deinit(gpa);
    } else if (comptime codec.owns_memory(T)) {
        for (items) |item| codec.free(T, gpa, item);
    }
}

pub fn NonEmptyVec(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Never empty.
        list: std.ArrayList(T),

        /// Rust `(RangeCfg<NonZeroUsize>, T::Cfg)`: a range admitting zero still rejects an
        /// empty vector as `Invalid`.
        pub const Cfg = codec.SliceCfg(codec.Cfg(T));
        pub const Item = T;

        /// A vector holding only `first` (Rust `new`).
        pub fn init(gpa: Allocator, value: T) Allocator.Error!Self {
            var list = try std.ArrayList(T).initCapacity(gpa, 1);
            list.appendAssumeCapacity(value);
            return .{ .list = list };
        }

        /// Wraps `list`, which must not be empty (Rust `from_unchecked`).
        pub fn from_unchecked(list: std.ArrayList(T)) Self {
            if (list.items.len == 0) @panic("NonEmptyVec.from_unchecked: vector is empty");
            return .{ .list = list };
        }

        /// Wraps `list`, or fails if it is empty (Rust `TryFrom<Vec<T>>`).
        pub fn from_list(list: std.ArrayList(T)) Error!Self {
            if (list.items.len == 0) return error.Empty;
            return .{ .list = list };
        }

        /// Copies `items` (Rust `TryFrom<&[T]>` and `non_empty_vec![a, b, c]`).
        pub fn from_slice(gpa: Allocator, values: []const T) (Error || Allocator.Error)!Self {
            if (values.len == 0) return error.Empty;
            var list: std.ArrayList(T) = .empty;
            try list.appendSlice(gpa, values);
            assert(list.items.len == values.len);
            return .{ .list = list };
        }

        /// `count` copies of `value` (Rust `non_empty_vec![value; count]`); `count` > 0.
        pub fn repeat(gpa: Allocator, value: T, count: usize) Allocator.Error!Self {
            if (count == 0) @panic("NonEmptyVec.repeat: count must be greater than 0");
            var list: std.ArrayList(T) = .empty;
            try list.appendNTimes(gpa, value, count);
            return .{ .list = list };
        }

        /// Releases the items and the list.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            release_items(T, gpa, self.list.items);
            self.list.deinit(gpa);
            self.* = undefined;
        }

        /// The number of items, at least one.
        pub fn len(self: *const Self) usize {
            assert(self.list.items.len > 0);
            return self.list.items.len;
        }

        /// Whether the vector holds exactly one item.
        pub fn is_singleton(self: *const Self) bool {
            return self.len() == 1;
        }

        /// The items (Rust `Deref<Target = [T]>`).
        pub fn items(self: *const Self) []T {
            assert(self.list.items.len > 0);
            return self.list.items;
        }

        pub fn first(self: *const Self) *const T {
            return &self.items()[0];
        }

        pub fn first_mut(self: *Self) *T {
            return &self.items()[0];
        }

        pub fn last(self: *const Self) *const T {
            return &self.items()[self.len() - 1];
        }

        pub fn last_mut(self: *Self) *T {
            return &self.items()[self.len() - 1];
        }

        /// A new vector of `transform(context, *const T)` for each item.
        pub fn map(
            self: *const Self,
            gpa: Allocator,
            comptime U: type,
            context: anytype,
            comptime transform: anytype,
        ) Allocator.Error!NonEmptyVec(U) {
            var list = try std.ArrayList(U).initCapacity(gpa, self.len());
            for (self.items()) |*item| list.appendAssumeCapacity(transform(context, item));
            assert(list.items.len == self.len());
            return .{ .list = list };
        }

        /// Moves every item through `transform(context, T)`; on success `self` is consumed.
        pub fn map_into(
            self: *Self,
            gpa: Allocator,
            comptime U: type,
            context: anytype,
            comptime transform: anytype,
        ) Allocator.Error!NonEmptyVec(U) {
            var list = try std.ArrayList(U).initCapacity(gpa, self.len());
            for (self.items()) |item| list.appendAssumeCapacity(transform(context, item));
            assert(list.items.len == self.len());
            self.list.deinit(gpa);
            self.* = undefined;
            return .{ .list = list };
        }

        pub fn push(self: *Self, gpa: Allocator, value: T) Allocator.Error!void {
            try self.list.append(gpa, value);
        }

        /// Inserts `value` at `index` (≤ len).
        pub fn insert(self: *Self, gpa: Allocator, index: usize, value: T) Allocator.Error!void {
            assert(index <= self.len());
            try self.list.insert(gpa, index, value);
        }

        pub fn extend(self: *Self, gpa: Allocator, values: []const T) Allocator.Error!void {
            try self.list.appendSlice(gpa, values);
        }

        /// Truncates to `new_len` (> 0), releasing dropped items, or extends with copies of
        /// `value`.
        pub fn resize(self: *Self, gpa: Allocator, new_len: usize, value: T) Allocator.Error!void {
            assert(new_len > 0);
            if (new_len <= self.len()) return self.truncate(gpa, new_len);
            try self.list.appendNTimes(gpa, value, new_len - self.len());
            assert(self.len() == new_len);
        }

        /// Truncates to `new_len` (> 0), releasing dropped items, or extends with
        /// `factory.make()` values in order.
        pub fn resize_with(
            self: *Self,
            gpa: Allocator,
            new_len: usize,
            factory: anytype,
        ) Allocator.Error!void {
            assert(new_len > 0);
            if (new_len <= self.len()) return self.truncate(gpa, new_len);
            try self.list.ensureTotalCapacity(gpa, new_len);
            while (self.len() < new_len) self.list.appendAssumeCapacity(factory.make());
            assert(self.len() == new_len);
        }

        fn truncate(self: *Self, gpa: Allocator, new_len: usize) void {
            assert(new_len > 0 and new_len <= self.len());
            release_items(T, gpa, self.list.items[new_len..]);
            self.list.shrinkRetainingCapacity(new_len);
        }

        /// Removes the last item, unless it is the only one.
        pub fn pop(self: *Self) ?T {
            if (self.len() == 1) return null;
            return self.list.pop();
        }

        /// Removes the item at `index` (< len), unless it is the only one.
        pub fn remove(self: *Self, index: usize) ?T {
            if (index >= self.len()) @panic("index out of bounds");
            if (self.len() == 1) return null;
            return self.list.orderedRemove(index);
        }

        /// Runs `operation(context, *std.ArrayList(T))` on the underlying list and returns its
        /// result; panics if the list is left empty.
        pub fn mutate(
            self: *Self,
            context: anytype,
            comptime operation: anytype,
        ) @typeInfo(@TypeOf(operation)).@"fn".return_type.? {
            const result = operation(context, &self.list);
            if (self.list.items.len == 0) @panic("NonEmptyVec.mutate: closure left vector empty");
            return result;
        }

        /// The underlying list; the caller owns it and its items.
        pub fn into_list(self: *Self) std.ArrayList(T) {
            const list = self.list;
            self.* = undefined;
            return list;
        }

        pub fn eql(a: Self, b: Self) bool {
            return codec.order_items(T, a.list.items, b.list.items) == .eq;
        }

        /// Lexicographic, like Rust's derived `Ord`.
        pub fn order(a: Self, b: Self) std.math.Order {
            return codec.order_items(T, a.list.items, b.list.items);
        }

        // Codec: identical to `Vec<T>`.

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write([]const T, self.items(), writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size([]const T, self.items());
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const count = try codec.read_usize(reader, cfg.range);
            if (count == 0) return reader.invalid("NonEmptyVec", "cannot decode empty vector");
            const decoded = try codec.read_items(T, gpa, reader, count, cfg.item);
            assert(decoded.len == count);
            return .{ .list = .fromOwnedSlice(decoded) };
        }

        /// commonware's `Arbitrary`: one item, then an arbitrary `Vec<T>` of the rest.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const head = try codec.arbitrary.value(T, gpa, u);
            const rest = codec.arbitrary.collect(T, gpa, u) catch |err| {
                var copy = [1]T{head};
                release_items(T, gpa, &copy);
                return err;
            };
            var list: std.ArrayList(T) = .fromOwnedSlice(rest);
            list.insert(gpa, 0, head) catch |err| {
                var copy = [1]T{head};
                release_items(T, gpa, &copy);
                release_items(T, gpa, list.items);
                list.deinit(gpa);
                return err;
            };
            return .{ .list = list };
        }
    };
}

test {
    _ = @import("vec_test.zig");
}

const death = @import("death.zig");

test "vec: from_unchecked panics on an empty list" {
    // commonware `vec.rs test_from_unchecked_panics_on_empty` (#[should_panic]).
    try death.expect_panic(@src(), "vector is empty", struct {
        fn body() !void {
            const list: std.ArrayList(i32) = .empty;
            _ = NonEmptyVec(i32).from_unchecked(list);
        }
    }.body);
}

test "vec: mutate panics when the closure empties it" {
    // commonware `vec.rs test_mutate_panics_on_empty` (#[should_panic]).
    try death.expect_panic(@src(), "closure left vector empty", struct {
        fn body() !void {
            const gpa = std.testing.allocator;
            var v = try NonEmptyVec(i32).init(gpa, 1);
            defer v.deinit(gpa);
            v.mutate({}, struct {
                fn clear(_: void, list: *std.ArrayList(i32)) void {
                    list.clearRetainingCapacity();
                }
            }.clear);
        }
    }.body);
}
