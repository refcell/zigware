//! Shared plumbing for strategies: the inputs a strategy iterates (`Range` and slices), the
//! comptime helpers that read an operation's result types, and the serial bodies that both
//! `Sequential` and each part of a parallel run execute over a contiguous span of the input.
//!
//! Rust closures become operation values: a struct (or a pointer to one) whose `pub` methods
//! are the closures commonware passes. An item of a slice `[]T` is `*T` (`*const T` for
//! `[]const T`), like iterating `&data` or `data.iter_mut()`; an item of a `Range` is its
//! `usize` index, like iterating `0..n`.

const std = @import("std");
const assert = std.debug.assert;

/// A half-open range of indices `start..end`, as an input of strategy operations and as the
/// span of a batch or a tile piece.
pub const Range = struct {
    start: usize,
    end: usize,

    pub fn init(start: usize, end: usize) Range {
        assert(start <= end);
        return .{ .start = start, .end = end };
    }

    /// `0..len`.
    pub fn upto(end: usize) Range {
        return .{ .start = 0, .end = end };
    }

    pub fn len(range: Range) usize {
        assert(range.start <= range.end);
        return range.end - range.start;
    }

    pub fn is_empty(range: Range) bool {
        assert(range.start <= range.end);
        return range.start == range.end;
    }

    pub fn eql(a: Range, b: Range) bool {
        return a.start == b.start and a.end == b.end;
    }
};

/// The item type an input of type `Items` yields.
pub fn Item(comptime Items: type) type {
    if (Items == Range) return usize;
    const info = @typeInfo(Items);
    if (info != .pointer) @compileError("strategy input must be a slice or Range: " ++
        @typeName(Items));
    const pointer = info.pointer;
    switch (pointer.size) {
        .slice => return if (pointer.attrs.@"const") *const pointer.child else *pointer.child,
        .one => {
            const array = @typeInfo(pointer.child);
            if (array != .array) @compileError("strategy input must be a slice or Range");
            const Child = array.array.child;
            return if (pointer.attrs.@"const") *const Child else *Child;
        },
        else => @compileError("strategy input must be a slice or Range: " ++ @typeName(Items)),
    }
}

/// The number of items in `items`.
pub fn count(items: anytype) usize {
    if (@TypeOf(items) == Range) return items.len();
    return items.len;
}

/// The item at `index` of `items`.
pub fn at(items: anytype, index: usize) Item(@TypeOf(items)) {
    assert(index < count(items));
    if (@TypeOf(items) == Range) return items.start + index;
    return &items[index];
}

/// The type behind `Op`, which may be a struct or a pointer to one.
pub fn Base(comptime Op: type) type {
    return switch (@typeInfo(Op)) {
        .pointer => |pointer| pointer.child,
        else => Op,
    };
}

/// The return type of `Op`'s method `name`.
pub fn Return(comptime Op: type, comptime name: []const u8) type {
    const B = Base(Op);
    if (!@hasDecl(B, name)) @compileError(@typeName(B) ++ " lacks method " ++ name);
    return @typeInfo(@TypeOf(@field(B, name))).@"fn".return_type.?;
}

/// The payload of the error union `T`.
pub fn Payload(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .error_union => |union_info| union_info.payload,
        else => @compileError("expected an error union, found " ++ @typeName(T)),
    };
}

/// The error set of the error union `T`.
pub fn ErrorOf(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .error_union => |union_info| union_info.error_set,
        else => @compileError("expected an error union, found " ++ @typeName(T)),
    };
}

/// The two results of a `join`.
pub fn Pair(comptime A: type, comptime B: type) type {
    return struct { A, B };
}

/// The two outputs of `map_partition_collect`: values whose mapping produced one, in input
/// order, and the keys of items whose mapping produced none, in input order. Free both with
/// the allocator that made them.
pub fn Partitioned(comptime K: type, comptime U: type) type {
    return struct {
        const Self = @This();

        results: []U,
        filtered: []K,

        pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
            allocator.free(self.results);
            allocator.free(self.filtered);
        }
    };
}

/// The key type of a `map_partition_collect` operation, whose `map` returns `struct { K, ?U }`.
pub fn PartitionKey(comptime Op: type) type {
    const fields = @typeInfo(Return(Op, "map")).@"struct".field_types;
    comptime assert(fields.len == 2);
    return fields[0];
}

/// The value type of a `map_partition_collect` operation.
pub fn PartitionValue(comptime Op: type) type {
    const fields = @typeInfo(Return(Op, "map")).@"struct".field_types;
    comptime assert(fields.len == 2);
    return @typeInfo(fields[1]).optional.child;
}

/// The most chunks a parallel operation splits its input into. The split depends only on the
/// input's length, never on the number of threads, so a fold or reduction gives the same result
/// on every pool.
pub const max_chunks: usize = 64;

/// The number of chunks an input of `len` items splits into.
pub fn chunk_count(len: usize) usize {
    const chunks = @min(len, max_chunks);
    assert(chunks <= len);
    assert(chunks <= max_chunks);
    return chunks;
}

/// Chunk `index` of `0..len` split into `chunks` ordered chunks whose lengths differ by at
/// most one, the first `len % chunks` one longer (commonware's `Batches::balanced`).
pub fn balanced(len: usize, chunks: usize, index: usize) Range {
    assert(chunks > 0);
    assert(index < chunks);
    const per_chunk = len / chunks;
    const extra = len % chunks;
    const start = index * per_chunk + @min(index, extra);
    const end = start + per_chunk + @intFromBool(index < extra);
    assert(end <= len);
    return .{ .start = start, .end = end };
}

/// Folds `items[start..end]` into a fresh accumulator with `op.identity` and `op.fold`.
pub fn fold_span(
    items: anytype,
    start: usize,
    end: usize,
    op: anytype,
) Return(@TypeOf(op), "identity") {
    assert(start <= end);
    assert(end <= count(items));
    var acc = op.identity();
    for (start..end) |index| acc = op.fold(acc, at(items, index));
    return acc;
}

/// Folds `items[start..end]` with one `op.init` state, `op.identity`, and `op.fold`.
pub fn fold_init_span(
    items: anytype,
    start: usize,
    end: usize,
    op: anytype,
) Return(@TypeOf(op), "identity") {
    assert(start <= end);
    assert(end <= count(items));
    var state = op.init();
    var acc = op.identity();
    for (start..end) |index| acc = op.fold(acc, &state, at(items, index));
    return acc;
}

/// Maps `items[start..end]` into `out[start..end]` with `op.map`.
pub fn map_span(items: anytype, start: usize, end: usize, out: anytype, op: anytype) void {
    assert(start <= end);
    assert(end <= count(items));
    assert(out.len == count(items));
    for (start..end) |index| out[index] = op.map(at(items, index));
}

/// Maps `items[start..end]` into `out[start..end]` with one `op.init` state and `op.map`. When
/// the operation declares `deinit_state(&state)`, the state is released afterwards.
pub fn map_init_span(items: anytype, start: usize, end: usize, out: anytype, op: anytype) void {
    assert(start <= end);
    assert(end <= count(items));
    assert(out.len == count(items));
    var state = op.init();
    defer if (comptime @hasDecl(Base(@TypeOf(op)), "deinit_state")) op.deinit_state(&state);
    for (start..end) |index| out[index] = op.map(&state, at(items, index));
}

test "range and slice inputs yield indices and element pointers" {
    const range = Range.init(3, 7);
    try std.testing.expectEqual(@as(usize, 4), count(range));
    try std.testing.expectEqual(@as(usize, 5), at(range, 2));
    try std.testing.expect(Range.upto(0).is_empty());

    var values = [_]u32{ 10, 20, 30 };
    const slice: []u32 = &values;
    at(slice, 1).* += 1;
    try std.testing.expectEqual(@as(u32, 21), values[1]);
    const constant: []const u32 = &values;
    try std.testing.expectEqual(*const u32, @TypeOf(at(constant, 0)));
    try std.testing.expectEqual(@as(usize, 3), count(&values));
}
