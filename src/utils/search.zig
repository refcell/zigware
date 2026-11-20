//! Binary search: a port of Rust's `slice::binary_search_by` (rust-lang/rust
//! `library/core/src/slice/mod.rs`), which commonware's `binary_search` runs.
//!
//! The loop halves the remaining span without an early exit on a match and picks the next base
//! with a select instead of a branch, so a lookup costs ⌈log2 n⌉ + 1 compares and no
//! mispredicted jumps. `std.sort.binarySearch` branches three ways per step, and on random
//! queries about half of those branches mispredict.

const std = @import("std");
const assert = std.debug.assert;

/// The index of an item that `compare` reports equal to `context`, or null. Same signature as
/// `std.sort.binarySearch`: `compare(context, item)` orders the query against `item`, and
/// `items` must be sorted by it. With duplicates, any of the equal items may be returned.
pub fn binary(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime compare: fn (@TypeOf(context), T) std.math.Order,
) ?usize {
    if (items.len == 0) return null;
    var base: usize = 0;
    var size: usize = items.len;
    // Each pass halves `size`: at most 64 passes.
    while (size > 1) {
        const half = size / 2;
        const middle = base + half;
        // Rust's `select_unpredictable`: step past `middle` unless the query sorts before it.
        const step: usize = @intFromBool(compare(context, items[middle]) != .lt);
        base += half * step;
        size -= half;
    }
    assert(base < items.len);
    return if (compare(context, items[base]) == .eq) base else null;
}

const testing = std.testing;

fn order_u32(query: u32, item: u32) std.math.Order {
    return std.math.order(query, item);
}

fn linear(items: []const u32, query: u32) ?usize {
    for (items, 0..) |item, index| {
        if (item == query) return index;
    }
    return null;
}

test "search: binary agrees with a linear scan" {
    var values: [300]u32 = undefined;
    var prng = std.Random.DefaultPrng.init(0x5ea4c4);
    const random = prng.random();
    for (0..values.len + 1) |len| {
        const items = values[0..len];
        // Odd values with runs of duplicates, so every even query misses between items.
        for (items) |*item| item.* = random.uintLessThan(u32, 64) * 2 + 1;
        std.mem.sort(u32, items, {}, std.sort.asc(u32));
        for (0..132) |query_index| {
            const query: u32 = @intCast(query_index);
            const found = binary(u32, items, query, order_u32);
            if (linear(items, query) == null) {
                try testing.expectEqual(@as(?usize, null), found);
            } else {
                try testing.expectEqual(query, items[found.?]);
            }
        }
    }
}

test "search: binary at the ends of distinct items" {
    const items = [_]u32{ 2, 4, 6, 8, 10, 12, 14 };
    for (items, 0..) |item, index| {
        try testing.expectEqual(@as(?usize, index), binary(u32, &items, item, order_u32));
        try testing.expectEqual(@as(?usize, null), binary(u32, &items, item + 1, order_u32));
    }
    try testing.expectEqual(@as(?usize, null), binary(u32, &items, @as(u32, 0), order_u32));
    try testing.expectEqual(@as(?usize, null), binary(u32, items[0..0], @as(u32, 2), order_u32));
}
