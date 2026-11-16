//! `rand` 0.10's `SliceRandom::shuffle` and `partial_shuffle`: Durstenfeld's Fisher-Yates
//! with `IncreasingUniform`, which draws one `u32` for several swaps.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");

/// `rand`'s `IncreasingUniform`: indices in `[0, n]`, `[0, n + 1]`, ... from batched draws.
fn IncreasingUniform(comptime Rng: type) type {
    return struct {
        rng: Rng,
        n: u32,
        chunk: u32 = 0,
        chunk_remaining: u8,

        const Self = @This();

        fn init(rng: Rng, n: u32) Self {
            return .{ .rng = rng, .n = n, .chunk_remaining = if (n == 0) 1 else 0 };
        }

        fn next_index(chooser: *Self) usize {
            const next_n = chooser.n + 1;
            const next_chunk_remaining = if (chooser.chunk_remaining > 0)
                chooser.chunk_remaining - 1
            else refill: {
                const bound, const remaining = calculate_bound_u32(next_n);
                chooser.chunk = utils.rng.range_less_than(chooser.rng, u32, 0, bound);
                break :refill remaining - 1;
            };
            const result: usize = if (next_chunk_remaining == 0) chooser.chunk else digit: {
                const digit = chooser.chunk % next_n;
                chooser.chunk /= next_n;
                break :digit digit;
            };
            assert(result <= chooser.n);
            chooser.chunk_remaining = next_chunk_remaining;
            chooser.n = next_n;
            return result;
        }
    };
}

/// The product `m * (m + 1) * ...` of as many factors as fit in a `u32`, and their count.
fn calculate_bound_u32(m: u32) struct { u32, u8 } {
    assert(m > 0);
    var product: u32 = m;
    var current: u64 = @as(u64, m) + 1;
    while (current <= std.math.maxInt(u32)) : (current += 1) {
        product = std.math.mul(u32, product, @intCast(current)) catch break;
    }
    const count: u8 = @intCast(current - m);
    assert(count >= 1);
    return .{ product, count };
}

/// Moves `amount` random elements to the end of `items` (fully shuffling it when `amount`
/// covers it) and returns that tail.
pub fn partial_shuffle(comptime T: type, items: []T, rng: anytype, amount: usize) []T {
    const n = items.len -| amount;
    assert(items.len < std.math.maxInt(u32));
    var chooser = IncreasingUniform(@TypeOf(rng)).init(rng, @intCast(n));
    for (n..items.len) |index| {
        const other = chooser.next_index();
        std.mem.swap(T, &items[index], &items[other]);
    }
    return items[n..];
}

pub fn shuffle(comptime T: type, items: []T, rng: anytype) void {
    if (items.len <= 1) return;
    _ = partial_shuffle(T, items, rng, items.len);
}

const testing = std.testing;

test "calculate_bound_u32 packs as many factors as fit" {
    // 2 * 3 * ... * 12 = 479001600 fits; times 13 does not.
    try testing.expectEqual(.{ @as(u32, 479001600), @as(u8, 11) }, calculate_bound_u32(2));
    try testing.expectEqual(.{ @as(u32, 4294967295), @as(u8, 1) }, calculate_bound_u32(4294967295));
}

test "shuffles are permutations and partial shuffles keep the head's elements" {
    var rng = utils.rng.test_rng();
    var items: [50]u32 = undefined;
    for (&items, 0..) |*item, index| item.* = @intCast(index);
    shuffle(u32, &items, &rng);
    var seen: [50]bool = @splat(false);
    var moved = false;
    for (items, 0..) |item, index| {
        seen[item] = true;
        if (item != index) moved = true;
    }
    for (seen) |bit| try testing.expect(bit);
    try testing.expect(moved);
    const tail = partial_shuffle(u32, &items, &rng, 10);
    try testing.expectEqual(@as(usize, 10), tail.len);
    try testing.expect(tail.ptr == items[40..].ptr);
    var one = [_]u32{7};
    shuffle(u32, &one, &rng);
    try testing.expectEqual(@as(u32, 7), one[0]);
}
