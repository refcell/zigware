//! Randomness helpers the runtime needs beyond `utils.rng`.
//!
//! commonware's deterministic executor shuffles its ready queue with rand 0.10's
//! `SliceRandom::shuffle`, drawing from the runtime's `StdRng` (`utils.rng.TestRng` here). To
//! replay a commonware seed with the same task order, `shuffle` consumes the generator exactly
//! as rand does: Fisher-Yates driven by `IncreasingUniform`, which packs several small index
//! draws into one `u32` sample.

const std = @import("std");
const utils = @import("utils");
const assert = std.debug.assert;

/// `slice.shuffle(rng)` from rand 0.10. `rng` is any `utils.rng` generator.
pub fn shuffle(rng: anytype, comptime T: type, items: []T) void {
    if (items.len <= 1) return;
    assert(items.len < std.math.maxInt(u32));
    var chooser: IncreasingUniform = .{ .n = 0, .chunk = 0, .chunk_remaining = 1 };
    for (0..items.len) |i| {
        const index = chooser.next_index(rng);
        assert(index <= i);
        std.mem.swap(T, &items[i], &items[index]);
    }
}

const IncreasingUniform = struct {
    n: u32,
    chunk: u32,
    chunk_remaining: u8,

    fn next_index(self: *IncreasingUniform, rng: anytype) u32 {
        const next_n = self.n + 1;
        var next_chunk_remaining: u8 = undefined;
        if (self.chunk_remaining == 0) {
            const bound, const remaining = calculate_bound(next_n);
            self.chunk = utils.rng.range_less_than(rng, u32, 0, bound);
            next_chunk_remaining = remaining - 1;
        } else {
            next_chunk_remaining = self.chunk_remaining - 1;
        }
        var result: u32 = undefined;
        if (next_chunk_remaining == 0) {
            result = self.chunk;
        } else {
            result = self.chunk % next_n;
            self.chunk /= next_n;
        }
        self.chunk_remaining = next_chunk_remaining;
        self.n = next_n;
        assert(result < next_n);
        return result;
    }

    /// Largest product `m * (m + 1) * ... * (m + count - 1)` that fits in a `u32`.
    fn calculate_bound(m: u32) struct { u32, u8 } {
        assert(m > 0);
        var product: u32 = m;
        var current: u32 = m + 1;
        while (std.math.mul(u32, product, current)) |next_product| {
            product = next_product;
            current += 1;
        } else |_| {}
        const count: u8 = @intCast(current - m);
        assert(count >= 1);
        return .{ product, count };
    }
};

const testing = std.testing;

fn iota(comptime n: usize) [n]u32 {
    var items: [n]u32 = undefined;
    for (&items, 0..) |*item, i| item.* = @intCast(i);
    return items;
}

// Vectors from rand 0.10.2: `StdRng::seed_from_u64(42)`, then three shuffles in a row.
test "shuffle matches rand 0.10" {
    var rng = utils.rng.TestRng.init(42);
    var twenty = iota(20);
    shuffle(&rng, u32, &twenty);
    const want20 = [_]u32{ 17, 16, 13, 2, 1, 5, 15, 14, 19, 0, 18, 6, 8, 3, 7, 10, 11, 12, 9, 4 };
    try testing.expectEqualSlices(u32, &want20, &twenty);
    var three = iota(3);
    shuffle(&rng, u32, &three);
    try testing.expectEqualSlices(u32, &.{ 2, 1, 0 }, &three);
    var many = iota(200);
    shuffle(&rng, u32, &many);
    const want200 = [_]u32{ 82, 138, 74, 1, 172, 69, 131, 150, 167, 2 };
    try testing.expectEqualSlices(u32, &want200, many[0..10]);
}

test "shuffle is a permutation (seeded fuzz)" {
    const build_options = @import("build_options");
    var seeds = utils.rng.TestRng.init(build_options.fuzz_seed);
    const iterations = 500 * @as(usize, build_options.fuzz_soak);
    for (0..iterations) |_| {
        var rng = utils.rng.TestRng.init(seeds.next_u64());
        const len = utils.rng.range_less_than(&seeds, usize, 0, 300);
        var items: [300]u32 = undefined;
        for (items[0..len], 0..) |*item, i| item.* = @intCast(i);
        shuffle(&rng, u32, items[0..len]);
        var seen: [300]bool = @splat(false);
        for (items[0..len]) |item| {
            try testing.expect(item < len);
            try testing.expect(!seen[item]);
            seen[item] = true;
        }
    }
}
