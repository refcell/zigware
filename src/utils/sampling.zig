//! Random sampling with weights (commonware `utils/src/sampling.rs`).
//!
//! `WeightedIndex` keeps weights at fixed indices in a Fenwick tree, supporting proportional and
//! uniform draws and weight updates in `O(log n)`. Zero-weight entries are never sampled. Draws
//! use only integer arithmetic and `rng.range_less_than` (rand's `random_range`), so the same
//! weights and random stream give the same indices as commonware.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const rng_mod = @import("rng.zig");

pub const WeightedIndex = struct {
    /// Weights in index order.
    weights: []u64,
    /// Fenwick tree: entry `i` holds the sum of `weights[i & (i + 1)..=i]`.
    tree: []u128,
    /// Number of positive weights in each Fenwick entry's range.
    counts: []u64,
    /// Sum of all weights.
    total_weight: u128,
    /// Number of positive weights.
    positive: u64,

    pub const empty: WeightedIndex = .{
        .weights = &.{},
        .tree = &.{},
        .counts = &.{},
        .total_weight = 0,
        .positive = 0,
    };

    /// Builds an index over `weights` (copied), preserving their order.
    pub fn init(gpa: Allocator, weights: []const u64) Allocator.Error!WeightedIndex {
        const owned = try gpa.dupe(u64, weights);
        errdefer gpa.free(owned);
        const tree = try gpa.alloc(u128, weights.len);
        errdefer gpa.free(tree);
        const counts = try gpa.alloc(u64, weights.len);
        var sum: u128 = 0;
        var positive: u64 = 0;
        for (weights, tree, counts) |value, *node, *count| {
            node.* = value;
            count.* = @intFromBool(value != 0);
            sum += value;
            positive += count.*;
        }
        // Each entry's range lies inside its parent's, so one forward pass builds the tree.
        for (0..tree.len) |index| {
            const parent = index | (index + 1);
            if (parent < tree.len) {
                tree[parent] += tree[index];
                counts[parent] += counts[index];
            }
        }
        return .{
            .weights = owned,
            .tree = tree,
            .counts = counts,
            .total_weight = sum,
            .positive = positive,
        };
    }

    pub fn deinit(self: *WeightedIndex, gpa: Allocator) void {
        gpa.free(self.weights);
        gpa.free(self.tree);
        gpa.free(self.counts);
        self.* = undefined;
    }

    pub fn len(self: *const WeightedIndex) usize {
        return self.weights.len;
    }

    /// The sum of all weights.
    pub fn total(self: *const WeightedIndex) u128 {
        return self.total_weight;
    }

    /// The number of positive weights.
    pub fn positive_count(self: *const WeightedIndex) u64 {
        return self.positive;
    }

    pub fn weight(self: *const WeightedIndex, index: usize) u64 {
        return self.weights[index];
    }

    /// Replaces the weight at `index`, returning its previous value.
    pub fn set(self: *WeightedIndex, index: usize, new_weight: u64) u64 {
        assert(index < self.weights.len);
        const previous = self.weights[index];
        if (new_weight == previous) return previous;
        self.weights[index] = new_weight;
        // Every Fenwick entry whose range contains `index` trades the old weight for the new.
        const old: u128 = previous;
        const new: u128 = new_weight;
        const was_positive: u64 = @intFromBool(previous != 0);
        const is_positive: u64 = @intFromBool(new_weight != 0);
        self.total_weight = self.total_weight - old + new;
        self.positive = self.positive - was_positive + is_positive;
        var node = index;
        while (node < self.tree.len) : (node |= node + 1) {
            self.tree[node] = self.tree[node] - old + new;
            self.counts[node] = self.counts[node] - was_positive + is_positive;
        }
        return previous;
    }

    /// Draws an index with probability proportional to its weight; null (without consuming
    /// randomness) when the total weight is zero.
    pub fn sample(self: *const WeightedIndex, rng: anytype) ?usize {
        if (self.total_weight == 0) return null;
        return self.locate(false, rng_mod.range_less_than(rng, u128, 0, self.total_weight));
    }

    /// Draws uniformly from the indices with positive weight; null (without consuming
    /// randomness) when all weights are zero.
    pub fn sample_uniform(self: *const WeightedIndex, rng: anytype) ?usize {
        if (self.positive == 0) return null;
        return self.locate(true, rng_mod.range_less_than(rng, u128, 0, self.positive));
    }

    /// Draws that choose each positive-weight index at most once; `deinit` restores every
    /// weight. Allocates only from the third draw on.
    pub fn without_replacement(self: *WeightedIndex, gpa: Allocator) WithoutReplacement {
        return .{ .pool = .{ .borrowed = .{ .index = self, .gpa = gpa } } };
    }

    /// Like `without_replacement`, but consumes the index; `deinit` frees it.
    pub fn into_without_replacement(self: WeightedIndex, gpa: Allocator) WithoutReplacement {
        return .{ .pool = .{ .owned = .{ .index = self, .gpa = gpa } } };
    }

    /// The first index whose cumulative weight (or positive count) exceeds `draw`.
    fn locate(self: *const WeightedIndex, comptime uniform: bool, draw: u128) usize {
        assert(self.tree.len > 0);
        var remaining = draw;
        var index: usize = 0;
        var step = @as(usize, 1) << std.math.log2_int(usize, self.tree.len);
        while (step != 0) : (step >>= 1) {
            const next = index + step;
            if (next > self.tree.len) continue;
            const sum: u128 = if (uniform) self.counts[next - 1] else self.tree[next - 1];
            if (sum <= remaining) {
                remaining -= sum;
                index = next;
            }
        }
        assert(index < self.weights.len);
        assert(self.weights[index] != 0);
        return index;
    }
};

/// Draws from a `WeightedIndex` without repeating an index. Weighted and uniform draws share
/// the same exclusions.
pub const WithoutReplacement = struct {
    const Excluded = struct { index: usize, weight: u64 };

    pool: union(enum) {
        borrowed: struct {
            index: *WeightedIndex,
            gpa: Allocator,
            excluded: std.ArrayList(Excluded) = .empty,
        },
        owned: struct { index: WeightedIndex, gpa: Allocator },
    },
    /// The last draw, excluded only if another draw is requested.
    previous: ?usize = null,

    /// Restores a borrowed index's weights, or frees an owned one.
    pub fn deinit(self: *WithoutReplacement) void {
        switch (self.pool) {
            .borrowed => |*borrowed| {
                for (borrowed.excluded.items) |item| {
                    _ = borrowed.index.set(item.index, item.weight);
                }
                borrowed.excluded.deinit(borrowed.gpa);
            },
            .owned => |*owned| owned.index.deinit(owned.gpa),
        }
        self.* = undefined;
    }

    /// Whether every positive-weight index has been drawn.
    pub fn is_empty(self: *const WithoutReplacement) bool {
        return self.index_const().positive == @intFromBool(self.previous != null);
    }

    /// Draws proportionally to the remaining weights.
    pub fn sample(self: *WithoutReplacement, rng: anytype) Allocator.Error!?usize {
        return self.draw(false, rng);
    }

    /// Draws uniformly from the remaining positive-weight indices.
    pub fn sample_uniform(self: *WithoutReplacement, rng: anytype) Allocator.Error!?usize {
        return self.draw(true, rng);
    }

    fn draw(
        self: *WithoutReplacement,
        comptime uniform: bool,
        rng: anytype,
    ) Allocator.Error!?usize {
        if (self.is_empty()) return null;
        const index = switch (self.pool) {
            .borrowed => |*borrowed| borrowed.index,
            .owned => |*owned| &owned.index,
        };
        // Delay mutation and allocation until a later draw needs the previous one excluded.
        if (self.previous) |previous| {
            switch (self.pool) {
                .borrowed => |*borrowed| try borrowed.excluded.append(borrowed.gpa, .{
                    .index = previous,
                    .weight = index.weight(previous),
                }),
                .owned => {},
            }
            self.previous = null;
            _ = index.set(previous, 0);
        }
        self.previous = if (uniform) index.sample_uniform(rng) else index.sample(rng);
        assert(self.previous != null);
        return self.previous;
    }

    fn index_const(self: *const WithoutReplacement) *const WeightedIndex {
        return switch (self.pool) {
            .borrowed => |borrowed| borrowed.index,
            .owned => |*owned| &owned.index,
        };
    }
};

const testing = std.testing;
const TestRng = rng_mod.TestRng;

/// Asserts `index` holds `weights` and every weighted interval and uniform rank locates its own
/// position.
fn expect_intervals(index: *const WeightedIndex, weights: []const u64) !void {
    try testing.expectEqualSlices(u64, weights, index.weights);
    var start: u128 = 0;
    var positive: u64 = 0;
    for (weights, 0..) |weight, position| {
        const end = start + weight;
        if (weight != 0) {
            try testing.expectEqual(position, index.locate(false, start));
            try testing.expectEqual(position, index.locate(false, end - 1));
            try testing.expectEqual(position, index.locate(true, positive));
            positive += 1;
        }
        start = end;
    }
    try testing.expectEqual(start, index.total());
    try testing.expectEqual(positive, index.positive);
}

test "weighted index updates match intervals" {
    const gpa = testing.allocator;
    var rng = TestRng.init(0);
    const lens = [_]usize{ 0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 63, 64, 65, 127, 128, 129 };
    for (lens) |len| {
        const weights = try gpa.alloc(u64, len);
        defer gpa.free(weights);
        for (weights, 0..) |*weight, i| weight.* = ([_]u64{ 0, 1, std.math.maxInt(u64) })[i % 3];
        var index = try WeightedIndex.init(gpa, weights);
        defer index.deinit(gpa);
        try expect_intervals(&index, weights);
        if (len == 0) continue;
        for (0..64) |_| {
            const position = rng_mod.range_less_than(&rng, usize, 0, len);
            const choices = [_]u64{ 0, 1, std.math.maxInt(u64), rng.next_u64() };
            const weight = choices[rng_mod.range_less_than(&rng, usize, 0, 4)];
            try testing.expectEqual(weights[position], index.set(position, weight));
            weights[position] = weight;
            try expect_intervals(&index, weights);
        }
    }
}

test "weighted index set moves entries between zero and positive" {
    const gpa = testing.allocator;
    var index = try WeightedIndex.init(gpa, &.{ 0, 7, std.math.maxInt(u64) });
    defer index.deinit(gpa);
    try testing.expectEqual(@as(u64, 7), index.set(1, 14));
    try expect_intervals(&index, &.{ 0, 14, std.math.maxInt(u64) });
    // Identity updates preserve every interval.
    for ([_]u64{ 0, 14, std.math.maxInt(u64) }, 0..) |weight, position| {
        try testing.expectEqual(weight, index.set(position, weight));
    }
    try testing.expectEqual(std.math.maxInt(u64), index.set(2, 0));
    try testing.expectEqual(@as(u64, 0), index.set(0, 1));
    try expect_intervals(&index, &.{ 1, 14, 0 });
}

test "weighted index zero total does not draw" {
    const gpa = testing.allocator;
    var rng = TestRng.init(0);
    var reference = TestRng.init(0);
    const zeros: [65]u64 = @splat(0);
    for ([_][]const u64{ &.{}, &.{0}, &zeros }) |weights| {
        var index = try WeightedIndex.init(gpa, weights);
        defer index.deinit(gpa);
        try testing.expect(index.sample(&rng) == null);
        try testing.expect(index.sample_uniform(&rng) == null);
        var draws = index.without_replacement(gpa);
        defer draws.deinit();
        try testing.expect(draws.is_empty());
        try testing.expect(try draws.sample(&rng) == null);
        try testing.expect(try draws.sample_uniform(&rng) == null);
    }
    for (0..4) |_| try testing.expectEqual(reference.next_u64(), rng.next_u64());
    var index = try WeightedIndex.init(gpa, &.{ 0, 7, 0 });
    defer index.deinit(gpa);
    try testing.expectEqual(@as(?usize, 1), index.sample(&rng));
    _ = index.set(1, 0);
    try testing.expect(index.sample(&rng) == null);
}

test "uniform draws match unit weights" {
    const gpa = testing.allocator;
    const nines: [65]u64 = @splat(9);
    const cases = [_][]const u64{ &.{ 0, 1, 0 }, &.{ std.math.maxInt(u64), 0, 1, 7 }, &nines };
    for (cases) |weights| {
        var index = try WeightedIndex.init(gpa, weights);
        defer index.deinit(gpa);
        const units = try gpa.alloc(u64, weights.len);
        defer gpa.free(units);
        for (weights, units) |weight, *unit| unit.* = @intFromBool(weight != 0);
        var uniform = try WeightedIndex.init(gpa, units);
        defer uniform.deinit(gpa);
        var rng = TestRng.init(0);
        var reference = TestRng.init(0);
        for (0..2000) |_| {
            try testing.expectEqual(uniform.sample(&reference), index.sample_uniform(&rng));
        }
        for (0..4) |_| try testing.expectEqual(reference.next_u64(), rng.next_u64());
    }
}

/// Checks a sequence against independently excluded weighted and unit-weight indices. `mode`
/// 0 draws by weight, 1 uniformly, 2 alternates starting by weight.
fn expect_without_replacement(
    draws: *WithoutReplacement,
    weights: []const u64,
    stop_after: usize,
    mode: usize,
) !void {
    const gpa = testing.allocator;
    var weighted = try WeightedIndex.init(gpa, weights);
    defer weighted.deinit(gpa);
    const units = try gpa.alloc(u64, weights.len);
    defer gpa.free(units);
    for (weights, units) |weight, *unit| unit.* = @intFromBool(weight != 0);
    var uniform = try WeightedIndex.init(gpa, units);
    defer uniform.deinit(gpa);
    var rng = TestRng.init(0);
    var reference = TestRng.init(0);
    for (0..stop_after) |step| {
        try testing.expect(!draws.is_empty());
        const by_uniform = mode == 1 or (mode == 2 and step % 2 == 1);
        const actual = if (by_uniform) try draws.sample_uniform(&rng) else try draws.sample(&rng);
        const source = if (by_uniform) &uniform else &weighted;
        const expected = source.sample(&reference);
        try testing.expectEqual(expected, actual);
        _ = weighted.set(expected.?, 0);
        _ = uniform.set(expected.?, 0);
    }
    try testing.expectEqual(weighted.total() == 0, draws.is_empty());
    if (draws.is_empty()) {
        try testing.expect(try draws.sample(&rng) == null);
        try testing.expect(try draws.sample_uniform(&rng) == null);
    }
    for (0..4) |_| try testing.expectEqual(reference.next_u64(), rng.next_u64());
}

test "without replacement matches exclusion and restores weights" {
    const gpa = testing.allocator;
    const max = std.math.maxInt(u64);
    const ones: [65]u64 = @splat(1);
    const cases = [_][]const u64{ &.{}, &.{ 0, 0 }, &.{ 0, 1, 0 }, &.{ max, 1, 0, 7, max }, &ones };
    for (cases) |weights| {
        var positive: usize = 0;
        for (weights) |weight| positive += @intFromBool(weight != 0);
        for (0..positive + 1) |stop_after| {
            for (0..3) |mode| {
                var index = try WeightedIndex.init(gpa, weights);
                var borrowed = index.without_replacement(gpa);
                try expect_without_replacement(&borrowed, weights, stop_after, mode);
                borrowed.deinit();
                try expect_intervals(&index, weights);
                var owned = index.into_without_replacement(gpa);
                defer owned.deinit();
                try expect_without_replacement(&owned, weights, stop_after, mode);
            }
        }
    }
}

test "draws match commonware sampling vectors" {
    // Reference values from commonware-utils `sampling` over rand 0.10 `StdRng`.
    const gpa = testing.allocator;
    var index = try WeightedIndex.init(gpa, &.{ 3, 0, 1, 4, 7, 2 });
    defer index.deinit(gpa);
    var rng = TestRng.init(7);
    for ([_]usize{ 3, 4, 5, 3, 4, 0, 3, 4, 4, 4, 3, 4 }) |expected| {
        try testing.expectEqual(@as(?usize, expected), index.sample(&rng));
    }
    for ([_]usize{ 2, 5, 5, 3, 2, 0, 3, 2, 4, 5, 4, 3 }) |expected| {
        try testing.expectEqual(@as(?usize, expected), index.sample_uniform(&rng));
    }
    var mixed = try WeightedIndex.init(gpa, &.{ 5, 9, 0, 1, 1, 30, 2 });
    defer mixed.deinit(gpa);
    var draws = mixed.without_replacement(gpa);
    defer draws.deinit();
    var seeded = TestRng.init(9);
    for ([_]usize{ 0, 5, 4, 1, 3, 6 }, 0..) |expected, step| {
        const drawn = if (step % 3 == 2)
            try draws.sample_uniform(&seeded)
        else
            try draws.sample(&seeded);
        try testing.expectEqual(@as(?usize, expected), drawn);
    }
    try testing.expect(draws.is_empty());
}

fn sample_counts(comptime n: usize, weights: [n]u64) ![n]usize {
    var index = try WeightedIndex.init(testing.allocator, &weights);
    defer index.deinit(testing.allocator);
    var counts: [n]usize = @splat(0);
    for (0..2000) |seed| {
        var rng = TestRng.init(seed);
        counts[index.sample(&rng).?] += 1;
    }
    return counts;
}

test "weighted index prefers heavier weights" {
    const counts = try sample_counts(4, .{ 0, 9, 1, 0 });
    try testing.expectEqual(@as(usize, 0), counts[0]);
    try testing.expectEqual(@as(usize, 0), counts[3]);
    try testing.expect(counts[1] >= 2000 * 85 / 100 and counts[1] < 2000 * 95 / 100);
}

test "weighted index equal weights are uniform" {
    for (try sample_counts(3, .{ 7, 7, 7 })) |count| {
        try testing.expect(count >= 2000 / 4 and count < 2000 * 5 / 12);
    }
}
