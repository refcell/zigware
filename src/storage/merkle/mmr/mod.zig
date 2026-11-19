//! Merkle Mountain Range (MMR): the `mmr` Merkle family.
//!
//! Port of commonware's `storage/src/merkle/mmr/{mod,iterator}.rs`. Nodes are numbered in
//! post-order: a leaf is followed by every parent it completes. With `n` leaves, the MMR
//! has `2n - popcount(n)` nodes, and its peaks are the roots of the perfect binary trees in
//! the binary decomposition of `n`, largest (oldest) first.

const std = @import("std");
const assert = std.debug.assert;
const merkle = @import("../mod.zig");

const Peak = merkle.Peak;

/// The MMR family (see `merkle.check_family`).
pub const Family = struct {
    /// Domain tag committed by every MMR root.
    pub const domain: u8 = 0;
    /// Maximum node count: `(1 << 63) - 1`.
    pub const max_nodes: u64 = 0x7fff_ffff_ffff_ffff;
    /// Maximum leaf count: `2^62`.
    pub const max_leaves: u64 = 0x4000_0000_0000_0000;

    /// The position of leaf `location`, equivalently the size of an MMR with `location` leaves.
    pub fn location_to_position(location: u64) u64 {
        assert(location <= std.math.maxInt(u64) / 2); // Should not overflow for a valid leaf.
        const position = location * 2 - @popCount(location);
        assert(position >= location);
        return position;
    }

    /// The leaf location of `position`, or null if it is not a leaf. Equivalently, the leaf
    /// count of an MMR of size `position`, or null if the size is invalid. Requires
    /// `position <= max_nodes`.
    pub fn position_to_location(position: u64) ?u64 {
        assert(position <= max_nodes);
        // `n` converges to within one of the leaf count in three fixed-point steps.
        var n = position >> 1;
        n = (position + @popCount(n)) >> 1;
        n = (position + @popCount(n)) >> 1;
        n = (position + @popCount(n)) >> 1;
        if (location_to_position(n) == position) return n;
        if (n > 0 and location_to_position(n - 1) == position) return n - 1;
        if (location_to_position(n + 1) == position) return n + 1;
        return null;
    }

    pub fn is_valid_size(size: u64) bool {
        if (size == 0) return true;
        const leading_zeros: u7 = @clz(size);
        if (leading_zeros == 0) return false;
        const start = @as(u64, std.math.maxInt(u64)) >> @intCast(leading_zeros);
        var two_h: u64 = @as(u64, 1) << @intCast(@ctz(~start));
        var node_position = start - 1;
        // Each step halves `two_h` or advances past a peak, so this runs at most 128 times.
        while (two_h > 1) {
            if (node_position < size) {
                if (two_h == 2) return node_position == size - 1;
                node_position += two_h - 1;
                if (node_position < size) return false;
                continue;
            }
            two_h >>= 1;
            node_position -= two_h;
        }
        return true;
    }

    /// The largest valid size that is no greater than `size`.
    pub fn to_nearest_size(size: u64) u64 {
        assert(size <= max_nodes); // size exceeds MAX_NODES
        if (size == 0) return 0;
        // Binary search for the largest leaf count whose MMR size fits; size >= leaf count.
        var low: u64 = 0;
        var high: u64 = size;
        while (low < high) {
            const middle = std.math.divCeil(u64, low + high, 2) catch unreachable;
            if (location_to_position(middle) <= size) low = middle else high = middle - 1;
        }
        const result = location_to_position(low);
        assert(result <= size and is_valid_size(result));
        return result;
    }

    pub fn peaks(size: u64) PeakIterator {
        return PeakIterator.init(size);
    }

    pub fn children(position: u64, height: u32) merkle.Children {
        assert(height > 0 and height < 64);
        const left = position - (@as(u64, 1) << @intCast(height));
        assert(left < position - 1);
        return .{ .left = left, .right = position - 1 };
    }

    /// Heights of the parents created when the leaf at `leaves` is appended: `1..=t` where
    /// `t` is the number of trailing ones of `leaves`.
    pub fn parent_heights(leaves: u64) merkle.Heights {
        return .{ .first = 1, .last = @ctz(~leaves) };
    }

    pub fn pos_to_height(position: u64) u32 {
        return position_height(position);
    }

    /// Leaves to append, starting with a node's leftmost leaf, before the node at `height`
    /// exists.
    pub fn birth_offset(height: u32) u64 {
        assert(height < 64); // height excessively large
        return @as(u64, 1) << @intCast(height);
    }

    /// The nodes covering bitmap chunk `chunk_index` at `grafting_height`: one subtree root.
    pub fn chunk_peaks(size: u64, chunk_index: u64, grafting_height: u32) Peak {
        const chunk_end = merkle.position_from_location(
            Family,
            (chunk_index + 1) << @intCast(grafting_height),
        ) catch unreachable; // chunk_peaks: chunk overflow
        assert(chunk_end <= size); // Chunk's leaf range exceeds the leaf count.
        const first_leaf = location_to_position(chunk_index << @intCast(grafting_height));
        const root = first_leaf + (@as(u64, 1) << @intCast(grafting_height + 1)) - 2;
        return .{ .position = root, .height = grafting_height };
    }

    /// The position of the node at `height` whose leftmost leaf is `leaf_start`.
    pub fn subtree_root_position(leaf_start: u64, height: u32) u64 {
        assert(height + 1 < 64); // height excessively large
        const shift = @as(u64, 1) << @intCast(height + 1);
        const leaf_position = location_to_position(leaf_start);
        return leaf_position + shift - 2;
    }

    /// The location of the leftmost leaf under the node at `position` with `height`.
    pub fn leftmost_leaf(position: u64, height: u32) u64 {
        assert(height + 1 < 64); // height excessively large
        const shift = @as(u64, 1) << @intCast(height + 1);
        assert(position + 2 >= shift); // position underflow
        const leftmost = position + 2 - shift;
        return position_to_location(leftmost).?; // Leftmost descendant must be a leaf.
    }
};

comptime {
    merkle.check_family(Family);
}

/// Iterates the peaks of an MMR of a given size, oldest (largest) first.
pub const PeakIterator = struct {
    /// Node count of the MMR when the iterator was created.
    size: u64 = 0,
    /// Position of the current candidate peak.
    node_position: u64 = 0,
    /// `2^(height + 1)` of the current candidate.
    two_h: u64 = 0,

    pub fn init(size: u64) PeakIterator {
        if (size == 0) return .{};
        const start = @as(u64, std.math.maxInt(u64)) >> @intCast(@clz(size));
        assert(start != std.math.maxInt(u64)); // size overflow
        return .{
            .size = size,
            .node_position = start - 1,
            .two_h = @as(u64, 1) << @intCast(@ctz(~start)),
        };
    }

    pub fn next(self: *PeakIterator) ?Peak {
        // Each step halves `two_h` or yields a peak, so this runs at most 64 times.
        while (self.two_h > 1) {
            if (self.node_position < self.size) {
                const peak: Peak = .{
                    .position = self.node_position,
                    .height = @ctz(self.two_h) - 1,
                };
                self.node_position += self.two_h - 1;
                // The sibling must not be in the MMR if the size is valid.
                assert(self.node_position >= self.size);
                return peak;
            }
            self.two_h >>= 1;
            self.node_position -= self.two_h;
        }
        return null;
    }
};

/// The height of the node at `position`.
pub fn position_height(position: u64) u32 {
    if (position == 0) return 0;
    var remaining = position;
    var size = @as(u64, std.math.maxInt(u64)) >> @intCast(@clz(position));
    // Strip the largest perfect subtree sizes; what remains is the height.
    while (size != 0) {
        if (remaining >= size) remaining -= size;
        size >>= 1;
    }
    assert(remaining < 64);
    return @intCast(remaining);
}

const testing = std.testing;
const test_max_nodes = Family.max_nodes;
const test_max_leaves = Family.max_leaves;

const leaf_positions = [_][2]u64{
    .{ 0, 0 },   .{ 1, 1 },   .{ 2, 3 },   .{ 3, 4 },   .{ 4, 7 },   .{ 5, 8 },
    .{ 6, 10 },  .{ 7, 11 },  .{ 8, 15 },  .{ 9, 16 },  .{ 10, 18 }, .{ 11, 19 },
    .{ 12, 22 }, .{ 13, 23 }, .{ 14, 25 }, .{ 15, 26 },
};

test "from location" {
    for (leaf_positions) |case| {
        try testing.expectEqual(case[1], try merkle.position_from_location(Family, case[0]));
    }
}

test "try from position" {
    for (leaf_positions) |case| {
        try testing.expectEqual(case[0], try merkle.location_from_position(Family, case[1]));
    }
}

test "try from position error" {
    const non_leaves = [_]u64{ 2, 5, 6, 9, 12, 13, 14, 17, 20, 21, 24, 27, 28, 29, 30 };
    for (non_leaves) |position| {
        try testing.expectError(error.NonLeaf, merkle.location_from_position(Family, position));
    }
}

test "try from position error overflow" {
    const overflow = merkle.location_from_position(Family, std.math.maxInt(u64));
    try testing.expectError(error.PositionOverflow, overflow);
    const max_location = try merkle.location_from_position(Family, test_max_nodes);
    try testing.expectEqual(test_max_leaves, max_location);
    const past_max = merkle.location_from_position(Family, test_max_nodes + 1);
    try testing.expectError(error.PositionOverflow, past_max);
}

test "max position and location boundary" {
    const max_size = 2 * test_max_leaves - 1;
    try testing.expectEqual(max_size, test_max_nodes);
    try testing.expectEqual((@as(u64, 1) << 63) - 1, test_max_nodes);
    try testing.expectEqual(@as(u7, 1), @clz(max_size));
    try testing.expectEqual(@as(u7, 0), @clz(2 * (test_max_leaves + 1) - 1));
    const max_position = try merkle.position_from_location(Family, test_max_leaves);
    try testing.expectEqual(test_max_nodes, max_position);
    try testing.expect(merkle.position_is_valid(Family, test_max_nodes));
    const past_max = merkle.position_from_location(Family, test_max_leaves + 1);
    try testing.expectError(error.LocationOverflow, past_max);
}

test "location is valid" {
    try testing.expect(merkle.location_is_valid(Family, 0));
    try testing.expect(merkle.location_is_valid(Family, 1000));
    try testing.expect(merkle.location_is_valid(Family, test_max_leaves));
    try testing.expect(merkle.location_is_valid(Family, test_max_leaves - 1));
    try testing.expect(!merkle.location_is_valid(Family, test_max_leaves + 1));
    try testing.expect(!merkle.location_is_valid(Family, std.math.maxInt(u64)));
}

fn checked_add_nodes(value: u64, rhs: u64) ?u64 {
    return merkle.checked_add(value, rhs, test_max_nodes);
}

fn saturating_add_nodes(value: u64, rhs: u64) u64 {
    return merkle.saturating_add(value, rhs, test_max_nodes);
}

test "position and location checked and saturating add" {
    const max = std.math.maxInt(u64);
    try testing.expectEqual(@as(?u64, 15), checked_add_nodes(10, 5));
    try testing.expectEqual(@as(?u64, null), checked_add_nodes(max, 1));
    try testing.expectEqual(@as(?u64, null), checked_add_nodes(test_max_nodes, 1));
    try testing.expectEqual(@as(?u64, null), checked_add_nodes(test_max_nodes - 5, 10));
    try testing.expectEqual(@as(?u64, test_max_nodes), checked_add_nodes(test_max_nodes - 10, 10));
    const leaves_sum = merkle.checked_add(test_max_leaves - 11, 10, test_max_leaves);
    try testing.expectEqual(@as(?u64, test_max_leaves - 1), leaves_sum);
    try testing.expectEqual(@as(u64, 15), saturating_add_nodes(10, 5));
    try testing.expectEqual(test_max_nodes, saturating_add_nodes(max, 1));
    try testing.expectEqual(test_max_nodes, saturating_add_nodes(test_max_nodes, 1000));
    const leaves_saturated = merkle.saturating_add(test_max_leaves, 1, test_max_leaves);
    try testing.expectEqual(test_max_leaves, leaves_saturated);
}

/// Encodes `value` as a raw varint and reads it back as a position.
fn read_position_varint(value: u64) !u64 {
    const codec = @import("codec");
    var buffer: [codec.varint.max_size(u64)]u8 = undefined;
    var writer: codec.Writer = .init(&buffer);
    codec.varint.write(u64, value, &writer);
    var reader: codec.Reader = .init(writer.written());
    const position = try merkle.read_position(Family, &reader);
    try testing.expectEqual(@as(usize, 0), reader.remaining());
    return position;
}

test "position read cfg valid values" {
    for ([_]u64{ 0, 12345, test_max_nodes, test_max_nodes - 1 }) |position| {
        try testing.expectEqual(position, try read_position_varint(position));
    }
}

test "position read cfg invalid values" {
    for ([_]u64{ test_max_nodes + 1, std.math.maxInt(u64) }) |value| {
        try testing.expectError(error.Invalid, read_position_varint(value));
    }
}

fn expect_round_trip(location: u64) !void {
    const position = Family.location_to_position(location);
    try testing.expectEqual(@as(?u64, location), Family.position_to_location(position));
}

test "position to location power of two boundaries" {
    for (1..63) |m| {
        const base = @as(i64, 1) << @intCast(m);
        var delta: i64 = -64;
        while (delta <= 64) : (delta += 1) {
            const n = base + delta;
            if (n < 0 or @as(u64, @intCast(n)) > test_max_leaves) continue;
            try expect_round_trip(@intCast(n));
        }
    }
}

test "position to location max boundary" {
    var n = test_max_leaves - 64;
    while (n <= test_max_leaves) : (n += 1) try expect_round_trip(n);
}

test "position to location behavior classes" {
    for (0..64) |n| try expect_round_trip(n);
    for (0..64) |low| {
        for (1..57) |run| {
            for (0..56) |extra| {
                const one: u128 = 1;
                const h_odd = (((one << @intCast(extra)) - 1) << @intCast(run + 1)) |
                    ((one << @intCast(run)) - 1);
                const h_even = ((one << @intCast(extra + 1)) - 1) << @intCast(run);
                for ([_]u128{ h_odd, h_even }) |h| {
                    const n = 64 * h + low;
                    if (n > one << 62) continue;
                    try expect_round_trip(@intCast(n));
                }
            }
        }
    }
}

test "leaf location calculation" {
    // An MMR with `n` leaves has size `location_to_position(n)`; check every position in
    // between maps to no leaf.
    var last_leaf_position: u64 = 0;
    for (0..1000) |location| {
        const position = try merkle.position_from_location(Family, location);
        try testing.expectEqual(location, try merkle.location_from_position(Family, position));
        if (location > 0) {
            for (last_leaf_position + 1..position) |between| {
                try testing.expect(Family.position_to_location(between) == null);
            }
        }
        last_leaf_position = position;
    }
}

test "pos to height" {
    var next_position: u64 = 0;
    for (0..500) |leaf| {
        try testing.expectEqual(@as(u32, 0), Family.pos_to_height(next_position));
        next_position += 1;
        var heights = Family.parent_heights(leaf);
        while (heights.next()) |height| {
            try testing.expectEqual(height, Family.pos_to_height(next_position));
            next_position += 1;
        }
    }
}

test "is valid size" {
    var size_to_check: u64 = 0;
    for (0..10_000) |leaves| {
        const size = Family.location_to_position(leaves);
        while (size_to_check != size) : (size_to_check += 1) {
            try testing.expect(!Family.is_valid_size(size_to_check));
        }
        try testing.expect(Family.is_valid_size(size_to_check));
        size_to_check += 1;
    }
    try testing.expect(!Family.is_valid_size(std.math.maxInt(u64)));
    try testing.expect(Family.is_valid_size(std.math.maxInt(u64) >> 1));
    try testing.expect(!Family.is_valid_size((std.math.maxInt(u64) >> 1) + 1));
    try testing.expect(Family.is_valid_size(test_max_nodes));
}

test "to nearest size" {
    for (0..1000) |leaves| {
        const current = Family.location_to_position(leaves);
        for (current..current + 11) |test_position| {
            const rounded = Family.to_nearest_size(test_position);
            try testing.expect(Family.is_valid_size(rounded));
            try testing.expect(rounded <= test_position);
            if (rounded < test_position) try testing.expect(!Family.is_valid_size(rounded + 1));
        }
    }
}

test "to nearest size specific cases" {
    try testing.expectEqual(@as(u64, 0), Family.to_nearest_size(0));
    try testing.expectEqual(@as(u64, 1), Family.to_nearest_size(1));
    var expected: u64 = 0;
    for (0..21) |size| {
        try testing.expectEqual(expected, Family.to_nearest_size(size));
        if (Family.is_valid_size(size + 1)) expected = size + 1;
    }
    const large = Family.to_nearest_size(1_000_000);
    try testing.expect(Family.is_valid_size(large) and large <= 1_000_000);
    const largest = Family.to_nearest_size(test_max_nodes);
    try testing.expect(Family.is_valid_size(largest) and largest <= test_max_nodes);
}

test "peak iterator" {
    // 11 leaves = 8 + 2 + 1: peaks at heights 3, 1, 0.
    var peaks = Family.peaks(Family.location_to_position(11));
    try testing.expectEqual(Peak{ .position = 14, .height = 3 }, peaks.next().?);
    try testing.expectEqual(Peak{ .position = 17, .height = 1 }, peaks.next().?);
    try testing.expectEqual(Peak{ .position = 18, .height = 0 }, peaks.next().?);
    try testing.expect(peaks.next() == null);
    var empty = Family.peaks(0);
    try testing.expect(empty.next() == null);
}

test "chunk peaks" {
    const size = Family.location_to_position(200);
    for (1..6) |grafting_height| {
        const chunk_size = @as(u64, 1) << @intCast(grafting_height);
        for (0..200 / chunk_size) |chunk_index| {
            const peak = Family.chunk_peaks(size, chunk_index, @intCast(grafting_height));
            try testing.expectEqual(@as(u32, @intCast(grafting_height)), peak.height);
            try testing.expect(peak.position < size);
            try testing.expectEqual(peak.height, Family.pos_to_height(peak.position));
            const leftmost = Family.leftmost_leaf(peak.position, peak.height);
            try testing.expectEqual(chunk_index * chunk_size, leftmost);
            const root = Family.subtree_root_position(leftmost, peak.height);
            try testing.expectEqual(peak.position, root);
        }
    }
}

test "location checked and saturating add at the leaf bound" {
    const max = std.math.maxInt(u64);
    try testing.expectEqual(@as(?u64, 15), merkle.checked_add(10, 5, test_max_leaves));
    try testing.expectEqual(@as(?u64, null), merkle.checked_add(max, 1, test_max_leaves));
    const past = merkle.checked_add(test_max_leaves, 1, test_max_leaves);
    try testing.expectEqual(@as(?u64, null), past);
    // The bound is inclusive: MAX_LEAVES itself is a valid location.
    const at_bound = merkle.checked_add(test_max_leaves - 10, 10, test_max_leaves);
    try testing.expectEqual(@as(?u64, test_max_leaves), at_bound);
    try testing.expectEqual(@as(u64, 15), merkle.saturating_add(10, 5, test_max_leaves));
    try testing.expectEqual(test_max_leaves, merkle.saturating_add(max, 1, test_max_leaves));
    const far = merkle.saturating_add(test_max_leaves, 1000, test_max_leaves);
    try testing.expectEqual(test_max_leaves, far);
}

// Every node of a growing MMR: a height-h parent created at leaf `i` has leftmost leaf
// `i + 1 - 2^h`, and is born that many leaves after it.
test "subtree root position" {
    var next_position: u64 = 0;
    for (0..500) |leaf| {
        try testing.expectEqual(next_position, Family.subtree_root_position(leaf, 0));
        next_position += 1;
        var heights = Family.parent_heights(leaf);
        while (heights.next()) |height| {
            const leftmost = leaf + 1 - (@as(u64, 1) << @intCast(height));
            try testing.expectEqual(next_position, Family.subtree_root_position(leftmost, height));
            try testing.expectEqual(leaf + 1, leftmost + Family.birth_offset(height));
            next_position += 1;
        }
    }
    try testing.expectEqual(Family.location_to_position(500), next_position);
}

test "birth offset" {
    try testing.expectEqual(@as(u64, 1), Family.birth_offset(0));
    try testing.expectEqual(@as(u64, 8), Family.birth_offset(3));
    // The root of a full 2^62-leaf MMR is the tallest node that can exist.
    try testing.expectEqual(test_max_leaves, Family.birth_offset(62));
}

// The peaks of a 200-leaf MMR (which depend only on its size) round-trip through their
// leftmost leaves.
test "leftmost leaf" {
    var peaks = Family.peaks(Family.location_to_position(200));
    var count: usize = 0;
    while (peaks.next()) |peak| : (count += 1) {
        const leftmost = Family.leftmost_leaf(peak.position, peak.height);
        try testing.expectEqual(peak.position, Family.subtree_root_position(leftmost, peak.height));
    }
    try testing.expectEqual(@as(usize, @popCount(@as(u64, 200))), count);
}

test "inactive peaks" {
    // 11 leaves: peaks cover leaves 0..8, 8..10, and 10..11.
    const cases = [_][2]u64{ .{ 0, 0 }, .{ 7, 0 }, .{ 8, 1 }, .{ 9, 1 }, .{ 10, 2 } };
    for (cases) |case| {
        try testing.expectEqual(case[1], merkle.inactive_peaks(Family, 11, case[0]));
    }
}
