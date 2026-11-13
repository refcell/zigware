//! Merkle Mountain Belt (MMB): the `mmb` Merkle family.
//!
//! Port of commonware's `storage/src/merkle/mmb/{mod,iterator}.rs`. Each appended leaf
//! creates at most one parent, merging the two oldest same-height peaks to the leaf's left
//! once they are old enough, so peaks stay shallow at the newest end and an append costs O(1)
//! hashing. With `n` leaves the MMB has `2n - ilog2(n + 1)` nodes and `ilog2(n + 1)` peaks,
//! oldest first, heights non-increasing. A parent's position follows the leaf that births
//! it, which can lie to the right of the parent's subtree.

const std = @import("std");
const assert = std.debug.assert;
const merkle = @import("../mod.zig");

const Peak = merkle.Peak;

/// The MMB family (see `merkle.check_family`).
pub const Family = struct {
    /// Domain tag committed by every MMB root.
    pub const domain: u8 = 1;
    /// Maximum node count.
    pub const max_nodes: u64 = 0x7fff_ffff_ffff_fffe;
    /// Maximum leaf count: `location_to_position(max_leaves) == max_nodes`.
    pub const max_leaves: u64 = 0x4000_0000_0000_001e;

    /// The position of leaf `location`, equivalently the size of an MMB with `location` leaves.
    pub fn location_to_position(location: u64) u64 {
        assert(location <= std.math.maxInt(u64) / 2); // Should not overflow for a valid leaf.
        const position = 2 * location - std.math.log2_int(u64, location + 1);
        assert(position >= location);
        return position;
    }

    /// The leaf location of `position`, or null if it is not a leaf. Equivalently, the leaf
    /// count of an MMB of size `position`, or null if the size is invalid. Requires
    /// `position <= max_nodes`.
    pub fn position_to_location(position: u64) ?u64 {
        assert(position <= max_nodes);
        // Two fixed-point steps land at or just below the answer; leaf positions grow by one
        // or two per leaf, so a few increments settle it.
        var n = position / 2;
        n = (position + std.math.log2_int(u64, n + 1)) / 2;
        for (0..steps_max) |_| {
            const leaf_position = location_to_position(n);
            if (leaf_position == position) return n;
            if (leaf_position > position) return null;
            n += 1;
        }
        unreachable; // The fixed-point estimate is within `steps_max` of the answer.
    }

    const steps_max = 8;

    pub fn is_valid_size(size: u64) bool {
        if (size > max_nodes) return false;
        return position_to_location(size) != null;
    }

    /// The largest valid size that is no greater than `size`.
    pub fn to_nearest_size(size: u64) u64 {
        assert(size <= max_nodes); // size exceeds MAX_NODES
        if (size == 0) return 0;
        var n = size / 2;
        n = (size + std.math.log2_int(u64, n + 1)) / 2;
        const candidate = location_to_position(n + 1);
        const result = if (candidate <= size) candidate else location_to_position(n);
        assert(result <= size and is_valid_size(result));
        return result;
    }

    pub fn peaks(size: u64) PeakIterator {
        return PeakIterator.init(size);
    }

    pub fn children(position: u64, height: u32) merkle.Children {
        assert(height > 0); // height-0 nodes are leaves and have no children
        const birth = parent_birth_leaf(position).?; // pos is not a valid parent position
        const leaves = child_leaves(birth, height);
        const is_leaf = height == 1;
        const result: merkle.Children = .{
            .left = birthed_node_position(leaves.left, is_leaf),
            .right = birthed_node_position(leaves.right, is_leaf),
        };
        assert(result.left < result.right and result.right < position);
        return result;
    }

    /// The height of the parent created when the leaf at `leaves` is appended: none when
    /// `leaves + 2` is a power of two, else `trailing_ones(leaves + 1) + 1`.
    pub fn parent_heights(leaves: u64) merkle.Heights {
        if (std.math.isPowerOfTwo(leaves + 2)) return .none;
        const height: u32 = @as(u32, @ctz(~(leaves + 1))) + 1;
        assert(height >= 1 and height < 64);
        return .{ .first = height, .last = height };
    }

    pub fn pos_to_height(position: u64) u32 {
        if (position_to_location(position) != null) return 0;
        assert(position > 0);
        // position is neither leaf nor parent
        const birth = position_to_location(position - 1).?;
        const height: u32 = @as(u32, @ctz(~(birth + 1))) + 1;
        assert(height < 64);
        return height;
    }

    /// Leaves to append, starting with a node's leftmost leaf, before the node at `height`
    /// exists: 1 for a leaf, else `3 * 2^(height - 1) - 1`.
    pub fn birth_offset(height: u32) u64 {
        if (height == 0) return 1;
        assert(height <= 63); // height excessively large
        const offset = 3 * (@as(u64, 1) << @intCast(height - 1)) - 1;
        assert(offset >= 2);
        return offset;
    }

    /// The location of the leftmost leaf under the node at `position` with `height`.
    pub fn leftmost_leaf(position: u64, height: u32) u64 {
        if (height == 0) return position_to_location(position).?; // height-0 node must be a leaf
        assert(position > 0); // position underflow
        // position is neither leaf nor parent
        const birth = position_to_location(position - 1).?;
        const term = subtree_birth_term(height);
        assert(birth >= term); // location underflow
        return birth - term;
    }

    /// The position of the node at `height` whose leftmost leaf is `leaf_start`.
    pub fn subtree_root_position(leaf_start: u64, height: u32) u64 {
        if (height == 0) return location_to_position(leaf_start);
        const birth_leaf = leaf_start + subtree_birth_term(height);
        assert(birth_leaf > leaf_start);
        return location_to_position(birth_leaf) + 1;
    }

    /// The peaks covering bitmap chunk `chunk_index` at `grafting_height`, oldest first: one
    /// subtree root when the chunk's subtree exists, else the smaller peaks partitioning it.
    pub fn chunk_peaks(size: u64, chunk_index: u64, grafting_height: u32) ChunkPeakIterator {
        return ChunkPeakIterator.init(size, chunk_index, grafting_height);
    }
};

comptime {
    merkle.check_family(Family);
}

/// `3 * 2^(height - 1) - 2`: from a subtree's leftmost leaf to the leaf that births its root.
fn subtree_birth_term(height: u32) u64 {
    assert(height > 0 and height <= 63); // height excessively large
    const term = 3 * (@as(u64, 1) << @intCast(height - 1)) - 2;
    assert(term >= 1);
    return term;
}

/// The leaf locations whose births created the children of the parent born at `parent_leaf`.
fn child_leaves(parent_leaf: u64, height: u32) merkle.Children {
    assert(height > 0 and height < 64);
    if (height == 1) {
        assert(parent_leaf >= 1);
        return .{ .left = parent_leaf - 1, .right = parent_leaf };
    }
    const base = @as(u64, 1) << @intCast(height - 2);
    assert(parent_leaf >= 3 * base);
    return .{ .left = parent_leaf - 3 * base, .right = parent_leaf - base };
}

/// The position of the node born when leaf `birth_leaf` was appended: the leaf itself, or
/// the parent right after it.
fn birthed_node_position(birth_leaf: u64, is_leaf: bool) u64 {
    const leaf_position = Family.location_to_position(birth_leaf);
    assert(leaf_position >= birth_leaf);
    return if (is_leaf) leaf_position else leaf_position + 1;
}

/// The leaf whose append created the parent at `position`, or null if `position` is not a
/// parent.
fn parent_birth_leaf(position: u64) ?u64 {
    if (position < 2) return null;
    if (Family.position_to_location(position) != null) return null;
    return Family.position_to_location(position - 1);
}

/// The leaf whose append created the peak of `height` whose last leaf is `last_leaf`.
fn peak_birth_leaf(last_leaf: u64, height: u32) u64 {
    assert(height < 64);
    if (height == 0) return last_leaf;
    return last_leaf + (@as(u64, 1) << @intCast(height - 1)) - 1;
}

/// Iterates the peaks of an MMB of a given size, oldest (largest) first.
pub const PeakIterator = struct {
    /// Leaf count of the MMB.
    leaves: u64 = 0,
    /// Bit index, counting down from `num_peaks - 1` to 0.
    index: u32 = 0,
    /// Peaks left to yield.
    remaining: u32 = 0,
    /// First leaf of the next (newer) peak.
    leaf_cursor: u64 = 0,

    pub fn init(size: u64) PeakIterator {
        const leaves = Family.position_to_location(size).?; // size is not a valid MMB size
        if (leaves == 0) return .{};
        const num_peaks: u32 = std.math.log2_int(u64, leaves + 1);
        assert(num_peaks >= 1 and num_peaks < 64);
        return .{ .leaves = leaves, .index = num_peaks - 1, .remaining = num_peaks };
    }

    pub fn next(self: *PeakIterator) ?Peak {
        if (self.remaining == 0) return null;
        const height: u32 = self.index + @as(u32, @intCast(((self.leaves + 1) >> @intCast(
            self.index,
        )) & 1));
        assert(height < 64);
        const peak_leaves = @as(u64, 1) << @intCast(height);
        const last_leaf = self.leaf_cursor + peak_leaves - 1;
        assert(last_leaf < self.leaves);
        self.leaf_cursor += peak_leaves;
        self.index -%= 1;
        self.remaining -= 1;
        const birth = peak_birth_leaf(last_leaf, height);
        return .{ .position = birthed_node_position(birth, height == 0), .height = height };
    }
};

/// Iterates the peaks covering one bitmap chunk (see `Family.chunk_peaks`).
pub const ChunkPeakIterator = struct {
    m: u64,
    peak_count: u32,
    k: u32,
    leaf_cursor: u64,
    chunk_start: u64,
    chunk_end: u64,
    grafting_height: u32,

    pub fn init(size: u64, chunk_index: u64, grafting_height: u32) ChunkPeakIterator {
        assert(grafting_height < 63);
        const chunk_size = @as(u64, 1) << @intCast(grafting_height);
        const chunk_start = chunk_index * chunk_size;
        const chunk_end = chunk_start + chunk_size;
        const n = Family.position_to_location(size).?; // chunk_peaks: invalid size
        assert(chunk_end <= n); // Chunk's leaf range exceeds the leaf count.
        const m = n + 1;
        const peak_count: u32 = std.math.log2_int(u64, m);
        // `x` counts the peaks from the one holding `chunk_start` to the newest.
        const diff = m - chunk_start;
        const maybe_x: u32 = std.math.log2_int(u64, diff);
        const x_power = @as(u64, 1) << @intCast(maybe_x);
        const x = if (diff <= x_power + (m & (x_power - 1))) maybe_x else maybe_x + 1;
        assert(x <= peak_count);
        const x_mask = (@as(u64, 1) << @intCast(x)) - 1;
        return .{
            .m = m,
            .peak_count = peak_count,
            .k = peak_count - x,
            .leaf_cursor = m - (x_mask + 1) - (m & x_mask),
            .chunk_start = chunk_start,
            .chunk_end = chunk_end,
            .grafting_height = grafting_height,
        };
    }

    pub fn next(self: *ChunkPeakIterator) ?Peak {
        if (self.k >= self.peak_count) return null;
        const i = self.peak_count - 1 - self.k;
        self.k += 1;
        const height: u32 = i + @as(u32, @intCast((self.m >> @intCast(i)) & 1));
        assert(height < 64);
        const peak_start = self.leaf_cursor;
        const peak_end = peak_start + (@as(u64, 1) << @intCast(height));
        self.leaf_cursor = peak_end;
        if (peak_start >= self.chunk_end) {
            self.k = self.peak_count;
            return null;
        }
        // A peak no taller than the chunk lies inside it; a taller one holds the chunk's
        // subtree, whose root is born `2^(h-1) - 1` leaves after the chunk's last leaf.
        const last_leaf, const peak_height = if (height <= self.grafting_height)
            .{ peak_end - 1, height }
        else
            .{ self.chunk_end - 1, self.grafting_height };
        const birth = peak_birth_leaf(last_leaf, peak_height);
        const position = birthed_node_position(birth, peak_height == 0);
        return .{ .position = position, .height = peak_height };
    }
};

const testing = std.testing;
const cryptography = @import("cryptography");
const Sha256 = cryptography.Sha256;
const Standard = merkle.hasher.Standard(Sha256);
const TestMem = merkle.mem.Mem(Family, Sha256.Digest);

fn build_ones(n: u64) !TestMem {
    const hasher = Standard.init(.forward_fold);
    var mem: TestMem = .empty;
    errdefer mem.deinit(testing.allocator);
    const digest: [32]u8 = @splat(1);
    for (0..n) |_| try mem.add(testing.allocator, &hasher, &digest);
    return mem;
}

test "parent heights schedule" {
    const expected = [16]?u32{
        null, 1, null, 1, 2, 1, null, 1, 2, 1, 3, 1, 2, 1, null, 1,
    };
    for (expected, 0..) |height, location| {
        var heights = Family.parent_heights(location);
        try testing.expectEqual(height, heights.next());
        try testing.expectEqual(@as(?u32, null), heights.next());
    }
}

test "pos to height" {
    var next_position: u64 = 0;
    for (0..500) |leaf| {
        try testing.expectEqual(@as(u32, 0), Family.pos_to_height(next_position));
        next_position += 1;
        var heights = Family.parent_heights(leaf);
        if (heights.next()) |height| {
            try testing.expectEqual(height, Family.pos_to_height(next_position));
            next_position += 1;
        }
    }
}

test "leftmost leaf" {
    var mem = try build_ones(200);
    defer mem.deinit(testing.allocator);
    var peaks = Family.peaks(mem.size());
    while (peaks.next()) |peak| {
        const leftmost = Family.leftmost_leaf(peak.position, peak.height);
        try testing.expectEqual(peak.position, Family.subtree_root_position(leftmost, peak.height));
    }
}

test "subtree root position virtual roundtrip" {
    for (0..10) |height| {
        const chunk_size = @as(u64, 1) << @intCast(height);
        for (0..200) |chunk_index| {
            const leaf_start = chunk_index * chunk_size;
            const position = Family.subtree_root_position(leaf_start, @intCast(height));
            try testing.expectEqual(leaf_start, Family.leftmost_leaf(position, @intCast(height)));
        }
    }
}

fn leftmost_descendant(position: u64, height: u32) u64 {
    var current = position;
    var current_height = height;
    while (current_height > 0) : (current_height -= 1) {
        current = Family.children(current, current_height).left;
    }
    return current;
}

test "chunk peaks" {
    var mem = try build_ones(200);
    defer mem.deinit(testing.allocator);
    const size = mem.size();
    for (1..6) |grafting_height| {
        const chunk_size = @as(u64, 1) << @intCast(grafting_height);
        for (0..200 / chunk_size) |chunk_index| {
            const chunk_start = chunk_index * chunk_size;
            var peaks = Family.chunk_peaks(size, chunk_index, @intCast(grafting_height));
            var covered: u64 = 0;
            var count: usize = 0;
            while (peaks.next()) |peak| : (count += 1) {
                try testing.expect(mem.get_node(peak.position) != null);
                try testing.expect(peak.height <= grafting_height);
                const leaf_position = Family.location_to_position(chunk_start + covered);
                const leftmost = leftmost_descendant(peak.position, peak.height);
                try testing.expectEqual(leaf_position, leftmost);
                covered += @as(u64, 1) << @intCast(peak.height);
            }
            try testing.expect(count > 0);
            try testing.expectEqual(chunk_size, covered);
        }
    }
}

test "subtree root position" {
    var next_position: u64 = 0;
    for (0..500) |leaf| {
        try testing.expectEqual(next_position, Family.subtree_root_position(leaf, 0));
        next_position += 1;
        var heights = Family.parent_heights(leaf);
        if (heights.next()) |height| {
            const leftmost = leaf + 2 - 3 * (@as(u64, 1) << @intCast(height - 1));
            try testing.expectEqual(next_position, Family.subtree_root_position(leftmost, height));
            try testing.expectEqual(leaf + 1, leftmost + Family.birth_offset(height));
            next_position += 1;
        }
    }
}

test "birth offset" {
    try testing.expectEqual(@as(u64, 1), Family.birth_offset(0));
    try testing.expectEqual(@as(u64, 2), Family.birth_offset(1));
    try testing.expectEqual(@as(u64, 11), Family.birth_offset(3));
    try testing.expect(Family.birth_offset(61) <= Family.max_leaves);
    try testing.expect(Family.birth_offset(62) > Family.max_leaves);
}

test "inactive peaks" {
    // 8 leaves: peaks cover leaves 0..4, 4..6, 6..8.
    const cases = [_][2]u64{ .{ 0, 0 }, .{ 3, 0 }, .{ 4, 1 }, .{ 5, 1 }, .{ 6, 2 }, .{ 8, 3 } };
    for (cases) |case| {
        try testing.expectEqual(case[1], merkle.inactive_peaks(Family, 8, case[0]));
    }
}

test "location to position" {
    try testing.expectEqual(@as(u64, 1), Family.location_to_position(1));
    try testing.expectEqual(@as(u64, 3), Family.location_to_position(2));
    try testing.expectEqual(@as(u64, 4), Family.location_to_position(3));
    try testing.expectEqual(@as(u64, 6), Family.location_to_position(4));
}

test "position to location roundtrip" {
    for (1..1001) |n| {
        const size = Family.location_to_position(n);
        try testing.expectEqual(@as(?u64, n), Family.position_to_location(size));
    }
}

test "max position and max location consistent" {
    const max_location = try merkle.location_from_position(Family, Family.max_nodes);
    try testing.expectEqual(Family.max_leaves, max_location);
    const max_position = try merkle.position_from_location(Family, Family.max_leaves);
    try testing.expectEqual(Family.max_nodes, max_position);
    try testing.expect(Family.location_to_position(Family.max_leaves + 1) > Family.max_nodes);
    try testing.expect(!merkle.position_is_valid(Family, Family.max_nodes + 1));
    try testing.expect(!Family.is_valid_size(Family.max_nodes + 1));
    try testing.expect(!Family.is_valid_size(std.math.maxInt(u64)));
}

test "max boundary roundtrip" {
    var n = Family.max_leaves - 64;
    while (n <= Family.max_leaves) : (n += 1) {
        const position = Family.location_to_position(n);
        try testing.expectEqual(@as(?u64, n), Family.position_to_location(position));
        if (n < Family.max_leaves) {
            const next_position = Family.location_to_position(n + 1);
            for (position + 1..next_position) |gap| {
                try testing.expect(Family.position_to_location(gap) == null);
            }
        }
    }
}

test "child leaves match children and peak births" {
    for (1..257) |n| {
        var peaks = Family.peaks(Family.location_to_position(n));
        var first_leaf: u64 = 0;
        while (peaks.next()) |peak| {
            const peak_leaves = @as(u64, 1) << @intCast(peak.height);
            const birth = peak_birth_leaf(first_leaf + peak_leaves - 1, peak.height);
            try testing.expectEqual(peak.position, birthed_node_position(birth, peak.height == 0));
            first_leaf += peak_leaves;
            if (peak.height == 0) continue;
            const leaves = child_leaves(parent_birth_leaf(peak.position).?, peak.height);
            const is_leaf = peak.height == 1;
            const expected = Family.children(peak.position, peak.height);
            try testing.expectEqual(expected.left, birthed_node_position(leaves.left, is_leaf));
            try testing.expectEqual(expected.right, birthed_node_position(leaves.right, is_leaf));
        }
        try testing.expectEqual(@as(u64, n), first_leaf);
    }
}

test "invalid sizes rejected" {
    for (0..1001) |n| {
        const position = Family.location_to_position(n);
        try testing.expectEqual(@as(?u64, n), Family.position_to_location(position));
        try testing.expect(Family.is_valid_size(position));
        const next_position = Family.location_to_position(n + 1);
        for (position + 1..next_position) |gap| {
            try testing.expect(Family.position_to_location(gap) == null);
            try testing.expectError(error.NonLeaf, merkle.location_from_position(Family, gap));
        }
    }
}

test "parent birth leaf rejects leaf positions" {
    try testing.expectEqual(@as(?u64, null), parent_birth_leaf(4));
    try testing.expectEqual(@as(?u64, null), parent_birth_leaf(11));
}

test "to nearest size" {
    try testing.expectEqual(@as(u64, 0), Family.to_nearest_size(0));
    var previous: u64 = 0;
    for (0..2001) |size| {
        const nearest = Family.to_nearest_size(size);
        try testing.expect(Family.is_valid_size(nearest));
        try testing.expect(nearest <= size and nearest >= previous);
        previous = nearest;
    }
    for (1..501) |n| {
        const size = Family.location_to_position(n);
        try testing.expectEqual(size, Family.to_nearest_size(size));
        for (size + 1..Family.location_to_position(n + 1)) |gap| {
            try testing.expectEqual(size, Family.to_nearest_size(gap));
        }
    }
    const largest = Family.to_nearest_size(Family.max_nodes);
    try testing.expectEqual(Family.max_nodes, largest);
}

test "add eight values structure" {
    var mem = try build_ones(8);
    defer mem.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 13), mem.size());
    var peaks = Family.peaks(mem.size());
    try testing.expectEqual(Peak{ .position = 7, .height = 2 }, peaks.next().?);
    try testing.expectEqual(Peak{ .position = 9, .height = 1 }, peaks.next().?);
    try testing.expectEqual(Peak{ .position = 12, .height = 1 }, peaks.next().?);
    try testing.expect(peaks.next() == null);
    const leaf_positions = [_]u64{ 0, 1, 3, 4, 6, 8, 10, 11 };
    for (leaf_positions, 0..) |position, location| {
        try testing.expectEqual(@as(?u64, location), Family.position_to_location(position));
    }
    // Parents: 2 = (0, 1), 5 = (3, 4), 7 = (2, 5), 9 = (6, 8), 12 = (10, 11).
    const parents = [_][3]u64{
        .{ 2, 0, 1 }, .{ 5, 3, 4 }, .{ 7, 2, 5 }, .{ 9, 6, 8 }, .{ 12, 10, 11 },
    };
    for (parents) |parent| {
        const children = Family.children(parent[0], Family.pos_to_height(parent[0]));
        try testing.expectEqual(parent[1], children.left);
        try testing.expectEqual(parent[2], children.right);
    }
}
