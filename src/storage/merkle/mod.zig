//! Shared types for Merkle-family data structures (MMR, MMB).
//!
//! Port of commonware's `storage/src/merkle/mod.rs`. A family is a comptime interface (see
//! `check_family`) with the per-family constants and conversions that make MMR differ from
//! MMB; the shared arithmetic lives here.
//!
//! Positions (node indices or node counts) and locations (leaf indices or leaf counts) are
//! plain `u64`s named `position`/`location` (or `size`/`leaves` when they are counts),
//! rather than commonware's `Position<F>`/`Location<F>` newtypes.

const std = @import("std");
const assert = std.debug.assert;

pub const hasher = @import("hasher.zig");
pub const mem = @import("mem.zig");
pub const mmb = @import("mmb/mod.zig");
pub const mmr = @import("mmr/mod.zig");
pub const conformance = @import("conformance.zig");
pub const proof = @import("proof.zig");
pub const Proof = proof.Proof;
pub const storage = @import("storage.zig");
pub const verification = @import("verification.zig");
pub const ProofStore = verification.ProofStore;

/// Upper bound on pinned nodes (and peaks) for any u64-backed family: a structure with `n`
/// leaves has at most `popcount(n)` peaks.
pub const max_pinned_nodes = 64;

/// The strategy used to fold peaks into the root digest.
pub const Bagging = enum {
    /// Oldest to newest, placing the smallest peak at the top.
    forward_fold,
    /// Newest to oldest, placing the largest peak at the top.
    backward_fold,

    /// Domain tag committed by every root folded under this policy.
    pub fn domain(self: Bagging) u8 {
        return switch (self) {
            .forward_fold => 0,
            .backward_fold => 1,
        };
    }
};

/// A half-open range of leaf locations `[start, end)`.
pub const Range = struct {
    start: u64,
    end: u64,
};

/// A fixed-capacity list: the bounded stacks and peak lists the Merkle code walks with.
/// Appending past `capacity` is a bug (every use has a proven bound), so it asserts.
pub fn BoundedList(comptime T: type, comptime capacity: usize) type {
    comptime assert(capacity > 0);
    return struct {
        const Self = @This();

        buffer: [capacity]T = undefined,
        len: usize = 0,

        pub fn from_slice(items: []const T) Self {
            assert(items.len <= capacity);
            var self: Self = .{};
            @memcpy(self.buffer[0..items.len], items);
            self.len = items.len;
            return self;
        }

        pub fn append(self: *Self, item: T) void {
            assert(self.len < capacity);
            self.buffer[self.len] = item;
            self.len += 1;
        }

        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            self.len -= 1;
            return self.buffer[self.len];
        }

        pub fn slice(self: *const Self) []const T {
            assert(self.len <= capacity);
            return self.buffer[0..self.len];
        }

        pub fn slice_mut(self: *Self) []T {
            assert(self.len <= capacity);
            return self.buffer[0..self.len];
        }
    };
}

/// A peak (or any node) and its height.
pub const Peak = struct {
    position: u64,
    height: u32,
};

pub const Children = struct {
    left: u64,
    right: u64,
};

/// The heights `first..=last` of the parents created when one leaf is appended (empty when
/// `first > last`).
pub const Heights = struct {
    first: u32,
    last: u32,

    pub const none: Heights = .{ .first = 1, .last = 0 };

    pub fn next(self: *Heights) ?u32 {
        if (self.first > self.last) return null;
        const height = self.first;
        self.first += 1;
        assert(height <= 64);
        return height;
    }
};

/// Errors from a Merkle-family structure (commonware's `merkle::Error`).
pub const Error = error{
    /// The position does not correspond to a leaf node.
    NonLeaf,
    /// The position exceeds the family's maximum.
    PositionOverflow,
    /// The location exceeds the family's maximum.
    LocationOverflow,
    /// The range is empty but must contain at least one element.
    Empty,
    /// The end of a range is out of bounds.
    RangeOutOfBounds,
    /// The requested size is invalid.
    InvalidSize,
    /// A requested leaf location exceeds the current leaf count.
    LeafOutOfBounds,
    /// A requested leaf location repeats the location before it.
    DuplicateLocation,
    /// A requested leaf location is less than the location before it.
    UnsortedLocation,
    /// A required node was pruned.
    ElementPruned,
    /// A required digest was compressed into a synthetic accumulator.
    CompressedDigest,
    /// The pinned node list does not match the pruning boundary.
    InvalidPinnedNodes,
    /// The structure is at none of the states recorded by the batch's chain.
    StaleBatch,
    /// An unapplied ancestor batch was dropped before this batch was merkleized.
    AncestorDropped,
    /// The proof is invalid.
    InvalidProof,
    /// The inactive peak count exceeds the peak count.
    InvalidInactivePeaks,
    /// The root does not match the computed root.
    RootMismatch,
    /// A required node is missing.
    MissingNode,
    /// Data is corrupted.
    DataCorrupted,
    /// Bit offset is out of bounds.
    BitOutOfBounds,
};

/// Asserts at comptime that `F` implements the family interface.
pub fn check_family(comptime F: type) void {
    comptime {
        assert(@TypeOf(F.domain) == u8);
        assert(@TypeOf(F.max_nodes) == u64);
        assert(@TypeOf(F.max_leaves) == u64);
        assert(F.max_leaves < F.max_nodes);
        for ([_][]const u8{
            "location_to_position", "position_to_location", "is_valid_size",
            "to_nearest_size",      "peaks",                "children",
            "parent_heights",       "pos_to_height",        "birth_offset",
        }) |name| assert(@hasDecl(F, name));
    }
}

/// Whether `position` is a valid node count or size (`<= max_nodes`).
pub fn position_is_valid(comptime F: type, position: u64) bool {
    return position <= F.max_nodes;
}

/// Whether `location` is a valid leaf count (`<= max_leaves`).
pub fn location_is_valid(comptime F: type, location: u64) bool {
    return location <= F.max_leaves;
}

/// The node position of leaf `location` (commonware's `Position::try_from(Location)`).
pub fn position_from_location(comptime F: type, location: u64) Error!u64 {
    if (!location_is_valid(F, location)) return error.LocationOverflow;
    const position = F.location_to_position(location);
    assert(position_is_valid(F, position));
    return position;
}

/// The leaf location of node `position` (commonware's `Location::try_from(Position)`).
pub fn location_from_position(comptime F: type, position: u64) Error!u64 {
    if (!position_is_valid(F, position)) return error.PositionOverflow;
    const location = F.position_to_location(position) orelse return error.NonLeaf;
    assert(location_is_valid(F, location));
    return location;
}

/// `value + rhs`, or null on overflow or past `max`.
pub fn checked_add(value: u64, rhs: u64, max: u64) ?u64 {
    const sum = std.math.add(u64, value, rhs) catch return null;
    if (sum > max) return null;
    return sum;
}

/// `value + rhs`, saturating at `max`.
pub fn saturating_add(value: u64, rhs: u64, max: u64) u64 {
    return @min(value +| rhs, max);
}

/// The number of oldest peaks whose leaves all precede `inactivity_floor`; these can be
/// bagged forward into a grafted root.
pub fn inactive_peaks(comptime F: type, leaves: u64, inactivity_floor: u64) usize {
    var count: usize = 0;
    var capacity_sum: u64 = 0;
    var peaks = F.peaks(F.location_to_position(leaves));
    while (peaks.next()) |peak| {
        assert(peak.height < 64); // height excessively large
        capacity_sum = std.math.add(u64, capacity_sum, @as(u64, 1) << @intCast(peak.height)) catch
            unreachable; // A u64 leaf count cannot have peaks holding more than 2^64 leaves.
        if (capacity_sum > inactivity_floor) break;
        count += 1;
    }
    assert(count <= max_pinned_nodes);
    return count;
}

/// Writes the positions of the nodes that must be pinned when pruning to `prune_location`
/// (the peaks of the structure at that location) into `out`, and returns them.
pub fn nodes_to_pin(
    comptime F: type,
    prune_location: u64,
    out: *[max_pinned_nodes]u64,
) []u64 {
    assert(location_is_valid(F, prune_location));
    const prune_position = F.location_to_position(prune_location);
    var count: usize = 0;
    var peaks = F.peaks(prune_position);
    while (peaks.next()) |peak| {
        if (peak.position >= prune_position) continue;
        out[count] = peak.position;
        count += 1;
    }
    return out[0..count];
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("proof_test.zig");
    _ = @import("mem_test.zig");
    _ = @import("verification_test.zig");
    _ = @import("fuzz_test.zig");
}

test "bagging domains are distinct" {
    try std.testing.expectEqual(@as(u8, 0), Bagging.forward_fold.domain());
    try std.testing.expectEqual(@as(u8, 1), Bagging.backward_fold.domain());
}
