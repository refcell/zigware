//! Finalized blocks awaiting application dispatch (commonware `marshal/core/staged.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Height = @import("../../types.zig").Height;
const HeightMap = @import("../../aggregation/height_map.zig").HeightMap;

/// Bounded staging of a variant's blocks that rejects heights below a monotonic retention
/// minimum. It owns the blocks it holds and releases them with `V.deinit_block`.
pub fn Staged(comptime V: type) type {
    return struct {
        const Self = @This();

        entries: HeightMap(V.Block),
        min: Height,
        max: u32,

        /// Empty staging that holds at most `max` blocks, all allocated here.
        pub fn init(gpa: Allocator, max: u32) Allocator.Error!Self {
            assert(max > 0);
            var entries: HeightMap(V.Block) = .empty;
            try entries.entries.ensureTotalCapacityPrecise(gpa, max);
            return .{ .entries = entries, .min = .zero(), .max = max };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.entries.items()) |*entry| V.deinit_block(gpa, &entry.value);
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        pub fn len(self: *const Self) u32 {
            return @intCast(self.entries.len());
        }

        /// Stages `block` (taking ownership) if its height is retained and capacity is
        /// available. Duplicate heights keep their existing block; a rejected block is
        /// released.
        pub fn insert(self: *Self, gpa: Allocator, height: Height, block: V.Block) void {
            var owned = block;
            const rejected = height.get() < self.min.get() or
                self.entries.len() >= self.max or self.entries.contains(height);
            if (rejected) return V.deinit_block(gpa, &owned);
            assert(self.entries.entries.capacity >= self.max);
            // `init` reserved `max` entries, so this does not allocate.
            self.entries.put_new(gpa, height, owned) catch unreachable;
            assert(self.entries.len() <= self.max);
        }

        /// Removes the staged block at `height` for dispatch; the caller owns it.
        pub fn remove(self: *Self, height: Height) ?V.Block {
            const all = self.entries.items();
            for (all, 0..) |entry, index| {
                if (entry.height.get() != height.get()) continue;
                _ = self.entries.entries.orderedRemove(index);
                assert(!self.entries.contains(height));
                return entry.value;
            }
            return null;
        }

        /// Retains entries at or above `min` and rejects future inserts below it. The retention
        /// minimum never decreases.
        pub fn retain(self: *Self, gpa: Allocator, min: Height) void {
            if (min.get() <= self.min.get()) return;
            self.min = min;
            for (self.entries.below(min)) |*entry| V.deinit_block(gpa, &entry.value);
            self.entries.remove_below(min);
            assert(self.entries.below(min).len == 0);
        }
    };
}

const testing = std.testing;

/// A variant whose blocks are reference counts, so tests see which block stayed staged.
const Counted = struct {
    const Block = struct { id: u32, live: *u32 };

    fn deinit_block(_: Allocator, block: *Block) void {
        assert(block.live.* > 0);
        block.live.* -= 1;
    }
};

test "insert keeps first block and rejects overflow" {
    const gpa = testing.allocator;
    var live: u32 = 4;
    var staged: Staged(Counted) = try .init(gpa, 2);
    defer staged.deinit(gpa);
    staged.insert(gpa, .new(5), .{ .id = 1, .live = &live });
    staged.insert(gpa, .new(5), .{ .id = 2, .live = &live });
    staged.insert(gpa, .new(6), .{ .id = 3, .live = &live });
    staged.insert(gpa, .new(7), .{ .id = 4, .live = &live });
    // The duplicate and the overflow were released.
    try testing.expectEqual(2, live);
    try testing.expectEqual(null, staged.remove(.new(7)));
    try testing.expectEqual(1, staged.remove(.new(5)).?.id);
    try testing.expectEqual(3, staged.remove(.new(6)).?.id);
}

test "retained minimum never decreases" {
    const gpa = testing.allocator;
    var live: u32 = 8;
    var staged: Staged(Counted) = try .init(gpa, 2);
    defer staged.deinit(gpa);
    staged.insert(gpa, .new(5), .{ .id = 1, .live = &live });
    staged.insert(gpa, .new(6), .{ .id = 2, .live = &live });

    staged.retain(gpa, .new(6));
    try testing.expectEqual(7, live);
    try testing.expectEqual(null, staged.remove(.new(5)));
    try testing.expectEqual(2, staged.remove(.new(6)).?.id);

    // A stale retain cannot restore eligibility after all entries are removed.
    staged.retain(gpa, .new(4));
    staged.insert(gpa, .new(5), .{ .id = 3, .live = &live });
    staged.insert(gpa, .new(6), .{ .id = 4, .live = &live });
    try testing.expectEqual(null, staged.remove(.new(5)));
    try testing.expectEqual(4, staged.remove(.new(6)).?.id);

    // Advancing an empty staging map still rejects late inserts.
    staged.retain(gpa, .new(8));
    staged.insert(gpa, .new(7), .{ .id = 5, .live = &live });
    staged.insert(gpa, .new(8), .{ .id = 6, .live = &live });
    try testing.expectEqual(null, staged.remove(.new(7)));
    try testing.expectEqual(6, staged.remove(.new(8)).?.id);
    try testing.expectEqual(5, live);
}
