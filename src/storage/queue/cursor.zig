//! Delivery and acknowledgement state of a queue's reader (commonware's `queue/cursor.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const RMap = @import("../rmap/mod.zig").RMap;

pub const Error = error{PositionOutOfRange} || Allocator.Error;

/// The next position to deliver and the set of acknowledged positions.
pub const Cursor = struct {
    /// Position of the next item to dequeue. `ack_up_to` can advance `ack_floor` past it;
    /// `next_position` then skips the already-acknowledged items.
    read_pos: u64,
    /// Every position below the floor is acknowledged.
    ack_floor: u64,
    /// Acknowledged positions at or above the floor (in memory only, lost on restart).
    acked_above: RMap = .empty,

    /// A cursor delivering from `start`, with every position below it acknowledged.
    pub fn init(start: u64) Cursor {
        return .{ .read_pos = start, .ack_floor = start };
    }

    pub fn deinit(self: *Cursor, gpa: Allocator) void {
        self.acked_above.deinit(gpa);
        self.* = undefined;
    }

    /// Whether `position` has been acknowledged.
    pub fn is_acked(self: *const Cursor, position: u64) bool {
        return position < self.ack_floor or self.acked_above.get(position) != null;
    }

    /// Fast-forward past acknowledged items and return the next position to deliver, or null
    /// when every item below `size` has been read or acknowledged.
    pub fn next_position(self: *Cursor, size: u64) ?u64 {
        if (self.read_pos < self.ack_floor) self.read_pos = self.ack_floor;
        if (self.acked_above.get(self.read_pos)) |range| self.read_pos = range.end +| 1;
        assert(!self.is_acked(self.read_pos) or self.read_pos == std.math.maxInt(u64));
        if (self.read_pos >= size) return null;
        return self.read_pos;
    }

    /// Record that the item at `next_position` was delivered.
    pub fn delivered(self: *Cursor, position: u64) void {
        assert(position == self.read_pos);
        self.read_pos = position + 1;
    }

    /// Mark the item at `position` as processed. A contiguous run from the floor advances it.
    /// Fails with `PositionOutOfRange` if `position >= size`.
    pub fn ack(self: *Cursor, gpa: Allocator, position: u64, size: u64) Error!void {
        if (position >= size) return error.PositionOutOfRange;
        if (self.is_acked(position)) return;
        if (position != self.ack_floor) {
            // Retain acknowledgements above the gap at the floor.
            try self.acked_above.insert(gpa, position);
            return;
        }
        // Advance the floor, consuming any contiguous acknowledged items.
        const next = position + 1;
        const floor = if (self.acked_above.get(next)) |range| range.end + 1 else next;
        try self.acked_above.remove(gpa, next, floor - 1);
        self.ack_floor = floor;
        assert(!self.is_acked(floor) or floor == std.math.maxInt(u64));
    }

    /// Acknowledge every item in `[ack_floor, up_to)` by advancing the floor directly. Fails
    /// with `PositionOutOfRange` if `up_to > size`.
    pub fn ack_up_to(self: *Cursor, gpa: Allocator, up_to: u64, size: u64) Error!void {
        if (up_to > size) return error.PositionOutOfRange;
        if (up_to <= self.ack_floor) return;
        const floor = if (self.acked_above.get(up_to)) |range| range.end + 1 else up_to;
        try self.acked_above.remove(gpa, self.ack_floor, floor - 1);
        self.ack_floor = floor;
        assert(self.ack_floor >= up_to);
    }

    /// Whether every item below `size` has been acknowledged. A non-empty `acked_above` means
    /// a gap at the floor, so all acknowledged implies the floor reached `size`.
    pub fn is_empty(self: *const Cursor, size: u64) bool {
        return self.ack_floor >= size;
    }

    /// Reset the read position to the floor so every unacknowledged item is re-delivered.
    pub fn reset(self: *Cursor) void {
        self.read_pos = self.ack_floor;
    }

    /// The number of acknowledged positions above the floor.
    pub fn acked_above_count(self: *const Cursor) u64 {
        var total: u64 = 0;
        for (self.acked_above.items()) |range| total += range.end - range.start + 1;
        return total;
    }
};

const testing = std.testing;

test "cursor: ack advances the floor through acknowledged runs" {
    var cursor: Cursor = .init(0);
    defer cursor.deinit(testing.allocator);
    try cursor.ack(testing.allocator, 2, 5);
    try cursor.ack(testing.allocator, 1, 5);
    try testing.expectEqual(0, cursor.ack_floor);
    try testing.expectEqual(2, cursor.acked_above_count());
    try cursor.ack(testing.allocator, 0, 5);
    try testing.expectEqual(3, cursor.ack_floor);
    try testing.expectEqual(0, cursor.acked_above_count());
    try testing.expectError(error.PositionOutOfRange, cursor.ack(testing.allocator, 5, 5));
}

test "cursor: next position skips acknowledged items" {
    var cursor: Cursor = .init(0);
    defer cursor.deinit(testing.allocator);
    try cursor.ack(testing.allocator, 1, 4);
    try cursor.ack(testing.allocator, 2, 4);
    try testing.expectEqual(0, cursor.next_position(4).?);
    cursor.delivered(0);
    try testing.expectEqual(3, cursor.next_position(4).?);
    cursor.delivered(3);
    try testing.expectEqual(null, cursor.next_position(4));
}
