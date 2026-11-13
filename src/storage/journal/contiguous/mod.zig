//! Contiguous journals with position-based access (commonware's `journal/contiguous`).
//!
//! Items are stored contiguously and accessed by their position (0-indexed), which is stable
//! across pruning.
//!
//! # Ownership
//!
//! Mutating methods leave a journal failed after a storage error (commonware consumes it);
//! only `deinit` may follow. State that was not yet durable is discarded, but everything
//! already on disk stays recoverable.

const std = @import("std");
const assert = std.debug.assert;

pub const checkpoint = @import("checkpoint.zig");
pub const blobs = @import("blobs.zig");
pub const fixed = @import("fixed.zig");

/// The readable positions `[start, end)` of a journal.
pub const Bounds = struct {
    start: u64,
    end: u64,

    pub fn len(self: Bounds) u64 {
        assert(self.start <= self.end);
        return self.end - self.start;
    }

    pub fn is_empty(self: Bounds) bool {
        assert(self.start <= self.end);
        return self.start == self.end;
    }
};

/// The number of items that can be written before crossing the current blob boundary.
/// `position` is the next item position and `remaining` the items left in the batch; the
/// result is at least one when `remaining > 0`.
pub fn batch_count_to_blob_boundary(position: u64, remaining: usize, items_per_blob: u64) usize {
    assert(items_per_blob > 0);
    const remaining_space = items_per_blob - position % items_per_blob;
    assert(remaining_space > 0);
    return @intCast(@min(remaining_space, @as(u64, remaining)));
}

/// The blob containing `position`.
pub fn position_to_blob(position: u64, items_per_blob: u64) u64 {
    assert(items_per_blob > 0);
    return position / items_per_blob;
}

/// The first position stored in `blob`.
pub fn blob_first_position(blob: u64, items_per_blob: u64) error{OffsetOverflow}!u64 {
    assert(items_per_blob > 0);
    return std.math.mul(u64, blob, items_per_blob) catch error.OffsetOverflow;
}

/// The exclusive logical end of `blob`, clamped to `end`.
pub fn blob_end_position(blob: u64, items_per_blob: u64, end: u64) u64 {
    assert(items_per_blob > 0);
    // No positions exist, so `end - 1` would underflow.
    if (end == 0) return 0;
    // This blob contains `end - 1`, so clamp to the journal end.
    if (blob >= (end - 1) / items_per_blob) return end;
    // Earlier blobs have a representable natural boundary.
    return (blob + 1) * items_per_blob;
}

test "contiguous: position to blob" {
    try std.testing.expectEqual(0, position_to_blob(0, 10));
    try std.testing.expectEqual(0, position_to_blob(9, 10));
    try std.testing.expectEqual(1, position_to_blob(10, 10));
    try std.testing.expectEqual(2, position_to_blob(25, 10));
    try std.testing.expectEqual(3, position_to_blob(30, 10));
}

test "contiguous: blob end position" {
    try std.testing.expectEqual(0, blob_end_position(0, 10, 0));
    try std.testing.expectEqual(10, blob_end_position(0, 10, 25));
    try std.testing.expectEqual(25, blob_end_position(2, 10, 25));
    try std.testing.expectEqual(20, blob_end_position(1, 10, 20));
    // A blob past the end clamps to the end.
    try std.testing.expectEqual(25, blob_end_position(7, 10, 25));
    // The last blob of a u64-sized space has no representable natural end.
    const max = std.math.maxInt(u64);
    try std.testing.expectEqual(max, blob_end_position(max / 10, 10, max));
}

test "contiguous: batch count to blob boundary" {
    try std.testing.expectEqual(3, batch_count_to_blob_boundary(7, 5, 10));
    try std.testing.expectEqual(5, batch_count_to_blob_boundary(0, 5, 10));
    try std.testing.expectEqual(1, batch_count_to_blob_boundary(9, 100, 10));
    // A 2^32-item blob space does not truncate to zero.
    try std.testing.expectEqual(4, batch_count_to_blob_boundary(0, 4, 1 << 32));
}

test {
    std.testing.refAllDecls(@This());
}
