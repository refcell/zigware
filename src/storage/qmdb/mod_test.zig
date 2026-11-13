//! Tests for the shared QMDB functions in qmdb/mod.rs.

const std = @import("std");
const testing = std.testing;
const qmdb = @import("mod.zig");

const validate = qmdb.validate_initialization_commit;

test "initialization bound rejects zero" {
    try testing.expectError(
        error.InvalidInitializationBound,
        qmdb.validate_initialization_bound(0),
    );
    try qmdb.validate_initialization_bound(1);
    try qmdb.validate_initialization_bound(null);
}

test "initialization commit validation" {
    const not_commit: ?u64 = null;
    // A fresh, empty journal has no floor; a non-fresh empty one is corrupt.
    try testing.expectEqual(@as(?u64, null), try validate(0, 0, true, null, true));
    try testing.expectError(error.DataCorrupted, validate(0, 0, false, null, true));
    // The last operation must be a commit whose floor precedes it.
    try testing.expectError(error.DataCorrupted, validate(0, 5, false, not_commit, true));
    try testing.expectError(error.DataCorrupted, validate(0, 5, false, @as(?u64, 5), true));
    try testing.expectEqual(@as(?u64, 4), try validate(0, 5, false, @as(?u64, 4), true));
    // Replaying from a pruned floor is impossible; keyless (no replay) does not care.
    try testing.expectError(error.HistoricalFloorPruned, validate(3, 5, false, @as(?u64, 2), true));
    try testing.expectEqual(@as(?u64, 2), try validate(3, 5, false, @as(?u64, 2), false));
}
