//! Tests for the shared QMDB functions in qmdb/mod.rs.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
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

/// A log of `floors`, where null is a non-commit, retained from `start`.
const FloorLog = struct {
    floors: []const ?u64,
    start: u64,

    const Op = struct {
        floor: ?u64,

        pub fn inactivity_floor(self: *const Op) ?u64 {
            return self.floor;
        }

        pub fn deinit(_: *Op, _: std.mem.Allocator) void {}
    };

    pub fn bounds(self: *const FloorLog) struct { start: u64, end: u64 } {
        return .{ .start = self.start, .end = self.floors.len };
    }

    pub fn read(self: *const FloorLog, _: std.mem.Allocator, location: u64) !Op {
        assert(location >= self.start and location < self.floors.len);
        return .{ .floor = self.floors[@intCast(location)] };
    }
};

test "commit_floor_at reads the floor of the commit at a size" {
    const gpa = testing.allocator;
    // 0: commit(0), 1: set, 2: commit(1), 3: set, 4: commit(5), past its own location.
    const log: FloorLog = .{ .floors = &.{ 0, null, 1, null, 5 }, .start = 1 };
    try testing.expectEqual(@as(?u64, 1), try qmdb.commit_floor_at(gpa, &log, 3));
    try testing.expectEqual(@as(?u64, null), try qmdb.commit_floor_at(gpa, &log, 4));
    try testing.expectError(error.DataCorrupted, qmdb.commit_floor_at(gpa, &log, 5));
    try testing.expectError(error.ItemPruned, qmdb.commit_floor_at(gpa, &log, 1));
    try testing.expectError(error.HistoricalFloorPruned, qmdb.commit_floor_at(gpa, &log, 0));
    // The variant that requires a commit refuses a retained non-commit.
    try testing.expectEqual(@as(u64, 1), try qmdb.find_inactivity_floor_at(gpa, &log, 3));
    try testing.expectError(
        error.HistoricalFloorPruned,
        qmdb.find_inactivity_floor_at(gpa, &log, 4),
    );
}
