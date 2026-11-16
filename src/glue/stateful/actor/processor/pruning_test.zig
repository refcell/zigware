//! commonware `actor/processor/mod.rs` tests of the prune schedule, `PruneConfig`, and the
//! finalization boundary. The panic test of an invalid config is an error here.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus");
const pruning = @import("pruning.zig");

const gpa = testing.allocator;
const Height = consensus.types.Height;
const PruneConfig = pruning.PruneConfig;
const Pruning = pruning.Pruning(u64);
const Prune = pruning.Prune(u64);

fn prune(marshal: u64, barrier: u64, target: u64) ?Prune {
    return .{
        .marshal_height = .new(marshal),
        .barrier_height = .new(barrier),
        .qmdb_target = target,
    };
}

fn expect_observe(schedule: *Pruning, height: u64, target: u64, expected: ?Prune) !void {
    const actual = schedule.observe(.new(height), target);
    try testing.expectEqual(expected == null, actual == null);
    if (expected) |e| {
        try testing.expectEqual(e.marshal_height.get(), actual.?.marshal_height.get());
        try testing.expectEqual(e.barrier_height.get(), actual.?.barrier_height.get());
        try testing.expectEqual(e.qmdb_target, actual.?.qmdb_target);
    }
}

test "stateful pruning: waits for a full retention window" {
    const config: PruneConfig = .{
        .maintenance_interval = 1,
        .retained_marshal_blocks = 1,
        .retained_qmdb_blocks = 1,
    };
    var schedule = try Pruning.init(gpa, config, 2, 0);
    defer schedule.deinit(gpa);
    try expect_observe(&schedule, 1, 10, null);
    try expect_observe(&schedule, 2, 20, null);
    try expect_observe(&schedule, 3, 30, null);
    try expect_observe(&schedule, 4, 40, prune(1, 1, 10));
}

test "stateful pruning: uses the oldest retained target" {
    const config: PruneConfig = .{
        .maintenance_interval = 1,
        .retained_marshal_blocks = 1,
        .retained_qmdb_blocks = 1,
    };
    var schedule = try Pruning.init(gpa, config, 1, 0);
    defer schedule.deinit(gpa);
    try expect_observe(&schedule, 1, 10, null);
    try expect_observe(&schedule, 2, 20, null);
    try expect_observe(&schedule, 3, 30, prune(1, 1, 10));
    try expect_observe(&schedule, 4, 40, prune(2, 2, 20));
}

test "stateful pruning: can retain more marshal history than qmdb" {
    const config: PruneConfig = .{
        .maintenance_interval = 3,
        .retained_marshal_blocks = 3,
        .retained_qmdb_blocks = 1,
    };
    var schedule = try Pruning.init(gpa, config, 1, 0);
    defer schedule.deinit(gpa);
    for (1..6) |height| try expect_observe(&schedule, height, height * 10, null);
    try expect_observe(&schedule, 6, 60, prune(2, 4, 40));
}

test "stateful pruning: uses the maintenance phase" {
    const config: PruneConfig = .{
        .maintenance_interval = 5,
        .retained_marshal_blocks = 1,
        .retained_qmdb_blocks = 0,
    };
    var schedule = try Pruning.init(gpa, config, 1, 2);
    defer schedule.deinit(gpa);
    for (1..7) |height| try expect_observe(&schedule, height, height * 10, null);
    try expect_observe(&schedule, 7, 70, prune(5, 6, 60));
    for (8..12) |height| try expect_observe(&schedule, height, height * 10, null);
    try expect_observe(&schedule, 12, 120, prune(10, 11, 110));
}

test "stateful pruning: config validation" {
    const invalid: PruneConfig = .{
        .maintenance_interval = 1,
        .retained_marshal_blocks = 1,
        .retained_qmdb_blocks = 2,
    };
    try testing.expectError(error.InvalidPruneConfig, invalid.validate());
    try testing.expectError(error.InvalidPruneConfig, Pruning.init(gpa, invalid, 1, 0));
    const zero: PruneConfig = .{
        .maintenance_interval = 1,
        .retained_marshal_blocks = 0,
        .retained_qmdb_blocks = 0,
    };
    try zero.validate();
    // The phase must lie within the interval.
    try testing.expectError(error.InvalidPruneConfig, Pruning.init(gpa, zero, 1, 1));
}

test "stateful pruning: the finalization boundary follows completed descendants" {
    const Step = pruning.ExecutionStep(u64);
    const round = struct {
        fn at(view: u64) consensus.Round {
            return .new(.zero(), .new(view));
        }
    }.at;
    const step = struct {
        fn make(digest: u64, parent: u64, view: u64) Step {
            return .{ .digest = digest, .parent = parent, .round = round(view) };
        }
    }.make;
    var boundary: pruning.FinalizationBoundary(u64) = .{ .digest = 10, .round = round(10) };
    defer boundary.deinit(gpa);
    try boundary.compatible.put(gpa, 10, {});
    try boundary.compatible.put(gpa, 11, {});

    // The winner must finish. A step on a cached descendant continues, while a step on an
    // uncached parent is rejected.
    try testing.expectEqual(.join, boundary.disposition(&step(10, 1, 10)));
    try testing.expectEqual(.retain, boundary.disposition(&step(12, 11, 12)));
    try testing.expectEqual(.reject, boundary.disposition(&step(13, 12, 13)));

    // A completed retained step can parent later steps. A step not in a later round than the
    // finalized block, or whose parent is unknown, stays rejected.
    try boundary.completed(gpa, &step(12, 11, 12));
    try testing.expectEqual(.retain, boundary.disposition(&step(13, 12, 13)));
    try testing.expectEqual(.reject, boundary.disposition(&step(14, 12, 10)));
    try testing.expectEqual(.reject, boundary.disposition(&step(20, 19, 11)));
}
