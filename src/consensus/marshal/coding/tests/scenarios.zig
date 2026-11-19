//! The harness scenarios on the coding variant (commonware `coding/mod.rs`,
//! `test_coding_finalize_*`), on the shared scenarios (mocks/scenarios.zig) over
//! `CodingHarness`.
//!
//! commonware runs these in its `slow` test group over five seeds. Here the good-links run
//! takes one seed in every build, and the full matrix of links, finalization modes, and five
//! seeds runs under `-Dslow-tests` or an optimized build.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const build_options = @import("build_options");
const shared = @import("../../mocks/harness.zig");
const scenarios = @import("../../mocks/scenarios.zig");
const harness = @import("../harness.zig");

const gpa = testing.allocator;
const Finalize = scenarios.Finalize(harness.CodingHarness);
const slow = !(builtin.mode == .debug and !build_options.slow_tests);
const seeds: u64 = if (slow) 5 else 1;

/// Two runs of one seed reach the same audit state.
fn expect_finalize_deterministic(
    seed: u64,
    link: @TypeOf(shared.link),
    quorum_sees_finalization: bool,
) !void {
    const first = try Finalize.run(gpa, seed, link, quorum_sees_finalization);
    const second = try Finalize.run(gpa, seed, link, quorum_sees_finalization);
    try testing.expectEqual(first, second);
}

test "coding finalize good links" {
    for (0..seeds) |seed| try expect_finalize_deterministic(seed, shared.link, false);
}

test "coding finalize bad links" {
    if (!slow) return error.SkipZigTest;
    for (0..seeds) |seed| try expect_finalize_deterministic(seed, shared.unreliable_link, false);
}

test "coding finalize good links quorum sees finalization" {
    if (!slow) return error.SkipZigTest;
    for (0..seeds) |seed| try expect_finalize_deterministic(seed, shared.link, true);
}

test "coding finalize bad links quorum sees finalization" {
    if (!slow) return error.SkipZigTest;
    for (0..seeds) |seed| try expect_finalize_deterministic(seed, shared.unreliable_link, true);
}

const Hailstorm = scenarios.Hailstorm(harness.CodingHarness);

/// Two runs of one storm reach the same audit state.
fn expect_hailstorm_deterministic(seed: u64, options: Hailstorm.Options) !void {
    const first = try Hailstorm.run(gpa, seed, options);
    const second = try Hailstorm.run(gpa, seed, options);
    try testing.expectEqual(first, second);
}

fn storm(shutdowns: u32, interval: u64, max_down: u32) Hailstorm.Options {
    return .{
        .shutdowns = shutdowns,
        .interval = interval,
        .max_down = max_down,
        .link = shared.link,
    };
}

// commonware's hailstorm tests are in its slow group; outside slow builds one short storm per
// shape keeps the coding crash and recovery path covered.
test "coding hailstorm restarts" {
    if (!slow) return expect_hailstorm_deterministic(0, storm(2, 3, 1));
    for (0..2) |seed| try expect_hailstorm_deterministic(seed, storm(4, 4, 1));
}

test "coding hailstorm multi restarts" {
    if (!slow) return expect_hailstorm_deterministic(1, storm(2, 3, 2));
    for (0..2) |seed| try expect_hailstorm_deterministic(seed, storm(4, 4, 2));
}

// A longer storm crosses the epoch boundary while validators are down, so recovery
// backfills certificates from a later epoch than the restarted validator last stored.
test "coding hailstorm restarts across epochs" {
    if (!slow) return error.SkipZigTest;
    _ = try Hailstorm.run(gpa, 13, storm(5, 5, 2));
}

const AckPipeline = scenarios.AckPipeline(harness.CodingHarness);

test "coding ack pipeline backlog" {
    try AckPipeline.backlog(gpa);
}

test "coding ack pipeline backlog persists on restart" {
    try AckPipeline.persists_on_restart(gpa);
}
