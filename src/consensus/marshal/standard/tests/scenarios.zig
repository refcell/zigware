//! The harness scenarios on the standard variant (commonware `standard/mod.rs`,
//! `test_standard_finalize_*` and `test_standard_hailstorm_*`). commonware runs each on
//! `InlineHarness` and `DeferredHarness`, which only delegate to `StandardHarness`; here each
//! runs once on it.

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const harness = @import("../../mocks/harness.zig");
const scenarios = @import("../../mocks/scenarios.zig");

const gpa = testing.allocator;
const Finalize = scenarios.Finalize(harness.StandardHarness);

/// Seeds per determinism check: commonware's five under `-Dslow-tests`, one otherwise.
const seeds: u64 = if (build_options.slow_tests) 5 else 1;

/// Two runs of one seed reach the same audit state (`assert_finalize_deterministic`).
fn expect_finalize_deterministic(
    seed: u64,
    link: @TypeOf(harness.link),
    quorum_sees_finalization: bool,
) !void {
    const first = try Finalize.run(gpa, seed, link, quorum_sees_finalization);
    const second = try Finalize.run(gpa, seed, link, quorum_sees_finalization);
    try testing.expectEqual(first, second);
}

/// Delivery once stalled at about height 50 of 160 while resolver.p2p's engine fell behind on
/// network responses; fixed in the resolver engine.
const resolver_keeps_up = true;

test "standard finalize good links" {
    if (!resolver_keeps_up) return error.SkipZigTest;
    for (0..seeds) |seed| try expect_finalize_deterministic(seed, harness.link, false);
}

const Hailstorm = scenarios.Hailstorm(harness.StandardHarness);

/// Two runs of one storm reach the same audit state (`assert_hailstorm_deterministic`).
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
        .link = harness.link,
    };
}

// commonware's hailstorm tests are all in its slow group; outside `-Dslow-tests` one short
// storm per shape keeps the crash and recovery path covered.
test "standard hailstorm restarts" {
    if (!build_options.slow_tests) return expect_hailstorm_deterministic(0, storm(2, 3, 1));
    for (0..2) |seed| try expect_hailstorm_deterministic(seed, storm(4, 4, 1));
}

test "standard hailstorm multi restarts" {
    if (!build_options.slow_tests) return expect_hailstorm_deterministic(1, storm(2, 3, 2));
    for (0..2) |seed| try expect_hailstorm_deterministic(seed, storm(4, 4, 2));
}

// A longer storm crosses the epoch boundary while validators are down, so recovery
// backfills certificates from a later epoch than the restarted validator last stored.
test "standard hailstorm restarts across epochs" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    _ = try Hailstorm.run(gpa, 13, storm(5, 5, 2));
}
