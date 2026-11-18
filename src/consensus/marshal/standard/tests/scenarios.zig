//! The harness scenarios on the standard variant (commonware `standard/mod.rs`,
//! `test_standard_finalize_*`). commonware runs each on `InlineHarness` and
//! `DeferredHarness`, which only delegate to `StandardHarness`; here each runs once on it.

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
