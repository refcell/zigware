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
