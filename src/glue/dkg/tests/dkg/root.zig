//! One-shot DKG end-to-end tests (commonware `glue::dkg::tests::dkg`): ceremonies of the
//! bootstrap engine on the simulated network. Commonware's `slow` group runs only with
//! -Dslow-tests.

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const utils = @import("utils");
const harness = @import("harness.zig");

const Duration = utils.time.Duration;
const gpa = testing.allocator;

fn skip_slow() error{SkipZigTest}!void {
    if (!build_options.slow_tests) return error.SkipZigTest;
}

test "dkg e2e completes for all participants" {
    var engine = try harness.DkgEngine.create(gpa, 4);
    defer engine.deinit();
    try harness.run_plan(&engine, harness.good_link, &.{}, .success, &.{0});
}

// A participant that never receives consensus traffic completes by fetching the final
// block's finalization through marshal.
test "dkg e2e deaf participant completes" {
    var engine = try harness.DkgEngine.create(gpa, 4);
    defer engine.deinit();
    engine.deaf = 0;
    try harness.run_plan(&engine, harness.good_link, &.{}, .success, &.{0});
}

test "dkg e2e lossy network" {
    try skip_slow();
    var engine = try harness.DkgEngine.create(gpa, 4);
    defer engine.deinit();
    const lossy: @TypeOf(harness.good_link) = .{
        .latency = Duration.from_millis(60),
        .jitter = Duration.from_millis(20),
        .success_rate = 0.75,
    };
    try harness.run_plan(&engine, lossy, &.{}, .success, &.{0});
}

test "dkg e2e filtered dkg channel fails" {
    try skip_slow();
    var engine = try harness.DkgEngine.create(gpa, 4);
    defer engine.deinit();
    engine.filtered_dkg = true;
    try harness.run_plan(&engine, harness.good_link, &.{}, .failure, &.{0});
}

test {
    _ = @import("properties_test.zig");
    _ = @import("single.zig");
}
