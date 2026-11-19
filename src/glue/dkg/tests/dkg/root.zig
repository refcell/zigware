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

const simulate = @import("../../../simulate/mod.zig");
const Key = harness.DkgEngine.PublicKey;
const Schedule = simulate.action.Schedule(Key);
const Action = simulate.action.Action(Key);

test "dkg e2e scheduled restart" {
    try skip_slow();
    var engine = try harness.DkgEngine.create(gpa, 4);
    defer engine.deinit();
    const restarted = engine.participant(0);
    var schedule: Schedule = .empty;
    defer schedule.deinit(gpa);
    try schedule.add(gpa, .from_millis(80), .{ .crash = restarted });
    try schedule.add(gpa, .from_millis(250), .{ .restart = restarted });
    const crashes = [_]simulate.action.Crash(Key){.{ .schedule = &schedule }};
    try harness.run_plan(&engine, harness.good_link, &crashes, .success, &.{0});
    try testing.expectEqual(@as(usize, 2), engine.inits_of(0).len);
}

// Random crashes can restart a participant that already persisted its epoch-zero share,
// including one that completed, and every participant still completes.
test "dkg e2e random crashes" {
    try skip_slow();
    var engine = try harness.DkgEngine.create(gpa, 4);
    defer engine.deinit();
    const crashes = [_]simulate.action.Crash(Key){.{ .random = .{
        .frequency = .from_millis(250),
        .downtime = .from_millis(50),
        .count = 1,
    } }};
    var seeds: [16]u64 = undefined;
    for (&seeds, 0..) |*seed, index| seed.* = index;
    try harness.run_plan(&engine, harness.good_link, &crashes, .success, &seeds);
}

// A participant that falls behind catches up from a participant that restarted after
// completing, and that restarted participant is the only peer it can reach.
test "dkg e2e laggard catches up from restarted participant" {
    try skip_slow();
    var engine = try harness.DkgEngine.create(gpa, 4);
    defer engine.deinit();
    const restarted = engine.participant(0);
    const laggard = engine.participant(3);
    var cut = harness.good_link;
    cut.success_rate = 0.0;
    var schedule: Schedule = .empty;
    defer schedule.deinit(gpa);
    // The laggard crashes mid-ceremony and loses its links to every peer but the
    // participant that will restart.
    const mid: Duration = .from_millis(1500);
    try schedule.add(gpa, mid, .{ .crash = laggard });
    for ([_]Key{ engine.participant(1), engine.participant(2) }) |peer| {
        const into: Action = .{ .update_link = .{ .from = peer, .to = laggard, .link = cut } };
        const out: Action = .{ .update_link = .{ .from = laggard, .to = peer, .link = cut } };
        try schedule.add(gpa, mid, into);
        try schedule.add(gpa, mid, out);
    }
    // The others complete; one restarts with its share, and the laggard returns afterward.
    // Commonware crashes at 4.5 s; the three survivors here complete near 6.9 s (seed 0), so
    // the rest of the schedule is 4.5 s later, with commonware's gaps.
    try schedule.add(gpa, .from_millis(9000), .{ .crash = restarted });
    try schedule.add(gpa, .from_millis(9100), .{ .restart = restarted });
    try schedule.add(gpa, .from_millis(9500), .{ .restart = laggard });
    const crashes = [_]simulate.action.Crash(Key){.{ .schedule = &schedule }};
    try harness.run_plan(&engine, harness.good_link, &crashes, .success, &.{0});
    // Guard the schedule: the restart held a share and the laggard never did.
    try testing.expectEqualSlices(bool, &.{ false, true }, engine.inits_of(0));
    try testing.expectEqualSlices(bool, &.{ false, false }, engine.inits_of(3));
}

test {
    _ = @import("properties_test.zig");
    _ = @import("single.zig");
}
