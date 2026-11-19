//! Stateful end-to-end tests (commonware `glue/src/stateful/tests/mod.rs`): validators run
//! Simplex, marshal, and the `Stateful` actor over QMDB on the simulated network. Commonware's
//! `slow` group runs only with -Dslow-tests; one short finalize plan always runs.

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const p2p = @import("p2p");
const utils = @import("utils");
const consensus = @import("consensus");
const simulate = @import("../../simulate/mod.zig");
const single = @import("single_db.zig");
const properties = @import("properties.zig");

const Duration = utils.time.Duration;
const Key = single.Key;
const Engine = single.SingleDbEngine;
const Plan = simulate.Plan(Engine);
const Crash = simulate.Crash(Key);
const Schedule = simulate.Schedule(Key);
const gpa = testing.allocator;

fn skip_slow() error{SkipZigTest}!void {
    if (!build_options.slow_tests) return error.SkipZigTest;
}

/// Seeds `0..count`.
fn seeds(comptime count: usize) [count]u64 {
    var result: [count]u64 = undefined;
    for (&result, 0..) |*seed, index| seed.* = index;
    return result;
}

const Options = struct {
    height: u64,
    crashes: []const Crash = &.{},
    link: p2p.simulated.Link = simulate.plan.default_link,
    timeout: ?Duration = null,
    pruning: bool = false,
};

/// Runs `engine` once per seed until every validator processed `options.height`, then checks
/// that they agree on its block (commonware's `PlanBuilder` runs). Returns each run's audit
/// state.
fn run_plan(
    engine: *const Engine,
    seed_list: []const u64,
    options: Options,
    states: ?[][8]u8,
) !void {
    const exit_condition: simulate.ProcessedHeightAtLeast = .{ .required = options.height };
    const agreement: properties.BlockAgreementAtHeight = .{ .height = options.height };
    const pruned: properties.MarshalPrunedBelow = .{ .pruned_height = 1, .retained_height = 95 };
    const qmdb: properties.QmdbPruned = .{ .min_oldest_retained = 1 };
    const all = [_]Plan.Property{ .from(&agreement), .from(&pruned), .from(&qmdb) };
    for (seed_list, 0..) |seed, index| {
        const plan: Plan = .{
            .engine = engine,
            .seed = seed,
            .link = options.link,
            .crashes = options.crashes,
            .exit_condition = .from(&exit_condition),
            .timeout = options.timeout,
            .properties = if (options.pruning) &all else all[0..1],
        };
        var result = try plan.run(gpa);
        defer result.deinit();
        if (states) |list| list[index] = result.state;
    }
}

test "stateful e2e: validators finalize and commit" {
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    try run_plan(&engine, &.{0}, .{ .height = 20 }, null);
}

test "stateful e2e: all validators finalize and commit" {
    try skip_slow();
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    try run_plan(&engine, &seeds(5), .{ .height = 100 }, null);
}

const good_link: p2p.simulated.Link = .{
    .latency = Duration.from_millis(10),
    .jitter = Duration.from_millis(5),
    .success_rate = 1.0,
};

// commonware runs every scenario on `SingleDbEngine` and `MultiDbEngine`; the multi-database
// engine is not ported yet, so these run the single-database engine only.

// Adaptation: zigware's database barriers are synchronous, so a failed sync surfaces as an
// actor error and the validator stays down until its scheduled restart (commonware's engine
// handle ends the same way).
test "stateful e2e: all validators finalize and commit with storage faults" {
    try skip_slow();
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    engine.tolerate_failures = true;
    var schedule: Schedule = .empty;
    defer schedule.deinit(gpa);
    const faulty: simulate.FaultConfig = .{ .sync_rate = utils.Probability.literal(0.01) };
    try schedule.add(gpa, .from_secs(1), .{ .set_storage_fault = faulty });
    try schedule.add(gpa, .from_secs(2), .{ .set_storage_fault = .{} });
    for (engine.participants(), 0..) |participant, index| {
        const at = Duration.from_millis(2500 + 250 * @as(u64, @intCast(index)));
        try schedule.add(gpa, at, .{ .restart = participant });
    }
    const crashes = [_]Crash{.{ .schedule = &schedule }};
    const options: Options = .{ .height = 100, .crashes = &crashes, .timeout = .from_secs(45) };
    try run_plan(&engine, &seeds(5), options, null);
}

test "stateful e2e: deterministic across seeds" {
    try skip_slow();
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    var first: [5][8]u8 = undefined;
    var second: [5][8]u8 = undefined;
    try run_plan(&engine, &seeds(5), .{ .height = 20 }, &first);
    try run_plan(&engine, &seeds(5), .{ .height = 20 }, &second);
    for (first, second) |left, right| try testing.expectEqualSlices(u8, &left, &right);
}

test "stateful e2e: crash and restart one validator" {
    try skip_slow();
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    const validator = engine.participants()[0];
    var schedule: Schedule = .empty;
    defer schedule.deinit(gpa);
    try schedule.add(gpa, .from_millis(2500), .{ .crash = validator });
    try schedule.add(gpa, .from_millis(5000), .{ .restart = validator });
    const crashes = [_]Crash{.{ .schedule = &schedule }};
    try run_plan(&engine, &seeds(5), .{ .height = 50, .crashes = &crashes }, null);
}

// Pruning runs with `max_pending_acks = 1`, `retained_marshal_blocks = 10`, and
// `retained_qmdb_blocks = 0`: marshal drops height 1 but serves 95, and QMDB discards its
// first operation, which only the deferred prune step can do.
test "stateful e2e: pruning bounds finalized history" {
    try skip_slow();
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    try run_plan(&engine, &seeds(5), .{ .height = 100, .pruning = true }, null);
}

test "stateful e2e: delayed start one validator" {
    try skip_slow();
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    const crashes = [_]Crash{.{ .delay_round = .{
        .participants = engine.participants()[0..1],
        .round = .new(.zero(), .new(5)),
    } }};
    try run_plan(&engine, &seeds(5), .{ .height = 20, .crashes = &crashes }, null);
}

test "stateful e2e: lossy network" {
    try skip_slow();
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    const lossy: p2p.simulated.Link = .{
        .latency = Duration.from_millis(200),
        .jitter = Duration.from_millis(150),
        .success_rate = 0.7,
    };
    try run_plan(&engine, &seeds(5), .{ .height = 20, .link = lossy }, null);
}

fn run_random(frequency_ms: u64, downtime_ms: u64, count: usize, height: u64) !void {
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    const crashes = [_]Crash{.{ .random = .{
        .frequency = .from_millis(frequency_ms),
        .downtime = .from_millis(downtime_ms),
        .count = count,
    } }};
    try run_plan(&engine, &seeds(5), .{ .height = height, .crashes = &crashes }, null);
}

test "stateful e2e: random crashes" {
    try skip_slow();
    try run_random(1500, 1000, 1, 50);
}

test "stateful e2e: many concurrent crashes" {
    try skip_slow();
    try run_random(1500, 1000, 3, 50);
}

test "stateful e2e: rapid crashes" {
    try skip_slow();
    try run_random(500, 100, 1, 50);
}

// Slow links make views long enough that the run spans many full-cluster outages; frequency
// minus downtime stays above the certification timeout so a certificate forms between them.
test "stateful e2e: full cluster outage and recovery" {
    try skip_slow();
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    const slow: p2p.simulated.Link = .{
        .latency = Duration.from_millis(100),
        .jitter = Duration.from_millis(5),
        .success_rate = 1.0,
    };
    const crashes = [_]Crash{.{ .random = .{
        .frequency = .from_millis(5000),
        .downtime = .from_millis(500),
        .count = single.num_validators,
    } }};
    const options: Options = .{ .height = 300, .crashes = &crashes, .link = slow };
    try run_plan(&engine, &seeds(5), options, null);
}

// One validator loses every link at 500 ms and heals at 2 s, recovering without a restart.
test "stateful e2e: network partition and rejoin" {
    try skip_slow();
    var engine = try Engine.create(gpa, single.num_validators);
    defer engine.deinit();
    const participants = engine.participants();
    const isolated = participants[0];
    const dead: p2p.simulated.Link = .{
        .latency = Duration.from_secs(1),
        .jitter = Duration.from_millis(0),
        .success_rate = 0.0,
    };
    var schedule: Schedule = .empty;
    defer schedule.deinit(gpa);
    for (participants[1..]) |peer| {
        const out: simulate.Action(Key) = .{
            .update_link = .{ .from = isolated, .to = peer, .link = dead },
        };
        const in: simulate.Action(Key) = .{
            .update_link = .{ .from = peer, .to = isolated, .link = dead },
        };
        try schedule.add(gpa, .from_millis(500), out);
        try schedule.add(gpa, .from_millis(500), in);
    }
    try schedule.add(gpa, .from_secs(2), .{ .heal = good_link });
    const crashes = [_]Crash{.{ .schedule = &schedule }};
    try run_plan(&engine, &seeds(5), .{ .height = 50, .crashes = &crashes }, null);
}
