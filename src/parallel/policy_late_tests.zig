//! More tests of `policy.zig`, ported from commonware's `parallel/src/policy.rs` with the same
//! numbers: spawn placement driven as the strategy drives it, confined and interleaved run
//! callers, and worker spawns. A call site is a constant, as `Location::caller()` is one there.

const std = @import("std");
const testing = std.testing;
const policy_module = @import("policy.zig");

const Policy = policy_module.Policy;
const Placement = policy_module.Placement;
const SpawnExecution = policy_module.SpawnExecution;
const RunExecution = policy_module.RunExecution;
const RunPlan = policy_module.RunPlan;
const Pools = policy_module.Pools;
const SpawnPlan = policy_module.SpawnPlan;
const Spawner = policy_module.Spawner;
const resample_interval: usize = policy_module.resample_interval;
const max_shift = policy_module.max_resample_shift;

/// The strategy parallelism the tests plan with.
const parallelism = 4;
const site: usize = 0x5174;

fn us(micros: u64) u64 {
    return micros * std.time.ns_per_us;
}

fn ms(millis: u64) u64 {
    return millis * std.time.ns_per_ms;
}

/// One admitted root: its placement and whether it was measured.
const Root = struct { placement: Placement, measured: bool };

const roots_max = 6 * resample_interval;

/// Admitted roots in call order.
const Roots = struct {
    items: [roots_max]Root = undefined,
    len: usize = 0,

    fn slice(roots: *const Roots) []const Root {
        return roots.items[0..roots.len];
    }

    /// The index of the `nth` root (from 0) placed Wide.
    fn wide(roots: *const Roots, nth: usize) usize {
        var seen: usize = 0;
        for (roots.slice(), 0..) |root, index| {
            if (root.placement != .wide) continue;
            if (seen == nth) return index;
            seen += 1;
        }
        unreachable;
    }

    /// Whether every root from `first` on is placed `placement`.
    fn all_from(roots: *const Roots, first: usize, placement: Placement) bool {
        for (roots.slice()[first..]) |root| {
            if (root.placement != placement) return false;
        }
        return true;
    }
};

/// Drives `calls` admitted external roots of `site` as the strategy does. A measured root
/// reports `walls.wall(placement)` as its job time, with a 50 us hand-off on top.
fn drive_roots(policy: *Policy, calls: usize, walls: anytype) Roots {
    std.debug.assert(calls <= roots_max);
    var roots: Roots = .{};
    for (0..calls) |_| {
        const chosen = policy.choose_spawn(site, 64, parallelism, .outside);
        const plan = policy.choose_spawn_placement(site, 64, parallelism, chosen);
        const placement = plan.placement.?;
        if (plan.measure) {
            const job_ns = walls.wall(placement);
            policy.record_spawn_job(site, 64, parallelism, plan, job_ns);
            policy.record_spawn_round_trip(site, 64, parallelism, plan, job_ns + us(50), job_ns);
        }
        roots.items[roots.len] = .{ .placement = placement, .measured = plan.measure };
        roots.len += 1;
    }
    std.debug.assert(roots.len == calls);
    return roots;
}

/// Wide walls of `wide_us` except on its `odd`-th measured run (from 1), and Local walls of
/// `local_us`.
const Walls = struct {
    wide_us: u64,
    local_us: u64,
    odd: u32 = 0,
    odd_us: u64 = 0,
    measured: u32 = 0,

    fn wall(walls: *Walls, placement: Placement) u64 {
        return switch (placement) {
            .local => us(walls.local_us),
            .wide => blk: {
                walls.measured += 1;
                break :blk us(if (walls.measured == walls.odd) walls.odd_us else walls.wide_us);
            },
        };
    }
};

test "spawn placement recovers a cold loser" {
    // commonware `spawn_placement_recovers_cold_loser`: Wide's seed and first probe ran cold,
    // so Local leads. Wide's next probe beats Local, and Wide takes the lead at once.
    const Cold = struct {
        measured: u32 = 0,
        fn wall(cold: *@This(), placement: Placement) u64 {
            if (placement == .local) return us(5_200);
            cold.measured += 1;
            return us(switch (cold.measured) {
                1 => 10_000,
                2 => 5_600,
                else => 4_700,
            });
        }
    };
    var policy = Policy.init(testing.io);
    var cold: Cold = .{};
    const roots = drive_roots(&policy, 2 * resample_interval, &cold);
    const probe = roots.wide(2);
    try testing.expect(roots.all_from(probe + 1, .wide));
}

test "spawn placement recovers after a spike" {
    // commonware `spawn_placement_recovers_after_spike`: one slow sample of the leading Wide
    // hands the lead to Local, and Wide's first probe after it restores the lead for good.
    var policy = Policy.init(testing.io);
    var walls: Walls = .{ .wide_us = 4_660, .local_us = 5_250, .odd = 2, .odd_us = 12_300 };
    const roots = drive_roots(&policy, 2 * resample_interval, &walls);
    var spike: ?usize = null;
    var measured_wide: usize = 0;
    for (roots.slice(), 0..) |root, index| {
        if (root.placement != .wide or !root.measured) continue;
        measured_wide += 1;
        if (measured_wide == 2) {
            spike = index;
            break;
        }
    }
    var probe: ?usize = null;
    for (roots.slice()[spike.? + 1 ..], spike.? + 1..) |root, index| {
        if (root.placement == .wide) {
            probe = index;
            break;
        }
    }
    // Local led after the spike, then the faster probe gave Wide the lead back.
    try testing.expect(probe.? > spike.? + 1);
    try testing.expect(roots.all_from(probe.? + 1, .wide));
}

test "spawn placement keeps a slow probe damped" {
    // commonware `spawn_placement_slow_probe_stays_damped`: a slow probe of the loser blends
    // into its estimate, so the next probe follows the usual backoff, not the outlier's.
    var policy = Policy.init(testing.io);
    var walls: Walls = .{ .wide_us = 5_500, .local_us = 5_200, .odd = 3, .odd_us = 30_000 };
    const roots = drive_roots(&policy, 6 * resample_interval, &walls);
    try testing.expect(roots.wide(3) - roots.wide(2) <= resample_interval << 2);
}

test "spawn placement reverts a lucky probe" {
    // commonware `spawn_placement_reverts_lucky_probe`: a lucky probe hands the lead to the
    // slower Wide, and Wide's true wall time returns it to Local within two measured runs.
    var policy = Policy.init(testing.io);
    var walls: Walls = .{ .wide_us = 5_200, .local_us = 4_700, .odd = 3, .odd_us = 4_500 };
    const roots = drive_roots(&policy, 2 * resample_interval, &walls);
    const lucky = roots.wide(2);
    var back: ?usize = null;
    for (roots.slice()[lucky..], lucky..) |root, index| {
        if (root.placement == .local) {
            back = index;
            break;
        }
    }
    try testing.expect(back.? > lucky + 1);
    var measured: usize = 0;
    for (roots.slice()[lucky + 1 .. back.?]) |root| measured += @intFromBool(root.measured);
    try testing.expect(measured <= 2);
}

test "a spawn round trip seeds no placement" {
    // commonware `spawn_round_trip_skips_placement`: a round trip records only the hand-off
    // overhead, so a placement whose job sample never arrives is offered again.
    var policy = Policy.init(testing.io);
    const chosen = policy.choose_spawn(site, 64, parallelism, .outside);
    const plan = policy.choose_spawn_placement(site, 64, parallelism, chosen);
    try testing.expectEqual(@as(?Placement, .wide), plan.placement);
    policy.record_spawn_round_trip(site, 64, parallelism, plan, std.time.ns_per_s, ms(2));
    const entry = policy.spawn_entry(site, 64, parallelism).?;
    try testing.expectEqual(@as(?u64, null), entry.placement.estimate(.wide));
    try testing.expectEqual(@as(?u64, null), entry.placement.estimate(.local));
    const again = policy.choose_spawn(site, 64, parallelism, .outside);
    const placed = policy.choose_spawn_placement(site, 64, parallelism, again);
    try testing.expectEqual(@as(?Placement, .wide), placed.placement);
}

/// A stretch of overflow roots, offloaded without a placement.
fn overflow(policy: *Policy) !void {
    for (0..2 * resample_interval) |_| {
        const plan = policy.choose_spawn(site, 64, parallelism, .outside);
        try testing.expectEqual(SpawnExecution.offload, plan.execution);
        try testing.expectEqual(@as(?Placement, null), plan.placement);
        if (plan.measure) policy.record_spawn_job(site, 64, parallelism, plan, ms(8));
    }
}

test "spawn overflow leaves the placement seeds untouched" {
    // commonware `spawn_overflow_leaves_seeds_untouched`: overflow job samples train only the
    // job estimate, so the seeds and the loser probe wait for admitted roots.
    var policy = Policy.init(testing.io);
    try overflow(&policy);
    const entry = policy.spawn_entry(site, 64, parallelism).?;
    try testing.expectEqual(@as(?u64, null), entry.placement.estimate(.wide));
    try testing.expectEqual(@as(?u64, null), entry.placement.estimate(.local));
    const steps = [_]struct { placement: Placement, millis: u64 }{
        .{ .placement = .wide, .millis = 8 },
        .{ .placement = .local, .millis = 2 },
        .{ .placement = .wide, .millis = 8 },
        .{ .placement = .local, .millis = 2 },
    };
    for (steps) |step| {
        try overflow(&policy);
        const chosen = policy.choose_spawn(site, 64, parallelism, .outside);
        const plan = policy.choose_spawn_placement(site, 64, parallelism, chosen);
        try testing.expectEqual(@as(?Placement, step.placement), plan.placement);
        policy.record_spawn_job(site, 64, parallelism, plan, ms(step.millis));
    }
}

const either: Pools = .either;

/// The placements of a caller confined to `placement`.
fn confined(placement: Placement) Pools {
    return .{ .fixed = placement };
}

/// Wall times in microseconds of serial and of a parallel run on each placement.
const RunWalls = struct {
    serial_us: u64,
    wide_us: u64,
    local_us: u64,

    /// Serial walls of `serial`, a parallel run on `pool` of `own`, and on the other of `rest`.
    fn of(pool: Placement, serial: u64, own: u64, rest: u64) RunWalls {
        return switch (pool) {
            .wide => .{ .serial_us = serial, .wide_us = own, .local_us = rest },
            .local => .{ .serial_us = serial, .wide_us = rest, .local_us = own },
        };
    }

    fn wall(walls: RunWalls, execution: RunExecution, placement: Placement) u64 {
        if (execution == .serial) return us(walls.serial_us);
        return us(switch (placement) {
            .wide => walls.wide_us,
            .local => walls.local_us,
        });
    }
};

/// A run's execution path and placement.
const Call = struct { execution: RunExecution, placement: Placement };

/// Records a run that followed `plan` with wall time `wall_ns`, and a parallel run's busy time
/// as `parallelism` workers busy for it, whatever parallelism its key carries.
fn record_perfect_run(policy: *Policy, planned: usize, plan: RunPlan, wall_ns: u64) void {
    const busy_ns = wall_ns * parallelism;
    const sample: policy_module.RunSample = .{ .wall_ns = wall_ns, .busy_ns = busy_ns };
    policy.record_run(site, 10, 10, planned, plan, sample);
}

/// Drives one call through the run policy, recording `walls` only when its plan is measured.
fn run_call(policy: *Policy, pools: Pools, walls: RunWalls) Call {
    const plan = policy.choose_run(site, 10, 10, parallelism, pools);
    if (plan.measure) {
        record_perfect_run(policy, parallelism, plan, walls.wall(plan.execution, plan.placement));
    }
    return .{ .execution = plan.execution, .placement = plan.placement };
}

/// Records one timed run per sample: its execution, the placement, and its wall in us.
fn record_samples(policy: *Policy, samples: []const Sample) void {
    for (samples) |sample| {
        const plan: RunPlan = .{
            .execution = sample.execution,
            .placement = sample.placement,
            .measure = true,
        };
        record_perfect_run(policy, parallelism, plan, us(sample.wall_us));
    }
}

const Sample = struct { execution: RunExecution, placement: Placement, wall_us: u64 };

/// The serial and preferred parallel estimates of the run entry.
const Estimates = struct { serial_ns: ?u64, parallel_ns: ?u64 };

fn run_estimates(policy: *Policy) Estimates {
    const entry = policy.run_entry(site, 10, 10, parallelism).?;
    return .{ .serial_ns = entry.serial_ns.get(), .parallel_ns = entry.parallel_ns() };
}

/// The boundaries a fresh cadence crosses over `calls` calls while one path stays preferred
/// and the loser trails it by `gap_shift` doublings (commonware `steady_probes`).
fn steady_probes(calls: usize, gap_shift: u32) usize {
    var boundaries: u32 = 0;
    var elapsed: usize = 0;
    while (true) {
        const shift = @min(gap_shift + (boundaries -| 1), max_shift);
        elapsed += resample_interval << @intCast(shift);
        if (elapsed > calls) return boundaries;
        boundaries += 1;
    }
}

fn expect_calls(expected: []const Call, actual: []const Call) !void {
    try testing.expectEqualSlices(Call, expected, actual);
}

test "a choice's Local seed keeps the serial seed due" {
    // commonware `choice_local_seed_keeps_serial_due`: a caller with a choice seeds Wide, seeds
    // Local, probes the loser, and then takes the serial seed the Local seed left due.
    var policy = Policy.init(testing.io);
    const walls: RunWalls = .of(.local, 50, 100, 200);
    var calls: [4]Call = undefined;
    for (&calls) |*call| call.* = run_call(&policy, either, walls);
    try expect_calls(&.{
        .{ .execution = .parallel, .placement = .wide },
        .{ .execution = .parallel, .placement = .local },
        .{ .execution = .parallel, .placement = .wide },
        .{ .execution = .serial, .placement = .wide },
    }, &calls);
    const estimates = run_estimates(&policy);
    try testing.expectEqual(@as(?u64, 50_000), estimates.serial_ns);
    try testing.expectEqual(@as(?u64, 100_000), estimates.parallel_ns);
}

test "a confined seed after serial preserves the cadence" {
    // commonware `confined_seed_preserves_cadence_after_serial`: Local workers seed Local and
    // serial, serial wins, and a Wide-confined caller's late seed leaves no boundary due, so it
    // runs serial and probes Wide once the interval its loss sets has passed.
    var policy = Policy.init(testing.io);
    const walls: RunWalls = .of(.wide, 50, 100, 80);
    const local = confined(.local);
    const seeded = run_call(&policy, local, walls);
    try testing.expectEqual(Call{ .execution = .parallel, .placement = .local }, seeded);
    const serial = run_call(&policy, local, walls);
    try testing.expectEqual(Call{ .execution = .serial, .placement = .wide }, serial);
    const shared = confined(.wide);
    const wide = run_call(&policy, shared, walls);
    try testing.expectEqual(Call{ .execution = .parallel, .placement = .wide }, wide);
    // Wide is twice as slow as serial, so its first probe comes after double the interval.
    var probes: [2]usize = undefined;
    var probes_len: usize = 0;
    for (1..2 * resample_interval + 1) |call| {
        if (run_call(&policy, shared, walls).execution != .parallel) continue;
        probes[probes_len] = call;
        probes_len += 1;
    }
    try testing.expectEqualSlices(usize, &.{2 * resample_interval}, probes[0..probes_len]);
}

test "a confined Wide caller leaves the Local seed due" {
    // commonware `confined_wide_leaves_local_seed_due`: with parallel preferred, Wide samples
    // already measure Wide, so the first caller with a choice seeds Local at once. After the
    // seed boundary probes the loser, the faster Local is preferred, and a Wide-confined caller
    // keeps Wide.
    var policy = Policy.init(testing.io);
    const wide: RunPlan = .{ .execution = .parallel, .placement = .wide, .measure = true };
    const serial: RunPlan = .{ .execution = .serial, .placement = .wide, .measure = true };
    record_perfect_run(&policy, parallelism, wide, ms(1));
    record_perfect_run(&policy, parallelism, serial, ms(100));
    const walls: RunWalls = .{ .serial_us = 2_000, .wide_us = 2_000, .local_us = 500 };
    const shared = confined(.wide);
    const callers = [_]Pools{ shared, either, either, either, either, shared };
    var calls: [callers.len]Call = undefined;
    for (callers, &calls) |pools, *call| call.* = run_call(&policy, pools, walls);
    try expect_calls(&.{
        .{ .execution = .parallel, .placement = .wide },
        .{ .execution = .parallel, .placement = .local },
        .{ .execution = .parallel, .placement = .wide },
        .{ .execution = .parallel, .placement = .local },
        .{ .execution = .parallel, .placement = .local },
        .{ .execution = .parallel, .placement = .wide },
    }, &calls);
}

test "a choice's parallel estimate tracks the preferred placement" {
    // commonware `choice_parallel_estimate_tracks_preferred_placement`: once Local is preferred,
    // probes of the slower Wide must not make parallel look slower than serial, which sits
    // between the two placements.
    var policy = Policy.init(testing.io);
    const walls: RunWalls = .{ .serial_us = 100, .wide_us = 900, .local_us = 80 };
    record_samples(&policy, &.{
        .{ .execution = .parallel, .placement = .wide, .wall_us = 900 },
        .{ .execution = .parallel, .placement = .local, .wall_us = 80 },
        .{ .execution = .serial, .placement = .wide, .wall_us = 100 },
    });
    const calls = (resample_interval << max_shift) * 2 + resample_interval * 3;
    var parallel_local: usize = 0;
    var wide_probes: usize = 0;
    var serial_runs: usize = 0;
    for (0..calls) |_| {
        const call = run_call(&policy, either, walls);
        if (call.execution == .serial) {
            serial_runs += 1;
        } else if (call.placement == .wide) {
            wide_probes += 1;
        } else {
            parallel_local += 1;
        }
    }
    const estimates = run_estimates(&policy);
    try testing.expectEqual(@as(?u64, 80_000), estimates.parallel_ns);
    try testing.expectEqual(@as(?u64, 100_000), estimates.serial_ns);
    try testing.expect(wide_probes >= 2);
    try testing.expect(serial_runs <= steady_probes(calls, 0));
    try testing.expectEqual(calls - wide_probes - serial_runs, parallel_local);
}

test "the busy budget ignores the strategy's parallelism" {
    // commonware `busy_budget_ignores_strategy_parallelism`: a 200 us Local run busy for 800 us
    // lets serial be sampled under a 64-worker strategy, and a faster serial slows Wide probes.
    const planned = 64;
    for ([_]Pools{ either, confined(.local) }) |pools| {
        var policy = Policy.init(testing.io);
        var serial_runs: usize = 0;
        var wide_runs: usize = 0;
        for (0..resample_interval * 4) |_| {
            const plan = policy.choose_run(site, 10, 10, planned, pools);
            const walls: RunWalls = .{ .serial_us = 15, .wide_us = 300, .local_us = 200 };
            record_perfect_run(&policy, planned, plan, walls.wall(plan.execution, plan.placement));
            if (plan.execution == .serial) {
                serial_runs += 1;
            } else if (plan.placement == .wide) {
                wide_runs += 1;
            }
        }
        try testing.expect(serial_runs > 0);
        try testing.expect(wide_runs <= 2);
    }
}

test "Local busy time tracks recent runs" {
    // commonware `local_busy_time_tracks_recent_runs`: expensive Local runs keep the busy time
    // over budget, and once the work turns cheap the timed runs bring it down for serial.
    var policy = Policy.init(testing.io);
    const pools = confined(.local);
    for (0..4 * resample_interval) |_| {
        const plan = policy.choose_run(site, 10, 10, parallelism, pools);
        try testing.expectEqual(RunExecution.parallel, plan.execution);
        if (plan.measure) record_perfect_run(&policy, parallelism, plan, ms(8));
    }
    var serial_runs: usize = 0;
    for (0..4 * resample_interval) |_| {
        const plan = policy.choose_run(site, 10, 10, parallelism, pools);
        if (plan.measure) {
            const wall_ns = if (plan.execution == .serial) us(150) else us(200);
            record_perfect_run(&policy, parallelism, plan, wall_ns);
        }
        serial_runs += @intFromBool(plan.execution == .serial);
    }
    try testing.expect(serial_runs > 0);
}

/// The placement other than `placement`.
fn other(placement: Placement) Placement {
    return switch (placement) {
        .wide => .local,
        .local => .wide,
    };
}

const placements = [_]Placement{ .wide, .local };

/// The most probes over `calls` of a path losing by more than the capped margin.
fn capped_probes(calls: usize) usize {
    return calls / (resample_interval << max_shift);
}

/// Calls within which probes rediscover a placement remembered as nine times slower than
/// serial (commonware `DISCOVERY`).
const discovery = 5 * (resample_interval << max_shift);
/// Calls in which a cadence at the cap crosses exactly one boundary.
const settled = resample_interval << max_shift;

/// Seeds the entry with serial between the placements: `preferred` beats serial, and the
/// other placement is nine times slower than serial.
fn seed_preferred(policy: *Policy, preferred: Placement) !void {
    record_samples(policy, &.{
        .{ .execution = .parallel, .placement = other(preferred), .wall_us = 900 },
        .{ .execution = .parallel, .placement = preferred, .wall_us = 80 },
        .{ .execution = .serial, .placement = .wide, .wall_us = 100 },
    });
    const estimates = run_estimates(policy);
    try testing.expectEqual(@as(?u64, 100_000), estimates.serial_ns);
    try testing.expectEqual(@as(?u64, 80_000), estimates.parallel_ns);
}

/// Drives a caller confined to `pool` through `discovery` calls, then returns how many of the
/// next `settled` run on that placement.
fn settled_parallel_runs(policy: *Policy, pool: Placement, walls: RunWalls) usize {
    for (0..discovery) |_| _ = run_call(policy, confined(pool), walls);
    var runs: usize = 0;
    for (0..settled) |_| {
        const call = run_call(policy, confined(pool), walls);
        runs += @intFromBool(call.execution == .parallel and call.placement == pool);
    }
    return runs;
}

/// The Wide and Local wall-time estimates of the run entry.
fn placement_estimates(policy: *Policy) [2]?u64 {
    const entry = policy.run_entry(site, 10, 10, parallelism).?;
    return .{ entry.placement.estimate(.wide), entry.placement.estimate(.local) };
}

test "confined calls compare their own placement" {
    // commonware `confined_calls_compare_own_placement`: the entry prefers the other placement
    // over serial, and the caller's is nine times slower than serial, so a confined caller runs
    // serial apart from its own probes and leaves both placement estimates intact.
    for (placements) |pool| {
        var policy = Policy.init(testing.io);
        try seed_preferred(&policy, other(pool));
        const walls: RunWalls = .of(pool, 100, 900, 80);
        const calls = 20_000;
        var serial_runs: usize = 0;
        var pool_runs: usize = 0;
        for (0..calls) |_| {
            const call = run_call(&policy, confined(pool), walls);
            if (call.execution == .serial) {
                serial_runs += 1;
            } else {
                try testing.expectEqual(pool, call.placement);
                pool_runs += 1;
            }
        }
        try testing.expect(pool_runs <= capped_probes(calls));
        try testing.expectEqual(@as(usize, calls), serial_runs + pool_runs);
        const estimates = run_estimates(&policy);
        try testing.expectEqual(@as(?u64, 100_000), estimates.serial_ns);
        try testing.expectEqual(@as(?u64, 80_000), estimates.parallel_ns);
        const chosen = run_call(&policy, either, walls);
        try testing.expectEqual(Call{ .execution = .parallel, .placement = other(pool) }, chosen);
    }
}

test "interleaved callers choose their fastest paths" {
    // commonware `interleaved_callers_choose_fastest_paths`: callers with a choice and callers
    // confined to Wide share the entry, each paying only its own cadences' probes.
    const walls: RunWalls = .of(.wide, 100, 900, 80);
    const calls = 20_000;
    for (0..2) |parity| {
        var policy = Policy.init(testing.io);
        try seed_preferred(&policy, .local);
        var with_pool_other: usize = 0;
        var without_pool_wide: usize = 0;
        for (0..calls) |call| {
            if (call % 2 == parity) {
                const chosen = run_call(&policy, either, walls);
                const local = chosen.execution == .parallel and chosen.placement == .local;
                with_pool_other += @intFromBool(!local);
            } else {
                const chosen = run_call(&policy, confined(.wide), walls);
                without_pool_wide += @intFromBool(chosen.execution != .serial);
            }
        }
        const half = calls / 2;
        try testing.expect(with_pool_other <= steady_probes(half, 0) + capped_probes(half));
        try testing.expect(without_pool_wide <= capped_probes(half));
    }
}

test "confined calls rediscover a faster placement" {
    // commonware `confined_calls_rediscover_faster_placement`: the caller's placement is
    // remembered as nine times slower than serial but now beats it, and its probes find out.
    for (placements) |pool| {
        var policy = Policy.init(testing.io);
        try seed_preferred(&policy, other(pool));
        const runs = settled_parallel_runs(&policy, pool, .of(pool, 100, 50, 80));
        try testing.expect(runs >= settled - 1);
    }
}

test "confined calls notice a serial slowdown" {
    // commonware `confined_calls_notice_serial_slowdown`: serial rises to 200 us and the
    // caller's placement falls to 150 us, so it moves there though the other stays faster.
    for (placements) |pool| {
        var policy = Policy.init(testing.io);
        try seed_preferred(&policy, other(pool));
        const runs = settled_parallel_runs(&policy, pool, .of(pool, 200, 150, 80));
        try testing.expect(runs >= settled - 1);
    }
}

/// Records the remembered ordering: `pool` at 900 us, the other at 120 us, serial at 100 us.
fn seed_serial_wins(policy: *Policy, pool: Placement) void {
    record_samples(policy, &.{
        .{ .execution = .parallel, .placement = pool, .wall_us = 900 },
        .{ .execution = .parallel, .placement = other(pool), .wall_us = 120 },
        .{ .execution = .serial, .placement = .wide, .wall_us = 100 },
    });
}

test "confined calls probe while serial wins" {
    // commonware `confined_calls_probe_while_serial_wins`: serial beats the other placement,
    // which beats the caller's, but the caller's now runs at half serial's wall.
    for (placements) |pool| {
        var policy = Policy.init(testing.io);
        seed_serial_wins(&policy, pool);
        const runs = settled_parallel_runs(&policy, pool, .of(pool, 100, 50, 120));
        try testing.expect(runs >= settled - 1);
    }
}

test "a choice rediscovers a placement while serial wins" {
    // commonware `choice_rediscovers_placement_while_serial_wins`: serial keeps a caller with a
    // choice on serial, but the placement remembered as nine times slower is now fastest. The
    // choice and the run cadence find it, then leave it only for capped probes.
    for (placements) |pool| {
        var policy = Policy.init(testing.io);
        // Recorded twice, so the estimates are live rather than seeds.
        seed_serial_wins(&policy, pool);
        seed_serial_wins(&policy, pool);
        const walls: RunWalls = .of(pool, 100, 50, 120);
        for (0..discovery) |_| _ = run_call(&policy, either, walls);
        var runs: usize = 0;
        for (0..settled) |_| {
            const call = run_call(&policy, either, walls);
            runs += @intFromBool(call.execution == .parallel and call.placement == pool);
        }
        try testing.expect(runs >= settled - 2);
    }
}

test "a choice caps probes while serial wins" {
    // commonware `choice_caps_probes_while_serial_wins`: serial is ten times faster than the
    // preferred placement, so each placement is probed at most once per capped interval.
    for (placements) |pool| {
        var policy = Policy.init(testing.io);
        record_samples(&policy, &.{
            .{ .execution = .parallel, .placement = other(pool), .wall_us = 150 },
            .{ .execution = .parallel, .placement = pool, .wall_us = 100 },
            .{ .execution = .serial, .placement = .wide, .wall_us = 10 },
        });
        const walls: RunWalls = .of(pool, 10, 100, 150);
        const calls = 20_000;
        var parallel_runs: usize = 0;
        for (0..calls) |_| {
            parallel_runs += @intFromBool(run_call(&policy, either, walls).execution == .parallel);
        }
        try testing.expect(parallel_runs <= 2 * capped_probes(calls));
    }
}

test "a choice ignores an ineligible serial when pacing" {
    // commonware `choice_ignores_ineligible_serial_when_pacing`: the busy time is over budget,
    // so serial never runs, and serial's wall must not stretch the placements' race to the cap.
    for (placements) |pool| {
        var policy = Policy.init(testing.io);
        record_samples(&policy, &.{
            .{ .execution = .parallel, .placement = other(pool), .wall_us = 6_100 },
            .{ .execution = .parallel, .placement = pool, .wall_us = 6_000 },
            .{ .execution = .serial, .placement = .wide, .wall_us = 100 },
        });
        const walls: RunWalls = .of(pool, 100, 6_000, 6_100);
        const calls = 20_000;
        var first: ?usize = null;
        var other_runs: usize = 0;
        for (0..calls) |call| {
            const chosen = run_call(&policy, either, walls);
            if (chosen.execution != .parallel or chosen.placement != other(pool)) continue;
            if (first == null) first = call;
            other_runs += 1;
        }
        try testing.expectEqual(@as(?usize, resample_interval), first.? + 1);
        try testing.expect(other_runs <= steady_probes(calls, 0));
    }
}

test "confined calls keep big work parallel" {
    // commonware `confined_calls_keep_big_work_parallel`: a confined caller whose placement is
    // busy past the budget never samples serial, though serial is faster.
    for (placements) |pool| {
        var policy = Policy.init(testing.io);
        record_samples(&policy, &.{
            .{ .execution = .parallel, .placement = pool, .wall_us = 6_000 },
            .{ .execution = .parallel, .placement = other(pool), .wall_us = 1_000 },
            .{ .execution = .serial, .placement = .wide, .wall_us = 2_000 },
        });
        const walls: RunWalls = .of(pool, 2_000, 6_000, 1_000);
        for (0..2_000) |_| {
            const call = run_call(&policy, confined(pool), walls);
            try testing.expectEqual(RunExecution.parallel, call.execution);
        }
    }
}

test "confined calls pay only their own probes" {
    // commonware `confined_calls_pay_only_own_probes`: a confined caller seeds its placement
    // and serial, then finds its placement faster and leaves it for exactly one serial probe
    // per settled window.
    for (placements) |pool| {
        var policy = Policy.init(testing.io);
        const remembered: RunWalls = .of(pool, 100, 900, 900);
        const seeded = run_call(&policy, confined(pool), remembered);
        try testing.expectEqual(Call{ .execution = .parallel, .placement = pool }, seeded);
        const serial = run_call(&policy, confined(pool), remembered);
        try testing.expectEqual(Call{ .execution = .serial, .placement = .wide }, serial);
        try testing.expectEqual(@as(?u64, 100_000), run_estimates(&policy).serial_ns);
        const expected: [2]?u64 = switch (pool) {
            .wide => .{ 900_000, null },
            .local => .{ null, 900_000 },
        };
        try testing.expectEqual(expected, placement_estimates(&policy));
        const runs = settled_parallel_runs(&policy, pool, .of(pool, 100, 60, 60));
        try testing.expectEqual(settled - 1, runs);
    }
}

test "confined calls leave the choice untouched" {
    // commonware `confined_calls_leave_choice_untouched`: a Local-confined worker's samples
    // train only Local, so the first caller with a choice still seeds Wide.
    var policy = Policy.init(testing.io);
    const local = confined(.local);
    const plan = policy.choose_run(site, 10, 10, parallelism, local);
    const expected: RunPlan = .{ .execution = .parallel, .placement = .local, .measure = true };
    try testing.expectEqual(expected, plan);
    record_perfect_run(&policy, parallelism, plan, us(80));
    const walls: RunWalls = .of(.local, 100, 80, 900);
    const serial = run_call(&policy, local, walls);
    try testing.expectEqual(Call{ .execution = .serial, .placement = .wide }, serial);
    for (0..resample_interval) |_| {
        const call = run_call(&policy, local, walls);
        try testing.expect(!(call.execution == .parallel and call.placement == .wide));
    }
    try testing.expectEqual([2]?u64{ null, 80_000 }, placement_estimates(&policy));
    const chosen = run_call(&policy, either, walls);
    try testing.expectEqual(Call{ .execution = .parallel, .placement = .wide }, chosen);
}

/// Seeds serial at 100 us, Local at 80 us, and Wide at 120 us.
fn seed_local_fastest(policy: *Policy) void {
    record_samples(policy, &.{
        .{ .execution = .serial, .placement = .wide, .wall_us = 100 },
        .{ .execution = .parallel, .placement = .local, .wall_us = 80 },
        .{ .execution = .parallel, .placement = .wide, .wall_us = 120 },
    });
}

/// Chooses a run for `pools` and records `walls` when it is measured, returning the plan.
fn decide(policy: *Policy, pools: Pools, walls: RunWalls) RunPlan {
    const plan = policy.choose_run(site, 10, 10, parallelism, pools);
    if (plan.measure) {
        record_perfect_run(policy, parallelism, plan, walls.wall(plan.execution, plan.placement));
    }
    return plan;
}

test "interleaved callers keep independent cadences" {
    // commonware `interleaved_callers_keep_independent_cadences`: with steady walls each
    // population makes the same decisions, probes and samples included, as when it calls alone.
    const walls: RunWalls = .{ .serial_us = 100, .wide_us = 120, .local_us = 80 };
    const populations = [_]Pools{ either, confined(.wide) };
    const calls = 10 * resample_interval;
    var alone: [populations.len][calls]RunPlan = undefined;
    for (populations, &alone) |pools, *plans| {
        var policy = Policy.init(testing.io);
        seed_local_fastest(&policy);
        for (plans) |*plan| plan.* = decide(&policy, pools, walls);
    }
    var together: [populations.len][calls]RunPlan = undefined;
    var policy = Policy.init(testing.io);
    seed_local_fastest(&policy);
    for (0..calls) |call| {
        for (populations, &together) |pools, *plans| plans[call] = decide(&policy, pools, walls);
    }
    for (alone, together) |expected, actual| {
        try testing.expectEqualSlices(RunPlan, &expected, &actual);
    }
}

test "confined Local samples update the shared choice" {
    // commonware `confined_local_samples_update_shared_choice`: Local workers time Local
    // slowing past Wide, and a caller with a choice moves to Wide without timing Local itself.
    var policy = Policy.init(testing.io);
    record_samples(&policy, &.{
        .{ .execution = .parallel, .placement = .wide, .wall_us = 120 },
        .{ .execution = .parallel, .placement = .local, .wall_us = 80 },
        .{ .execution = .serial, .placement = .wide, .wall_us = 1_000 },
    });
    const slow: RunWalls = .of(.local, 1_000, 300, 120);
    for (0..resample_interval) |_| _ = run_call(&policy, confined(.local), slow);
    const chosen = run_call(&policy, either, slow);
    try testing.expectEqual(Call{ .execution = .parallel, .placement = .wide }, chosen);
}

test "a choice advances the run cadence once per call" {
    // commonware `choice_advances_run_cadence_once`: over a settled window a caller with a
    // choice on a Wide-preferring entry pays only the run cadence's serial probes and the
    // choice's probes of Local.
    var policy = Policy.init(testing.io);
    record_samples(&policy, &.{
        .{ .execution = .parallel, .placement = .wide, .wall_us = 60 },
        .{ .execution = .parallel, .placement = .local, .wall_us = 80 },
        .{ .execution = .serial, .placement = .wide, .wall_us = 100 },
    });
    const walls: RunWalls = .{ .serial_us = 100, .wide_us = 60, .local_us = 80 };
    const window = 1_000;
    var elsewhere: usize = 0;
    for (0..window) |_| {
        const call = run_call(&policy, either, walls);
        elsewhere += @intFromBool(!(call.execution == .parallel and call.placement == .wide));
    }
    try testing.expectEqual(2 * steady_probes(window, 0), elsewhere);
}

/// Every phase of a strict alternation and of one call in ten by the caller with a choice.
const rhythms = blk: {
    var all: [12]struct { period: usize, phase: usize } = undefined;
    for (0..2) |phase| all[phase] = .{ .period = 2, .phase = phase };
    for (0..10) |phase| all[2 + phase] = .{ .period = 10, .phase = phase };
    break :blk all;
};

test "interleaved callers refresh the Local estimate" {
    // commonware `interleaved_callers_refresh_local_estimate`: the busy time exceeds the budget,
    // so every call is parallel, and whatever rhythm Wide-confined callers keep, Local's cadence
    // keeps timing the choosing caller's Local runs as Local slows down.
    for (rhythms) |rhythm| {
        var policy = Policy.init(testing.io);
        record_samples(&policy, &.{
            .{ .execution = .parallel, .placement = .wide, .wall_us = 9_000 },
            .{ .execution = .parallel, .placement = .local, .wall_us = 6_000 },
        });
        const calls = 5_000;
        var local_runs: usize = 0;
        for (0..calls) |call| {
            const pools = if (call % rhythm.period == rhythm.phase) either else confined(.wide);
            const local_us: u64 = if (call >= calls / 2) 8_000 else 6_000;
            const walls: RunWalls = .{ .serial_us = 0, .wide_us = 9_000, .local_us = local_us };
            const ran = run_call(&policy, pools, walls);
            try testing.expectEqual(RunExecution.parallel, ran.execution);
            local_runs += @intFromBool(ran.placement == .local);
        }
        const with_pool = calls / rhythm.period;
        try testing.expect(local_runs >= with_pool - steady_probes(with_pool, 0));
        try testing.expect(run_estimates(&policy).parallel_ns.? >= 7_900_000);
    }
}

test "interleaved callers rediscover a faster Local placement" {
    // commonware `interleaved_callers_rediscover_faster_local_placement`: serial and Local both
    // speed up, and the choosing caller's probes keep landing on it at any phase of the others'
    // calls, so Local is timed again and preferred once more.
    const walls: RunWalls = .{ .serial_us = 60, .wide_us = 900, .local_us = 30 };
    for (rhythms) |rhythm| {
        var policy = Policy.init(testing.io);
        try seed_preferred(&policy, .local);
        const calls = 20_000;
        const second_half = calls / 2;
        var with_pool: usize = 0;
        var local_runs: usize = 0;
        for (0..calls) |call| {
            const chooser = call % rhythm.period == rhythm.phase;
            const ran = run_call(&policy, if (chooser) either else confined(.wide), walls);
            if (call < second_half or !chooser) continue;
            with_pool += 1;
            local_runs += @intFromBool(ran.execution == .parallel and ran.placement == .local);
        }
        const slack = (steady_probes(with_pool, 0) + 1) + (capped_probes(with_pool) + 1);
        try testing.expect(local_runs >= with_pool - slack);
    }
}

/// Seeds Wide at `wide_us` and serial at 100 us, `times` times.
fn seed_wide_serial(policy: *Policy, wide_us: u64, times: usize) void {
    for (0..times) |_| {
        record_samples(policy, &.{
            .{ .execution = .parallel, .placement = .wide, .wall_us = wide_us },
            .{ .execution = .serial, .placement = .wide, .wall_us = 100 },
        });
    }
}

/// The calls (from 1) of the next `calls` Wide-confined calls that ran `execution`.
fn runs_of(
    policy: *Policy,
    execution: RunExecution,
    calls: usize,
    walls: RunWalls,
    out: []usize,
) []usize {
    var len: usize = 0;
    for (1..calls + 1) |call| {
        if (run_call(policy, confined(.wide), walls).execution != execution) continue;
        out[len] = call;
        len += 1;
    }
    return out[0..len];
}

/// The probes of a steady close race backing off to the cap over 20,000 calls.
const backed_off = [_]usize{
    100, 200, 400, 800, 1_600, 3_200, 6_400, 9_600, 12_800, 16_000, 19_200,
};

test "confined races back off until a flip" {
    // commonware `confined_races_back_off_until_flip`: serial beats Wide by a sixth, so every
    // probe confirms and the intervals double to the cap. When serial slows past Wide the flip
    // resets the confirmations, and probing resumes from the base interval.
    var policy = Policy.init(testing.io);
    seed_wide_serial(&policy, 120, 1);
    var out: [64]usize = undefined;
    const calls = 20_000;
    const probes = runs_of(&policy, .parallel, calls, .of(.wide, 100, 120, 120), &out);
    try testing.expectEqualSlices(usize, &backed_off, probes);
    try testing.expectEqual(steady_probes(calls, 0), probes.len);
    const window = resample_interval << max_shift;
    const serial_runs = runs_of(&policy, .serial, window, .of(.wide, 240, 120, 120), &out);
    const expected = [_]usize{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 111, 311, 711, 1_511, 3_111 };
    try testing.expectEqualSlices(usize, &expected, serial_runs);
}

test "confined flips reset the confirmations between boundaries" {
    // commonware `confined_flips_reset_confirmations_between_boundaries`: flips between probe
    // boundaries clear the confirmations even when the original winner returns, so the next
    // probe follows the base interval instead of the capped one.
    var policy = Policy.init(testing.io);
    seed_wide_serial(&policy, 120, 1);
    for (0..6_400) |_| _ = run_call(&policy, confined(.wide), .of(.wide, 100, 120, 120));
    for (0..10) |_| {
        const call = run_call(&policy, confined(.wide), .of(.wide, 300, 120, 120));
        try testing.expectEqual(RunExecution.serial, call.execution);
    }
    for (0..10) |_| {
        const call = run_call(&policy, confined(.wide), .of(.wide, 300, 250, 250));
        try testing.expectEqual(RunExecution.parallel, call.execution);
    }
    var out: [8]usize = undefined;
    const walls: RunWalls = .of(.wide, 140, 146, 146);
    const probes = runs_of(&policy, .parallel, resample_interval - 20, walls, &out);
    try testing.expectEqualSlices(usize, &.{resample_interval - 20}, probes);
}

test "confined noisy races rediscover a stale placement" {
    // commonware `confined_noisy_races_rediscover_stale_placement`: Wide is remembered at nine
    // times serial but runs at half of it, so the probes close the gap and the caller settles on
    // Wide 11,601 calls in. A close race whose loser stays within 2x still backs off to the cap.
    var policy = Policy.init(testing.io);
    seed_wide_serial(&policy, 900, 2);
    var pool_runs: [32]usize = undefined;
    var pool_len: usize = 0;
    var settled_at: ?usize = null;
    for (1..discovery + 1) |call| {
        const ran = run_call(&policy, confined(.wide), .of(.wide, 100, 50, 50));
        if (ran.execution != .parallel) continue;
        const follows = pool_len > 0 and pool_runs[pool_len - 1] == call - 1;
        pool_runs[pool_len] = call;
        pool_len += 1;
        if (follows) {
            settled_at = call;
            break;
        }
    }
    try testing.expectEqual(@as(?usize, 11_601), settled_at);
    const expected = [_]usize{
        3_200,  6_400,  8_000,  8_800,  9_200,  9_600,  9_800,
        10_000, 10_100, 10_200, 10_400, 10_800, 11_600, 11_601,
    };
    try testing.expectEqualSlices(usize, &expected, pool_runs[0..pool_len]);
    var noisy_policy = Policy.init(testing.io);
    seed_wide_serial(&noisy_policy, 150, 1);
    var probes: [16]usize = undefined;
    var probes_len: usize = 0;
    var samples: usize = 0;
    for (1..20_001) |call| {
        const plan = noisy_policy.choose_run(site, 10, 10, parallelism, confined(.wide));
        if (plan.execution != .parallel) {
            if (plan.measure) record_perfect_run(&noisy_policy, parallelism, plan, us(100));
            continue;
        }
        probes[probes_len] = call;
        probes_len += 1;
        if (!plan.measure) continue;
        samples += 1;
        const wall_us: u64 = if (samples % 2 == 1) 110 else 190;
        record_perfect_run(&noisy_policy, parallelism, plan, us(wall_us));
    }
    try testing.expectEqualSlices(usize, &backed_off, probes[0..probes_len]);
    try testing.expectEqual(@as(usize, 11), samples);
}

/// Makes one spawn call from a worker or from outside the pool, records `job_ns` as the job time
/// and `job_ns + overhead_ns` as the round trip when the plan measures, and returns the plan.
fn spawn_call(policy: *Policy, worker: bool, job_ns: u64, overhead_ns: u64) SpawnPlan {
    const spawner: Spawner = if (worker) .worker else .outside;
    const plan = policy.choose_spawn(site, 64, parallelism, spawner);
    if (!plan.measure) return plan;
    switch (plan.execution) {
        .inlined => policy.record_spawn_inline(site, 64, parallelism, job_ns),
        .offload => {
            policy.record_spawn_job(site, 64, parallelism, plan, job_ns);
            const round_trip_ns = job_ns + overhead_ns;
            policy.record_spawn_round_trip(site, 64, parallelism, plan, round_trip_ns, job_ns);
        },
    }
    return plan;
}

test "spawn workers preserve the outside inline preference" {
    // commonware `spawn_workers_preserve_outside_inline_preference`: however often workers with
    // a 1 us overhead call, outside callers keep comparing inline against their 30 us overhead.
    const patterns = [_][]const bool{
        &.{false},
        &.{ false, true, true },
        &.{ false, true, true, true, true, true, true },
    };
    for (patterns) |pattern| {
        var policy = Policy.init(testing.io);
        var calls: usize = 0;
        var offloads: usize = 0;
        for (0..30_000) |index| {
            const worker = pattern[index % pattern.len];
            const plan = spawn_call(&policy, worker, us(15), us(if (worker) 1 else 30));
            if (worker) continue;
            calls += 1;
            offloads += @intFromBool(plan.execution == .offload);
        }
        try testing.expect(offloads * 50 <= calls);
    }
}

test "spawn workers learn an inline preference" {
    // commonware `spawn_workers_learn_inline_preference`: a worker-only site with a 1 us job
    // against a 3 us own-pool overhead settles inline.
    var policy = Policy.init(testing.io);
    var inlined: usize = 0;
    for (0..1_000) |_| {
        inlined += @intFromBool(spawn_call(&policy, true, us(1), us(3)).execution == .inlined);
    }
    try testing.expect(inlined > 900);
}

/// A spawn entry seeded with 20 us jobs, a 15 us worker overhead, and a 30 us hand-off.
fn seeded_spawns() Policy {
    var policy = Policy.init(testing.io);
    const job_ns = us(20);
    policy.record_spawn_inline(site, 64, parallelism, job_ns);
    const outside: SpawnPlan = .{ .execution = .offload, .spawner = .outside, .measure = true };
    policy.record_spawn_job(site, 64, parallelism, outside, job_ns);
    for ([_]Spawner{ .worker, .outside }) |spawner| {
        const plan: SpawnPlan = .{ .execution = .offload, .spawner = spawner, .measure = true };
        const overhead_ns = spawn_overhead(spawner == .worker);
        policy.record_spawn_round_trip(site, 64, parallelism, plan, job_ns + overhead_ns, job_ns);
    }
    return policy;
}

fn spawn_overhead(worker: bool) u64 {
    return us(if (worker) 15 else 30);
}

test "spawn populations keep independent cadences" {
    // commonware `spawn_populations_keep_independent_cadences`: with estimates that never move,
    // workers and outside callers each make the same decisions on a shared entry as alone.
    const populations = [_]bool{ true, false };
    const calls = 10 * resample_interval;
    var alone: [populations.len][calls]SpawnPlan = undefined;
    for (populations, &alone) |worker, *plans| {
        var policy = seeded_spawns();
        for (plans) |*plan| plan.* = spawn_call(&policy, worker, us(20), spawn_overhead(worker));
        var probed = false;
        for (plans) |plan| probed = probed or plan.execution != plans[0].execution;
        try testing.expect(probed);
    }
    var together: [populations.len][calls]SpawnPlan = undefined;
    var policy = seeded_spawns();
    for (0..calls) |call| {
        for (populations, &together) |worker, *plans| {
            plans[call] = spawn_call(&policy, worker, us(20), spawn_overhead(worker));
        }
    }
    for (alone, together) |expected, actual| {
        try testing.expectEqualSlices(SpawnPlan, &expected, &actual);
    }
}
