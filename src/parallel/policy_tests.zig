//! Tests of `policy.zig`, ported from commonware's `parallel/src/policy.rs` with the same
//! numbers. A call site is a constant here, as `Location::caller()` is one in the originals.

const std = @import("std");
const testing = std.testing;
const policy_module = @import("policy.zig");

const Policy = policy_module.Policy;
const RunEntry = policy_module.RunEntry;
const SpawnEntry = policy_module.SpawnEntry;
const Choice = policy_module.Choice;
const Cadence = policy_module.Cadence;
const RunExecution = policy_module.RunExecution;
const SpawnExecution = policy_module.SpawnExecution;
const Placement = policy_module.Placement;
const RunPlan = policy_module.RunPlan;
const SpawnPlan = policy_module.SpawnPlan;
const Spawner = policy_module.Spawner;
const resample_interval = policy_module.resample_interval;
const preferred_interval = policy_module.preferred_sample_interval;
const max_shift = policy_module.max_resample_shift;
const budget = policy_module.spawn_inline_budget_ns;

/// The strategy parallelism the tests plan with.
const parallelism = 4;
const site: usize = 0x5173;

fn us(micros: u64) u64 {
    return micros * std.time.ns_per_us;
}

fn ms(millis: u64) u64 {
    return millis * std.time.ns_per_ms;
}

/// Records a serial run, or a Wide parallel run that keeps `parallelism` workers busy.
fn record(entry: *RunEntry, execution: RunExecution, wall_ns: u64) void {
    switch (execution) {
        .serial => entry.serial_ns.record(wall_ns),
        .parallel => entry.record_parallel(.wide, wall_ns, wall_ns * parallelism),
    }
}

/// Chooses for `entry` on its preferred placement's cadence.
fn choose(entry: *RunEntry) policy_module.Decision(RunExecution) {
    return entry.choose(entry.placement.preferred());
}

/// The path `entry` prefers between serial and its preferred placement.
fn preferred(entry: *const RunEntry) RunExecution {
    const placement = entry.placement.preferred();
    return RunEntry.preferred(
        entry.serial_ns.get().?,
        entry.parallel_ns().?,
        entry.busy_ns[@backingInt(placement)].get().?,
    );
}

fn expect_decision(path: anytype, measure: bool, actual: anytype) !void {
    try testing.expectEqual(path, actual.path);
    try testing.expectEqual(measure, actual.measure);
}

/// Calls `first..last` (exclusive) run `path`, measured every `preferred_interval` calls.
fn expect_holds(entry: *RunEntry, first: u32, last: u32, path: RunExecution) !void {
    for (first..last) |call| {
        try expect_decision(path, call % preferred_interval == 0, choose(entry));
    }
}

fn spawn_choose(entry: *SpawnEntry) policy_module.Decision(SpawnExecution) {
    return entry.choose(.outside, budget);
}

test "starts parallel then seeds serial immediately" {
    var entry: RunEntry = .{};
    try expect_decision(RunExecution.parallel, true, choose(&entry));
    record(&entry, .parallel, us(100));
    // The busy time fits the budget, so the serial seed comes on the very next call.
    try expect_decision(RunExecution.serial, true, choose(&entry));
    record(&entry, .serial, us(95));
    try expect_holds(&entry, 1, resample_interval, .serial);
    try expect_decision(RunExecution.parallel, true, choose(&entry));
}

test "defers serial seed when busy time exceeds budget" {
    var entry: RunEntry = .{};
    try expect_decision(RunExecution.parallel, true, choose(&entry));
    record(&entry, .parallel, ms(10));
    try expect_decision(RunExecution.parallel, true, choose(&entry));
    try testing.expectEqual(@as(?u64, null), entry.serial_ns.get());
    try expect_holds(&entry, 1, resample_interval, .parallel);
}

test "never seeds serial when busy time exceeds budget" {
    var entry: RunEntry = .{};
    record(&entry, .parallel, ms(10));
    try expect_holds(&entry, 1, 2 * resample_interval + 1, .parallel);
    try testing.expectEqual(@as(?u64, null), entry.serial_ns.get());
}

test "never runs serial on big work" {
    var entry: RunEntry = .{};
    entry.record_parallel(.wide, ms(25), ms(300));
    for (0..10_000) |_| {
        const decision = choose(&entry);
        try testing.expectEqual(RunExecution.parallel, decision.path);
        if (decision.measure) entry.record_parallel(.wide, ms(25), ms(300));
    }
    try testing.expectEqual(@as(?u64, null), entry.serial_ns.get());
}

test "big serial estimate biases parallel" {
    var entry: RunEntry = .{};
    record(&entry, .parallel, ms(30));
    record(&entry, .serial, ms(12));
    for (0..2 * resample_interval) |_| {
        try testing.expectEqual(RunExecution.parallel, choose(&entry).path);
    }
}

test "busy gates preferred serial" {
    var entry: RunEntry = .{};
    entry.record_parallel(.wide, ms(25), ms(300));
    record(&entry, .serial, ms(8));
    for (0..2 * resample_interval) |_| {
        try testing.expectEqual(RunExecution.parallel, choose(&entry).path);
    }
}

test "serial runs leave the busy estimate untouched" {
    var policy = Policy.init(testing.io);
    const Recorder = struct {
        fn run(target: *Policy, execution: RunExecution, wall: u64, busy_ms: u64) void {
            const plan: RunPlan = .{ .execution = execution, .placement = .wide, .measure = true };
            const sample: policy_module.RunSample = .{
                .wall_ns = ms(wall),
                .busy_ns = ms(busy_ms),
            };
            target.record_run(site, 10, 10, parallelism, plan, sample);
        }
        fn busy(target: *Policy, placement: Placement) ?u64 {
            const entry = target.run_entry(site, 10, 10, parallelism).?;
            return entry.busy_ns[@backingInt(placement)].get();
        }
    };
    Recorder.run(&policy, .serial, 5, 5);
    try testing.expectEqual(@as(?u64, null), Recorder.busy(&policy, .wide));
    Recorder.run(&policy, .parallel, 1, 3);
    Recorder.run(&policy, .serial, 50, 50);
    try testing.expectEqual(@as(?u64, 3_000_000), Recorder.busy(&policy, .wide));
    try testing.expectEqual(@as(?u64, null), Recorder.busy(&policy, .local));
}

test "placements gate serial on their own busy time" {
    var entry: RunEntry = .{};
    entry.record_parallel(.wide, ms(25), ms(300));
    entry.record_parallel(.local, ms(8), ms(6));
    record(&entry, .serial, ms(5));
    try testing.expectEqual(@as(?u64, 5_000_000), entry.serial_rival_ns(.local));
    try testing.expectEqual(@as(?u64, null), entry.serial_rival_ns(.wide));
    try testing.expectEqual(RunExecution.serial, entry.choose(.local).path);
    try testing.expectEqual(RunExecution.parallel, entry.choose(.wide).path);
}

test "queueing does not gate serial" {
    var entry: RunEntry = .{};
    try expect_decision(RunExecution.parallel, true, choose(&entry));
    entry.record_parallel(.wide, ms(25), ms(2));
    try expect_decision(RunExecution.serial, true, choose(&entry));
    record(&entry, .serial, ms(5));
    try testing.expectEqual(RunExecution.serial, preferred(&entry));
    // Parallel is five times slower, so serial runs until the boundary 100 << 4 calls later.
    try expect_holds(&entry, 1, resample_interval << 4, .serial);
    try expect_decision(RunExecution.parallel, true, choose(&entry));
}

test "prefers serial when faster, parallel when it wins wall time, serial on a tie" {
    const cases = [_]struct { parallel: u64, serial: u64, path: RunExecution }{
        .{ .parallel = 100, .serial = 95, .path = .serial },
        .{ .parallel = 100, .serial = 200, .path = .parallel },
        .{ .parallel = 100, .serial = 100, .path = .serial },
    };
    for (cases) |case| {
        var entry: RunEntry = .{};
        record(&entry, .parallel, us(case.parallel));
        record(&entry, .serial, us(case.serial));
        try expect_decision(case.path, false, choose(&entry));
    }
}

test "pre-seed parallel samples blend" {
    var entry: RunEntry = .{};
    record(&entry, .parallel, ms(10));
    record(&entry, .parallel, ms(20));
    try testing.expectEqual(@as(?u64, 12_000_000), entry.parallel_ns());
    try testing.expectEqual(@as(?u64, 48_000_000), entry.busy_ns[0].get());
}

test "blends preferred samples with integer math" {
    var entry: RunEntry = .{};
    record(&entry, .parallel, 1000);
    record(&entry, .serial, 100);
    record(&entry, .serial, 200);
    try testing.expectEqual(@as(?u64, 120), entry.serial_ns.get());

    var parallel_entry: RunEntry = .{};
    record(&parallel_entry, .parallel, 100);
    record(&parallel_entry, .serial, 1000);
    record(&parallel_entry, .parallel, 200);
    try testing.expectEqual(@as(?u64, 120), parallel_entry.parallel_ns());
}

test "probes blend into stale estimates" {
    var entry: RunEntry = .{};
    for (0..2) |_| {
        record(&entry, .parallel, ms(25));
        record(&entry, .serial, ms(100));
    }
    record(&entry, .serial, ms(5));
    try testing.expectEqual(@as(?u64, 81_000_000), entry.serial_ns.get());
    try testing.expectEqual(RunExecution.parallel, preferred(&entry));
}

test "seeds serial once busy time shrinks into budget" {
    var entry: RunEntry = .{};
    record(&entry, .parallel, ms(10));
    for (1..resample_interval) |_| {
        const decision = choose(&entry);
        try testing.expectEqual(RunExecution.parallel, decision.path);
        if (decision.measure) record(&entry, .parallel, us(100));
    }
    try expect_decision(RunExecution.serial, true, choose(&entry));
}

test "resamples the other execution" {
    var entry: RunEntry = .{};
    record(&entry, .parallel, us(100));
    record(&entry, .serial, us(80));
    try expect_holds(&entry, 1, resample_interval, .serial);
    try expect_decision(RunExecution.parallel, true, choose(&entry));

    var parallel_wins: RunEntry = .{};
    record(&parallel_wins, .parallel, us(100));
    record(&parallel_wins, .serial, us(150));
    try expect_holds(&parallel_wins, 1, resample_interval, .parallel);
    try expect_decision(RunExecution.serial, true, choose(&parallel_wins));
}

test "resample interval doubles per slowdown multiple and is capped" {
    var entry: RunEntry = .{};
    record(&entry, .parallel, us(250));
    record(&entry, .serial, us(100));
    try expect_holds(&entry, 1, 2 * resample_interval, .serial);
    try expect_decision(RunExecution.parallel, true, choose(&entry));

    var capped: RunEntry = .{};
    record(&capped, .parallel, us(100));
    record(&capped, .serial, us(900));
    try expect_holds(&capped, 1, resample_interval << max_shift, .parallel);
    try expect_decision(RunExecution.serial, true, choose(&capped));
}

test "recovers from a stale estimate" {
    var entry: RunEntry = .{};
    for (0..2) |_| {
        record(&entry, .parallel, ms(2));
        record(&entry, .serial, ms(1));
    }
    try testing.expectEqual(RunExecution.serial, preferred(&entry));
    var probes: u32 = 0;
    var flipped_at: ?u32 = null;
    for (1..2_001) |call| {
        if (preferred(&entry) == .parallel) {
            flipped_at = @intCast(call - 1);
            break;
        }
        const decision = choose(&entry);
        switch (decision.path) {
            .parallel => {
                try testing.expect(decision.measure);
                probes += 1;
                record(&entry, .parallel, us(500));
            },
            .serial => if (decision.measure) record(&entry, .serial, ms(1)),
        }
    }
    // 2 -> 1.7 -> 1.46 -> 1.268 -> 1.1144 -> 0.99152ms over five probes, flipping at call 1,000.
    try testing.expectEqual(@as(u32, 5), probes);
    try testing.expectEqual(@as(?u32, 1_000), flipped_at);
}

test "a seed is offered once per interval" {
    var entry: RunEntry = .{};
    record(&entry, .parallel, us(250));
    for (0..2) |_| {
        try expect_holds(&entry, 1, resample_interval, .parallel);
        try expect_decision(RunExecution.serial, true, choose(&entry));
    }
    // Each boundary confirms parallel, so the later retries back off to the capped interval.
    const cap = resample_interval << max_shift;
    var seeds: [8]u32 = undefined;
    var seeds_len: usize = 0;
    for (2 * resample_interval + 1..4 * cap + 1) |call| {
        const decision = choose(&entry);
        if (decision.path == .serial and decision.measure) {
            seeds[seeds_len] = @intCast(call);
            seeds_len += 1;
        }
    }
    const expected = [_]u32{ 400, 800, 1_600, 3_200, 6_400, 9_600, 12_800 };
    try testing.expectEqualSlices(u32, &expected, seeds[0..seeds_len]);
    record(&entry, .serial, ms(1));
    try testing.expectEqual(RunExecution.parallel, choose(&entry).path);
}

test "probes big serial when busy time is affordable" {
    var entry: RunEntry = .{};
    for (0..2) |_| {
        record(&entry, .parallel, us(500));
        record(&entry, .serial, ms(15));
    }
    try testing.expectEqual(RunExecution.parallel, preferred(&entry));
    try expect_holds(&entry, 1, resample_interval << max_shift, .parallel);
    try expect_decision(RunExecution.serial, true, choose(&entry));
    record(&entry, .serial, us(300));
    try testing.expectEqual(@as(?u64, 12_060_000), entry.serial_ns.get());
}

const Workload = struct { serial: u64, parallel: u64, busy: u64 };

fn run_confined(policy: *Policy, work: Workload) RunExecution {
    const plan = policy.choose_run(site, 10, 10, parallelism, .{ .fixed = .wide });
    if (plan.measure) {
        const sample: policy_module.RunSample = switch (plan.execution) {
            .serial => .{ .wall_ns = work.serial, .busy_ns = work.serial },
            .parallel => .{ .wall_ns = work.parallel, .busy_ns = work.busy },
        };
        policy.record_run(site, 10, 10, parallelism, plan, sample);
    }
    return plan.execution;
}

test "serial is rediscovered after growth settles" {
    var policy = Policy.init(testing.io);
    const interval = resample_interval << max_shift;
    const small: Workload = .{ .serial = ms(5), .parallel = ms(25), .busy = ms(2) };
    for (0..2 * preferred_interval) |_| _ = run_confined(&policy, small);
    try testing.expectEqual(RunExecution.serial, run_confined(&policy, small));

    const grown: Workload = .{ .serial = us(11_500), .parallel = ms(25), .busy = us(4_600) };
    for (0..interval) |_| _ = run_confined(&policy, grown);
    try testing.expectEqual(RunExecution.parallel, run_confined(&policy, grown));

    const settled: Workload = .{ .serial = ms(7), .parallel = ms(25), .busy = us(2_800) };
    var probe: ?usize = null;
    var last: RunExecution = .parallel;
    for (0..2 * interval) |call| {
        last = run_confined(&policy, settled);
        if (probe == null and last == .serial) probe = call;
    }
    try testing.expect(probe.? < interval);
    try testing.expectEqual(RunExecution.serial, last);
}

test "a fast sample preserves the established preference" {
    var entry: RunEntry = .{};
    for (0..2) |_| {
        record(&entry, .parallel, us(800));
        record(&entry, .serial, ms(3));
    }
    try testing.expectEqual(RunExecution.parallel, preferred(&entry));
    record(&entry, .serial, us(20));
    try testing.expectEqual(@as(?u64, 2_404_000), entry.serial_ns.get());
    try testing.expectEqual(RunExecution.parallel, preferred(&entry));
}

test "refreshes the preferred parallel sample" {
    var entry: RunEntry = .{};
    record(&entry, .parallel, us(100));
    record(&entry, .serial, us(410));
    try expect_holds(&entry, 1, preferred_interval, .parallel);
    try expect_decision(RunExecution.parallel, true, choose(&entry));
}

/// Drives `cadence` through `calls` calls of a race that `winner` wins in 1,000ns against
/// `loser_ns`, and returns the calls, counted from one, that crossed a boundary.
fn boundaries(
    cadence: *Cadence(RunExecution),
    calls: u32,
    winner: RunExecution,
    loser_ns: u64,
    probe_allowed: bool,
    out: []u32,
) ![]u32 {
    const loser: RunExecution = if (winner == .serial) .parallel else .serial;
    var count: usize = 0;
    for (1..calls + 1) |call| {
        const decision = cadence.arbitrate(winner, loser, 1_000, loser_ns, probe_allowed);
        const boundary = cadence.since_probe == 0;
        if (boundary) try testing.expect(decision.measure);
        try testing.expectEqual(boundary and probe_allowed, decision.path == loser);
        if (!boundary) continue;
        out[count] = @intCast(call);
        count += 1;
    }
    return out[0..count];
}

fn expect_boundaries(
    expected: []const u32,
    cadence: *Cadence(RunExecution),
    calls: u32,
    winner: RunExecution,
    loser_ns: u64,
    probe_allowed: bool,
) !void {
    var out: [32]u32 = undefined;
    const actual = try boundaries(cadence, calls, winner, loser_ns, probe_allowed, &out);
    try testing.expectEqualSlices(u32, expected, actual);
}

test "cadence backs off after confirmations" {
    var cadence: Cadence(RunExecution) = .{};
    const base = [_]u32{ 100, 200, 400, 800, 1_600, 3_200, 6_400, 9_600, 12_800 };
    try expect_boundaries(&base, &cadence, 13_000, .serial, 1_000, true);
    cadence = .{};
    const gap = [_]u32{ 800, 1_600, 3_200, 6_400, 9_600, 12_800 };
    try expect_boundaries(&gap, &cadence, 13_000, .serial, 4_000, true);
}

test "cadence resets confirmations on a flip" {
    var cadence: Cadence(RunExecution) = .{};
    const held = [_]u32{ 100, 200, 400, 800, 1_600, 3_200, 6_400 };
    try expect_boundaries(&held, &cadence, 7_400, .serial, 1_000, true);
    const flipped = [_]u32{ 1, 101, 301, 701, 1_501, 3_101, 6_301 };
    try expect_boundaries(&flipped, &cadence, 6_400, .parallel, 1_000, true);
}

test "cadence counts disallowed boundaries" {
    var cadence: Cadence(RunExecution) = .{};
    try expect_boundaries(&.{ 100, 200, 400 }, &cadence, 400, .parallel, 1_000, false);
    try expect_boundaries(&.{ 400, 1_200, 2_800 }, &cadence, 2_800, .parallel, 1_000, true);
}

test "cadence resets when the gap multiple shrinks" {
    var cadence: Cadence(RunExecution) = .{};
    try expect_boundaries(&.{ 100, 200, 400 }, &cadence, 400, .serial, 1_500, true);
    try expect_boundaries(&.{ 800, 2_400, 5_600 }, &cadence, 5_600, .serial, 2_900, true);
    try expect_boundaries(&.{3_200}, &cadence, 4_200, .serial, 2_000, true);
    const reset = [_]u32{ 1, 101, 301, 701, 1_501, 3_101 };
    try expect_boundaries(&reset, &cadence, 3_200, .serial, 1_500, true);
}

test "spawn seeds offload then inlines a sub-overhead job" {
    var entry: SpawnEntry = .{};
    try expect_decision(SpawnExecution.offload, true, spawn_choose(&entry));
    entry.job_ns.record(2_000);
    entry.overhead_ns.record(50_000);
    try expect_decision(SpawnExecution.offload, true, spawn_choose(&entry));
    entry.job_ns.record(2_000);
    entry.overhead_ns.record(50_000);
    try expect_decision(SpawnExecution.inlined, false, spawn_choose(&entry));
}

test "spawn keeps offloading a job bigger than the overhead" {
    var entry: SpawnEntry = .{};
    try expect_decision(SpawnExecution.offload, true, spawn_choose(&entry));
    entry.job_ns.record(50_000);
    entry.overhead_ns.record(5_000);
    try expect_decision(SpawnExecution.inlined, true, spawn_choose(&entry));
    entry.inline_ns.record(50_000);
    for (0..2 * resample_interval) |_| {
        const decision = spawn_choose(&entry);
        try testing.expectEqual(SpawnExecution.offload, decision.path);
        if (decision.measure) {
            entry.job_ns.record(50_000);
            entry.overhead_ns.record(5_000);
        }
    }
}

test "spawn probe learns the inline wall" {
    var entry: SpawnEntry = .{};
    try expect_decision(SpawnExecution.offload, true, spawn_choose(&entry));
    entry.job_ns.record(25_000);
    entry.overhead_ns.record(10_000);
    try expect_decision(SpawnExecution.inlined, true, spawn_choose(&entry));
    entry.inline_ns.record(8_000);
    try expect_decision(SpawnExecution.inlined, false, spawn_choose(&entry));
}

test "spawn budget caps inline when the overhead is inflated" {
    var entry: SpawnEntry = .{};
    try expect_decision(SpawnExecution.offload, true, spawn_choose(&entry));
    entry.job_ns.record(2_000_000);
    entry.overhead_ns.record(50_000_000);
    for (0..2 * resample_interval) |_| {
        const decision = spawn_choose(&entry);
        try testing.expectEqual(SpawnExecution.offload, decision.path);
        if (decision.measure) {
            entry.job_ns.record(2_000_000);
            entry.overhead_ns.record(50_000_000);
        }
    }
}

test "spawn with a single worker always inlines" {
    var policy = Policy.init(testing.io);
    const plan = policy.choose_spawn(site, 64, 1, .outside);
    try testing.expectEqual(SpawnPlan.fixed(.inlined), plan);
}

test "spawn inline EWMA crossing the overhead revokes inline" {
    var entry: SpawnEntry = .{};
    entry.job_ns.record(2_000);
    entry.overhead_ns.record(50_000);
    entry.inline_ns.record(2_000);
    try testing.expectEqual(SpawnExecution.inlined, spawn_choose(&entry).path);
    entry.inline_ns.record(500_000);
    try testing.expectEqual(@as(?u64, 101_600), entry.inline_ns.get());
    try testing.expectEqual(SpawnExecution.offload, spawn_choose(&entry).path);
}

test "spawn entries bucket by len" {
    var policy = Policy.init(testing.io);
    for ([_]usize{ 1, 2, 3 }) |len| _ = policy.choose_spawn(site, len, parallelism, .outside);
    try testing.expectEqual(@as(usize, 2), policy.spawn_len());
}

fn spawn_plan(execution: SpawnExecution, spawner: Spawner, measure: bool) SpawnPlan {
    return .{ .execution = execution, .spawner = spawner, .measure = measure };
}

test "spawn records feed choose" {
    var policy = Policy.init(testing.io);
    const offload = spawn_plan(.offload, .outside, true);
    try testing.expectEqual(offload, policy.choose_spawn(site, 64, parallelism, .outside));
    policy.record_spawn_job(site, 64, parallelism, offload, us(25));
    policy.record_spawn_round_trip(site, 64, parallelism, offload, us(10), 0);
    const probe = policy.choose_spawn(site, 64, parallelism, .outside);
    try testing.expectEqual(spawn_plan(.inlined, .outside, true), probe);
    policy.record_spawn_inline(site, 64, parallelism, us(8));
    const settled = policy.choose_spawn(site, 64, parallelism, .outside);
    try testing.expectEqual(spawn_plan(.inlined, .outside, false), settled);
}

test "spawn placement learns external job times" {
    var policy = Policy.init(testing.io);
    const Next = struct {
        fn plan(target: *Policy) SpawnPlan {
            const chosen = target.choose_spawn(site, 64, parallelism, .outside);
            return target.choose_spawn_placement(site, 64, parallelism, chosen);
        }
    };
    const seeds = [_]struct { placement: Placement, millis: u64 }{
        .{ .placement = .wide, .millis = 8 },
        .{ .placement = .local, .millis = 2 },
    };
    for (seeds) |seed| {
        const plan = Next.plan(&policy);
        try testing.expectEqual(SpawnExecution.offload, plan.execution);
        try testing.expectEqual(@as(?Placement, seed.placement), plan.placement);
        try testing.expect(plan.measure);
        policy.record_spawn_job(site, 64, parallelism, plan, ms(seed.millis));
    }
    const worker = policy.choose_spawn(site, 64, parallelism, .worker);
    try testing.expectEqual(Spawner.worker, worker.spawner);
    try testing.expectEqual(@as(?Placement, null), worker.placement);
    policy.record_spawn_job(site, 64, parallelism, worker, ms(30));
    const entry = policy.spawn_entry(site, 64, parallelism).?;
    try testing.expectEqual(@as(?u64, 8_000_000), entry.placement.estimate(.wide));
    try testing.expectEqual(@as(?u64, 2_000_000), entry.placement.estimate(.local));
    try testing.expectEqual(@as(?Placement, .wide), Next.plan(&policy).placement);
    try testing.expectEqual(@as(?Placement, .local), Next.plan(&policy).placement);
}

test "choice seeds then prefers the faster placement" {
    var choice: Choice = .{};
    try testing.expectEqual(Placement.wide, choice.choose(null).path);
    choice.record(.wide, 100_000);
    try testing.expectEqual(Placement.local, choice.choose(null).path);
    choice.record(.local, 50_000);
    try testing.expectEqual(Placement.wide, choice.choose(null).path);
    choice.record(.wide, 100_000);
    for (1..resample_interval << 1) |_| {
        try testing.expectEqual(Placement.local, choice.choose(null).path);
    }
    try testing.expectEqual(Placement.wide, choice.choose(null).path);
}

test "choice ties prefer wide" {
    var choice: Choice = .{};
    choice.record(.wide, 50_000);
    choice.record(.local, 50_000);
    choice.cadence.since_probe = 1;
    try testing.expectEqual(Placement.wide, choice.choose(null).path);
}

test "choice second sample replaces a slow seed" {
    var choice: Choice = .{};
    try expect_decision(Placement.wide, true, choice.choose(null));
    choice.record(.wide, 6_000_000);
    try expect_decision(Placement.local, true, choice.choose(null));
    choice.record(.local, 5_200_000);
    try expect_decision(Placement.wide, true, choice.choose(null));
    choice.record(.wide, 4_800_000);
    try testing.expectEqual(@as(?u64, 4_800_000), choice.estimate(.wide));
    try testing.expectEqual(Placement.wide, choice.preferred());
    try expect_decision(Placement.wide, false, choice.choose(null));
    choice.record(.wide, 5_500_000);
    try testing.expectEqual(@as(?u64, 4_940_000), choice.estimate(.wide));

    var slower: Choice = .{};
    slower.record(.wide, 5_000_000);
    slower.record(.wide, 6_000_000);
    try testing.expectEqual(@as(?u64, 5_200_000), slower.estimate(.wide));
}

test "choice recovers after a failed local seed" {
    var policy = Policy.init(testing.io);
    const Call = struct {
        fn plan(target: *Policy) RunPlan {
            return target.choose_run(site, 10, 10, parallelism, .either);
        }
        fn record_perfect(target: *Policy, made: RunPlan, millis: u64) void {
            const sample: policy_module.RunSample = .{
                .wall_ns = ms(millis),
                .busy_ns = ms(millis) * parallelism,
            };
            target.record_run(site, 10, 10, parallelism, made, sample);
        }
    };
    const wide: RunPlan = .{ .execution = .parallel, .placement = .wide, .measure = true };
    const local: RunPlan = .{ .execution = .parallel, .placement = .local, .measure = true };
    try testing.expectEqual(wide, Call.plan(&policy));
    Call.record_perfect(&policy, wide, 8);
    // The Local seed fails and records nothing, so Local is offered again.
    try testing.expectEqual(local, Call.plan(&policy));
    try testing.expectEqual(local, Call.plan(&policy));
    Call.record_perfect(&policy, local, 6);
    try testing.expectEqual(wide, Call.plan(&policy));
    Call.record_perfect(&policy, wide, 5);
    try testing.expectEqual(wide, Call.plan(&policy));
}

test "spawn recorded accepts a worker round trip" {
    var policy = Policy.init(testing.io);
    const plan = policy.choose_spawn(site, 64, parallelism, .worker);
    try testing.expectEqual(spawn_plan(.offload, .worker, true), plan);
    const fresh = policy.spawn_entry(site, 64, parallelism).?;
    try testing.expectEqual(@as(?u64, null), fresh.own_overhead_ns.get());
    policy.record_spawn_round_trip(site, 64, parallelism, plan, us(30), us(10));
    const entry = policy.spawn_entry(site, 64, parallelism).?;
    try testing.expectEqual(@as(?u64, null), entry.overhead_ns.get());
    try testing.expectEqual(@as(?u64, 20_000), entry.own_overhead_ns.get());
}

test "spawn uses the job EWMA" {
    var entry: SpawnEntry = .{};
    entry.job_ns.record(2_000);
    entry.overhead_ns.record(50_000);
    entry.inline_ns.record(2_000);
    entry.inline_ns.record(100_000);
    try testing.expectEqual(@as(?u64, 21_600), entry.inline_ns.get());
    try testing.expectEqual(SpawnExecution.inlined, spawn_choose(&entry).path);
}

test "spawn recovers a stale inline estimate" {
    var entry: SpawnEntry = .{};
    for (0..2) |_| {
        entry.job_ns.record(2_000);
        entry.overhead_ns.record(50_000);
        entry.inline_ns.record(15_000_000);
    }
    const limit = 18 * (resample_interval << max_shift) + 3_600;
    var calls: u32 = 0;
    while (true) {
        calls += 1;
        try testing.expect(calls <= limit);
        const decision = spawn_choose(&entry);
        switch (decision.path) {
            .inlined => {
                if (decision.measure) entry.inline_ns.record(2_000);
                if (entry.inline_ns.get().? <= 50_000) break;
            },
            .offload => if (decision.measure) {
                entry.job_ns.record(2_000);
                entry.overhead_ns.record(50_000);
            },
        }
    }
    try testing.expectEqual(limit, calls);
}

test "spawn inline records on cadence and probes offload, capped" {
    const cases = [_]struct { job: u64, interval: u32 }{
        .{ .job = 30_000, .interval = resample_interval },
        .{ .job = 2_000, .interval = resample_interval << max_shift },
    };
    for (cases) |case| {
        var entry: SpawnEntry = .{};
        entry.job_ns.record(case.job);
        entry.overhead_ns.record(50_000);
        for (1..case.interval) |call| {
            const measure = call % preferred_interval == 0;
            try expect_decision(SpawnExecution.inlined, measure, spawn_choose(&entry));
        }
        try expect_decision(SpawnExecution.offload, true, spawn_choose(&entry));
    }
}

test "len buckets are powers of two" {
    try testing.expectEqual(@as(u8, 0), policy_module.len_bucket(0));
    try testing.expectEqual(@as(u8, 1), policy_module.len_bucket(1));
    try testing.expectEqual(@as(u8, 2), policy_module.len_bucket(2));
    try testing.expectEqual(@as(u8, 2), policy_module.len_bucket(3));
    try testing.expectEqual(@as(u8, 64), policy_module.len_bucket(std.math.maxInt(u64)));
}

test "a full table runs parallel untimed" {
    var policy = Policy.init(testing.io);
    for (0..policy_module.run_entries_max) |index| {
        _ = policy.choose_run(index + 1, 10, 10, parallelism, .{ .fixed = .wide });
    }
    const plan = policy.choose_run(0, 10, 10, parallelism, .{ .fixed = .wide });
    const expected: RunPlan = .{ .execution = .parallel, .placement = .wide, .measure = false };
    try testing.expectEqual(expected, plan);
    try testing.expectEqual(@as(usize, policy_module.run_entries_max), policy.len());
}
