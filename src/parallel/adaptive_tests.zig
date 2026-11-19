//! Tests of an adaptive Rayon's use of its policy, ported from commonware's
//! `parallel/src/lib.rs`: spawn decisions, busy-time metering of measured runs, run_batches'
//! single decision and success-only samples, and one policy entry per call site and size
//! bucket. A call site is a return address, so calls meant to share one go through a single
//! non-inlined call instruction in a loop with a runtime trip count, which the optimizer can
//! neither unroll nor merge with another site.

const std = @import("std");
const testing = std.testing;
const parallel = @import("root.zig");

const Range = parallel.Range;
const Rayon = parallel.Rayon;
const Policy = parallel.Policy;
const ThreadPool = parallel.ThreadPool;
const Placement = parallel.policy.Placement;
const TestClock = parallel.TestClock;
const gpa = testing.allocator;
const us = std.time.ns_per_us;
const ms = std.time.ns_per_ms;

fn create_pool(threads: u32) !*ThreadPool {
    return ThreadPool.create(gpa, testing.io, .{ .threads = threads });
}

/// A runtime count of one-element slices, so loops over call sites cannot be unrolled.
fn runtime(values: anytype) @TypeOf(values) {
    var copy = values;
    std.mem.doNotOptimizeAway(&copy);
    return copy;
}

fn now_ns() u64 {
    return @intCast(std.Io.Clock.awake.now(testing.io).nanoseconds);
}

/// The id of the thread a spawned job ran on, after spinning `spin_ns` on `clock`.
const ThreadOf = struct {
    clock: ?*TestClock = null,
    spin_ns: u64 = 0,
    pub fn call(job: ThreadOf) std.Thread.Id {
        if (job.clock) |clock| clock.spin(job.spin_ns);
        return std.Thread.getCurrentId();
    }
};

/// Spawns `job` and returns whether the strategy handed it to the pool. Waiting may take a
/// queued job back, so the thread a job ran on does not tell.
fn spawn_site(strategy: Rayon, job: ThreadOf) bool {
    var task: parallel.Task(ThreadOf) = .init(job);
    strategy.spawn(64, &task);
    const offloaded = task.is_offloaded();
    _ = strategy.block_on(&task);
    return offloaded;
}

test "spawn inlines a job cheaper than its hand-off" {
    // commonware `spawn_inlines_a_sub_overhead_job`: after 2 us jobs with 52 us round trips
    // are recorded at a call site, its next spawn runs on the calling thread.
    const pool = try create_pool(3);
    defer pool.destroy();
    var policy = Policy.init(testing.io);
    const strategy = Rayon.init(pool).with_policy(&policy);
    const threads = pool.threads;
    // The first spawn only finds the site; forget the round trip it measured.
    _ = @call(.never_inline, spawn_site, .{ strategy, ThreadOf{} });
    const site = policy.spawn_entries.keys[0].site;
    policy = Policy.init(testing.io);
    for (0..2) |_| {
        const plan = policy.choose_spawn(site, 64, threads, .outside);
        try testing.expectEqual(parallel.policy.SpawnExecution.offload, plan.execution);
        try testing.expect(plan.measure);
        policy.record_spawn_job(site, 64, threads, plan, 2 * us);
        policy.record_spawn_round_trip(site, 64, threads, plan, 52 * us, 2 * us);
    }
    try testing.expect(!@call(.never_inline, spawn_site, .{ strategy, ThreadOf{} }));
    try testing.expectEqual(@as(usize, 1), policy.spawn_len());
}

test "spawn keeps offloading jobs over the inline budget" {
    // commonware `spawn_keeps_offloading_big_jobs`: jobs of 2 ms on the virtual clock never
    // run on the caller.
    const pool = try create_pool(3);
    defer pool.destroy();
    var clock: TestClock = .{};
    var policy = Policy.init(testing.io);
    const strategy = Rayon.init(pool).with_policy(&policy).with_clock(&clock);
    for (0..runtime(@as(usize, 20))) |_| {
        const job: ThreadOf = .{ .clock = &clock, .spin_ns = 2 * ms };
        try testing.expect(@call(.never_inline, spawn_site, .{ strategy, job }));
    }
}

/// The busy-time estimate `policy`'s only run entry recorded for the Wide placement.
fn recorded_busy(policy: *Policy) ?u64 {
    std.debug.assert(policy.len() == 1);
    return policy.run_entries.entries[0].busy_ns[@backingInt(Placement.wide)].get();
}

/// A map item that spins `ns` on the virtual clock, charging whichever thread runs it.
const SpinEach = struct {
    clock: *TestClock,
    ns: u64,
    pub fn map(each: SpinEach, _: usize) u8 {
        each.clock.spin(each.ns);
        return 0;
    }
};

/// A pool, a policy, and a strategy timing on a virtual clock (commonware `virtual_strategy`).
const Virtual = struct {
    pool: *ThreadPool,
    clock: TestClock = .{},
    policy: Policy,

    fn init(threads: u32) !Virtual {
        return .{ .pool = try create_pool(threads), .policy = Policy.init(testing.io) };
    }

    fn deinit(virtual: *Virtual) void {
        virtual.pool.destroy();
    }

    fn strategy(virtual: *Virtual) Rayon {
        return Rayon.init(virtual.pool).with_policy(&virtual.policy).with_clock(&virtual.clock);
    }
};

test "a measured run records the busy time of all its items" {
    // commonware `measured_run_records_busy_time_of_all_items`: 32 items that each spin 1 ms
    // record 32 ms, wherever each item runs.
    var virtual: Virtual = try .init(3);
    defer virtual.deinit();
    const each: SpinEach = .{ .clock = &virtual.clock, .ns = ms };
    gpa.free(try virtual.strategy().map_collect(gpa, Range.upto(32), each));
    try testing.expectEqual(@as(?u64, 32 * ms), recorded_busy(&virtual.policy));
}

const SpinThenAwait = struct {
    clock: *TestClock,
    stolen: *std.atomic.Value(bool),
    pub fn call(side: SpinThenAwait) void {
        side.clock.spin(5 * ms);
        const start = now_ns();
        while (!side.stolen.load(.acquire)) {
            std.debug.assert(now_ns() - start < 10 * std.time.ns_per_s);
            std.atomic.spinLoopHint();
        }
    }
};

const MarkThenSpin = struct {
    clock: *TestClock,
    stolen: *std.atomic.Value(bool),
    pub fn call(side: MarkThenSpin) void {
        side.stolen.store(true, .release);
        side.clock.spin(40 * ms);
    }
};

test "a measured join is charged its work, not the joiner's wait" {
    // commonware `measured_join_excludes_idle_waits`: the 5 ms side and the 40 ms that pass on
    // the worker that took the other side charge 45 ms. The joiner waits for the second side
    // to be taken, and that wait passes no time on its clock.
    var virtual: Virtual = try .init(3);
    defer virtual.deinit();
    var stolen: std.atomic.Value(bool) = .init(false);
    _ = virtual.strategy().join(
        SpinThenAwait{ .clock = &virtual.clock, .stolen = &stolen },
        MarkThenSpin{ .clock = &virtual.clock, .stolen = &stolen },
    );
    try testing.expectEqual(@as(?u64, 45 * ms), recorded_busy(&virtual.policy));
}

/// Holds a worker until released, letting `elapse_ns` pass for every thread once it starts.
const Occupy = struct {
    clock: *TestClock,
    elapse_ns: u64,
    started: *std.atomic.Value(usize),
    release: *std.atomic.Value(bool),
    pub fn call(occupy: Occupy) void {
        occupy.clock.elapse(occupy.elapse_ns);
        _ = occupy.started.fetchAdd(1, .acq_rel);
        while (!occupy.release.load(.acquire)) std.atomic.spinLoopHint();
    }
};

test "a measured run is not charged for time its workers spend elsewhere" {
    // commonware `measured_run_excludes_queueing`: two occupied workers let 50 ms pass each,
    // and the run's four 1 ms items are charged 4 ms. zigware's caller takes back the jobs no
    // worker has started, so the items run on the caller rather than wait in the queue.
    var virtual: Virtual = try .init(2);
    defer virtual.deinit();
    var started: std.atomic.Value(usize) = .init(0);
    var release: std.atomic.Value(bool) = .init(false);
    const occupy: Occupy = .{
        .clock = &virtual.clock,
        .elapse_ns = 50 * ms,
        .started = &started,
        .release = &release,
    };
    var occupied: [2]parallel.Task(Occupy) = .{ .init(occupy), .init(occupy) };
    const fixed = Rayon.init(virtual.pool);
    for (&occupied) |*task| fixed.spawn(1, task);
    while (started.load(.acquire) < occupied.len) std.atomic.spinLoopHint();
    const each: SpinEach = .{ .clock = &virtual.clock, .ns = ms };
    gpa.free(try virtual.strategy().map_collect(gpa, Range.upto(4), each));
    release.store(true, .release);
    for (&occupied) |*task| fixed.block_on(task);
    try testing.expectEqual(@as(?u64, 4 * ms), recorded_busy(&virtual.policy));
}

/// Each batch's range and the thread that mapped it.
const Located = struct { range: parallel.Range, thread: std.Thread.Id };

const LocateBatches = struct {
    out: *[16]Located,
    count: *usize,

    pub fn run(op: LocateBatches, batches: anytype) void {
        op.count.* = batches.count();
        const Map = struct {
            pub fn map(_: @This(), _: usize, range: parallel.Range) Located {
                return .{ .range = range, .thread = std.Thread.getCurrentId() };
            }
        };
        batches.map_collect(op.out[0..batches.count()], Map{});
    }
};

fn locate_batches_site(strategy: Rayon, out: *[16]Located) usize {
    var count: usize = 0;
    strategy.run_batches(16, 1, 1, LocateBatches{ .out = out, .count = &count });
    return count;
}

test "run_batches runs a serial decision as one batch on the calling thread" {
    // commonware `run_batches_runs_serial_decision_on_calling_thread`: once serial is the
    // faster path, a call that could form four batches gets one whole batch on the caller.
    const pool = try create_pool(4);
    defer pool.destroy();
    var policy = Policy.init(testing.io);
    const strategy = Rayon.init(pool).with_policy(&policy);
    const planned = strategy.parallelism();
    var out: [16]Located = undefined;
    var count: usize = 0;
    for (0..runtime(@as(usize, 2))) |call| {
        count = @call(.never_inline, locate_batches_site, .{ strategy, &out });
        if (call > 0) continue;
        // The first call only finds the site; forget its sample and record serial as faster.
        const site = policy.run_entries.keys[0].site;
        policy = Policy.init(testing.io);
        const parallel_plan: parallel.policy.RunPlan = .{
            .execution = .parallel,
            .placement = .wide,
            .measure = true,
        };
        policy.record_run(site, 16, 16, planned, parallel_plan, .{
            .wall_ns = 100 * us,
            .busy_ns = 400 * us,
        });
        const serial_plan: parallel.policy.RunPlan = .{
            .execution = .serial,
            .placement = .wide,
            .measure = true,
        };
        policy.record_run(site, 16, 16, planned, serial_plan, .{
            .wall_ns = 95 * us,
            .busy_ns = 0,
        });
    }
    try testing.expectEqual(@as(usize, 1), policy.len());
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(std.Thread.getCurrentId(), out[0].thread);
    try testing.expectEqual(@as(usize, 0), out[0].range.start);
    try testing.expectEqual(@as(usize, 16), out[0].range.end);
}

const Flagged = struct {
    fail_mapping: bool,
    fail_assembly: bool,

    pub fn run(op: Flagged, batches: anytype) error{Failed}!usize {
        var lens: [16]usize = undefined;
        const Map = struct {
            fail: bool,
            pub fn map(flags: @This(), _: usize, range: parallel.Range) error{Failed}!usize {
                if (flags.fail) return error.Failed;
                return range.end - range.start;
            }
        };
        try batches.try_map_collect(lens[0..batches.count()], Map{ .fail = op.fail_mapping });
        var total: usize = 0;
        for (lens[0..batches.count()]) |len| total += len;
        if (op.fail_assembly) return error.Failed;
        return total;
    }
};

inline fn run_flagged(strategy: Rayon, fail_mapping: bool, fail_assembly: bool) !usize {
    const op: Flagged = .{ .fail_mapping = fail_mapping, .fail_assembly = fail_assembly };
    return strategy.try_run_batches(16, 1, std.math.maxInt(usize), op);
}

fn run_failing_mapping(strategy: Rayon) !usize {
    return run_flagged(strategy, true, false);
}

fn run_failing_assembly(strategy: Rayon) !usize {
    return run_flagged(strategy, false, true);
}

fn run_succeeding(strategy: Rayon) !usize {
    return run_flagged(strategy, false, false);
}

test "run_batches records only complete successes" {
    // commonware `run_batches_records_only_complete_success`: a failure while mapping or
    // assembling makes an entry without samples.
    const pool = try create_pool(3);
    defer pool.destroy();
    var policy = Policy.init(testing.io);
    const strategy = Rayon.init(pool).with_policy(&policy);
    try testing.expectError(error.Failed, @call(.never_inline, run_failing_mapping, .{strategy}));
    try testing.expectError(error.Failed, @call(.never_inline, run_failing_assembly, .{strategy}));
    try testing.expectEqual(@as(usize, 16), try @call(.never_inline, run_succeeding, .{strategy}));
    try testing.expectEqual(@as(usize, 3), policy.len());
    for (policy.run_entries.entries[0..2]) |entry| {
        try testing.expectEqual(@as(?u64, null), entry.serial_ns.get());
        try testing.expectEqual(@as(?u64, null), entry.placement.estimate(.wide));
    }
    const success = &policy.run_entries.entries[2];
    const serial = success.serial_ns.get();
    try testing.expect(serial != null or success.placement.estimate(.wide) != null);
}

const LenOfBatches = struct {
    total: *usize,
    pub fn run(op: LenOfBatches, batches: anytype) void {
        var lens: [16]usize = undefined;
        const Map = struct {
            pub fn map(_: @This(), _: usize, range: parallel.Range) usize {
                return range.end - range.start;
            }
        };
        batches.map_collect(lens[0..batches.count()], Map{});
        for (lens[0..batches.count()]) |len| op.total.* += len;
    }
};

test "run_batches makes one policy decision, and without a policy none" {
    // commonware `run_batches_keeps_one_policy_decision_and_fixed_execution`; zigware's
    // caller runs batches while it waits, so a fixed strategy's batches need not all run on
    // pool workers.
    const pool = try create_pool(3);
    defer pool.destroy();
    var policy = Policy.init(testing.io);
    const strategy = Rayon.init(pool).with_policy(&policy);
    var total: usize = 0;
    strategy.run_batches(16, 1, 1, LenOfBatches{ .total = &total });
    try testing.expectEqual(@as(usize, 16), total);
    try testing.expectEqual(@as(usize, 1), policy.len());
    const fixed = Rayon.init(pool);
    for (0..3) |_| {
        total = 0;
        fixed.run_batches(16, 1, 1, LenOfBatches{ .total = &total });
        try testing.expectEqual(@as(usize, 16), total);
    }
    try testing.expectEqual(@as(usize, 1), policy.len());
}

const Identity = struct {
    pub fn map(_: Identity, x: usize) usize {
        return x;
    }
};

const Sum = struct {
    pub fn identity(_: Sum) usize {
        return 0;
    }
    pub fn fold(_: Sum, acc: usize, x: usize) usize {
        return acc + x;
    }
    pub fn reduce(_: Sum, a: usize, b: usize) usize {
        return a + b;
    }
};

const TrySum = struct {
    pub fn identity(_: TrySum) usize {
        return 0;
    }
    pub fn fold(_: TrySum, acc: usize, x: usize) error{Never}!usize {
        return acc + x;
    }
    pub fn reduce(_: TrySum, a: usize, b: usize) usize {
        return a + b;
    }
};

const TryIdentity = struct {
    pub fn map(_: TryIdentity, x: usize) error{Never}!usize {
        return x;
    }
};

const Counted = struct {
    pub fn init(_: Counted) usize {
        return 0;
    }
    pub fn map(_: Counted, counter: *usize, x: usize) usize {
        counter.* += 1;
        return x;
    }
};

const FoldInitSum = struct {
    pub fn init(_: FoldInitSum) void {}
    pub fn identity(_: FoldInitSum) usize {
        return 0;
    }
    pub fn fold(_: FoldInitSum, acc: usize, _: *void, x: usize) usize {
        return acc + x;
    }
    pub fn reduce(_: FoldInitSum, a: usize, b: usize) usize {
        return a + b;
    }
};

const Evens = struct {
    pub fn map(_: Evens, x: usize) struct { usize, ?usize } {
        return .{ x, if (x % 2 == 0) x else null };
    }
};

const Bodies = struct {
    pub fn serial(_: Bodies) usize {
        return 1;
    }
    pub fn parallel(_: Bodies) usize {
        return 2;
    }
};

const One = struct {
    pub fn call(_: One) u32 {
        return 1;
    }
};

test "an adaptive Rayon records each adaptive operation" {
    // commonware `adaptive_policy_records_all_adaptive_operations`: twelve operations at
    // twelve call sites make twelve entries.
    const pool = try create_pool(3);
    defer pool.destroy();
    var policy = Policy.init(testing.io);
    const s = Rayon.init(pool).with_policy(&policy);
    const items = Range.upto(16);
    _ = s.fold_init(items, FoldInitSum{});
    _ = s.fold(items, Sum{});
    _ = try s.try_fold(items, TrySum{});
    gpa.free(try s.map_collect(gpa, items, Identity{}));
    gpa.free(try s.try_map_collect(gpa, items, TryIdentity{}));
    gpa.free(try s.map_init_collect(gpa, items, Counted{}));
    gpa.free(try s.map_init_collect_with_multiplier(gpa, items, 2, Counted{}));
    _ = s.run(16, Bodies{});
    const partitioned = try s.map_partition_collect(gpa, items, Evens{});
    gpa.free(partitioned.results);
    gpa.free(partitioned.filtered);
    _ = s.join(One{}, One{});
    var sortable = [_]i32{ 3, 2, 1 };
    s.sort_by(i32, &sortable, {}, std.sort.asc(i32));
    try testing.expectEqualSlices(i32, &.{ 1, 2, 3 }, &sortable);
    s.sort_unstable_by(i32, &sortable, {}, std.sort.desc(i32));
    try testing.expectEqualSlices(i32, &.{ 3, 2, 1 }, &sortable);
    try testing.expectEqual(@as(usize, 12), policy.len());
}

fn map_site(strategy: Rayon, len: usize, multiplier: usize) !void {
    const out = try strategy.map_init_collect_with_multiplier(
        gpa,
        Range.upto(len),
        multiplier,
        Counted{},
    );
    gpa.free(out);
}

fn run_site(strategy: Rayon, len: usize) void {
    _ = strategy.run(len, Bodies{});
}

test "an adaptive Rayon buckets entries by input size and work" {
    // commonware `adaptive_policy_buckets_by_input_size`, `_by_work_multiplier`, and
    // `adaptive_run_buckets_by_input_size`: sizes 1, 2, and 3 fall in two power-of-two
    // buckets, as do 16 items at multipliers 1, 2, and 3.
    const pool = try create_pool(3);
    defer pool.destroy();
    const sizes = [_]usize{ 1, 2, 3 };
    var policy = Policy.init(testing.io);
    const strategy = Rayon.init(pool).with_policy(&policy);
    for (runtime(sizes)) |len| try @call(.never_inline, map_site, .{ strategy, len, 1 });
    try testing.expectEqual(@as(usize, 2), policy.len());
    var by_work = Policy.init(testing.io);
    const work = Rayon.init(pool).with_policy(&by_work);
    for (runtime(sizes)) |multiplier| {
        try @call(.never_inline, map_site, .{ work, 16, multiplier });
    }
    try testing.expectEqual(@as(usize, 2), by_work.len());
    var by_run = Policy.init(testing.io);
    const runs = Rayon.init(pool).with_policy(&by_run);
    for (runtime(sizes)) |len| @call(.never_inline, run_site, .{ runs, len });
    try testing.expectEqual(@as(usize, 2), by_run.len());
}

const Ignore = struct {
    pub fn run(_: Ignore, _: anytype) void {}
};

fn partition_site(strategy: Rayon) !void {
    const partitioned = try strategy.map_partition_collect(gpa, Range.upto(16), Evens{});
    gpa.free(partitioned.results);
    gpa.free(partitioned.filtered);
}

test "an adaptive Rayon keys entries by the caller's call site" {
    // commonware `adaptive_policy_keys_default_methods_by_external_callsite` and
    // `adaptive_policy_keys_partition_map_by_external_callsite`.
    const pool = try create_pool(3);
    defer pool.destroy();
    var policy = Policy.init(testing.io);
    const s = Rayon.init(pool).with_policy(&policy);
    _ = s.fold(Range.upto(16), Sum{});
    _ = s.fold(Range.upto(16), Sum{});
    s.run_batches(16, 1, 1, Ignore{});
    s.run_batches(16, 1, 1, Ignore{});
    try testing.expectEqual(@as(usize, 4), policy.len());
    var partitions = Policy.init(testing.io);
    const p = Rayon.init(pool).with_policy(&partitions);
    try @call(.never_inline, partition_site, .{p});
    const partitioned = try p.map_partition_collect(gpa, Range.upto(16), Evens{});
    gpa.free(partitioned.results);
    gpa.free(partitioned.filtered);
    try testing.expectEqual(@as(usize, 2), partitions.len());
}

fn join_site(strategy: Rayon) !void {
    const a, const b = strategy.join(One{}, One{});
    try testing.expectEqual(@as(u32, 2), a + b);
}

test "joins at one call site share a policy entry" {
    // commonware `join_shares_policy_entry_per_callsite`. Its nested joins from pool workers
    // skip the policy; zigware's workers have no identity, so every join counts as outside
    // (lane Decisions).
    const pool = try create_pool(3);
    defer pool.destroy();
    var policy = Policy.init(testing.io);
    const strategy = Rayon.init(pool).with_policy(&policy);
    for (0..runtime(@as(usize, 3))) |_| try @call(.never_inline, join_site, .{strategy});
    try testing.expectEqual(@as(usize, 1), policy.len());
    _ = strategy.join(One{}, One{});
    try testing.expectEqual(@as(usize, 2), policy.len());
}
