//! Tests of the behavior commonware's `parallel` API promises of a Rayon strategy and its pool,
//! ported from tests the lane audit first filed as not portable because they drive rayon's
//! grouped pool, `install`, or futures. Each keeps the promise its original checks (item order,
//! submission order, nested and cross-pool calls that never deadlock, concurrent callers, a
//! waiting job that runs its own dependency, zero-thread pools, and policy scoping) and drops
//! what zigware's single-group pool does not have: placements, worker identities, and futures.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const parallel = @import("root.zig");

const Range = parallel.Range;
const Rayon = parallel.Rayon;
const Policy = parallel.Policy;
const Task = parallel.Task;
const ThreadPool = parallel.ThreadPool;
const gpa = testing.allocator;
const us = std.time.ns_per_us;
const ms = std.time.ns_per_ms;

fn create_pool(threads: u32) !*ThreadPool {
    return ThreadPool.create(gpa, testing.io, .{ .threads = threads });
}

fn sleep_ns(ns: u64) void {
    testing.io.sleep(.fromNanoseconds(ns), .awake) catch {};
}

fn now_ns() u64 {
    return @intCast(std.Io.Clock.awake.now(testing.io).nanoseconds);
}

fn spin(ns: u64) void {
    const start = now_ns();
    while (now_ns() - start < ns) std.atomic.spinLoopHint();
}

/// Waits up to 10 s for `value` to reach `target`, and returns whether it did.
fn await_count(value: *const std.atomic.Value(usize), target: usize) bool {
    const deadline = now_ns() + 10 * std.time.ns_per_s;
    while (value.load(.acquire) < target) {
        if (now_ns() > deadline) return false;
        sleep_ns(ms);
    }
    return true;
}

/// Whether the pool's queue is empty: every job was taken by a worker or its caller.
fn queue_empty(pool: *ThreadPool) bool {
    pool.mutex.lockUncancelable(pool.io);
    defer pool.mutex.unlock(pool.io);
    return pool.queue.first == null;
}

/// Occupies the worker that takes it until `release` is set.
const Hold = struct {
    started: *std.atomic.Value(usize),
    release: *std.atomic.Value(bool),

    pub fn call(hold: Hold) void {
        _ = hold.started.fetchAdd(1, .acq_rel);
        while (!hold.release.load(.acquire)) sleep_ns(ms);
    }
};

/// The order in which jobs ran: each entry is the running thread and the job's tag.
const Log = struct {
    const Entry = struct { thread: std.Thread.Id, tag: usize };
    entries: []Entry,
    len: std.atomic.Value(usize) = .init(0),

    fn push(log: *Log, tag: usize) void {
        const slot = log.len.fetchAdd(1, .acq_rel);
        std.debug.assert(slot < log.entries.len);
        log.entries[slot] = .{ .thread = std.Thread.getCurrentId(), .tag = tag };
    }
};

const Record = struct {
    log: *Log,
    tag: usize,

    pub fn call(record: Record) void {
        record.log.push(record.tag);
    }
};

/// Counts the jobs that ran.
const Count = struct {
    ran: *std.atomic.Value(usize),

    pub fn call(count: Count) void {
        _ = count.ran.fetchAdd(1, .acq_rel);
    }
};

/// Waits up to 10 s for all `threads` workers of `pool` to sleep, and returns whether they did.
fn await_sleepers(pool: *ThreadPool, threads: u32) bool {
    const deadline = now_ns() + 10 * std.time.ns_per_s;
    while (pool.sleepers.load(.acquire) < threads) {
        if (now_ns() > deadline) return false;
        sleep_ns(ms);
    }
    return true;
}

test "a job spawned while every worker sleeps wakes a worker to run it" {
    // The pool skips the futex wake when no worker sleeps; a sleeper it fails to count would
    // leave the job queued until its caller takes it back. Each round lets both workers park
    // first, then requires a worker, not the caller, to run the job within the deadline.
    const threads = 2;
    const pool = try create_pool(threads);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var ran: std.atomic.Value(usize) = .init(0);
    for (0..20) |round| {
        try testing.expect(await_sleepers(pool, threads));
        var task: Task(Count) = .init(.{ .ran = &ran });
        rayon.spawn(1, &task);
        // On failure the caller takes the job back, so teardown finds the queue empty.
        defer rayon.block_on(&task);
        try testing.expect(await_count(&ran, round + 1));
    }
    try testing.expect(queue_empty(pool));
}

test "jobs queued behind the held worker run in submission order" {
    // commonware `spawn_external_jobs_keep_submission_order`: on a one-worker pool held busy,
    // ten queued jobs run in the order they were spawned once the worker is released.
    const pool = try create_pool(1);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    for (0..3) |_| {
        var started: std.atomic.Value(usize) = .init(0);
        var release: std.atomic.Value(bool) = .init(false);
        var hold: Task(Hold) = .init(.{ .started = &started, .release = &release });
        rayon.spawn(1, &hold);
        try testing.expect(await_count(&started, 1));
        var entries: [10]Log.Entry = undefined;
        var log: Log = .{ .entries = &entries };
        var tasks: [10]Task(Record) = undefined;
        for (&tasks, 0..) |*task, index| {
            task.* = .init(.{ .log = &log, .tag = index });
            rayon.spawn(1, task);
        }
        release.store(true, .release);
        // Await only after every job ran, so the caller takes none back out of order.
        try testing.expect(await_count(&log.len, tasks.len));
        for (&tasks) |*task| rayon.block_on(task);
        rayon.block_on(&hold);
        for (entries, 0..) |entry, index| try testing.expectEqual(index, entry.tag);
    }
}

const jobs_per_producer = 1000;

fn produce(
    rayon: Rayon,
    log: *Log,
    producer: usize,
    producers: usize,
    tasks: []Task(Record),
) void {
    for (tasks, 0..) |*task, index| {
        task.* = .init(.{ .log = log, .tag = producer * jobs_per_producer + index });
        rayon.spawn(1, task);
    }
    // Await only after every producer's jobs ran on the workers.
    _ = await_count(&log.len, producers * jobs_per_producer);
    for (tasks) |*task| rayon.block_on(task);
}

/// Whether, on each thread, every producer's jobs ran in the order it spawned them.
fn per_thread_order_kept(entries: []const Log.Entry) bool {
    for (entries, 0..) |entry, index| {
        for (entries[index + 1 ..]) |later| {
            if (later.thread != entry.thread) continue;
            if (later.tag / jobs_per_producer != entry.tag / jobs_per_producer) continue;
            if (later.tag < entry.tag) return false;
        }
    }
    return true;
}

test "contended producers' jobs run in submission order on each thread" {
    // commonware `spawn_contended_producers_keep_submission_order`: one producer alone, then
    // four racing, each spawning 1,000 jobs on a four-worker pool.
    const pool = try create_pool(4);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    for ([_]usize{ 1, 4 }) |producers| {
        const entries = try gpa.alloc(Log.Entry, producers * jobs_per_producer);
        defer gpa.free(entries);
        var log: Log = .{ .entries = entries };
        const tasks = try gpa.alloc(Task(Record), producers * jobs_per_producer);
        defer gpa.free(tasks);
        var group: std.Io.Group = .init;
        for (0..producers) |producer| {
            const own = tasks[producer * jobs_per_producer ..][0..jobs_per_producer];
            try group.concurrent(testing.io, produce, .{ rayon, &log, producer, producers, own });
        }
        try group.await(testing.io);
        try testing.expectEqual(producers * jobs_per_producer, log.len.load(.acquire));
        try testing.expect(per_thread_order_kept(entries));
    }
}

/// Spawns the next hop on `pools[index]` and waits for it, sleeping first when `sleepy`.
const Hop = struct {
    pools: []const *ThreadPool,
    index: usize,
    sleep_ns: u64,

    pub fn call(hop: Hop) bool {
        if (hop.index == hop.pools.len) return true;
        if (hop.sleep_ns > 0) sleep_ns(hop.sleep_ns);
        const rayon = Rayon.init(hop.pools[hop.index]);
        var task: Task(Hop) = .init(.{
            .pools = hop.pools,
            .index = hop.index + 1,
            .sleep_ns = hop.sleep_ns,
        });
        rayon.spawn(1, &task);
        return rayon.block_on(&task);
    }
};

test "nested spawns on one-worker pools, within and across pools, never deadlock" {
    // commonware `self_install`, `mutual_install`, `mutual_install_sleepy`, and
    // `install_crosses_pools_and_returns`: a job on a one-worker pool waits for a job on the
    // same pool, or on another that waits for the first again; sleeps let the workers sleep.
    // The sleepy hops sleep 100 ms where commonware sleeps 1 s.
    const first = try create_pool(1);
    defer first.destroy();
    const second = try create_pool(1);
    defer second.destroy();
    const routes = [_][]const *ThreadPool{
        &.{ first, first },
        &.{ first, second, first },
        &.{ first, second, first, second },
    };
    for (routes) |route| {
        for ([_]u64{ 0, 100 * ms }) |sleep| {
            const hop: Hop = .{ .pools = route, .index = 0, .sleep_ns = sleep };
            try testing.expect(hop.call());
        }
    }
    try testing.expect(queue_empty(first));
    try testing.expect(queue_empty(second));
}

const Value = struct {
    value: u64,
    pub fn call(value: Value) u64 {
        return value.value;
    }
};

/// Spawns a job that sends 42 and waits for it.
const Dependent = struct {
    rayon: Rayon,
    pub fn call(dependent: Dependent) u64 {
        var dependency: Task(Value) = .init(.{ .value = 42 });
        dependent.rayon.spawn(1, &dependency);
        return dependent.rayon.block_on(&dependency);
    }
};

test "a waiting job runs its queued dependency while every other worker is held" {
    // commonware `waiting_worker_runs_queued_dependencies`: with the other worker held, job A
    // waits for job B it queued, and A's worker must run B rather than wait for a free worker.
    const pool = try create_pool(2);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var started: std.atomic.Value(usize) = .init(0);
    var release: std.atomic.Value(bool) = .init(false);
    var hold: Task(Hold) = .init(.{ .started = &started, .release = &release });
    rayon.spawn(1, &hold);
    try testing.expect(await_count(&started, 1));
    var dependent: Task(Dependent) = .init(.{ .rayon = rayon });
    rayon.spawn(1, &dependent);
    const deadline = now_ns() + 10 * std.time.ns_per_s;
    while (!dependent.is_done() and now_ns() < deadline) sleep_ns(ms);
    const done_while_held = dependent.is_done();
    release.store(true, .release);
    const value = rayon.block_on(&dependent);
    rayon.block_on(&hold);
    try testing.expect(done_while_held);
    try testing.expectEqual(@as(u64, 42), value);
}

const AddRound = struct {
    round: u64,
    pub fn map(add: AddRound, x: usize) u64 {
        return x + add.round;
    }
};

const Double = struct {
    pub fn map(_: Double, x: usize) u64 {
        return 2 * x;
    }
};

/// A spawned job that runs a nested map and waits for a child job: 240 + `j` + `round`.
const MapAndChild = struct {
    rayon: Rayon,
    j: u64,
    round: u64,

    pub fn call(job: MapAndChild) u64 {
        const doubled = job.rayon.map_collect(gpa, Range.upto(16), Double{}) catch return 0;
        defer gpa.free(doubled);
        var child: Task(Value) = .init(.{ .value = job.j + job.round });
        job.rayon.spawn(1, &child);
        var sum: u64 = 0;
        for (doubled) |value| sum += value;
        return sum + job.rayon.block_on(&child);
    }
};

fn spawn_and_map(rayon: Rayon, failures: *std.atomic.Value(usize)) void {
    for (0..20) |round_index| {
        const round: u64 = round_index;
        var jobs: [4]Task(MapAndChild) = undefined;
        for (&jobs, 0..) |*job, j| {
            job.* = .init(.{ .rayon = rayon, .j = j, .round = round });
            rayon.spawn(64, job);
        }
        var sum: u64 = 0;
        if (rayon.map_collect(gpa, Range.upto(64), AddRound{ .round = round })) |summed| {
            for (summed) |value| sum += value;
            gpa.free(summed);
        } else |_| {}
        if (sum != 2016 + 64 * round) _ = failures.fetchAdd(1, .monotonic);
        for (&jobs, 0..) |*job, j| {
            if (rayon.block_on(job) != 240 + j + round) _ = failures.fetchAdd(1, .monotonic);
        }
    }
}

test "concurrent callers' spawned jobs and maps all complete" {
    // commonware `grouped_jobs_and_runs_complete`: callers on three threads each spawn jobs that
    // run nested maps and wait for child jobs, and run maps themselves, checking every result.
    // The pool ends with nothing queued.
    const pool = try create_pool(4);
    defer pool.destroy();
    var failures: std.atomic.Value(usize) = .init(0);
    var group: std.Io.Group = .init;
    for (0..3) |_| {
        try group.concurrent(testing.io, spawn_and_map, .{ Rayon.init(pool), &failures });
    }
    try group.await(testing.io);
    try testing.expectEqual(@as(usize, 0), failures.load(.acquire));
    try testing.expect(queue_empty(pool));
}

/// Commonware's `mix`: a SplitMix64 finalizer over `seed`.
fn mix(seed: u64) u64 {
    var z = seed +% 0x9e37_79b9_7f4a_7c15;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

/// A random job tree of joins, one-child calls, and spawns, counting the nodes it runs.
const Tree = struct {
    rayon: Rayon,
    nodes: *std.atomic.Value(usize),
    seed: u64,
    depth: u32,

    fn child(node: Tree, seed: u64) Tree {
        std.debug.assert(node.depth > 0);
        return .{
            .rayon = node.rayon,
            .nodes = node.nodes,
            .seed = seed,
            .depth = node.depth - 1,
        };
    }

    pub fn call(node: Tree) void {
        _ = node.nodes.fetchAdd(1, .monotonic);
        const roll = mix(node.seed);
        if (node.depth == 0) return spin((roll % 20) * us);
        const left = node.child(mix(node.seed ^ 1));
        const right = node.child(mix(node.seed ^ 2));
        switch (roll % 4) {
            0 => _ = node.rayon.join(left, right),
            1 => left.call(),
            else => {
                var task: Task(Tree) = .init(left);
                node.rayon.spawn(1, &task);
                right.call();
                node.rayon.block_on(&task);
            },
        }
    }
};

/// Runs a root inline for an even seed, or spawns it and waits for an odd one.
fn run_root(root: Tree) void {
    if (root.seed % 2 == 0) return root.call();
    var task: Task(Tree) = .init(root);
    root.rayon.spawn(1, &task);
    root.rayon.block_on(&task);
}

test "random job trees started from several threads all complete" {
    // commonware `random_placements_complete`: eight random job trees of depth 6 per round,
    // each from its own thread, on a six-worker pool. Each tree runs as many nodes as the same
    // tree run serially on a zero-thread pool.
    const pool = try create_pool(6);
    defer pool.destroy();
    const serial_pool = try create_pool(0);
    defer serial_pool.destroy();
    for (0..20) |round| {
        var rng = utils.TestRng.init(round);
        var seeds: [8]u64 = undefined;
        for (&seeds) |*seed| seed.* = rng.next_u64();
        var nodes: std.atomic.Value(usize) = .init(0);
        var group: std.Io.Group = .init;
        for (seeds) |seed| {
            const root: Tree = .{ .rayon = .init(pool), .nodes = &nodes, .seed = seed, .depth = 6 };
            try group.concurrent(testing.io, run_root, .{root});
        }
        try group.await(testing.io);
        var expected: std.atomic.Value(usize) = .init(0);
        for (seeds) |seed| {
            const root: Tree = .{
                .rayon = .init(serial_pool),
                .nodes = &expected,
                .seed = seed,
                .depth = 6,
            };
            run_root(root);
        }
        try testing.expectEqual(expected.load(.acquire), nodes.load(.acquire));
        try testing.expect(queue_empty(pool));
    }
}

/// Collects `2x` per chunk after a 20 us sleep per item, concatenating chunks in order.
const SlowDoubles = struct {
    const List = std.ArrayList(u64);

    pub fn init(_: SlowDoubles) void {}
    pub fn identity(_: SlowDoubles) List {
        return .empty;
    }
    pub fn fold(_: SlowDoubles, acc: List, _: *void, x: *const u64) List {
        sleep_ns(20 * us);
        var list = acc;
        list.append(gpa, x.* * 2) catch @panic("out of memory");
        return list;
    }
    pub fn reduce(_: SlowDoubles, a: List, b: List) List {
        var left = a;
        var right = b;
        defer right.deinit(gpa);
        left.appendSlice(gpa, right.items) catch @panic("out of memory");
        return left;
    }
};

test "fold_init keeps item order across slow items" {
    // commonware `fold_init_wide_seed_preserves_order`: 1,000 items that sleep 20 us each fold
    // on four threads into the doubled items in input order.
    const pool = try create_pool(3);
    defer pool.destroy();
    var data: [1000]u64 = undefined;
    for (&data, 0..) |*x, index| x.* = index;
    var folded = Rayon.init(pool).fold_init(@as([]const u64, &data), SlowDoubles{});
    defer folded.deinit(gpa);
    try testing.expectEqual(data.len, folded.items.len);
    for (folded.items, 0..) |x, index| try testing.expectEqual(2 * index, x);
}

/// A set of the threads that ran items, guarded by `testing.io`'s mutex.
const Threads = struct {
    mutex: std.Io.Mutex = .init,
    ids: [16]std.Thread.Id = undefined,
    len: usize = 0,

    fn insert(threads: *Threads) void {
        const id = std.Thread.getCurrentId();
        threads.mutex.lockUncancelable(testing.io);
        defer threads.mutex.unlock(testing.io);
        for (threads.ids[0..threads.len]) |seen| if (seen == id) return;
        threads.ids[threads.len] = id;
        threads.len += 1;
    }

    /// The threads other than `caller`.
    fn others(threads: *const Threads, caller: std.Thread.Id) usize {
        var count: usize = 0;
        for (threads.ids[0..threads.len]) |id| count += @intFromBool(id != caller);
        return count;
    }
};

const Product = struct {
    x: u64,
    threads: *Threads,
    pub fn map(product: Product, y: usize) u64 {
        sleep_ns(100 * us);
        product.threads.insert();
        return product.x * y;
    }
};

const NestedSum = struct {
    rayon: Rayon,
    threads: *Threads,
    pub fn map(nested: NestedSum, x: usize) u64 {
        const products = nested.rayon.map_collect(gpa, Range.upto(16), Product{
            .x = x,
            .threads = nested.threads,
        }) catch return 0;
        defer gpa.free(products);
        var sum: u64 = 0;
        for (products) |value| sum += value;
        return sum;
    }
};

test "nested maps use every pool worker and leave nothing queued" {
    // commonware `nested_calls_use_current_pool`: a map whose items each run a nested map, on
    // one- and two-worker pools planned for four. Every worker takes part, and zigware's caller
    // also helps (lane Decisions), so only the threads besides the caller are counted.
    for ([_]u32{ 1, 2 }) |workers| {
        const pool = try create_pool(workers);
        defer pool.destroy();
        const rayon = Rayon.init(pool).with_parallelism(4);
        var threads: Threads = .{};
        const sums = try rayon.map_collect(gpa, Range.upto(16), NestedSum{
            .rayon = rayon,
            .threads = &threads,
        });
        defer gpa.free(sums);
        for (sums, 0..) |sum, x| try testing.expectEqual(x * 120, sum);
        try testing.expectEqual(@as(usize, workers), threads.others(std.Thread.getCurrentId()));
        try testing.expect(queue_empty(pool));
    }
}

const Increment = struct {
    pub fn map(_: Increment, x: *const u64) u64 {
        return x.* + 1;
    }
};

const Sum = struct {
    pub fn identity(_: Sum) u64 {
        return 0;
    }
    pub fn fold(_: Sum, acc: u64, x: *const u64) u64 {
        return acc + x.*;
    }
    pub fn reduce(_: Sum, a: u64, b: u64) u64 {
        return a + b;
    }
};

test "a zero-thread pool runs maps and folds on the caller and leaves nothing queued" {
    // commonware `taken_over_thread_leaves_no_jobs`: a pool whose only thread is the caller,
    // planned for four, maps and folds 64 items four times over.
    const pool = try create_pool(0);
    defer pool.destroy();
    const rayon = Rayon.init(pool).with_parallelism(4);
    var data: [64]u64 = undefined;
    for (&data, 0..) |*x, index| x.* = index;
    const items: []const u64 = &data;
    for (0..4) |_| {
        const out = try rayon.map_collect(gpa, items, Increment{});
        defer gpa.free(out);
        for (out, 1..) |x, expected| try testing.expectEqual(@as(u64, expected), x);
        try testing.expectEqual(@as(u64, 2016), rayon.fold(items, Sum{}));
    }
    try testing.expect(queue_empty(pool));
}

const Identity = struct {
    pub fn map(_: Identity, x: usize) usize {
        return x;
    }
};

const Constant = struct {
    value: u32,
    pub fn call(constant: Constant) u32 {
        return constant.value;
    }
};

test "a policy records only its own strategy's calls and is shared by copies" {
    // commonware `adaptive_policy_is_scoped_to_rayon`, `adaptive_policy_is_shared_by_clones`,
    // and `strategy_without_policy_records_nothing`.
    const pool = try create_pool(2);
    defer pool.destroy();
    var policy = Policy.init(testing.io);
    var other = Policy.init(testing.io);
    const strategy = Rayon.init(pool).with_policy(&policy);
    _ = Rayon.init(pool).with_policy(&other);
    gpa.free(try strategy.map_collect(gpa, Range.upto(16), Identity{}));
    try testing.expectEqual(@as(usize, 1), policy.len());
    try testing.expectEqual(@as(usize, 0), other.len());
    // A copy shares the policy: its call lands in the same policy.
    const copy = strategy;
    gpa.free(try copy.map_collect(gpa, Range.upto(16), Identity{}));
    try testing.expectEqual(@as(usize, 2), policy.len());
    // A strategy over the same pool without a policy records nothing anywhere.
    const fixed = Rayon.init(pool);
    var data: [4]u64 = .{ 0, 1, 2, 3 };
    try testing.expectEqual(@as(u64, 6), fixed.fold(@as([]const u64, &data), Sum{}));
    const both = fixed.join(Constant{ .value = 1 }, Constant{ .value = 2 });
    try testing.expectEqual(@as(u32, 2), both[1]);
    try testing.expectEqual(@as(usize, 2), policy.len());
    try testing.expectEqual(@as(usize, 0), other.len());
}

/// Creates a pool with workers, waits to be canceled, then destroys the pool. True when the
/// cancel is still pending after the teardown, so a later wait fails at once.
fn teardown_after_cancel(ready: *std.atomic.Value(bool)) bool {
    const io = testing.io;
    // Not `gpa`: on Darwin its free captures a stack trace through the MachO unwinder, which
    // takes a cancelable debug-info lock and so consumes this task's pending cancel. This
    // allocator still checks for leaks but captures no traces.
    var safe: std.heap.SafeAllocator = .init(std.heap.page_allocator, .{
        .stack_trace_frames = 0,
    });
    defer std.debug.assert(safe.deinit() == 0);
    const pool = ThreadPool.create(safe.allocator(), io, .{ .threads = 2 }) catch {
        return false;
    };
    ready.store(true, .release);
    // The cancel is acknowledged here, so it is re-armed, as AGENTS.md requires.
    if (io.sleep(.fromSeconds(60), .awake)) |_| {} else |_| io.recancel();
    pool.destroy();
    if (io.sleep(.fromSeconds(5), .awake)) |_| return false else |err| {
        return err == error.Canceled;
    }
}

test "destroying a pool in a canceled task leaves the cancel pending" {
    var ready: std.atomic.Value(bool) = .init(false);
    var future = try testing.io.concurrent(teardown_after_cancel, .{&ready});
    // Bounded: the task sets `ready` right after creating its pool.
    while (!ready.load(.acquire)) sleep_ns(100 * us);
    try testing.expect(future.cancel(testing.io));
}
