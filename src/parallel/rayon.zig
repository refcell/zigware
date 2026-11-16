//! `Rayon`: runs operations on a shared `ThreadPool` (commonware's `Rayon` strategy, named the
//! same so ports read alike; the pool is zigware's own, see `pool.zig`).
//!
//! A fold or map over `len` items splits into `min(len, max_chunks)` balanced chunks, a number
//! that depends only on `len`, so a fold gives the same result on every pool size; with a
//! lawful operation (an identity and an associative reduce) it also equals the `Sequential`
//! result. Without parallelism (`parallelism() == 1`) every operation runs serially.
//!
//! By default the strategy runs the parallel shape whenever its parallelism exceeds one, like
//! commonware's `Rayon::without_policy`, so results never depend on timing. `with_policy`
//! makes it adaptive like commonware's default `Rayon`: each operation asks a shared `Policy`
//! whether this call site runs serial or parallel, and timed calls report their wall time and
//! busy time (the summed time of the pool jobs a parallel run placed, or the wall time of a
//! serial run or of `run`'s bodies, which run on the caller).

const std = @import("std");
const assert = std.debug.assert;
const ops = @import("ops.zig");
const shared = @import("strategy.zig");
const tiles = @import("tiles.zig");
const task_module = @import("task.zig");
const pool_module = @import("pool.zig");
const policy_module = @import("policy.zig");

const ThreadPool = pool_module.ThreadPool;
const Policy = policy_module.Policy;

comptime {
    assert(pool_module.max_jobs == ops.max_chunks);
}

pub const Rayon = struct {
    pool: *ThreadPool,
    /// The parallelism assumed for planning batches and choosing serial or parallel shapes.
    parallelism_planned: usize,
    /// The adaptive policy, or null to always run the parallel shape.
    policy: ?*Policy = null,
    /// Where `execute` adds each job's busy time during a measured parallel run.
    meter: ?*std.atomic.Value(u64) = null,

    /// A strategy over `pool`, planning with the pool's workers plus the calling thread, which
    /// also runs jobs while it waits.
    pub fn init(pool: *ThreadPool) Rayon {
        const parallelism_planned = @as(usize, pool.threads) + 1;
        assert(parallelism_planned >= 1);
        return .{ .pool = pool, .parallelism_planned = parallelism_planned };
    }

    /// Overrides the parallelism assumed for planning without resizing the pool, as a runtime
    /// that runs strategy work inline on one thread does.
    pub fn with_parallelism(rayon: Rayon, parallelism_planned: usize) Rayon {
        assert(parallelism_planned >= 1);
        var copy = rayon;
        copy.parallelism_planned = parallelism_planned;
        assert(copy.pool == rayon.pool);
        return copy;
    }

    /// The strategy with an adaptive `policy`, which may be shared with other strategies.
    pub fn with_policy(rayon: Rayon, policy: *Policy) Rayon {
        var copy = rayon;
        copy.policy = policy;
        assert(copy.pool == rayon.pool);
        return copy;
    }

    /// One call's plan and timing (see `strategy.adapt`).
    pub const Adaptation = struct {
        /// The strategy the call runs on, without a policy so nothing in it adapts again.
        chosen: Rayon,
        policy: ?*Policy,
        site: usize,
        len: usize,
        work: usize,
        body: shared.Body,
        /// The parallelism the plan was made with, before a serial choice lowered it to 1.
        parallelism_planned: usize,
        plan: policy_module.RunPlan,
        start_ns: u64,
        busy_ns: std.atomic.Value(u64) = .init(0),

        fn metered(adaptation: *const Adaptation) bool {
            return adaptation.plan.measure and adaptation.plan.execution == .parallel and
                adaptation.body == .placed;
        }

        /// The strategy to run the call on. `adaptation` must not move until `finish`.
        pub fn get(adaptation: *Adaptation) Rayon {
            var chosen = adaptation.chosen;
            if (adaptation.metered()) chosen.meter = &adaptation.busy_ns;
            assert(chosen.policy == null);
            return chosen;
        }

        /// Records a measured call that succeeded, and returns its `result`.
        pub fn finish(adaptation: *Adaptation, result: anytype) @TypeOf(result) {
            const policy = adaptation.policy orelse return result;
            if (!adaptation.plan.measure) return result;
            if (@typeInfo(@TypeOf(result)) == .error_union) {
                // An error can skip work and bias the estimates down.
                _ = result catch return result;
            }
            const wall_ns = now_ns(adaptation.chosen.pool.io) -| adaptation.start_ns;
            const metered_ns = adaptation.busy_ns.load(.acquire);
            const busy_ns = if (adaptation.metered()) metered_ns else wall_ns;
            policy.record_run(
                adaptation.site,
                adaptation.len,
                adaptation.work,
                adaptation.parallelism_planned,
                adaptation.plan,
                .{ .wall_ns = wall_ns, .busy_ns = busy_ns },
            );
            return result;
        }
    };

    /// Plans one call from `site` (see `strategy.adapt`). Without a policy the call runs as is.
    pub fn adapt(
        rayon: Rayon,
        site: usize,
        len: usize,
        work: usize,
        body: shared.Body,
    ) Adaptation {
        var chosen = rayon;
        chosen.policy = null;
        chosen.meter = null;
        var plan: policy_module.RunPlan = .{
            .execution = if (rayon.parallelism_planned > 1) .parallel else .serial,
            .placement = .wide,
            .measure = false,
        };
        if (rayon.policy) |policy| {
            const pools: policy_module.Pools = .{ .fixed = .wide };
            plan = policy.choose_run(site, len, work, rayon.parallelism_planned, pools);
        }
        if (plan.execution == .serial) chosen.parallelism_planned = 1;
        assert(chosen.parallelism_planned >= 1);
        return .{
            .chosen = chosen,
            .policy = rayon.policy,
            .site = site,
            .len = len,
            .work = work,
            .body = body,
            .parallelism_planned = rayon.parallelism_planned,
            .plan = plan,
            .start_ns = if (plan.measure) now_ns(rayon.pool.io) else 0,
        };
    }

    pub fn parallelism(rayon: Rayon) usize {
        assert(rayon.parallelism_planned >= 1);
        return rayon.parallelism_planned;
    }

    /// A fold or map over `len` items runs as `min(len, max_chunks)` chunks when parallel.
    pub fn split(rayon: Rayon, len: usize) usize {
        if (rayon.parallelism_planned <= 1 or len < 2) return 1;
        const chunks = ops.chunk_count(len);
        assert(chunks >= 2);
        return chunks;
    }

    /// Calls `body(context, index)` for `index` in `0..count` on the pool.
    pub fn execute(
        rayon: Rayon,
        count: usize,
        context: anytype,
        comptime body: fn (@TypeOf(context), usize) void,
    ) void {
        assert(count >= 1);
        assert(count <= ops.max_chunks);
        if (rayon.parallelism_planned <= 1) {
            for (0..count) |index| body(context, index);
            return;
        }
        const meter = rayon.meter orelse return rayon.pool.run(count, context, body);
        const Metered = struct {
            inner: @TypeOf(context),
            meter: *std.atomic.Value(u64),
            io: std.Io,

            fn call(metered: *const @This(), index: usize) void {
                const start = now_ns(metered.io);
                body(metered.inner, index);
                _ = metered.meter.fetchAdd(now_ns(metered.io) -| start, .release);
            }
        };
        const metered: Metered = .{ .inner = context, .meter = meter, .io = rayon.pool.io };
        rayon.pool.run(count, &metered, Metered.call);
    }

    /// The pool's allocator, which parallel sorts borrow for their merge buffer.
    pub fn scratch(rayon: Rayon) ?std.mem.Allocator {
        return rayon.pool.allocator;
    }

    /// Hands `task`'s job to the pool, or runs it inline when the pool has no workers (like
    /// commonware's single-worker pool), whatever the planning parallelism. With a policy, the
    /// call site learns whether a job of about `len` items runs faster inline than the
    /// hand-off costs. Every caller counts as outside the pool (`Spawner.outside`): pool
    /// workers are `std.Io` tasks, which carry no identity a thread-local could hold.
    pub fn spawn(rayon: Rayon, len: usize, task: anytype) void {
        const threads: usize = rayon.pool.threads;
        if (threads == 0) {
            task.run_inline();
            assert(task.is_done());
            return;
        }
        const policy = rayon.policy orelse return task.offload(rayon.pool);
        const site = @returnAddress();
        const plan = policy.choose_spawn(site, len, threads, .outside);
        switch (plan.execution) {
            .inlined => {
                const start = if (plan.measure) now_ns(rayon.pool.io) else 0;
                task.run_inline();
                assert(task.is_done());
                if (!plan.measure) return;
                const job_ns = now_ns(rayon.pool.io) -| start;
                policy.record_spawn_inline(site, len, threads, job_ns);
            },
            .offload => {
                if (!plan.measure) return task.offload(rayon.pool);
                task.offload_measured(rayon.pool, .{
                    .policy = policy,
                    .site = site,
                    .len = len,
                    .threads = threads,
                    .plan = plan,
                });
            },
        }
    }

    pub const block_on = task_module.block_on;
    pub const run = shared.run;
    pub const try_run = shared.try_run;
    pub const run_batches = shared.run_batches;
    pub const try_run_batches = shared.try_run_batches;
    pub const run_tiles = tiles.run_tiles;
    pub const fold = shared.fold;
    pub const fold_init = shared.fold_init;
    pub const try_fold = shared.try_fold;
    pub const map_into = shared.map_into;
    pub const map_init_into = shared.map_init_into;
    pub const try_map_into = shared.try_map_into;
    pub const map_collect = shared.map_collect;
    pub const map_init_collect = shared.map_init_collect;
    pub const map_collect_with_multiplier = shared.map_collect_with_multiplier;
    pub const map_init_collect_with_multiplier = shared.map_init_collect_with_multiplier;
    pub const try_map_collect = shared.try_map_collect;
    pub const map_partition_collect = shared.map_partition_collect;
    pub const join = shared.join;
    pub const sort_by = shared.sort_by;
    pub const sort_unstable_by = shared.sort_unstable_by;
};

/// Nanoseconds on `io`'s monotonic clock.
fn now_ns(io: std.Io) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    assert(now >= 0);
    return @intCast(now);
}
