//! `Task`: one CPU-bound job submitted with a strategy's `spawn` (commonware's
//! `Strategy::spawn`), awaited with `block_on`.
//!
//! Commonware's `spawn` returns a future; here the caller owns the task's memory instead, so
//! submitting never allocates:
//!
//! ```zig
//! var task: parallel.Task(Op) = .init(op);
//! strategy.spawn(len, &task);
//! const result = strategy.block_on(&task);
//! ```
//!
//! `op.call()` runs the job; an op that needs the strategy captures it. A task must be awaited
//! with `block_on` before it goes out of scope or its pool is destroyed. A strategy without a
//! pool (or with parallelism 1) runs the job inline before `spawn` returns. A caller waiting
//! for a job no worker has started runs it itself; one waiting for a job a worker holds runs
//! other queued jobs meanwhile.

const std = @import("std");
const assert = std.debug.assert;
const ops = @import("ops.zig");
const pool_module = @import("pool.zig");
const policy_module = @import("policy.zig");

const ThreadPool = pool_module.ThreadPool;

/// Where a measured offloaded job reports its timing: an adaptive strategy's policy, keyed by
/// the spawning call site.
pub const Recorder = struct {
    policy: *policy_module.Policy,
    site: usize,
    len: usize,
    threads: usize,
    plan: policy_module.SpawnPlan,
    /// When the job was handed off, on the pool's clock.
    start_ns: u64 = 0,
};

pub fn Task(comptime Op: type) type {
    return struct {
        const Self = @This();
        pub const Result = ops.Return(Op, "call");

        op: Op,
        result: Result = undefined,
        latch: pool_module.Latch = .{ .pending = .init(1) },
        job: pool_module.Job = undefined,
        pool: ?*ThreadPool = null,
        spawned: bool = false,
        /// Set for a measured offload; the job then times itself.
        recorder: ?Recorder = null,
        job_ns: u64 = 0,

        pub fn init(op: Op) Self {
            return .{ .op = op };
        }

        /// Whether the job has finished.
        pub fn is_done(self: *const Self) bool {
            return self.latch.pending.load(.acquire) == 0;
        }

        /// Whether `spawn` handed the job to a pool rather than running it inline.
        pub fn is_offloaded(self: *const Self) bool {
            assert(self.spawned);
            return self.pool != null;
        }

        fn body(context: *const anyopaque, index: usize) void {
            assert(index == 0);
            const self: *Self = @ptrCast(@alignCast(@constCast(context)));
            if (self.recorder == null) {
                self.result = self.op.call();
                return;
            }
            const io = self.pool.?.io;
            const start = now_ns(io);
            self.result = self.op.call();
            self.job_ns = now_ns(io) -| start;
        }

        /// Runs the job on the calling thread before returning.
        pub fn run_inline(self: *Self) void {
            assert(!self.spawned);
            assert(self.latch.pending.load(.monotonic) == 1);
            self.spawned = true;
            self.result = self.op.call();
            self.latch.pending.store(0, .release);
        }

        /// Hands the job to `pool`.
        pub fn offload(self: *Self, pool: *ThreadPool) void {
            assert(!self.spawned);
            assert(self.latch.pending.load(.monotonic) == 1);
            self.spawned = true;
            self.pool = pool;
            self.job = .{
                .context = self,
                .call = body,
                .index = 0,
                .latch = &self.latch,
                .queued = true,
            };
            pool.submit(&self.job);
        }

        /// Hands the job to `pool` and reports its timing to `recorder` when it is awaited:
        /// the job's own wall time, and the round trip from hand-off to result.
        pub fn offload_measured(self: *Self, pool: *ThreadPool, recorder: Recorder) void {
            assert(recorder.plan.execution == .offload and recorder.plan.measure);
            var measured = recorder;
            measured.start_ns = now_ns(pool.io);
            self.recorder = measured;
            self.offload(pool);
        }

        /// Waits for the job and returns its result. A measured job reports here, since every
        /// task is awaited (commonware's worker reports the job even if its future is dropped).
        pub fn wait(self: *Self) Result {
            assert(self.spawned);
            if (self.pool) |pool| pool.finish(&self.job);
            assert(self.is_done());
            if (self.recorder) |recorder| {
                const round_trip_ns = now_ns(self.pool.?.io) -| recorder.start_ns;
                const policy = recorder.policy;
                const job_ns = self.job_ns;
                policy.record_spawn_job(
                    recorder.site,
                    recorder.len,
                    recorder.threads,
                    recorder.plan,
                    job_ns,
                );
                policy.record_spawn_round_trip(
                    recorder.site,
                    recorder.len,
                    recorder.threads,
                    recorder.plan,
                    round_trip_ns,
                    job_ns,
                );
            }
            return self.result;
        }
    };
}

/// Waits for `task` (a `*Task(Op)`) and returns its result.
pub fn block_on(strategy: anytype, task: anytype) @TypeOf(task.*).Result {
    _ = strategy;
    comptime assert(@typeInfo(@TypeOf(task)) == .pointer);
    return task.wait();
}

/// Nanoseconds on `io`'s monotonic clock.
fn now_ns(io: std.Io) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    assert(now >= 0);
    return @intCast(now);
}
