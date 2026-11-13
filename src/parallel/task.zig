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

const ThreadPool = pool_module.ThreadPool;

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

        pub fn init(op: Op) Self {
            return .{ .op = op };
        }

        /// Whether the job has finished.
        pub fn is_done(self: *const Self) bool {
            return self.latch.pending.load(.acquire) == 0;
        }

        fn body(context: *const anyopaque, index: usize) void {
            assert(index == 0);
            const self: *Self = @ptrCast(@alignCast(@constCast(context)));
            self.result = self.op.call();
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

        /// Waits for the job and returns its result.
        pub fn wait(self: *Self) Result {
            assert(self.spawned);
            if (self.pool) |pool| pool.finish(&self.job);
            assert(self.is_done());
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
