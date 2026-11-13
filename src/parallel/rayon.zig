//! `Rayon`: runs operations on a shared `ThreadPool` (commonware's `Rayon` strategy, named the
//! same so ports read alike; the pool is zigware's own, see `pool.zig`).
//!
//! A fold or map over `len` items splits into `min(len, max_chunks)` balanced chunks, a number
//! that depends only on `len`, so a fold gives the same result on every pool size; with a
//! lawful operation (an identity and an associative reduce) it also equals the `Sequential`
//! result. Without parallelism (`parallelism() == 1`) every operation runs serially.
//!
//! This strategy has no adaptive policy yet: like commonware's `Rayon::without_policy`, it runs
//! the parallel shape whenever its parallelism exceeds one.

const std = @import("std");
const assert = std.debug.assert;
const ops = @import("ops.zig");
const shared = @import("strategy.zig");
const tiles = @import("tiles.zig");
const task_module = @import("task.zig");
const pool_module = @import("pool.zig");

const ThreadPool = pool_module.ThreadPool;

comptime {
    assert(pool_module.max_jobs == ops.max_chunks);
}

pub const Rayon = struct {
    pool: *ThreadPool,
    /// The parallelism assumed for planning batches and choosing serial or parallel shapes.
    parallelism_planned: usize,

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
        rayon.pool.run(count, context, body);
    }

    /// The pool's allocator, which parallel sorts borrow for their merge buffer.
    pub fn scratch(rayon: Rayon) ?std.mem.Allocator {
        return rayon.pool.allocator;
    }

    /// Hands `task`'s job to the pool, or runs it inline when the pool has no workers (like
    /// commonware's single-worker pool), whatever the planning parallelism. `len` sizes the job
    /// for adaptive strategies.
    pub fn spawn(rayon: Rayon, len: usize, task: anytype) void {
        _ = len;
        if (rayon.pool.threads == 0) {
            task.run_inline();
            assert(task.is_done());
            return;
        }
        task.offload(rayon.pool);
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
