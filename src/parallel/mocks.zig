//! Mock strategies for tests (commonware's `parallel::mocks`).
//!
//! An adaptive strategy may run any call serially or in parallel, and cut batches and tiles
//! for fewer workers than it plans for, so code generic over a strategy must produce the same
//! result whatever it chooses. An `Explorer` chooses each call's shape by a fixed rule on a
//! `Rayon`'s pool, and `explore` runs an operation under serial, most parallel, and seeded
//! mixtures of shapes and checks that every run returns the serial run's output.
//!
//! Commonware keys a seeded choice by the call's source location; Zig has no caller location,
//! so a call site here is the call's return address relative to this file's code, which is
//! fixed for one build of the test binary. A seed therefore repeats its choices within a build,
//! not across optimize modes: an unrolled or inlined caller has one site per machine call.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const ops = @import("ops.zig");
const shared = @import("strategy.zig");
const tiles_module = @import("tiles.zig");
const task_module = @import("task.zig");
const pool_module = @import("pool.zig");
const Rayon = @import("rayon.zig").Rayon;
const Sequential = @import("sequential.zig").Sequential;

const ThreadPool = pool_module.ThreadPool;
const Allocator = std.mem.Allocator;
const max_chunks = ops.max_chunks;
const sequential: Sequential = .{};

/// The number of seeded rules `explore` runs after the serial and parallel ones.
pub const seeds: u64 = 4;

/// Worker threads of the pool `explore` builds.
pub const workers: u32 = 4;

/// Tasks the strategy `explore` builds plans for. Planning more tasks than there are workers
/// makes the most parallel shapes cut more batches and tiles than the pool has threads.
pub const tasks: usize = 8;

/// A strategy on a new pool of `worker_count` threads that plans for `parallelism` tasks.
/// Destroy its pool with `strategy.pool.destroy()`.
pub fn pooled(
    allocator: Allocator,
    io: std.Io,
    worker_count: u32,
    parallelism: usize,
) ThreadPool.Error!Rayon {
    assert(parallelism >= 1);
    const pool = try ThreadPool.create(allocator, io, .{ .threads = worker_count });
    return Rayon.init(pool).with_parallelism(parallelism);
}

/// A strategy without worker threads that plans for `parallelism` tasks, so its spawned jobs
/// run inline at submission.
pub fn inlined(allocator: Allocator, io: std.Io, parallelism: usize) ThreadPool.Error!Rayon {
    return pooled(allocator, io, 0, parallelism);
}

/// A strategy whose `worker_count` workers never start, so a spawned job stays queued until
/// its caller's `block_on` takes it back and runs it (commonware's queue it forever).
pub fn pending(allocator: Allocator, io: std.Io, worker_count: u32) ThreadPool.Error!Rayon {
    assert(worker_count >= 1); // Without workers, `spawn` runs jobs inline.
    const pool = try ThreadPool.create(allocator, io, .{
        .threads = worker_count,
        .start_workers = false,
    });
    return Rayon.init(pool);
}

/// How an `Explorer` chooses the shape of each call.
pub const Rule = union(enum) {
    /// Every call takes its serial shape.
    serial,
    /// Every call takes its most parallel shape.
    parallel,
    /// Each call takes a shape picked by hashing the seed, the call site, and its length.
    seeded: u64,
};

/// The address call sites are measured from.
fn anchor() callconv(.c) void {}

/// Runs `body` on the pool whatever the planning parallelism, as commonware's `Rayon::join`.
const OnPool = struct {
    pool: *ThreadPool,

    pub fn execute(
        on_pool: OnPool,
        count: usize,
        context: anytype,
        comptime body: fn (@TypeOf(context), usize) void,
    ) void {
        on_pool.pool.run(count, context, body);
    }
};

/// A strategy that chooses the execution shape of each call by a fixed rule:
///
/// - `run` takes its serial or parallel body;
/// - a collection operation runs serially or on the pool;
/// - `join` runs its closures on the calling thread or on the pool;
/// - `run_batches` supplies the whole input or balanced batches, at most one per planned task;
/// - `run_tiles` cuts serial tiles or shares them among at most one worker per planned task;
/// - a spawned job runs inline or is handed to the pool.
pub const Explorer = struct {
    /// The explored strategy; its pool runs the parallel shapes, and its planning parallelism
    /// bounds the batch and worker counts.
    strategy: Rayon,
    rule: Rule,

    /// Takes the most parallel shape of `strategy` at every call.
    pub fn parallel(strategy: Rayon) Explorer {
        return .{ .strategy = strategy, .rule = .parallel };
    }

    /// Picks each call's shape by hashing `seed`, the call site, and the call's length.
    pub fn seeded(strategy: Rayon, seed: u64) Explorer {
        return .{ .strategy = strategy, .rule = .{ .seeded = seed } };
    }

    /// Picks one of `options` shapes, ordered from serial to most parallel, for a call from
    /// `address` over `len` items.
    fn pick(explorer: Explorer, address: usize, len: usize, options: usize) usize {
        assert(options >= 1);
        const picked: usize = switch (explorer.rule) {
            .serial => 0,
            .parallel => options - 1,
            .seeded => |seed| picked: {
                const site: u64 = address -% @intFromPtr(&anchor);
                const mixed = utils.rng.mix64(site ^ utils.rng.mix64(len));
                const hash = utils.rng.mix64(seed ^ mixed);
                break :picked @intCast(hash % options);
            },
        };
        assert(picked < options);
        return picked;
    }

    /// Whether a call takes its parallel shape. A strategy planning one task never does.
    fn parallel_at(explorer: Explorer, address: usize, len: usize) bool {
        return explorer.strategy.parallelism() > 1 and explorer.pick(address, len, 2) == 1;
    }

    pub fn parallelism(explorer: Explorer) usize {
        return explorer.strategy.parallelism();
    }

    pub fn split(explorer: Explorer, len: usize) usize {
        return explorer.strategy.split(len);
    }

    /// Runs the calls on the pool or one after another on the calling thread, as when the
    /// pool's workers start late.
    pub noinline fn execute(
        explorer: Explorer,
        count: usize,
        context: anytype,
        comptime body: fn (@TypeOf(context), usize) void,
    ) void {
        assert(count >= 1);
        assert(count <= max_chunks);
        if (explorer.pick(@returnAddress(), count, 2) == 1) {
            explorer.strategy.pool.run(count, context, body);
            return;
        }
        for (0..count) |index| body(context, index);
    }

    pub fn scratch(explorer: Explorer) ?Allocator {
        return explorer.strategy.scratch();
    }

    /// Runs `task`'s job inline or hands it to the pool. A pool without workers takes the job
    /// back on the caller's `block_on`.
    pub noinline fn spawn(explorer: Explorer, len: usize, task: anytype) void {
        if (explorer.pick(@returnAddress(), len, 2) == 1) {
            task.offload(explorer.strategy.pool);
        } else {
            task.run_inline();
        }
        assert(task.spawned);
    }

    pub const block_on = task_module.block_on;

    pub noinline fn run(explorer: Explorer, len: usize, op: anytype) @TypeOf(op.serial()) {
        if (explorer.parallel_at(@returnAddress(), len)) return op.parallel();
        return op.serial();
    }

    pub const try_run = run;

    pub noinline fn run_batches(
        explorer: Explorer,
        len: usize,
        minimum_batch_len: usize,
        multiplier: usize,
        op: anytype,
    ) ops.Return(@TypeOf(op), "run") {
        assert(minimum_batch_len > 0);
        _ = multiplier;
        const planned = @min(explorer.strategy.parallelism(), len / minimum_batch_len, max_chunks);
        const most = @max(planned, 1);
        const count = explorer.pick(@returnAddress(), len, most) + 1;
        assert(count == 1 or len / count >= minimum_batch_len);
        const batches: shared.Batches(Explorer) = .{
            .strategy = explorer,
            .len = len,
            .batches = count,
        };
        return op.run(batches);
    }

    pub const try_run_batches = run_batches;

    pub noinline fn run_tiles(
        explorer: Explorer,
        len: usize,
        grids: []const tiles_module.Grid,
        multiplier: usize,
        op: anytype,
    ) ops.Return(@TypeOf(op), "run") {
        assert(grids.len > 0);
        _ = multiplier;
        const T = tiles_module.Tiles(Explorer);
        const most = @max(@min(explorer.strategy.parallelism(), max_chunks), 1);
        const count = explorer.pick(@returnAddress(), len, most) + 1;
        if (count == 1) return op.run(T.serial(explorer, grids, len));
        return op.run(T.parallel(explorer, grids, len, count));
    }

    pub noinline fn fold(explorer: Explorer, items: anytype, op: anytype) @TypeOf(
        sequential.fold(items, op),
    ) {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.fold(items, op);
        }
        return sequential.fold(items, op);
    }

    pub noinline fn fold_init(explorer: Explorer, items: anytype, op: anytype) @TypeOf(
        sequential.fold_init(items, op),
    ) {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.fold_init(items, op);
        }
        return sequential.fold_init(items, op);
    }

    pub noinline fn try_fold(explorer: Explorer, items: anytype, op: anytype) @TypeOf(
        sequential.try_fold(items, op),
    ) {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.try_fold(items, op);
        }
        return sequential.try_fold(items, op);
    }

    pub noinline fn map_into(explorer: Explorer, items: anytype, out: anytype, op: anytype) void {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.map_into(items, out, op);
        }
        return sequential.map_into(items, out, op);
    }

    pub noinline fn map_init_into(
        explorer: Explorer,
        items: anytype,
        out: anytype,
        op: anytype,
    ) void {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.map_init_into(items, out, op);
        }
        return sequential.map_init_into(items, out, op);
    }

    pub noinline fn try_map_into(
        explorer: Explorer,
        items: anytype,
        out: anytype,
        op: anytype,
    ) @TypeOf(sequential.try_map_into(items, out, op)) {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.try_map_into(items, out, op);
        }
        return sequential.try_map_into(items, out, op);
    }

    pub noinline fn map_collect(
        explorer: Explorer,
        allocator: Allocator,
        items: anytype,
        op: anytype,
    ) @TypeOf(sequential.map_collect(allocator, items, op)) {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.map_collect(allocator, items, op);
        }
        return sequential.map_collect(allocator, items, op);
    }

    pub noinline fn map_init_collect(
        explorer: Explorer,
        allocator: Allocator,
        items: anytype,
        op: anytype,
    ) @TypeOf(sequential.map_init_collect(allocator, items, op)) {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.map_init_collect(allocator, items, op);
        }
        return sequential.map_init_collect(allocator, items, op);
    }

    pub noinline fn map_collect_with_multiplier(
        explorer: Explorer,
        allocator: Allocator,
        items: anytype,
        multiplier: usize,
        op: anytype,
    ) @TypeOf(sequential.map_collect(allocator, items, op)) {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.map_collect_with_multiplier(allocator, items, multiplier, op);
        }
        return sequential.map_collect_with_multiplier(allocator, items, multiplier, op);
    }

    pub noinline fn map_init_collect_with_multiplier(
        explorer: Explorer,
        allocator: Allocator,
        items: anytype,
        multiplier: usize,
        op: anytype,
    ) @TypeOf(sequential.map_init_collect(allocator, items, op)) {
        const strategy = explorer.strategy;
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return strategy.map_init_collect_with_multiplier(allocator, items, multiplier, op);
        }
        return sequential.map_init_collect_with_multiplier(allocator, items, multiplier, op);
    }

    pub noinline fn try_map_collect(
        explorer: Explorer,
        allocator: Allocator,
        items: anytype,
        op: anytype,
    ) @TypeOf(sequential.try_map_collect(allocator, items, op)) {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.try_map_collect(allocator, items, op);
        }
        return sequential.try_map_collect(allocator, items, op);
    }

    pub noinline fn map_partition_collect(
        explorer: Explorer,
        allocator: Allocator,
        items: anytype,
        op: anytype,
    ) @TypeOf(sequential.map_partition_collect(allocator, items, op)) {
        if (explorer.parallel_at(@returnAddress(), ops.count(items))) {
            return explorer.strategy.map_partition_collect(allocator, items, op);
        }
        return sequential.map_partition_collect(allocator, items, op);
    }

    /// Joins on the pool whatever the planning parallelism, or on the calling thread.
    pub noinline fn join(explorer: Explorer, a: anytype, b: anytype) @TypeOf(
        sequential.join(a, b),
    ) {
        if (explorer.pick(@returnAddress(), 2, 2) == 1) {
            return shared.join(OnPool{ .pool = explorer.strategy.pool }, a, b);
        }
        return sequential.join(a, b);
    }

    pub noinline fn sort_by(
        explorer: Explorer,
        comptime T: type,
        items: []T,
        context: anytype,
        comptime lessThan: fn (@TypeOf(context), T, T) bool,
    ) void {
        if (explorer.parallel_at(@returnAddress(), items.len)) {
            return explorer.strategy.sort_by(T, items, context, lessThan);
        }
        return sequential.sort_by(T, items, context, lessThan);
    }

    pub noinline fn sort_unstable_by(
        explorer: Explorer,
        comptime T: type,
        items: []T,
        context: anytype,
        comptime lessThan: fn (@TypeOf(context), T, T) bool,
    ) void {
        if (explorer.parallel_at(@returnAddress(), items.len)) {
            return explorer.strategy.sort_unstable_by(T, items, context, lessThan);
        }
        return sequential.sort_unstable_by(T, items, context, lessThan);
    }
};

/// The output of an `explore` operation: `op.run`'s result, without its error set.
pub fn Output(comptime Op: type) type {
    const R = ops.Return(Op, "run");
    return switch (@typeInfo(R)) {
        .error_union => |union_info| union_info.payload,
        else => R,
    };
}

fn call(op: anytype, explorer: Explorer) anyerror!Output(@TypeOf(op)) {
    return op.run(explorer);
}

fn release(op: anytype, output: anytype) void {
    if (comptime @hasDecl(ops.Base(@TypeOf(op)), "discard")) op.discard(output);
}

fn same(op: anytype, expected: anytype, actual: @TypeOf(expected)) bool {
    if (comptime @hasDecl(ops.Base(@TypeOf(op)), "eql")) return op.eql(expected, actual);
    std.testing.expectEqualDeep(expected, actual) catch return false;
    return true;
}

/// The rules `explore` runs, in order.
pub const rules = [_]Rule{
    .serial, .parallel, .{ .seeded = 0 }, .{ .seeded = 1 }, .{ .seeded = 2 }, .{ .seeded = 3 },
};

comptime {
    assert(rules.len == 2 + seeds);
}

/// Runs `op.run(explorer)` under every rule in `rules`, on one strategy of `workers` workers
/// planning `tasks` tasks, and returns the serial run's output. Every other run must return
/// the same output (compared with `op.eql` if declared, else deeply), or `explore` returns
/// `error.ShapeDependentOutput`. Outputs other than the returned one go to `op.discard` if
/// declared. To reproduce a seeded run, use `Explorer.seeded` with its seed.
pub fn explore(allocator: Allocator, io: std.Io, op: anytype) anyerror!Output(@TypeOf(op)) {
    const strategy = try pooled(allocator, io, workers, tasks);
    defer strategy.pool.destroy();
    const serial = try call(op, .{ .strategy = strategy, .rule = rules[0] });
    errdefer release(op, serial);
    for (rules[1..]) |rule| {
        const output = try call(op, .{ .strategy = strategy, .rule = rule });
        defer release(op, output);
        if (!same(op, serial, output)) return error.ShapeDependentOutput;
    }
    return serial;
}
