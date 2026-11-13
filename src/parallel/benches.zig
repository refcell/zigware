//! Benchmarks of the strategies: a fold, a map, and a sort, sequentially and on a pool, so the
//! cost of handing work to the pool is visible next to the work itself.

const std = @import("std");
const assert = std.debug.assert;
const bench = @import("bench");
const parallel = @import("parallel");

const Range = parallel.Range;

/// A fold of a non-affine mixing function over `0..len` (an affine one folds to a closed
/// form), heavy enough per item to parallelize.
fn FoldWorkload(comptime Strategy: type) type {
    return struct {
        strategy: Strategy,
        len: usize,

        const Mix = struct {
            pub fn identity(_: Mix) u64 {
                return 0;
            }
            pub fn fold(_: Mix, acc: u64, index: usize) u64 {
                var value: u64 = index;
                for (0..16) |_| {
                    value ^= value >> 29;
                    value *%= 0xbf58_476d_1ce4_e5b9;
                }
                return acc +% value;
            }
            pub fn reduce(_: Mix, a: u64, b: u64) u64 {
                return a +% b;
            }
        };

        pub fn iter(workload: *@This()) u64 {
            return workload.strategy.fold(Range.upto(workload.len), Mix{});
        }
    };
}

/// A stable sort of `len` pseudo-random keys, refilled before every iteration.
fn SortWorkload(comptime Strategy: type) type {
    return struct {
        strategy: Strategy,
        values: []u64,

        pub fn before_iter(workload: *@This()) void {
            for (workload.values, 0..) |*value, index| {
                value.* = (index *% 0x9e37_79b9_7f4a_7c15) >> 17;
            }
        }

        pub fn iter(workload: *@This()) u64 {
            workload.strategy.sort_by(u64, workload.values, {}, std.sort.asc(u64));
            assert(workload.values.len == 0 or
                workload.values[0] <= workload.values[workload.values.len - 1]);
            return workload.values.len;
        }
    };
}

fn run_strategy(runner: *bench.Runner, strategy: anytype, label: []const u8) !void {
    const len = runner.inputs.pick(usize, 1_000, 1_000_000, 10_000_000);
    const Strategy = @TypeOf(strategy);
    var fold: FoldWorkload(Strategy) = .{ .strategy = strategy, .len = len };
    const fold_name = bench.Benchmark.init("parallel::fold")
        .with_param("strategy", label)
        .with_param("len", len);
    try runner.run(fold_name, &fold);

    const values = try runner.allocator.alloc(u64, len);
    defer runner.allocator.free(values);
    var sort: SortWorkload(Strategy) = .{ .strategy = strategy, .values = values };
    const sort_name = bench.Benchmark.init("parallel::sort_by")
        .with_param("strategy", label)
        .with_param("len", len);
    try runner.run(sort_name, &sort);
}

pub fn run(runner: *bench.Runner) !void {
    try run_strategy(runner, parallel.sequential, "sequential");
    const threads: u32 = 3;
    const pool = try parallel.ThreadPool.create(runner.allocator, runner.io, .{
        .threads = threads,
    });
    defer pool.destroy();
    try run_strategy(runner, parallel.Rayon.init(pool), "rayon-4");
}
