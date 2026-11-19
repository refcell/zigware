//! parallel: Parallelize fold operations with pluggable execution strategies.
//!
//! Zig port of commonware's `commonware-parallel` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/parallel). The lane file
//! docs/lanes/parallel.md tracks what is ported.
//!
//! A strategy is a small value passed by copy; algorithms take `strategy: anytype` and work
//! the same on every strategy:
//!
//! - `Sequential` (`parallel.sequential`): everything on the calling thread, in order.
//! - `Rayon`: a `ThreadPool` of workers started through `std.Io`, so the deterministic runtime
//!   can host it. Fold and map results do not depend on the number of threads.
//!
//! Rust closures become operation values: a struct (or a pointer to one) whose methods are the
//! closures. Inputs are slices (items are element pointers, like `&data`) or `Range` (items are
//! `usize` indices, like `0..n`). The interface, mirroring commonware's `Strategy` trait:
//!
//! | operation | op methods |
//! | --- | --- |
//! | `s.run(len, op) R` / `s.try_run` | `serial() R`, `parallel() R` |
//! | `s.fold(items, op) R` | `identity() R`, `fold(R, item) R`, `reduce(R, R) R` |
//! | `s.fold_init(items, op) R` | `init() T`, `identity()`, `fold(R, *T, item) R`, `reduce` |
//! | `s.try_fold(items, op) E!R` | `identity() R`, `fold(R, item) E!R`, `reduce(R, R) R` |
//! | `s.map_into(items, out, op)` | `map(item) U` (no allocation) |
//! | `s.map_collect(gpa, items, op) ![]U` | `map(item) U` |
//! | `s.map_init_collect(gpa, items, op)` | `init() T`, `map(*T, item) U` |
//! | `s.try_map_collect(gpa, items, op)` | `map(item) E!U` |
//! | `s.map_partition_collect(gpa, items, op)` | `map(item) struct { K, ?U }` |
//! | `s.join(a, b) struct { RA, RB }` | `a.call() RA`, `b.call() RB` |
//! | `s.sort_by(T, items, ctx, lessThan)` | stable; `sort_unstable_by` is not |
//! | `s.run_batches(len, min_len, multiplier, op)` | `run(batches) R`, see `Batches` |
//! | `s.run_tiles(len, grids, multiplier, op)` | `run(tiles) R`, see `Tiles` |
//! | `s.spawn(len, &task)`, `s.block_on(&task) R` | `call() R`, see `Task` |
//! | `s.parallelism() usize` | |
//!
//! Optional op methods: `discard(value)` releases accumulators or outputs a failed fallible
//! operation drops, and `deinit_state(*T)` releases a `fold_init` or `map_init` chunk's state.

const std = @import("std");
const assert = std.debug.assert;

pub const ops = @import("ops.zig");
pub const Range = ops.Range;
pub const Partitioned = ops.Partitioned;
pub const max_chunks = ops.max_chunks;

const strategy_module = @import("strategy.zig");
pub const Batches = strategy_module.Batches;

const tiles_module = @import("tiles.zig");
pub const Grid = tiles_module.Grid;
pub const Tiles = tiles_module.Tiles;
pub const max_units = tiles_module.max_units;

pub const Task = @import("task.zig").Task;
pub const mocks = @import("mocks.zig");
pub const policy = @import("policy.zig");
pub const Policy = policy.Policy;
pub const topology = @import("topology.zig");
pub const Topology = topology.Topology;

pub const Sequential = @import("sequential.zig").Sequential;
pub const Rayon = @import("rayon.zig").Rayon;

const pool_module = @import("pool.zig");
pub const ThreadPool = pool_module.ThreadPool;
pub const ThreadPoolConfig = pool_module.Config;

/// The sequential strategy value.
pub const sequential: Sequential = .{};

/// Asserts at compile time that `S` implements the strategy interface.
pub fn assert_strategy(comptime S: type) void {
    comptime {
        for ([_][]const u8{
            "parallelism",      "split",                 "execute",     "scratch",
            "run",              "try_run",               "run_batches", "try_run_batches",
            "fold",             "fold_init",             "try_fold",    "map_into",
            "map_init_into",    "try_map_into",          "map_collect", "map_init_collect",
            "try_map_collect",  "map_partition_collect", "join",        "sort_by",
            "sort_unstable_by",
        }) |decl| {
            if (!@hasDecl(S, decl)) @compileError(@typeName(S) ++ " lacks Strategy." ++ decl);
        }
    }
}

comptime {
    assert_strategy(Sequential);
    assert_strategy(Rayon);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
    _ = @import("tiles_tests.zig");
    _ = @import("mocks_tests.zig");
    _ = @import("rayon_tests.zig");
    _ = @import("adaptive_tests.zig");
    _ = @import("pool_api_tests.zig");
}
