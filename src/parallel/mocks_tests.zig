//! Tests of `mocks`, ported from commonware's `parallel/src/mocks.rs`. Commonware's probe also
//! records whether maps and joins ran on a pool thread; here the calling thread helps run pool
//! jobs, so the probe records the shapes that are observable: batch count, tile workers, the
//! `run` body, and whether a spawned job was handed off.

const std = @import("std");
const testing = std.testing;
const parallel = @import("root.zig");
const mocks = parallel.mocks;

const Range = parallel.Range;
const Grid = parallel.Grid;
const Explorer = mocks.Explorer;
const gpa = testing.allocator;

const Shapes = struct {
    /// Batches its run was cut into.
    batches: usize,
    /// Workers its tiles were planned for, one for serial tiles.
    tile_workers: usize,
    /// The body its `run` took.
    body: u8,
    /// Whether its spawned job was handed to the pool.
    offloaded: bool,
};

const serial_shapes: Shapes = .{ .batches = 1, .tile_workers = 1, .body = 's', .offloaded = false };

fn parallel_shapes(parallelism: usize) Shapes {
    return .{
        .batches = parallelism,
        .tile_workers = parallelism,
        .body = 'p',
        .offloaded = true,
    };
}

const RangeOf = struct {
    pub fn map(_: RangeOf, _: usize, range: Range) Range {
        return range;
    }
};

const CountBatches = struct {
    pub fn run(_: CountBatches, batches: anytype) usize {
        var out: [parallel.max_chunks]Range = undefined;
        batches.map_collect(out[0..batches.count()], RangeOf{});
        return batches.count();
    }
};

const TileWorkers = struct {
    pub fn run(_: TileWorkers, tiles: anytype) usize {
        return switch (tiles.plan) {
            .serial => 1,
            .shared => |shared| shared.workers,
        };
    }
};

const Body = struct {
    pub fn serial(_: Body) u8 {
        return 's';
    }
    pub fn parallel(_: Body) u8 {
        return 'p';
    }
};

const Unit = struct {
    pub fn call(_: Unit) void {}
};

const Seven = struct {
    pub fn call(_: Seven) u32 {
        return 7;
    }
};

/// Makes one call of each kind through `strategy` and returns the shapes they took.
fn probe(strategy: anytype) Shapes {
    const batches = strategy.run_batches(64, 1, 1, CountBatches{});
    const grids = [_]Grid{.{ .rows = 4, .tile_cost = 1 }};
    const tile_workers = strategy.run_tiles(64, &grids, 1, TileWorkers{});
    const body = strategy.run(64, Body{});
    var task: parallel.Task(Unit) = .init(.{});
    strategy.spawn(1, &task);
    const offloaded = task.is_offloaded();
    strategy.block_on(&task);
    return .{
        .batches = batches,
        .tile_workers = tile_workers,
        .body = body,
        .offloaded = offloaded,
    };
}

const Sum = struct {
    pub fn identity(_: Sum) u64 {
        return 0;
    }
    pub fn fold(_: Sum, acc: u64, index: usize) u64 {
        return acc + index;
    }
    pub fn reduce(_: Sum, a: u64, b: u64) u64 {
        return a + b;
    }
};

test "inlined runs spawned jobs at submission" {
    const strategy = try mocks.inlined(gpa, testing.io, 4);
    defer strategy.pool.destroy();
    // The planning parallelism cuts a run into four batches without worker threads.
    try testing.expectEqual(@as(usize, 4), strategy.run_batches(16, 1, 1, CountBatches{}));
    var task: parallel.Task(Seven) = .init(.{});
    strategy.spawn(1, &task);
    try testing.expect(task.is_done());
    try testing.expectEqual(@as(u32, 7), strategy.block_on(&task));
}

test "pending never starts spawned jobs" {
    const strategy = try mocks.pending(gpa, testing.io, 2);
    defer strategy.pool.destroy();
    var task: parallel.Task(Seven) = .init(.{});
    strategy.spawn(1, &task);
    try testing.expect(task.is_offloaded());
    try testing.expect(!task.is_done());
    // Waiting takes the queued job back and runs it on the caller.
    try testing.expectEqual(@as(u32, 7), strategy.block_on(&task));
}

const ProbeAndSum = struct {
    runs: *std.ArrayList(Shapes),

    pub fn run(probing: ProbeAndSum, explorer: Explorer) !u64 {
        try probing.runs.append(gpa, probe(explorer));
        return explorer.fold(Range.upto(100), Sum{});
    }
};

test "explore runs serial, parallel, and seeded shapes" {
    var runs: std.ArrayList(Shapes) = .empty;
    defer runs.deinit(gpa);
    const sum = try mocks.explore(gpa, testing.io, ProbeAndSum{ .runs = &runs });
    try testing.expectEqual(@as(u64, 4950), sum);
    try testing.expectEqual(mocks.rules.len, runs.items.len);
    try testing.expectEqual(serial_shapes, runs.items[0]);
    try testing.expectEqual(parallel_shapes(mocks.tasks), runs.items[1]);
}

test "explore runs the rules in order" {
    const Record = struct {
        rules: *std.ArrayList(mocks.Rule),
        pub fn run(record: @This(), explorer: Explorer) !void {
            try record.rules.append(gpa, explorer.rule);
        }
    };
    var rules: std.ArrayList(mocks.Rule) = .empty;
    defer rules.deinit(gpa);
    try mocks.explore(gpa, testing.io, Record{ .rules = &rules });
    try testing.expectEqualDeep(@as([]const mocks.Rule, &mocks.rules), rules.items);
}

test "explore rejects an output that depends on the shape" {
    const Bodies = struct {
        pub fn run(_: @This(), explorer: Explorer) u8 {
            return explorer.run(64, Body{});
        }
        pub fn eql(_: @This(), a: u8, b: u8) bool {
            return a == b;
        }
    };
    try testing.expectError(error.ShapeDependentOutput, mocks.explore(gpa, testing.io, Bodies{}));
}

test "explore doc example: squares in order" {
    const Squares = struct {
        pub fn map(_: @This(), n: usize) u64 {
            return n * n;
        }
        pub fn run(_: @This(), explorer: Explorer) ![]u64 {
            return explorer.map_collect(gpa, Range.upto(4), @This(){});
        }
        pub fn discard(_: @This(), values: []u64) void {
            gpa.free(values);
        }
    };
    const squares = try mocks.explore(gpa, testing.io, Squares{});
    defer gpa.free(squares);
    try testing.expectEqualSlices(u64, &.{ 0, 1, 4, 9 }, squares);
}

test "seeded explorers repeat and vary their shapes" {
    const strategy = try mocks.pooled(gpa, testing.io, 2, 8);
    defer strategy.pool.destroy();
    var batch_counts: [9]bool = @splat(false);
    var worker_counts: [9]bool = @splat(false);
    var bodies = [_]bool{ false, false };
    var offloads = [_]bool{ false, false };
    for (0..256) |seed| {
        const shapes = probe(Explorer.seeded(strategy, seed));
        // A seed repeats its shapes.
        try testing.expectEqual(shapes, probe(Explorer.seeded(strategy, seed)));
        batch_counts[shapes.batches] = true;
        worker_counts[shapes.tile_workers] = true;
        bodies[@intFromBool(shapes.body == 'p')] = true;
        offloads[@intFromBool(shapes.offloaded)] = true;
    }
    // Across seeds, every call takes each of its shapes, including every batch count from the
    // whole input to the planning parallelism and every tile worker count.
    for (1..9) |count| {
        try testing.expect(batch_counts[count]);
        try testing.expect(worker_counts[count]);
    }
    try testing.expect(bodies[0] and bodies[1]);
    try testing.expect(offloads[0] and offloads[1]);
}

fn body_at(explorer: Explorer, len: usize) u8 {
    return explorer.run(len, Body{});
}

test "seeded choices depend on the call site and the length" {
    const strategy = try mocks.pooled(gpa, testing.io, 2, 2);
    defer strategy.pool.destroy();
    var by_length = false;
    var by_site = false;
    for (0..64) |seed| {
        const explorer = Explorer.seeded(strategy, seed);
        if (body_at(explorer, 10) != body_at(explorer, 11)) by_length = true;
        const first = explorer.run(10, Body{});
        const second = explorer.run(10, Body{});
        if (first != second) by_site = true;
    }
    try testing.expect(by_length);
    try testing.expect(by_site);
}

const Maps = struct {
    squares: []u64,
    shifted: []u64,
    failed_at_57: bool,
    doubled: []u64,
    weighted: []u64,
};

const MapOps = struct {
    const Square = struct {
        pub fn map(_: @This(), n: usize) u64 {
            return n * n;
        }
    };
    const Shift = struct {
        pub fn map(_: @This(), n: usize) error{Never}!u64 {
            return n + 1;
        }
    };
    const Fail = struct {
        pub fn map(_: @This(), n: usize) error{Fifty7}!u64 {
            if (n == 57) return error.Fifty7;
            return n;
        }
    };
    const Double = struct {
        pub fn init(_: @This()) std.ArrayList(u64) {
            return .empty;
        }
        pub fn map(_: @This(), seen: *std.ArrayList(u64), n: usize) u64 {
            seen.append(gpa, n) catch @panic("out of memory");
            return n * 2;
        }
        pub fn deinit_state(_: @This(), seen: *std.ArrayList(u64)) void {
            seen.deinit(gpa);
        }
    };
    const Weigh = struct {
        pub fn init(_: @This()) void {}
        pub fn map(_: @This(), _: *void, n: usize) u64 {
            return n + 3;
        }
    };

    pub fn run(_: MapOps, explorer: Explorer) !Maps {
        const items = Range.upto(100);
        const squares = try explorer.map_collect(gpa, items, Square{});
        errdefer gpa.free(squares);
        const shifted = try explorer.try_map_collect(gpa, items, Shift{});
        errdefer gpa.free(shifted);
        const failed_at_57 = if (explorer.try_map_collect(gpa, items, Fail{})) |values| failed: {
            gpa.free(values);
            break :failed false;
        } else |err| err == error.Fifty7;
        const doubled = try explorer.map_init_collect(gpa, items, Double{});
        errdefer gpa.free(doubled);
        const weighted = try explorer.map_init_collect_with_multiplier(gpa, items, 4, Weigh{});
        return .{
            .squares = squares,
            .shifted = shifted,
            .failed_at_57 = failed_at_57,
            .doubled = doubled,
            .weighted = weighted,
        };
    }

    pub fn discard(_: MapOps, maps: Maps) void {
        gpa.free(maps.squares);
        gpa.free(maps.shifted);
        gpa.free(maps.doubled);
        gpa.free(maps.weighted);
    }
};

test "explore runs every map operation" {
    const maps = try mocks.explore(gpa, testing.io, MapOps{});
    defer (MapOps{}).discard(maps);
    for (0..100) |n| {
        try testing.expectEqual(@as(u64, n * n), maps.squares[n]);
        try testing.expectEqual(@as(u64, n + 1), maps.shifted[n]);
        try testing.expectEqual(@as(u64, n * 2), maps.doubled[n]);
        try testing.expectEqual(@as(u64, n + 3), maps.weighted[n]);
    }
    try testing.expect(maps.failed_at_57);
}

test "parallel explorer takes the most parallel shapes" {
    const strategy = try mocks.pooled(gpa, testing.io, 2, 3);
    defer strategy.pool.destroy();
    try testing.expectEqual(parallel_shapes(3), probe(Explorer.parallel(strategy)));
    // Planning one task keeps bodies and collection operations serial, while the pool still
    // takes spawned jobs.
    var serial = serial_shapes;
    serial.offloaded = true;
    try testing.expectEqual(serial, probe(Explorer.parallel(strategy.with_parallelism(1))));
}
