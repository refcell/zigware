//! Tests of `run_tiles`, ported from commonware's `parallel/src/lib.rs` (`run_tiles_*`). The
//! stall tests pause a worker inside `fill` with a bounded spin, so they need the pool's
//! threads to run concurrently with the caller.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const parallel = @import("root.zig");

const Range = parallel.Range;
const Grid = parallel.Grid;
const Rayon = parallel.Rayon;
const ThreadPool = parallel.ThreadPool;
const sequential = parallel.sequential;
const allocator = testing.allocator;

/// A tile as its row and the pieces `fill` received.
const Tile = struct { row: usize, pieces: []Range };

const Recorded = struct {
    grid: usize,
    tiles: []Tile,

    fn deinit(recorded: Recorded) void {
        for (recorded.tiles) |tile| allocator.free(tile.pieces);
        allocator.free(recorded.tiles);
    }
};

const NoHook = struct {
    pub fn on_fill(_: NoHook, _: usize, _: Range) void {}
    pub fn on_finish(_: NoHook, _: []const Range) void {}
};

/// Records each piece; finishing a tile takes every recorded piece, which must belong to the
/// tile's row, and leaves the state empty for the next tile.
fn Recorder(comptime Hook: type) type {
    return struct {
        hook: Hook,

        pub const State = struct { row: ?usize = null, pieces: std.ArrayList(Range) = .empty };

        pub fn init(_: @This()) State {
            return .{};
        }

        pub fn fill(recorder: @This(), state: *State, row: usize, columns: Range) void {
            if (state.row) |open| assert(open == row);
            assert(!columns.is_empty());
            recorder.hook.on_fill(row, columns);
            state.row = row;
            state.pieces.append(allocator, columns) catch @panic("out of memory");
        }

        pub fn finish(recorder: @This(), state: *State, row: usize) Tile {
            assert(state.row.? == row);
            recorder.hook.on_finish(state.pieces.items);
            const pieces = state.pieces.toOwnedSlice(allocator) catch @panic("out of memory");
            state.row = null;
            return .{ .row = row, .pieces = pieces };
        }

        pub fn deinit_state(_: @This(), state: *State) void {
            state.pieces.deinit(allocator);
        }
    };
}

fn Run(comptime Hook: type) type {
    return struct {
        hook: Hook,

        pub fn run(run_op: @This(), tiles: anytype) anyerror!Recorded {
            const grid_index = tiles.grid();
            const recorder: Recorder(Hook) = .{ .hook = run_op.hook };
            return .{ .grid = grid_index, .tiles = try tiles.fill_collect(allocator, recorder) };
        }
    };
}

fn grid(rows: usize, tile_cost: usize) Grid {
    return .{ .rows = rows, .tile_cost = tile_cost };
}

fn tiles_hooked(strategy: anytype, len: usize, grids: []const Grid, hook: anytype) !Recorded {
    return strategy.run_tiles(len, grids, 1, Run(@TypeOf(hook)){ .hook = hook });
}

fn tiles_of(strategy: anytype, rows: usize, len: usize, tile_cost: usize) !Recorded {
    const recorded = try tiles_hooked(strategy, len, &.{grid(rows, tile_cost)}, NoHook{});
    try testing.expectEqual(@as(usize, 0), recorded.grid);
    return recorded;
}

/// Asserts that `tiles` cover a `rows` by `len` grid exactly once, each tile with contiguous
/// pieces in column order.
fn expect_covers(tiles: []const Tile, rows: usize, len: usize) !void {
    const seen = try allocator.alloc(bool, rows * len);
    defer allocator.free(seen);
    @memset(seen, false);
    for (tiles) |tile| {
        try testing.expect(tile.row < rows and tile.pieces.len > 0);
        for (tile.pieces, 0..) |columns, index| {
            if (index > 0) try testing.expectEqual(tile.pieces[index - 1].end, columns.start);
            try testing.expect(!columns.is_empty() and columns.end <= len);
            for (columns.start..columns.end) |column| {
                try testing.expect(!seen[tile.row * len + column]);
                seen[tile.row * len + column] = true;
            }
        }
    }
    for (seen) |cell| try testing.expect(cell);
}

fn expect_covered(strategy: anytype, rows: usize, len: usize, tile_cost: usize) !void {
    const recorded = try tiles_of(strategy, rows, len, tile_cost);
    defer recorded.deinit();
    try expect_covers(recorded.tiles, rows, len);
}

/// Spins until `ready.check()`; false if that takes implausibly long.
fn wait_until(ready: anytype) bool {
    var spins: u64 = 0;
    while (!ready.check()) : (spins += 1) {
        if (spins > 200_000_000) return false;
        std.Thread.yield() catch {};
    }
    return true;
}

const AtLeast = struct {
    value: *const std.atomic.Value(usize),
    target: usize,

    fn check(at_least: AtLeast) bool {
        return at_least.value.load(.acquire) >= at_least.target;
    }
};

fn create_pool(threads: u32) !*ThreadPool {
    return ThreadPool.create(allocator, testing.io, .{ .threads = threads });
}

test "run_tiles cover every cell once" {
    const pool = try create_pool(3);
    defer pool.destroy();
    // Empty grids, one cell, rows too short to cut, and longer rows, the last two with more
    // than `max_units` cells and multi-cell units.
    const grids = [_][3]usize{
        .{ 0, 5, 1 },
        .{ 3, 0, 1 },
        .{ 1, 1, 1 },
        .{ 3, 10, 1 },
        .{ 5, 7, 1 },
        .{ 5, 7, 3 },
        .{ 30, 63, 64 },
        .{ 30, 100, 64 },
        .{ 30, 32_769, 2_304 },
        .{ 44, 2_001, 288 },
    };
    for (grids) |case| {
        const rows, const len, const tile_cost = case;
        try expect_covered(sequential, rows, len, tile_cost);
        try expect_covered(Rayon.init(pool), rows, len, tile_cost);
        for ([_]usize{ 1, 2, 8, 16, 32, 64 }) |parallelism| {
            const strategy = Rayon.init(pool).with_parallelism(parallelism);
            try expect_covered(strategy, rows, len, tile_cost);
        }
    }
    // More workers than pool threads, with tiles cheap enough to cut finely, keep claims and
    // steals racing.
    for (0..200) |_| try expect_covered(Rayon.init(pool).with_parallelism(16), 7, 300, 2);
}

test "run_tiles group rows beyond the unit limit" {
    const pool = try create_pool(3);
    defer pool.destroy();
    // Three columns at tile cost four keep every grid on whole rows.
    const strategy = Rayon.init(pool).with_parallelism(4);
    const max_units = parallel.max_units;
    for ([_]usize{ max_units, max_units + 1, 2 * max_units + 1 }) |rows| {
        const recorded = try tiles_of(strategy, rows, 3, 4);
        defer recorded.deinit();
        try testing.expectEqual(rows, recorded.tiles.len);
        for (recorded.tiles) |tile| {
            try testing.expectEqual(@as(usize, 1), tile.pieces.len);
            try testing.expect(tile.pieces[0].eql(Range.upto(3)));
        }
        try expect_covers(recorded.tiles, rows, 3);
    }
}

fn expect_whole_rows(strategy: anytype) !void {
    const recorded = try tiles_of(strategy, 3, 10, 1);
    defer recorded.deinit();
    try testing.expectEqual(@as(usize, 3), recorded.tiles.len);
    for (recorded.tiles, 0..) |tile, row| {
        try testing.expectEqual(row, tile.row);
        try testing.expectEqual(@as(usize, 1), tile.pieces.len);
        try testing.expect(tile.pieces[0].eql(Range.upto(10)));
    }
}

test "run_tiles serial runs make every row one tile" {
    const pool = try create_pool(3);
    defer pool.destroy();
    try expect_whole_rows(sequential);
    try expect_whole_rows(Rayon.init(pool).with_parallelism(1));
    const empty = try tiles_of(sequential, 3, 0, 1);
    defer empty.deinit();
    try testing.expectEqual(@as(usize, 0), empty.tiles.len);
}

test "run_tiles bound workers by the grid" {
    const pool = try create_pool(3);
    defer pool.destroy();
    const strategy = Rayon.init(pool).with_parallelism(std.math.maxInt(usize));
    const cases = [_][3]usize{ .{ 1, 1, 1 }, .{ 3, 10, 1 }, .{ 32, 1, 100 }, .{ 30, 100, 64 } };
    for (cases) |case| try expect_covered(strategy, case[0], case[1], case[2]);
}

test "run_tiles cut the grid that finishes first" {
    const pool = try create_pool(3);
    defer pool.destroy();
    // Twenty-six rows finishing at 1024 cells cost fewer cells than twenty-four finishing at
    // 2048, so a serial run cuts the first grid. Eight workers get three whole rows each of
    // the second but would cut rows of the first, so a shared run cuts the second whole.
    const len = 5_000;
    const grids = [_]Grid{ grid(26, 1024), grid(24, 2048) };
    const serial = try tiles_hooked(sequential, len, &grids, NoHook{});
    defer serial.deinit();
    try testing.expectEqual(@as(usize, 0), serial.grid);
    try expect_covers(serial.tiles, 26, len);
    try testing.expectEqual(@as(usize, 26), serial.tiles.len);

    const shared = try tiles_hooked(Rayon.init(pool).with_parallelism(8), len, &grids, NoHook{});
    defer shared.deinit();
    try testing.expectEqual(@as(usize, 1), shared.grid);
    try expect_covers(shared.tiles, 24, len);
    try testing.expectEqual(@as(usize, 24), shared.tiles.len);
    for (shared.tiles) |tile| {
        try testing.expectEqual(@as(usize, 1), tile.pieces.len);
        try testing.expect(tile.pieces[0].eql(Range.upto(len)));
    }

    // The order of equally cheap grids breaks the tie.
    const tie = try tiles_hooked(sequential, len, &.{ grid(24, 2048), grid(24, 2048) }, NoHook{});
    defer tie.deinit();
    try testing.expectEqual(@as(usize, 0), tie.grid);
}

test "run_tiles share whole rows when cutting only adds tiles" {
    const pool = try create_pool(3);
    defer pool.destroy();
    const four = Rayon.init(pool).with_parallelism(4);
    const eight = try tiles_hooked(four, 1_000, &.{grid(8, 10)}, NoHook{});
    defer eight.deinit();
    try expect_covers(eight.tiles, 8, 1_000);
    try testing.expectEqual(@as(usize, 8), eight.tiles.len);

    // Nine rows over four workers put three share boundaries inside rows, and each cuts one.
    const nine = try tiles_hooked(four, 1_000, &.{grid(9, 10)}, NoHook{});
    defer nine.deinit();
    try expect_covers(nine.tiles, 9, 1_000);
    try testing.expect(nine.tiles.len >= 12);

    // Cutting three rows of fifty cells over two workers ties two whole rows; the tie keeps
    // the rows whole.
    const two = Rayon.init(pool).with_parallelism(2);
    const three = try tiles_hooked(two, 50, &.{grid(3, 10)}, NoHook{});
    defer three.deinit();
    try expect_covers(three.tiles, 3, 50);
    try testing.expectEqual(@as(usize, 3), three.tiles.len);
}

/// The worker filling row 0 waits until other workers have filled `others_min` rows.
const RowZeroWaits = struct {
    others: *std.atomic.Value(usize),
    others_min: usize,

    pub fn on_fill(hook: RowZeroWaits, row: usize, _: Range) void {
        if (row != 0) {
            _ = hook.others.fetchAdd(1, .release);
            return;
        }
        const ready: AtLeast = .{ .value = hook.others, .target = hook.others_min };
        if (!wait_until(ready)) @panic("other workers must fill rows");
    }

    pub fn on_finish(_: RowZeroWaits, _: []const Range) void {}
};

test "run_tiles spread short rows across workers" {
    const pool = try create_pool(3);
    defer pool.destroy();
    // Every row is shorter than a tile's cost, so no row is cut, but rows still go to separate
    // workers: the worker filling the first row waits until another has filled a row.
    var others: std.atomic.Value(usize) = .init(0);
    const hook: RowZeroWaits = .{ .others = &others, .others_min = 1 };
    const strategy = Rayon.init(pool).with_parallelism(4);
    const recorded = try tiles_hooked(strategy, 1, &.{grid(32, 100)}, hook);
    defer recorded.deinit();
    try expect_covers(recorded.tiles, 32, 1);
    try testing.expectEqual(@as(usize, 32), recorded.tiles.len);
}

test "run_tiles take a stalled worker's last row" {
    const pool = try create_pool(3);
    defer pool.destroy();
    // Two workers over eight whole rows. The worker filling the first row stalls until every
    // other row is filled, which only the other worker can do by claiming the whole queue.
    var others: std.atomic.Value(usize) = .init(0);
    const hook: RowZeroWaits = .{ .others = &others, .others_min = 7 };
    const strategy = Rayon.init(pool).with_parallelism(2);
    const recorded = try tiles_hooked(strategy, 1, &.{grid(8, 100)}, hook);
    defer recorded.deinit();
    try expect_covers(recorded.tiles, 8, 1);
    try testing.expectEqual(@as(usize, 8), recorded.tiles.len);
}

const StalledShare = struct {
    filled: *std.atomic.Value(usize),
    target: usize,

    pub fn on_fill(hook: StalledShare, _: usize, columns: Range) void {
        if (columns.start == 0) {
            const ready: AtLeast = .{ .value = hook.filled, .target = hook.target };
            if (!wait_until(ready)) @panic("the stalled share must be cut");
        }
        _ = hook.filled.fetchAdd(columns.len(), .release);
    }

    pub fn on_finish(_: StalledShare, _: []const Range) void {}
};

test "run_tiles cut the share of a stalled worker" {
    const pool = try create_pool(3);
    defer pool.destroy();
    // Four equal shares of one row. The worker holding the first share stalls in its first
    // piece until the others have filled every cell except those it may keep: that piece,
    // plus at most two tile costs that are not worth taking.
    const len = 4_000;
    const tile_cost = 10;
    var filled: std.atomic.Value(usize) = .init(0);
    const hook: StalledShare = .{ .filled = &filled, .target = len - 3 * tile_cost };
    const strategy = Rayon.init(pool).with_parallelism(4);
    const recorded = try tiles_hooked(strategy, len, &.{grid(1, tile_cost)}, hook);
    defer recorded.deinit();
    try expect_covers(recorded.tiles, 1, len);
    for (recorded.tiles) |tile| {
        if (tile.pieces[0].start != 0) continue;
        var kept: usize = 0;
        for (tile.pieces) |columns| kept += columns.len();
        try testing.expect(kept <= 3 * tile_cost);
    }
}

/// Workers on the last three shares pause at the claims starting at `wait_for` until the
/// first share's tile finishes; the first worker pauses at the claim starting at `drain`
/// until all three have paused, then empties its share.
const NoCheapSteal = struct {
    ready: *std.atomic.Value(usize),
    release: *std.atomic.Value(usize),
    wait_for: [3]usize,
    drain: usize,

    pub fn on_fill(hook: NoCheapSteal, _: usize, columns: Range) void {
        if (std.mem.indexOfScalar(usize, &hook.wait_for, columns.start) != null) {
            _ = hook.ready.fetchAdd(1, .release);
            const released: AtLeast = .{ .value = hook.release, .target = 1 };
            if (!wait_until(released)) @panic("the first share must finish");
        } else if (columns.start == hook.drain) {
            const paused: AtLeast = .{ .value = hook.ready, .target = hook.wait_for.len };
            if (!wait_until(paused)) @panic("the other shares must pause");
        }
    }

    pub fn on_finish(hook: NoCheapSteal, pieces: []const Range) void {
        if (pieces[0].start == 0) hook.release.store(1, .release);
    }
};

/// Fills one row of `len` cells as four shares and expects no worker to steal: the tails
/// left pending are too small to pay for a split, so the run ends with one tile per share.
fn expect_no_cheap_steal(len: usize, tile_cost: usize, wait_for: [3]usize, drain: usize) !void {
    const pool = try create_pool(3);
    defer pool.destroy();
    var ready: std.atomic.Value(usize) = .init(0);
    var release: std.atomic.Value(usize) = .init(0);
    const hook: NoCheapSteal = .{
        .ready = &ready,
        .release = &release,
        .wait_for = wait_for,
        .drain = drain,
    };
    const strategy = Rayon.init(pool).with_parallelism(4);
    const recorded = try tiles_hooked(strategy, len, &.{grid(1, tile_cost)}, hook);
    defer recorded.deinit();
    try expect_covers(recorded.tiles, 1, len);
    try testing.expectEqual(@as(usize, 4), recorded.tiles.len);
}

test "run_tiles do not steal equal cost tails" {
    // Shares of three claims each: a paused share's pending back half is exactly one tile cost.
    try expect_no_cheap_steal(120, 10, .{ 30, 60, 90 }, 0);
}

test "run_tiles do not steal clipped tails at cost" {
    // Two-cell units at a tile cost of three cells: the last share's pending back half spans
    // two units but only three cells before the grid ends.
    try expect_no_cheap_steal(65_537, 3, .{ 32_762, 49_146, 65_526 }, 16_384);
}

test "run_tiles serial runs reuse worker state" {
    const Counting = struct {
        inits: *usize,

        pub fn init(counting: @This()) void {
            counting.inits.* += 1;
        }
        pub fn fill(_: @This(), _: *void, _: usize, _: Range) void {}
        pub fn finish(_: @This(), _: *void, row: usize) usize {
            return row;
        }
    };
    const RunCounting = struct {
        inits: *usize,

        pub fn run(run_op: @This(), tiles: anytype) anyerror![]usize {
            return tiles.fill_collect(allocator, Counting{ .inits = run_op.inits });
        }
    };
    var inits: usize = 0;
    const rows = try sequential.run_tiles(1_000, &.{grid(7, 16)}, 1, RunCounting{
        .inits = &inits,
    });
    defer allocator.free(rows);
    try testing.expectEqual(@as(usize, 1), inits);
    try testing.expectEqual(@as(usize, 7), rows.len);
}
