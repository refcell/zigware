//! `run_tiles`: runs an operation over tiles of several passes (rows) over the same `len`
//! columns, where finishing a tile has a fixed cost (commonware's `Grid`, `Tiles`, `Shares`).
//!
//! A tile is one row over a contiguous range of columns, and a run pays `tile_cost` once per
//! tile, so every cut of a row adds a finish. A serial run cuts the grid with the fewest cells,
//! counting each row's finish, and makes every row one tile on the calling thread. A parallel
//! run estimates each grid's critical path over its workers, as whole rows and as equal shares
//! of cells, and cuts the grid and shape with the shortest estimate:
//!
//! - whole rows queue in one share that every worker claims from, one unit of rows at a time;
//! - shares of cells give each worker an equal share that it claims from the front one tile cost
//!   at a time; a worker whose share is empty takes the back half of the largest other share,
//!   while that half is longer than a tile's cost.

const std = @import("std");
const assert = std.debug.assert;
const ops = @import("ops.zig");
const strategy_module = @import("strategy.zig");

const Range = ops.Range;
const max_chunks = ops.max_chunks;

/// A grid `run_tiles` can cut: `rows` passes over the run's columns, where finishing a tile
/// costs `tile_cost` cells.
pub const Grid = struct {
    rows: usize,
    tile_cost: usize,

    pub const Estimate = struct { cells: usize, whole: bool };

    /// Estimates the cells on the critical path when `workers` share this grid over `len`
    /// columns, and whether the workers take whole rows. Cutting rows is considered only when
    /// half a row is at least the tile cost, and a tie goes to whole rows.
    pub fn critical_path(grid: Grid, len: usize, workers: usize) Estimate {
        assert(grid.tile_cost > 0);
        assert(workers > 0);
        const tile_cost = grid.tile_cost;
        const row = len +| tile_cost;
        const whole = div_ceil(grid.rows, workers) *| row;
        if (len < tile_cost *| 2) return .{ .cells = whole, .whole = true };
        const cut = ((grid.rows *| row) / workers) +| (tile_cost *| 3);
        if (cut < whole) return .{ .cells = cut, .whole = false };
        return .{ .cells = whole, .whole = true };
    }
};

pub const Choice = struct { grid: usize, cells: usize, whole: bool };

/// The grid among `grids` with the shortest estimated critical path for `workers` over `len`
/// columns. Ties go to the earliest grid.
pub fn choose(grids: []const Grid, len: usize, workers: usize) Choice {
    assert(grids.len > 0); // run_tiles must receive at least one grid.
    var best: Choice = undefined;
    for (grids, 0..) |grid, index| {
        const estimate = grid.critical_path(len, workers);
        if (index == 0 or estimate.cells < best.cells) {
            best = .{ .grid = index, .cells = estimate.cells, .whole = estimate.whole };
        }
    }
    assert(best.grid < grids.len);
    return best;
}

fn div_ceil(numerator: usize, denominator: usize) usize {
    assert(denominator > 0);
    return numerator / denominator + @intFromBool(numerator % denominator != 0);
}

/// Bits for each end of a packed range of units, few enough for any `usize`.
const half_bits = 16;

/// The largest unit index a packed range can hold.
pub const max_units: usize = (1 << half_bits) - 1;

fn pack(start: usize, end: usize) usize {
    assert(start <= end);
    assert(end <= max_units);
    return start << half_bits | end;
}

fn unpack(word: usize) struct { usize, usize } {
    const start = word >> half_bits;
    const end = word & max_units;
    assert(start <= end);
    return .{ start, end };
}

/// One worker's packed range of units, alone on its cache line so that neighboring workers'
/// claims do not contend.
const Pending = struct {
    word: std.atomic.Value(usize) align(std.atomic.cache_line),
};

/// The unclaimed cells of a shared run: one queue of whole rows, or one share of cells per
/// worker. Claiming from the front and splitting off the back are each one atomic update.
const Shares = struct {
    pending: [max_chunks]Pending,
    pending_count: usize,
    workers: usize,
    /// Cells per unit, enough that every unit index fits in `half_bits`.
    unit: usize,
    cells: usize,
    /// Units in one claim.
    claim_units: usize,
    /// Cells a stolen half must exceed, or zero for the queue of whole rows.
    split_cost: usize,
    /// Whether any initial share of cells has a payable split. Claims only shrink shares and
    /// only a taken half refills one, so without one at the start there is never one.
    splittable: bool,

    const Split = struct { middle: usize, cells: usize };

    /// Queues whole rows when `whole` is set, and otherwise splits the cells into equal shares,
    /// none smaller than a claim. At most `workers_requested` workers take part.
    fn init(
        shares: *Shares,
        rows: usize,
        len: usize,
        tile_cost: usize,
        workers_requested: usize,
        whole: bool,
    ) void {
        assert(rows > 0 and len > 0);
        assert(workers_requested > 0);
        const cells = rows * len;
        const unit = if (whole) len * div_ceil(rows, max_units) else div_ceil(cells, max_units);
        const claim_units = if (whole) 1 else div_ceil(tile_cost, unit);
        const units = div_ceil(cells, unit);
        assert(units <= max_units);
        // A nonempty grid holds at least one whole claim, since `critical_path` shares cells
        // only when a row holds two tile costs.
        const workers = @min(workers_requested, units / claim_units, max_chunks);
        assert(workers >= 1);
        shares.* = .{
            .pending = undefined,
            .pending_count = if (whole) 1 else workers,
            .workers = workers,
            .unit = unit,
            .cells = cells,
            .claim_units = claim_units,
            .split_cost = if (whole) 0 else tile_cost,
            .splittable = false,
        };
        if (whole) {
            shares.pending[0] = .{ .word = .init(pack(0, units)) };
            return;
        }
        for (0..workers) |worker| {
            const range = ops.balanced(units, workers, worker);
            shares.pending[worker] = .{ .word = .init(pack(range.start, range.end)) };
            const word = shares.pending[worker].word.raw;
            if (shares.split(word) != null) shares.splittable = true;
        }
    }

    /// The midpoint and actual cell count of a share whose back half pays for a split.
    fn split(shares: *const Shares, word: usize) ?Split {
        const start, const end = unpack(word);
        if (end - start < 2) return null;
        // The last unit can run past the grid, so the back half's actual cells decide whether
        // the split pays, and the share's actual cells rank it among victims.
        const middle = start + (end - start) / 2;
        const stop = @min(end *| shares.unit, shares.cells);
        assert(middle * shares.unit <= stop);
        if (stop - middle * shares.unit <= shares.split_cost) return null;
        return .{ .middle = middle, .cells = stop - start * shares.unit };
    }

    /// Returns the next cells for `worker`, or null once no share is worth splitting.
    fn claim(shares: *Shares, worker: usize) ?Range {
        assert(worker < shares.workers);
        const pending = &shares.pending[@min(worker, shares.pending_count - 1)].word;
        var word = pending.load(.monotonic);
        while (true) {
            const start, const end = unpack(word);
            if (start == end) {
                // Only this worker refills its own empty share, so a plain store loses no units.
                word = shares.steal(worker) orelse return null;
                pending.store(word, .monotonic);
                continue;
            }
            // Thieves only cut the back, so a failed exchange retries with the current range.
            const stop = start + @min(shares.claim_units, end - start);
            if (pending.cmpxchgWeak(word, pack(stop, end), .monotonic, .monotonic)) |current| {
                word = current;
                continue;
            }
            const cells_end = @min(stop *| shares.unit, shares.cells);
            return Range.init(start * shares.unit, cells_end);
        }
    }

    /// Takes the back half of the largest share other than the thief's, returning it packed.
    fn steal(shares: *Shares, thief: usize) ?usize {
        if (!shares.splittable) return null;
        while (true) {
            // Halving the largest share keeps steals, and the tiles they add, few. Ties go to
            // the last share, like Rust's `max_by_key`.
            var victim: ?usize = null;
            var victim_word: usize = 0;
            var victim_split: Split = undefined;
            for (0..shares.pending_count) |worker| {
                if (worker == thief) continue;
                const word = shares.pending[worker].word.load(.monotonic);
                const candidate = shares.split(word) orelse continue;
                if (victim == null or candidate.cells >= victim_split.cells) {
                    victim = worker;
                    victim_word = word;
                    victim_split = candidate;
                }
            }
            const index = victim orelse return null;
            assert(index != thief);
            // Keep the victim's front half if its range is still the one scanned.
            const start, const end = unpack(victim_word);
            const front = pack(start, victim_split.middle);
            const exchanged = shares.pending[index].word.cmpxchgStrong(
                victim_word,
                front,
                .monotonic,
                .monotonic,
            );
            if (exchanged == null) return pack(victim_split.middle, end);
        }
    }

    /// Processes the cells `worker` claims, `len` to a row, appending a result per tile. A tile
    /// ends where its row ends or where the worker's next cells do not continue it.
    fn run(
        shares: *Shares,
        worker: usize,
        len: usize,
        state: anytype,
        op: anytype,
        results: anytype,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!void {
        assert(len > 0);
        var open_row: ?usize = null;
        var open_column: usize = 0;
        while (shares.claim(worker)) |cells| {
            var start = cells.start;
            while (start < cells.end) {
                const row = start / len;
                const column = start % len;
                const end = @min(cells.end, (row + 1) * len);
                if (open_row) |open| {
                    if (open != row or open_column != column) {
                        try results.append(allocator, op.finish(state, open));
                    }
                }
                op.fill(state, row, Range.init(column, column + (end - start)));
                open_row = row;
                open_column = column + (end - start);
                start = end;
            }
        }
        if (open_row) |open| try results.append(allocator, op.finish(state, open));
    }
};

/// How a `Tiles` run cuts its grid.
const Plan = union(enum) {
    /// Every row is one tile, processed on the calling thread.
    serial,
    shared: struct { tile_cost: usize, workers: usize, whole: bool },
};

/// Tiles supplied for one `run_tiles` operation. Each tile is one row over a contiguous range
/// of columns, and the tiles cover every cell of the chosen grid exactly once.
pub fn Tiles(comptime Strategy: type) type {
    return struct {
        const Self = @This();

        strategy: Strategy,
        grid_index: usize,
        rows: usize,
        len: usize,
        plan: Plan,

        /// Makes every row of the cheapest serial grid one tile.
        pub fn serial(strategy: Strategy, grids: []const Grid, len: usize) Self {
            const choice = choose(grids, len, 1);
            return .{
                .strategy = strategy,
                .grid_index = choice.grid,
                .rows = grids[choice.grid].rows,
                .len = len,
                .plan = .serial,
            };
        }

        /// Shares the grid that `workers` workers finish soonest among them.
        pub fn parallel(strategy: Strategy, grids: []const Grid, len: usize, workers: usize) Self {
            assert(workers >= 1);
            const choice = choose(grids, len, workers);
            const rows = grids[choice.grid].rows;
            _ = std.math.mul(usize, rows, len) catch @panic("rows * len must fit in usize");
            return .{
                .strategy = strategy,
                .grid_index = choice.grid,
                .rows = rows,
                .len = len,
                .plan = .{ .shared = .{
                    .tile_cost = grids[choice.grid].tile_cost,
                    .workers = workers,
                    .whole = choice.whole,
                } },
            };
        }

        /// The index, among the grids supplied to the run, of the grid it cuts.
        pub fn grid(self: Self) usize {
            return self.grid_index;
        }

        /// Fills every tile piece by piece with per-worker state, collecting one result per tile.
        ///
        /// `op.fill(&state, row, columns)` receives a tile's row and each of its pieces in column
        /// order (no piece is empty); `op.finish(&state, row)` then ends the tile and returns its
        /// result. `op.init()` creates state a worker reuses across its tiles, so `finish` must
        /// leave it ready for another tile. Results come back in no particular order; where a
        /// parallel run cuts a row depends on timing, so combine a row's results in a way that
        /// does not depend on its cuts. Free the result with `allocator`.
        pub fn fill_collect(
            self: Self,
            allocator: std.mem.Allocator,
            op: anytype,
        ) std.mem.Allocator.Error![]ops.Return(@TypeOf(op), "finish") {
            const R = ops.Return(@TypeOf(op), "finish");
            if (self.rows == 0 or self.len == 0) return allocator.alloc(R, 0);
            switch (self.plan) {
                .serial => {
                    const results = try allocator.alloc(R, self.rows);
                    var state = op.init();
                    defer deinit_state(op, &state);
                    for (results, 0..) |*result, row| {
                        op.fill(&state, row, Range.upto(self.len));
                        result.* = op.finish(&state, row);
                    }
                    return results;
                },
                .shared => |shared| return self.fill_shared(allocator, op, shared),
            }
        }

        fn fill_shared(
            self: Self,
            allocator: std.mem.Allocator,
            op: anytype,
            shared: @FieldType(Plan, "shared"),
        ) std.mem.Allocator.Error![]ops.Return(@TypeOf(op), "finish") {
            const R = ops.Return(@TypeOf(op), "finish");
            const List = std.ArrayList(R);
            var shares: Shares = undefined;
            shares.init(self.rows, self.len, shared.tile_cost, shared.workers, shared.whole);
            var lists: [max_chunks]List = @splat(.empty);
            defer for (&lists) |*list| list.deinit(allocator);
            var failed: std.atomic.Value(bool) = .init(false);
            const Context = struct {
                shares: *Shares,
                lists: *[max_chunks]List,
                op: @TypeOf(op),
                allocator: std.mem.Allocator,
                len: usize,
                failed: *std.atomic.Value(bool),

                pub fn body(context: *const @This(), worker: usize) void {
                    var state = context.op.init();
                    defer deinit_state(context.op, &state);
                    const list = &context.lists[worker];
                    const claims = context.shares;
                    const gpa = context.allocator;
                    claims.run(worker, context.len, &state, context.op, list, gpa) catch {
                        context.failed.store(true, .monotonic);
                    };
                }
            };
            const context: Context = .{
                .shares = &shares,
                .lists = &lists,
                .op = op,
                .allocator = allocator,
                .len = self.len,
                .failed = &failed,
            };
            self.strategy.execute(shares.workers, &context, Context.body);
            if (failed.load(.monotonic)) return error.OutOfMemory;
            var total: usize = 0;
            for (lists[0..shares.workers]) |list| total += list.items.len;
            const results = try allocator.alloc(R, total);
            var offset: usize = 0;
            for (lists[0..shares.workers]) |list| {
                @memcpy(results[offset..][0..list.items.len], list.items);
                offset += list.items.len;
            }
            assert(offset == total);
            return results;
        }
    };
}

fn deinit_state(op: anytype, state: anytype) void {
    if (comptime @hasDecl(ops.Base(@TypeOf(op)), "deinit_state")) op.deinit_state(state);
}

/// Runs `op.run(tiles)` once with tiles over `len` columns of one of `grids` (see `Tiles`).
/// `multiplier` estimates work per cell for adaptive strategies. A parallel run plans for at
/// most `max_chunks` workers. Both shapes must produce equivalent results.
pub noinline fn run_tiles(
    strategy: anytype,
    len: usize,
    grids: []const Grid,
    multiplier: usize,
    op: anytype,
) ops.Return(@TypeOf(op), "run") {
    assert(grids.len > 0);
    // Like commonware, the work is the cheapest serial grid's cells times the multiplier.
    var cells: usize = std.math.maxInt(usize);
    for (grids) |grid| cells = @min(cells, grid.critical_path(len, 1).cells);
    const work = @max(len, cells *| multiplier);
    var call = strategy_module.adapt(strategy, @returnAddress(), len, work, .placed);
    return call.finish(run_tiles_on(call.get(), len, grids, op));
}

fn run_tiles_on(
    strategy: anytype,
    len: usize,
    grids: []const Grid,
    op: anytype,
) ops.Return(@TypeOf(op), "run") {
    const T = Tiles(@TypeOf(strategy));
    const workers = @min(strategy.parallelism(), max_chunks);
    if (workers <= 1) return op.run(T.serial(strategy, grids, len));
    return op.run(T.parallel(strategy, grids, len, workers));
}

test "pack and unpack round trip" {
    try std.testing.expectEqual(.{ @as(usize, 3), @as(usize, 9) }, unpack(pack(3, 9)));
    const start, const end = unpack(pack(max_units, max_units));
    try std.testing.expectEqual(max_units, start);
    try std.testing.expectEqual(max_units, end);
}

test "critical path prefers whole rows on ties" {
    // Three rows of fifty cells over two workers: cutting at 90 + 30 ties two whole rows at 120.
    const estimate = (Grid{ .rows = 3, .tile_cost = 10 }).critical_path(50, 2);
    try std.testing.expectEqual(@as(usize, 120), estimate.cells);
    try std.testing.expect(estimate.whole);
}
