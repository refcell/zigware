//! Tests of the Rayon strategy's pool work, ported from commonware's `parallel/src/rayon`
//! tests: try_fold's early stop, recursive joins, the busy-time meter, sort edge inputs, spawns
//! from inside a job, and the configured thread count.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const parallel = @import("root.zig");

const Range = parallel.Range;
const Rayon = parallel.Rayon;
const ThreadPool = parallel.ThreadPool;
const gpa = testing.allocator;
const ms = std.time.ns_per_ms;

fn create_pool(threads: u32) !*ThreadPool {
    return ThreadPool.create(gpa, testing.io, .{ .threads = threads });
}

/// Which items `try_fold` folded and how many it discarded (commonware's `Ledger`).
const Ledger = struct {
    calls: []std.atomic.Value(u32),
    discarded: std.atomic.Value(usize) = .init(0),
    errors: []const usize,

    const List = std.ArrayList(usize);

    pub fn identity(_: *Ledger) List {
        return .empty;
    }

    pub fn fold(ledger: *Ledger, acc: List, index: usize) error{Failed}!List {
        _ = ledger.calls[index].fetchAdd(1, .monotonic);
        var list = acc;
        for (ledger.errors) |failing| {
            if (index == failing) {
                list.deinit(gpa);
                return error.Failed;
            }
        }
        list.append(gpa, index) catch @panic("out of memory");
        return list;
    }

    pub fn reduce(_: *Ledger, a: List, b: List) List {
        var list = a;
        var other = b;
        defer other.deinit(gpa);
        list.appendSlice(gpa, other.items) catch @panic("out of memory");
        return list;
    }

    pub fn discard(ledger: *Ledger, acc: List) void {
        var list = acc;
        _ = ledger.discarded.fetchAdd(list.items.len, .monotonic);
        list.deinit(gpa);
    }
};

test "try_fold stops at an error and frees every accumulator" {
    // commonware `try_fold_stops_at_an_error_and_drops_every_item_once`: an owning accumulator
    // is discarded exactly once whether its chunk succeeds or fails (the test allocator finds
    // a leaked one).
    const len = 1000;
    var calls: [len]std.atomic.Value(u32) = undefined;
    const cases = [_]struct { u32, []const usize }{
        .{ 0, &.{10} }, .{ 1, &.{ 10, 500, 999 } }, .{ 3, &.{ 10, 500, 999 } },
    };
    for (cases) |case| {
        const threads, const errors = case;
        const pool = try create_pool(threads);
        defer pool.destroy();
        for (&calls) |*call| call.* = .init(0);
        var ledger: Ledger = .{ .calls = &calls, .errors = errors };
        try testing.expectError(error.Failed, Rayon.init(pool).try_fold(Range.upto(len), &ledger));
        for (calls) |call| try testing.expect(call.load(.monotonic) <= 1);
        if (threads == 0) {
            // One thread folds in order and stops at the failing item.
            for (calls, 0..) |call, index| {
                try testing.expectEqual(@intFromBool(index <= 10), call.load(.monotonic));
            }
        }
    }
    // Without an error, the items come back in order.
    const pool = try create_pool(3);
    defer pool.destroy();
    for (&calls) |*call| call.* = .init(0);
    var ledger: Ledger = .{ .calls = &calls, .errors = &.{} };
    var items = try Rayon.init(pool).try_fold(Range.upto(len), &ledger);
    defer items.deinit(gpa);
    for (items.items, 0..) |item, index| try testing.expectEqual(index, item);
    try testing.expectEqual(@as(usize, len), items.items.len);
}

/// commonware's recursive `quick_sort`: partition, then sort both halves in a join.
const QuickSort = struct {
    rayon: Rayon,
    items: []u32,

    pub fn call(sort: QuickSort) void {
        if (sort.items.len <= 1) return;
        const mid = partition(sort.items);
        _ = sort.rayon.join(
            QuickSort{ .rayon = sort.rayon, .items = sort.items[0..mid] },
            QuickSort{ .rayon = sort.rayon, .items = sort.items[mid + 1 ..] },
        );
    }

    fn partition(items: []u32) usize {
        const pivot = items.len - 1;
        var low: usize = 0;
        for (0..pivot) |index| {
            if (items[index] <= items[pivot]) {
                std.mem.swap(u32, &items[low], &items[index]);
                low += 1;
            }
        }
        std.mem.swap(u32, &items[low], &items[pivot]);
        return low;
    }
};

fn quick_sort_random(len: usize) !void {
    const pool = try create_pool(3);
    defer pool.destroy();
    var rng = utils.TestRng.init(0);
    const data = try gpa.alloc(u32, len);
    defer gpa.free(data);
    for (data) |*value| value.* = rng.next_u32();
    const expected = try gpa.dupe(u32, data);
    defer gpa.free(expected);
    std.sort.pdq(u32, expected, {}, std.sort.asc(u32));
    QuickSort.call(.{ .rayon = Rayon.init(pool), .items = data });
    try testing.expectEqualSlices(u32, expected, data);
}

test "a recursive join quicksort sorts random data" {
    // commonware join `sort` (6K items) and `sort_in_pool` (12K items), on 4 threads.
    try quick_sort_random(6 * 1024);
    try quick_sort_random(12 * 1024);
}

const Increment = struct {
    counter: *u32,
    pub fn call(increment: Increment) void {
        increment.counter.* += 1;
    }
};

test "many joins all run both sides" {
    // commonware `join_counter_overflow`: 500,000 joins on a 2-thread pool.
    const pool = try create_pool(1);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var i: u32 = 0;
    var j: u32 = 0;
    const joins = 500_000;
    for (0..joins) |_| _ = rayon.join(Increment{ .counter = &i }, Increment{ .counter = &j });
    try testing.expectEqual(@as(u32, joins), i);
    try testing.expectEqual(@as(u32, joins), j);
}

fn now_ns() u64 {
    return @intCast(std.Io.Clock.awake.now(testing.io).nanoseconds);
}

/// Busy-waits `ns` nanoseconds (commonware's `clock.spin`).
const Spin = struct {
    ns: u64,
    pub fn call(spin: Spin) void {
        const start = now_ns();
        while (now_ns() - start < spin.ns) std.atomic.spinLoopHint();
    }
};

/// The metered busy time is at least `expected_ns` and short of `expected_ns + slack_ns`.
fn expect_busy(busy: *const std.atomic.Value(u64), expected_ns: u64, slack_ns: u64) !void {
    const value = busy.load(.acquire);
    try testing.expect(value >= expected_ns);
    try testing.expect(value < expected_ns + slack_ns);
}

/// Runs `a.call()` and `b.call()` as `join` does, on `rayon.execute` with `busy` as its
/// meter (the meter a measured adaptive join installs).
fn metered_join(rayon: Rayon, busy: *std.atomic.Value(u64), a: anytype, b: anytype) void {
    const Sides = struct {
        a: @TypeOf(a),
        b: @TypeOf(b),
        fn body(sides: *const @This(), index: usize) void {
            if (index == 0) sides.a.call() else sides.b.call();
        }
    };
    var metered = rayon;
    metered.meter = busy;
    const sides: Sides = .{ .a = a, .b = b };
    metered.execute(2, &sides, Sides.body);
}

test "a metered join charges both sides" {
    // commonware `inline_joins_charge_both_sides`: 5 ms and 40 ms charge 45 ms.
    const pool = try create_pool(0);
    defer pool.destroy();
    var busy: std.atomic.Value(u64) = .init(0);
    const rayon = Rayon.init(pool).with_parallelism(2);
    metered_join(rayon, &busy, Spin{ .ns = 5 * ms }, Spin{ .ns = 40 * ms });
    try expect_busy(&busy, 45 * ms, 20 * ms);
}

/// Spins until the other side of the join has started, so the joiner waits on it.
const AwaitStolen = struct {
    stolen: *std.atomic.Value(bool),
    pub fn call(side: AwaitStolen) void {
        const start = now_ns();
        while (!side.stolen.load(.acquire)) {
            std.debug.assert(now_ns() - start < 10 * std.time.ns_per_s);
            std.atomic.spinLoopHint();
        }
    }
};

const Stolen = struct {
    stolen: *std.atomic.Value(bool),
    pub fn call(side: Stolen) void {
        side.stolen.store(true, .release);
        Spin.call(.{ .ns = 40 * ms });
    }
};

test "a metered join charges the stolen side but not the wait" {
    // commonware `joins_charge_the_stolen_side_but_not_the_wait`: the joiner waits out the
    // other side's 40 ms, which is charged once.
    const pool = try create_pool(1);
    defer pool.destroy();
    var busy: std.atomic.Value(u64) = .init(0);
    var stolen: std.atomic.Value(bool) = .init(false);
    const rayon = Rayon.init(pool);
    metered_join(rayon, &busy, AwaitStolen{ .stolen = &stolen }, Stolen{ .stolen = &stolen });
    try expect_busy(&busy, 40 * ms, 30 * ms);
}

test "a spawned job charges nothing to the meter" {
    // commonware `spawned_jobs_charge_nothing`.
    const pool = try create_pool(1);
    defer pool.destroy();
    var busy: std.atomic.Value(u64) = .init(0);
    var rayon = Rayon.init(pool);
    rayon.meter = &busy;
    var task: parallel.Task(Spin) = .init(.{ .ns = 20 * ms });
    rayon.spawn(1, &task);
    rayon.block_on(&task);
    try testing.expectEqual(@as(u64, 0), busy.load(.acquire));
}

const Pair = struct { key: u32, position: u32 };

fn pair_less(_: void, a: Pair, b: Pair) bool {
    return a.key < b.key;
}

test "parallel sorts handle presorted and reversed runs" {
    // commonware `sorts_presorted_runs`: ascending, descending, and descending 2,000-item
    // chunks, and a stable sort of descending keys with ties.
    const pool = try create_pool(3);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    const len: u32 = 10_000;
    const data = try gpa.alloc(u32, len);
    defer gpa.free(data);
    for (0..3) |shape| {
        for (data, 0..) |*value, position| {
            const i: u32 = @intCast(position);
            value.* = switch (shape) {
                0 => i,
                1 => len - 1 - i,
                else => (i / 2000) * 2000 + (1999 - i % 2000),
            };
        }
        rayon.sort_by(u32, data, {}, std.sort.asc(u32));
        for (data, 0..) |value, index| try testing.expectEqual(@as(u32, @intCast(index)), value);
    }
    const pairs = try gpa.alloc(Pair, len);
    defer gpa.free(pairs);
    for (pairs, 0..) |*pair, i| {
        const position: u32 = @intCast(i);
        pair.* = .{ .key = (len - position) / 2, .position = position };
    }
    const expected = try gpa.dupe(Pair, pairs);
    defer gpa.free(expected);
    std.sort.block(Pair, expected, {}, pair_less);
    rayon.sort_by(Pair, pairs, {}, pair_less);
    try testing.expectEqualSlices(Pair, expected, pairs);
}

test "parallel unstable sorts handle presorted, reversed, and equal inputs" {
    // commonware `quicksorts_presorted_reversed_and_equal_inputs`.
    const pool = try create_pool(3);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var rng = utils.TestRng.init(0);
    const data = try gpa.alloc(u32, 50_000);
    defer gpa.free(data);
    const expected = try gpa.alloc(u32, 50_000);
    defer gpa.free(expected);
    for ([_]usize{ 20, 21, 50, 51, 2_001, 4_002, 50_000 }) |len| {
        for (0..4) |shape| {
            const input = data[0..len];
            for (input, 0..) |*value, i| value.* = switch (shape) {
                0 => @intCast(i),
                1, 3 => @intCast(len - 1 - i),
                else => 7,
            };
            if (shape == 3) for (0..5) |_| {
                const a = utils.rng.range_less_than(&rng, usize, 0, len);
                const b = utils.rng.range_less_than(&rng, usize, 0, len);
                if (a < b) {
                    std.mem.reverse(u32, input[a..b]);
                } else {
                    std.mem.swap(u32, &input[a], &input[b]);
                }
            };
            @memcpy(expected[0..len], input);
            std.sort.pdq(u32, expected[0..len], {}, std.sort.asc(u32));
            rayon.sort_unstable_by(u32, input, {}, std.sort.asc(u32));
            try testing.expectEqualSlices(u32, expected[0..len], input);
        }
    }
}

fn never_compared(_: void, _: void, _: void) bool {
    @panic("zero-sized values must not be compared");
}

test "parallel sorts never compare zero-sized values" {
    // commonware `sorts_zero_sized_values` and `quicksorts_zero_sized_values`.
    const pool = try create_pool(3);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var values: [5000]void = @splat({});
    rayon.sort_by(void, &values, {}, never_compared);
    rayon.sort_unstable_by(void, &values, {}, never_compared);
    var empty: [0]u64 = .{};
    rayon.sort_unstable_by(u64, &empty, {}, std.sort.asc(u64));
    var one = [_]u64{0xDEAD_BEEF};
    rayon.sort_unstable_by(u64, &one, {}, std.sort.asc(u64));
    try testing.expectEqual(@as(u64, 0xDEAD_BEEF), one[0]);
}

fn random_less(rng: *utils.TestRng, _: usize, _: usize) bool {
    return rng.next_u32() & 1 == 1;
}

test "an inconsistent comparator still permutes the slice" {
    // commonware `an_inconsistent_comparator_still_permutes_the_slice`.
    const pool = try create_pool(3);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var values: [100]usize = undefined;
    for (&values, 0..) |*value, index| value.* = index;
    var rng = utils.TestRng.init(0);
    rayon.sort_unstable_by(usize, &values, &rng, random_less);
    rayon.sort_unstable_by(usize, &values, {}, std.sort.asc(usize));
    for (values, 0..) |value, index| try testing.expectEqual(index, value);
}

const SpawnInJob = struct {
    rayon: Rayon,
    task: *parallel.Task(Seven),
    pub fn call(job: SpawnInJob) void {
        job.rayon.spawn(1, job.task);
    }
};

const Seven = struct {
    pub fn call(_: Seven) u32 {
        return 22;
    }
};

test "a job spawns another that runs to completion" {
    // commonware `spawn_then_join_in_worker`: a spawn from inside a pool job.
    const pool = try create_pool(3);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var task: parallel.Task(Seven) = .init(.{});
    const Noop = struct {
        pub fn call(_: @This()) void {}
    };
    _ = rayon.join(SpawnInJob{ .rayon = rayon, .task = &task }, Noop{});
    try testing.expectEqual(@as(u32, 22), rayon.block_on(&task));
}

test "a pool reports its configured thread count" {
    // commonware `check_config_build`: 22 threads. The strategy plans with the caller too.
    const pool = try create_pool(22);
    defer pool.destroy();
    try testing.expectEqual(@as(u32, 22), pool.threads);
    try testing.expectEqual(@as(usize, 23), Rayon.init(pool).parallelism());
}
