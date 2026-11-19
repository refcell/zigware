//! Fold and map property checks over one input plan, ported from commonware's
//! `parallel/src/fold_plan.rs` and `fuzz.rs` (commonware #5774): the eight checks of the former
//! proptests run on its three regression inputs, then on seeded and coverage-guided fuzz input
//! (`test_fuzz_plan` and the `parallel` fuzz target). A plan is a list of `i32`, and the fuzz
//! body reads it as little-endian words, as commonware's `Plan::arbitrary` does.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const parallel = @import("root.zig");

const Range = parallel.Range;
const Rayon = parallel.Rayon;
const ThreadPool = parallel.ThreadPool;
const sequential = parallel.sequential;
const gpa = testing.allocator;
const List = std.ArrayList(i32);

fn concat(a: List, b: List) List {
    var left = a;
    var right = b;
    defer right.deinit(gpa);
    left.appendSlice(gpa, right.items) catch @panic("out of memory");
    return left;
}

fn push(acc: List, x: i32) List {
    var list = acc;
    list.append(gpa, x) catch @panic("out of memory");
    return list;
}

/// Collects `x * factor` with `fold_init` and a stateless init.
const CollectInit = struct {
    factor: i32,
    pub fn init(_: CollectInit) void {}
    pub fn identity(_: CollectInit) List {
        return .empty;
    }
    pub fn fold(op: CollectInit, acc: List, _: *void, x: *const i32) List {
        return push(acc, x.* *% op.factor);
    }
    pub fn reduce(_: CollectInit, a: List, b: List) List {
        return concat(a, b);
    }
};

/// Collects `x * factor` with `fold`.
const Collect = struct {
    factor: i32,
    pub fn identity(_: Collect) List {
        return .empty;
    }
    pub fn fold(op: Collect, acc: List, x: *const i32) List {
        return push(acc, x.* *% op.factor);
    }
    pub fn reduce(_: Collect, a: List, b: List) List {
        return concat(a, b);
    }
};

const WrappingSum = struct {
    pub fn identity(_: WrappingSum) i32 {
        return 0;
    }
    pub fn fold(_: WrappingSum, acc: i32, x: *const i32) error{Never}!i32 {
        return acc +% x.*;
    }
    pub fn reduce(_: WrappingSum, a: i32, b: i32) i32 {
        return a +% b;
    }
};

const Times = struct {
    factor: i32,
    pub fn map(times: Times, x: *const i32) i32 {
        return x.* *% times.factor;
    }
};

const TryTimes = struct {
    factor: i32,
    pub fn map(times: TryTimes, x: *const i32) error{Never}!i32 {
        return x.* *% times.factor;
    }
};

fn expect_lists(a: List, b: List) !void {
    var left = a;
    var right = b;
    defer left.deinit(gpa);
    defer right.deinit(gpa);
    try testing.expectEqualSlices(i32, left.items, right.items);
}

/// `parallel_fold_init_matches_sequential`, `fold_equals_fold_init`,
/// `parallel_try_fold_matches_sequential`, and `map_collect_vec_equals_fold`.
fn check_folds(rayon: Rayon, data: []const i32) !void {
    const doubled: CollectInit = .{ .factor = 2 };
    try expect_lists(sequential.fold_init(data, doubled), rayon.fold_init(data, doubled));
    const plain: CollectInit = .{ .factor = 1 };
    const via_fold = sequential.fold(data, Collect{ .factor = 1 });
    try expect_lists(via_fold, sequential.fold_init(data, plain));
    const serial_sum = try sequential.try_fold(data, WrappingSum{});
    try testing.expectEqual(serial_sum, try rayon.try_fold(data, WrappingSum{}));
    const mapped = try sequential.map_collect(gpa, data, Times{ .factor = 3 });
    defer gpa.free(mapped);
    var folded = sequential.fold(data, Collect{ .factor = 3 });
    defer folded.deinit(gpa);
    try testing.expectEqualSlices(i32, folded.items, mapped);
}

/// Fails at the first multiple of seven, recording its position.
const Sevens = struct {
    data: []const i32,
    failed_at: *?usize,
    pub fn map(sevens: Sevens, index: usize) error{Seven}!i32 {
        if (@rem(sevens.data[index], 7) == 0) {
            sevens.failed_at.* = index;
            return error.Seven;
        }
        return sevens.data[index];
    }
};

/// `try_map_collect_vec_collects_successes` and `try_map_collect_vec_returns_first_error`.
fn check_try_maps(rayon: Rayon, data: []const i32) !void {
    const times: TryTimes = .{ .factor = 5 };
    const serial = try sequential.try_map_collect(gpa, data, times);
    defer gpa.free(serial);
    const par = try rayon.try_map_collect(gpa, data, times);
    defer gpa.free(par);
    try testing.expectEqual(data.len, serial.len);
    for (data, serial, par) |x, s, p| {
        try testing.expectEqual(x *% 5, s);
        try testing.expectEqual(x *% 5, p);
    }
    const expected: ?usize = for (data, 0..) |x, index| {
        if (@rem(x, 7) == 0) break index;
    } else null;
    var failed_at: ?usize = null;
    const op: Sevens = .{ .data = data, .failed_at = &failed_at };
    if (sequential.try_map_collect(gpa, Range.upto(data.len), op)) |values| {
        defer gpa.free(values);
        try testing.expectEqual(@as(?usize, null), expected);
        try testing.expectEqualSlices(i32, data, values);
    } else |err| {
        try testing.expectEqual(error.Seven, err);
        try testing.expectEqual(expected, failed_at);
    }
}

/// Adds a per-state call counter to each item.
const Counted = struct {
    pub fn init(_: Counted) i32 {
        return 0;
    }
    pub fn map(_: Counted, counter: *i32, x: *const i32) i32 {
        counter.* += 1;
        return x.* +% counter.*;
    }
};

const CountedFold = struct {
    pub fn init(_: CountedFold) i32 {
        return 0;
    }
    pub fn identity(_: CountedFold) List {
        return .empty;
    }
    pub fn fold(_: CountedFold, acc: List, counter: *i32, x: *const i32) List {
        counter.* += 1;
        return push(acc, x.* +% counter.*);
    }
    pub fn reduce(_: CountedFold, a: List, b: List) List {
        return concat(a, b);
    }
};

const Partition = struct {
    pub fn map(_: Partition, x: *const i32) struct { i32, ?i32 } {
        return .{ x.*, if (@rem(x.*, 2) == 0) x.* *% 2 else null };
    }
};

/// `map_init_collect_vec_equals_fold_init` and
/// `map_partition_collect_vec_returns_valid_results`.
fn check_init_and_partition(data: []const i32) !void {
    const via_map = try sequential.map_init_collect(gpa, data, Counted{});
    defer gpa.free(via_map);
    var via_fold = sequential.fold_init(data, CountedFold{});
    defer via_fold.deinit(gpa);
    try testing.expectEqualSlices(i32, via_fold.items, via_map);
    const split = try sequential.map_partition_collect(gpa, data, Partition{});
    defer split.deinit(gpa);
    var results: usize = 0;
    var filtered: usize = 0;
    for (data) |x| {
        if (@rem(x, 2) == 0) {
            try testing.expectEqual(x *% 2, split.results[results]);
            results += 1;
        } else {
            try testing.expectEqual(x, split.filtered[filtered]);
            filtered += 1;
        }
    }
    try testing.expectEqual(split.results.len, results);
    try testing.expectEqual(split.filtered.len, filtered);
}

/// Every check of commonware's `Plan::run` on `data`.
fn check_plan(rayon: Rayon, data: []const i32) !void {
    try check_folds(rayon, data);
    try check_try_maps(rayon, data);
    try check_init_and_partition(data);
}

/// A pool of four threads: three workers and the caller (commonware `parallel_strategy`).
fn create_pool() !*ThreadPool {
    return ThreadPool.create(gpa, testing.io, .{ .threads = 3 });
}

test "fold plan checks pass on the regression inputs" {
    // commonware `Plan::regressions`: empty and large inputs, and wrapping arithmetic.
    const pool = try create_pool();
    defer pool.destroy();
    var counting: [499]i32 = undefined;
    for (&counting, 1..) |*x, value| x.* = @intCast(value);
    const plans = [_][]const i32{
        &.{},
        &.{ std.math.maxInt(i32), std.math.maxInt(i32), std.math.minInt(i32) },
        &counting,
    };
    for (plans) |plan| try check_plan(Rayon.init(pool), plan);
}

/// Words a fuzz plan holds at most: the fuzz driver's largest input.
const plan_words_max = utils.fuzz.input_size_max / 4;

fn fuzz_plan(pool: *ThreadPool, rng: *utils.rng.FuzzRng) anyerror!void {
    const words = utils.rng.range_at_most(rng, usize, 0, plan_words_max);
    var bytes: [plan_words_max * 4]u8 = undefined;
    rng.fill_bytes(bytes[0 .. words * 4]);
    var data: [plan_words_max]i32 = undefined;
    for (data[0..words], 0..) |*x, index| {
        x.* = std.mem.readInt(i32, bytes[index * 4 ..][0..4], .little);
    }
    try check_plan(Rayon.init(pool), data[0..words]);
}

test "fuzz: fold plan checks hold on every plan" {
    // commonware `test_fuzz_plan` and the `parallel` fuzz target.
    const pool = try create_pool();
    defer pool.destroy();
    try utils.fuzz.run(pool, fuzz_plan, 0x666f_6c64, 256);
}
