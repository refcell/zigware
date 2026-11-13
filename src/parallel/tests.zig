//! Tests of the strategy interface, ported from commonware's `parallel/src/lib.rs` (doc
//! examples, the proptests as seeded randomized tests over `TestRng`, and the unit tests that
//! need no adaptive policy), plus checks that results do not depend on the pool size.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const parallel = @import("root.zig");

const Range = parallel.Range;
const Rayon = parallel.Rayon;
const ThreadPool = parallel.ThreadPool;
const sequential = parallel.sequential;

fn create_pool(threads: u32) !*ThreadPool {
    return ThreadPool.create(testing.allocator, testing.io, .{ .threads = threads });
}

/// Random `i32` data of 0 to 499 items, like the proptests' `vec(any::<i32>(), 0..500)`.
fn random_data(rng: *utils.TestRng, buffer: *[500]i32) []i32 {
    const len = utils.rng.range_less_than(rng, usize, 0, buffer.len);
    for (buffer[0..len]) |*value| value.* = @bitCast(rng.next_u32());
    return buffer[0..len];
}

const SumSquares = struct {
    pub fn identity(_: SumSquares) i64 {
        return 0;
    }
    pub fn fold(_: SumSquares, acc: i64, x: *const i64) i64 {
        return acc + x.* * x.*;
    }
    pub fn reduce(_: SumSquares, a: i64, b: i64) i64 {
        return a + b;
    }
};

test "doc: sum of squares, fold, map, join, sort" {
    const data = [_]i64{ 1, 2, 3, 4, 5 };
    try testing.expectEqual(@as(i64, 55), sequential.fold(@as([]const i64, &data), SumSquares{}));

    const Square = struct {
        pub fn map(_: @This(), x: *const i64) i64 {
            return x.* * x.*;
        }
    };
    const squared = try sequential.map_collect(testing.allocator, &data, Square{});
    defer testing.allocator.free(squared);
    try testing.expectEqualSlices(i64, &.{ 1, 4, 9, 16, 25 }, squared);

    const Sum = struct {
        pub fn call(_: @This()) i32 {
            var sum: i32 = 0;
            for (1..6) |x| sum += @intCast(x);
            return sum;
        }
    };
    const Product = struct {
        pub fn call(_: @This()) i32 {
            var product: i32 = 1;
            for (1..6) |x| product *= @intCast(x);
            return product;
        }
    };
    const sum, const product = sequential.join(Sum{}, Product{});
    try testing.expectEqual(@as(i32, 15), sum);
    try testing.expectEqual(@as(i32, 120), product);

    var unsorted = [_]i32{ 3, 1, 2 };
    sequential.sort_by(i32, &unsorted, {}, std.sort.asc(i32));
    try testing.expectEqualSlices(i32, &.{ 1, 2, 3 }, &unsorted);

    const pool = try create_pool(1);
    defer pool.destroy();
    var thousand: [1000]i64 = undefined;
    for (&thousand, 0..) |*value, index| value.* = @intCast(index);
    const Sum64 = struct {
        pub fn identity(_: @This()) i64 {
            return 0;
        }
        pub fn fold(_: @This(), acc: i64, x: *const i64) i64 {
            return acc + x.*;
        }
        pub fn reduce(_: @This(), a: i64, b: i64) i64 {
            return a + b;
        }
    };
    const total = Rayon.init(pool).fold(@as([]const i64, &thousand), Sum64{});
    try testing.expectEqual(@as(i64, 499_500), total);
}

test "doc: map_init indexes within the partition, map_partition splits evens" {
    const data = [_]i32{ 1, 2, 3, 4, 5 };
    const Indexed = struct {
        pub fn init(_: @This()) usize {
            return 0;
        }
        pub fn map(_: @This(), counter: *usize, x: *const i32) struct { usize, i32 } {
            const index = counter.*;
            counter.* += 1;
            return .{ index, x.* * 2 };
        }
    };
    const indexed = try sequential.map_init_collect(testing.allocator, &data, Indexed{});
    defer testing.allocator.free(indexed);
    for (indexed, 0..) |pair, index| {
        try testing.expectEqual(index, pair[0]);
        try testing.expectEqual(data[index] * 2, pair[1]);
    }

    const Evens = struct {
        pub fn map(_: @This(), x: *const i32) struct { i32, ?i32 } {
            return .{ x.*, if (@mod(x.*, 2) == 0) x.* * 10 else null };
        }
    };
    const split = try sequential.map_partition_collect(testing.allocator, &data, Evens{});
    defer split.deinit(testing.allocator);
    try testing.expectEqualSlices(i32, &.{ 20, 40 }, split.results);
    try testing.expectEqualSlices(i32, &.{ 1, 3, 5 }, split.filtered);
}

/// Collects `2x` into a list per chunk and concatenates chunks: the order-sensitive fold of the
/// proptests (`acc.push(x * 2); a.extend(b)`).
const Doubles = struct {
    const List = std.ArrayList(i32);

    pub fn init(_: Doubles) void {}
    pub fn identity(_: Doubles) List {
        return .empty;
    }
    pub fn fold(_: Doubles, acc: List, _: *void, x: *const i32) List {
        var list = acc;
        list.append(testing.allocator, x.* *% 2) catch @panic("out of memory");
        return list;
    }
    pub fn reduce(_: Doubles, a: List, b: List) List {
        var left = a;
        var right = b;
        left.appendSlice(testing.allocator, right.items) catch @panic("out of memory");
        right.deinit(testing.allocator);
        return left;
    }
};

test "parallel fold_init matches sequential" {
    const pool = try create_pool(3);
    defer pool.destroy();
    var rng = utils.TestRng.init(0);
    var buffer: [500]i32 = undefined;
    for (0..64) |_| {
        const data: []const i32 = random_data(&rng, &buffer);
        var serial = sequential.fold_init(data, Doubles{});
        defer serial.deinit(testing.allocator);
        var par = Rayon.init(pool).fold_init(data, Doubles{});
        defer par.deinit(testing.allocator);
        try testing.expectEqualSlices(i32, serial.items, par.items);
        try testing.expectEqual(data.len, serial.items.len);
    }
}

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

test "parallel try_fold and map_collect match sequential" {
    const pool = try create_pool(3);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var rng = utils.TestRng.init(1);
    var buffer: [500]i32 = undefined;
    for (0..64) |_| {
        const data: []const i32 = random_data(&rng, &buffer);
        const serial_sum = try sequential.try_fold(data, WrappingSum{});
        try testing.expectEqual(serial_sum, try rayon.try_fold(data, WrappingSum{}));

        const serial = try sequential.map_collect(testing.allocator, data, Times{ .factor = 3 });
        defer testing.allocator.free(serial);
        const par = try rayon.map_collect(testing.allocator, data, Times{ .factor = 3 });
        defer testing.allocator.free(par);
        try testing.expectEqualSlices(i32, serial, par);

        const times: TryTimes = .{ .factor = 5 };
        const fallible = try rayon.try_map_collect(testing.allocator, data, times);
        defer testing.allocator.free(fallible);
        for (data, fallible) |x, y| try testing.expectEqual(x *% 5, y);
    }
}

test "try_map_collect returns the first error and short-circuits sequentially" {
    const FailAt = struct {
        calls: *usize,
        pub fn map(fail: @This(), index: usize) error{Failed}!usize {
            fail.calls.* += 1;
            if (index == 3) return error.Failed;
            return index;
        }
    };
    var calls: usize = 0;
    const result = sequential.try_map_collect(testing.allocator, Range.upto(10), FailAt{
        .calls = &calls,
    });
    try testing.expectError(error.Failed, result);
    try testing.expectEqual(@as(usize, 4), calls);

    // The proptest: the first multiple of seven fails, at its position.
    var rng = utils.TestRng.init(2);
    var buffer: [500]i32 = undefined;
    for (0..64) |_| {
        const data: []const i32 = random_data(&rng, &buffer);
        const Sevens = struct {
            data: []const i32,
            pub fn map(sevens: @This(), index: usize) error{Seven}!i32 {
                if (@rem(sevens.data[index], 7) == 0) return error.Seven;
                return sevens.data[index];
            }
        };
        const op: Sevens = .{ .data = data };
        const expected = for (data) |x| {
            if (@rem(x, 7) == 0) break true;
        } else false;
        const mapped = sequential.try_map_collect(testing.allocator, Range.upto(data.len), op);
        if (expected) {
            try testing.expectError(error.Seven, mapped);
        } else {
            const values = try mapped;
            defer testing.allocator.free(values);
            try testing.expectEqualSlices(i32, data, values);
        }
    }
}

test "parallel try_map_collect returns an error and discards written outputs" {
    const pool = try create_pool(3);
    defer pool.destroy();
    const Fail = struct {
        discarded: *std.atomic.Value(usize),
        pub fn map(_: @This(), index: usize) error{ Seventeen, FortyTwo }!usize {
            if (index == 17) return error.Seventeen;
            if (index == 42) return error.FortyTwo;
            return index;
        }
        pub fn discard(fail: @This(), _: usize) void {
            _ = fail.discarded.fetchAdd(1, .monotonic);
        }
    };
    var discarded: std.atomic.Value(usize) = .init(0);
    const result = Rayon.init(pool).try_map_collect(testing.allocator, Range.upto(128), Fail{
        .discarded = &discarded,
    });
    if (result) |values| {
        testing.allocator.free(values);
        return error.TestExpectedError;
    } else |err| switch (err) {
        error.Seventeen, error.FortyTwo => {},
        error.OutOfMemory => return err,
    }
    try testing.expect(discarded.load(.monotonic) < 128);
}

test "map_partition_collect keeps evens and filters odds in order" {
    const pool = try create_pool(2);
    defer pool.destroy();
    var rng = utils.TestRng.init(3);
    var buffer: [500]i32 = undefined;
    const Partition = struct {
        pub fn map(_: @This(), x: *const i32) struct { i32, ?i32 } {
            return .{ x.*, if (@rem(x.*, 2) == 0) x.* *% 2 else null };
        }
    };
    for (0..32) |_| {
        const data: []const i32 = random_data(&rng, &buffer);
        const rayon = Rayon.init(pool);
        const split = try rayon.map_partition_collect(testing.allocator, data, Partition{});
        defer split.deinit(testing.allocator);
        var result_index: usize = 0;
        var filtered_index: usize = 0;
        for (data) |x| {
            if (@rem(x, 2) == 0) {
                try testing.expectEqual(x *% 2, split.results[result_index]);
                result_index += 1;
            } else {
                try testing.expectEqual(x, split.filtered[filtered_index]);
                filtered_index += 1;
            }
        }
        try testing.expectEqual(split.results.len, result_index);
        try testing.expectEqual(split.filtered.len, filtered_index);
    }
}

/// A non-associative fold: the result depends on exactly how the input is chunked.
const Chained = struct {
    pub fn identity(_: Chained) u64 {
        return 0x9e37_79b9_7f4a_7c15;
    }
    pub fn fold(_: Chained, acc: u64, index: usize) u64 {
        return utils.rng.mix64(acc ^ index);
    }
    pub fn reduce(_: Chained, a: u64, b: u64) u64 {
        return utils.rng.mix64(a *% 31 +% b);
    }
};

test "fold results do not depend on the pool size" {
    var expected: [5]u64 = undefined;
    const lens = [_]usize{ 2, 63, 64, 65, 10_000 };
    for ([_]u32{ 1, 2, 3, 7 }, 0..) |threads, run_index| {
        const pool = try create_pool(threads);
        defer pool.destroy();
        for (lens, 0..) |len, index| {
            const result = Rayon.init(pool).fold(Range.upto(len), Chained{});
            if (run_index == 0) expected[index] = result;
            try testing.expectEqual(expected[index], result);
        }
    }
    // A strategy without parallelism folds in one chunk, like `Sequential`.
    const pool = try create_pool(0);
    defer pool.destroy();
    const serial = Rayon.init(pool).fold(Range.upto(10_000), Chained{});
    try testing.expectEqual(sequential.fold(Range.upto(10_000), Chained{}), serial);
}

test "nested parallel folds inside jobs complete" {
    const pool = try create_pool(3);
    defer pool.destroy();
    const Inner = struct {
        rayon: Rayon,
        pub fn identity(_: @This()) u64 {
            return 0;
        }
        pub fn fold(inner: @This(), acc: u64, index: usize) u64 {
            const Count = struct {
                pub fn identity(_: @This()) u64 {
                    return 0;
                }
                pub fn fold(_: @This(), sum: u64, value: usize) u64 {
                    return sum + value;
                }
                pub fn reduce(_: @This(), a: u64, b: u64) u64 {
                    return a + b;
                }
            };
            return acc + inner.rayon.fold(Range.upto(index), Count{});
        }
        pub fn reduce(_: @This(), a: u64, b: u64) u64 {
            return a + b;
        }
    };
    const rayon = Rayon.init(pool);
    const total = rayon.fold(Range.upto(200), Inner{ .rayon = rayon });
    // sum over i < 200 of i(i-1)/2 = C(200, 3).
    try testing.expectEqual(@as(u64, 1_313_400), total);
}

test "sequential run uses the serial body; parallel strategies the parallel one" {
    const Body = struct {
        pub fn serial(_: @This()) u8 {
            return 's';
        }
        pub fn parallel(_: @This()) u8 {
            return 'p';
        }
    };
    try testing.expectEqual(@as(u8, 's'), sequential.run(16, Body{}));
    const pool = try create_pool(2);
    defer pool.destroy();
    try testing.expectEqual(@as(u8, 'p'), Rayon.init(pool).run(16, Body{}));
    try testing.expectEqual(@as(u8, 's'), Rayon.init(pool).with_parallelism(1).run(16, Body{}));
}

const RangeOf = struct {
    pub fn map(_: RangeOf, _: usize, range: Range) Range {
        return range;
    }
};

fn check_whole(strategy: anytype, len: usize, minimum: usize) !void {
    const Run = struct {
        pub fn run(_: @This(), batches: anytype) anyerror!Range {
            try testing.expect(batches.is_whole());
            var out: [1]Range = undefined;
            batches.map_collect(&out, RangeOf{});
            return out[0];
        }
    };
    const range = try strategy.run_batches(len, minimum, std.math.maxInt(usize), Run{});
    try testing.expect(range.eql(Range.upto(len)));
}

test "run_batches preserves the whole input without splitting" {
    const one = try create_pool(0);
    defer one.destroy();
    const pool = try create_pool(3);
    defer pool.destroy();
    for ([_]usize{ 0, 1, 7, 8, 15 }) |len| {
        try check_whole(sequential, len, 8);
        try check_whole(Rayon.init(one), len, 8);
        try check_whole(Rayon.init(pool).with_parallelism(4), len, 8);
    }
    try check_whole(sequential, std.math.maxInt(usize), 1);
    try check_whole(Rayon.init(one), std.math.maxInt(usize), 1);
    try check_whole(Rayon.init(pool), std.math.maxInt(usize), std.math.maxInt(usize));
}

test "run_batches supplies ordered balanced ranges" {
    const pool = try create_pool(0);
    defer pool.destroy();
    const rayon = Rayon.init(pool).with_parallelism(8);
    const max = std.math.maxInt(usize);
    const cases = [_][2]usize{
        .{ 2, 1 },  .{ 7, 1 },  .{ 8, 1 },  .{ 9, 1 },   .{ 17, 1 },
        .{ 15, 7 }, .{ 16, 8 }, .{ 17, 8 }, .{ max, 1 }, .{ max, max / 2 },
    };
    for (cases) |case| {
        const len, const minimum = case;
        const Run = struct {
            pub fn run(_: @This(), batches: anytype) anyerror![parallel.max_chunks]Range {
                try testing.expect(!batches.is_whole());
                var out: [parallel.max_chunks]Range = undefined;
                batches.map_collect(out[0..batches.count()], RangeOf{});
                return out;
            }
        };
        const ranges_all = try rayon.run_batches(len, minimum, max, Run{});
        const count = @min(8, len / minimum);
        const ranges = ranges_all[0..count];
        try testing.expectEqual(@as(usize, 0), ranges[0].start);
        try testing.expectEqual(len, ranges[count - 1].end);
        var shortest: usize = max;
        var longest: usize = 0;
        for (ranges, 0..) |range, index| {
            if (index > 0) try testing.expectEqual(ranges[index - 1].end, range.start);
            try testing.expect(range.len() >= minimum);
            shortest = @min(shortest, range.len());
            longest = @max(longest, range.len());
        }
        try testing.expect(longest - shortest <= 1);
    }
}

test "run_batches prepares borrowed outputs once and fills them in parallel" {
    const pool = try create_pool(3);
    defer pool.destroy();
    var input: [17]u32 = undefined;
    for (&input, 0..) |*value, index| value.* = @intCast(index * 3);
    var output: [17]u32 = @splat(0);
    const Copy = struct {
        input: []const u32,
        output: []u32,
        pub fn map(copy: @This(), _: usize, range: Range) Range {
            @memcpy(copy.output[range.start..range.end], copy.input[range.start..range.end]);
            return range;
        }
    };
    const Run = struct {
        copy: Copy,
        pub fn run(run_op: @This(), batches: anytype) usize {
            var out: [parallel.max_chunks]Range = undefined;
            batches.map_collect(out[0..batches.count()], run_op.copy);
            return batches.count();
        }
    };
    const copy: Copy = .{ .input = &input, .output = &output };
    const count = Rayon.init(pool).run_batches(input.len, 1, 1, Run{ .copy = copy });
    try testing.expectEqual(@as(usize, 4), count);
    try testing.expectEqualSlices(u32, &input, &output);
}

test "try_run_batches returns a batch error" {
    const pool = try create_pool(3);
    defer pool.destroy();
    const Fail = struct {
        pub fn map(_: @This(), index: usize, range: Range) error{Batch}!usize {
            if (index == 2) return error.Batch;
            return range.len();
        }
    };
    const Run = struct {
        pub fn run(_: @This(), batches: anytype) error{Batch}!usize {
            var out: [parallel.max_chunks]usize = undefined;
            try batches.try_map_collect(out[0..batches.count()], Fail{});
            return 0;
        }
    };
    try testing.expectError(error.Batch, Rayon.init(pool).try_run_batches(16, 1, 1, Run{}));
}

const Keyed = struct {
    key: u16,
    position: u32,

    pub fn less(_: void, a: Keyed, b: Keyed) bool {
        return a.key < b.key;
    }
};

test "parallel sorts match serial sorts and stay stable" {
    const pool = try create_pool(3);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var rng = utils.TestRng.init(4);
    const items = try testing.allocator.alloc(Keyed, 5_000);
    defer testing.allocator.free(items);
    const expected = try testing.allocator.alloc(Keyed, 5_000);
    defer testing.allocator.free(expected);
    for ([_]usize{ 0, 1, 255, 512, 513, 1_000, 5_000 }) |len| {
        for (items[0..len], 0..) |*item, index| item.* = .{
            .key = @truncate(rng.next_u32() % 97),
            .position = @intCast(index),
        };
        @memcpy(expected[0..len], items[0..len]);
        std.sort.block(Keyed, expected[0..len], {}, Keyed.less);
        rayon.sort_by(Keyed, items[0..len], {}, Keyed.less);
        try testing.expectEqualSlices(Keyed, expected[0..len], items[0..len]);

        rayon.sort_unstable_by(Keyed, items[0..len], {}, Keyed.less);
        for (items[0..len], expected[0..len]) |item, sorted| {
            try testing.expectEqual(sorted.key, item.key);
        }
    }
}

const Seven = struct {
    pub fn call(_: Seven) u32 {
        return 7;
    }
};

test "sequential spawn runs the job inline and block_on returns it" {
    var task: parallel.Task(Seven) = .init(.{});
    sequential.spawn(1, &task);
    try testing.expect(task.is_done());
    try testing.expectEqual(@as(u32, 7), sequential.block_on(&task));
}

test "rayon spawn runs the job on a pool worker" {
    const pool = try create_pool(2);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var task: parallel.Task(Seven) = .init(.{});
    rayon.spawn(1, &task);
    // Only a worker can finish the job before `block_on`.
    var spins: u64 = 0;
    while (!task.is_done()) : (spins += 1) {
        try testing.expect(spins < 200_000_000);
        std.Thread.yield() catch {};
    }
    try testing.expectEqual(@as(u32, 7), rayon.block_on(&task));
}

test "rayon spawn runs inline without parallelism" {
    const pool = try create_pool(0);
    defer pool.destroy();
    const rayon = Rayon.init(pool).with_parallelism(4);
    var task: parallel.Task(Seven) = .init(.{});
    rayon.spawn(1, &task);
    try testing.expect(task.is_done());
    try testing.expectEqual(@as(u32, 7), rayon.block_on(&task));
}

/// Folds `0..n` on the strategy it captures, from inside a spawned job.
const SpawnedFold = struct {
    rayon: Rayon,
    n: usize,

    pub fn call(spawned: SpawnedFold) u64 {
        const Sum = struct {
            pub fn identity(_: @This()) u64 {
                return 0;
            }
            pub fn fold(_: @This(), acc: u64, index: usize) u64 {
                return acc + index;
            }
            pub fn reduce(_: @This(), a: u64, b: u64) u64 {
                return a + b;
            }
        };
        return spawned.rayon.fold(Range.upto(spawned.n), Sum{});
    }
};

test "many spawned jobs with nested folds all complete" {
    const pool = try create_pool(3);
    defer pool.destroy();
    const rayon = Rayon.init(pool);
    var tasks: [100]parallel.Task(SpawnedFold) = undefined;
    for (&tasks, 0..) |*task, index| {
        task.* = .init(.{ .rayon = rayon, .n = index * 10 });
        rayon.spawn(index, task);
    }
    for (&tasks, 0..) |*task, index| {
        const n: u64 = index * 10;
        const expected = if (n == 0) 0 else n * (n - 1) / 2;
        try testing.expectEqual(expected, rayon.block_on(task));
    }
}
