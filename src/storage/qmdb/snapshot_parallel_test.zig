//! Tests of the parallel snapshot build (commonware qmdb/snapshot.rs `ParallelPlan` tests and
//! the any/{unordered,ordered}/fixed.rs `*_parallel_init_*` tests): over seeded logs, every
//! budget and every strategy shape builds the serial build's snapshot, active key count, and
//! activity bitmap; empty logs build like the serial path; and failing reads, in the decode or
//! in a worker, surface after every unit joins and leak nothing.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const parallel = @import("parallel");
const utils = @import("utils");
const merkle = @import("../merkle/mod.zig");
const translator = @import("../translator.zig");
const partitioned = @import("../index/partitioned/mod.zig");
const contiguous = @import("../journal/contiguous/mod.zig");
const value = @import("value.zig");
const any = @import("any/operation.zig");
const snapshot = @import("snapshot.zig");
const snapshot_parallel = @import("snapshot_parallel.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");

const U64 = utils.sequence.U64;
const Op = any.Unordered(merkle.mmr.Family, U64, value.Fixed(U64));
const Plan = snapshot_parallel.Plan;
const gpa = testing.allocator;
const commit: Op = .{ .commit = .{ .metadata = null, .floor = 0 } };

/// An in-memory log whose reads fail once `budget` reads have been made. Units read it from
/// several threads.
const Log = struct {
    ops: []const Op,
    budget: u64 = std.math.maxInt(u64),
    reads: std.atomic.Value(u64) = .init(0),

    pub fn get_bounds(self: *const Log) contiguous.Bounds {
        return .{ .start = 0, .end = self.ops.len };
    }

    pub fn read(self: *Log, position: u64) !Op {
        if (position >= self.ops.len) return error.ItemOutOfRange;
        if (self.reads.fetchAdd(1, .monotonic) >= self.budget) return error.ItemPruned;
        return self.ops[position];
    }
};

/// Keys over seven partitions (their first byte) whose next byte is zero, so every key of a
/// partition collides under `OneCap`.
fn key_of(k: u64) U64 {
    return U64.init((k % 7) << 56 | k);
}

fn random_log(random: std.Random, len: usize, keys: u64) ![]Op {
    const ops = try gpa.alloc(Op, len);
    for (ops[0 .. len - 1]) |*op| {
        const k = key_of(random.uintLessThan(u64, keys));
        op.* = switch (random.uintLessThan(u8, 10)) {
            0...5 => .{ .update = .{ .key = k, .value = U64.init(random.int(u64)) } },
            6...7 => .{ .delete = k },
            else => commit,
        };
    }
    ops[len - 1] = commit;
    return ops;
}

/// A build's observable result, independent of where the index stores each value.
const Summary = struct {
    active_keys: usize,
    activity_len: u64,
    activity: u64,
    items: u64,
    values: u64,

    const Fold = struct {
        sum: *u64,

        fn visit(fold: *const Fold, location: *const u64) void {
            fold.sum.* +%= utils.rng.mix64(location.*);
        }
    };

    fn of(built: *const snapshot.Build, index: anytype) Summary {
        var activity: u64 = 0;
        for (0..built.activity.len()) |bit| {
            if (built.activity.get(bit)) activity +%= utils.rng.mix64(bit + 1);
        }
        var values: u64 = 0;
        index.for_each_value(&Fold{ .sum = &values }, Fold.visit);
        return .{
            .active_keys = built.active_keys,
            .activity_len = built.activity.len(),
            .activity = activity,
            .items = index.items(),
            .values = values,
        };
    }
};

fn Flavor(comptime ordered: bool) type {
    const T = translator.OneCap;
    return if (ordered)
        partitioned.ordered.Index(T, u64, 1)
    else
        partitioned.unordered.Index(T, u64, 1);
}

fn new_index(comptime I: type) I {
    return I.init(gpa, partitioned.Translator(translator.OneCap, 1).init(.{}));
}

fn serial(comptime I: type, ops: []const Op, floor: u64, cache: ?usize) !Summary {
    var log: Log = .{ .ops = ops };
    var index = new_index(I);
    defer index.deinit();
    var built = try snapshot.build(Op, gpa, floor, &log, &index, cache);
    defer built.deinit(gpa);
    return Summary.of(&built, &index);
}

fn Run(comptime I: type) type {
    return struct {
        ops: []const Op,
        floor: u64,
        cache: ?usize,
        concurrency: usize,

        pub fn run(op: @This(), strategy: parallel.mocks.Explorer) !Summary {
            var log: Log = .{ .ops = op.ops };
            var index = new_index(I);
            defer index.deinit();
            var built = try snapshot_parallel.build(
                Op,
                gpa,
                op.floor,
                &log,
                &index,
                op.cache,
                op.concurrency,
                strategy,
            );
            defer built.deinit(gpa);
            return Summary.of(&built, &index);
        }
    };
}

const budgets = [_]usize{ 1, 2, 3, 4, 5, 9, 201, 301, std.math.maxInt(usize) };

test "parallel snapshot build matches the serial build under every budget and shape" {
    var prng = std.Random.DefaultPrng.init(fuzz_bytes.seed(0x70617261));
    for (0..fuzz_bytes.iterations(3)) |_| {
        // Several decode chunks (64 operations in tests) and delete-then-reinsert sequences.
        const len = prng.random().intRangeAtMost(usize, 1, 400);
        const ops = try random_log(prng.random(), len, 1 + prng.random().uintLessThan(u64, 60));
        defer gpa.free(ops);
        const floor = prng.random().uintAtMost(u64, len - 1);
        inline for (.{ false, true }) |ordered| {
            const I = Flavor(ordered);
            for ([_]?usize{ null, 3, 4096 }) |cache| {
                const expected = try serial(I, ops, floor, cache);
                for (budgets) |concurrency| {
                    const run: Run(I) = .{
                        .ops = ops,
                        .floor = floor,
                        .cache = cache,
                        .concurrency = concurrency,
                    };
                    const actual = try parallel.mocks.explore(gpa, testing.io, run);
                    try testing.expectEqualDeep(expected, actual);
                }
            }
        }
    }
}

test "parallel snapshot build of a fresh or empty log matches the serial build" {
    const fresh = [_]Op{commit};
    inline for (.{ false, true }) |ordered| {
        const I = Flavor(ordered);
        for ([_][]const Op{ &.{}, &fresh }) |ops| {
            const expected = try serial(I, ops, 0, null);
            try testing.expectEqual(@as(usize, 0), expected.active_keys);
            for (budgets) |concurrency| {
                const run: Run(I) = .{
                    .ops = ops,
                    .floor = 0,
                    .cache = null,
                    .concurrency = concurrency,
                };
                const actual = try parallel.mocks.explore(gpa, testing.io, run);
                try testing.expectEqualDeep(expected, actual);
            }
        }
    }
}

fn expect_failure(comptime I: type, ops: []const Op, budget: u64) !void {
    const pool = try parallel.ThreadPool.create(gpa, testing.io, .{ .threads = 3 });
    defer pool.destroy();
    const strategy = parallel.Rayon.init(pool).with_parallelism(4);
    var log: Log = .{ .ops = ops, .budget = budget };
    var index = new_index(I);
    defer index.deinit();
    const result = snapshot_parallel.build(Op, gpa, 0, &log, &index, null, 4, strategy);
    try testing.expectError(error.ItemPruned, result);
}

test "parallel snapshot build surfaces decode and worker read failures" {
    // Two keys of one partition and translated sub-key: the second resolves its collision by
    // reading the first's operation, which is the only read past the decode's one per op.
    const ops = [_]Op{
        .{ .update = .{ .key = key_of(0x10), .value = U64.init(1) } },
        .{ .update = .{ .key = key_of(0x10 + 7), .value = U64.init(2) } },
        commit,
    };
    inline for (.{ false, true }) |ordered| {
        // The decode's first read fails, before any worker has an operation.
        try expect_failure(Flavor(ordered), &ops, 0);
        // The decode succeeds and the worker's collision read fails.
        try expect_failure(Flavor(ordered), &ops, ops.len);
    }
}

test "parallel plan budget and ranges" {
    for (0..129) |partitions| {
        for (1..65) |budget| {
            const plan = Plan.init(partitions, budget, null) orelse {
                try testing.expect(partitions == 0 or budget == 1);
                continue;
            };
            try testing.expect(partitions != 0 and budget != 1);
            try testing.expect(plan.workers >= 1 and plan.workers <= partitions);
            if (budget <= 3) {
                try testing.expectEqual(@as(usize, 0), plan.decoders);
                try testing.expect(plan.workers < budget);
            } else {
                try testing.expect(plan.decoders >= 2);
                try testing.expect(plan.decoders + plan.workers <= budget);
            }
            var end: usize = 0;
            for (0..plan.workers) |worker| {
                const span = plan.range(worker);
                try testing.expectEqual(end, span.lo);
                try testing.expect(span.len >= 1 and span.len <= plan.range_size);
                end = span.lo + span.len;
                try testing.expect(end <= partitions);
                for (span.lo..end) |partition| {
                    try testing.expectEqual(worker, partition / plan.range_size);
                }
            }
            try testing.expectEqual(partitions, end);
        }
    }
}

test "parallel plan cache split" {
    // Uneven ranges can reduce the worker count, so the cache splits among the final workers.
    for (1..65) |partitions| {
        for (2..33) |budget| {
            for ([_]usize{ 0, 1, 3, 8, 64 }) |cache_size| {
                const cache: ?usize = if (cache_size == 0) null else cache_size;
                const plan = Plan.init(partitions, budget, cache).?;
                const share = plan.per_worker_cache orelse 0;
                try testing.expectEqual(cache_size < plan.workers, plan.per_worker_cache == null);
                const allocated = share * plan.workers;
                try testing.expect(allocated <= cache_size);
                try testing.expect(cache_size - allocated < plan.workers);
            }
        }
    }
}
