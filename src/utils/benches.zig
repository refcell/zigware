//! Benchmarks of the utils package (commonware `utils/src/{bitmap,cache,rational,sequence}/
//! benches`), with commonware's names, inputs, and per-iteration work.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const utils = @import("utils");

const TestRng = utils.rng.TestRng;
const BigRational = utils.rational.BigRational;

pub fn run(runner: *bench.Runner) !void {
    try bench_log2_ceil(runner);
    try bench_cmp_bytes(runner);
    try bench_cache(runner);
    try @import("bitmap_benches.zig").run(runner);
}

// rational::log2_ceil

const Log2CeilWorkload = struct {
    value: *const BigRational,
    precision: usize,

    pub fn iter(workload: *Log2CeilWorkload) !bool {
        var result = try workload.value.log2_ceil(workload.precision);
        defer result.deinit();
        return result.numer.isPositive();
    }
};

fn bench_log2_ceil(runner: *bench.Runner) !void {
    const cases = [_][2]u64{
        .{ 1, 2 }, .{ 1, 4 },   .{ 3, 4 },     .{ 3, 8 },
        .{ 7, 8 }, .{ 15, 16 }, .{ 511, 512 }, .{ 1023, 1024 },
    };
    for (cases) |case| {
        var value = try BigRational.from_frac_u64(runner.allocator, case[0], case[1]);
        defer value.deinit();
        var label: [48]u8 = undefined;
        const fraction = try std.fmt.bufPrint(&label, "{d}:{d}", .{ case[0], case[1] });
        for ([_]usize{ 4, 8, 12 }) |precision| {
            const benchmark = bench.Benchmark.init("rational::log2_ceil")
                .with_param("value", fraction).with_param("precision", precision);
            var workload: Log2CeilWorkload = .{ .value = &value, .precision = precision };
            try runner.run(benchmark, &workload);
        }
    }
}

// sequence::cmp_bytes

fn SortWorkload(comptime N: usize) type {
    const Key = utils.sequence.FixedBytes(N);
    return struct {
        keys: []const Key,
        work: []Key,

        fn less_than(_: void, a: Key, b: Key) bool {
            return a.order(b) == .lt;
        }

        /// Untimed, as commonware's `iter_batched` clones the keys outside the measurement.
        pub fn before_iter(workload: *@This()) void {
            @memcpy(workload.work, workload.keys);
        }

        pub fn iter(workload: *@This()) usize {
            std.mem.sortUnstable(Key, workload.work, {}, less_than);
            assert(workload.work.len == workload.keys.len);
            return workload.work.len;
        }
    };
}

fn SearchWorkload(comptime N: usize) type {
    const Key = utils.sequence.FixedBytes(N);
    return struct {
        sorted: []const Key,
        queries: []const Key,

        fn compare(query: Key, item: Key) std.math.Order {
            return query.order(item);
        }

        pub fn iter(workload: *@This()) usize {
            var found: usize = 0;
            for (workload.queries) |query| {
                const query_kept = query;
                std.mem.doNotOptimizeAway(&query_kept);
                if (std.sort.binarySearch(Key, workload.sorted, query_kept, compare) != null) {
                    found += 1;
                }
            }
            assert(found <= workload.queries.len);
            return found;
        }
    };
}

fn random_keys(
    comptime N: usize,
    gpa: Allocator,
    rng: *TestRng,
    n: usize,
) ![]utils.sequence.FixedBytes(N) {
    const keys = try gpa.alloc(utils.sequence.FixedBytes(N), n);
    for (keys) |*key| rng.fill_bytes(&key.bytes);
    return keys;
}

fn bench_cmp_bytes_size(comptime N: usize, runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const Key = utils.sequence.FixedBytes(N);
    const counts = runner.inputs.pick([]const u64, &.{100}, &.{ 100, 10_000, 100_000 }, &.{
        100, 10_000, 100_000,
    });
    for (counts) |n| {
        var rng = TestRng.init(n);
        const keys = try random_keys(N, gpa, &rng, n);
        defer gpa.free(keys);
        const work = try gpa.alloc(Key, n);
        defer gpa.free(work);
        const name = bench.Benchmark.init("sequence::cmp_bytes");
        var sort: SortWorkload(N) = .{ .keys = keys, .work = work };
        const sort_name = name.with_param("op", "sort").with_param("size", N).with_param("n", n);
        try runner.run(sort_name, &sort);
        sort.before_iter();
        _ = sort.iter();
        // A hit ends on an equal compare, which reads every byte. A miss usually stops early.
        const misses = try random_keys(N, gpa, &rng, n);
        defer gpa.free(misses);
        for ([_][]const u8{ "hit", "miss" }, [_][]const Key{ keys, misses }) |op, queries| {
            var search: SearchWorkload(N) = .{ .sorted = work, .queries = queries };
            const benchmark = name.with_param("op", op).with_param("size", N).with_param("n", n);
            try runner.run(benchmark, &search);
        }
    }
}

fn bench_cmp_bytes(runner: *bench.Runner) !void {
    // 16 and 65 keep the derived compare. The rest cover whole words with and without leftovers.
    inline for (.{ 16, 20, 23, 32, 33, 64, 65 }) |size| try bench_cmp_bytes_size(size, runner);
}

// cache::{get,insert,mixed,refill}

const Cache = utils.cache.Cache(u64, u64);

/// A factory that must never run: every benchmarked cache is already at capacity.
const Unreachable = struct {
    pub fn make(_: Unreachable) u64 {
        unreachable; // Each cache is full before it is measured, so it never grows.
    }
};

fn full_cache(gpa: Allocator, capacity: usize) !Cache {
    var cache = try Cache.init(gpa, capacity);
    for (0..capacity) |key| _ = cache.put(key, key);
    assert(cache.len() == capacity);
    return cache;
}

const GetWorkload = struct {
    cache: *Cache,
    keys: []const u64,

    pub fn iter(workload: *GetWorkload) usize {
        var hits: usize = 0;
        for (workload.keys) |key| {
            if (workload.cache.get(key)) |value| {
                std.mem.doNotOptimizeAway(value);
                hits += 1;
            }
        }
        return hits;
    }
};

const inserts_per_iteration = 1024;

/// Every key is fresh and never read, so each insertion into the full cache evicts the
/// unreferenced Small tail into Ghost.
const InsertWorkload = struct {
    cache: *Cache,
    next: u64,

    pub fn iter(workload: *InsertWorkload) u64 {
        const start = workload.next;
        workload.next += inserts_per_iteration;
        for (start..workload.next) |key| _ = workload.cache.put(key, key);
        return workload.next;
    }
};

/// Each round reads 8 live slots, then installs one fresh key.
const MixedWorkload = struct {
    cache: *Cache,
    rounds: []const [8]usize,
    keys: []u64,
    next: u64,

    pub fn iter(workload: *MixedWorkload) u64 {
        for (workload.rounds) |reads| {
            for (reads) |slot| std.mem.doNotOptimizeAway(workload.cache.get(workload.keys[slot]));
            const key = workload.next;
            workload.next += 1;
            const entry = workload.cache.get_or_insert_mut(key, Unreachable{});
            entry.value.* = key;
            workload.keys[entry.slot] = key;
        }
        return workload.next;
    }
};

/// Reuse after bulk invalidation: a fresh cache with every odd key removed is built before
/// each iteration (commonware `BatchSize::PerIteration`), and the odd keys are re-inserted.
const RefillWorkload = struct {
    gpa: Allocator,
    capacity: usize,
    cache: ?Cache = null,

    const Zero = struct {
        pub fn make(_: Zero) u64 {
            return 0;
        }
    };

    const Even = struct {
        pub fn keep(_: Even, key: u64, _: *const u64) bool {
            return key % 2 == 0;
        }
    };

    pub fn before_iter(workload: *RefillWorkload) !void {
        if (workload.cache) |*cache| cache.deinit(workload.gpa);
        workload.cache = try Cache.init(workload.gpa, workload.capacity);
        const cache = &workload.cache.?;
        cache.prefill(Zero{});
        for (0..workload.capacity) |key| _ = cache.put(key, key);
        cache.retain(Even{});
        assert(cache.len() == workload.capacity / 2);
    }

    pub fn iter(workload: *RefillWorkload) usize {
        const cache = &workload.cache.?;
        var key: u64 = 1;
        while (key < workload.capacity) : (key += 2) {
            const entry = cache.get_or_insert_mut(key, Unreachable{});
            entry.value.* = key;
            std.mem.doNotOptimizeAway(entry.slot);
        }
        return cache.len();
    }

    pub fn teardown(workload: *RefillWorkload) void {
        if (workload.cache) |*cache| cache.deinit(workload.gpa);
        workload.cache = null;
    }
};

fn bench_cache_capacity(runner: *bench.Runner, capacity: usize) !void {
    const gpa = runner.allocator;
    var rng = TestRng.init(capacity);
    var keys: [1024]u64 = undefined;
    for (&keys) |*key| key.* = utils.rng.range_less_than(&rng, u64, 0, capacity);
    {
        var cache = try full_cache(gpa, capacity);
        defer cache.deinit(gpa);
        var get: GetWorkload = .{ .cache = &cache, .keys = &keys };
        const name = bench.Benchmark.init("cache::get").with_param("capacity", capacity);
        try runner.run(name, &get);
    }
    {
        var cache = try full_cache(gpa, capacity);
        defer cache.deinit(gpa);
        var insert: InsertWorkload = .{ .cache = &cache, .next = capacity };
        const name = bench.Benchmark.init("cache::insert").with_param("capacity", capacity);
        try runner.run(name, &insert);
    }
    try bench_mixed(runner, capacity);
    var refill: RefillWorkload = .{ .gpa = gpa, .capacity = capacity };
    defer refill.teardown();
    const name = bench.Benchmark.init("cache::refill").with_param("capacity", capacity);
    try runner.run(name, &refill);
}

fn bench_mixed(runner: *bench.Runner, capacity: usize) !void {
    const gpa = runner.allocator;
    var cache = try full_cache(gpa, capacity);
    defer cache.deinit(gpa);
    var rng = TestRng.init(capacity);
    const rounds = try gpa.alloc([8]usize, 1024);
    defer gpa.free(rounds);
    for (rounds) |*reads| {
        for (reads) |*slot| slot.* = utils.rng.range_less_than(&rng, usize, 0, capacity);
    }
    const keys = try gpa.alloc(u64, capacity);
    defer gpa.free(keys);
    for (keys, 0..) |*key, index| key.* = index;
    var mixed: MixedWorkload = .{
        .cache = &cache,
        .rounds = rounds,
        .keys = keys,
        .next = capacity,
    };
    const name = bench.Benchmark.init("cache::mixed").with_param("capacity", capacity);
    try runner.run(name, &mixed);
}

fn bench_cache(runner: *bench.Runner) !void {
    const capacities = runner.inputs.pick([]const usize, &.{1 << 10}, &.{
        1 << 10, 1 << 14, 1 << 18,
    }, &.{ 1 << 10, 1 << 14, 1 << 18 });
    for (capacities) |capacity| try bench_cache_capacity(runner, capacity);
}
