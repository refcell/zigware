//! Tests of the strategy MSM (`G.msm_strategy`, `arithmetic.msm.msm_tiled`), ported from
//! commonware's `group.rs` (`test_msm_parallel_*`, `msm_tiled_covers_every_window_of_every_point`,
//! `msm_matches_naive_sum_through_cut_and_padded_tiles`). Every strategy shape must return the
//! naive sum.
//!
//! blst's tile routine reads one point ahead, so commonware pads a one-point tile with a copy
//! of its point under a zero scalar. The Zig tile kernel reads no further than its range, so a
//! one-point tile runs unpadded; the coverage test checks it is still reached.

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const testing = std.testing;
const parallel = @import("parallel");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const group = @import("group.zig");
const tiled = @import("arithmetic/root.zig").msm;
const math = @import("math");

const Scalar = group.Scalar;
const SmallScalar = group.SmallScalar;
const G1 = group.G1;
const G2 = group.G2;
const Explorer = parallel.mocks.Explorer;
const gpa = testing.allocator;

fn naive(comptime G: type, points: []const G, scalars: anytype) G {
    var sum = G.zero;
    for (points, scalars) |point, scalar| sum = sum.add(point.mul(scalar));
    return sum;
}

/// `G.msm_strategy` under every explored shape (commonware `explore`).
fn msm_explored(comptime G: type, points: []const G, scalars: anytype) !G {
    const Op = struct {
        points: []const G,
        scalars: @TypeOf(scalars),

        pub fn run(op: @This(), explorer: Explorer) !G {
            return G.msm_strategy(gpa, op.points, op.scalars, explorer);
        }

        pub fn eql(_: @This(), a: G, b: G) bool {
            return a.eql(b);
        }
    };
    return parallel.mocks.explore(gpa, testing.io, Op{ .points = points, .scalars = scalars });
}

fn check_parallel(comptime G: type, points: []const G, scalars: []const Scalar) !void {
    // Planning more workers than the pool has threads runs more tasks than threads.
    const shared = try parallel.mocks.pooled(gpa, testing.io, 4, 32);
    defer shared.pool.destroy();
    const explorer: Explorer = .parallel(shared);
    const expected = naive(G, points, scalars);
    try testing.expect((try msm_explored(G, points, scalars)).eql(expected));
    try testing.expect((try G.msm_strategy(gpa, points, scalars, explorer)).eql(expected));

    // The same points with 128-bit scalars take the tiled path with fewer bits.
    var rng = utils.test_rng();
    var small: [100]SmallScalar = undefined;
    assert(points.len <= small.len);
    for (small[0..points.len]) |*scalar| scalar.* = SmallScalar.random(&rng);
    const smalls = small[0..points.len];
    const expected_small = naive(G, points, smalls);
    try testing.expect((try msm_explored(G, points, smalls)).eql(expected_small));
    try testing.expect((try G.msm_strategy(gpa, points, smalls, explorer)).eql(expected_small));
}

fn parallel_body(comptime G: type) fn (void, *minifuzz.Unstructured) anyerror!void {
    return struct {
        fn body(_: void, u: *minifuzz.Unstructured) anyerror!void {
            const n = u.int_in_range(usize, 2, 100);
            var points: [100]G = undefined;
            var scalars: [100]Scalar = undefined;
            for (points[0..n]) |*point| point.* = try G.arbitrary(u);
            for (scalars[0..n]) |*scalar| scalar.* = try Scalar.arbitrary(u);
            try check_parallel(G, points[0..n], scalars[0..n]);
        }
    }.body;
}

/// Point arithmetic is slow in Debug builds, so these use fewer cases than commonware's
/// time-bounded default.
fn fuzz_cases(cases: u64, body: fn (void, *minifuzz.Unstructured) anyerror!void) !void {
    try (minifuzz.Builder{}).with_search_limit(cases * build_options.fuzz_soak)
        .run(gpa, {}, body);
}

test "group msm: parallel G1 matches the naive sum under every shape" {
    try fuzz_cases(3, parallel_body(G1));
}

test "group msm: parallel G2 matches the naive sum under every shape" {
    try fuzz_cases(2, parallel_body(G2));
}

fn edge_body(comptime G: type) fn (void, *minifuzz.Unstructured) anyerror!void {
    return struct {
        fn body(_: void, u: *minifuzz.Unstructured) anyerror!void {
            var points: [50]G = undefined;
            var scalars: [50]Scalar = undefined;
            for (&points) |*point| point.* = try G.arbitrary(u);
            for (&scalars) |*scalar| scalar.* = try Scalar.arbitrary(u);
            const single_point = try G.arbitrary(u);
            const single_scalar = try Scalar.arbitrary(u);
            const index = u.int_in_range(usize, 0, 49);
            try check_edges(G, &points, &scalars, single_point, single_scalar, index);
        }
    }.body;
}

fn check_edges(
    comptime G: type,
    points: *[50]G,
    scalars: *[50]Scalar,
    single_point: G,
    single_scalar: Scalar,
    index: usize,
) !void {
    const pool = try parallel.ThreadPool.create(gpa, testing.io, .{ .threads = 7 });
    defer pool.destroy();
    const par = parallel.Rayon.init(pool).with_parallelism(8);
    const zeros: [50]Scalar = @splat(Scalar.zero);
    const identities: [50]G = @splat(G.zero);
    // All zero scalars, then all identity points.
    try testing.expect((try G.msm_strategy(gpa, points, &zeros, par)).eql(G.zero));
    try testing.expect((try G.msm_strategy(gpa, &identities, scalars, par)).eql(G.zero));
    // A single nonzero term among zeros.
    var lone_points = identities;
    var lone_scalars = zeros;
    lone_points[index] = single_point;
    lone_scalars[index] = single_scalar;
    const lone = try G.msm_strategy(gpa, &lone_points, &lone_scalars, par);
    try testing.expect(lone.eql(single_point.mul(single_scalar)));
}

test "group msm: parallel G1 edge cases" {
    try fuzz_cases(2, edge_body(G1));
}

test "group msm: parallel G2 edge cases" {
    try fuzz_cases(1, edge_body(G2));
}

/// A tile kernel that counts the `(row, point)` cells it reaches instead of summing points,
/// and records the windows and the shortest tile of a run. The sum of a run is its number of
/// cells, so doubling leaves it unchanged.
const CellKernel = struct {
    counts: []std.atomic.Value(u32),
    npoints: usize,
    window: *std.atomic.Value(u32),
    shortest: *std.atomic.Value(usize),

    pub const window_max = 10;
    pub const zero: usize = 0;
    pub const State = struct { tiles: usize };

    pub fn init(_: CellKernel) State {
        return .{ .tiles = 0 };
    }

    pub fn tile(
        kernel: CellKernel,
        state: *State,
        row: u32,
        window: u32,
        columns: parallel.Range,
    ) usize {
        assert(!columns.is_empty() and columns.end <= kernel.npoints);
        state.tiles += 1;
        // Every tile of a run shares one window.
        const previous = kernel.window.cmpxchgStrong(0, window, .monotonic, .monotonic);
        if (previous) |seen| assert(seen == window);
        _ = kernel.shortest.fetchMin(columns.end - columns.start, .monotonic);
        for (columns.start..columns.end) |point| {
            _ = kernel.counts[row * kernel.npoints + point].fetchAdd(1, .monotonic);
        }
        return columns.end - columns.start;
    }

    pub fn add(_: CellKernel, a: usize, b: usize) usize {
        return a + b;
    }

    pub fn double(_: CellKernel, a: usize) usize {
        return a;
    }
};

/// Cuts a tiled run over `npoints` points of `nbits`-bit scalars with `strategy`, asserts that
/// every `(row, point)` cell of the chosen window's grid is reached exactly once, and returns
/// the fewest points a tile held.
fn covers(strategy: anytype, nbits: u32, npoints: usize) !usize {
    const rows_max = nbits / 2 + 1;
    const counts = try gpa.alloc(std.atomic.Value(u32), rows_max * npoints);
    defer gpa.free(counts);
    @memset(counts, .init(0));
    var window: std.atomic.Value(u32) = .init(0);
    var shortest: std.atomic.Value(usize) = .init(std.math.maxInt(usize));
    const kernel: CellKernel = .{
        .counts = counts,
        .npoints = npoints,
        .window = &window,
        .shortest = &shortest,
    };
    const cells = try tiled.run_tiled(usize, gpa, npoints, nbits, strategy, kernel);
    const chosen = window.load(.monotonic);
    try testing.expect(chosen >= 2);
    const rows = nbits / chosen + 1;
    try testing.expectEqual(rows * npoints, cells);
    for (counts, 0..) |count, cell| {
        const expected: u32 = if (cell < rows * npoints) 1 else 0;
        try testing.expectEqual(expected, count.load(.monotonic));
    }
    return shortest.load(.monotonic);
}

const shapes = [_]struct { nbits: u32, npoints: usize }{
    .{ .nbits = 255, .npoints = 32 },  .{ .nbits = 255, .npoints = 33 },
    .{ .nbits = 255, .npoints = 64 },  .{ .nbits = 255, .npoints = 100 },
    .{ .nbits = 255, .npoints = 257 }, .{ .nbits = 128, .npoints = 80 },
};

/// Explorers that take the most parallel shape at every call while planning 3, 7, 12, and 32
/// workers on a four-thread pool. Destroy them with `destroy_cutting`.
fn cutting_strategies() ![4]Explorer {
    var out: [4]Explorer = undefined;
    for (&out, [_]usize{ 3, 7, 12, 32 }) |*explorer, workers| {
        explorer.* = .parallel(try parallel.mocks.pooled(gpa, testing.io, 4, workers));
    }
    return out;
}

fn destroy_cutting(strategies: [4]Explorer) void {
    for (strategies) |explorer| explorer.strategy.pool.destroy();
}

test "group msm: tiled covers every window of every point" {
    const Op = struct {
        nbits: u32,
        npoints: usize,

        pub fn run(op: @This(), explorer: Explorer) !bool {
            _ = try covers(explorer, op.nbits, op.npoints);
            return true;
        }
    };
    const strategies = try cutting_strategies();
    defer destroy_cutting(strategies);
    for (shapes) |shape| {
        const op: Op = .{ .nbits = shape.nbits, .npoints = shape.npoints };
        try testing.expect(try parallel.mocks.explore(gpa, testing.io, op));
        for (strategies) |strategy| _ = try covers(strategy, shape.nbits, shape.npoints);
    }
    // Three and seven planned workers cut rows of 257 points, and twelve leave a one-point
    // tile of 64. Shares start at fixed boundaries and steals only add cuts, so this holds
    // whatever the timing.
    for (strategies[0..2]) |strategy| try testing.expect(try covers(strategy, 255, 257) < 257);
    try testing.expectEqual(@as(usize, 1), try covers(strategies[2], 255, 64));
}

test "group msm: matches the naive sum through cut and one-point tiles" {
    var rng = utils.test_rng();
    const strategies = try cutting_strategies();
    defer destroy_cutting(strategies);
    for ([_]usize{ 64, 257 }) |npoints| {
        const points = try gpa.alloc(G1, npoints);
        defer gpa.free(points);
        const scalars = try gpa.alloc(Scalar, npoints);
        defer gpa.free(scalars);
        for (points) |*point| point.* = G1.generator.mul(Scalar.random(&rng));
        for (scalars) |*scalar| scalar.* = Scalar.random(&rng);
        const expected = naive(G1, points, scalars);
        for (strategies) |strategy| {
            try testing.expect((try G1.msm_strategy(gpa, points, scalars, strategy)).eql(expected));
        }
    }
}

test "group msm: eval_msm across pools equals eval and the sequential msm" {
    var rng = utils.test_rng();
    for ([_]u32{ 1, 2, 5, 34, 334 }) |degree_plus_one| {
        var secret = try math.poly.Poly(Scalar).random(gpa, &rng, degree_plus_one - 1);
        defer secret.deinit(gpa);
        var public = try math.poly.commit(gpa, G1, secret);
        defer public.deinit(gpa);
        const x = Scalar.random(&rng);
        const expected = public.eval(Scalar, x);
        const serial = try public.eval_msm(gpa, Scalar, x, parallel.sequential);
        try testing.expect(serial.eql(expected));
        for ([_]u32{ 0, 1, 3, 8 }) |workers| {
            const strategy = try parallel.mocks.pooled(gpa, testing.io, workers, 8);
            defer strategy.pool.destroy();
            const pooled = try public.eval_msm(gpa, Scalar, x, strategy);
            try testing.expect(pooled.eql(expected));
        }
    }
}
