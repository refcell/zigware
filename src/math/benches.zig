//! Benchmarks of the math package (commonware `math/benches/interpolation.rs`), with
//! commonware's names and cases.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const math = @import("math");
const utils = @import("utils");

const F = math.fields.goldilocks.F;
const Interpolator = math.poly.Interpolator(u32, F);

const counts_all = [_]u32{ 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 };
const counts_smoke = [_]u32{4};

/// Builds a roots-of-unity interpolator over the first `quorum(n)` points (key `i` at
/// exponent `i + 1`).
const CreationWorkload = struct {
    gpa: Allocator,
    total: u32,
    keys: []const u32,
    exponents: []const u32,

    pub fn iter(workload: *CreationWorkload) !void {
        var interpolator = try Interpolator.init_roots_of_unity(
            workload.gpa,
            workload.total,
            workload.keys,
            workload.exponents,
        );
        interpolator.deinit(workload.gpa);
    }
};

fn bench_interpolator_creation(runner: *bench.Runner) !void {
    const counts = runner.inputs.pick([]const u32, &counts_smoke, &counts_all, &counts_all);
    const gpa = runner.allocator;
    for (counts) |n| {
        const quorum = utils.N3f1.quorum(n);
        assert(quorum > 0 and quorum <= n);
        const keys = try gpa.alloc(u32, quorum);
        defer gpa.free(keys);
        const exponents = try gpa.alloc(u32, quorum);
        defer gpa.free(exponents);
        for (keys, exponents, 0..) |*key, *exponent, index| {
            key.* = @intCast(index);
            exponent.* = @intCast(index + 1);
        }
        var workload: CreationWorkload = .{
            .gpa = gpa,
            .total = n,
            .keys = keys,
            .exponents = exponents,
        };
        const benchmark = bench.Benchmark.init("interpolation::interpolator_creation")
            .with_param("n", n);
        try runner.run(benchmark, &workload);
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_interpolator_creation(runner);
}
