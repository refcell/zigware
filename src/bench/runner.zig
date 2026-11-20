//! `Runner`: measures workloads the way Criterion does for `zig build bench`, runs each once
//! for `zig build test`, and lists names for `--list`.
//!
//! A measured run warms up by doubling the iteration count until the warm-up's wall time
//! passes, and estimates the wall time per iteration: the warm-up's total over its iterations,
//! counting the `setup`, `before_iter`, and `teardown` hooks, as Criterion's `iter_custom` counts
//! the fixture commonware's benches build inside it. It then takes `samples` samples of an equal
//! iteration count sized to fill the measurement time, and reports the fastest, median, and
//! slowest time per iteration. Every loop is bounded by the configured times and `iters_max`.

const std = @import("std");
const assert = std.debug.assert;
const bench = @import("root.zig");

pub const Config = struct {
    warm_up_ns: u64 = 300 * std.time.ns_per_ms,
    measurement_ns: u64 = std.time.ns_per_s,
    samples: u32 = 20,
    /// The most iterations one sample runs.
    iters_max: u64 = 1 << 32,
};

/// The most samples a measured run takes.
pub const samples_max = 1000;

/// The fastest, median, and slowest nanoseconds per iteration of a measured run.
pub const Summary = struct {
    min_ns: f64,
    median_ns: f64,
    max_ns: f64,
    iters_per_sample: u64,
};

pub const Runner = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    out: *std.Io.Writer,
    inputs: bench.Inputs,
    /// A benchmark runs only if its name contains one of these, or if there are none.
    filters: []const []const u8 = &.{},
    /// Print the names of matching benchmarks instead of running them.
    list: bool = false,
    config: Config = .{},
    /// Where custom metrics go as JSON lines, if anywhere.
    metrics_out: ?*std.Io.Writer = null,
    /// Benchmarks run (or listed) so far.
    ran: u32 = 0,

    /// Whether the filters select `name`.
    pub fn matches(runner: *const Runner, name: []const u8) bool {
        if (runner.filters.len == 0) return true;
        for (runner.filters) |filter| {
            if (std.mem.indexOf(u8, name, filter) != null) return true;
        }
        return false;
    }

    /// Runs `workload` (a pointer to a workload) as `benchmark`, if the filters select it.
    pub fn run(runner: *Runner, benchmark: bench.Benchmark, workload: anytype) anyerror!void {
        bench.assert_workload(@typeInfo(@TypeOf(workload)).pointer.child);
        const name = benchmark.name();
        if (!runner.matches(name)) return;
        runner.ran += 1;
        if (runner.list) {
            try runner.out.print("{s}: benchmark\n", .{name});
            return;
        }
        if (runner.inputs == .smoke) {
            _ = try bench.criterion(runner.io, workload, 1);
            try runner.out.print("Testing {s}\nSuccess\n", .{name});
        } else {
            const summary = try runner.measure(workload);
            try runner.out.print("{s}\n", .{name});
            try runner.out.writeAll("                        time:   [");
            try write_time(runner.out, summary.min_ns);
            try runner.out.writeByte(' ');
            try write_time(runner.out, summary.median_ns);
            try runner.out.writeByte(' ');
            try write_time(runner.out, summary.max_ns);
            try runner.out.writeAll("]\n");
        }
        try runner.emit_metrics(&benchmark, workload);
        try runner.out.flush();
    }

    fn emit_metrics(runner: *Runner, benchmark: *const bench.Benchmark, workload: anytype) !void {
        const W = @typeInfo(@TypeOf(workload)).pointer.child;
        if (comptime !@hasDecl(W, "metrics")) return;
        const writer = runner.metrics_out orelse return;
        var buffer: [bench.metrics_max]bench.Metric = undefined;
        const metrics = workload.metrics(&buffer);
        assert(metrics.len <= bench.metrics_max);
        try benchmark.metrics_json(writer, metrics);
        try writer.writeByte('\n');
        try writer.flush();
    }

    /// Warms up, then samples `workload`, returning nanoseconds per iteration.
    pub fn measure(runner: *Runner, workload: anytype) anyerror!Summary {
        const config = runner.config;
        assert(config.samples >= 1 and config.samples <= samples_max);
        assert(config.iters_max >= 1);
        var iters: u64 = 1;
        var warm_ns: u64 = 0;
        var last_ns: u64 = 0;
        var warm_iters: u64 = 0;
        // Doubling from one reaches `iters_max` within 64 rounds. As Criterion's `iter_custom`
        // does, the warm-up and the estimate count wall time, every hook included, so a workload
        // that rebuilds a large fixture (per call in `setup`, or per iteration in `before_iter`)
        // runs as many iterations as its commonware counterpart.
        for (0..64) |_| {
            const start = std.Io.Clock.awake.now(runner.io);
            _ = try bench.criterion(runner.io, workload, iters);
            const end = std.Io.Clock.awake.now(runner.io);
            last_ns = @intCast(@max(end.nanoseconds - start.nanoseconds, 0));
            warm_ns +|= last_ns;
            warm_iters += iters;
            if (warm_ns >= config.warm_up_ns or iters >= config.iters_max) break;
            iters = @min(iters * 2, config.iters_max);
        }
        assert(warm_iters >= iters);
        const per_iter_ns = @max(warm_ns / warm_iters, 1);
        const sample_ns = config.measurement_ns / config.samples;
        const sample_iters = std.math.clamp(sample_ns / per_iter_ns, 1, config.iters_max);

        var times: [samples_max]f64 = undefined;
        for (times[0..config.samples]) |*time| {
            const elapsed_ns = try bench.criterion(runner.io, workload, sample_iters);
            time.* = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(sample_iters));
        }
        const sorted = times[0..config.samples];
        std.sort.pdq(f64, sorted, {}, std.sort.asc(f64));
        const summary: Summary = .{
            .min_ns = sorted[0],
            .median_ns = sorted[sorted.len / 2],
            .max_ns = sorted[sorted.len - 1],
            .iters_per_sample = sample_iters,
        };
        assert(summary.min_ns <= summary.median_ns and summary.median_ns <= summary.max_ns);
        return summary;
    }
};

/// Writes `ns` with four significant digits in the largest unit below it, as Criterion does.
pub fn write_time(writer: *std.Io.Writer, ns: f64) std.Io.Writer.Error!void {
    assert(ns >= 0);
    const Unit = struct { scale: f64, name: []const u8 };
    const unit: Unit = if (ns < 1e3)
        .{ .scale = 1, .name = "ns" }
    else if (ns < 1e6)
        .{ .scale = 1e3, .name = "µs" }
    else if (ns < 1e9)
        .{ .scale = 1e6, .name = "ms" }
    else
        .{ .scale = 1e9, .name = "s" };
    const value = ns / unit.scale;
    if (value < 10) {
        try writer.print("{d:.4} {s}", .{ value, unit.name });
    } else if (value < 100) {
        try writer.print("{d:.3} {s}", .{ value, unit.name });
    } else {
        try writer.print("{d:.2} {s}", .{ value, unit.name });
    }
}

const testing = std.testing;

const Sum = struct {
    values: [64]u64 = @splat(3),
    pub fn iter(sum: *Sum) u64 {
        var total: u64 = 0;
        for (sum.values) |value| total +%= value;
        return total;
    }
    pub fn metrics(_: *const Sum, buffer: []bench.Metric) []const bench.Metric {
        buffer[0] = .init("values", 64);
        return buffer[0..1];
    }
};

test "runner smoke-runs, lists, filters, and emits metrics" {
    var out_buffer: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buffer);
    var metrics_buffer: [256]u8 = undefined;
    var metrics_out: std.Io.Writer = .fixed(&metrics_buffer);
    var runner: Runner = .{
        .io = testing.io,
        .allocator = testing.allocator,
        .out = &out,
        .inputs = .smoke,
        .filters = &.{"sum"},
        .metrics_out = &metrics_out,
    };
    var workload: Sum = .{};
    try runner.run(bench.Benchmark.init("bench::sum").with_param("n", 64), &workload);
    try runner.run(bench.Benchmark.init("bench::other"), &workload);
    try testing.expectEqual(@as(u32, 1), runner.ran);
    try testing.expectEqualStrings("Testing bench::sum/n=64\nSuccess\n", out.buffered());
    try testing.expectEqualStrings(
        "{\"benchmark\":\"bench::sum/n=64\",\"commonware_bench_metrics\":true," ++
            "\"metrics\":{\"values\":64}}\n",
        metrics_out.buffered(),
    );

    out.end = 0;
    runner.list = true;
    try runner.run(bench.Benchmark.init("bench::sum"), &workload);
    try testing.expectEqualStrings("bench::sum: benchmark\n", out.buffered());
}

test "runner measures ordered per-iteration times" {
    var out_buffer: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buffer);
    var runner: Runner = .{
        .io = testing.io,
        .allocator = testing.allocator,
        .out = &out,
        .inputs = .standard,
        .config = .{ .warm_up_ns = 1_000_000, .measurement_ns = 2_000_000, .samples = 5 },
    };
    var workload: Sum = .{};
    const summary = try runner.measure(&workload);
    try testing.expect(summary.min_ns <= summary.median_ns);
    try testing.expect(summary.median_ns <= summary.max_ns);
    try testing.expect(summary.iters_per_sample >= 1);
    try runner.run(bench.Benchmark.init("bench::sum"), &workload);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "time:   [") != null);
}

/// A workload whose untimed setup costs far more than its timed iteration.
const SlowSetup = struct {
    io: std.Io,
    iters: u64 = 0,

    pub fn before_iter(workload: *SlowSetup) void {
        const start = std.Io.Clock.awake.now(workload.io);
        while (true) {
            const now = std.Io.Clock.awake.now(workload.io);
            if (now.nanoseconds - start.nanoseconds >= 100 * std.time.ns_per_us) break;
        }
    }

    pub fn iter(workload: *SlowSetup) u64 {
        workload.iters += 1;
        return workload.iters;
    }
};

test "runner plans samples from wall time, setup included, as criterion does" {
    var out_buffer: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buffer);
    var runner: Runner = .{
        .io = testing.io,
        .allocator = testing.allocator,
        .out = &out,
        .inputs = .standard,
        .config = .{
            .warm_up_ns = 10 * std.time.ns_per_ms,
            .measurement_ns = 20 * std.time.ns_per_ms,
            .samples = 2,
            .iters_max = 1000,
        },
    };
    var workload: SlowSetup = .{ .io = testing.io };
    const summary = try runner.measure(&workload);
    // About 100 µs per iteration of wall time fits at most 100 in a 10 ms sample; planning from
    // the timed span alone would run `iters_max`.
    try testing.expect(summary.iters_per_sample >= 1);
    try testing.expect(summary.iters_per_sample <= 100);
}

test "times print with four significant digits" {
    var buffer: [64]u8 = undefined;
    const cases = [_]struct { ns: f64, text: []const u8 }{
        .{ .ns = 1.5, .text = "1.5000 ns" },
        .{ .ns = 12.25, .text = "12.250 ns" },
        .{ .ns = 999, .text = "999.00 ns" },
        .{ .ns = 1_234, .text = "1.2340 µs" },
        .{ .ns = 56_780_000, .text = "56.780 ms" },
        .{ .ns = 2e9, .text = "2.0000 s" },
    };
    for (cases) |case| {
        var writer: std.Io.Writer = .fixed(&buffer);
        try write_time(&writer, case.ns);
        try testing.expectEqualStrings(case.text, writer.buffered());
    }
}
