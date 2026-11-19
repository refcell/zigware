//! bench: Abstract benchmark workloads.
//!
//! Zig port of commonware's `commonware-bench` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/bench). The lane file
//! docs/lanes/parallel.md tracks what is ported.
//!
//! A package adds benchmarks in `src/<package>/benches.zig`, which `zig build bench` and
//! `zig build test` discover. The file exports `pub fn run(runner: *bench.Runner) !void` and
//! may import its own package, that package's dependencies, and `bench`:
//!
//! ```zig
//! const bench = @import("bench");
//! pub fn run(runner: *bench.Runner) !void {
//!     const len = runner.inputs.pick(usize, 16, 4_096, 1 << 20);
//!     const benchmark = bench.Benchmark.init("codec::varint").with_param("len", len);
//!     var workload: VarintWorkload = .{ .len = len };
//!     try runner.run(benchmark, &workload);
//! }
//! ```
//!
//! A workload (commonware's `Workload` trait) is a struct with `iter(*W) Output` and optional
//! `setup`, `before_iter`, `teardown` (each `fn (*W) void` or `!void`), and
//! `metrics(*const W, []Metric) []const Metric`. `zig build bench` measures every workload
//! (`Inputs.standard`, or `Inputs.full` with `COMMONWARE_BENCH_FULL=1`), and `zig build test`
//! runs each once on `Inputs.smoke`, like `cargo test` runs Criterion benches.

const std = @import("std");
const assert = std.debug.assert;

pub const runner_module = @import("runner.zig");
pub const Runner = runner_module.Runner;
pub const RunnerConfig = runner_module.Config;
pub const Summary = runner_module.Summary;
pub const tracker = @import("tracker/root.zig");

/// Environment variable naming a JSONL file for custom benchmark metrics.
pub const metrics_path_env = "COMMONWARE_BENCH_METRICS_PATH";

/// Environment variable that selects `Inputs.full` when set to `1`.
pub const full_env = "COMMONWARE_BENCH_FULL";

/// The inputs a benchmark runs with.
pub const Inputs = enum {
    /// The smallest inputs that still run every benchmark, used under `zig build test`, which
    /// runs each benchmark once without measuring it.
    smoke,
    /// The inputs `zig build bench` measures.
    standard,
    /// The largest inputs, selected with `COMMONWARE_BENCH_FULL=1`.
    full,

    /// The inputs for a run with the harness arguments `args` (without the program name) and
    /// the value of `COMMONWARE_BENCH_FULL`, if set. `--list` gets `standard` so listings
    /// name the measured inputs.
    pub fn current(args: []const []const u8, full_value: ?[]const u8) Inputs {
        if (full_value) |value| {
            if (std.mem.eql(u8, value, "1")) return .full;
        }
        if (test_mode(args)) return .smoke;
        return .standard;
    }

    /// The value of `smoke`, `standard`, or `full` for these inputs.
    pub fn pick(inputs: Inputs, comptime T: type, smoke: T, standard: T, full: T) T {
        return switch (inputs) {
            .smoke => smoke,
            .standard => standard,
            .full => full,
        };
    }
};

/// Whether harness arguments select the unmeasured test mode, mirroring Criterion's
/// `configure_from_args`: arguments after `--` are filters.
pub fn test_mode(args: []const []const u8) bool {
    var bench_flag = false;
    var test_flag = false;
    var list_flag = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--")) break;
        if (std.mem.eql(u8, arg, "--bench")) bench_flag = true;
        if (std.mem.eql(u8, arg, "--test")) test_flag = true;
        if (std.mem.eql(u8, arg, "--list")) list_flag = true;
    }
    return !list_flag and (!bench_flag or test_flag);
}

/// The longest benchmark name, in bytes.
pub const name_len_max = 256;

/// A named benchmark configuration: a prefix and `key=value` parameters.
pub const Benchmark = struct {
    buffer: [name_len_max]u8 = undefined,
    len: usize = 0,

    /// A benchmark named by a commonware benchmark prefix, such as `qmdb::merkleize`.
    pub fn init(prefix: []const u8) Benchmark {
        assert(prefix.len <= name_len_max);
        var benchmark: Benchmark = .{};
        @memcpy(benchmark.buffer[0..prefix.len], prefix);
        benchmark.len = prefix.len;
        return benchmark;
    }

    /// Appends one `key=value` parameter: the first after a `/`, later ones after a space.
    /// Strings print as-is, booleans as `true`/`false`, numbers in decimal, enums by tag.
    pub fn with_param(benchmark: Benchmark, key: []const u8, value: anytype) Benchmark {
        var result = benchmark;
        const separator: u8 = if (std.mem.indexOfScalar(u8, result.name(), '/') == null)
            '/'
        else
            ' ';
        var writer: std.Io.Writer = .fixed(result.buffer[result.len..]);
        writer.writeByte(separator) catch @panic("benchmark name exceeds name_len_max");
        writer.print("{s}=", .{key}) catch @panic("benchmark name exceeds name_len_max");
        write_value(&writer, value) catch @panic("benchmark name exceeds name_len_max");
        result.len += writer.end;
        assert(result.len <= name_len_max);
        return result;
    }

    /// The full benchmark name.
    pub fn name(benchmark: *const Benchmark) []const u8 {
        assert(benchmark.len <= name_len_max);
        return benchmark.buffer[0..benchmark.len];
    }

    /// Writes custom metrics as one benchmark-tracking JSON object, byte-identical to
    /// commonware's `metrics_json(..).to_string()`: keys sorted, and of metrics sharing a
    /// name the last wins.
    pub fn metrics_json(
        benchmark: *const Benchmark,
        writer: *std.Io.Writer,
        metrics: []const Metric,
    ) std.Io.Writer.Error!void {
        assert(metrics.len <= metrics_max);
        var order: [metrics_max]usize = undefined;
        for (order[0..metrics.len], 0..) |*slot, index| slot.* = index;
        std.sort.insertion(usize, order[0..metrics.len], metrics, metric_less);
        try writer.writeAll("{\"benchmark\":");
        try write_json_string(writer, benchmark.name());
        try writer.writeAll(",\"commonware_bench_metrics\":true,\"metrics\":{");
        var written: usize = 0;
        for (order[0..metrics.len], 0..) |index, position| {
            // Sorting is stable, so the last of equal names comes last in its run.
            const next = position + 1;
            const metric = metrics[index];
            if (next < metrics.len and std.mem.eql(u8, metrics[order[next]].name, metric.name)) {
                continue;
            }
            if (written > 0) try writer.writeByte(',');
            try write_json_string(writer, metric.name);
            try writer.print(":{d}", .{metric.value});
            written += 1;
        }
        try writer.writeAll("}}");
        assert(written <= metrics.len);
    }
};

fn write_value(writer: *std.Io.Writer, value: anytype) std.Io.Writer.Error!void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .bool => try writer.writeAll(if (value) "true" else "false"),
        .int, .comptime_int, .float, .comptime_float => try writer.print("{d}", .{value}),
        .@"enum", .enum_literal => try writer.writeAll(@tagName(value)),
        .pointer => try writer.print("{s}", .{value}),
        else => @compileError("unsupported benchmark parameter type " ++ @typeName(T)),
    }
}

/// The most custom metrics one workload reports.
pub const metrics_max = 64;

/// A custom metric emitted by a benchmark workload.
pub const Metric = struct {
    name: []const u8,
    value: u64,

    pub fn init(name: []const u8, value: u64) Metric {
        return .{ .name = name, .value = value };
    }
};

fn metric_less(metrics: []const Metric, a: usize, b: usize) bool {
    return std.mem.order(u8, metrics[a].name, metrics[b].name) == .lt;
}

/// Writes `string` as a JSON string, escaping as serde_json does.
fn write_json_string(writer: *std.Io.Writer, string: []const u8) std.Io.Writer.Error!void {
    try writer.writeByte('"');
    for (string) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        0x08 => try writer.writeAll("\\b"),
        0x0c => try writer.writeAll("\\f"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0x00...0x07, 0x0b, 0x0e...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

/// Asserts at compile time that `W` implements the workload interface.
pub fn assert_workload(comptime W: type) void {
    comptime {
        if (!@hasDecl(W, "iter")) @compileError(@typeName(W) ++ " lacks Workload.iter");
    }
}

/// Calls the workload hook `hook` if `W` declares it, propagating its error.
pub fn call_hook(workload: anytype, comptime hook: []const u8) anyerror!void {
    const W = @typeInfo(@TypeOf(workload)).pointer.child;
    if (comptime !@hasDecl(W, hook)) return;
    const result = @field(W, hook)(workload);
    if (comptime @typeInfo(@TypeOf(result)) == .error_union) try result;
}

/// Runs one timed iteration and keeps its output from being optimized away.
pub fn call_iter(workload: anytype) anyerror!void {
    const W = @typeInfo(@TypeOf(workload)).pointer.child;
    const result = W.iter(workload);
    if (comptime @typeInfo(@TypeOf(result)) == .error_union) {
        std.mem.doNotOptimizeAway(try result);
    } else {
        std.mem.doNotOptimizeAway(result);
    }
}

/// Runs `workload` with Criterion's `iter_custom` timing model: `setup`, then `iters` times
/// `before_iter` (untimed) and `iter` (timed), then `teardown`. Returns the timed nanoseconds.
///
/// A workload without `before_iter` times its `iters` iterations as one batch between two
/// clock reads, as Criterion's `iter` does, so a nanosecond-scale `iter` is not floored at the
/// cost of a clock pair. With `before_iter`, each iteration is timed on its own.
pub fn criterion(io: std.Io, workload: anytype, iters: u64) anyerror!u64 {
    const W = @typeInfo(@TypeOf(workload)).pointer.child;
    assert_workload(W);
    assert(iters > 0);
    try call_hook(workload, "setup");
    var total_ns: u64 = 0;
    if (comptime !@hasDecl(W, "before_iter")) {
        const start = std.Io.Clock.awake.now(io);
        for (0..iters) |_| try call_iter(workload);
        total_ns = elapsed_ns(start, std.Io.Clock.awake.now(io));
    } else {
        for (0..iters) |_| {
            try call_hook(workload, "before_iter");
            const start = std.Io.Clock.awake.now(io);
            try call_iter(workload);
            total_ns +|= elapsed_ns(start, std.Io.Clock.awake.now(io));
        }
    }
    try call_hook(workload, "teardown");
    return total_ns;
}

fn elapsed_ns(start: std.Io.Timestamp, end: std.Io.Timestamp) u64 {
    const elapsed = end.nanoseconds - start.nanoseconds;
    assert(elapsed >= 0);
    return @intCast(elapsed);
}

const testing = std.testing;

test "detects criterion test mode" {
    const Case = struct { args: []const []const u8, expected: bool };
    const cases = [_]Case{
        .{ .args = &.{}, .expected = true },
        .{ .args = &.{"--verbose"}, .expected = true },
        .{ .args = &.{"--bench"}, .expected = false },
        .{ .args = &.{ "--bench", "--test" }, .expected = true },
        .{ .args = &.{"--list"}, .expected = false },
        .{ .args = &.{ "--bench", "--list" }, .expected = false },
        .{ .args = &.{ "--bench", "--profile-time", "5" }, .expected = false },
        .{ .args = &.{ "--profile-time", "5" }, .expected = true },
        .{ .args = &.{ "--", "--bench" }, .expected = true },
        .{ .args = &.{ "--bench", "--", "--test" }, .expected = false },
        .{ .args = &.{ "--bench", "--", "--list" }, .expected = false },
    };
    for (cases) |case| try testing.expectEqual(case.expected, test_mode(case.args));
    try testing.expectEqual(Inputs.full, Inputs.current(&.{}, "1"));
    try testing.expectEqual(Inputs.smoke, Inputs.current(&.{}, "0"));
    try testing.expectEqual(Inputs.standard, Inputs.current(&.{"--bench"}, null));
}

test "formats dynamic name" {
    const benchmark = Benchmark.init("qmdb::merkleize")
        .with_param("variant", "any::unordered::fixed::mmr")
        .with_param("keys", 10_000)
        .with_param("ch", false);
    try testing.expectEqualStrings(
        "qmdb::merkleize/variant=any::unordered::fixed::mmr keys=10000 ch=false",
        benchmark.name(),
    );
}

test "formats metric json line" {
    const benchmark = Benchmark.init("qmdb::merkleize").with_param("variant", "a");
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const metrics = [_]Metric{ .init("updates", 100), .init("keys", 1_000) };
    try benchmark.metrics_json(&writer, &metrics);
    try testing.expectEqualStrings(
        "{\"benchmark\":\"qmdb::merkleize/variant=a\",\"commonware_bench_metrics\":true," ++
            "\"metrics\":{\"keys\":1000,\"updates\":100}}",
        writer.buffered(),
    );
}

test "metric json escapes names and keeps the last duplicate" {
    const benchmark = Benchmark.init("a\"b\\c\n\x01");
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const metrics = [_]Metric{ .init("x", 1), .init("w", 5), .init("x", 2) };
    try benchmark.metrics_json(&writer, &metrics);
    try testing.expectEqualStrings(
        "{\"benchmark\":\"a\\\"b\\\\c\\n\\u0001\",\"commonware_bench_metrics\":true," ++
            "\"metrics\":{\"w\":5,\"x\":2}}",
        writer.buffered(),
    );
}

test "criterion times every iteration and runs hooks once" {
    const Counting = struct {
        setups: u32 = 0,
        befores: u32 = 0,
        iters: u32 = 0,
        teardowns: u32 = 0,

        pub fn setup(counting: *@This()) void {
            counting.setups += 1;
        }
        pub fn before_iter(counting: *@This()) !void {
            counting.befores += 1;
        }
        pub fn iter(counting: *@This()) u32 {
            counting.iters += 1;
            return counting.iters;
        }
        pub fn teardown(counting: *@This()) void {
            counting.teardowns += 1;
        }
    };
    var workload: Counting = .{};
    _ = try criterion(testing.io, &workload, 5);
    const expected: Counting = .{ .setups = 1, .befores = 5, .iters = 5, .teardowns = 1 };
    try testing.expectEqual(expected, workload);
}

test "criterion runs every iteration of a workload without before_iter" {
    const Plain = struct {
        setups: u32 = 0,
        iters: u32 = 0,
        teardowns: u32 = 0,
        pub fn setup(plain: *@This()) void {
            plain.setups += 1;
        }
        pub fn iter(plain: *@This()) u32 {
            plain.iters += 1;
            return plain.iters;
        }
        pub fn teardown(plain: *@This()) void {
            plain.teardowns += 1;
        }
    };
    var workload: Plain = .{};
    _ = try criterion(testing.io, &workload, 7);
    const expected: Plain = .{ .setups = 1, .iters = 7, .teardowns = 1 };
    try testing.expectEqual(expected, workload);
}

test {
    std.testing.refAllDecls(@This());
}
