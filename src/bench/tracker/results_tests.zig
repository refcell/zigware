//! Tests of output parsing, comparison, outputs, and the report, ported from commonware's
//! `bench/src/bin/tests.rs` with its fixtures.

const std = @import("std");
const testing = std.testing;
const toml = @import("toml.zig");
const config = @import("config.zig");
const output = @import("output.zig");
const results = @import("results.zig");
const render = @import("render.zig");

const Allocator = std.mem.Allocator;
const Benchmark = config.Benchmark;
const BenchResult = results.BenchResult;
const Metrics = output.Metrics;
const Diagnostic = toml.Diagnostic;

const fixture = @embedFile("testdata/gungraun-output.jsonl");
const custom_fixture = @embedFile("testdata/custom-metrics.jsonl");
const config_fixture = @embedFile("testdata/benchmark-tracking.toml");

const Context = struct {
    arena: std.heap.ArenaAllocator,
    diagnostic: Diagnostic = .{},

    fn init() Context {
        return .{ .arena = .init(testing.allocator) };
    }

    fn deinit(context: *Context) void {
        context.arena.deinit();
    }

    fn gpa(context: *Context) Allocator {
        return context.arena.allocator();
    }

    fn compare(
        context: *Context,
        current: []const BenchResult,
        baseline: []const BenchResult,
    ) ![]results.Comparison {
        return results.compare(context.gpa(), &context.diagnostic, current, baseline);
    }

    fn report(context: *Context, comparisons: []const results.Comparison) ![]u8 {
        return render.render_report(context.gpa(), comparisons);
    }

    fn write(
        context: *Context,
        dir: std.Io.Dir,
        current: []const BenchResult,
        comparisons: ?[]const results.Comparison,
    ) !void {
        const diagnostic = &context.diagnostic;
        try results.write_outputs(context.gpa(), testing.io, diagnostic, dir, current, comparisons);
    }

    fn load(context: *Context, dir: std.Io.Dir, path: ?[]const u8) ![]BenchResult {
        return results.load_baseline(context.gpa(), testing.io, &context.diagnostic, dir, path);
    }

    fn lines(context: *Context, text: []const u8) ![]output.Line {
        return output.parse_lines(context.gpa(), &context.diagnostic, text, "fixture");
    }

    fn benchmarks(context: *Context) ![]Benchmark {
        return config.load_config(context.gpa(), config_fixture, &context.diagnostic);
    }

    fn summaries(context: *Context) ![]const output.Summary {
        const parsed = try context.lines(fixture);
        var list: std.ArrayList(output.Summary) = .empty;
        for (parsed) |line| if (line == .summary) try list.append(context.gpa(), line.summary);
        return list.items;
    }

    /// A result for `benchmark` with `metrics`, or with the fixtures' metrics when null.
    fn result_for(context: *Context, benchmark: Benchmark, given_metrics: ?Metrics) !BenchResult {
        if (given_metrics) |given| return .{ .benchmark = benchmark, .metrics = given };
        const gpa_arena = context.gpa();
        var found: ?output.Summary = null;
        for (try context.summaries()) |summary| {
            if (summary.matches(gpa_arena, benchmark.filter)) found = found orelse summary;
        }
        var collected = try found.?.callgrind_metrics(
            gpa_arena,
            &context.diagnostic,
            &config.callgrind_metrics,
        );
        const custom = try context.lines(custom_fixture);
        const diagnostic = &context.diagnostic;
        const extra = try output.custom_metrics(gpa_arena, diagnostic, custom, benchmark.name);
        for (extra.items()) |entry| _ = try collected.put(gpa_arena, entry.name, entry.value);
        return .{ .benchmark = benchmark, .metrics = collected };
    }

    fn metrics_of(context: *Context, entries: []const output.Metrics.Entry) !Metrics {
        var map: Metrics = .{};
        for (entries) |entry| _ = try map.put(context.gpa(), entry.name, entry.value);
        return map;
    }

    /// Every callgrind metric set to 1.
    fn complete_metrics(context: *Context) !Metrics {
        var map: Metrics = .{};
        for (config.callgrind_metrics) |name| _ = try map.put(context.gpa(), name, 1);
        return map;
    }
};

fn custom_metric_benchmark() Benchmark {
    return .{
        .package = "commonware-storage",
        .target = "qmdb_gungraun",
        .name = "qmdb::merkleize/v=any::unordered::fixed::mmr k=10000 ch=false s=true cc=true",
        .filter = "*::bench_merkleize::any_unordered_fixed_mmr",
        .baseline_suite = "commonware-storage",
        .gates = &.{.{ .metric = "blob_reads", .direction = .down, .threshold_percent = 10.0 }},
    };
}

fn expect_contains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) return;
    std.debug.print("`{s}` not found in:\n{s}\n", .{ needle, haystack });
    return error.TestUnexpectedResult;
}

fn read(context: *Context, dir: std.Io.Dir, name: []const u8) ![]u8 {
    return dir.readFileAlloc(testing.io, name, context.gpa(), .unlimited);
}

test "parses and filters gungraun output" {
    var context: Context = .init();
    defer context.deinit();
    const summaries = try context.summaries();
    try testing.expectEqual(@as(usize, 2), summaries.len);
    const filter = "*::bench_merkleize::any_unordered_fixed_mmr";
    try testing.expect(summaries[0].matches(context.gpa(), filter));
    try testing.expect(!summaries[0].matches(context.gpa(), "*::missing"));
}

test "extracts selected callgrind metrics" {
    var context: Context = .init();
    defer context.deinit();
    const summaries = try context.summaries();
    const selected = &config.callgrind_metrics;
    const first = try summaries[0].callgrind_metrics(context.gpa(), &context.diagnostic, selected);
    try testing.expectEqual(@as(?u64, 1_000_000), first.get("Ir"));
    try testing.expectEqual(@as(?u64, 1_450_000), first.get("EstimatedCycles"));
    const second = try summaries[1].callgrind_metrics(context.gpa(), &context.diagnostic, selected);
    try testing.expectEqual(@as(?u64, 2_000_000), second.get("Ir"));
    try testing.expectEqual(@as(?u64, 2_550_000), second.get("EstimatedCycles"));
    const missing = summaries[0].callgrind_metrics(context.gpa(), &context.diagnostic, &.{"Nope"});
    try testing.expectError(error.Invalid, missing);
    try expect_contains(context.diagnostic.message(), "Gungraun result is missing `Nope`");
}

test "reads custom metrics from a jsonl file written by metrics_json" {
    var context: Context = .init();
    defer context.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const benchmark = (try context.benchmarks())[0];
    const line = try std.fmt.allocPrint(
        context.gpa(),
        "{{\"commonware_bench_metrics\":true,\"benchmark\":\"{s}\"," ++
            "\"metrics\":{{\"blob_reads\":12}}}}\n",
        .{benchmark.name},
    );
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "custom.jsonl", .data = line });
    const text = try read(&context, tmp.dir, "custom.jsonl");
    const lines = try context.lines(text);
    const diagnostic = &context.diagnostic;
    const metrics = try output.custom_metrics(context.gpa(), diagnostic, lines, benchmark.name);
    try testing.expectEqual(@as(?u64, 12), metrics.get("blob_reads"));
}

test "compares and renders a passing result" {
    var context: Context = .init();
    defer context.deinit();
    const current = try context.result_for((try context.benchmarks())[0], null);
    const comparisons = try context.compare(&.{current}, &.{current});
    const report = try context.report(comparisons);
    try testing.expect(!comparisons[0].regressed());
    try expect_contains(report, "Regressions: `0`.");
    try expect_contains(report, "2/2 gates passed");
    try expect_contains(report, "`EstimatedCycles`");
    try expect_contains(report, "| `Ir` | 1,000,000 | 1,000,000 | +0.00% | - |");
    try testing.expect(std.mem.indexOf(u8, report, "Missing baseline") == null);
}

test "a missing baseline warns without regression" {
    var context: Context = .init();
    defer context.deinit();
    const current = try context.result_for((try context.benchmarks())[0], null);
    const comparisons = try context.compare(&.{current}, &.{});
    const report = try context.report(comparisons);
    try testing.expect(!comparisons[0].regressed());
    try expect_contains(report, "Missing baseline");
    try expect_contains(report, "| `EstimatedCycles` | 1,450,000 |");
}

test "an estimated cycles regression writes the summary" {
    var context: Context = .init();
    defer context.deinit();
    const benchmark = (try context.benchmarks())[0];
    var baseline_metrics: Metrics = .{};
    for (try config.tracked_labels(context.gpa(), &.{benchmark})) |label| {
        _ = try baseline_metrics.put(context.gpa(), label, 1_000);
    }
    var current_metrics: Metrics = .{};
    for (baseline_metrics.items()) |entry| {
        _ = try current_metrics.put(context.gpa(), entry.name, entry.value);
    }
    _ = try current_metrics.put(context.gpa(), "EstimatedCycles", 1_111);
    const baseline = try context.result_for(benchmark, baseline_metrics);
    const current = try context.result_for(benchmark, current_metrics);
    const comparisons = try context.compare(&.{current}, &.{baseline});
    try testing.expect(comparisons[0].regressed());

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try context.write(tmp.dir, &.{current}, comparisons);
    try expect_contains(try read(&context, tmp.dir, "summary.toml"), "regression_count = 1");
}

test "a custom metric gate regresses" {
    var context: Context = .init();
    defer context.deinit();
    const benchmark = custom_metric_benchmark();
    var current_metrics = try context.complete_metrics();
    _ = try current_metrics.put(context.gpa(), "blob_reads", 111);
    const current = try context.result_for(benchmark, current_metrics);
    const baseline = try context.result_for(benchmark, try context.metrics_of(&.{
        .{ .name = "blob_reads", .value = 100 },
    }));
    const comparisons = try context.compare(&.{current}, &.{baseline});
    const report = try context.report(comparisons);
    try testing.expect(comparisons[0].regressed());
    try expect_contains(report, "blob_reads");
    try expect_contains(report, "Regressions: `1`.");

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try context.write(tmp.dir, &.{current}, comparisons);
    try expect_contains(try read(&context, tmp.dir, "current.toml"), "blob_reads = 111");
}

test "a zero baseline metric regresses when the current one increases" {
    var context: Context = .init();
    defer context.deinit();
    const benchmark = custom_metric_benchmark();
    var current_metrics = try context.complete_metrics();
    _ = try current_metrics.put(context.gpa(), "blob_reads", 1);
    const current = try context.result_for(benchmark, current_metrics);
    const baseline = try context.result_for(benchmark, try context.metrics_of(&.{
        .{ .name = "blob_reads", .value = 0 },
    }));
    const comparisons = try context.compare(&.{current}, &.{baseline});
    const report = try context.report(comparisons);
    try testing.expect(std.math.isInf(comparisons[0].deltas.get("blob_reads").?));
    try testing.expect(comparisons[0].regressed());
    try expect_contains(report, "Regressions: `1`.");
    try expect_contains(report, "| `blob_reads` | 0 | 1 | +inf% |");

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try context.write(tmp.dir, &.{current}, comparisons);
    const comparison = try read(&context, tmp.dir, "comparison.toml");
    try expect_contains(comparison, "blob_reads = \"inf\"");
    const failed = "\nfailed_gates = [{ metric = \"blob_reads\", direction = \"down\"";
    try expect_contains(comparison, failed);
    try expect_contains(comparison, "\nregressed = true\n");
    _ = try toml.parse(context.gpa(), comparison, &context.diagnostic);
    try expect_contains(try read(&context, tmp.dir, "summary.toml"), "regression_count = 1");
    try expect_contains(try read(&context, tmp.dir, "comment.md"), "Regressions: `1`.");
}

test "a missing custom metric baseline warns without regression" {
    var context: Context = .init();
    defer context.deinit();
    const benchmark = custom_metric_benchmark();
    const current = try context.result_for(benchmark, try context.metrics_of(&.{
        .{ .name = "blob_reads", .value = 111 },
    }));
    const baseline = try context.result_for(benchmark, try context.metrics_of(&.{
        .{ .name = "EstimatedCycles", .value = 100 },
    }));
    const comparisons = try context.compare(&.{current}, &.{baseline});
    const report = try context.report(comparisons);
    try testing.expect(!comparisons[0].regressed());
    try expect_contains(report, "that gate was not evaluated");
    try expect_contains(report, "| `blob_reads` | n/a | 111 | n/a |");
}

test "rejects invalid baseline fields while deserializing" {
    var context: Context = .init();
    defer context.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const baseline =
        \\[[benchmarks]]
        \\package = ""
        \\target = "qmdb_gungraun"
        \\name = "qmdb::merkleize/variant=empty"
        \\filter = "*"
        \\baseline_suite = "commonware-storage"
        \\gates = [{ metric = "EstimatedCycles", direction = "down", threshold_percent = 10 }]
        \\
        \\[benchmarks.metrics]
        \\Ir = 1
        \\L1hits = 1
        \\LLhits = 1
        \\RamHits = 1
        \\TotalRW = 1
        \\EstimatedCycles = 1
    ;
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "current.toml", .data = baseline });
    const loaded = context.load(tmp.dir, "current.toml");
    try testing.expectError(error.Invalid, loaded);
    try expect_contains(context.diagnostic.message(), "must be a non-empty string");

    // No path, or a path to no file, is an empty baseline.
    const none = try context.load(tmp.dir, null);
    try testing.expectEqual(@as(usize, 0), none.len);
    const absent = try context.load(tmp.dir, "x");
    try testing.expectEqual(@as(usize, 0), absent.len);
}

test "a written current file can be loaded as a baseline" {
    var context: Context = .init();
    defer context.deinit();
    var current = try context.result_for((try context.benchmarks())[0], null);
    current.commit = "0123456789abcdef";
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try context.write(tmp.dir, &.{current}, null);
    const baseline = try context.load(tmp.dir, "current.toml");
    try testing.expectEqual(@as(usize, 1), baseline.len);
    try testing.expectEqualStrings("0123456789abcdef", baseline[0].commit);
    try testing.expectEqual(current.benchmark.gates.len, baseline[0].benchmark.gates.len);
    try testing.expectEqualStrings("--features", baseline[0].benchmark.cargo_flags[0]);
    const comparisons = try context.compare(&.{current}, baseline);
    try testing.expectEqual(@as(?f64, 0.0), comparisons[0].deltas.get("EstimatedCycles"));
    const report = try context.report(comparisons);
    try expect_contains(report, "Baseline commit(s): `0123456789ab`");
    // Without comparisons, no comparison or report is written.
    try testing.expectError(error.FileNotFound, read(&context, tmp.dir, "comment.md"));
}

test "generate rejects a missing gate metric" {
    var context: Context = .init();
    defer context.deinit();
    const complete = try context.complete_metrics();
    const current = try context.result_for(custom_metric_benchmark(), complete);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const written = context.write(tmp.dir, &.{current}, null);
    try testing.expectError(error.Invalid, written);
    try expect_contains(context.diagnostic.message(), "missing `blob_reads`");
    try testing.expectError(error.FileNotFound, read(&context, tmp.dir, "current.toml"));
}

test "glob matches like the glob crate" {
    const cases = [_]struct { pattern: []const u8, text: []const u8, matches: bool }{
        .{ .pattern = "*", .text = "", .matches = true },
        .{ .pattern = "*::b", .text = "a::x::b", .matches = true },
        .{ .pattern = "a?c", .text = "abc", .matches = true },
        .{ .pattern = "a?c", .text = "ac", .matches = false },
        .{ .pattern = "[a-c]x", .text = "bx", .matches = true },
        .{ .pattern = "[!a-c]x", .text = "bx", .matches = false },
        .{ .pattern = "[]]", .text = "]", .matches = true },
        .{ .pattern = "*a*a*a", .text = "aaaaaaaaab", .matches = false },
        .{ .pattern = "[ab", .text = "a", .matches = false },
    };
    for (cases) |case| {
        try testing.expectEqual(case.matches, output.glob(case.pattern, case.text));
    }
}
