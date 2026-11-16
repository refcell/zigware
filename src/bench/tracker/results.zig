//! Benchmark results, their comparison with a baseline, and the files the tracker writes
//! (commonware's `bench/src/bin/results.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const toml = @import("toml.zig");
const config = @import("config.zig");
const output = @import("output.zig");
const render = @import("render.zig");

const Benchmark = config.Benchmark;
const Gate = config.Gate;
const Metrics = output.Metrics;
const Diagnostic = toml.Diagnostic;
const Writer = std.Io.Writer;
pub const Error = toml.Error;
pub const Deltas = output.Map(f64);

pub const BenchResult = struct {
    benchmark: Benchmark,
    metrics: Metrics,
    commit: []const u8 = "",
    run_id: []const u8 = "",
    ref_name: []const u8 = "",

    /// Fails unless every tracked label (callgrind metrics and gate metrics) has a value.
    pub fn validate(
        result: *const BenchResult,
        gpa: Allocator,
        diagnostic: *Diagnostic,
    ) Error!void {
        const labels = try config.tracked_labels(gpa, (&result.benchmark)[0..1]);
        for (labels) |label| {
            if (result.metrics.contains(label)) continue;
            return diagnostic.fail("benchmark `{s}` is missing `{s}`", .{
                result.benchmark.name,
                label,
            });
        }
    }
};

pub const Comparison = struct {
    current: BenchResult,
    baseline: ?BenchResult,
    deltas: Deltas,

    /// Whether `gate` fails against the baseline (never without one).
    pub fn gate_failed(comparison: *const Comparison, gate: Gate) bool {
        if (comparison.baseline == null) return false;
        const delta = comparison.deltas.get(gate.label()) orelse return false;
        return gate.failed(delta);
    }

    pub fn failed_gate_count(comparison: *const Comparison) usize {
        var count: usize = 0;
        for (comparison.current.benchmark.gates) |gate| {
            count += @intFromBool(comparison.gate_failed(gate));
        }
        return count;
    }

    pub fn regressed(comparison: *const Comparison) bool {
        return comparison.failed_gate_count() > 0;
    }
};

pub fn regression_count(comparisons: []const Comparison) usize {
    var count: usize = 0;
    for (comparisons) |*comparison| count += @intFromBool(comparison.regressed());
    return count;
}

/// The baseline result for `benchmark`, if any.
pub fn find(baseline: []const BenchResult, benchmark: Benchmark) ?BenchResult {
    for (baseline) |result| {
        if (result.benchmark.same_key(benchmark)) return result;
    }
    return null;
}

/// Loads the baseline at `path` in `dir`; no path or a missing file is an empty baseline.
pub fn load_baseline(
    gpa: Allocator,
    io: std.Io,
    diagnostic: *Diagnostic,
    dir: std.Io.Dir,
    path: ?[]const u8,
) Error![]BenchResult {
    const file_path = path orelse return &.{};
    const input = dir.readFileAlloc(io, file_path, gpa, .unlimited) catch |err| {
        if (err == error.FileNotFound) return &.{};
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return diagnostic.fail("read baseline `{s}`: {t}", .{ file_path, err });
    };
    return parse_baseline(gpa, diagnostic, input, file_path);
}

/// Parses a baseline (a written `current.toml`); `name` labels errors.
pub fn parse_baseline(
    gpa: Allocator,
    diagnostic: *Diagnostic,
    input: []const u8,
    name: []const u8,
) Error![]BenchResult {
    const root = toml.parse(gpa, input, diagnostic) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return diagnostic.fail("baseline `{s}` must contain a `benchmarks` array", .{name});
    };
    const items = config.tables(diagnostic, root, "benchmarks") catch
        return diagnostic.fail("baseline `{s}` must contain a `benchmarks` array", .{name});
    var baseline: std.ArrayList(BenchResult) = .empty;
    for (items) |item| {
        const result = try decode_result(gpa, diagnostic, item.table);
        try result.validate(gpa, diagnostic);
        // A later entry with the same key replaces an earlier one, as in a map.
        for (baseline.items) |*existing| {
            if (existing.benchmark.same_key(result.benchmark)) {
                existing.* = result;
                break;
            }
        } else try baseline.append(gpa, result);
    }
    return baseline.items;
}

fn decode_result(
    gpa: Allocator,
    diagnostic: *Diagnostic,
    table: *const toml.Table,
) Error!BenchResult {
    const benchmark = try config.decode_benchmark(gpa, diagnostic, table);
    const metrics_value = table.get("metrics") orelse
        return diagnostic.fail("missing field `metrics`", .{});
    if (metrics_value != .table) return diagnostic.fail("`metrics` must be a table", .{});
    const metrics_table = metrics_value.table;
    var metrics: Metrics = .{};
    for (metrics_table.keys.items, metrics_table.values.items) |name, value| {
        if (value != .integer or value.integer < 0) {
            return diagnostic.fail("metric `{s}` must be a non-negative integer", .{name});
        }
        _ = try metrics.put(gpa, name, @intCast(value.integer));
    }
    return .{
        .benchmark = benchmark,
        .metrics = metrics,
        .commit = try plain_string(diagnostic, table, "commit"),
        .run_id = try plain_string(diagnostic, table, "run_id"),
        .ref_name = try plain_string(diagnostic, table, "ref"),
    };
}

fn plain_string(diagnostic: *Diagnostic, table: *const toml.Table, key: []const u8) ![]const u8 {
    const value = table.get(key) orelse return "";
    if (value != .string) return diagnostic.fail("`{s}` must be a string", .{key});
    return value.string;
}

/// Compares each current result with its baseline entry, if any.
pub fn compare(
    gpa: Allocator,
    diagnostic: *Diagnostic,
    current: []const BenchResult,
    baseline: []const BenchResult,
) Error![]Comparison {
    const comparisons = try gpa.alloc(Comparison, current.len);
    for (current, comparisons) |result, *comparison| {
        for (result.benchmark.gates) |gate| {
            if (result.metrics.contains(gate.label())) continue;
            return diagnostic.fail("current result `{s}` is missing `{s}`", .{
                result.benchmark.name,
                gate.label(),
            });
        }
        comparison.* = .{ .current = result, .baseline = null, .deltas = .{} };
        const previous = find(baseline, result.benchmark) orelse continue;
        comparison.baseline = previous;
        for (try display_metrics(gpa, &result, &previous)) |metric| {
            const now = result.metrics.get(metric) orelse continue;
            const before = previous.metrics.get(metric) orelse continue;
            _ = try comparison.deltas.put(gpa, metric, percent_delta(now, before));
        }
    }
    return comparisons;
}

/// The tracked labels, then any other metric of `current` or `baseline`, each once.
pub fn display_metrics(
    gpa: Allocator,
    current: *const BenchResult,
    baseline: ?*const BenchResult,
) Allocator.Error![]const []const u8 {
    var metrics: std.ArrayList([]const u8) = .empty;
    try metrics.appendSlice(gpa, try config.tracked_labels(gpa, (&current.benchmark)[0..1]));
    const sources = [_]?*const BenchResult{ current, baseline };
    for (sources) |source| {
        const result = source orelse continue;
        for (result.metrics.items()) |entry| {
            if (config.contains(metrics.items, entry.name)) continue;
            try metrics.append(gpa, entry.name);
        }
    }
    return metrics.items;
}

/// The change from `baseline` to `current` in percent; infinite from a zero baseline.
pub fn percent_delta(current: u64, baseline: u64) f64 {
    if (baseline == 0) return if (current == 0) 0.0 else std.math.inf(f64);
    const now: f64 = @floatFromInt(current);
    const before: f64 = @floatFromInt(baseline);
    return (now - before) / before * 100.0;
}

/// Validates `current`, then writes `current.toml`, `summary.toml`, and, with comparisons,
/// `comparison.toml` and `comment.md` into `dir`. Nothing is written if validation fails.
pub fn write_outputs(
    gpa: Allocator,
    io: std.Io,
    diagnostic: *Diagnostic,
    dir: std.Io.Dir,
    current: []const BenchResult,
    comparisons: ?[]const Comparison,
) Error!void {
    for (current) |*result| try result.validate(gpa, diagnostic);
    const files = try render_outputs(gpa, current, comparisons);
    for (files) |file| {
        const contents = file.contents orelse continue;
        dir.writeFile(io, .{ .sub_path = file.name, .data = contents }) catch |err|
            return diagnostic.fail("write `{s}`: {t}", .{ file.name, err });
    }
}

pub const File = struct { name: []const u8, contents: ?[]const u8 };

/// The tracker's output files: `current.toml`, `comparison.toml`, `comment.md`, and
/// `summary.toml`, the middle two only with comparisons.
pub fn render_outputs(
    gpa: Allocator,
    current: []const BenchResult,
    comparisons: ?[]const Comparison,
) Allocator.Error![4]File {
    var files: [4]File = .{
        .{ .name = "current.toml", .contents = null },
        .{ .name = "comparison.toml", .contents = null },
        .{ .name = "comment.md", .contents = null },
        .{ .name = "summary.toml", .contents = null },
    };
    var buffer: Writer.Allocating = .init(gpa);
    write_current(&buffer.writer, current) catch return error.OutOfMemory;
    files[0].contents = try buffer.toOwnedSlice();
    if (comparisons) |items| {
        write_comparisons(&buffer.writer, items) catch return error.OutOfMemory;
        files[1].contents = try buffer.toOwnedSlice();
        files[2].contents = try render.render_report(gpa, items);
    }
    const benchmarks = try gpa.alloc(Benchmark, current.len);
    for (current, benchmarks) |result, *benchmark| benchmark.* = result.benchmark;
    const labels = try config.tracked_labels(gpa, benchmarks);
    write_summary(&buffer.writer, current.len, labels, comparisons) catch return error.OutOfMemory;
    files[3].contents = try buffer.toOwnedSlice();
    return files;
}

fn write_current(writer: *Writer, current: []const BenchResult) Writer.Error!void {
    for (current, 0..) |result, index| {
        if (index > 0) try writer.writeByte('\n');
        try writer.writeAll("[[benchmarks]]\n");
        try write_result_fields(writer, result);
        try writer.writeAll("\n[benchmarks.metrics]\n");
        try write_metrics(writer, result.metrics);
    }
}

/// The benchmark's fields and the result's provenance, as plain keys of the current table.
fn write_result_fields(writer: *Writer, result: BenchResult) Writer.Error!void {
    const benchmark = result.benchmark;
    const fields = [_][2][]const u8{
        .{ "package", benchmark.package },
        .{ "target", benchmark.target },
        .{ "name", benchmark.name },
        .{ "filter", benchmark.filter },
        .{ "baseline_suite", benchmark.baseline_suite },
    };
    for (fields) |entry| try write_string_field(writer, entry[0], entry[1]);
    try writer.writeAll("cargo_flags = ");
    try toml.write_strings(writer, benchmark.cargo_flags);
    try writer.writeAll("\ngates = ");
    try write_gates(writer, benchmark.gates);
    try writer.writeByte('\n');
    const provenance = [_][2][]const u8{
        .{ "commit", result.commit },
        .{ "run_id", result.run_id },
        .{ "ref", result.ref_name },
    };
    for (provenance) |entry| {
        if (entry[1].len > 0) try write_string_field(writer, entry[0], entry[1]);
    }
}

fn write_string_field(writer: *Writer, key: []const u8, value: []const u8) Writer.Error!void {
    try toml.write_key(writer, key);
    try writer.writeAll(" = ");
    try toml.write_string(writer, value);
    try writer.writeByte('\n');
}

fn write_gates(writer: *Writer, gates: []const Gate) Writer.Error!void {
    try writer.writeByte('[');
    for (gates, 0..) |gate, index| {
        if (index > 0) try writer.writeAll(", ");
        try write_gate(writer, gate);
    }
    try writer.writeByte(']');
}

/// Writes `gate` as an inline table.
fn write_gate(writer: *Writer, gate: Gate) Writer.Error!void {
    try writer.writeAll("{ metric = ");
    try toml.write_string(writer, gate.metric);
    try writer.print(", direction = \"{t}\", threshold_percent = ", .{gate.direction});
    try toml.write_float(writer, gate.threshold_percent);
    try writer.writeAll(" }");
}

fn write_metrics(writer: *Writer, metrics: Metrics) Writer.Error!void {
    for (metrics.items()) |entry| {
        try toml.write_key(writer, entry.name);
        try writer.print(" = {d}\n", .{entry.value});
    }
}

fn write_comparisons(writer: *Writer, comparisons: []const Comparison) Writer.Error!void {
    for (comparisons, 0..) |*comparison, index| {
        if (index > 0) try writer.writeByte('\n');
        try writer.writeAll("[[comparisons]]\n");
        try write_result_fields(writer, comparison.current);
        try writer.writeAll("failed_gates = [");
        var written: usize = 0;
        for (comparison.current.benchmark.gates) |gate| {
            if (!comparison.gate_failed(gate)) continue;
            if (written > 0) try writer.writeAll(", ");
            try write_gate(writer, gate);
            written += 1;
        }
        try writer.writeAll("]\n");
        if (comparison.baseline != null) {
            try writer.print("regressed = {}\n", .{comparison.regressed()});
        }
        try writer.writeAll("\n[comparisons.metrics]\n");
        try write_metrics(writer, comparison.current.metrics);
        try writer.writeAll("\n[comparisons.metric_deltas]\n");
        for (comparison.deltas.items()) |entry| {
            try toml.write_key(writer, entry.name);
            try writer.writeAll(" = ");
            // Non-finite deltas are strings, as commonware writes them.
            if (std.math.isFinite(entry.value)) {
                try toml.write_float(writer, entry.value);
            } else {
                try writer.writeByte('"');
                try toml.write_float(writer, entry.value);
                try writer.writeByte('"');
            }
            try writer.writeByte('\n');
        }
        const baseline = comparison.baseline orelse continue;
        try writer.writeAll("\n[comparisons.baseline_metrics]\n");
        try write_metrics(writer, baseline.metrics);
    }
}

fn write_summary(
    writer: *Writer,
    count: usize,
    labels: []const []const u8,
    comparisons: ?[]const Comparison,
) Writer.Error!void {
    try writer.print("benchmark_count = {d}\nmetrics = ", .{count});
    try toml.write_strings(writer, labels);
    try writer.writeByte('\n');
    const items = comparisons orelse return;
    try writer.print("regression_count = {d}\n", .{regression_count(items)});
}
