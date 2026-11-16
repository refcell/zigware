//! The Markdown report the tracker posts (commonware's `bench/src/bin/render.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const config = @import("config.zig");
const results = @import("results.zig");

const Benchmark = config.Benchmark;
const Comparison = results.Comparison;
const Writer = std.Io.Writer;

pub const comment_marker = "<!-- commonware-benchmark-tracking-results -->";

/// The report for `comparisons`, ending with a new line.
pub fn render_report(gpa: Allocator, comparisons: []const Comparison) Allocator.Error![]u8 {
    var buffer: Writer.Allocating = .init(gpa);
    write_report(gpa, &buffer.writer, comparisons) catch return error.OutOfMemory;
    return buffer.toOwnedSlice();
}

fn write_report(gpa: Allocator, writer: *Writer, comparisons: []const Comparison) !void {
    try writer.print("{s}\n## Benchmark results\n\nRegressions: `{d}`.\n", .{
        comment_marker,
        results.regression_count(comparisons),
    });
    try write_warnings(writer, comparisons);
    for (comparisons) |*item| {
        try writer.writeAll("\n<details><summary>");
        try write_summary_line(writer, item);
        try writer.writeAll("</summary>\n\n");
        try write_metadata(writer, item.current.benchmark);
        try write_metrics(gpa, writer, item);
        try writer.writeAll("\n</details>\n");
    }
    try write_commits(gpa, writer, comparisons);
}

fn write_warnings(writer: *Writer, comparisons: []const Comparison) Writer.Error!void {
    var any = false;
    for (comparisons) |item| {
        const name = item.current.benchmark.name;
        const baseline = item.baseline orelse {
            try warning_start(writer, &any);
            try writer.print("> Missing baseline for `{s}`.\n", .{name});
            continue;
        };
        for (item.current.benchmark.gates) |gate| {
            if (baseline.metrics.contains(gate.label())) continue;
            try warning_start(writer, &any);
            try writer.print(
                "> Baseline for `{s}` is missing `{s}`; that gate was not evaluated.\n",
                .{ name, gate.label() },
            );
        }
    }
}

fn warning_start(writer: *Writer, any: *bool) Writer.Error!void {
    if (any.*) return;
    any.* = true;
    try writer.writeAll("\n> [!WARNING]\n>\n");
}

fn write_summary_line(writer: *Writer, item: *const Comparison) Writer.Error!void {
    const name = item.current.benchmark.name;
    if (item.baseline == null) {
        try writer.writeAll("\u{26a0}\u{fe0f} `");
        try write_escaped_summary(writer, name);
        return writer.writeAll("` (baseline missing)");
    }
    try writer.writeAll(if (item.regressed()) "\u{274c} `" else "\u{2705} `");
    try write_escaped_summary(writer, name);
    try writer.writeAll("` (");
    const gates = item.current.benchmark.gates;
    if (gates.len == 1) {
        const gate = gates[0];
        try writer.print("{s}: ", .{gate.label()});
        // `compare` checked that the current result has every gate's metric.
        try write_count(writer, item.current.metrics.get(gate.label()).?);
        try writer.writeAll(", delta: ");
        try write_optional_delta(writer, item.deltas.get(gate.label()));
        try writer.writeAll(", ");
        try gate.write_description(writer);
    } else {
        const failed = item.failed_gate_count();
        try writer.print("{d}/{d} gates passed", .{ gates.len - failed, gates.len });
    }
    try writer.writeByte(')');
}

fn write_metadata(writer: *Writer, benchmark: Benchmark) Writer.Error!void {
    try writer.writeAll("| Field | Value |\n|---|---|\n");
    const rows = [_][2][]const u8{
        .{ "Package", benchmark.package },
        .{ "Benchmark target", benchmark.target },
        .{ "Variant", benchmark.name },
        .{ "Filter", benchmark.filter },
        .{ "Baseline suite", benchmark.baseline_suite },
    };
    for (rows) |row| {
        try writer.print("| {s} | `", .{row[0]});
        try write_escaped_cell(writer, row[1]);
        try writer.writeAll("` |\n");
    }
    try writer.writeAll("| Gates | `");
    for (benchmark.gates, 0..) |gate, index| {
        if (index > 0) try writer.writeAll("; ");
        var description: [256]u8 = undefined;
        var fixed: Writer = .fixed(&description);
        try gate.write_description(&fixed);
        try write_escaped_cell(writer, fixed.buffered());
    }
    try writer.writeAll("` |\n");
    if (benchmark.cargo_flags.len == 0) return;
    try writer.writeAll("| Cargo flags | `");
    for (benchmark.cargo_flags, 0..) |flag, index| {
        if (index > 0) try writer.writeByte(' ');
        try write_escaped_cell(writer, flag);
    }
    try writer.writeAll("` |\n");
}

fn write_metrics(gpa: Allocator, writer: *Writer, item: *const Comparison) !void {
    const current = &item.current;
    if (item.baseline) |*baseline| {
        try writer.writeAll("\n| Metric | Baseline | Current | Delta | Gate |\n");
        try writer.writeAll("|---|---:|---:|---:|---|\n");
        for (try results.display_metrics(gpa, current, baseline)) |metric| {
            try writer.print("| `{s}` | ", .{metric});
            try write_optional_count(writer, baseline.metrics.get(metric));
            try writer.writeAll(" | ");
            try write_optional_count(writer, current.metrics.get(metric));
            try writer.writeAll(" | ");
            try write_optional_delta(writer, item.deltas.get(metric));
            try writer.writeAll(" | ");
            try write_gate_text(writer, current.benchmark, metric);
            try writer.writeAll(" |\n");
        }
        return;
    }
    try writer.writeAll("\n| Metric | Current | Gate |\n|---|---:|---|\n");
    for (try results.display_metrics(gpa, current, null)) |metric| {
        const value = current.metrics.get(metric) orelse continue;
        try writer.print("| `{s}` | ", .{metric});
        try write_count(writer, value);
        try writer.writeAll(" | ");
        try write_gate_text(writer, current.benchmark, metric);
        try writer.writeAll(" |\n");
    }
}

fn write_commits(gpa: Allocator, writer: *Writer, comparisons: []const Comparison) !void {
    var commits: std.ArrayList([]const u8) = .empty;
    for (comparisons) |item| {
        const baseline = item.baseline orelse continue;
        if (baseline.commit.len == 0) continue;
        // The first 12 characters, as commonware takes 12 chars of a hex commit.
        const short = baseline.commit[0..@min(baseline.commit.len, 12)];
        if (config.contains(commits.items, short)) continue;
        try commits.append(gpa, short);
    }
    if (commits.items.len > 0) {
        std.sort.pdq([]const u8, commits.items, {}, less_than);
        try writer.writeAll("\nBaseline commit(s): `");
        for (commits.items, 0..) |commit, index| {
            if (index > 0) try writer.writeAll(", ");
            try writer.writeAll(commit);
        }
        try writer.writeAll("`\n");
    }
}

fn less_than(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn write_gate_text(writer: *Writer, benchmark: Benchmark, metric: []const u8) Writer.Error!void {
    var any = false;
    for (benchmark.gates) |gate| {
        if (!std.mem.eql(u8, gate.label(), metric)) continue;
        if (any) try writer.writeAll("<br>");
        any = true;
        try gate.write_description(writer);
    }
    if (!any) try writer.writeByte('-');
}

fn write_optional_count(writer: *Writer, value: ?u64) Writer.Error!void {
    if (value) |count| return write_count(writer, count);
    try writer.writeAll("n/a");
}

/// Writes `value` with thousands separators: `1,450,000`.
pub fn write_count(writer: *Writer, value: u64) Writer.Error!void {
    var digits: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{value}) catch unreachable; // 20 digits fit.
    for (text, 0..) |digit, index| {
        if (index > 0 and (text.len - index) % 3 == 0) try writer.writeByte(',');
        try writer.writeByte(digit);
    }
}

fn write_optional_delta(writer: *Writer, value: ?f64) Writer.Error!void {
    if (value) |delta| return write_delta(writer, delta);
    try writer.writeAll("n/a");
}

/// Writes `value` with a sign and two decimals, as Rust's `{:+.2}%`: `+0.00%`, `+inf%`.
pub fn write_delta(writer: *Writer, value: f64) Writer.Error!void {
    if (std.math.isNan(value)) return writer.writeAll("NaN%");
    const sign: u8 = if (std.math.signbit(value)) '-' else '+';
    try writer.writeByte(sign);
    if (std.math.isInf(value)) return writer.writeAll("inf%");
    try writer.print("{d:.2}%", .{@abs(value)});
}

fn write_escaped_cell(writer: *Writer, value: []const u8) Writer.Error!void {
    for (value) |char| switch (char) {
        '|' => try writer.writeAll("\\|"),
        '\n' => try writer.writeAll("<br>"),
        else => try writer.writeByte(char),
    };
}

fn write_escaped_summary(writer: *Writer, value: []const u8) Writer.Error!void {
    for (value) |char| switch (char) {
        '&' => try writer.writeAll("&amp;"),
        '<' => try writer.writeAll("&lt;"),
        '>' => try writer.writeAll("&gt;"),
        '\n' => try writer.writeByte(' '),
        else => try writer.writeByte(char),
    };
}

test "counts take thousands separators and deltas a sign" {
    var buffer: [64]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    for ([_]u64{ 0, 999, 1000, 1_450_000, std.math.maxInt(u64) }) |value| {
        try write_count(&writer, value);
        try writer.writeByte(' ');
    }
    try std.testing.expectEqualStrings(
        "0 999 1,000 1,450,000 18,446,744,073,709,551,615 ",
        writer.buffered(),
    );
    writer = .fixed(&buffer);
    for ([_]f64{ 0, 11.1, -3.456, std.math.inf(f64), -std.math.inf(f64) }) |value| {
        try write_delta(&writer, value);
        try writer.writeByte(' ');
    }
    try std.testing.expectEqualStrings("+0.00% +11.10% -3.46% +inf% -inf% ", writer.buffered());
    assert(comment_marker.len > 0);
}
