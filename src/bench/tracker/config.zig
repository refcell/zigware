//! The tracker's configuration (commonware's `bench/src/bin/config.rs`): packages, their bench
//! targets, the variants tracked in each, and the regression gates, which a variant inherits
//! from its target, package, or the file unless it sets its own.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const toml = @import("toml.zig");

const Table = toml.Table;
const Value = toml.Value;
const Diagnostic = toml.Diagnostic;
pub const Error = toml.Error;

/// The metrics a callgrind (Gungraun) run reports for every benchmark.
pub const callgrind_metrics = [_][]const u8{
    "Ir",
    "L1hits",
    "LLhits",
    "RamHits",
    "TotalRW",
    "EstimatedCycles",
};

/// The direction a metric is expected to move.
pub const Direction = enum { down, up };

pub const Gate = struct {
    metric: []const u8,
    direction: Direction,
    threshold_percent: f64,

    /// The gate used when a file sets none.
    pub const default: Gate = .{
        .metric = "EstimatedCycles",
        .direction = .down,
        .threshold_percent = 10.0,
    };

    pub fn label(gate: Gate) []const u8 {
        return gate.metric;
    }

    /// Writes `<metric> should <decrease|increase>; tolerance <threshold>%`.
    pub fn write_description(gate: Gate, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const movement = switch (gate.direction) {
            .down => "decrease",
            .up => "increase",
        };
        try writer.print("{s} should {s}; tolerance {d:.2}%", .{
            gate.metric,
            movement,
            gate.threshold_percent,
        });
    }

    /// Whether a change of `delta` percent breaks the gate.
    pub fn failed(gate: Gate, delta: f64) bool {
        assert(gate.threshold_percent >= 0);
        return switch (gate.direction) {
            .down => delta > gate.threshold_percent,
            .up => delta < -gate.threshold_percent,
        };
    }
};

/// One tracked benchmark variant.
pub const Benchmark = struct {
    package: []const u8,
    target: []const u8,
    name: []const u8,
    filter: []const u8,
    baseline_suite: []const u8,
    cargo_flags: []const []const u8 = &.{},
    gates: []const Gate,

    /// Whether `a` and `b` share a baseline entry: the same suite and name.
    pub fn same_key(a: Benchmark, b: Benchmark) bool {
        return std.mem.eql(u8, a.baseline_suite, b.baseline_suite) and
            std.mem.eql(u8, a.name, b.name);
    }
};

/// Loads every benchmark the configuration in `input` tracks.
pub fn load_config(gpa: Allocator, input: []const u8, diagnostic: *Diagnostic) Error![]Benchmark {
    const root = try toml.parse(gpa, input, diagnostic);
    try check_fields(diagnostic, root, &.{ "gates", "packages" });
    const default_gates: []const Gate = &.{Gate.default};
    const config_gates = try optional_gates(gpa, diagnostic, root) orelse default_gates;
    var benchmarks: std.ArrayList(Benchmark) = .empty;
    const fields = &.{ "name", "baseline_suite", "cargo_flags", "gates", "benchmarks" };
    for (try tables(diagnostic, root, "packages")) |package_value| {
        const package = package_value.table;
        try check_fields(diagnostic, package, fields);
        const name = try required_string(diagnostic, package, "name");
        const package_gates = try optional_gates(gpa, diagnostic, package) orelse config_gates;
        const prototype: Benchmark = .{
            .package = name,
            .target = undefined,
            .name = undefined,
            .filter = undefined,
            .baseline_suite = try optional_string(diagnostic, package, "baseline_suite") orelse
                name,
            .cargo_flags = try strings(gpa, diagnostic, package, "cargo_flags"),
            .gates = package_gates,
        };
        for (try tables(diagnostic, package, "benchmarks")) |target| {
            try load_target(gpa, diagnostic, target.table, prototype, &benchmarks);
        }
    }
    return benchmarks.items;
}

fn load_target(
    gpa: Allocator,
    diagnostic: *Diagnostic,
    target: *const Table,
    prototype: Benchmark,
    benchmarks: *std.ArrayList(Benchmark),
) Error!void {
    try check_fields(diagnostic, target, &.{ "name", "gates", "variants" });
    var base = prototype;
    base.target = try required_string(diagnostic, target, "name");
    const target_gates = try optional_gates(gpa, diagnostic, target) orelse prototype.gates;
    for (try tables(diagnostic, target, "variants")) |variant_value| {
        const variant = variant_value.table;
        try check_fields(diagnostic, variant, &.{ "name", "filter", "gates" });
        var benchmark = base;
        benchmark.name = try required_string(diagnostic, variant, "name");
        benchmark.filter = try required_string(diagnostic, variant, "filter");
        benchmark.gates = try optional_gates(gpa, diagnostic, variant) orelse target_gates;
        for (benchmarks.items) |existing| {
            if (existing.same_key(benchmark)) {
                return diagnostic.fail("duplicate benchmark `{s}`", .{benchmark.name});
            }
        }
        try benchmarks.append(gpa, benchmark);
    }
}

/// Decodes a benchmark written into a results file. Fields it does not know are ignored, as
/// commonware's flattened results ignore them.
pub fn decode_benchmark(
    gpa: Allocator,
    diagnostic: *Diagnostic,
    table: *const Table,
) Error!Benchmark {
    const gates = try optional_gates(gpa, diagnostic, table) orelse
        return diagnostic.fail("missing field `gates`", .{});
    return .{
        .package = try required_string(diagnostic, table, "package"),
        .target = try required_string(diagnostic, table, "target"),
        .name = try required_string(diagnostic, table, "name"),
        .filter = try required_string(diagnostic, table, "filter"),
        .baseline_suite = try required_string(diagnostic, table, "baseline_suite"),
        .cargo_flags = try strings(gpa, diagnostic, table, "cargo_flags"),
        .gates = gates,
    };
}

/// The callgrind metrics, then every gate's metric not among them, each once.
pub fn tracked_labels(gpa: Allocator, benchmarks: []const Benchmark) Allocator.Error![][]const u8 {
    var labels: std.ArrayList([]const u8) = .empty;
    try labels.appendSlice(gpa, &callgrind_metrics);
    for (benchmarks) |benchmark| {
        for (benchmark.gates) |gate| {
            if (contains(labels.items, gate.label())) continue;
            try labels.append(gpa, gate.label());
        }
    }
    assert(labels.items.len >= callgrind_metrics.len);
    return labels.items;
}

pub fn contains(labels: []const []const u8, label: []const u8) bool {
    for (labels) |existing| {
        if (std.mem.eql(u8, existing, label)) return true;
    }
    return false;
}

/// Rejects keys of `table` outside `allowed` (serde's `deny_unknown_fields`).
fn check_fields(
    diagnostic: *Diagnostic,
    table: *const Table,
    comptime allowed: []const []const u8,
) error{Invalid}!void {
    for (table.keys.items) |key| {
        if (!contains(allowed, key)) return diagnostic.fail("unknown field `{s}`", .{key});
    }
}

pub fn required_string(
    diagnostic: *Diagnostic,
    table: *const Table,
    key: []const u8,
) error{Invalid}![]const u8 {
    return try optional_string(diagnostic, table, key) orelse
        diagnostic.fail("missing field `{s}`", .{key});
}

/// The non-empty string at `key`, or null when absent.
pub fn optional_string(
    diagnostic: *Diagnostic,
    table: *const Table,
    key: []const u8,
) error{Invalid}!?[]const u8 {
    const value = table.get(key) orelse return null;
    if (value != .string) return diagnostic.fail("`{s}` must be a string", .{key});
    if (value.string.len == 0) {
        return diagnostic.fail("`{s}` must be a non-empty string", .{key});
    }
    return value.string;
}

/// The strings at `key`, or none when absent.
fn strings(
    gpa: Allocator,
    diagnostic: *Diagnostic,
    table: *const Table,
    key: []const u8,
) Error![]const []const u8 {
    const value = table.get(key) orelse return &.{};
    if (value != .array) return diagnostic.fail("`{s}` must be an array", .{key});
    const items = value.array.items.items;
    const out = try gpa.alloc([]const u8, items.len);
    for (items, out) |item, *slot| {
        if (item != .string) return diagnostic.fail("`{s}` must hold strings", .{key});
        slot.* = item.string;
    }
    return out;
}

/// The values of the required, non-empty array of tables at `key`; each holds `.table`.
pub fn tables(
    diagnostic: *Diagnostic,
    table: *const Table,
    key: []const u8,
) error{Invalid}![]const Value {
    const value = table.get(key) orelse return diagnostic.fail("missing field `{s}`", .{key});
    if (value != .array) return diagnostic.fail("`{s}` must be an array", .{key});
    const items = value.array.items.items;
    if (items.len == 0) return diagnostic.fail("`{s}` must be a non-empty array", .{key});
    for (items) |item| {
        if (item != .table) return diagnostic.fail("`{s}` must hold tables", .{key});
    }
    return items;
}

/// The gates at `gates`, or null when absent. A present list must be non-empty.
fn optional_gates(
    gpa: Allocator,
    diagnostic: *Diagnostic,
    table: *const Table,
) Error!?[]const Gate {
    const value = table.get("gates") orelse return null;
    if (value != .array) return diagnostic.fail("`gates` must be an array", .{});
    const items = value.array.items.items;
    if (items.len == 0) return diagnostic.fail("`gates` must be a non-empty array", .{});
    const gates = try gpa.alloc(Gate, items.len);
    for (items, gates) |item, *gate| {
        if (item != .table) return diagnostic.fail("`gates` must hold tables", .{});
        gate.* = try decode_gate(diagnostic, item.table);
    }
    return gates;
}

fn decode_gate(diagnostic: *Diagnostic, table: *const Table) error{Invalid}!Gate {
    try check_fields(diagnostic, table, &.{ "metric", "direction", "threshold_percent" });
    const direction_name = try required_string(diagnostic, table, "direction");
    const direction = std.meta.stringToEnum(Direction, direction_name) orelse
        return diagnostic.fail("unknown variant `{s}`, expected `down` or `up`", .{direction_name});
    const threshold: f64 = switch (table.get("threshold_percent") orelse
        return diagnostic.fail("missing field `threshold_percent`", .{})) {
        .integer => |integer| @floatFromInt(integer),
        .float => |float| float,
        else => return diagnostic.fail("`threshold_percent` must be a number", .{}),
    };
    if (!(threshold >= 0)) return diagnostic.fail("`threshold_percent` must be non-negative", .{});
    return .{
        .metric = try required_string(diagnostic, table, "metric"),
        .direction = direction,
        .threshold_percent = threshold,
    };
}
