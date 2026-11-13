//! The estimator's output, byte for byte as commonware prints it (`main.rs`
//! `print_simulation_results` and `print_aggregated_results`), including the `colored` crate's
//! ANSI sequences and the two `tracing` debug lines it logs to stdout.
//!
//! Colors follow `colored` 3: `CLICOLOR_FORCE` other than `0` forces them, otherwise any
//! `NO_COLOR` disables them, otherwise `CLICOLOR` other than `0` (default on) applies when
//! stdout is a terminal. `tracing` colors its lines unless `NO_COLOR` is non-empty.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const lib = @import("lib.zig");
const rust = @import("rust.zig");
const simulate = @import("simulate.zig");

pub const Color = enum(u8) {
    green = 32,
    yellow = 33,
    blue = 34,
    magenta = 35,
    cyan = 36,
    white = 37,
};

/// Whether `colored` would colorize, given the environment and whether stdout is a terminal.
pub fn should_colorize(
    clicolor: ?[]const u8,
    clicolor_force: ?[]const u8,
    no_color: ?[]const u8,
    is_tty: bool,
) bool {
    if (clicolor_force) |force| {
        if (!std.mem.eql(u8, force, "0")) return true;
    }
    if (no_color != null) return false;
    const enabled = if (clicolor) |value| !std.mem.eql(u8, value, "0") else true;
    return enabled and is_tty;
}

/// Whether `tracing_subscriber::fmt` writes ANSI sequences.
pub fn tracing_ansi(no_color: ?[]const u8) bool {
    const value = no_color orelse return true;
    return value.len == 0;
}

pub const Style = struct {
    colors: bool,

    /// `println!("{}", text.color())`, optionally bold.
    fn line(style: Style, writer: *Writer, color: Color, bold: bool, text: []const u8) !void {
        if (!style.colors) {
            try writer.writeAll(text);
            return writer.writeByte('\n');
        }
        const prefix = if (bold) "1;" else "";
        try writer.print("\x1b[{s}{d}m{s}\x1b[0m\n", .{ prefix, @backingInt(color), text });
    }

    /// `println!("{}", format!(format, args).color())`.
    fn print(
        style: Style,
        writer: *Writer,
        color: Color,
        comptime format: []const u8,
        args: anytype,
    ) !void {
        if (style.colors) try writer.print("\x1b[{d}m", .{@backingInt(color)});
        try writer.print(format, args);
        if (style.colors) try writer.writeAll("\x1b[0m");
        try writer.writeByte('\n');
    }
};

/// A float printed as Rust's `{:.2}`.
const Fixed = struct {
    value: f64,

    pub fn format(self: Fixed, writer: *Writer) Writer.Error!void {
        return rust.write_fixed(writer, self.value, 2);
    }
};

fn fixed(value: f64) Fixed {
    return .{ .value = value };
}

/// `{ts} DEBUG {target}: ` in `tracing`'s full format, with its colors when `ansi`.
fn debug_prefix(writer: *Writer, ansi: bool, now_us: u64, target: []const u8) !void {
    const seconds = now_us / std.time.us_per_s;
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day = epoch.getDaySeconds();
    if (ansi) try writer.writeAll("\x1b[2m");
    try writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
        now_us % std.time.us_per_s,
    });
    if (ansi) {
        const format = "\x1b[0m \x1b[34mDEBUG\x1b[0m \x1b[2m{s}\x1b[0m\x1b[2m:\x1b[0m ";
        try writer.print(format, .{target});
    } else {
        try writer.print(" DEBUG {s}: ", .{target});
    }
}

fn debug_field(writer: *Writer, ansi: bool, name: []const u8) !void {
    if (ansi) return writer.print("\x1b[3m{s}\x1b[0m\x1b[2m=\x1b[0m", .{name});
    try writer.print("{s}=", .{name});
}

fn write_cap(writer: *Writer, cap: ?u64) !void {
    if (cap) |value| return writer.print("Some({d})", .{value});
    try writer.writeAll("None");
}

/// `debug!(peers, ?args.distribution, "Initializing simulator")`.
pub fn log_initializing(
    writer: *Writer,
    ansi: bool,
    now_us: u64,
    peers: u64,
    distribution: *const lib.Distribution,
) !void {
    try debug_prefix(writer, ansi, now_us, "commonware_estimator");
    try writer.writeAll("Initializing simulator ");
    try debug_field(writer, ansi, "peers");
    try writer.print("{d} ", .{peers});
    try debug_field(writer, ansi, "args.distribution");
    try writer.writeByte('{');
    for (distribution.entries.items, 0..) |entry, index| {
        if (index > 0) try writer.writeAll(", ");
        try rust.write_debug_string(writer, entry.region);
        try writer.print(": RegionConfig {{ count: {d}, egress_cap: ", .{entry.config.count});
        try write_cap(writer, entry.config.egress_cap);
        try writer.writeAll(", ingress_cap: ");
        try write_cap(writer, entry.config.ingress_cap);
        try writer.writeAll(" }");
    }
    try writer.writeAll("}\n");
}

/// `debug!(message)` from the estimator library (`loading`/`downloading latency data`).
pub fn log_message(writer: *Writer, ansi: bool, now_us: u64, message: []const u8) !void {
    try debug_prefix(writer, ansi, now_us, "estimator");
    try writer.print("{s}\n", .{message});
}

/// Maps 1-based line numbers to command indices.
pub const LineIndex = struct {
    commands: []const lib.Command,

    fn command_at(index: LineIndex, line: usize) ?usize {
        for (index.commands, 0..) |command, position| {
            if (command.line == line) return position;
        }
        return null;
    }
};

const Stats = struct { mean: f64, median: f64, std_dev: f64 };

/// commonware's per-region statistics: mean of the samples, then median (sorting them), then
/// the standard deviation of the sorted samples. `scratch` holds `samples.len` values.
fn region_stats(samples: []const f64, scratch: []f64) Stats {
    assert(scratch.len >= samples.len);
    const sorted = scratch[0..samples.len];
    @memcpy(sorted, samples);
    const mean = lib.mean(sorted);
    const median = lib.median(sorted);
    return .{ .mean = mean, .median = median, .std_dev = lib.std_dev(sorted) orelse 0.0 };
}

/// Statistics over unsorted samples, with the median of a sorted copy.
fn overall_stats(samples: []const f64, scratch: []f64) Stats {
    assert(scratch.len >= samples.len);
    const sorted = scratch[0..samples.len];
    @memcpy(sorted, samples);
    return .{
        .mean = lib.mean(samples),
        .median = lib.median(sorted),
        .std_dev = lib.std_dev(samples) orelse 0.0,
    };
}

fn write_stats(
    style: Style,
    writer: *Writer,
    color: Color,
    label: []const u8,
    stats: Stats,
) !void {
    try style.print(writer, color, "    [{s}] mean: {f}ms (stdv: {f}ms) | median: {f}ms", .{
        label, fixed(stats.mean), fixed(stats.std_dev), fixed(stats.median),
    });
}

/// Results of one simulation (commonware `print_simulation_results`).
pub fn print_simulation(
    gpa: Allocator,
    style: Style,
    writer: *Writer,
    result: *const simulate.Simulation,
    distribution: *const lib.Distribution,
    task: *const lib.Task,
    task_content: []const u8,
) !void {
    var header_buffer: [256]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buffer, "\nresults for proposer {d} ({s}):\n", .{
        result.proposer, result.proposer_region,
    });
    try style.line(writer, .cyan, true, header);
    const index: LineIndex = .{ .commands = task.commands };
    var lines: rust.Lines = .{ .text = task_content };
    var line_number: usize = 0;
    while (lines.next()) |line| {
        line_number += 1;
        try style.line(writer, .yellow, false, line);
        const command = index.command_at(line_number) orelse continue;
        if (!result.steps.observed(command)) continue;
        if (result.steps.proposer[command]) |latency| {
            try style.print(writer, .magenta, "    [proposer] latency: {f}ms", .{fixed(latency)});
        }
        if (std.mem.startsWith(u8, line, "collect")) continue;
        for (distribution.entries.items, 0..) |entry, region| {
            const samples = result.steps.at(command, region).items;
            if (samples.len == 0) continue;
            const scratch = try gpa.alloc(f64, samples.len);
            defer gpa.free(scratch);
            try write_stats(style, writer, .cyan, entry.region, region_stats(samples, scratch));
        }
    }
}

/// Results averaged over every simulation (commonware `print_aggregated_results`).
pub fn print_aggregated(
    gpa: Allocator,
    style: Style,
    writer: *Writer,
    results: []const simulate.Simulation,
    distribution: *const lib.Distribution,
    task: *const lib.Task,
    task_content: []const u8,
) !void {
    try writer.writeByte('\n');
    try style.line(writer, .yellow, false, &@as([80]u8, @splat('-')));
    try style.line(writer, .blue, true, "\nresults:\n");
    const index: LineIndex = .{ .commands = task.commands };
    var lines: rust.Lines = .{ .text = task_content };
    var line_number: usize = 0;
    while (lines.next()) |line| {
        line_number += 1;
        try style.line(writer, .green, false, line);
        const command = index.command_at(line_number) orelse continue;
        var observed = false;
        for (results) |result| observed = observed or result.steps.observed(command);
        if (!observed) continue;
        try print_aggregated_proposer(gpa, style, writer, results, command);
        if (std.mem.startsWith(u8, line, "collect")) continue;
        try print_aggregated_regions(gpa, style, writer, results, distribution, command);
    }
}

fn print_aggregated_proposer(
    gpa: Allocator,
    style: Style,
    writer: *Writer,
    results: []const simulate.Simulation,
    command: usize,
) !void {
    var samples: std.ArrayList(f64) = .empty;
    defer samples.deinit(gpa);
    for (results) |result| {
        if (result.steps.proposer[command]) |latency| try samples.append(gpa, latency);
    }
    if (samples.items.len == 0) return;
    const scratch = try gpa.alloc(f64, samples.items.len);
    defer gpa.free(scratch);
    try write_stats(style, writer, .magenta, "proposer", overall_stats(samples.items, scratch));
}

fn print_aggregated_regions(
    gpa: Allocator,
    style: Style,
    writer: *Writer,
    results: []const simulate.Simulation,
    distribution: *const lib.Distribution,
    command: usize,
) !void {
    var all: std.ArrayList(f64) = .empty;
    defer all.deinit(gpa);
    var samples: std.ArrayList(f64) = .empty;
    defer samples.deinit(gpa);
    var scratch: std.ArrayList(f64) = .empty;
    defer scratch.deinit(gpa);
    for (distribution.entries.items, 0..) |entry, region| {
        samples.clearRetainingCapacity();
        for (results) |result| try samples.appendSlice(gpa, result.steps.at(command, region).items);
        if (samples.items.len == 0) continue;
        try scratch.resize(gpa, samples.items.len);
        const stats = region_stats(samples.items, scratch.items);
        try write_stats(style, writer, .blue, entry.region, stats);
        try all.appendSlice(gpa, samples.items);
    }
    if (all.items.len == 0) return;
    try scratch.resize(gpa, all.items.len);
    try write_stats(style, writer, .white, "all", overall_stats(all.items, scratch.items));
}

const testing = std.testing;

test "should_colorize follows colored 3" {
    try testing.expect(should_colorize(null, null, null, true));
    try testing.expect(!should_colorize(null, null, null, false));
    try testing.expect(!should_colorize("0", null, null, true));
    try testing.expect(!should_colorize(null, null, "", true));
    try testing.expect(!should_colorize(null, "0", "1", true));
    try testing.expect(should_colorize("0", "1", "1", false));
    try testing.expect(tracing_ansi(null));
    try testing.expect(tracing_ansi(""));
    try testing.expect(!tracing_ansi("1"));
}

test "debug lines match tracing's format" {
    var buffer: [512]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    var distribution: lib.Distribution = .{};
    defer distribution.deinit(testing.allocator);
    const none: lib.RegionConfig = .{ .count = 1, .egress_cap = null, .ingress_cap = null };
    try distribution.put(testing.allocator, "us-east-1", none);
    const capped: lib.RegionConfig = .{ .count = 2, .egress_cap = 9, .ingress_cap = 3 };
    try distribution.put(testing.allocator, "eu-west-1", capped);
    // 2026-11-13T16:27:51.676445Z
    const now_us: u64 = 1_794_587_271_676_445;
    try log_initializing(&writer, false, now_us, 3, &distribution);
    try log_message(&writer, false, now_us, "loading latency data");
    try testing.expectEqualStrings("2026-11-13T16:27:51.676445Z DEBUG commonware_estimator: " ++
        "Initializing simulator peers=3 args.distribution={\"eu-west-1\": RegionConfig " ++
        "{ count: 2, egress_cap: Some(9), ingress_cap: Some(3) }, \"us-east-1\": RegionConfig " ++
        "{ count: 1, egress_cap: None, ingress_cap: None }}\n" ++
        "2026-11-13T16:27:51.676445Z DEBUG estimator: loading latency data\n", writer.buffered());
    var colored: Writer = .fixed(&buffer);
    try log_message(&colored, true, now_us, "loading latency data");
    try testing.expectEqualStrings("\x1b[2m2026-11-13T16:27:51.676445Z\x1b[0m " ++
        "\x1b[34mDEBUG\x1b[0m " ++
        "\x1b[2mestimator\x1b[0m\x1b[2m:\x1b[0m loading latency data\n", colored.buffered());
}
