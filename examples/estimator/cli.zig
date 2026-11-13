//! Command-line parsing for the estimator, with the help, version, and error text that clap
//! prints for commonware's `commonware-estimator` (`main.rs` `parse_arguments`), and its exit
//! codes: 0 for help and version, 2 for usage errors.
//!
//! The binary name in usage lines is taken from argv[0], as clap does. Help and errors are
//! printed without clap's terminal styling.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const rust = @import("rust.zig");
const lib = @import("lib.zig");

pub const about = "Simulate mechanism performance under realistic network conditions";
/// The clap command name commonware gives the estimator, shown by `--version`.
pub const command_name = "commonware-simulator";

const help_pad: []const u8 = &@as([37]u8, @splat(' '));
const help_options = "Arguments:\n" ++
    "  <task>  Path to .lazy file defining the simulation behavior\n" ++
    "\n" ++
    "Options:\n" ++
    "      --distribution <distribution>  Distribution of peers across regions:\n" ++
    help_pad ++ "<region>:<count> (unlimited bandwidth)\n" ++
    help_pad ++ "<region>:<count>:<egress>/<ingress> (asymmetric)\n" ++
    help_pad ++ "<region>:<count>:<bandwidth> (symmetric)\n" ++
    help_pad ++ "\n" ++
    help_pad ++ "Bandwidth is in bytes per second.\n" ++
    help_pad ++ "\n" ++
    help_pad ++ "Examples:\n" ++
    help_pad ++ "us-east-1:3 (3 peers, unlimited bandwidth)\n" ++
    help_pad ++ "us-east-1:3:1000/500 (1000 B/s egress, 500 B/s ingress)\n" ++
    help_pad ++ "eu-west-1:2:2000 (2000 B/s both ways)\n" ++
    "      --reload                       Reload latency data from cloudping.co\n" ++
    "  -h, --help                         Print help\n" ++
    "  -V, --version                      Print version\n";

/// Arguments as given on the command line, borrowed from argv.
pub const Arguments = struct {
    task: []const u8,
    /// The comma-separated `--distribution` value.
    distribution: []const u8,
    reload: bool,
};

pub const Outcome = union(enum) {
    run: Arguments,
    /// Print `help` (stdout) and exit 0.
    help,
    /// Print `version` (stdout) and exit 0.
    version,
    /// The error text is in the writer (stderr); exit 2.
    usage_error,
};

/// Long options in clap's order, which decides ties between suggestions.
const longs = [_][]const u8{ "distribution", "reload", "help", "version" };

const Used = struct {
    task: bool = false,
    distribution: bool = false,
    reload: bool = false,
    help: bool = false,
    version: bool = false,
};

/// Writes the help text (`--help`).
pub fn write_help(writer: *std.Io.Writer, bin_name: []const u8) std.Io.Writer.Error!void {
    try writer.print("{s}\n\n", .{about});
    try writer.print("Usage: {s} [OPTIONS] --distribution <distribution> <task>\n\n", .{bin_name});
    try writer.writeAll(help_options);
}

pub fn write_version(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.print("{s} {s}\n", .{ command_name, lib.crate_version() });
}

/// Parses `args` (without argv[0]). Usage errors are written to `err` in clap's format.
pub fn parse(
    args: []const []const u8,
    bin_name: []const u8,
    err: *std.Io.Writer,
) std.Io.Writer.Error!Outcome {
    var used: Used = .{};
    var task: ?[]const u8 = null;
    var distribution: ?[]const u8 = null;
    var pending_distribution = false;
    var trailing = false;
    for (args) |arg| {
        if (pending_distribution and !(arg.len > 1 and arg[0] == '-' and arg[1] != '-')) {
            if (std.mem.startsWith(u8, arg, "--") and !trailing) return missing_value(err);
            pending_distribution = false;
            distribution = arg;
            used.distribution = true;
            continue;
        }
        if (trailing or arg.len < 2 or arg[0] != '-') {
            if (task != null) return unexpected_positional(err, arg, bin_name);
            task = arg;
            used.task = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--")) {
            trailing = true;
            continue;
        }
        if (arg[1] != '-') {
            // Short flags: the first known one acts, anything else is unexpected.
            switch (arg[1]) {
                'h' => return .help,
                'V' => return .version,
                else => return unexpected_short(err, arg[0..2], bin_name),
            }
        }
        const body = arg[2..];
        const equals = std.mem.indexOfScalar(u8, body, '=');
        const name = body[0 .. equals orelse body.len];
        const value: ?[]const u8 = if (equals) |index| body[index + 1 ..] else null;
        if (std.mem.eql(u8, name, "distribution")) {
            if (used.distribution) return duplicate(err, "--distribution <distribution>", bin_name);
            if (value) |text| {
                distribution = text;
                used.distribution = true;
            } else pending_distribution = true;
            continue;
        }
        const flag = flag_index(name) orelse {
            const suggestion = suggest(name);
            if (suggestion) |index| set_used(&used, index);
            return unexpected_long(err, arg, suggestion, used, bin_name);
        };
        if (flag == 1 and used.reload) return duplicate(err, "--reload", bin_name);
        set_used(&used, flag);
        if (value) |text| return unexpected_value(err, text, name, used, bin_name);
        switch (flag) {
            1 => {},
            2 => return .help,
            3 => return .version,
            else => unreachable,
        }
    }
    if (pending_distribution) return missing_value(err);
    if (task == null or distribution == null) return missing_required(err, used, bin_name);
    return .{ .run = .{ .task = task.?, .distribution = distribution.?, .reload = used.reload } };
}

fn flag_index(name: []const u8) ?usize {
    for (longs, 0..) |long, index| {
        if (index > 0 and std.mem.eql(u8, long, name)) return index;
    }
    return null;
}

fn set_used(used: *Used, index: usize) void {
    switch (index) {
        0 => used.distribution = true,
        1 => used.reload = true,
        2 => used.help = true,
        3 => used.version = true,
        else => unreachable,
    }
}

/// clap's did-you-mean: the long name most similar to `name` (Jaro above 0.7), later wins ties.
fn suggest(name: []const u8) ?usize {
    var best: ?usize = null;
    var best_confidence: f64 = 0;
    for (longs, 0..) |long, index| {
        const confidence = jaro(name, long);
        if (confidence > 0.7 and confidence >= best_confidence) {
            best = index;
            best_confidence = confidence;
        }
    }
    return best;
}

/// Jaro similarity of two byte strings (strsim 0.11 `jaro`).
pub fn jaro(a: []const u8, b: []const u8) f64 {
    if (a.len == 0 and b.len == 0) return 1.0;
    if (a.len == 0 or b.len == 0) return 0.0;
    if (a.len > 64 or b.len > 64) return jaro(a[0..@min(a.len, 64)], b[0..@min(b.len, 64)]);
    const search_range = (@max(a.len, b.len) / 2) -| 1;
    var a_flags: [64]bool = @splat(false);
    var b_flags: [64]bool = @splat(false);
    var matches: usize = 0;
    for (a, 0..) |a_byte, i| {
        const low = i -| search_range;
        const high = @max(low, @min(b.len, i + search_range + 1));
        for (low..high) |j| {
            if (a_byte == b[j] and !b_flags[j]) {
                a_flags[i] = true;
                b_flags[j] = true;
                matches += 1;
                break;
            }
        }
    }
    if (matches == 0) return 0.0;
    var transpositions: usize = 0;
    var j: usize = 0;
    for (a, 0..) |a_byte, i| {
        if (!a_flags[i]) continue;
        while (!b_flags[j]) j += 1;
        if (a_byte != b[j]) transpositions += 1;
        j += 1;
    }
    transpositions /= 2;
    const m: f64 = @floatFromInt(matches);
    const a_len: f64 = @floatFromInt(a.len);
    const b_len: f64 = @floatFromInt(b.len);
    const t: f64 = @floatFromInt(transpositions);
    return (m / a_len + m / b_len + (m - t) / m) / 3.0;
}

fn write_full_usage(err: *std.Io.Writer, bin_name: []const u8) std.Io.Writer.Error!void {
    try err.print("Usage: {s} [OPTIONS] --distribution <distribution> <task>\n\n", .{bin_name});
}

/// The required arguments plus the flags already used, as clap's "smart usage".
fn write_smart_usage(err: *std.Io.Writer, used: Used, bin_name: []const u8) !void {
    try err.print("Usage: {s} --distribution <distribution>", .{bin_name});
    if (used.reload) try err.writeAll(" --reload");
    if (used.help) try err.writeAll(" --help");
    if (used.version) try err.writeAll(" --version");
    try err.writeAll(" <task>\n\n");
}

fn write_more_information(err: *std.Io.Writer) std.Io.Writer.Error!Outcome {
    try err.writeAll("For more information, try '--help'.\n");
    return .usage_error;
}

fn missing_value(err: *std.Io.Writer) std.Io.Writer.Error!Outcome {
    try err.writeAll("error: a value is required for '--distribution <distribution>' " ++
        "but none was supplied\n\n");
    return write_more_information(err);
}

fn missing_required(err: *std.Io.Writer, used: Used, bin_name: []const u8) !Outcome {
    assert(!used.task or !used.distribution);
    try err.writeAll("error: the following required arguments were not provided:\n");
    if (!used.distribution) try err.writeAll("  --distribution <distribution>\n");
    if (!used.task) try err.writeAll("  <task>\n");
    try err.writeAll("\n");
    try write_smart_usage(err, used, bin_name);
    return write_more_information(err);
}

fn duplicate(err: *std.Io.Writer, arg: []const u8, bin_name: []const u8) !Outcome {
    try err.print("error: the argument '{s}' cannot be used multiple times\n\n", .{arg});
    try write_full_usage(err, bin_name);
    return write_more_information(err);
}

fn unexpected_positional(err: *std.Io.Writer, arg: []const u8, bin_name: []const u8) !Outcome {
    try err.print("error: unexpected argument '{s}' found\n\n", .{arg});
    try write_full_usage(err, bin_name);
    return write_more_information(err);
}

fn unexpected_short(err: *std.Io.Writer, arg: []const u8, bin_name: []const u8) !Outcome {
    try err.print("error: unexpected argument '{s}' found\n\n", .{arg});
    try err.print("  tip: to pass '{s}' as a value, use '-- {s}'\n\n", .{ arg, arg });
    try write_full_usage(err, bin_name);
    return write_more_information(err);
}

fn unexpected_long(
    err: *std.Io.Writer,
    arg: []const u8,
    suggestion: ?usize,
    used: Used,
    bin_name: []const u8,
) std.Io.Writer.Error!Outcome {
    const name = arg[0 .. std.mem.indexOfScalar(u8, arg, '=') orelse arg.len];
    try err.print("error: unexpected argument '{s}' found\n\n", .{name});
    if (suggestion) |index| {
        try err.print("  tip: a similar argument exists: '--{s}'\n\n", .{longs[index]});
    } else {
        try err.print("  tip: to pass '{s}' as a value, use '-- {s}'\n\n", .{ name, name });
    }
    const any_used = used.task or used.distribution or used.reload or used.help or used.version;
    if (any_used) {
        try write_smart_usage(err, used, bin_name);
    } else {
        try write_full_usage(err, bin_name);
    }
    return write_more_information(err);
}

fn unexpected_value(
    err: *std.Io.Writer,
    value: []const u8,
    name: []const u8,
    used: Used,
    bin_name: []const u8,
) std.Io.Writer.Error!Outcome {
    try err.print("error: unexpected value '{s}' for '--{s}' found; no more were expected\n\n", .{
        value, name,
    });
    try write_smart_usage(err, used, bin_name);
    return write_more_information(err);
}

/// A failure that commonware reports with a panic; the message is commonware's.
pub const Panic = struct {
    buffer: [512]u8 = undefined,
    len: usize = 0,

    pub fn message(panic: *const Panic) []const u8 {
        return panic.buffer[0..panic.len];
    }

    pub fn fail(panic: *Panic, comptime format: []const u8, args: anytype) error{Panic} {
        var writer: std.Io.Writer = .fixed(&panic.buffer);
        writer.print(format, args) catch {}; // Truncated: the buffer is full.
        panic.len = writer.end;
        return error.Panic;
    }
};

/// Parses `region:count[:bandwidth | :egress/ingress],...` (commonware's distribution
/// parsing); region slices borrow `text`. A later entry for a region replaces an earlier one.
pub fn parse_distribution(
    gpa: Allocator,
    text: []const u8,
    panic: *Panic,
) (error{Panic} || Allocator.Error)!lib.Distribution {
    var distribution: lib.Distribution = .{};
    errdefer distribution.deinit(gpa);
    var entries = std.mem.splitScalar(u8, text, ',');
    while (entries.next()) |entry| {
        var parts = std.mem.splitScalar(u8, entry, ':');
        const region = parts.next().?; // Splitting always yields a first part.
        const count_text = parts.next() orelse return panic.fail("missing count", .{});
        const count = rust.parse_unsigned(u64, count_text) catch |err|
            return panic.fail("invalid count: {s}", .{lib.dsl.int_error_name(err)});
        var config: lib.RegionConfig = .{ .count = count, .egress_cap = null, .ingress_cap = null };
        if (parts.next()) |bandwidth| {
            if (std.mem.indexOfScalar(u8, bandwidth, '/')) |slash| {
                const ingress_end = std.mem.indexOfScalarPos(u8, bandwidth, slash + 1, '/') orelse
                    bandwidth.len;
                config.egress_cap = try parse_cap(bandwidth[0..slash], "egress", panic);
                const ingress = bandwidth[slash + 1 .. ingress_end];
                config.ingress_cap = try parse_cap(ingress, "ingress", panic);
            } else {
                const cap = try parse_cap(bandwidth, "bandwidth", panic);
                config.egress_cap = cap;
                config.ingress_cap = cap;
            }
        }
        try distribution.put(gpa, region, config);
    }
    return distribution;
}

fn parse_cap(text: []const u8, comptime what: []const u8, panic: *Panic) error{Panic}!u64 {
    return rust.parse_unsigned(u64, text) catch |err|
        panic.fail("invalid " ++ what ++ ": {s}", .{lib.dsl.int_error_name(err)});
}

const testing = std.testing;

fn expect_error_text(args: []const []const u8, expected: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const outcome = try parse(args, "commonware-estimator", &writer);
    try testing.expectEqual(Outcome.usage_error, outcome);
    try testing.expectEqualStrings(expected, writer.buffered());
}

test "help and version match clap's output" {
    var buffer: [2048]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try write_help(&writer, "commonware-estimator");
    try testing.expectEqualStrings(@embedFile("testdata/help.txt"), writer.buffered());
    var sink: std.Io.Writer = .fixed(&buffer);
    try testing.expectEqual(Outcome.help, try parse(&.{ "--help", "--bogus" }, "x", &sink));
    try testing.expectEqual(Outcome.help, try parse(&.{ "x", "-hV" }, "x", &sink));
    try testing.expectEqual(Outcome.version, try parse(&.{ "--version", "x" }, "x", &sink));
}

test "usage errors match clap's output" {
    // Each expected text was printed by the commonware binary for the same arguments.
    const usage_full = "Usage: commonware-estimator [OPTIONS] " ++
        "--distribution <distribution> <task>\n\n";
    const usage_smart = "Usage: commonware-estimator --distribution <distribution> <task>\n\n";
    const more = "For more information, try '--help'.\n";
    try expect_error_text(&.{}, "error: the following required arguments were not provided:\n" ++
        "  --distribution <distribution>\n  <task>\n\n" ++ usage_smart ++ more);
    try expect_error_text(&.{"x.lazy"}, "error: the following required arguments were not " ++
        "provided:\n  --distribution <distribution>\n\n" ++ usage_smart ++ more);
    try expect_error_text(&.{ "x", "--reload" }, "error: the following required arguments were " ++
        "not provided:\n  --distribution <distribution>\n\nUsage: commonware-estimator " ++
        "--distribution <distribution> --reload <task>\n\n" ++ more);
    try expect_error_text(&.{ "x", "--distribution", "a:1", "--distribution", "b:2" }, "error: " ++
        "the argument '--distribution <distribution>' cannot be used multiple times\n\n" ++
        usage_full ++ more);
    try expect_error_text(&.{ "x.lazy", "--bogus" }, "error: unexpected argument '--bogus' " ++
        "found\n\n  tip: to pass '--bogus' as a value, use '-- --bogus'\n\n" ++
        usage_smart ++ more);
    try expect_error_text(&.{ "--distributio", "a:2", "x" }, "error: unexpected argument " ++
        "'--distributio' found\n\n  tip: a similar argument exists: '--distribution'\n\n" ++
        usage_smart ++ more);
    try expect_error_text(&.{"--hel"}, "error: unexpected argument '--hel' found\n\n  tip: a " ++
        "similar argument exists: '--help'\n\nUsage: commonware-estimator --distribution " ++
        "<distribution> --help <task>\n\n" ++ more);
    try expect_error_text(&.{ "-x", "x" }, "error: unexpected argument '-x' found\n\n  tip: to " ++
        "pass '-x' as a value, use '-- -x'\n\n" ++ usage_full ++ more);
    try expect_error_text(&.{ "x", "--distribution", "-5" }, "error: unexpected argument '-5' " ++
        "found\n\n  tip: to pass '-5' as a value, use '-- -5'\n\n" ++ usage_full ++ more);
    try expect_error_text(&.{ "x", "extra", "--distribution", "a:2" }, "error: unexpected " ++
        "argument 'extra' found\n\n" ++ usage_full ++ more);
    try expect_error_text(&.{ "x", "--distribution", "--reload" }, "error: a value is required " ++
        "for '--distribution <distribution>' but none was supplied\n\n" ++ more);
    try expect_error_text(&.{ "--reload=1", "x", "--distribution", "a:2" }, "error: unexpected " ++
        "value '1' for '--reload' found; no more were expected\n\nUsage: commonware-estimator " ++
        "--distribution <distribution> --reload <task>\n\n" ++ more);
    try expect_error_text(&.{ "x", "--reload", "--reload", "--distribution", "a:2" }, "error: " ++
        "the argument '--reload' cannot be used multiple times\n\n" ++ usage_full ++ more);
}

test "parse accepts the commonware forms" {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const a = (try parse(&.{ "simplex.lazy", "--distribution", "us-east-1:2" }, "x", &writer)).run;
    try testing.expectEqualStrings("simplex.lazy", a.task);
    try testing.expectEqualStrings("us-east-1:2", a.distribution);
    try testing.expect(!a.reload);
    const b = (try parse(&.{ "--reload", "--distribution=a:2", "--", "-t" }, "x", &writer)).run;
    try testing.expectEqualStrings("-t", b.task);
    try testing.expectEqualStrings("a:2", b.distribution);
    try testing.expect(b.reload);
}

test "parse_distribution" {
    var panic: Panic = .{};
    var distribution = try parse_distribution(
        testing.allocator,
        "us-east-1:3:1000/500,eu-west-1:2:2000,ap-south-1:1,us-east-1:4:1000/500",
        &panic,
    );
    defer distribution.deinit(testing.allocator);
    const entries = distribution.entries.items;
    try testing.expectEqual(@as(usize, 3), entries.len);
    try testing.expectEqualStrings("ap-south-1", entries[0].region);
    const symmetric: lib.RegionConfig = .{ .count = 2, .egress_cap = 2000, .ingress_cap = 2000 };
    try testing.expectEqual(symmetric, entries[1].config);
    const asymmetric: lib.RegionConfig = .{ .count = 4, .egress_cap = 1000, .ingress_cap = 500 };
    try testing.expectEqual(asymmetric, entries[2].config);
    const failures = [_]struct { []const u8, []const u8 }{
        .{ "us-east-1:1,", "missing count" },
        .{ "us-east-1", "missing count" },
        .{ "a:x", "invalid count: ParseIntError { kind: InvalidDigit }" },
        .{ "a:1:1000/", "invalid ingress: ParseIntError { kind: Empty }" },
        .{ "a:1:/5", "invalid egress: ParseIntError { kind: Empty }" },
        .{ "a:1:fast", "invalid bandwidth: ParseIntError { kind: InvalidDigit }" },
    };
    for (failures) |failure| {
        const result = parse_distribution(testing.allocator, failure[0], &panic);
        try testing.expectError(error.Panic, result);
        try testing.expectEqualStrings(failure[1], panic.message());
    }
}

test "jaro matches strsim" {
    try testing.expectEqual(@as(f64, 1.0), jaro("", ""));
    try testing.expectEqual(@as(f64, 0.0), jaro("", "a"));
    try testing.expect(@abs(jaro("martha", "marhta") - 0.9444444444444445) < 1e-12);
    try testing.expect(@abs(jaro("dixon", "dicksonx") - 0.7666666666666666) < 1e-12);
    try testing.expect(jaro("bogus", "distribution") <= 0.7);
}
