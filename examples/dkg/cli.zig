//! The `dkg` binary's command line: commonware's clap `Cli` (`examples/dkg/src/main.rs`) with
//! its `bootstrap`, `setup`, and `validator` subcommands, printing clap 4.6's help and error
//! text byte for byte (`testdata/cli_clap_cases.txt`, printed by `commonware-dkg`).
//!
//! clap's order of checks, which those cases pin down:
//!
//! - A value given as its own argument is checked, and a repeat of its option reported, only
//!   when it is settled: by the next option, `-h`, or the end of its command. The top command
//!   settles its last value after the subcommand has parsed, so `--log-level nope setup
//!   --help` prints help.
//! - An error that ends parsing first settles the option before it silently: a valid value
//!   then counts as used in the usage line, and a repeated option drops out of it.
//! - `--name=value` and flags settle at once.
//! - The derive groups each command's options, so `--flag=value` after another option prints
//!   them as one `<a|b>` group in its usage line.

const std = @import("std");
const assert = std.debug.assert;
const Writer = std.Io.Writer;
const zigware = @import("zigware");
const ui = @import("ui");
const setup = @import("setup.zig");

const rust = ui.rust;
const IpAddr = zigware.deployer.IpAddr;
pub const Level = zigware.runtime.telemetry.traces.Level;

pub const default_node_dir = "./data/validator-0";

pub const Node = struct { node_dir: []const u8 = default_node_dir };

pub const Validator = struct {
    node_dir: []const u8 = default_node_dir,
    /// Run one-time peer state sync for a new late joiner.
    state_sync: bool = false,
};

pub const Command = union(enum) {
    bootstrap: Node,
    setup: setup.Options,
    validator: Validator,
};

pub const Cli = struct {
    /// Minimum trace level emitted by the node.
    log_level: Level = .info,
    /// commonware's Tokio worker threads; parsed for parity, the runner does not use it.
    worker_threads: u64 = 3,
    command: Command,
};

pub const Outcome = union(enum) {
    run: Cli,
    /// Help or an error was printed; exit with this status.
    exit: u8,
};

const Kind = enum { path, count, port, ip, level, flag };

const Arg = struct { long: []const u8, value_name: []const u8 = "", kind: Kind };

const Spec = struct {
    /// Appended to the binary's name in usage lines: `" setup"`, or `""` for the top.
    path: []const u8,
    about: []const u8 = "",
    args: []const Arg,
    subcommands: bool = false,
    /// The help after its usage line.
    options: []const u8,
};

const top_spec: Spec = .{
    .path = "",
    .args = &.{
        .{ .long = "log-level", .value_name = "LOG_LEVEL", .kind = .level },
        .{ .long = "worker-threads", .value_name = "WORKER_THREADS", .kind = .count },
    },
    .subcommands = true,
    .options =
    \\Commands:
    \\  bootstrap  Run the one-shot DKG, write the resulting genesis, and keep serving until stopped
    \\  setup      Generate every validator directory with node and network config
    \\  validator  Start a validator node
    \\  help       Print this message or the help of the given subcommand(s)
    \\
    \\Options:
    \\      --log-level <LOG_LEVEL>            Minimum trace level emitted by the node [default: INFO]
    \\      --worker-threads <WORKER_THREADS>  Number of Tokio worker threads [default: 3]
    \\  -h, --help                             Print help
    \\
    ,
};

const bootstrap_spec: Spec = .{
    .path = " bootstrap",
    .about = "Run the one-shot DKG, write the resulting genesis, and keep serving until stopped",
    .args = &.{.{ .long = "node-dir", .value_name = "NODE_DIR", .kind = .path }},
    .options =
    \\Options:
    \\      --node-dir <NODE_DIR>  Validator node directory containing config and runtime storage [default: ./data/validator-0]
    \\  -h, --help                 Print help
    \\
    ,
};

const setup_spec: Spec = .{
    .path = " setup",
    .about = "Generate every validator directory with node and network config",
    .args = &.{
        .{ .long = "node-dir", .value_name = "NODE_DIR", .kind = .path },
        .{ .long = "peers", .value_name = "PEERS", .kind = .count },
        .{ .long = "committee-size", .value_name = "COMMITTEE_SIZE", .kind = .count },
        .{ .long = "base-port", .value_name = "BASE_PORT", .kind = .port },
        .{ .long = "host", .value_name = "HOST", .kind = .ip },
    },
    .options =
    \\Options:
    \\      --node-dir <NODE_DIR>
    \\          Directory where validator subdirectories will be generated [default: ./data]
    \\      --peers <PEERS>
    \\          Total number of validators to generate [default: 6]
    \\      --committee-size <COMMITTEE_SIZE>
    \\          Number of validators in each epoch committee [default: 4]
    \\      --base-port <BASE_PORT>
    \\          First local P2P port assigned to validator-0 [default: 3000]
    \\      --host <HOST>
    \\          IP address used for generated listen and dial addresses [default: 127.0.0.1]
    \\  -h, --help
    \\          Print help
    \\
    ,
};

const validator_spec: Spec = .{
    .path = " validator",
    .about = "Start a validator node",
    .args = &.{
        .{ .long = "node-dir", .value_name = "NODE_DIR", .kind = .path },
        .{ .long = "state-sync", .kind = .flag },
    },
    .options =
    \\Options:
    \\      --node-dir <NODE_DIR>  Validator node directory containing config, genesis, and runtime storage [default: ./data/validator-0]
    \\      --state-sync           Run one-time peer state sync for a new late joiner
    \\  -h, --help                 Print help
    \\
    ,
};

/// The subcommands in clap's order, `help` last; `Target` indexes `subcommand_specs` by them.
const subcommand_names = [_][]const u8{ "bootstrap", "setup", "validator", "help" };
const subcommand_specs = [_]*const Spec{ &bootstrap_spec, &setup_spec, &validator_spec };
const Target = enum(u8) { bootstrap, setup, validator, help, top };

const level_error = "error parsing level: expected one of \"error\", \"warn\", \"info\", " ++
    "\"debug\", \"trace\", or a number 1-5";

const Stop = enum {
    /// Print the command's help to stdout and exit 0.
    help,
    /// The error is written to stderr; exit 2.
    failed,
};

/// Parses `args` (without argv[0]). Help goes to `out`, errors to `err`.
pub fn parse(args: []const []const u8, bin: []const u8, out: *Writer, err: *Writer) !Outcome {
    // `arg_required_else_help`: no arguments at all print the help as an error.
    if (args.len == 0) {
        try write_help(&top_spec, err, bin);
        return .{ .exit = 2 };
    }
    var top: Parser(top_spec) = .{ .bin = bin };
    for (args, 0..) |_, index| {
        switch (try top.step(args, index, err)) {
            .next => {},
            .stop => |stop| return stopped(&top_spec, stop, bin, out),
            .subcommand => |target| {
                return parse_subcommand(&top, target, args[index + 1 ..], out, err);
            },
        }
    }
    if (try top.settle(err)) |stop| return stopped(&top_spec, stop, bin, out);
    try err.print("error: '{s}' requires a subcommand but one was not provided\n", .{bin});
    try err.writeAll("  [subcommands: bootstrap, setup, validator, help]\n\n");
    try write_full_usage(&top_spec, err, bin);
    return stopped(&top_spec, try more_information(err), bin, out);
}

fn parse_subcommand(
    top: *Parser(top_spec),
    target: Target,
    rest: []const []const u8,
    out: *Writer,
    err: *Writer,
) !Outcome {
    const bin = top.bin;
    const command: Command = switch (target) {
        .bootstrap => switch (try parse_level(bootstrap_spec, top, rest, out, err)) {
            .exit => |status| return .{ .exit = status },
            .values => |values| .{ .bootstrap = .{
                .node_dir = values[0] orelse default_node_dir,
            } },
        },
        .setup => switch (try parse_level(setup_spec, top, rest, out, err)) {
            .exit => |status| return .{ .exit = status },
            .values => |values| .{ .setup = setup_options(values) },
        },
        .validator => switch (try parse_level(validator_spec, top, rest, out, err)) {
            .exit => |status| return .{ .exit = status },
            .values => |values| .{ .validator = .{
                .node_dir = values[0] orelse default_node_dir,
                .state_sync = values[1] != null,
            } },
        },
        .help => return help_subcommand(rest, bin, out, err),
        .top => unreachable, // Proof: `subcommand_index` only returns subcommands.
    };
    var cli: Cli = .{ .command = command };
    if (top.values[0]) |text| cli.log_level = parse_tracing_level(text).?;
    if (top.values[1]) |text| cli.worker_threads = unsigned(text);
    return .{ .run = cli };
}

fn LevelResult(comptime count: usize) type {
    return union(enum) { exit: u8, values: [count]?[]const u8 };
}

/// Parses a subcommand's arguments, then settles the top command's last value (clap's order).
fn parse_level(
    comptime spec: Spec,
    top: *Parser(top_spec),
    rest: []const []const u8,
    out: *Writer,
    err: *Writer,
) !LevelResult(spec.args.len) {
    comptime assert(!spec.subcommands);
    var level: Parser(spec) = .{ .bin = top.bin };
    for (rest, 0..) |_, index| {
        switch (try level.step(rest, index, err)) {
            .next => {},
            .stop => |stop| return .{ .exit = (try stopped(&spec, stop, top.bin, out)).exit },
            .subcommand => unreachable, // Proof: this command has no subcommands.
        }
    }
    if (try level.settle(err)) |stop| {
        return .{ .exit = (try stopped(&spec, stop, top.bin, out)).exit };
    }
    if (try top.settle(err)) |stop| {
        return .{ .exit = (try stopped(&top_spec, stop, top.bin, out)).exit };
    }
    assert(level.pending == null and top.pending == null);
    return .{ .values = level.values };
}

/// `help [COMMAND]...`: the help of the named subcommand, or an error at the first unknown name.
fn help_subcommand(
    rest: []const []const u8,
    bin: []const u8,
    out: *Writer,
    err: *Writer,
) !Outcome {
    var current: Target = .top;
    for (rest) |arg| {
        if (current == .top) {
            if (subcommand_index(arg)) |target| {
                current = target;
                continue;
            }
        }
        try err.print("error: unrecognized subcommand '{s}'\n\n", .{arg});
        if (current == .help) {
            // The help subcommand has no `--help`, so clap prints no hint to try it.
            try err.print("Usage: {s} help [COMMAND]...\n", .{bin});
            return .{ .exit = 2 };
        }
        try write_full_usage(spec_of(current), err, bin);
        _ = try more_information(err);
        return .{ .exit = 2 };
    }
    if (current == .help) {
        try out.print(
            \\Print this message or the help of the given subcommand(s)
            \\
            \\Usage: {s} help [COMMAND]...
            \\
            \\Arguments:
            \\  [COMMAND]...  Print help for the subcommand(s)
            \\
        , .{bin});
    } else {
        try write_help(spec_of(current), out, bin);
    }
    return .{ .exit = 0 };
}

fn spec_of(target: Target) *const Spec {
    assert(target != .help);
    if (target == .top) return &top_spec;
    return subcommand_specs[@backingInt(target)];
}

fn stopped(spec: *const Spec, stop: Stop, bin: []const u8, out: *Writer) !Outcome {
    switch (stop) {
        .help => {
            try write_help(spec, out, bin);
            return .{ .exit = 0 };
        },
        .failed => return .{ .exit = 2 },
    }
}

fn write_help(spec: *const Spec, writer: *Writer, bin: []const u8) !void {
    if (spec.about.len > 0) try writer.print("{s}\n\n", .{spec.about});
    try write_full_usage(spec, writer, bin);
    try writer.writeAll(spec.options);
}

fn write_full_usage(spec: *const Spec, writer: *Writer, bin: []const u8) !void {
    const command = if (spec.subcommands) " <COMMAND>" else "";
    try writer.print("Usage: {s}{s} [OPTIONS]{s}\n\n", .{ bin, spec.path, command });
}

fn more_information(err: *Writer) !Stop {
    try err.writeAll("For more information, try '--help'.\n");
    return .failed;
}

fn subcommand_index(arg: []const u8) ?Target {
    for (subcommand_names, 0..) |name, index| {
        if (std.mem.eql(u8, name, arg)) return @fromBackingInt(@intCast(index));
    }
    return null;
}

/// clap's did-you-mean: the candidate most similar to `name` (Jaro above 0.7); later
/// candidates win ties.
fn suggest(name: []const u8, candidates: []const []const u8) ?usize {
    var best: ?usize = null;
    var best_confidence: f64 = 0;
    for (candidates, 0..) |candidate, index| {
        const confidence = rust.jaro(name, candidate);
        if (confidence > 0.7 and confidence >= best_confidence) {
            best = index;
            best_confidence = confidence;
        }
    }
    assert(best == null or best_confidence > 0.7);
    return best;
}

/// `  tip: ...` for the subcommands similar to `arg`, least similar first, as clap lists them.
fn write_similar_subcommands(err: *Writer, arg: []const u8) !void {
    var order: [subcommand_names.len]u8 = undefined;
    var confidences: [subcommand_names.len]f64 = undefined;
    var len: usize = 0;
    for (subcommand_names, 0..) |name, index| {
        const confidence = rust.jaro(arg, name);
        if (confidence <= 0.7) continue;
        // Insert after every candidate at most as similar (clap's binary search).
        var at: usize = len;
        while (at > 0 and confidences[at - 1] > confidence) : (at -= 1) {
            order[at] = order[at - 1];
            confidences[at] = confidences[at - 1];
        }
        order[at] = @intCast(index);
        confidences[at] = confidence;
        len += 1;
    }
    assert(len <= subcommand_names.len);
    if (len == 0) return;
    try err.writeAll(if (len == 1)
        "  tip: a similar subcommand exists: "
    else
        "  tip: some similar subcommands exist: ");
    for (order[0..len], 0..) |index, position| {
        if (position > 0) try err.writeAll(", ");
        try err.print("'{s}'", .{subcommand_names[index]});
    }
    try err.writeAll("\n\n");
}

/// The subcommand option most similar to an unknown top option, among the subcommands named
/// later on the command line; the one named first wins (clap's `did_you_mean_flag`).
fn suggest_subcommand_flag(name: []const u8, remaining: []const []const u8) ?[2][]const u8 {
    var best: ?[2][]const u8 = null;
    var best_position: usize = std.math.maxInt(usize);
    inline for (subcommand_specs, 0..) |spec, index| {
        const longs = comptime long_names(spec.*);
        if (suggest(name, &longs)) |found| {
            for (remaining, 0..) |arg, position| {
                if (!std.mem.eql(u8, arg, subcommand_names[index])) continue;
                if (position < best_position) {
                    best = .{ subcommand_names[index], longs[found] };
                    best_position = position;
                }
                break;
            }
        }
    }
    assert(best == null or best_position < remaining.len);
    return best;
}

/// The command's longs, `help` last (clap's keymap order).
fn long_names(comptime spec: Spec) [spec.args.len + 1][]const u8 {
    var names: [spec.args.len + 1][]const u8 = undefined;
    for (spec.args, 0..) |arg, index| names[index] = arg.long;
    names[spec.args.len] = "help";
    return names;
}

/// `--long <VALUE>` (or `--long` for flags) for each option, `--help` last.
fn spec_texts(comptime spec: Spec) [spec.args.len + 1][]const u8 {
    var texts: [spec.args.len + 1][]const u8 = undefined;
    for (spec.args, 0..) |arg, index| {
        texts[index] = if (arg.kind == .flag)
            "--" ++ arg.long
        else
            "--" ++ arg.long ++ " <" ++ arg.value_name ++ ">";
    }
    texts[spec.args.len] = "--help";
    return texts;
}

/// The derive's argument group of a command: `<--a <A>|--b>`.
fn group_text(comptime spec: Spec) []const u8 {
    const texts = spec_texts(spec);
    var text: []const u8 = "<" ++ texts[0];
    for (texts[1..spec.args.len]) |each| text = text ++ "|" ++ each;
    return text ++ ">";
}

/// The parser of one command's arguments, in clap's matcher terms.
fn Parser(comptime spec: Spec) type {
    const count = spec.args.len;
    comptime assert(count > 0 and count < 8);
    const help_index = count;
    const args_table: [count]Arg = spec.args[0..count].*;
    const longs = long_names(spec);
    const texts = spec_texts(spec);
    const group = group_text(spec);
    return struct {
        const Self = @This();

        const Step = union(enum) { next, stop: Stop, subcommand: Target };

        bin: []const u8,
        /// Each settled option's value (`"true"` for a flag).
        values: [count]?[]const u8 = @splat(null),
        /// The options present, in the order clap's matcher holds them.
        present: [count]u8 = undefined,
        present_len: u8 = 0,
        /// A did-you-mean of `--help` adds it to the usage line.
        help_used: bool = false,
        /// The option whose value clap has not settled yet, and that value.
        pending: ?usize = null,
        pending_value: ?[]const u8 = null,
        /// The pending option still waits for its value (clap's `ParseState::Opt`).
        awaiting: bool = false,
        /// After `--`: every argument is positional.
        trailing: bool = false,

        fn step(self: *Self, args: []const []const u8, index: usize, err: *Writer) !Step {
            assert(index < args.len);
            const arg = args[index];
            if (!self.trailing) {
                if (spec.subcommands and !self.awaiting) {
                    if (subcommand_index(arg)) |target| return .{ .subcommand = target };
                }
                if (std.mem.eql(u8, arg, "--")) {
                    self.trailing = true;
                    return .next;
                }
                if (std.mem.startsWith(u8, arg, "--")) return self.step_long(args, index, err);
                if (arg.len > 1 and arg[0] == '-') return self.step_short(arg, err);
                if (self.awaiting) {
                    self.awaiting = false;
                    self.pending_value = arg;
                    return .next;
                }
            }
            self.settle_silently();
            return .{ .stop = try self.positional(arg, err) };
        }

        fn step_long(self: *Self, args: []const []const u8, index: usize, err: *Writer) !Step {
            const body = args[index][2..];
            const equals = std.mem.indexOfScalar(u8, body, '=');
            const name = body[0 .. equals orelse body.len];
            const value: ?[]const u8 = if (equals) |at| body[at + 1 ..] else null;
            const found = for (longs, 0..) |long, position| {
                if (std.mem.eql(u8, long, name)) break position;
            } else {
                self.settle_silently();
                return .{ .stop = try self.unknown_long(name, args[index + 1 ..], err) };
            };
            const takes_value = found < count and args_table[found].kind != .flag;
            if (!takes_value) {
                if (value) |text| return .{ .stop = try self.unneeded_value(found, text, err) };
            }
            if (try self.settle(err)) |stop| return .{ .stop = stop };
            if (found == help_index) return .{ .stop = .help };
            if (!takes_value) return step_of(try self.set(found, "true", err));
            if (value != null) return step_of(try self.set(found, value, err));
            self.pending = found;
            self.awaiting = true;
            return .next;
        }

        fn step_short(self: *Self, arg: []const u8, err: *Writer) !Step {
            assert(arg.len > 1 and arg[0] == '-' and arg[1] != '-');
            if (arg[1] == 'h') {
                if (try self.settle(err)) |stop| return .{ .stop = stop };
                return .{ .stop = .help };
            }
            self.settle_silently();
            const width = std.unicode.utf8ByteSequenceLength(arg[1]) catch 1;
            const shown = arg[0..@min(arg.len, 1 + width)];
            try err.print("error: unexpected argument '{s}' found\n\n", .{shown});
            try write_full_usage(&spec, err, self.bin);
            return .{ .stop = try more_information(err) };
        }

        fn step_of(stop: ?Stop) Step {
            return if (stop) |each| .{ .stop = each } else .next;
        }

        /// Settles the pending option: checks its value and records it.
        fn settle(self: *Self, err: *Writer) !?Stop {
            const index = self.pending orelse return null;
            const value = self.pending_value;
            self.pending = null;
            self.pending_value = null;
            self.awaiting = false;
            return self.set(index, value, err);
        }

        /// clap's `let _ = self.resolve_pending(matcher)` before an error.
        fn settle_silently(self: *Self) void {
            var buffer: [64]u8 = undefined;
            var discarding: Writer.Discarding = .init(&buffer);
            // Proof: a discarding writer never fails.
            _ = self.settle(&discarding.writer) catch unreachable;
            assert(self.pending == null);
        }

        /// clap's `react` for an option with its value (`null` when none came).
        fn set(self: *Self, index: usize, value: ?[]const u8, err: *Writer) !?Stop {
            assert(index < count);
            assert(self.pending == null);
            const arg = args_table[index];
            if (arg.kind != .flag and value == null) return try missing_value(err, texts[index]);
            if (self.remove(index)) {
                const text = texts[index];
                try err.print("error: the argument '{s}' cannot be used multiple times\n\n", .{
                    text,
                });
                try write_full_usage(&spec, err, self.bin);
                return try more_information(err);
            }
            self.add(index);
            self.values[index] = value;
            if (arg.kind == .flag) return null;
            return check_value(err, arg.kind, texts[index], value.?);
        }

        fn add(self: *Self, index: usize) void {
            assert(index < count);
            for (self.present[0..self.present_len]) |each| if (each == index) return;
            self.present[self.present_len] = @intCast(index);
            self.present_len += 1;
            assert(self.present_len <= count);
        }

        fn remove(self: *Self, index: usize) bool {
            const len = self.present_len;
            const at = std.mem.indexOfScalar(u8, self.present[0..len], @intCast(index)) orelse
                return false;
            std.mem.copyForwards(u8, self.present[at .. len - 1], self.present[at + 1 .. len]);
            self.present_len -= 1;
            self.values[index] = null;
            return true;
        }

        fn positional(self: *Self, arg: []const u8, err: *Writer) !Stop {
            if (!spec.subcommands) {
                try err.print("error: unexpected argument '{s}' found\n\n", .{arg});
            } else if (self.trailing and subcommand_index(arg) != null) {
                try err.print("error: unexpected argument '{s}' found\n\n", .{arg});
                try err.print("  tip: subcommand '{s}' exists; to use it, remove the '--' " ++
                    "before it\n\n", .{arg});
            } else {
                try err.print("error: unrecognized subcommand '{s}'\n\n", .{arg});
                try write_similar_subcommands(err, arg);
            }
            try write_full_usage(&spec, err, self.bin);
            return more_information(err);
        }

        fn unknown_long(
            self: *Self,
            name: []const u8,
            remaining: []const []const u8,
            err: *Writer,
        ) !Stop {
            const suggestion = suggest(name, &longs);
            if (suggestion) |index| {
                if (index == help_index) self.help_used = true else self.add(index);
            }
            try err.print("error: unexpected argument '--{s}' found\n\n", .{name});
            if (suggestion) |index| {
                try err.print("  tip: a similar argument exists: '--{s}'\n\n", .{longs[index]});
            } else if (spec.subcommands) {
                if (suggest_subcommand_flag(name, remaining)) |found| {
                    try err.print("  tip: '{s} --{s}' exists\n\n", .{ found[0], found[1] });
                }
            }
            try err.print("Usage: {s}{s}", .{ self.bin, spec.path });
            if (self.present_len == 0 and !self.help_used) try err.writeAll(" [OPTIONS]");
            for (self.present[0..self.present_len]) |index| try err.print(" {s}", .{texts[index]});
            if (self.help_used) try err.writeAll(" --help");
            try self.end_usage(err);
            return more_information(err);
        }

        /// `--flag=value` for an option without values (`--help` included).
        fn unneeded_value(self: *Self, index: usize, value: []const u8, err: *Writer) !Stop {
            assert(index == help_index or args_table[index].kind == .flag);
            try err.print("error: unexpected value '{s}' for '{s}' found; no more were " ++
                "expected\n\n", .{ value, texts[index] });
            try err.print("Usage: {s}{s}", .{ self.bin, spec.path });
            if (self.present_len > 0) {
                // A present option brings in its group, which replaces the group's members.
                if (index == help_index) try err.writeAll(" --help");
                try err.writeAll(" " ++ group);
            } else {
                try err.print(" {s}", .{texts[index]});
            }
            try self.end_usage(err);
            return more_information(err);
        }

        fn end_usage(_: *const Self, err: *Writer) !void {
            if (spec.subcommands) try err.writeAll(" <COMMAND>");
            try err.writeAll("\n\n");
        }
    };
}

fn missing_value(err: *Writer, text: []const u8) !Stop {
    try err.print("error: a value is required for '{s}' but none was supplied\n\n", .{text});
    return more_information(err);
}

/// Each option's value parser: `PathBuf`, `usize`, `u16` (clap's ranged `i64`), `IpAddr`, and
/// tracing's `Level`.
fn check_value(err: *Writer, kind: Kind, text: []const u8, value: []const u8) !?Stop {
    assert(kind != .flag);
    var buffer: [64]u8 = undefined;
    const reason: []const u8 = switch (kind) {
        .flag => unreachable, // Proof: asserted above.
        .path => return if (value.len == 0) try missing_value(err, text) else null,
        .count => if (rust.parse_unsigned(u64, value)) |_| return null else |failure| rust
            .int_error_text(failure),
        .port => port: {
            const number = rust.parse_i64(value) catch |failure|
                break :port rust.signed_error_text(failure);
            if (number >= 0 and number <= std.math.maxInt(u16)) return null;
            // Proof: an i64 prints in at most 20 bytes.
            break :port std.fmt.bufPrint(&buffer, "{d} is not in 0..=65535", .{number}) catch
                unreachable;
        },
        .ip => if (IpAddr.parse(value)) |_| return null else |_| "invalid IP address syntax",
        .level => if (parse_tracing_level(value) != null) return null else level_error,
    };
    try err.print("error: invalid value '{s}' for '{s}': {s}\n\n", .{ value, text, reason });
    return try more_information(err);
}

/// tracing's `Level::from_str`: a number 1-5 or a name in any case.
pub fn parse_tracing_level(text: []const u8) ?Level {
    const levels = [_]Level{ .@"error", .warn, .info, .debug, .trace };
    if (rust.parse_unsigned(u64, text)) |number| {
        if (number >= 1 and number <= levels.len) return levels[number - 1];
    } else |_| {}
    for (levels) |level| {
        if (std.ascii.eqlIgnoreCase(text, @tagName(level))) return level;
    }
    return null;
}

fn unsigned(text: []const u8) u64 {
    // Proof: `check_value` accepted the text as a `usize`.
    return rust.parse_unsigned(u64, text) catch unreachable;
}

fn setup_options(values: [setup_spec.args.len]?[]const u8) setup.Options {
    var options: setup.Options = .{};
    if (values[0]) |text| options.node_dir = text;
    if (values[1]) |text| options.peers = unsigned(text);
    if (values[2]) |text| options.committee_size = unsigned(text);
    // Proof: `check_value` accepted the port and the host.
    if (values[3]) |text| options.base_port = @intCast(rust.parse_i64(text) catch unreachable);
    if (values[4]) |text| options.host = IpAddr.parse(text) catch unreachable;
    return options;
}
