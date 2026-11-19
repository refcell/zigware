//! The slice of clap 4 the examples' `main`s use: long options taking one value each (some
//! split on `,`, some checked by a value parser piece by piece), `-h`/`--help`, and clap's
//! help, usage, and error text. Help prints to stdout with exit 0, errors to stderr with exit 2.
//!
//! clap reads arguments left to right and fails at the first error:
//!
//! - An unknown argument fails at once: a long one with smart usage once any option was used
//!   (or one is suggested), a positional or short one with full usage.
//! - A known option (or `-h`, `--help`, `--`) first settles the option before it: one still
//!   waiting for its value fails as "a value is required", and a parsed value is checked.
//! - A second value for an option fails as "cannot be used multiple times" when it arrives.
//! - After the last argument the option before settles the same way, then missing required
//!   options fail.

const std = @import("std");
const assert = std.debug.assert;
const Writer = std.Io.Writer;
const rust = @import("rust.zig");

/// One long option taking a value (`Arg::new(id).long(long)`).
pub const Arg = struct {
    long: []const u8,
    /// The `Arg::new` id, shown as the value name, when it differs from `long`.
    id: ?[]const u8 = null,
    required: bool = false,
    help: []const u8 = "",
    /// `.value_delimiter(',')`.
    delimited: bool = false,
    /// The `value_parser!` each piece must pass.
    value: Value = .string,
};

/// clap's `value_parser!` for each type the examples parse.
pub const Value = enum {
    string,
    /// `u64` and `usize`: `str::parse`.
    u64,
    /// `i32` and `u32`: clap's ranged parser, an `i64` within the type's range.
    i32,
    u32,
    /// `NonZeroU32` and `NonZeroUsize`: `str::parse`, then non-zero.
    non_zero_u32,
    non_zero_u64,
    /// `bool`: `true` or `false`.
    bool,
};

/// The help column past which clap's help moves each option's help below it.
const term_width = 100;

pub const Command = struct {
    about: []const u8,
    args: []const Arg,
};

/// A parser for `command`. Values stay as given: `values[i]` belongs to `command.args[i]`.
pub fn Parser(comptime command: Command) type {
    comptime assert(command.args.len > 0 and command.args.len < 32);
    const count = command.args.len;
    // `--help` is option `count` in usage and suggestions.
    const help_index = count;
    const specs = comptime value_names(command);
    return struct {
        pub const Values = [count]?[]const u8;
        pub const Outcome = union(enum) {
            run: Values,
            /// Print the help (stdout) and exit 0.
            help,
            /// The error text is in the error writer (stderr); exit 2.
            usage_error,
        };

        /// The options used so far, in the order first used (clap's matcher). An option whose
        /// value came as its own argument counts once a later argument commits it; one
        /// written `--long=value` counts at once.
        const Used = struct {
            order: [count + 1]u8 = undefined,
            len: u8 = 0,

            fn add(used: *Used, index: usize) void {
                assert(index <= count);
                if (used.contains(index)) return;
                used.order[used.len] = @intCast(index);
                used.len += 1;
                assert(used.len <= count + 1);
            }

            fn contains(used: *const Used, index: usize) bool {
                for (used.order[0..used.len]) |each| if (each == index) return true;
                return false;
            }
        };

        const State = struct {
            values: Values = @splat(null),
            used: Used = .{},
            /// The option waiting for its value.
            awaiting: ?usize = null,
            /// The option whose value clap has not checked yet.
            unchecked: ?usize = null,
            /// After `--`: every argument is positional.
            positional_only: bool = false,
        };

        pub fn write_help(writer: *Writer, bin_name: []const u8) Writer.Error!void {
            try writer.print("{s}\n\n", .{command.about});
            try write_full_usage(writer, bin_name);
            try writer.writeAll("Options:\n");
            const width = comptime spec_width();
            if (comptime next_line_help()) {
                inline for (command.args, specs) |arg, spec| {
                    const text = comptime about(arg);
                    try writer.writeAll("      " ++ spec ++ "\n" ++ next_line ++ text ++ "\n");
                }
                try writer.writeAll("  -h, --help\n" ++ next_line ++ "Print help\n");
                return;
            }
            inline for (command.args, specs) |arg, spec| {
                try writer.writeAll("      " ++ spec);
                try writer.splatByteAll(' ', width - spec.len + 2);
                try writer.writeAll(comptime about(arg) ++ "\n");
            }
            try writer.writeAll("  -h, --help");
            try writer.splatByteAll(' ', width + 4 - "-h, --help".len + 2);
            try writer.writeAll("Print help\n");
        }

        const next_line = "          "; // clap's TAB and NEXT_LINE_INDENT.

        /// An option's help and its possible values.
        fn about(comptime arg: Arg) []const u8 {
            if (arg.value != .bool) return arg.help;
            if (arg.help.len == 0) return possible_values;
            return arg.help ++ " " ++ possible_values;
        }

        /// clap's `will_args_wrap`: some option's help overflows the terminal width past a help
        /// column that starts beyond 40% of it.
        fn next_line_help() bool {
            const taken = spec_width() + 8;
            for (command.args) |arg| {
                const overflows = about(arg).len > term_width -| taken;
                if (taken <= term_width and taken * 5 > term_width * 2 and overflows) return true;
            }
            return false;
        }

        /// The widest `--long <long>`; the help column starts two spaces past it.
        fn spec_width() usize {
            var width: usize = "-h, --help".len - 4;
            for (specs) |spec| width = @max(width, spec.len);
            return width;
        }

        /// Parses `args` (without argv[0]); error text goes to `err`.
        pub fn parse(
            args: []const []const u8,
            bin_name: []const u8,
            err: *Writer,
        ) Writer.Error!Outcome {
            var state: State = .{};
            for (args) |arg| {
                if (try step(&state, arg, bin_name, err)) |outcome| return outcome;
            }
            if (try settle(&state, err)) |outcome| return outcome;
            assert(state.awaiting == null and state.unchecked == null);
            inline for (command.args, 0..) |arg, index| {
                if (arg.required and !state.used.contains(index)) {
                    return missing_required(err, state.used, bin_name);
                }
            }
            return .{ .run = state.values };
        }

        /// Handles one argument; an outcome ends parsing.
        fn step(state: *State, arg: []const u8, bin_name: []const u8, err: *Writer) !?Outcome {
            if (state.awaiting) |index| {
                const is_value = state.positional_only or !std.mem.startsWith(u8, arg, "-") or
                    std.mem.eql(u8, arg, "-");
                if (is_value) return give_value(state, index, arg, bin_name, err);
            }
            if (state.positional_only or arg.len < 2 or arg[0] != '-') {
                return try unexpected(err, arg, null, .{}, bin_name);
            }
            if (std.mem.eql(u8, arg, "--")) {
                if (try settle(state, err)) |outcome| return outcome;
                state.positional_only = true;
                return null;
            }
            if (arg[1] != '-') {
                if (arg[1] != 'h') return try unexpected(err, arg[0..2], null, .{}, bin_name);
                if (try settle(state, err)) |outcome| return outcome;
                return .help;
            }
            return step_long(state, arg, bin_name, err);
        }

        fn step_long(
            state: *State,
            arg: []const u8,
            bin_name: []const u8,
            err: *Writer,
        ) Writer.Error!?Outcome {
            assert(std.mem.startsWith(u8, arg, "--"));
            const body = arg[2..];
            const equals = std.mem.indexOfScalar(u8, body, '=');
            const name = body[0 .. equals orelse body.len];
            const value: ?[]const u8 = if (equals) |index| body[index + 1 ..] else null;
            const index = flag_index(name) orelse {
                // clap commits a value given as its own argument before reporting, unchecked.
                if (state.unchecked) |pending| state.used.add(pending);
                const suggestion = suggest(name);
                if (suggestion) |found| state.used.add(found);
                const shown = arg[0 .. 2 + name.len];
                return try unexpected(err, shown, suggestion, state.used, bin_name);
            };
            if (index == help_index) {
                state.used.add(help_index);
                if (value) |text| return try unexpected_value(err, text, state.used, bin_name);
                if (try settle(state, err)) |outcome| return outcome;
                return .help;
            }
            if (try settle(state, err)) |outcome| return outcome;
            if (value) |text| {
                state.used.add(index);
                return give_value(state, index, text, bin_name, err);
            }
            state.awaiting = index;
            return null;
        }

        fn give_value(
            state: *State,
            index: usize,
            value: []const u8,
            bin_name: []const u8,
            err: *Writer,
        ) Writer.Error!?Outcome {
            assert(index < count);
            state.awaiting = null;
            if (state.values[index] != null) return try duplicate(err, index, bin_name);
            state.values[index] = value;
            state.unchecked = index;
            return null;
        }

        /// Ends the option before: without a value it fails, and a parsed value is checked.
        fn settle(state: *State, err: *Writer) Writer.Error!?Outcome {
            if (state.awaiting) |index| {
                state.awaiting = null;
                return try missing_value(err, index);
            }
            const index = state.unchecked orelse return null;
            state.unchecked = null;
            state.used.add(index);
            const value = state.values[index].?;
            inline for (command.args, 0..) |arg, arg_index| {
                if (arg.value != .string and arg_index == index) {
                    // An empty value has no possible value, so clap reports it missing.
                    if (arg.value == .bool and value.len == 0) return try missing_value(err, index);
                    return check_values(err, arg, specs[arg_index], value);
                }
            }
            return null;
        }

        fn check_values(
            err: *Writer,
            comptime arg: Arg,
            spec: []const u8,
            value: []const u8,
        ) Writer.Error!?Outcome {
            var pieces = std.mem.splitScalar(u8, value, ',');
            while (true) {
                const piece = if (arg.delimited) pieces.next() orelse break else value;
                if (arg.value == .bool) {
                    if (std.mem.eql(u8, piece, "true") or std.mem.eql(u8, piece, "false")) {
                        if (!arg.delimited) break;
                        continue;
                    }
                    return try invalid_bool(err, spec, piece);
                }
                var reason: [64]u8 = undefined;
                if (try value_error(arg.value, piece, &reason)) |text| {
                    try err.print("error: invalid value '{s}' for '{s}': {s}\n\n", .{
                        piece,
                        spec,
                        text,
                    });
                    return try more_information(err);
                }
                if (!arg.delimited) break;
            }
            return null;
        }

        fn invalid_bool(err: *Writer, spec: []const u8, value: []const u8) Writer.Error!Outcome {
            try err.print("error: invalid value '{s}' for '{s}'\n", .{ value, spec });
            try err.writeAll("  " ++ possible_values ++ "\n\n");
            // clap's did-you-mean over the possible values; later ones win ties.
            var best: ?[]const u8 = null;
            var best_confidence: f64 = 0;
            for ([_][]const u8{ "true", "false" }) |candidate| {
                const confidence = rust.jaro(value, candidate);
                if (confidence > 0.7 and confidence >= best_confidence) {
                    best = candidate;
                    best_confidence = confidence;
                }
            }
            if (best) |found| try err.print("  tip: a similar value exists: '{s}'\n\n", .{found});
            return more_information(err);
        }

        fn flag_index(name: []const u8) ?usize {
            inline for (command.args, 0..) |arg, index| {
                if (std.mem.eql(u8, arg.long, name)) return index;
            }
            if (std.mem.eql(u8, name, "help")) return help_index;
            return null;
        }

        fn long_name(index: usize) []const u8 {
            assert(index <= count);
            inline for (command.args, 0..) |arg, arg_index| {
                if (arg_index == index) return arg.long;
            }
            return "help";
        }

        fn is_required(index: usize) bool {
            assert(index < count);
            inline for (command.args, 0..) |arg, arg_index| {
                if (arg_index == index) return arg.required;
            }
            unreachable; // Proof: index < count.
        }

        /// clap's did-you-mean: the long most similar to `name` (Jaro above 0.7); later
        /// options win ties, with `help` last.
        fn suggest(name: []const u8) ?usize {
            var best: ?usize = null;
            var best_confidence: f64 = 0;
            for (0..count + 1) |index| {
                const confidence = rust.jaro(name, long_name(index));
                if (confidence > 0.7 and confidence >= best_confidence) {
                    best = index;
                    best_confidence = confidence;
                }
            }
            assert(best == null or best_confidence > 0.7);
            return best;
        }

        fn write_required(writer: *Writer) Writer.Error!void {
            inline for (command.args, specs) |arg, spec| {
                if (arg.required) try writer.writeAll(" " ++ spec);
            }
        }

        fn write_full_usage(writer: *Writer, bin_name: []const u8) Writer.Error!void {
            // clap shows `[OPTIONS]` only when some option is optional (help aside).
            const has_optional = comptime for (command.args) |arg| {
                if (!arg.required) break true;
            } else false;
            try writer.print("Usage: {s}", .{bin_name});
            if (has_optional) try writer.writeAll(" [OPTIONS]");
            try write_required(writer);
            try writer.writeAll("\n\n");
        }

        /// The required options, then the optional ones in the order used (clap's "smart
        /// usage").
        fn write_smart_usage(writer: *Writer, used: Used, bin_name: []const u8) !void {
            try writer.print("Usage: {s}", .{bin_name});
            try write_required(writer);
            for (used.order[0..used.len]) |index| {
                if (index == help_index) {
                    try writer.writeAll(" --help");
                } else if (!is_required(index)) {
                    try writer.print(" {s}", .{specs[index]});
                }
            }
            try writer.writeAll("\n\n");
        }

        fn more_information(err: *Writer) Writer.Error!Outcome {
            try err.writeAll("For more information, try '--help'.\n");
            return .usage_error;
        }

        fn missing_value(err: *Writer, index: usize) Writer.Error!Outcome {
            assert(index < count);
            try err.print("error: a value is required for '{s}' but none was supplied\n", .{
                specs[index],
            });
            inline for (command.args, 0..) |arg, arg_index| {
                if (arg.value == .bool and arg_index == index) {
                    try err.writeAll("  " ++ possible_values ++ "\n");
                }
            }
            try err.writeAll("\n");
            return more_information(err);
        }

        fn missing_required(err: *Writer, used: Used, bin_name: []const u8) !Outcome {
            try err.writeAll("error: the following required arguments were not provided:\n");
            inline for (command.args, specs, 0..) |arg, spec, index| {
                if (arg.required and !used.contains(index)) try err.writeAll("  " ++ spec ++ "\n");
            }
            try err.writeAll("\n");
            try write_smart_usage(err, used, bin_name);
            return more_information(err);
        }

        fn duplicate(err: *Writer, index: usize, bin_name: []const u8) !Outcome {
            assert(index < count);
            try err.print("error: the argument '{s}' cannot be used multiple times\n\n", .{
                specs[index],
            });
            try write_full_usage(err, bin_name);
            return more_information(err);
        }

        fn unexpected(
            err: *Writer,
            name: []const u8,
            suggestion: ?usize,
            used: Used,
            bin_name: []const u8,
        ) Writer.Error!Outcome {
            try err.print("error: unexpected argument '{s}' found\n\n", .{name});
            if (suggestion) |index| {
                const long = long_name(index);
                try err.print("  tip: a similar argument exists: '--{s}'\n\n", .{long});
            }
            if (used.len > 0) {
                try write_smart_usage(err, used, bin_name);
            } else {
                try write_full_usage(err, bin_name);
            }
            return more_information(err);
        }

        fn unexpected_value(
            err: *Writer,
            value: []const u8,
            used: Used,
            bin_name: []const u8,
        ) Writer.Error!Outcome {
            assert(used.contains(help_index));
            try err.print(
                "error: unexpected value '{s}' for '--help' found; no more were expected\n\n",
                .{value},
            );
            try write_smart_usage(err, used, bin_name);
            return more_information(err);
        }
    };
}

const possible_values = "[possible values: true, false]";

/// Why `piece` fails `value`'s parser, written into `buffer` when it names the value, or null.
fn value_error(value: Value, piece: []const u8, buffer: *[64]u8) Writer.Error!?[]const u8 {
    switch (value) {
        .string, .bool => unreachable, // Strings pass, and booleans are matched by name.
        .u64 => _ = rust.parse_unsigned(u64, piece) catch |failure| {
            return rust.int_error_text(failure);
        },
        .non_zero_u32, .non_zero_u64 => {
            const number: u64 = if (value == .non_zero_u32)
                rust.parse_unsigned(u32, piece) catch |failure| return rust.int_error_text(failure)
            else
                rust.parse_unsigned(u64, piece) catch |failure| return rust.int_error_text(failure);
            if (number == 0) return "number would be zero for non-zero type";
        },
        .i32, .u32 => {
            const number = rust.parse_i64(piece) catch |failure| {
                return rust.signed_error_text(failure);
            };
            const min: i64 = if (value == .i32) std.math.minInt(i32) else 0;
            const max: i64 = if (value == .i32) std.math.maxInt(i32) else std.math.maxInt(u32);
            if (number < min or number > max) {
                var writer: Writer = .fixed(buffer);
                try writer.print("{d} is not in {d}..={d}", .{ number, min, max });
                return writer.buffered();
            }
        },
    }
    return null;
}

/// `--long <id>` for each option.
fn value_names(comptime command: Command) [command.args.len][]const u8 {
    var names: [command.args.len][]const u8 = undefined;
    for (&names, command.args) |*name, arg| {
        name.* = "--" ++ arg.long ++ " <" ++ (arg.id orelse arg.long) ++ ">";
    }
    return names;
}

/// Runs each `### <args>` record of `cases` (exit status, then stdout and stderr together,
/// as a commonware binary printed them) through `run`, and checks there are `count`.
pub fn expect_cases(
    cases: []const u8,
    count: usize,
    run: fn (std.mem.Allocator, []const []const u8, *Writer) anyerror!u8,
) !void {
    const gpa = std.testing.allocator;
    var records = std.mem.splitSequence(u8, cases[4..], "\n### ");
    var seen: usize = 0;
    while (records.next()) |record| : (seen += 1) {
        const args_end = std.mem.indexOfScalar(u8, record, '\n').?;
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(gpa);
        var words = std.mem.tokenizeScalar(u8, record[0..args_end], ' ');
        while (words.next()) |word| try args.append(gpa, word);
        const rest = record[args_end + 1 ..];
        const exit_end = std.mem.indexOfScalar(u8, rest, '\n').?;
        const expected_exit = try std.fmt.parseInt(u8, rest["exit=".len..exit_end], 10);
        const expected = std.mem.trimEnd(u8, rest[exit_end + 1 ..], "\n");
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        errdefer std.debug.print("case: {s}\n", .{record[0..args_end]});
        try std.testing.expectEqual(expected_exit, try run(gpa, args.items, &out.writer));
        try std.testing.expectEqualStrings(expected, std.mem.trimEnd(u8, out.written(), "\n"));
    }
    try std.testing.expectEqual(count, seen);
}
