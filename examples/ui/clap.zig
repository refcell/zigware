//! The slice of clap 4 the examples' `main`s use: long options taking one value each (some
//! split on `,`, some parsed as `u64` piece by piece), `-h`/`--help`, and clap's help, usage,
//! and error text. Help prints to stdout with exit 0, errors to stderr with exit 2.
//!
//! clap reads arguments left to right and fails at the first error:
//!
//! - An unknown argument fails at once: a long one with smart usage once any option was used
//!   (or one is suggested), a positional or short one with full usage.
//! - A known option (or `-h`, `--help`, `--`) first settles the option before it: one still
//!   waiting for its value fails as "a value is required", and a `u64` value is checked.
//! - A second value for an option fails as "cannot be used multiple times" when it arrives.
//! - After the last argument the option before settles the same way, then missing required
//!   options fail.

const std = @import("std");
const assert = std.debug.assert;
const Writer = std.Io.Writer;
const rust = @import("rust.zig");

/// One long option taking a value (`Arg::new(long).long(long)`).
pub const Arg = struct {
    long: []const u8,
    required: bool = false,
    help: []const u8 = "",
    /// `.value_delimiter(',')`.
    delimited: bool = false,
    /// `.value_parser(value_parser!(u64))`: each piece must parse as a `u64`.
    integer: bool = false,
};

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
            inline for (command.args, specs) |arg, spec| {
                try writer.writeAll("      " ++ spec);
                try writer.splatByteAll(' ', width - spec.len + 2);
                try writer.writeAll(arg.help ++ "\n");
            }
            try writer.writeAll("  -h, --help");
            try writer.splatByteAll(' ', width + 4 - "-h, --help".len + 2);
            try writer.writeAll("Print help\n");
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

        /// Ends the option before: without a value it fails, and a `u64` value is checked.
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
                if (arg.integer and arg_index == index) {
                    return check_integers(err, arg.delimited, specs[arg_index], value);
                }
            }
            return null;
        }

        fn check_integers(
            err: *Writer,
            delimited: bool,
            spec: []const u8,
            value: []const u8,
        ) Writer.Error!?Outcome {
            var pieces = std.mem.splitScalar(u8, value, ',');
            while (true) {
                const piece = if (delimited) pieces.next() orelse break else value;
                _ = rust.parse_unsigned(u64, piece) catch |failure| {
                    try err.print("error: invalid value '{s}' for '{s}': {s}\n\n", .{
                        piece,
                        spec,
                        rust.int_error_text(failure),
                    });
                    return try more_information(err);
                };
                if (!delimited) break;
            }
            return null;
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
            try err.print("error: a value is required for '{s}' but none was supplied\n\n", .{
                specs[index],
            });
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

/// `--long <long>` for each option.
fn value_names(comptime command: Command) [command.args.len][]const u8 {
    var names: [command.args.len][]const u8 = undefined;
    for (&names, command.args) |*name, arg| name.* = "--" ++ arg.long ++ " <" ++ arg.long ++ ">";
    return names;
}
