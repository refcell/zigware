//! Command-line parsing for chat, with the help and error text clap prints for commonware's
//! `commonware-chat` (exit 0 for help, 2 for usage errors), and the checks commonware's
//! `main` makes afterwards, which fail with its panic messages.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const about = "send encrypted messages to a group of friends";

const help_text = "Options:\n" ++
    "      --me <me>                        \n" ++
    "      --friends <friends>              \n" ++
    "      --bootstrappers <bootstrappers>  \n" ++
    "  -h, --help                           Print help\n";

/// A bootstrapper: its key seed and socket address.
pub const Bootstrapper = struct { key: u64, address: Io.net.IpAddress };

/// Parsed arguments; slices are owned by the allocator given to `parse`.
pub const Arguments = struct {
    key: u64,
    port: u16,
    friends: []const u64,
    bootstrappers: []const Bootstrapper,
};

pub const Outcome = union(enum) {
    run: Arguments,
    /// Print the help (stdout) and exit 0.
    help,
    /// The error text is in the writer (stderr); exit 2.
    usage_error,
};

/// Long options in clap's order, which decides ties between suggestions.
const longs = [_][]const u8{ "me", "friends", "bootstrappers", "help" };
const value_names = [_][]const u8{
    "--me <me>",
    "--friends <friends>",
    "--bootstrappers <bootstrappers>",
};

const Used = [longs.len]bool;

pub fn write_help(writer: *Io.Writer, bin_name: []const u8) Io.Writer.Error!void {
    try writer.print("{s}\n\n", .{about});
    try write_full_usage(writer, bin_name);
    try writer.writeAll(help_text);
}

/// Parses `args` (without argv[0]) as clap does. Values stay unparsed in `raw`.
pub fn parse(
    gpa: Allocator,
    args: []const []const u8,
    bin_name: []const u8,
    err: *Io.Writer,
    panic: *Panic,
) (Io.Writer.Error || Allocator.Error || error{Panic})!Outcome {
    var used: Used = @splat(false);
    var values: [3]?[]const u8 = @splat(null);
    var pending: ?usize = null;
    for (args) |arg| {
        if (pending) |index| {
            // clap reports a missing value before a repeated option.
            if (arg.len > 1 and arg[0] == '-') return missing_value(err, index);
            if (values[index] != null) return duplicate(err, index, bin_name);
            values[index] = arg;
            pending = null;
            continue;
        }
        if (arg.len < 2 or arg[0] != '-') return unexpected(err, arg, null, used, bin_name);
        if (arg[1] != '-') {
            if (arg[1] == 'h') return .help;
            return unexpected(err, arg[0..2], null, used, bin_name);
        }
        const body = arg[2..];
        const equals = std.mem.indexOfScalar(u8, body, '=');
        const name = body[0 .. equals orelse body.len];
        const value: ?[]const u8 = if (equals) |index| body[index + 1 ..] else null;
        const index = flag_index(name) orelse {
            const suggestion = suggest(name);
            if (suggestion) |found| used[found] = true;
            return unexpected(err, arg[0 .. 2 + name.len], suggestion, used, bin_name);
        };
        if (index == 3) {
            used[3] = true;
            if (value) |text| return unexpected_value(err, text, used, bin_name);
            return .help;
        }
        used[index] = true;
        if (value) |text| {
            if (values[index] != null) return duplicate(err, index, bin_name);
            values[index] = text;
        } else pending = index;
    }
    if (pending) |index| return missing_value(err, index);
    if (!used[0] or !used[1]) return missing_required(err, used, bin_name);
    const friends = try parse_friends(gpa, values[1].?, err) orelse return .usage_error;
    assert(friends.len > 0);
    return .{ .run = try checked(gpa, values[0].?, friends, values[2], panic) };
}

fn flag_index(name: []const u8) ?usize {
    for (longs, 0..) |long, index| if (std.mem.eql(u8, long, name)) return index;
    return null;
}

/// `--friends`: comma-separated `u64` values, each checked by clap.
fn parse_friends(gpa: Allocator, text: []const u8, err: *Io.Writer) !?[]const u64 {
    var friends: std.ArrayList(u64) = .empty;
    errdefer friends.deinit(gpa);
    var pieces = std.mem.splitScalar(u8, text, ',');
    while (pieces.next()) |piece| {
        const friend = parse_unsigned(u64, piece) catch |failure| {
            try err.print("error: invalid value '{s}' for '--friends <friends>': {s}\n\n", .{
                piece,
                int_error_text(failure),
            });
            try err.writeAll("For more information, try '--help'.\n");
            friends.deinit(gpa);
            return null;
        };
        try friends.append(gpa, friend);
    }
    assert(friends.items.len > 0);
    return try friends.toOwnedSlice(gpa);
}

/// commonware's checks after clap: `--me` as `<key>@<port>`, unique friends, and each
/// bootstrapper as `<key>@<ip>:<port>`, in commonware's order.
fn checked(
    gpa: Allocator,
    me: []const u8,
    friends: []const u64,
    bootstrappers_text: ?[]const u8,
    panic: *Panic,
) (Allocator.Error || error{Panic})!Arguments {
    var parts = std.mem.splitScalar(u8, me, '@');
    const key_text = parts.first();
    const key = parse_unsigned(u64, key_text) catch |failure|
        return panic.fail("Key not well-formed: {s}", .{int_error_debug(failure)});
    const port_text = parts.next() orelse return panic.fail(out_of_bounds, .{});
    const port = parse_unsigned(u16, port_text) catch |failure|
        return panic.fail("Port not well-formed: {s}", .{int_error_debug(failure)});
    for (friends, 0..) |friend, index| {
        for (friends[0..index]) |earlier| {
            if (earlier == friend) return panic.fail("public keys are unique: DuplicateKey", .{});
        }
    }
    var bootstrappers: std.ArrayList(Bootstrapper) = .empty;
    errdefer bootstrappers.deinit(gpa);
    if (bootstrappers_text) |text| {
        var entries = std.mem.splitScalar(u8, text, ',');
        while (entries.next()) |entry| {
            var fields = std.mem.splitScalar(u8, entry, '@');
            const bootstrapper_key = parse_unsigned(u64, fields.first()) catch |failure| {
                const debug = int_error_debug(failure);
                return panic.fail("Bootstrapper key not well-formed: {s}", .{debug});
            };
            const address_text = fields.next() orelse return panic.fail(out_of_bounds, .{});
            const address = parse_socket_address(address_text) orelse return panic.fail(
                "Bootstrapper address not well-formed: AddrParseError(Socket)",
                .{},
            );
            try bootstrappers.append(gpa, .{ .key = bootstrapper_key, .address = address });
        }
    }
    return .{
        .key = key,
        .port = port,
        .friends = friends,
        .bootstrappers = try bootstrappers.toOwnedSlice(gpa),
    };
}

const out_of_bounds = "index out of bounds: the len is 1 but the index is 1";

/// Rust's `SocketAddr::from_str`: `a.b.c.d:port` or `[ipv6]:port`.
pub fn parse_socket_address(text: []const u8) ?Io.net.IpAddress {
    const separator = std.mem.lastIndexOfScalar(u8, text, ':') orelse return null;
    const port_text = text[separator + 1 ..];
    if (port_text.len == 0 or port_text.len > 5) return null;
    for (port_text) |byte| if (!std.ascii.isDigit(byte)) return null;
    const port = std.fmt.parseInt(u16, port_text, 10) catch return null;
    const host = text[0..separator];
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return Io.net.IpAddress.parseIp6(host[1 .. host.len - 1], port) catch null;
    }
    if (std.mem.indexOfScalar(u8, host, ':') != null) return null;
    return Io.net.IpAddress.parseIp4(host, port) catch null;
}

/// Rust `IntErrorKind`.
pub const ParseIntError = error{ Empty, InvalidDigit, PosOverflow };

/// Rust `str::parse::<T>()` for an unsigned integer: an optional `+`, then decimal digits.
pub fn parse_unsigned(comptime T: type, text: []const u8) ParseIntError!T {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    if (text.len == 0) return error.Empty;
    const digits = if (text[0] == '+' and text.len > 1) text[1..] else text;
    assert(digits.len > 0);
    var value: T = 0;
    for (digits) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidDigit;
        const shifted = std.math.mul(T, value, 10) catch return error.PosOverflow;
        value = std.math.add(T, shifted, byte - '0') catch return error.PosOverflow;
    }
    return value;
}

fn int_error_text(failure: ParseIntError) []const u8 {
    return switch (failure) {
        error.Empty => "cannot parse integer from empty string",
        error.InvalidDigit => "invalid digit found in string",
        error.PosOverflow => "number too large to fit in target type",
    };
}

fn int_error_debug(failure: ParseIntError) []const u8 {
    return switch (failure) {
        error.Empty => "ParseIntError { kind: Empty }",
        error.InvalidDigit => "ParseIntError { kind: InvalidDigit }",
        error.PosOverflow => "ParseIntError { kind: PosOverflow }",
    };
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

/// Jaro similarity of two byte strings (strsim 0.11 `jaro`), as in the estimator's CLI.
fn jaro(a_full: []const u8, b_full: []const u8) f64 {
    const a = a_full[0..@min(a_full.len, 64)];
    const b = b_full[0..@min(b_full.len, 64)];
    if (a.len == 0 and b.len == 0) return 1.0;
    if (a.len == 0 or b.len == 0) return 0.0;
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
    const t: f64 = @floatFromInt(transpositions);
    const a_len: f64 = @floatFromInt(a.len);
    const b_len: f64 = @floatFromInt(b.len);
    return (m / a_len + m / b_len + (m - t) / m) / 3.0;
}

fn write_full_usage(err: *Io.Writer, bin_name: []const u8) Io.Writer.Error!void {
    try err.print("Usage: {s} [OPTIONS] --me <me> --friends <friends>\n\n", .{bin_name});
}

/// The required arguments plus the options already used (clap's "smart usage").
fn write_smart_usage(err: *Io.Writer, used: Used, bin_name: []const u8) !void {
    try err.print("Usage: {s} --me <me> --friends <friends>", .{bin_name});
    if (used[2]) try err.writeAll(" --bootstrappers <bootstrappers>");
    if (used[3]) try err.writeAll(" --help");
    try err.writeAll("\n\n");
}

fn more_information(err: *Io.Writer) Io.Writer.Error!Outcome {
    try err.writeAll("For more information, try '--help'.\n");
    return .usage_error;
}

fn missing_value(err: *Io.Writer, index: usize) Io.Writer.Error!Outcome {
    assert(index < value_names.len);
    try err.print("error: a value is required for '{s}' but none was supplied\n\n", .{
        value_names[index],
    });
    return more_information(err);
}

fn missing_required(err: *Io.Writer, used: Used, bin_name: []const u8) !Outcome {
    assert(!used[0] or !used[1]);
    try err.writeAll("error: the following required arguments were not provided:\n");
    if (!used[0]) try err.writeAll("  --me <me>\n");
    if (!used[1]) try err.writeAll("  --friends <friends>\n");
    try err.writeAll("\n");
    try write_smart_usage(err, used, bin_name);
    return more_information(err);
}

fn duplicate(err: *Io.Writer, index: usize, bin_name: []const u8) !Outcome {
    try err.print("error: the argument '{s}' cannot be used multiple times\n\n", .{
        value_names[index],
    });
    try write_full_usage(err, bin_name);
    return more_information(err);
}

/// An unknown argument: with a suggestion, clap shows smart usage; otherwise full usage.
fn unexpected(
    err: *Io.Writer,
    name: []const u8,
    suggestion: ?usize,
    used: Used,
    bin_name: []const u8,
) Io.Writer.Error!Outcome {
    try err.print("error: unexpected argument '{s}' found\n\n", .{name});
    if (suggestion) |index| {
        try err.print("  tip: a similar argument exists: '--{s}'\n\n", .{longs[index]});
        try write_smart_usage(err, used, bin_name);
    } else {
        try write_full_usage(err, bin_name);
    }
    return more_information(err);
}

fn unexpected_value(err: *Io.Writer, value: []const u8, used: Used, bin_name: []const u8) !Outcome {
    try err.print("error: unexpected value '{s}' for '--help' found; no more were expected\n\n", .{
        value,
    });
    try write_smart_usage(err, used, bin_name);
    return more_information(err);
}

/// A failure commonware reports with a panic; the message is commonware's.
pub const Panic = struct {
    buffer: [256]u8 = undefined,
    len: usize = 0,

    pub fn message(panic: *const Panic) []const u8 {
        return panic.buffer[0..panic.len];
    }

    pub fn fail(panic: *Panic, comptime format: []const u8, args: anytype) error{Panic} {
        var writer: Io.Writer = .fixed(&panic.buffer);
        writer.print(format, args) catch {}; // Truncated: the buffer is full.
        panic.len = writer.end;
        return error.Panic;
    }
};
