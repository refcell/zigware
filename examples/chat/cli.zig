//! Command-line parsing for chat: clap's parsing, help, and errors for commonware's
//! `commonware-chat` (`ui.clap`; exit 0 for help, 2 for usage errors), then the checks
//! commonware's `main` makes afterwards, which fail with its panic messages.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const ui = @import("ui");

const rust = ui.rust;
const parse_unsigned = rust.parse_unsigned;
const int_error_debug = rust.int_error_debug;
pub const parse_socket_address = rust.parse_socket_address;

pub const about = "send encrypted messages to a group of friends";

const Clap = ui.clap.Parser(.{ .about = about, .args = &.{
    .{ .long = "me", .required = true },
    .{ .long = "friends", .required = true, .delimited = true, .integer = true },
    .{ .long = "bootstrappers", .delimited = true },
} });

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

pub const write_help = Clap.write_help;

/// Parses `args` (without argv[0]) as clap does, then checks them as commonware's `main`.
pub fn parse(
    gpa: Allocator,
    args: []const []const u8,
    bin_name: []const u8,
    err: *Io.Writer,
    panic: *Panic,
) (Io.Writer.Error || Allocator.Error || error{Panic})!Outcome {
    const values = switch (try Clap.parse(args, bin_name, err)) {
        .help => return .help,
        .usage_error => return .usage_error,
        .run => |values| values,
    };
    const friends = try parse_friends(gpa, values[1].?);
    assert(friends.len > 0);
    return .{ .run = try checked(gpa, values[0].?, friends, values[2], panic) };
}

/// `--friends`, which clap already checked: comma-separated `u64` values.
fn parse_friends(gpa: Allocator, text: []const u8) Allocator.Error![]const u64 {
    var friends: std.ArrayList(u64) = .empty;
    errdefer friends.deinit(gpa);
    var pieces = std.mem.splitScalar(u8, text, ',');
    while (pieces.next()) |piece| {
        const friend = parse_unsigned(u64, piece) catch unreachable; // Proof: clap checked it.
        try friends.append(gpa, friend);
    }
    assert(friends.items.len > 0);
    return friends.toOwnedSlice(gpa);
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
