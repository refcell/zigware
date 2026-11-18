//! Command-line parsing for log: clap's parsing, help, and errors for commonware's
//! `commonware-log` (`ui.clap`; exit 0 for help, 2 for usage errors), then the checks
//! commonware's `main` makes afterwards, which fail with its panic messages.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const ui = @import("ui");

const rust = ui.rust;

pub const about = "generate secret logs and agree on their hash";

const Clap = ui.clap.Parser(.{ .about = about, .args = &.{
    .{ .long = "bootstrappers", .delimited = true },
    .{ .long = "me", .required = true },
    .{
        .long = "participants",
        .required = true,
        .delimited = true,
        .integer = true,
        .help = "All participant keys (arbiter and contributors), including your own",
    },
    .{ .long = "storage-dir", .required = true },
} });

/// A bootstrapper: its key seed and socket address.
pub const Bootstrapper = rust.Bootstrapper;

/// Parsed arguments; slices are owned by the allocator given to `parse`.
pub const Arguments = struct {
    key: u64,
    port: u16,
    participants: []const u64,
    bootstrappers: []const Bootstrapper,
    storage_directory: []const u8,
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
    const me = values[1].?;
    var parts = std.mem.splitScalar(u8, me, '@');
    const key_text = parts.first();
    const port_text = parts.next() orelse return panic.fail("Identity not well-formed", .{});
    if (parts.next() != null) return panic.fail("Identity not well-formed", .{});
    const key = rust.parse_unsigned(u64, key_text) catch |failure|
        return panic.fail("Key not well-formed: {s}", .{rust.int_error_debug(failure)});
    const port = rust.parse_unsigned(u16, port_text) catch |failure|
        return panic.fail("Port not well-formed: {s}", .{rust.int_error_debug(failure)});
    const participants = try parse_participants(gpa, values[2].?);
    for (participants, 0..) |participant, index| {
        for (participants[0..index]) |earlier| {
            if (earlier == participant) {
                return panic.fail("public keys are unique: DuplicateKey", .{});
            }
        }
    }
    const bootstrappers = try rust.parse_bootstrappers(gpa, values[0], panic);
    assert(participants.len > 0);
    return .{ .run = .{
        .key = key,
        .port = port,
        .participants = participants,
        .bootstrappers = bootstrappers,
        .storage_directory = values[3].?,
    } };
}

/// `--participants`, which clap already checked: comma-separated `u64` values.
fn parse_participants(gpa: Allocator, text: []const u8) Allocator.Error![]const u64 {
    var participants: std.ArrayList(u64) = .empty;
    errdefer participants.deinit(gpa);
    var pieces = std.mem.splitScalar(u8, text, ',');
    while (pieces.next()) |piece| {
        // Proof: clap checked every piece.
        const participant = rust.parse_unsigned(u64, piece) catch unreachable;
        try participants.append(gpa, participant);
    }
    assert(participants.items.len > 0);
    return participants.toOwnedSlice(gpa);
}

/// A failure commonware reports with a panic; the message is commonware's.
pub const Panic = rust.Panic;
