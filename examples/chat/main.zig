//! Send encrypted messages to a group of friends (commonware `examples/chat`).
//!
//! ```sh
//! zig build run-chat -- --me=1@3001 --friends=1,2,3,4
//! zig build run-chat -- --me=2@3002 --friends=1,2,3,4 --bootstrappers=1@127.0.0.1:3001
//! ```
//!
//! Each friend is an ed25519 key from a `u64` seed. The UI (`handler.zig`) runs in the
//! terminal with plain ANSI escapes, as ratatui draws commonware's. The network is p2p's
//! authenticated discovery dialect, which the p2p lane is still porting, so the binary stops
//! after loading its configuration until it lands.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const cli = @import("cli.zig");

const ed25519 = zigware.cryptography.ed25519;
const traces = zigware.runtime.telemetry.traces;

/// Unique namespace to avoid message replay attacks.
pub const namespace = "_COMMONWARE_EXAMPLES_CHAT";
/// Capacity of the network's internal actor mailboxes.
pub const mailbox_size = 1_000;
/// Chat lines are short, so this payload limit only has to cover them.
pub const message_size_max: u32 = 16 * 1024;
/// Messages per second each friend may send on the chat channel.
pub const message_rate_per_second = 128;
/// The log target of `main`'s events.
pub const target = "commonware_chat";

/// Rust's panic exit status, used for commonware's panics.
const panic_status: u8 = 101;

/// The configuration commonware's `main` builds before starting the network.
pub const Setup = struct {
    signer: ed25519.PrivateKey,
    port: u16,
    /// The authorized peers, sorted.
    recipients: []ed25519.PublicKey,
    bootstrappers: []const Bootstrapper,
    max_peers_per_set: usize,

    pub const Bootstrapper = struct { key: ed25519.PublicKey, address: Io.net.IpAddress };
};

/// Derives the keys from `arguments` and logs them as commonware does.
pub fn setup(gpa: Allocator, arguments: cli.Arguments, tracer: traces.Tracer) !Setup {
    assert(arguments.friends.len > 0);
    const signer = ed25519.PrivateKey.from_seed(arguments.key);
    tracer.event(.info, "loaded signer", .{ .key = signer.public_key() });
    tracer.event(.info, "loaded port", .{ .port = arguments.port });
    const recipients = try gpa.alloc(ed25519.PublicKey, arguments.friends.len);
    errdefer gpa.free(recipients);
    for (recipients, arguments.friends) |*recipient, friend| {
        recipient.* = ed25519.PrivateKey.from_seed(friend).public_key();
        tracer.event(.info, "registered authorized key", .{ .key = recipient.* });
    }
    std.sort.pdq(ed25519.PublicKey, recipients, {}, less_than);
    const bootstrappers = try gpa.alloc(Setup.Bootstrapper, arguments.bootstrappers.len);
    for (bootstrappers, arguments.bootstrappers) |*bootstrapper, given| {
        const key = ed25519.PrivateKey.from_seed(given.key).public_key();
        bootstrapper.* = .{ .key = key, .address = given.address };
    }
    const local = signer.public_key();
    const max_peers_per_set =
        zigware.p2p.sizing.peer_set_limit(ed25519.PublicKey, recipients, local);
    assert(max_peers_per_set >= recipients.len);
    return .{
        .signer = signer,
        .port = arguments.port,
        .recipients = recipients,
        .bootstrappers = bootstrappers,
        .max_peers_per_set = max_peers_per_set,
    };
}

fn less_than(_: void, a: ed25519.PublicKey, b: ed25519.PublicKey) bool {
    return ed25519.PublicKey.order(a, b) == .lt;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(io, &stderr_buffer);
    const stderr = &stderr_writer.interface;
    defer stdout.flush() catch {};
    defer stderr.flush() catch {};
    const bin_name = if (args.len > 0) std.fs.path.basename(args[0]) else "chat";

    var panic: cli.Panic = .{};
    const given = args[@min(args.len, 1)..];
    const outcome = cli.parse(arena, given, bin_name, stderr, &panic) catch |err|
        switch (err) {
            error.Panic => {
                try stderr.print("error: {s}\n", .{panic.message()});
                return panic_status;
            },
            else => |other| return other,
        };
    const arguments = switch (outcome) {
        .help => {
            try cli.write_help(stdout, bin_name);
            return 0;
        },
        .usage_error => return 2,
        .run => |arguments| arguments,
    };
    var collector: traces.Collector = .init(init.gpa, .{});
    defer collector.deinit();
    const configured = try setup(arena, arguments, collector.tracer(target));
    try stderr.print("loaded config: friends={d} port={d} max_peers_per_set={d}\n", .{
        configured.recipients.len,
        configured.port,
        configured.max_peers_per_set,
    });
    try stderr.writeAll("error: p2p's authenticated discovery network is not ported yet\n");
    return 1;
}

test {
    _ = @import("chat_test.zig");
}
