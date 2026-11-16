//! Send encrypted messages to a group of friends (commonware `examples/chat`).
//!
//! ```sh
//! zig build run-chat -- --me=1@3001 --friends=1,2,3,4
//! zig build run-chat -- --me=2@3002 --friends=1,2,3,4 --bootstrappers=1@127.0.0.1:3001
//! ```
//!
//! Each friend is an ed25519 key from a `u64` seed. Friends find each other through p2p's
//! authenticated discovery network on 127.0.0.1, on the production runtime, and the UI
//! (`handler.zig`) runs in the terminal with plain ANSI escapes, as ratatui draws commonware's.
//! Connected friends show in the Metrics pane as `network_tracker_directory_connected`
//! samples, one per friend (commonware's README still names the removed `p2p_connections`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const cli = @import("cli.zig");
const clock = @import("clock.zig");
const handler = @import("handler.zig");
const terminal_mod = @import("terminal.zig");

const ed25519 = zigware.cryptography.ed25519;
const traces = zigware.runtime.telemetry.traces;
const production = zigware.runtime.production;
const discovery = zigware.p2p.authenticated.discovery;
const Upgrader = zigware.stream.SakeCups(ed25519.PrivateKey, zigware.cryptography.ChaCha20Poly1305);
const Net = discovery.Network(Upgrader, production.network.Network);

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
    var zone = clock.Zone.load(init.gpa, io, init.environ_map.get("TZ"));
    defer zone.deinit();
    var random: [8]u8 = undefined;
    io.random(&random);
    const storage_directory = try std.fmt.allocPrint(arena, "/tmp/commonware_tokio_runtime_{d}", .{
        std.mem.readInt(u64, &random, .little),
    });
    var runner: production.Runner = undefined;
    try runner.init(init.gpa, .{ .storage_directory = storage_directory });
    defer runner.deinit();
    try runner.start(run, .{ &runner, init.gpa, &collector, &zone, configured });
    return 0;
}

/// Discovery on 127.0.0.1:`port`, configured as commonware's `main` does.
fn network_config(arena: Allocator, configured: Setup) !Net.Config {
    const local: zigware.codec.SocketAddr = .{
        .ip = .{ .v4 = zigware.codec.Ipv4.init(127, 0, 0, 1) },
        .port = configured.port,
    };
    const Bootstrapper = discovery.Bootstrapper(ed25519.PublicKey);
    const bootstrappers = try arena.alloc(Bootstrapper, configured.bootstrappers.len);
    for (bootstrappers, configured.bootstrappers) |*bootstrapper, given| {
        const address: zigware.codec.SocketAddr = .{
            .ip = discovery.network.to_ip(given.address),
            .port = given.address.getPort(),
        };
        bootstrapper.* = .{ .peer = given.key, .ingress = .{ .socket = address } };
    }
    return Net.Config.local(.{
        .upgrader = .init(.{
            .signer = configured.signer,
            .synchrony_bound_ms = 5_000,
            .max_handshake_age_ms = 10_000,
            .version = .v1,
        }, .v1),
        .namespace = namespace,
        .listen = discovery.network.to_address(local),
        .dialable = .{ .socket = local },
        .bootstrappers = bootstrappers,
        .max_peers_per_set = configured.max_peers_per_set,
        .max_message_size = message_size_max,
        .mailbox_size = mailbox_size,
    });
}

fn run(
    runner: *production.Runner,
    gpa: Allocator,
    collector: *traces.Collector,
    zone: *const clock.Zone,
    configured: Setup,
) !void {
    const io = runner.io();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const scope = runner.metrics();
    const config = try network_config(arena_state.allocator(), configured);
    const network = try Net.create(gpa, io, runner.network(), scope.child("network"), config);
    defer network.destroy();
    // In a real-world scenario, this would be updated as new peer sets are created (like when
    // the composition of a validator set changes).
    _ = network.oracle().track(0, .init_primary(.init(configured.recipients)));
    var registered = try network.register(handler.channel, .per_second(message_rate_per_second));
    defer {
        registered.sender.deinit();
        while (registered.receiver.try_recv()) |message| {
            var owned = message;
            owned.deinit();
        } else |_| {}
        registered.receiver.deinit();
    }
    var network_task = try io.concurrent(run_network, .{network});
    defer network_task.cancel(io) catch {};

    var out_buffer: [64 * 1024]u8 = undefined;
    var out_writer = Io.File.stdout().writer(io, &out_buffer);
    const out = &out_writer.interface;
    var terminal = try terminal_mod.Terminal.enter(io, out);
    defer terminal.leave(out);
    var state: handler.State = .init(gpa);
    defer state.deinit();
    var me: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&me, "{f}", .{configured.signer.public_key()});
    try handler.run(.{
        .gpa = gpa,
        .io = io,
        .me = &me,
        .state = &state,
        .collector = collector,
        .scope = &scope,
        .zone = zone,
        .terminal = .{
            .out = out,
            .context = &terminal,
            .size = terminal_mod.Terminal.size,
            .keyboard = terminal.keyboard(),
        },
    }, &registered.sender, &registered.receiver);
}

fn run_network(network: *Net) anyerror!void {
    return network.run();
}

test {
    _ = @import("chat_test.zig");
}
