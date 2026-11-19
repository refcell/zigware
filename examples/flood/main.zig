//! Spam peers with random messages (commonware `examples/flood`, `bin/flood.rs`).
//!
//! ```sh
//! zig build run-flood -- --hosts hosts.yaml --config <public key>.yaml
//! ```
//!
//! Reads the deployer's hosts file and this peer's config, then floods every connected peer
//! over p2p's authenticated discovery network on the production runtime, counting sent
//! messages (`flood_sender_messages`) and observing their latency
//! (`flood_receiver_latency`). Logs are tracing's JSON lines on stdout; metrics are served at
//! `GET /metrics` on the deployer's `METRICS_PORT` (9090).
//!
//! commonware listens on `0.0.0.0` for both. A peer whose host IP is a loopback address binds
//! that address instead, which changes nothing for a deployment (a loopback address is always
//! local) and lets several peers share one machine on 127.0.0.1, 127.0.0.2, ... with the same
//! ports (`examples/flood/local.sh`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const ui = @import("ui");
const lib = @import("lib.zig");

const p2p = zigware.p2p;
const ed25519 = zigware.cryptography.ed25519;
const production = zigware.runtime.production;
const metrics = zigware.runtime.telemetry.metrics;
const discovery = p2p.authenticated.discovery;
const Upgrader = zigware.stream.SakeCups(ed25519.PrivateKey, zigware.cryptography.ChaCha20Poly1305);
const Net = discovery.Network(Upgrader, production.network.Network);
const Bootstrapper = discovery.Bootstrapper(ed25519.PublicKey);

/// commonware `deployer::aws::METRICS_PORT`.
pub const metrics_port: u16 = 9090;
/// The log target: the binary's crate name.
const target = "flood";

pub const about = "Spam peers with random messages.";

/// commonware's `Command::new("runner")`.
pub const Clap = ui.clap.Parser(.{ .about = about, .args = &.{
    .{ .long = "hosts", .required = true },
    .{ .long = "config", .required = true },
} });

/// Parses `args` (without argv[0]) as clap does: help goes to `stdout` (exit 0), usage
/// errors to `stderr` (exit 2).
pub fn parse(
    args: []const []const u8,
    bin_name: []const u8,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) Io.Writer.Error!union(enum) { run: Clap.Values, exit: u8 } {
    return switch (try Clap.parse(args, bin_name, stderr)) {
        .help => {
            try Clap.write_help(stdout, bin_name);
            return .{ .exit = 0 };
        },
        .usage_error => .{ .exit = 2 },
        .run => |values| .{ .run = values },
    };
}

/// A peer from the hosts file: its key and IP.
const Peer = struct { key: ed25519.PublicKey, ip: Io.net.IpAddress };

/// Everything `run` needs, loaded before the runtime starts.
const Loaded = struct {
    gpa: Allocator,
    signer: ed25519.PrivateKey,
    config: lib.Config,
    peers: []const Peer,
    stdout: *Io.Writer,
};

fn decode_key(arena: Allocator, hex: []const u8) ![32]u8 {
    const bytes = (try zigware.formatting.from_hex(arena, hex)) orelse return error.InvalidKey;
    if (bytes.len != 32) return error.InvalidKey;
    return bytes[0..32].*;
}

fn find_ip(peers: []const Peer, key: ed25519.PublicKey) ?Io.net.IpAddress {
    for (peers) |peer| if (ed25519.PublicKey.order(peer.key, key) == .eq) return peer.ip;
    return null;
}

fn now_ns(io: Io) u64 {
    return @intCast(Io.Clock.real.now(io).nanoseconds);
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(io, &stderr_buffer);
    const stderr = &stderr_writer.interface;
    defer stderr.flush() catch {};
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    const bin_name = if (args.len > 0) std.fs.path.basename(args[0]) else "flood";
    const values = switch (try parse(args[@min(args.len, 1)..], bin_name, stdout, stderr)) {
        .run => |values| values,
        .exit => |status| {
            try stdout.flush();
            try stderr.flush();
            if (status == 0) return;
            std.process.exit(status);
        },
    };
    const arguments: struct { hosts: []const u8, config: []const u8 } = .{
        .hosts = values[0].?,
        .config = values[1].?,
    };

    const limit: Io.Limit = .limited(1 << 20);
    const hosts_text = try Io.Dir.cwd().readFileAlloc(io, arguments.hosts, arena, limit);
    const hosts = try lib.Hosts.parse(arena, hosts_text);
    const peers = try arena.alloc(Peer, hosts.hosts.len);
    for (peers, hosts.hosts) |*peer, host| {
        const key = ed25519.PublicKey.from_bytes(try decode_key(arena, host.name)) orelse
            return error.InvalidKey;
        peer.* = .{ .key = key, .ip = host.ip };
    }
    const config_text = try Io.Dir.cwd().readFileAlloc(io, arguments.config, arena, limit);
    var config = try lib.Config.parse(arena, config_text);
    try lib.write_json_event(stdout, now_ns(io), .info, target, "loaded peers", .{
        .peers = peers.len,
    });
    try stdout.flush();
    const signer = ed25519.PrivateKey.from_bytes(try decode_key(arena, config.private_key));
    config.message_size = @max(config.message_size, lib.message_size_min);

    var random: [8]u8 = undefined;
    io.random(&random);
    const storage_directory = try std.fmt.allocPrint(arena, "/tmp/commonware_tokio_runtime_{d}", .{
        std.mem.readInt(u64, &random, .little),
    });
    var runner: production.Runner = undefined;
    try runner.init(init.gpa, .{
        .storage_directory = storage_directory,
        .worker_threads = std.math.cast(u32, config.worker_threads) orelse
            return error.InvalidValue,
    });
    defer runner.deinit();
    try runner.start(run, .{ &runner, Loaded{
        .gpa = init.gpa,
        .signer = signer,
        .config = config,
        .peers = peers,
        .stdout = stdout,
    } });
}

/// The flood channel and the bootstrappers, configured as commonware's `main` does.
fn configure(arena: Allocator, loaded: *const Loaded, ip: Io.net.IpAddress) !Net.Config {
    const config = &loaded.config;
    const bootstrappers = try arena.alloc(Bootstrapper, config.bootstrappers.len);
    for (bootstrappers, config.bootstrappers) |*bootstrapper, hex| {
        const key = ed25519.PublicKey.from_bytes(try decode_key(arena, hex)) orelse
            return error.InvalidKey;
        var address = find_ip(loaded.peers, key) orelse return error.BootstrapperNotInHosts;
        address.setPort(config.port);
        bootstrapper.* = .{ .peer = key, .ingress = .{ .socket = socket(address) } };
    }
    const keys = try arena.alloc(ed25519.PublicKey, loaded.peers.len);
    for (keys, loaded.peers) |*key, peer| key.* = peer.key;
    const max_peers_per_set =
        p2p.sizing.peer_set_limit(ed25519.PublicKey, keys, loaded.signer.public_key());
    var dialable = ip;
    dialable.setPort(config.port);
    const namespace = lib.namespace ++ "_P2P";
    return Net.Config.local(.{
        .upgrader = .init(.{
            .signer = loaded.signer,
            .synchrony_bound_ms = 5_000,
            .max_handshake_age_ms = 10_000,
            .version = .v1,
        }, .v1),
        .namespace = namespace,
        .listen = bind_address(ip, config.port),
        .dialable = .{ .socket = socket(dialable) },
        .bootstrappers = bootstrappers,
        .max_peers_per_set = max_peers_per_set,
        .max_message_size = config.message_size,
        .mailbox_size = config.mailbox_size,
    });
}

/// `0.0.0.0:port`, or `ip:port` when `ip` is a loopback address.
fn bind_address(ip: Io.net.IpAddress, port: u16) Io.net.IpAddress {
    const loopback = switch (ip) {
        .ip4 => |ip4| ip4.bytes[0] == 127,
        .ip6 => |ip6| std.mem.eql(u8, &ip6.bytes, &(@as([15]u8, @splat(0)) ++ [_]u8{1})),
    };
    var address: Io.net.IpAddress = if (loopback) ip else .{ .ip4 = .unspecified(port) };
    address.setPort(port);
    assert(address.getPort() == port);
    return address;
}

fn socket(address: Io.net.IpAddress) zigware.codec.SocketAddr {
    return .{ .ip = discovery.network.to_ip(address), .port = address.getPort() };
}

fn run(runner: *production.Runner, loaded: Loaded) !void {
    const io = runner.io();
    const gpa = loaded.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const public_key = loaded.signer.public_key();
    const ip = find_ip(loaded.peers, public_key) orelse @panic("Could not find self in IPs");
    try lib.write_json_event(loaded.stdout, now_ns(io), .info, target, "loaded config", .{
        .public_key = try std.fmt.allocPrint(arena, "{f}", .{public_key}),
        .ip = try std.fmt.allocPrint(arena, "{f}", .{IpOnly{ .address = ip }}),
        .port = loaded.config.port,
        .message_size = loaded.config.message_size,
    });
    try loaded.stdout.flush();

    const scope = runner.metrics();
    var metrics_address = bind_address(ip, metrics_port);
    var server = metrics_address.listen(io, .{ .reuse_address = true }) catch
        @panic("Failed to bind metrics server");
    defer server.deinit(io);

    const network_config = try configure(arena, &loaded, ip);
    const network_scope = scope.child("network");
    const network = try Net.create(gpa, io, runner.network(), network_scope, network_config);
    defer network.destroy();
    const sorted = try arena.alloc(ed25519.PublicKey, loaded.peers.len);
    for (sorted, loaded.peers) |*key, peer| key.* = peer.key;
    std.sort.pdq(ed25519.PublicKey, sorted, {}, ed25519.PublicKey.less_than);
    _ = network.oracle().track(0, .init_primary(.init(sorted)));
    const quota = p2p.Quota.per_second(loaded.config.message_rate);
    var registered = try network.register(0, quota);
    defer {
        registered.sender.deinit();
        while (registered.receiver.try_recv()) |message| {
            var owned = message;
            owned.deinit();
        } else |_| {}
        registered.receiver.deinit();
    }
    var messages = try scope.child("flood_sender").counter("messages", "Sent messages");
    defer messages.deinit();
    const help = "Message latency in seconds";
    const buckets = &lib.latency_buckets;
    var latency = try scope.child("flood_receiver").histogram("latency", help, buckets);
    defer latency.deinit();
    try supervise(io, gpa, &scope, &server, network, &registered, loaded, .{
        .messages = messages.metric(),
        .latency = latency.metric(),
    });
}

/// Writes an IP address without its port (Rust's `IpAddr` debug form).
const IpOnly = struct {
    address: Io.net.IpAddress,

    pub fn format(self: IpOnly, writer: *Io.Writer) Io.Writer.Error!void {
        switch (self.address) {
            .ip4 => |ip4| try writer.print("{d}.{d}.{d}.{d}", .{
                ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3],
            }),
            .ip6 => |ip6| {
                var copy = ip6;
                copy.port = 0;
                var buffer: [64]u8 = undefined;
                const text = std.fmt.bufPrint(&buffer, "{f}", .{copy}) catch unreachable;
                // `[addr]:0` without the brackets and port.
                try writer.writeAll(text[1..std.mem.lastIndexOfScalar(u8, text, ']').?]);
            },
        }
    }
};

const Instruments = struct { messages: *metrics.raw.Counter, latency: *metrics.raw.Histogram };

const Outcome = union(enum) {
    network: anyerror!void,
    sender: anyerror!void,
    receiver: anyerror!void,
    metrics: Io.Cancelable!void,
};

/// Runs the network, the flood tasks, and the metrics server until one of them exits
/// (commonware's `Handle::select`), then stops the rest.
fn supervise(
    io: Io,
    gpa: Allocator,
    scope: *const metrics.Scope,
    server: *Io.net.Server,
    network: *Net,
    registered: *Net.Registered,
    loaded: Loaded,
    instruments: Instruments,
) !void {
    var buffer: [4]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);
    defer while (select.cancel()) |_| {};
    try select.concurrent(.metrics, production.telemetry.serve, .{ io, gpa, scope, server });
    try select.concurrent(.network, run_network, .{network});
    const size = loaded.config.message_size;
    const sender_args = .{ gpa, io, &registered.sender, size, instruments.messages };
    try select.concurrent(.sender, run_sender, sender_args);
    const receiver_args = .{ io, &registered.receiver, instruments.latency };
    try select.concurrent(.receiver, run_receiver, receiver_args);
    const first = try select.await();
    const failure: ?anyerror = switch (first) {
        .metrics => |result| if (result) |_| null else |err| err,
        inline else => |result| if (result) |_| null else |err| err,
    };
    if (failure) |err| {
        try lib.write_json_event(loaded.stdout, now_ns(io), .@"error", target, "task failed", .{
            .e = @errorName(err),
        });
        try loaded.stdout.flush();
    }
    assert(buffer.len == 4);
}

/// Runs the network until canceled. Like commonware (whose listener panics with "failed to
/// bind listener"), a network failure ends the process instead of silently closing every
/// channel.
fn run_network(network: *Net) Io.Cancelable!void {
    network.run() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => std.debug.panic("network failed: {t}", .{err}),
    };
}

fn run_sender(
    gpa: Allocator,
    io: Io,
    sender: *Net.Sender,
    size: u32,
    messages: *metrics.raw.Counter,
) anyerror!void {
    return lib.run_sender(gpa, io, sender, size, messages, null);
}

fn run_receiver(io: Io, receiver: *Net.Receiver, latency: *metrics.raw.Histogram) anyerror!void {
    return lib.run_receiver(io, receiver, latency, null);
}

test {
    _ = lib;
    _ = @import("main_test.zig");
}
