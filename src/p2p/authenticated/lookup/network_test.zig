//! Tests of the lookup network over the deterministic runtime (commonware `lookup/mod.rs`
//! tests).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const stream = @import("stream");
const metrics = runtime.telemetry.metrics;
const p2p = @import("../../root.zig");
const types = @import("../../types.zig");
const data = @import("../data.zig");
const network_mod = @import("network.zig");

const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Upgrader = stream.SakeCups(PrivateKey, cryptography.ChaCha20Poly1305);
const Transport = runtime.network.deterministic.Network;
const Net = network_mod.Network(Upgrader, Transport);
const Entry = Net.Tracker.PeerMap.Entry;
const gpa = testing.allocator;

const base_port: u16 = 3000;
const peers_max = 25;

fn upgrader(signer: PrivateKey) Upgrader {
    return .init(.{
        .signer = signer,
        .synchrony_bound_ms = 5_000,
        .max_handshake_age_ms = 10_000,
        .version = .v1,
    }, .v1);
}

fn local_socket(port: u16) codec.SocketAddr {
    return .{ .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) }, .port = port };
}

/// commonware's `Config::test`: `local` with faster dialing and pings.
fn test_config(signer: PrivateKey, port: u16, max_message_size: u32) Net.Config {
    var config = Net.Config.local(.{
        .upgrader = upgrader(signer),
        .namespace = "test_namespace",
        .listen = network_mod.to_address(local_socket(port)),
        .max_peers_per_set = 32,
        .max_message_size = max_message_size,
        .mailbox_size = 1_000,
    });
    config.peer_connection_cooldown = .from_millis(250);
    config.allowed_handshake_rate_per_ip = .per_second(128);
    config.allowed_handshake_rate_per_subnet = .per_second(256);
    config.ping_frequency = .from_secs(1);
    config.dial_frequency = .from_millis(200);
    config.block_duration = .from_secs(60);
    return config;
}

const Node = struct {
    network: *Net,
    registered: Net.Registered,
    task: Io.Future(anyerror!void),
};

/// Every node's key and address, sorted by key, as `track` takes them.
fn peer_entries(keys: []const PublicKey, entries: []Entry) void {
    assert(keys.len == entries.len);
    for (keys, entries, 0..) |key, *entry, index| {
        const port = base_port + @as(u16, @intCast(index));
        entry.* = .{ .key = key, .value = .{ .symmetric = local_socket(port) } };
    }
    std.sort.pdq(Entry, entries, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return PublicKey.order(a.key, b.key) == .lt;
        }
    }.less);
}

fn start_nodes(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    keys: []const PublicKey,
    nodes: []Node,
) !void {
    var entries: [peers_max]Entry = undefined;
    peer_entries(keys, entries[0..keys.len]);
    const tracked: Net.Tracker.Tracked = .init_primary(.init(entries[0..keys.len]));
    for (nodes, 0..) |*node, index| {
        const port = base_port + @as(u16, @intCast(index));
        const config = test_config(PrivateKey.from_seed(index), port, 1024 * 1024);
        const network = try Net.create(gpa, io, transport, node_scope(scope, index), config);
        try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(0, tracked));
        node.* = .{
            .network = network,
            .registered = try network.register(0, .per_second(100)),
            .task = undefined,
        };
        node.task = try io.concurrent(run_network, .{network});
    }
}

/// Each node's metrics, under `peer_<index>` like commonware's per-peer contexts.
fn node_scope(scope: metrics.Scope, index: usize) metrics.Scope {
    var label_buffer: [32]u8 = undefined;
    // Proof: "peer_" plus a usize fits in 32 bytes.
    const label = std.fmt.bufPrint(&label_buffer, "peer_{d}", .{index}) catch unreachable;
    return scope.child(label);
}

fn run_network(network: *Net) anyerror!void {
    return network.run();
}

fn stop_nodes(io: Io, nodes: []Node) void {
    for (nodes) |*node| {
        node.task.cancel(io) catch {};
        node.registered.sender.deinit();
    }
    for (nodes) |*node| {
        // Receivers drain, then report the closed network.
        while (node.registered.receiver.try_recv()) |message| {
            var owned = message;
            owned.deinit();
        } else |_| {}
        node.registered.receiver.deinit();
        node.network.destroy();
    }
}

/// Every node sends its identity to all peers until each has heard from every other
/// (commonware `run_network` with `Mode::All`).
fn connectivity(io: Io, transport: *Transport, scope: metrics.Scope, n: usize) !void {
    assert(n <= peers_max);
    var keys: [peers_max]PublicKey = undefined;
    for (keys[0..n], 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var nodes: [peers_max]Node = undefined;
    try start_nodes(io, transport, scope, keys[0..n], nodes[0..n]);
    defer stop_nodes(io, nodes[0..n]);
    var heard: [peers_max][peers_max]bool = @splat(@splat(false));
    var rounds: u32 = 0;
    while (!all_heard(&heard, n)) : (rounds += 1) {
        try testing.expect(rounds < 600);
        for (nodes[0..n], 0..) |*node, index| {
            const sent = try node.registered.sender.send(.all, &.{&keys[index].key.bytes}, true);
            gpa.free(sent);
        }
        for (nodes[0..n], 0..) |*node, index| {
            while (node.registered.receiver.try_recv()) |message| {
                var owned = message;
                defer owned.deinit();
                try testing.expectEqualSlices(u8, &owned.peer.key.bytes, owned.payload);
                for (keys[0..n], 0..) |key, from| {
                    if (key.eql(owned.peer)) heard[index][from] = true;
                }
            } else |_| {}
        }
        try io.sleep(.fromMilliseconds(100), .real);
    }
}

fn all_heard(heard: *const [peers_max][peers_max]bool, n: usize) bool {
    for (0..n) |to| {
        for (0..n) |from| {
            if (to != from and !heard[to][from]) return false;
        }
    }
    return true;
}

fn run_deterministic(seed: u64, comptime function: anytype, args: anytype) !void {
    const timeout_ns = 120 * std.time.ns_per_s;
    const config: runtime.deterministic.Config = .{ .seed = seed, .timeout_ns = timeout_ns };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    const args_all = .{ runner.io(), runner.network(), runner.metrics() } ++ args;
    try (try runner.start(function, args_all));
}

test "tracked peers connect at their addresses and exchange messages" {
    // commonware `test_determinism_all` with 25 peers; seeds 0 and 1 here.
    for ([_]u64{ 0, 1 }) |seed| try run_deterministic(seed, connectivity, .{@as(usize, 5)});
}

test "the frame fits the payload limit and its overhead" {
    var transport = Transport.init(gpa, Io.failing);
    defer transport.deinit();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const config = test_config(PrivateKey.from_seed(0), 0, 1024);
    const network = try Net.create(gpa, Io.failing, &transport, .init(&registry), config);
    defer network.destroy();
    try testing.expectEqual(1024 + data.max_payload_overhead, network.max_frame_size);
    try testing.expectEqualStrings("test_namespace_STREAM", network.stream_namespace);
}

test "the largest payload the stream carries is accepted" {
    // commonware `test_max_message_size_stream_boundary`.
    var transport = Transport.init(gpa, Io.failing);
    defer transport.deinit();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const largest: u32 = @intCast(data.max_size(Upgrader.max_size));
    const config = test_config(PrivateKey.from_seed(0), 0, largest);
    const network = try Net.create(gpa, Io.failing, &transport, .init(&registry), config);
    defer network.destroy();
    try testing.expect(network.max_frame_size <= Upgrader.max_size);
}
