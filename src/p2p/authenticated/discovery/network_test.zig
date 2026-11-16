//! Tests of the discovery network over the deterministic runtime (commonware
//! `discovery/mod.rs` and `discovery/network.rs` tests).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const stream = @import("stream");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const p2p = @import("../../root.zig");
const data = @import("../data.zig");
const network_mod = @import("network.zig");
const config_mod = @import("config.zig");

const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Upgrader = stream.SakeCups(PrivateKey, cryptography.ChaCha20Poly1305);
const Transport = runtime.network.deterministic.Network;
const Net = network_mod.Network(Upgrader, Transport);
const Bootstrapper = config_mod.Bootstrapper(PublicKey);
const gpa = testing.allocator;

const base_port: u16 = 3000;
const peers_max = 5;

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

/// commonware's `Config::test`: `local` with faster dialing and gossip.
fn test_config(
    signer: PrivateKey,
    port: u16,
    bootstrappers: []const Bootstrapper,
    max_message_size: u32,
) Net.Config {
    const socket = local_socket(port);
    var config = Net.Config.local(.{
        .upgrader = upgrader(signer),
        .namespace = "test_namespace",
        .listen = network_mod.to_address(socket),
        .dialable = .{ .socket = socket },
        .bootstrappers = bootstrappers,
        .max_peers_per_set = 32,
        .max_message_size = max_message_size,
        .mailbox_size = 1_000,
    });
    config.peer_connection_cooldown = .from_millis(250);
    config.allowed_handshake_rate_per_ip = .per_second(128);
    config.allowed_handshake_rate_per_subnet = .per_second(256);
    config.dial_frequency = .from_millis(200);
    config.gossip_bit_vec_frequency = .from_secs(1);
    config.block_duration = .from_secs(60);
    return config;
}

const Node = struct {
    network: *Net,
    registered: Net.Registered,
    task: Io.Future(anyerror!void),
};

fn start_nodes(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    keys: []const PublicKey,
    nodes: []Node,
) !void {
    const first: p2p.Ingress = .{ .socket = local_socket(base_port) };
    const bootstrap = [_]Bootstrapper{.{ .peer = keys[0], .ingress = first }};
    const sorted = try gpa.dupe(PublicKey, keys);
    defer gpa.free(sorted);
    std.sort.pdq(PublicKey, sorted, {}, PublicKey.less_than);
    for (nodes, 0..) |*node, index| {
        const port = base_port + @as(u16, @intCast(index));
        const bootstrappers: []const Bootstrapper = if (index == 0) &.{} else &bootstrap;
        const signer = PrivateKey.from_seed(index);
        const config = test_config(signer, port, bootstrappers, 1024 * 1024);
        const network = try Net.create(gpa, io, transport, node_scope(scope, index), config);
        const tracked: p2p.TrackedPeers(PublicKey) = .init_primary(.init(sorted));
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

/// Every node sends its identity to all peers until each has heard from every other.
fn connectivity(io: Io, transport: *Transport, scope: metrics.Scope, n: usize) !void {
    assert(n <= peers_max);
    var keys: [peers_max]PublicKey = undefined;
    for (keys[0..n], 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var nodes: [peers_max]Node = undefined;
    try start_nodes(io, transport, scope, keys[0..n], nodes[0..n]);
    defer stop_nodes(io, nodes[0..n]);
    var heard: [peers_max][peers_max]bool = @splat(@splat(false));
    var rounds: u32 = 0;
    while (!all_heard(heard, n)) : (rounds += 1) {
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
    try expect_connected_metrics(scope, n);
}

/// Once every node heard every other: node 0 records a connection to each peer, and its
/// greeting and data counters moved without any invalid message.
fn expect_connected_metrics(scope: metrics.Scope, n: usize) !void {
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    var connected = metrics.metric_samples(text, "peer_0_tracker_directory_connected");
    var count: usize = 0;
    while (connected.next()) |_| count += 1;
    try testing.expectEqual(n - 1, count);
    var expected: usize = 0;
    const names = [_][]const u8{
        "peer_0_spawner_messages_sent_total",
        "peer_0_spawner_messages_received_total",
    };
    for (names) |name| {
        var samples = metrics.metric_samples(text, name);
        while (samples.next()) |sample| {
            const value = try std.fmt.parseInt(u64, sample.value, 10);
            if (std.mem.endsWith(u8, sample.labels, "message=\"invalid\"")) {
                try testing.expectEqual(@as(u64, 0), value);
                continue;
            }
            const greeting = std.mem.endsWith(u8, sample.labels, "message=\"greeting\"");
            const data_0 = std.mem.endsWith(u8, sample.labels, "message=\"data_0\"");
            if (!greeting and !data_0) continue;
            try testing.expect(value > 0);
            expected += 1;
        }
    }
    // Greeting and data, sent and received, for at least every connected peer.
    try testing.expect(expected >= 4 * (n - 1));
    var attempts = metrics.metric_samples(text, "peer_1_dialer_attempts_total");
    try testing.expect(attempts.next() != null);
}

fn all_heard(heard: [peers_max][peers_max]bool, n: usize) bool {
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

test "peers discover each other through a bootstrapper and exchange messages" {
    for ([_]u64{ 0, 1 }) |seed| try run_deterministic(seed, connectivity, .{@as(usize, 5)});
}

test "the payload limit stays configured while the frame grows to carry gossip" {
    // commonware `test_gossip_sizes_frame_not_payload_limit`.
    const signer = PrivateKey.from_seed(0);
    const data_frame: usize = data.max_payload_overhead;
    var sizes: [2]usize = undefined;
    for ([_]usize{ 2, 200_000 }, &sizes) |capacity, *size| {
        var config = test_config(signer, 0, &.{}, 0);
        config.max_peers_per_set = capacity;
        size.* = config.max_gossip_size();
    }
    try testing.expect(data_frame < sizes[0] and sizes[0] < sizes[1]);
    var transport = Transport.init(gpa, Io.failing);
    defer transport.deinit();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    for ([_]usize{ 2, 200_000 }, sizes) |capacity, size| {
        var config = test_config(signer, 0, &.{}, 0);
        config.max_peers_per_set = capacity;
        const network = try Net.create(gpa, Io.failing, &transport, .init(&registry), config);
        defer network.destroy();
        try testing.expectEqual(@as(u32, 0), network.config.max_message_size);
        try testing.expectEqual(@as(u32, @intCast(size)), network.max_frame_size);
    }
}

test "greeting and verifier use the upgrader identity and gossip namespace" {
    var transport = Transport.init(gpa, Io.failing);
    defer transport.deinit();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const signer = PrivateKey.from_seed(0);
    const peer_signer = PrivateKey.from_seed(1);
    var config = test_config(signer, 7000, &.{}, 64 * 1024);
    config.namespace = "discovery-test";
    config.max_peers_per_set = 2;
    const network = try Net.create(gpa, Io.failing, &transport, .init(&registry), config);
    defer network.destroy();
    try testing.expectEqualStrings("discovery-test_TRACKER_IP", network.ip_namespace);
    const Info = Net.Tracker.Info;
    const ingress: p2p.Ingress = .{ .socket = local_socket(7000) };
    const ip_namespace = "discovery-test_TRACKER_IP";
    const peer_info = Info.sign(peer_signer.public_key(), ip_namespace, ingress, 0, &peer_signer);
    try network.peer_config.verifier.validate(.UNIX_EPOCH, &.{peer_info});
    const greeting = network.tracker.directory.info(signer.public_key()).?;
    try testing.expect(greeting.public_key.eql(signer.public_key()));
    try testing.expect(greeting.ingress.eql(ingress));
    try testing.expect(greeting.verify("discovery-test_TRACKER_IP"));
}
