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
        node.* = try start_node(io, transport, node_scope(scope, index), index, port, 0, tracked);
    }
}

/// Starts the node with key seed `index` listening on `port`, tracking `tracked` at `set`.
fn start_node(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    index: usize,
    port: u16,
    set: u64,
    tracked: Net.Tracker.Tracked,
) !Node {
    const config = test_config(PrivateKey.from_seed(index), port, 1024 * 1024);
    const network = try Net.create(gpa, io, transport, scope, config);
    errdefer network.destroy();
    try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(set, tracked));
    var node: Node = .{
        .network = network,
        .registered = try network.register(0, .per_second(100)),
        .task = undefined,
    };
    node.task = try io.concurrent(run_network, .{network});
    return node;
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
    for (nodes) |*node| release_node(node);
}

/// Stops one node (commonware aborts its handle) and frees it.
fn stop_node(io: Io, node: *Node) void {
    node.task.cancel(io) catch {};
    node.registered.sender.deinit();
    release_node(node);
}

fn release_node(node: *Node) void {
    // Receivers drain, then report the closed network.
    while (node.registered.receiver.try_recv()) |message| {
        var owned = message;
        owned.deinit();
    } else |_| {}
    node.registered.receiver.deinit();
    node.network.destroy();
    node.* = undefined;
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

/// Sends our identity to `recipients` until it reaches `count` peers.
fn send_until(io: Io, node: *Node, key: PublicKey, recipients: Recipients, count: usize) !void {
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        try testing.expect(attempts < 600);
        const sent = try node.registered.sender.send(recipients, &.{&key.key.bytes}, true);
        defer gpa.free(sent);
        if (sent.len == count) return;
        try io.sleep(.fromMilliseconds(100), .real);
    }
}

/// Receives until every key in `from` but `skip` has sent its identity.
fn receive_all(node: *Node, keys: []const PublicKey, skip: usize) !void {
    var heard: [peers_max]bool = @splat(false);
    var count: usize = 0;
    while (count < keys.len - 1) {
        var message = try node.registered.receiver.recv();
        defer message.deinit();
        try testing.expectEqualSlices(u8, &message.peer.key.bytes, message.payload);
        for (keys, 0..) |key, index| {
            if (index == skip or heard[index] or !key.eql(message.peer)) continue;
            heard[index] = true;
            count += 1;
        }
    }
}

const Recipients = p2p.Recipients(PublicKey);

/// Every running node but `skip` tracks the nodes' addresses at `ports` as set `set`.
fn retrack(
    nodes: []Node,
    keys: []const PublicKey,
    ports: []const u16,
    set: u64,
    skip: usize,
) !void {
    var entries: [peers_max]Entry = undefined;
    tracked_at(keys, ports, entries[0..keys.len]);
    const tracked: Net.Tracker.Tracked = .init_primary(.init(entries[0..keys.len]));
    for (nodes, 0..) |*node, index| {
        if (index == skip) continue;
        try testing.expectEqual(p2p.Feedback.ok, node.network.oracle().track(set, tracked));
    }
}

fn tracked_at(keys: []const PublicKey, ports: []const u16, entries: []Entry) void {
    for (keys, ports, entries) |key, port, *entry| {
        entry.* = .{ .key = key, .value = .{ .symmetric = local_socket(port) } };
    }
    std.sort.pdq(Entry, entries, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return PublicKey.order(a.key, b.key) == .lt;
        }
    }.less);
}

/// commonware `test_many_peer_restart_with_new_address`: every peer but the first restarts
/// at a new port three times; the others learn its address and reconnect.
fn restart_with_new_address(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const n = 5;
    var keys: [n]PublicKey = undefined;
    for (&keys, 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var ports: [n]u16 = undefined;
    for (&ports, 0..) |*port, index| port.* = base_port + @as(u16, @intCast(index));
    var nodes: [n]Node = undefined;
    try start_nodes(io, transport, scope, &keys, &nodes);
    defer stop_nodes(io, &nodes);
    for (&nodes, keys) |*node, key| try send_until(io, node, key, .all, n - 1);
    for (&nodes, 0..) |*node, index| try receive_all(node, &keys, index);
    var restarts: u16 = 0;
    for (0..3) |round| {
        for (1..n) |restarted| {
            restarts += 1;
            ports[restarted] = base_port + 100 + restarts;
            stop_node(io, &nodes[restarted]);
            const set: u64 = round * (n - 1) + restarted;
            try retrack(&nodes, &keys, &ports, set, restarted);
            var entries: [n]Entry = undefined;
            tracked_at(&keys, &ports, &entries);
            const tracked: Net.Tracker.Tracked = .init_primary(.init(&entries));
            var label_buffer: [32]u8 = undefined;
            const label_args = .{ restarted, round };
            // Proof: "peer_" and two small integers fit in 32 bytes.
            const label = std.fmt.bufPrint(&label_buffer, "peer_{d}_{d}", label_args) catch
                unreachable;
            const node_port = ports[restarted];
            const child = scope.child(label);
            nodes[restarted] =
                try start_node(io, transport, child, restarted, node_port, set, tracked);
            try send_until(io, &nodes[restarted], keys[restarted], .all, n - 1);
            for (&nodes, keys, 0..) |*node, key, index| {
                if (index == restarted) continue;
                try send_until(io, node, key, .{ .one = keys[restarted] }, 1);
            }
            try receive_all(&nodes[restarted], &keys, restarted);
        }
    }
}

test "peers that restart at new addresses reconnect" {
    try run_deterministic(0, restart_with_new_address, .{});
}

fn run_deterministic(seed: u64, comptime function: anytype, args: anytype) !void {
    const timeout_ns = 600 * std.time.ns_per_s;
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
