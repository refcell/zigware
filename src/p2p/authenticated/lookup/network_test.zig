//! Tests of the lookup network over the deterministic runtime (commonware `lookup/mod.rs`
//! tests), and the harness the other lookup network tests share.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const build_options = @import("build_options");
const stream = @import("stream");
const metrics = runtime.telemetry.metrics;
const p2p = @import("../../root.zig");
const types = @import("../../types.zig");
const data = @import("../data.zig");
const rate_limit = @import("../../rate_limit.zig");
const network_mod = @import("network.zig");

pub const PrivateKey = cryptography.ed25519.PrivateKey;
pub const PublicKey = cryptography.ed25519.PublicKey;
pub const Upgrader = stream.SakeCups(PrivateKey, cryptography.ChaCha20Poly1305);
pub const Transport = runtime.network.deterministic.Network;
pub const Net = network_mod.Network(Upgrader, Transport);
pub const Entry = Net.Tracker.PeerMap.Entry;
const gpa = testing.allocator;

pub const base_port: u16 = 3000;
pub const peers_max = 25;

pub fn upgrader(signer: PrivateKey) Upgrader {
    return .init(.{
        .signer = signer,
        .synchrony_bound_ms = 5_000,
        .max_handshake_age_ms = 10_000,
        .version = .v1,
    }, .v1);
}

pub fn local_socket(port: u16) codec.SocketAddr {
    return .{ .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) }, .port = port };
}

/// commonware's `Config::test`: `local` with faster dialing and pings.
pub fn test_config(signer: PrivateKey, port: u16, max_message_size: u32) Net.Config {
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

pub const Node = struct {
    network: *Net,
    registered: Net.Registered,
    task: Io.Future(anyerror!void),
};

/// Every node's key and address, sorted by key, as `track` takes them.
pub fn peer_entries(keys: []const PublicKey, entries: []Entry) void {
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

pub fn start_nodes(
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
pub fn start_node(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    index: usize,
    port: u16,
    set: u64,
    tracked: Net.Tracker.Tracked,
) !Node {
    const config = test_config(PrivateKey.from_seed(index), port, 1024 * 1024);
    return start_network(io, transport, scope, config, set, tracked, .per_second(100));
}

/// Starts a network with `config`, tracking `tracked` at `set`, with channel 0 at `quota`.
pub fn start_network(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    config: Net.Config,
    set: u64,
    tracked: Net.Tracker.Tracked,
    quota: rate_limit.Quota,
) !Node {
    const network = try Net.create(gpa, io, transport, scope, config);
    errdefer network.destroy();
    try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(set, tracked));
    var node: Node = .{
        .network = network,
        .registered = try network.register(0, quota),
        .task = undefined,
    };
    node.task = try io.concurrent(run_network, .{network});
    return node;
}

/// Each node's metrics scope: `peer` with an `index` attribute, then `network`, as
/// commonware's `context.child("peer").with_attribute("index", i).child("network")`.
pub fn node_scope(scope: metrics.Scope, index: usize) metrics.Scope {
    return scope.child("peer").with_attribute("index", index).child("network");
}

/// commonware `assert_no_rate_limiting`: rate-limited counters exist, all at zero.
pub fn expect_no_rate_limiting(scope: metrics.Scope) !void {
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    var samples = metrics.metric_samples(text, "messages_rate_limited_total");
    var count: usize = 0;
    while (samples.next()) |sample| : (count += 1) {
        try testing.expectEqualStrings("0", sample.value);
    }
    try testing.expect(count > 0);
}

fn run_network(network: *Net) anyerror!void {
    return network.run();
}

pub fn stop_nodes(io: Io, nodes: []Node) void {
    for (nodes) |*node| {
        node.task.cancel(io) catch {};
        node.registered.sender.deinit();
    }
    for (nodes) |*node| release_node(node);
}

/// Stops one node (commonware aborts its handle) and frees it.
pub fn stop_node(io: Io, node: *Node) void {
    node.task.cancel(io) catch {};
    node.registered.sender.deinit();
    release_node(node);
}

pub fn release_node(node: *Node) void {
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
/// How each node addresses its identity (commonware's `Mode`).
const Mode = enum { one, some, all };

/// Sends `keys[me]` to every other node per `mode`; true once every recipient took it.
fn send_identity(node: *Node, keys: []const PublicKey, me: usize, mode: Mode) !bool {
    var recipients: [peers_max]PublicKey = undefined;
    var count: usize = 0;
    for (keys, 0..) |key, index| {
        if (index == me) continue;
        recipients[count] = key;
        count += 1;
    }
    std.sort.pdq(PublicKey, recipients[0..count], {}, PublicKey.less_than);
    const payload: []const []const u8 = &.{&keys[me].key.bytes};
    const sender = &node.registered.sender;
    if (mode == .one) {
        var delivered: usize = 0;
        for (recipients[0..count]) |recipient| {
            const sent = try sender.send(.{ .one = recipient }, payload, true);
            defer gpa.free(sent);
            delivered += sent.len;
        }
        return delivered == count;
    }
    const to: Recipients = if (mode == .some) .{ .some = recipients[0..count] } else .all;
    const sent = try sender.send(to, payload, true);
    defer gpa.free(sent);
    return sent.len == count;
}

fn connectivity(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    n: usize,
    mode: Mode,
) !void {
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
            _ = try send_identity(node, keys[0..n], index, mode);
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
    try expect_no_rate_limiting(scope);
    try expect_connected(scope, n);
}

/// Node 0's directory records a connection to each of its `n - 1` peers.
fn expect_connected(scope: metrics.Scope, n: usize) !void {
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    var samples = metrics.metric_samples(text, "peer_network_tracker_directory_connected");
    var count: usize = 0;
    while (samples.next()) |sample| {
        if (std.mem.startsWith(u8, sample.labels, "index=\"0\",")) count += 1;
    }
    try testing.expectEqual(n - 1, count);
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
pub fn send_until(
    io: Io,
    node: *Node,
    key: PublicKey,
    recipients: Recipients,
    count: usize,
) !void {
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
pub fn receive_all(node: *Node, keys: []const PublicKey, skip: usize) !void {
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

pub const Recipients = p2p.Recipients(PublicKey);

/// Every running node but `skip` tracks the nodes' addresses at `ports` as set `set`.
pub fn retrack(
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

pub fn tracked_at(keys: []const PublicKey, ports: []const u16, entries: []Entry) void {
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
            const node_port = ports[restarted];
            const child = scope.child("peer_restarted").with_attribute("index", restarted)
                .with_attribute("round", round).child("network");
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

pub fn run_deterministic(seed: u64, comptime function: anytype, args: anytype) !void {
    const timeout_ns = 600 * std.time.ns_per_s;
    const config: runtime.deterministic.Config = .{ .seed = seed, .timeout_ns = timeout_ns };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    const args_all = .{ runner.io(), runner.network(), runner.metrics() } ++ args;
    try (try runner.start(function, args_all));
}

test "tracked peers connect at their addresses and exchange messages" {
    // commonware `test_determinism_all` with 25 peers; seeds 0 and 1 here.
    for ([_]u64{ 0, 1 }) |seed| {
        try run_deterministic(seed, connectivity, .{ @as(usize, 5), Mode.all });
    }
}

/// Runs `connectivity` with `seed`; returns the auditor state and the final simulated time.
fn run_audited(seed: u64, n: usize, mode: Mode) !struct { [8]u8, u64 } {
    const timeout_ns = 600 * std.time.ns_per_s;
    const config: runtime.deterministic.Config = .{ .seed = seed, .timeout_ns = timeout_ns };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    const args = .{ runner.io(), runner.network(), runner.metrics(), n, mode };
    try (try runner.start(connectivity, args));
    return .{ runner.auditor.state(), runner.now_ns() };
}

test "connectivity replays exactly for each recipient mode" {
    // commonware `test_determinism_{one,some,all}`: 25 peers and seeds 0..10 in its slow
    // group; 10 peers and fewer seeds here, more under fuzz soak.
    const seeds: u64 = 1 * build_options.fuzz_soak;
    for (0..seeds) |seed| {
        for ([_]Mode{ .one, .some, .all }) |mode| {
            const first = try run_audited(seed, 10, mode);
            const second = try run_audited(seed, 10, mode);
            try testing.expectEqualSlices(u8, &first[0], &second[0]);
            try testing.expectEqual(first[1], second[1]);
        }
    }
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
