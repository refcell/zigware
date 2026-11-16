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
const build_options = @import("build_options");
const metrics = runtime.telemetry.metrics;
const p2p = @import("../../root.zig");
const data = @import("../data.zig");
const rate_limit = @import("../../rate_limit.zig");
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
const peers_max = 25;
const max_message_size_default: u32 = 1024 * 1024;

/// How each node addresses its identity (commonware's `Mode`).
const Mode = enum { one, some, all };

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
    /// When the node next sends its identity.
    send_at_ns: u64 = 0,
    /// Mode `one`: the next recipient to send to.
    cursor: usize = 0,
};

/// Each node's metrics scope: `peer` with an `index` attribute, then `network`, as
/// commonware's `context.child("peer").with_attribute("index", i).child("network")`.
fn node_scope(scope: metrics.Scope, index: usize) metrics.Scope {
    return scope.child("peer").with_attribute("index", index).child("network");
}

/// Starts `keys.len` networks: node 0 bootstraps the rest, and all track every key at index 0.
fn start_nodes(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    max_message_size: u32,
    keys: []const PublicKey,
    nodes: []Node,
) !void {
    assert(keys.len == nodes.len);
    const first: p2p.Ingress = .{ .socket = local_socket(base_port) };
    const bootstrap = [_]Bootstrapper{.{ .peer = keys[0], .ingress = first }};
    const sorted = try gpa.dupe(PublicKey, keys);
    defer gpa.free(sorted);
    std.sort.pdq(PublicKey, sorted, {}, PublicKey.less_than);
    for (nodes, 0..) |*node, index| {
        const bootstrappers: []const Bootstrapper = if (index == 0) &.{} else &bootstrap;
        const config = test_config(
            PrivateKey.from_seed(index),
            base_port + @as(u16, @intCast(index)),
            bootstrappers,
            max_message_size,
        );
        const quota: rate_limit.Quota = .per_second(100);
        node.* = try start_node(io, transport, node_scope(scope, index), config, sorted, quota);
    }
}

/// Creates a network tracking `sorted` at index 0 with channel 0 at `quota`, and runs it.
fn start_node(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    config: Net.Config,
    sorted: []const PublicKey,
    quota: rate_limit.Quota,
) !Node {
    const network = try Net.create(gpa, io, transport, scope, config);
    const tracked: p2p.TrackedPeers(PublicKey) = .init_primary(.init(sorted));
    try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(0, tracked));
    var node: Node = .{
        .network = network,
        .registered = try network.register(0, quota),
        .task = undefined,
    };
    node.task = try io.concurrent(run_node, .{network});
    return node;
}

fn run_node(network: *Net) anyerror!void {
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
fn now_ns(io: Io) u64 {
    return @intCast(Io.Clock.real.now(io).nanoseconds);
}

/// Sends `node`'s identity per `mode` when due (commonware's sender task): after a complete
/// send it waits 10 s, after a partial one 100 ms.
fn send_identity(io: Io, node: *Node, keys: []const PublicKey, me: usize, mode: Mode) !void {
    const now = now_ns(io);
    if (now < node.send_at_ns) return;
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
    const done = switch (mode) {
        .one => one: {
            assert(node.cursor < count);
            const sent = try sender.send(.{ .one = recipients[node.cursor] }, payload, true);
            defer gpa.free(sent);
            if (sent.len == 1) node.cursor += 1;
            if (node.cursor == count) node.cursor = 0;
            break :one sent.len == 1 and node.cursor == 0;
        },
        .some, .all => many: {
            const to: p2p.Recipients(PublicKey) =
                if (mode == .some) .{ .some = recipients[0..count] } else .all;
            const sent = try sender.send(to, payload, true);
            defer gpa.free(sent);
            break :many sent.len == count;
        },
    };
    const wait_ms: u64 = if (done) 10_000 else if (mode == .one and node.cursor > 0) 0 else 100;
    node.send_at_ns = now + wait_ms * std.time.ns_per_ms;
}

/// commonware `run_network`: every node sends its identity to every other until each has
/// heard from all the others, with no message rate limited along the way.
fn connectivity(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    max_message_size: u32,
    n: usize,
    mode: Mode,
) !void {
    assert(n >= 2 and n <= peers_max);
    var keys: [peers_max]PublicKey = undefined;
    for (keys[0..n], 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var nodes: [peers_max]Node = undefined;
    try start_nodes(io, transport, scope, max_message_size, keys[0..n], nodes[0..n]);
    defer stop_nodes(io, nodes[0..n]);
    var heard: [peers_max][peers_max]bool = @splat(@splat(false));
    var rounds: u32 = 0;
    while (!all_heard(&heard, n)) : (rounds += 1) {
        try testing.expect(rounds < 10_000);
        for (nodes[0..n], 0..) |*node, index| try send_identity(io, node, keys[0..n], index, mode);
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
        try io.sleep(.fromMilliseconds(10), .real);
    }
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    try expect_no_rate_limiting(text);
    try expect_connected_metrics(text, n);
}

/// commonware `assert_no_rate_limiting`: rate-limited counters exist, all at zero.
fn expect_no_rate_limiting(text: []const u8) !void {
    var samples = metrics.metric_samples(text, "messages_rate_limited_total");
    var count: usize = 0;
    while (samples.next()) |sample| : (count += 1) {
        try testing.expectEqualStrings("0", sample.value);
    }
    try testing.expect(count > 0);
}

/// Node 0 records a connection to each peer, and its greeting and data counters moved
/// without any invalid message.
fn expect_connected_metrics(text: []const u8, n: usize) !void {
    const node_0 = "index=\"0\",";
    var connected = metrics.metric_samples(text, "peer_network_tracker_directory_connected");
    var count: usize = 0;
    while (connected.next()) |sample| {
        if (std.mem.startsWith(u8, sample.labels, node_0)) count += 1;
    }
    try testing.expectEqual(n - 1, count);
    var expected: usize = 0;
    const names = [_][]const u8{
        "peer_network_spawner_messages_sent_total",
        "peer_network_spawner_messages_received_total",
    };
    for (names) |name| {
        var samples = metrics.metric_samples(text, name);
        while (samples.next()) |sample| {
            if (!std.mem.startsWith(u8, sample.labels, node_0)) continue;
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
    var attempts = metrics.metric_samples(text, "peer_network_dialer_attempts_total");
    try testing.expect(attempts.next() != null);
}

fn all_heard(heard: *const [peers_max][peers_max]bool, n: usize) bool {
    for (0..n) |to| {
        for (0..n) |from| {
            if (to != from and !heard[to][from]) return false;
        }
    }
    return true;
}

/// Runs `function(io, transport, scope, args...)` on a deterministic runner seeded with
/// `seed`; returns the auditor state and the final simulated time.
fn run_deterministic(seed: u64, comptime function: anytype, args: anytype) !struct { [8]u8, u64 } {
    const timeout_ns = 600 * std.time.ns_per_s;
    const config: runtime.deterministic.Config = .{ .seed = seed, .timeout_ns = timeout_ns };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    const args_all = .{ runner.io(), runner.network(), runner.metrics() } ++ args;
    try (try runner.start(function, args_all));
    return .{ runner.auditor.state(), runner.now_ns() };
}

test "peers discover each other through a bootstrapper and exchange messages" {
    for ([_]u64{ 0, 1 }) |seed| {
        _ = try run_deterministic(seed, connectivity, .{
            max_message_size_default, @as(usize, 5), Mode.all,
        });
    }
}

/// commonware `run_deterministic_test`: two runs of one seed end in the same state.
fn expect_deterministic(seed: u64, n: usize, mode: Mode) !void {
    const args = .{ max_message_size_default, n, mode };
    const first = try run_deterministic(seed, connectivity, args);
    const second = try run_deterministic(seed, connectivity, args);
    try testing.expectEqualSlices(u8, &first[0], &second[0]);
    try testing.expectEqual(first[1], second[1]);
}

test "connectivity is deterministic for each recipient mode" {
    // commonware `test_determinism_{one,some,all}` (25 peers, seeds 0..10, the "slow" group);
    // fewer seeds here, more under fuzz soak.
    const seeds: u64 = 1 * build_options.fuzz_soak;
    for (0..seeds) |seed| {
        for ([_]Mode{ .one, .some, .all }) |mode| try expect_deterministic(seed, peers_max, mode);
    }
}

test "discovery converges with a payload limit below the gossip bound" {
    // commonware `test_discovery_below_max_gossip_size`: the payload limit fits only the keys
    // the peers send each other, so discovery converges only because frames fit gossip.
    const limit: u32 = PublicKey.fixed_size;
    _ = try run_deterministic(0, connectivity, .{ limit, @as(usize, 25), Mode.one });
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

test "a send before the network starts is accepted" {
    // commonware `test_pre_start_send_is_accepted`.
    var transport = Transport.init(gpa, Io.failing);
    defer transport.deinit();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const config = test_config(PrivateKey.from_seed(0), 0, &.{}, max_message_size_default);
    const network = try Net.create(gpa, Io.failing, &transport, .init(&registry), config);
    defer network.destroy();
    var registered = try network.register(0, .per_second(100));
    defer registered.receiver.deinit();
    defer registered.sender.deinit();
    const recipient = PrivateKey.from_seed(1).public_key();
    const checked = switch (try registered.sender.check(.{ .one = recipient })) {
        .checked => |checked| checked,
        .limited => return error.TestUnexpectedResult,
    };
    const feedback = checked.send(&.{"message"}, false);
    try testing.expectEqual(p2p.Unreliable(p2p.Feedback).new(.ok), feedback);
}

/// One network whose peer set is only itself, started and stopped after `run_ms`.
fn lone_node(io: Io, transport: *Transport, scope: metrics.Scope, run_ms: u64) !Node {
    const signer = PrivateKey.from_seed(0);
    const config = test_config(signer, 5000, &.{}, max_message_size_default);
    const me = [_]PublicKey{signer.public_key()};
    const node_scope_ = scope.child("peer").child("network");
    var node = try start_node(io, transport, node_scope_, config, &me, .per_second(100));
    try io.sleep(.fromMilliseconds(@intCast(run_ms)), .real);
    // Canceling `run` returns once every network task has stopped.
    node.task.cancel(io) catch {};
    try testing.expectEqual(@as(u32, 0), node.network.handshakes.load(.monotonic));
    return node;
}

fn operations_after_shutdown(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var node = try lone_node(io, transport, scope, 0);
    defer node.network.destroy();
    defer node.registered.receiver.deinit();
    defer node.registered.sender.deinit();
    try io.sleep(.fromMilliseconds(100), .real);
    const me = PrivateKey.from_seed(0).public_key();
    const oracle = node.network.oracle();
    const set = [_]PublicKey{me};
    _ = oracle.track(1, .init_primary(.init(&set)));
    if (try oracle.peer_set(gpa, 0)) |owned| owned.free(gpa);
    if (oracle.subscribe()) |subscription| {
        var owned = subscription;
        owned.deinit();
    } else |_| {}
    _ = oracle.block(me);
    const sent = try node.registered.sender.send(.all, &.{&me.key.bytes}, true);
    gpa.free(sent);
    try testing.expectEqual(@as(usize, 0), sent.len);
    // The closed network ends the receiver (commonware `test_drop_before_start_closes_channels`).
    try testing.expectError(error.NetworkClosed, node.registered.receiver.recv());
}

test "operations after shutdown do not panic" {
    // commonware `test_operations_after_shutdown_do_not_panic`, with the receiver half of
    // `test_drop_before_start_closes_channels` (senders cannot outlive the network here).
    _ = try run_deterministic(0, operations_after_shutdown, .{});
}

fn clean_shutdown(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var node = try lone_node(io, transport, scope, 100);
    node.registered.sender.deinit();
    node.registered.receiver.deinit();
    node.network.destroy();
}

test "the network stops every task when canceled" {
    // commonware `test_clean_shutdown`: `run` owns every task in one group, so a returned
    // cancel means none is left running.
    for (0..25) |seed| _ = try run_deterministic(seed, clean_shutdown, .{});
}

test "the payload limit may reach the stream boundary" {
    // commonware `test_max_message_size_stream_boundary` (above it, `create` panics).
    var transport = Transport.init(gpa, Io.failing);
    defer transport.deinit();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const limit = data.max_size(Upgrader.max_size);
    for ([_]u32{ 0, limit }) |size| {
        const config = test_config(PrivateKey.from_seed(0), 0, &.{}, size);
        const network = try Net.create(gpa, Io.failing, &transport, .init(&registry), config);
        network.destroy();
    }
}

/// The other peer of a pair, as a bootstrapper for peer `index`.
fn pair_bootstrapper(index: usize) [1]Bootstrapper {
    assert(index < 2);
    const other = 1 - index;
    return .{.{
        .peer = PrivateKey.from_seed(other).public_key(),
        .ingress = .{ .socket = local_socket(base_port + @as(u16, @intCast(other))) },
    }};
}

/// Peer `index` of a pair on loopback, bootstrapping from `bootstrappers`.
fn pair_config(
    index: usize,
    bootstrappers: []const Bootstrapper,
    max_message_size: u32,
) Net.Config {
    const port = base_port + @as(u16, @intCast(index));
    return test_config(PrivateKey.from_seed(index), port, bootstrappers, max_message_size);
}

fn sorted_pair() [2]PublicKey {
    var keys = [_]PublicKey{
        PrivateKey.from_seed(0).public_key(),
        PrivateKey.from_seed(1).public_key(),
    };
    std.sort.pdq(PublicKey, &keys, {}, PublicKey.less_than);
    return keys;
}

fn message_too_large_not_delivered(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const limit: u32 = 64;
    const keys = sorted_pair();
    // Peer 1 admits payloads up to a limit whose data frame is below its gossip bound; peer 0
    // admits larger ones.
    const bootstrap_1 = pair_bootstrapper(1);
    const config_0 = pair_config(0, &.{}, max_message_size_default);
    const config_1 = pair_config(1, &bootstrap_1, limit);
    try testing.expect(limit + data.max_payload_overhead < config_1.max_gossip_size());
    const quota: rate_limit.Quota = .per_second(100);
    var nodes = [_]Node{
        try start_node(io, transport, node_scope(scope, 0), config_0, &keys, quota),
        try start_node(io, transport, node_scope(scope, 1), config_1, &keys, quota),
    };
    defer stop_nodes(io, &nodes);
    const key_0 = PrivateKey.from_seed(0).public_key();
    const key_1 = PrivateKey.from_seed(1).public_key();
    // Peer 0 receives a payload at peer 1's limit.
    const at_limit: [limit]u8 = @splat(1);
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        try testing.expect(attempts < 600);
        const sent = try nodes[1].registered.sender.send(.{ .one = key_0 }, &.{&at_limit}, true);
        gpa.free(sent);
        try io.sleep(.fromMilliseconds(100), .real);
        var message = nodes[0].registered.receiver.try_recv() catch continue;
        defer message.deinit();
        try testing.expect(message.peer.eql(key_1));
        try testing.expectEqualSlices(u8, &at_limit, message.payload);
        break;
    }
    // One byte more still fits peer 1's frame, sized for gossip, but is never delivered.
    const above: [limit + 1]u8 = @splat(2);
    for (0..50) |_| {
        const sent = try nodes[0].registered.sender.send(.{ .one = key_1 }, &.{&above}, true);
        gpa.free(sent);
        try io.sleep(.fromMilliseconds(100), .real);
        try testing.expectError(error.Empty, nodes[1].registered.receiver.try_recv());
    }
}

test "a payload above the receiver's limit is never delivered" {
    // commonware `test_message_too_large_not_delivered`.
    _ = try run_deterministic(0, message_too_large_not_delivered, .{});
}

fn rate_limiting(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const keys = sorted_pair();
    const key_1 = PrivateKey.from_seed(1).public_key();
    // Each peer bootstraps from the other.
    const bootstraps = [_][1]Bootstrapper{ pair_bootstrapper(0), pair_bootstrapper(1) };
    var nodes: [2]Node = undefined;
    for (&nodes, 0..) |*node, index| {
        const config = pair_config(index, &bootstraps[index], max_message_size_default);
        const quota: rate_limit.Quota = .per_minute(1);
        node.* = try start_node(io, transport, node_scope(scope, index), config, &keys, quota);
    }
    defer stop_nodes(io, &nodes);
    const sender = &nodes[0].registered.sender;
    const message: [1024]u8 = @splat(0);
    // The first message consumes the quota once peer 1 is connected. Waiting a minute between
    // checks keeps the wait itself from being rate limited.
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        try testing.expect(attempts < 60);
        const checked = switch (try sender.check(.all)) {
            .checked => |checked| checked,
            .limited => return error.TestUnexpectedResult,
        };
        if (checked.recipients().len > 0) {
            _ = checked.send(&.{&message}, true);
            break;
        }
        checked.deinit();
        try io.sleep(.fromSeconds(60), .real);
    }
    // The second is limited at the sender, so the receiver never rate limits.
    const sent = try sender.send(.{ .one = key_1 }, &.{&message}, true);
    defer gpa.free(sent);
    try testing.expectEqual(@as(usize, 0), sent.len);
    for (0..10) |_| {
        const text = try scope.encode(gpa);
        defer gpa.free(text);
        try expect_no_rate_limiting(text);
        try io.sleep(.fromMilliseconds(100), .real);
    }
}

test "the sender's rate limit keeps the receiver from limiting" {
    // commonware `test_rate_limiting`.
    _ = try run_deterministic(0, rate_limiting, .{});
}
