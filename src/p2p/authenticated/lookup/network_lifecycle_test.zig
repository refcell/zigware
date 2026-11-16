//! Lifecycle tests of the lookup network (commonware `lookup/mod.rs` tests): graceful and
//! clean shutdown, rate limiting, simultaneous restart, and multi-index tracking.
//!
//! commonware's shutdown tests count each actor's running tasks through runtime metrics. A
//! lookup network runs all its tasks in one group under `run`, so a returned cancel means none
//! is left; these tests check that, that no handshake is in flight, and that receivers end.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const p2p = @import("../../root.zig");
const harness = @import("network_test.zig");

const PrivateKey = harness.PrivateKey;
const PublicKey = harness.PublicKey;
const Transport = harness.Transport;
const Net = harness.Net;
const Entry = harness.Entry;
const Node = harness.Node;
const gpa = testing.allocator;

const max_message_size: u32 = 1024 * 1024;

fn keys_init(keys: []PublicKey) void {
    for (keys, 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
}

/// Every node sends until it reaches its expected peers: peer 0 all others, the rest at
/// least one (commonware `test_graceful_shutdown`'s agents).
fn wait_connected(io: Io, keys: []const PublicKey, nodes: []Node) !void {
    assert(keys.len == nodes.len);
    var connected: [harness.peers_max]bool = @splat(false);
    var rounds: u32 = 0;
    while (std.mem.indexOfScalar(bool, connected[0..nodes.len], false) != null) : (rounds += 1) {
        try testing.expect(rounds < 600);
        for (nodes, 0..) |*node, index| {
            if (connected[index]) continue;
            const expected: usize = if (index == 0) nodes.len - 1 else 1;
            const payload: []const []const u8 = &.{&keys[index].key.bytes};
            const sent = try node.registered.sender.send(.all, payload, true);
            defer gpa.free(sent);
            connected[index] = sent.len >= expected;
        }
        try io.sleep(.fromMilliseconds(100), .real);
    }
}

fn graceful_shutdown(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const n = 5;
    var keys: [n]PublicKey = undefined;
    keys_init(&keys);
    var nodes: [n]Node = undefined;
    try harness.start_nodes(io, transport, scope, &keys, &nodes);
    wait_connected(io, &keys, &nodes) catch |err| {
        harness.stop_nodes(io, &nodes);
        return err;
    };
    // Canceling each `run` returns once all of that network's tasks have stopped.
    for (&nodes) |*node| {
        node.task.cancel(io) catch |err| if (err != error.Canceled) return err;
        try testing.expectEqual(@as(u32, 0), node.network.handshakes.load(.monotonic));
        node.registered.sender.deinit();
    }
    for (&nodes) |*node| {
        while (node.registered.receiver.try_recv()) |message| {
            var owned = message;
            owned.deinit();
        } else |_| {}
        try testing.expectError(error.NetworkClosed, node.registered.receiver.recv());
        node.registered.receiver.deinit();
        node.network.destroy();
    }
}

test "connected networks shut down cleanly" {
    // commonware `test_graceful_shutdown`.
    try harness.run_deterministic(0, graceful_shutdown, .{});
}

fn clean_shutdown(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const signer = PrivateKey.from_seed(0);
    const port: u16 = 5200;
    const me = [_]Entry{.{
        .key = signer.public_key(),
        .value = .{ .symmetric = harness.local_socket(port) },
    }};
    const config = harness.test_config(signer, port, max_message_size);
    const node_scope = scope.child("peer").child("network");
    var node = try harness.start_network(
        io,
        transport,
        node_scope,
        config,
        0,
        .init_primary(.init(&me)),
        .per_second(100),
    );
    try io.sleep(.fromMilliseconds(100), .real);
    node.task.cancel(io) catch |err| if (err != error.Canceled) return err;
    try testing.expectEqual(@as(u32, 0), node.network.handshakes.load(.monotonic));
    node.registered.sender.deinit();
    harness.release_node(&node);
}

test "the network stops every task when canceled" {
    // commonware `test_clean_shutdown`.
    for (0..25) |seed| try harness.run_deterministic(seed, clean_shutdown, .{});
}

/// Starts `keys.len` nodes tracking every key at set 0, with channel 0 at `quota`.
fn start_quota_nodes(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    keys: []const PublicKey,
    nodes: []Node,
    quota: p2p.Quota,
) !void {
    assert(keys.len == nodes.len);
    var entries: [harness.peers_max]Entry = undefined;
    harness.peer_entries(keys, entries[0..keys.len]);
    const tracked: Net.Tracker.Tracked = .init_primary(.init(entries[0..keys.len]));
    var started: usize = 0;
    errdefer harness.stop_nodes(io, nodes[0..started]);
    for (nodes, 0..) |*node, index| {
        const port = harness.base_port + @as(u16, @intCast(index));
        const config = harness.test_config(PrivateKey.from_seed(index), port, max_message_size);
        const child = harness.node_scope(scope, index);
        node.* = try harness.start_network(io, transport, child, config, 0, tracked, quota);
        started += 1;
    }
}

fn rate_limiting(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var keys: [2]PublicKey = undefined;
    keys_init(&keys);
    var nodes: [2]Node = undefined;
    try start_quota_nodes(io, transport, scope, &keys, &nodes, .per_minute(1));
    defer harness.stop_nodes(io, &nodes);
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
    const sent = try sender.send(.{ .one = keys[1] }, &.{&message}, true);
    defer gpa.free(sent);
    try testing.expectEqual(@as(usize, 0), sent.len);
    for (0..10) |_| {
        try harness.expect_no_rate_limiting(scope);
        try io.sleep(.fromMilliseconds(100), .real);
    }
}

test "the sender's rate limit keeps the receiver from limiting" {
    // commonware `test_rate_limiting`.
    try harness.run_deterministic(0, rate_limiting, .{});
}

/// Stops the nodes still running.
fn stop_running(io: Io, nodes: []Node, running: []const bool) void {
    for (nodes, running) |*node, alive| {
        if (alive) harness.stop_node(io, node);
    }
}

/// Every node sends its identity to all others, then hears from every other.
fn exchange_all(io: Io, keys: []const PublicKey, nodes: []Node) !void {
    for (nodes, keys) |*node, key| try harness.send_until(io, node, key, .all, keys.len - 1);
    for (nodes, 0..) |*node, index| try harness.receive_all(node, keys, index);
}

fn simultaneous_restart(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const n = 5;
    var keys: [n]PublicKey = undefined;
    keys_init(&keys);
    var ports: [n]u16 = undefined;
    for (&ports, 0..) |*port, index| port.* = harness.base_port + @as(u16, @intCast(index));
    var nodes: [n]Node = undefined;
    try harness.start_nodes(io, transport, scope, &keys, &nodes);
    var running: [n]bool = @splat(true);
    defer stop_running(io, &nodes, &running);
    try exchange_all(io, &keys, &nodes);
    // Every peer but the first stops at once and comes back at a new port.
    for (1..n) |index| {
        harness.stop_node(io, &nodes[index]);
        running[index] = false;
        ports[index] = harness.base_port + 100 + @as(u16, @intCast(index));
    }
    try io.sleep(.fromSeconds(2), .real);
    var entries: [n]Entry = undefined;
    harness.tracked_at(&keys, &ports, &entries);
    const tracked: Net.Tracker.Tracked = .init_primary(.init(&entries));
    try testing.expectEqual(p2p.Feedback.ok, nodes[0].network.oracle().track(1, tracked));
    for (1..n) |index| {
        const child = scope.child("peer_restarted").with_attribute("index", index)
            .child("network");
        const port = ports[index];
        nodes[index] = try harness.start_node(io, transport, child, index, port, 1, tracked);
        running[index] = true;
    }
    try exchange_all(io, &keys, &nodes);
    try harness.expect_no_rate_limiting(scope);
}

test "peers that restart at once at new addresses reconnect" {
    // commonware `test_simultaneous_peer_restart`.
    try harness.run_deterministic(0, simultaneous_restart, .{});
}

fn multi_index_oracle(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const n = 10;
    var keys: [n]PublicKey = undefined;
    keys_init(&keys);
    var ports: [n]u16 = undefined;
    for (&ports, 0..) |*port, index| port.* = harness.base_port + @as(u16, @intCast(index));
    var nodes: [n]Node = undefined;
    var started: usize = 0;
    defer harness.stop_nodes(io, nodes[0..started]);
    // Every peer tracks peer 0 at set 0, peers 1 and 2 at set 1, and the rest at set 2.
    const ranges = [_][2]usize{ .{ 0, 1 }, .{ 1, 3 }, .{ 2, n } };
    for (&nodes, 0..) |*node, index| {
        const signer = PrivateKey.from_seed(index);
        const config = harness.test_config(signer, ports[index], max_message_size);
        const child = harness.node_scope(scope, index);
        const network = try Net.create(gpa, io, transport, child, config);
        errdefer network.destroy();
        for (ranges, 0..) |range, set| {
            var entries: [n]Entry = undefined;
            const slice = entries[0 .. range[1] - range[0]];
            harness.tracked_at(keys[range[0]..range[1]], ports[range[0]..range[1]], slice);
            const tracked: Net.Tracker.Tracked = .init_primary(.init(slice));
            try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(set, tracked));
        }
        node.* = .{
            .network = network,
            .registered = try network.register(0, .per_second(10)),
            .task = undefined,
        };
        node.task = try io.concurrent(run_network, .{network});
        started += 1;
    }
    try harness.send_until(io, &nodes[0], keys[0], .all, n - 1);
    for (nodes[1..]) |*node| {
        var message = try node.registered.receiver.recv();
        defer message.deinit();
        try testing.expectEqualSlices(u8, &message.peer.key.bytes, message.payload);
    }
    try harness.expect_no_rate_limiting(scope);
}

fn run_network(network: *Net) anyerror!void {
    return network.run();
}

test "peers tracked across several sets all connect" {
    // commonware `test_multi_index_oracle`.
    try harness.run_deterministic(0, multi_index_oracle, .{});
}
