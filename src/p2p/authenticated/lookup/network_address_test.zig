//! Address tests of the lookup network (commonware `lookup/mod.rs` tests): peers tracked at
//! another peer's address, or at a wrong one. The DNS tests are in `network_dns_test.zig`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const harness = @import("network_test.zig");

const PrivateKey = harness.PrivateKey;
const PublicKey = harness.PublicKey;
const Transport = harness.Transport;
const Net = harness.Net;
const Entry = harness.Entry;
const Node = harness.Node;
const gpa = testing.allocator;

const base_port: u16 = 6000;
const max_message_size: u32 = 1024 * 1024;

fn key(seed: u64) PublicKey {
    return PrivateKey.from_seed(seed).public_key();
}

/// Starts the node with key seed `seed` at `base_port + seed`, tracking peers 0, 1, and 2 at
/// `ports` (offsets from `base_port`) as set 0.
fn start(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    seed: u64,
    ports: [3]u16,
) !Node {
    var entries: [3]Entry = undefined;
    const keys = [_]PublicKey{ key(0), key(1), key(2) };
    var sockets: [3]u16 = undefined;
    for (&sockets, ports) |*socket, port| socket.* = base_port + port;
    harness.tracked_at(&keys, &sockets, &entries);
    const port = base_port + @as(u16, @intCast(seed));
    const config = harness.test_config(PrivateKey.from_seed(seed), port, max_message_size);
    const tracked: Net.Tracker.Tracked = .init_primary(.init(&entries));
    const child = harness.node_scope(scope, seed);
    return harness.start_network(io, transport, child, config, 0, tracked, .per_second(100));
}

/// Sends `payload` to all until it reaches exactly `expected` (in any order).
fn send_until_exactly(
    io: Io,
    node: *Node,
    payload: []const u8,
    expected: []const PublicKey,
) !void {
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        try testing.expect(attempts < 600);
        const sent = try node.registered.sender.send(.all, &.{payload}, true);
        defer gpa.free(sent);
        if (sent.len == expected.len) {
            for (expected) |peer| {
                var found = false;
                for (sent) |recipient| found = found or recipient.eql(peer);
                try testing.expect(found);
            }
            return;
        }
        try io.sleep(.fromMilliseconds(100), .real);
    }
}

/// Receives until a message from `peer` arrives.
fn receive_from(node: *Node, peer: PublicKey) !void {
    var messages: u32 = 0;
    while (true) : (messages += 1) {
        try testing.expect(messages < 10_000);
        var message = try node.registered.receiver.recv();
        defer message.deinit();
        if (message.peer.eql(peer)) return;
    }
}

fn duplicate_addresses_disconnected(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    // Peer 0 tracks peers 1 and 2 at peer 1's address while nobody listens there.
    var node_0 = try start(io, transport, scope, 0, .{ 0, 1, 1 });
    defer harness.stop_node(io, &node_0);
    try io.sleep(.fromSeconds(30), .real);
    const sent = try node_0.registered.sender.send(.all, &.{&key(1).key.bytes}, true);
    gpa.free(sent);
    try testing.expectEqual(@as(usize, 0), sent.len);
    // Peer 1 starts there, with a wrong address for peer 0, so only peer 0 dials.
    var node_1 = try start(io, transport, scope, 1, .{ 100, 1, 1 });
    defer harness.stop_node(io, &node_1);
    try io.sleep(.fromSeconds(30), .real);
    try send_until_exactly(io, &node_0, &key(0).key.bytes, &.{key(1)});
    var message = try node_1.registered.receiver.recv();
    defer message.deinit();
    try testing.expect(message.peer.eql(key(0)));
}

test "a peer tracked at another peer's address does not connect in its place" {
    // commonware `test_duplicate_addresses_disconnected`.
    for (0..25) |seed| {
        try harness.run_deterministic(seed, duplicate_addresses_disconnected, .{});
    }
}

fn duplicate_addresses_connected(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    // Peers 0 and 2 track peer 2 at peer 1's address; peer 2 dials peer 0.
    var node_0 = try start(io, transport, scope, 0, .{ 0, 1, 1 });
    defer harness.stop_node(io, &node_0);
    var node_2 = try start(io, transport, scope, 2, .{ 0, 1, 1 });
    defer harness.stop_node(io, &node_2);
    try io.sleep(.fromSeconds(30), .real);
    try send_until_exactly(io, &node_0, &key(2).key.bytes, &.{key(2)});
    try receive_from(&node_2, key(0));
    // Peer 1 starts with a wrong address for peer 0; peers 0 and 2 both dial it.
    var node_1 = try start(io, transport, scope, 1, .{ 100, 1, 1 });
    defer harness.stop_node(io, &node_1);
    try io.sleep(.fromSeconds(30), .real);
    try send_until_exactly(io, &node_1, &key(1).key.bytes, &.{ key(0), key(2) });
    try receive_from(&node_0, key(1));
    try receive_from(&node_2, key(1));
}

test "a connected peer tracked at another peer's address keeps its connection" {
    // commonware `test_duplicate_addresses_connected`.
    try harness.run_deterministic(0, duplicate_addresses_connected, .{});
}
