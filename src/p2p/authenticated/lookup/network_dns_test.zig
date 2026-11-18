//! DNS tests of the lookup network (commonware `lookup/mod.rs` tests): peers tracked at a
//! hostname dial one of its resolved addresses, through the deterministic runner's DNS table.
//!
//! commonware's network reads the resolver from its runtime context; here it is
//! `Config.resolver`, set to the runner's `dns.resolver()`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const p2p = @import("../../root.zig");
const metrics = runtime.telemetry.metrics;
const harness = @import("network_test.zig");

const PrivateKey = harness.PrivateKey;
const PublicKey = harness.PublicKey;
const Transport = harness.Transport;
const Net = harness.Net;
const Entry = harness.Entry;
const Node = harness.Node;
const Dns = runtime.resolver.Dns;
const gpa = testing.allocator;

const max_message_size: u32 = 1024 * 1024;

/// `harness.run_deterministic` that also passes the runner's DNS table after the scope.
fn run_with_dns(seed: u64, timeout_s: u64, comptime function: anytype, args: anytype) !void {
    const timeout_ns = timeout_s * std.time.ns_per_s;
    const config: runtime.deterministic.Config = .{ .seed = seed, .timeout_ns = timeout_ns };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    const args_all = .{ runner.io(), runner.network(), runner.metrics(), &runner.dns } ++ args;
    try (try runner.start(function, args_all));
}

fn key(seed: u64) PublicKey {
    return PrivateKey.from_seed(seed).public_key();
}

fn localhost() codec.IpAddr {
    return .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) };
}

/// Peer `index` dialed at `host`, egress from its local socket at `port`.
fn dns_address(host: []const u8, port: u16) p2p.Address {
    return .{ .asymmetric = .{
        .ingress = .{ .dns = .{ .host = utils.Hostname.literal(host), .port = port } },
        .egress = harness.local_socket(port),
    } };
}

/// Sorts `entries` by key, as `track` takes them.
fn sort_entries(entries: []Entry) void {
    std.sort.pdq(Entry, entries, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return PublicKey.order(a.key, b.key) == .lt;
        }
    }.less);
}

/// Starts node `index` at `port` resolving through `dns`, tracking `entries` as set 0.
fn start_dns_node(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    dns: *Dns,
    index: usize,
    port: u16,
    entries: []const Entry,
    allow_private_ips: bool,
) !Node {
    var config = harness.test_config(PrivateKey.from_seed(index), port, max_message_size);
    config.resolver = dns.resolver();
    config.allow_private_ips = allow_private_ips;
    const tracked: Net.Tracker.Tracked = .init_primary(.init(entries));
    const child = harness.node_scope(scope, index);
    return harness.start_network(io, transport, child, config, 0, tracked, .per_second(100));
}

/// Each of `n` peers on `base_port + i` (peers from `dns_from` on tracked by hostname) sends
/// its identity until all others are connected, then hears every other identity.
fn exchange(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    dns: *Dns,
    comptime n: usize,
    base_port: u16,
    dns_from: usize,
) !void {
    const hosts = [_][]const u8{ "peer-0.local", "peer-1.local", "peer-2.local", "peer-3.local" };
    comptime std.debug.assert(n <= hosts.len);
    var keys: [n]PublicKey = undefined;
    var entries: [n]Entry = undefined;
    for (&keys, &entries, 0..) |*peer_key, *entry, index| {
        const port = base_port + @as(u16, @intCast(index));
        peer_key.* = key(index);
        const address: p2p.Address = if (index < dns_from)
            .{ .symmetric = harness.local_socket(port) }
        else
            dns_address(hosts[index], port);
        if (index >= dns_from) try dns.register(hosts[index], &.{localhost()});
        entry.* = .{ .key = peer_key.*, .value = address };
    }
    sort_entries(&entries);
    var nodes: [n]Node = undefined;
    var started: usize = 0;
    defer harness.stop_nodes(io, nodes[0..started]);
    for (&nodes, 0..) |*node, index| {
        const port = base_port + @as(u16, @intCast(index));
        node.* = try start_dns_node(io, transport, scope, dns, index, port, &entries, true);
        started += 1;
    }
    for (&nodes, keys) |*node, peer_key| {
        try harness.send_until(io, node, peer_key, .all, n - 1);
    }
    for (&nodes, 0..) |*node, index| try harness.receive_all(node, &keys, index);
    try harness.expect_no_rate_limiting(scope);
}

fn dns_peer_addresses(io: Io, transport: *Transport, scope: metrics.Scope, dns: *Dns) !void {
    try exchange(io, transport, scope, dns, 3, 3200, 0);
}

test "peers tracked by hostname connect and exchange messages" {
    // commonware `test_dns_peer_addresses`.
    try run_with_dns(0, 600, dns_peer_addresses, .{});
}

fn mixed_addresses(io: Io, transport: *Transport, scope: metrics.Scope, dns: *Dns) !void {
    // Peers 0 and 1 are tracked at sockets, peers 2 and 3 by hostname.
    try exchange(io, transport, scope, dns, 4, 3300, 2);
}

test "peers tracked by socket and by hostname connect together" {
    // commonware `test_mixed_socket_and_dns_addresses`.
    try run_with_dns(0, 600, mixed_addresses, .{});
}

fn private_ip_not_dialed(io: Io, transport: *Transport, scope: metrics.Scope, dns: *Dns) !void {
    const base_port: u16 = 4400;
    // peer-0.local resolves to localhost, a private address.
    try dns.register("peer-0.local", &.{localhost()});
    var entries_0 = [_]Entry{
        .{ .key = key(0), .value = .{ .symmetric = harness.local_socket(base_port) } },
        .{ .key = key(1), .value = .{ .symmetric = harness.local_socket(base_port + 1) } },
    };
    sort_entries(&entries_0);
    var node_0 = try start_dns_node(io, transport, scope, dns, 0, base_port, &entries_0, true);
    defer harness.stop_node(io, &node_0);
    var entries_1 = [_]Entry{
        .{ .key = key(0), .value = dns_address("peer-0.local", base_port) },
        .{ .key = key(1), .value = .{ .symmetric = harness.local_socket(base_port + 1) } },
    };
    sort_entries(&entries_1);
    // Peer 1 disallows private addresses, so it never dials what peer-0.local resolves to.
    var node_1 = try start_dns_node(io, transport, scope, dns, 1, base_port + 1, &entries_1, false);
    defer harness.stop_node(io, &node_1);
    try io.sleep(.fromSeconds(5), .real);
    const sent = try node_1.registered.sender.send(.all, &.{&key(1).key.bytes}, true);
    gpa.free(sent);
    try testing.expectEqual(@as(usize, 0), sent.len);
    try io.sleep(.fromSeconds(1), .real);
    try testing.expectError(error.Empty, node_0.registered.receiver.try_recv());
}

test "a hostname resolving to a private address is not dialed" {
    // commonware `test_dns_resolving_to_private_ip_not_dialed`.
    try run_with_dns(0, 10, private_ip_not_dialed, .{});
}

fn mixed_ips(io: Io, transport: *Transport, scope: metrics.Scope, dns: *Dns) !void {
    const base_port: u16 = 3500;
    // Each hostname resolves to three unreachable addresses and the reachable one.
    for ([_][]const u8{ "peer-0.local", "peer-1.local" }, [_]u8{ 100, 110 }) |host, first| {
        var ips: [4]codec.IpAddr = undefined;
        for (ips[0..3], 1..) |*ip, offset| {
            ip.* = .{ .v4 = codec.Ipv4.init(127, 0, 0, first + @as(u8, @intCast(offset))) };
        }
        ips[3] = localhost();
        try dns.register(host, &ips);
    }
    var entries = [_]Entry{
        .{ .key = key(0), .value = dns_address("peer-0.local", base_port) },
        .{ .key = key(1), .value = dns_address("peer-1.local", base_port + 1) },
    };
    sort_entries(&entries);
    var node_0 = try start_dns_node(io, transport, scope, dns, 0, base_port, &entries, true);
    defer harness.stop_node(io, &node_0);
    var node_1 = try start_dns_node(io, transport, scope, dns, 1, base_port + 1, &entries, true);
    defer harness.stop_node(io, &node_1);
    // The dialers pick addresses at random, so connecting may take several attempts.
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        try testing.expect(attempts < 1_000);
        const sent = try node_1.registered.sender.send(.all, &.{&key(1).key.bytes}, true);
        gpa.free(sent);
        try io.sleep(.fromMilliseconds(100), .real);
        var message = node_0.registered.receiver.try_recv() catch |err| switch (err) {
            error.Empty => continue,
            error.Disconnected => return err,
        };
        defer message.deinit();
        try testing.expect(message.peer.eql(key(1)));
        try testing.expectEqualSlices(u8, &key(1).key.bytes, message.payload);
        return;
    }
}

test "a hostname with several addresses connects through its reachable one" {
    // commonware `test_dns_mixed_ips_connectivity`, over 25 seeds.
    for (0..25) |seed| try run_with_dns(seed, 120, mixed_ips, .{});
}
