//! commonware lookup `test_tokio_connectivity`: 10 peers connect over real TCP sockets on the
//! production runtime, each sending its identity to every other peer one at a time
//! (`Mode::One`), with no message rate limited.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const p2p = @import("../../root.zig");
const network_mod = @import("network.zig");
const harness = @import("network_test.zig");

const production = runtime.production;
const Transport = production.network.Network;
const Net = network_mod.Network(harness.Upgrader, Transport);
const Entry = Net.Tracker.PeerMap.Entry;
const PrivateKey = harness.PrivateKey;
const PublicKey = harness.PublicKey;
const gpa = testing.allocator;
const peers = 10;

/// A base port whose next `peers` ports bind now: lanes and CI jobs sharing a host run this
/// test at once, so a fixed port (commonware's 3000) would collide.
fn free_base_port(io: Io, transport: *Transport) !u16 {
    for (0..16) |_| {
        var random: [2]u8 = undefined;
        io.random(&random);
        const base: u16 = 20_000 + std.mem.readInt(u16, &random, .little) % 40_000;
        var bound: usize = 0;
        var listeners: [peers]*Transport.Listener = undefined;
        defer for (listeners[0..bound]) |listener| listener.deinit();
        while (bound < peers) : (bound += 1) {
            const port = base + @as(u16, @intCast(bound));
            const address = network_mod.to_address(harness.local_socket(port));
            listeners[bound] = transport.bind(address) catch break;
        }
        if (bound == peers) return base;
    }
    return error.TestNoFreePorts;
}

const Node = struct {
    network: *Net,
    registered: Net.Registered,
    task: Io.Future(anyerror!void),
};

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

fn start_nodes(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    base: u16,
    nodes: []Node,
) !void {
    var entries: [peers]Entry = undefined;
    for (&entries, 0..) |*entry, index| {
        const socket = harness.local_socket(base + @as(u16, @intCast(index)));
        const key = PrivateKey.from_seed(index).public_key();
        entry.* = .{ .key = key, .value = .{ .symmetric = socket } };
    }
    std.sort.pdq(Entry, &entries, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return PublicKey.order(a.key, b.key) == .lt;
        }
    }.less);
    const tracked: Net.Tracker.Tracked = .init_primary(.init(&entries));
    var started: usize = 0;
    errdefer stop_nodes(io, nodes[0..started]);
    for (nodes, 0..) |*node, index| {
        const port = base + @as(u16, @intCast(index));
        const config = harness.test_config(PrivateKey.from_seed(index), port, 1024 * 1024);
        const node_scope = harness.node_scope(scope, index);
        const network = try Net.create(gpa, io, transport, node_scope, config);
        errdefer network.destroy();
        try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(0, tracked));
        var registered = try network.register(0, .per_second(100));
        errdefer {
            registered.sender.deinit();
            registered.receiver.deinit();
        }
        node.* = .{
            .network = network,
            .registered = registered,
            .task = try io.concurrent(run_network, .{network}),
        };
        started += 1;
    }
}

/// Sends `keys[me]` to each other peer, one recipient at a time (commonware `Mode::One`).
fn send_identity(node: *Node, keys: []const PublicKey, me: usize) !void {
    const payload: []const []const u8 = &.{&keys[me].key.bytes};
    for (keys, 0..) |key, index| {
        if (index == me) continue;
        const sent = try node.registered.sender.send(.{ .one = key }, payload, true);
        gpa.free(sent);
    }
}

fn connectivity(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const base = try free_base_port(io, transport);
    var keys: [peers]PublicKey = undefined;
    for (&keys, 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var nodes: [peers]Node = undefined;
    try start_nodes(io, transport, scope, base, &nodes);
    defer stop_nodes(io, &nodes);
    var heard: [peers][peers]bool = @splat(@splat(false));
    var missing: usize = peers * (peers - 1);
    var rounds: u32 = 0;
    while (missing > 0) : (rounds += 1) {
        try testing.expect(rounds < 600);
        for (&nodes, 0..) |*node, index| try send_identity(node, &keys, index);
        for (&nodes, 0..) |*node, index| {
            while (node.registered.receiver.try_recv()) |message| {
                var owned = message;
                defer owned.deinit();
                try testing.expectEqualSlices(u8, &owned.peer.key.bytes, owned.payload);
                for (keys, 0..) |key, from| {
                    if (!key.eql(owned.peer) or heard[index][from]) continue;
                    heard[index][from] = true;
                    missing -= 1;
                }
            } else |_| {}
        }
        try io.sleep(.fromMilliseconds(100), .real);
    }
    try harness.expect_no_rate_limiting(scope);
}

test "lookup peers connect over real sockets on the production runtime" {
    // commonware `test_tokio_connectivity`.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [128]u8 = undefined;
    const directory = std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/runner", .{tmp.sub_path}) catch
        unreachable; // The buffer fits the fixed-length temporary path.
    var runner: production.Runner = undefined;
    try runner.init(gpa, .{ .storage_directory = directory });
    defer runner.deinit();
    try runner.start(connectivity, .{ runner.io(), runner.network(), runner.metrics() });
}
