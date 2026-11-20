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
const builtin = @import("builtin");
const metrics = runtime.telemetry.metrics;
const traces = runtime.telemetry.traces;
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
/// commonware's 25-peer runs at full size outside Debug (or with `-Dslow-tests`); Debug builds
/// run them with fewer peers to keep the suite fast.
const peers_full = builtin.mode != .debug or build_options.slow_tests;
const peers_large: usize = if (peers_full) peers_max else 10;
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

/// A running network and its channel 0, over network type `N`.
fn NodeOf(comptime N: type) type {
    return struct {
        network: *N,
        registered: N.Registered,
        task: Io.Future(anyerror!void),
        /// When the node next sends its identity.
        send_at_ns: u64 = 0,
        /// Mode `one`: the next recipient to send to.
        cursor: usize = 0,
    };
}

/// The discovery network over transport type `T`.
fn NetOf(comptime T: type) type {
    return network_mod.Network(Upgrader, T);
}

/// The node type of a transport pointer.
fn TransportNode(comptime TransportPointer: type) type {
    return NodeOf(NetOf(@typeInfo(TransportPointer).pointer.child));
}

const Node = NodeOf(Net);

/// Each node's metrics scope: `peer` with an `index` attribute, then `network`, as
/// commonware's `context.child("peer").with_attribute("index", i).child("network")`.
fn node_scope(scope: metrics.Scope, index: usize) metrics.Scope {
    return scope.child("peer").with_attribute("index", index).child("network");
}

/// Starts `keys.len` networks on ports from `base`: node 0 bootstraps the rest, and all track
/// every key at index 0.
fn start_nodes(
    io: Io,
    transport: anytype,
    scope: metrics.Scope,
    base: u16,
    max_message_size: u32,
    keys: []const PublicKey,
    nodes: []TransportNode(@TypeOf(transport)),
) !void {
    assert(keys.len == nodes.len);
    const first: p2p.Ingress = .{ .socket = local_socket(base) };
    const bootstrap = [_]Bootstrapper{.{ .peer = keys[0], .ingress = first }};
    const sorted = try gpa.dupe(PublicKey, keys);
    defer gpa.free(sorted);
    std.sort.pdq(PublicKey, sorted, {}, PublicKey.less_than);
    for (nodes, 0..) |*node, index| {
        const bootstrappers: []const Bootstrapper = if (index == 0) &.{} else &bootstrap;
        const config = test_config(
            PrivateKey.from_seed(index),
            base + @as(u16, @intCast(index)),
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
    transport: anytype,
    scope: metrics.Scope,
    config: Net.Config,
    sorted: []const PublicKey,
    quota: rate_limit.Quota,
) !TransportNode(@TypeOf(transport)) {
    const N = NetOf(@typeInfo(@TypeOf(transport)).pointer.child);
    const network = try N.create(gpa, io, transport, scope, config);
    const tracked: p2p.TrackedPeers(PublicKey) = .init_primary(.init(sorted));
    try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(0, tracked));
    var node: TransportNode(@TypeOf(transport)) = .{
        .network = network,
        .registered = try network.register(0, quota),
        .task = undefined,
    };
    node.task = try io.concurrent(RunNode(N).run, .{network});
    return node;
}

fn run_node(network: *Net) anyerror!void {
    return network.run();
}

fn RunNode(comptime N: type) type {
    return struct {
        fn run(network: *N) anyerror!void {
            return network.run();
        }
    };
}

fn stop_nodes(io: Io, nodes: anytype) void {
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
fn send_identity(io: Io, node: anytype, keys: []const PublicKey, me: usize, mode: Mode) !void {
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
    return connectivity_at(io, transport, scope, base_port, max_message_size, n, mode, false);
}

/// `connectivity` on any transport, with nodes listening on ports from `base`. With
/// `probe_listeners`, first waits for every node's port to accept (real sockets only).
fn connectivity_at(
    io: Io,
    transport: anytype,
    scope: metrics.Scope,
    base: u16,
    max_message_size: u32,
    n: usize,
    mode: Mode,
    comptime probe_listeners: bool,
) !void {
    assert(n >= 2 and n <= peers_max);
    var keys: [peers_max]PublicKey = undefined;
    for (keys[0..n], 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var nodes: [peers_max]TransportNode(@TypeOf(transport)) = undefined;
    try start_nodes(io, transport, scope, base, max_message_size, keys[0..n], nodes[0..n]);
    defer stop_nodes(io, nodes[0..n]);
    defer production_phase.store(.stopping, .monotonic);
    if (probe_listeners) try wait_listening(io, transport, base, n);
    production_phase.store(.exchanging, .monotonic);
    var heard: [peers_max][peers_max]bool = @splat(@splat(false));
    var rounds: u32 = 0;
    while (!all_heard(&heard, n)) : (rounds += 1) {
        if (rounds >= 10_000) return report_unheard(&heard, n);
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
    production_phase.store(.checking, .monotonic);
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    errdefer std.debug.print("connectivity metrics failed:\n{s}\n", .{text});
    // On real sockets a slow host bunches gossip (macOS CI, 3 vCPUs: two `bit_vec`s arrived
    // within half a gossip period after a redial), and the throttle rightly delays one. Only
    // this test's own channel must be unthrottled there; simulated runs keep commonware's
    // full check.
    if (probe_listeners) {
        try expect_no_data_rate_limiting(text);
    } else {
        try expect_no_rate_limiting(text);
    }
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

/// `expect_no_rate_limiting` for the data channels only (`message="data_<channel>"`), which
/// must be registered.
fn expect_no_data_rate_limiting(text: []const u8) !void {
    var samples = metrics.metric_samples(text, "messages_rate_limited_total");
    var count: usize = 0;
    while (samples.next()) |sample| {
        if (std.mem.indexOf(u8, sample.labels, "message=\"data_") == null) continue;
        try testing.expectEqualStrings("0", sample.value);
        count += 1;
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

/// Names every node that never heard from a peer, then fails: a bare failed `expect` gives
/// no output in release builds.
fn report_unheard(heard: *const [peers_max][peers_max]bool, n: usize) error{TestUnheard} {
    std.debug.print("connectivity timed out; nodes that never heard a peer (to <- from):", .{});
    for (0..n) |to| {
        for (0..n) |from| {
            if (to != from and !heard[to][from]) std.debug.print(" {d}<-{d}", .{ to, from });
        }
    }
    std.debug.print("\n", .{});
    return error.TestUnheard;
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

const production = runtime.production;
const production_peers = 10;
const production_peers_max = 16;

/// A base port whose next `production_peers` ports bind now: lanes and CI jobs sharing a host
/// run this test at once, so a fixed port (commonware's 3000) would collide. Bases stay in
/// [10000, 32000), below the ephemeral ranges of Linux (32768) and macOS (49152), so no
/// outgoing connection takes a port between this probe and a node's own bind.
pub fn free_base_port(io: Io, transport: *production.network.Network, count: u16) !u16 {
    assert(count <= production_peers_max);
    for (0..64) |_| {
        var random: [2]u8 = undefined;
        io.random(&random);
        const base: u16 = 10_000 + std.mem.readInt(u16, &random, .little) % (22_000 - count);
        var bound: usize = 0;
        var listeners: [production_peers_max]*production.network.Network.Listener = undefined;
        defer for (listeners[0..bound]) |listener| listener.deinit();
        while (bound < count) : (bound += 1) {
            const port = base + @as(u16, @intCast(bound));
            const address = network_mod.to_address(local_socket(port));
            listeners[bound] = transport.bind(address) catch |err| {
                if (err == error.Canceled) return err;
                break;
            };
        }
        if (bound == count) return base;
    }
    std.debug.print("no run of {d} free ports below 32000\n", .{count});
    return error.TestNoFreePorts;
}

/// Waits up to `listen_wait_s` in all for each of the `count` ports from `base` to accept. A
/// node whose bind lost its port to another process never does, and on a loaded host a dial
/// can take its whole connect timeout: either way `error.TestPortLost` asks for a retry.
pub fn wait_listening(io: Io, transport: anytype, base: u16, count: usize) !void {
    production_phase.store(.probing, .monotonic);
    const deadline_ns = now_ns(io) + listen_wait_s * std.time.ns_per_s;
    for (0..count) |index| {
        const port = base + @as(u16, @intCast(index));
        const address = network_mod.to_address(local_socket(port));
        while (true) {
            var connection = transport.dial(address) catch |err| {
                if (err == error.Canceled) return err;
                if (now_ns(io) >= deadline_ns) {
                    std.debug.print("port {d} did not accept within {d} s\n", .{
                        port,
                        listen_wait_s,
                    });
                    return error.TestPortLost;
                }
                try io.sleep(.fromMilliseconds(10), .real);
                continue;
            };
            connection.deinit();
            break;
        }
    }
}

const listen_wait_s = 30;

/// What a real-socket run is doing, for `watchdog`'s report.
const Phase = enum(u8) { starting, probing, exchanging, checking, stopping };
var production_phase: std.atomic.Value(Phase) = .init(.starting);

/// Real-socket runs finish in well under a minute; past this one is stuck. It stays under the
/// test step's 10-minute limit so the failure names the phase.
const watchdog_s = 300;

/// Panics, naming the phase, once a run has taken `watchdog_s` (it runs on its own thread).
fn watchdog(io: Io) void {
    io.sleep(.fromSeconds(watchdog_s), .awake) catch return; // Canceled: the run finished.
    const phase = production_phase.load(.monotonic);
    std.debug.panic("real-socket run stuck for {d} s while {s}", .{ watchdog_s, @tagName(phase) });
}

fn Watched(comptime function: anytype) type {
    const Args = std.meta.ArgsTuple(@TypeOf(function));
    return struct {
        fn run(io: Io, transport: *production.network.Network, scope: metrics.Scope) !void {
            production_phase.store(.starting, .monotonic);
            var guard = try io.concurrent(watchdog, .{io});
            defer guard.cancel(io);
            const args: Args = .{ io, transport, scope };
            return @call(.auto, function, args);
        }
    };
}

/// Runs `function(io, network, metrics)` on a fresh production runner, under `watchdog`, up to
/// three times while an attempt reports `error.TestPortLost`.
pub fn run_production(comptime function: anytype) !void {
    var attempt: u32 = 1;
    while (true) : (attempt += 1) {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var buffer: [128]u8 = undefined;
        const directory = std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/runner", .{
            tmp.sub_path,
        }) catch unreachable; // The buffer fits the fixed-length temporary path.
        var runner: production.Runner = undefined;
        try runner.init(gpa, .{ .storage_directory = directory });
        defer runner.deinit();
        const args = .{ runner.io(), runner.network(), runner.metrics() };
        runner.start(Watched(function).run, args) catch |err| {
            if (err != error.TestPortLost or attempt == 3) return err;
            std.debug.print("attempt {d} lost a port; retrying on fresh ports\n", .{attempt});
            continue;
        };
        return;
    }
}

fn production_connectivity(
    io: Io,
    transport: *production.network.Network,
    scope: metrics.Scope,
) !void {
    const base = try free_base_port(io, transport, production_peers);
    const n = production_peers;
    try connectivity_at(io, transport, scope, base, max_message_size_default, n, Mode.one, true);
}

test "peers connect over real sockets on the production runtime" {
    // commonware `test_tokio_connectivity`.
    try run_production(production_connectivity);
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
        for ([_]Mode{ .one, .some, .all }) |mode| try expect_deterministic(seed, peers_large, mode);
    }
}

test "discovery converges with a payload limit below the gossip bound" {
    // commonware `test_discovery_below_max_gossip_size`: the payload limit fits only the keys
    // the peers send each other, so discovery converges only because frames fit gossip.
    const limit: u32 = PublicKey.fixed_size;
    _ = try run_deterministic(0, connectivity, .{ limit, peers_large, Mode.one });
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

/// `keys`, sorted, in `buffer`.
fn sorted_keys(buffer: []PublicKey, keys: []const PublicKey) []PublicKey {
    assert(buffer.len >= keys.len);
    const out = buffer[0..keys.len];
    @memcpy(out, keys);
    std.sort.pdq(PublicKey, out, {}, PublicKey.less_than);
    return out;
}

fn expect_keys(expected: []const PublicKey, actual: []const PublicKey) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, have| try testing.expect(want.eql(have));
}

/// The next update is `index`, with `latest` and `all` as primaries and no secondaries.
fn expect_update(
    subscription: *Net.Tracker.PeerSetSubscription,
    index: u64,
    latest: []const PublicKey,
    all: []const PublicKey,
) !void {
    var update = (try subscription.recv()) orelse return error.TestUnexpectedResult;
    defer update.deinit();
    try testing.expectEqual(index, update.index);
    try expect_keys(latest, update.latest.primary);
    try testing.expectEqual(@as(usize, 0), update.latest.secondary.len);
    try expect_keys(all, update.all.primary);
    try testing.expectEqual(@as(usize, 0), update.all.secondary.len);
}

fn track_primary(network: *Net, index: u64, sorted: []const PublicKey) !void {
    const tracked: p2p.TrackedPeers(PublicKey) = .init_primary(.init(sorted));
    try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(index, tracked));
}

/// A running network for peer 0 on `base_port`, bootstrapping from `bootstrappers`.
fn start_lone(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    bootstrappers: []const Bootstrapper,
) !struct { *Net, Io.Future(anyerror!void) } {
    const signer = PrivateKey.from_seed(0);
    const config = test_config(signer, base_port, bootstrappers, max_message_size_default);
    const network = try Net.create(gpa, io, transport, scope.child("network"), config);
    errdefer network.destroy();
    return .{ network, try io.concurrent(run_node, .{network}) };
}

fn unordered_peer_sets(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var keys: [10]PublicKey = undefined;
    for (&keys, 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    // Peer 0 lists itself as a bootstrapper, as in commonware's test.
    const myself = [_]Bootstrapper{.{
        .peer = keys[0],
        .ingress = .{ .socket = local_socket(base_port) },
    }};
    const network, var task = try start_lone(io, transport, scope, &myself);
    defer network.destroy();
    defer task.cancel(io) catch {};
    var subscription = try network.oracle().subscribe();
    defer subscription.deinit();

    var buffer_10: [10]PublicKey = undefined;
    const set_10 = sorted_keys(&buffer_10, keys[0..2]);
    try track_primary(network, 10, set_10);
    try expect_update(&subscription, 10, set_10, set_10);
    // An older index is ignored and sends no update.
    var buffer_9: [10]PublicKey = undefined;
    try track_primary(network, 9, sorted_keys(&buffer_9, keys[2..]));
    var buffer_11: [10]PublicKey = undefined;
    const set_11 = sorted_keys(&buffer_11, keys[4..]);
    try track_primary(network, 11, set_11);
    var union_keys: [8]PublicKey = undefined;
    @memcpy(union_keys[0..2], keys[0..2]);
    @memcpy(union_keys[2..], keys[4..]);
    var buffer_all: [10]PublicKey = undefined;
    try expect_update(&subscription, 11, set_11, sorted_keys(&buffer_all, &union_keys));
}

test "peer sets tracked out of order are ignored" {
    // commonware `test_unordered_peer_sets`.
    _ = try run_deterministic(0, unordered_peer_sets, .{});
}

fn subscription_includes_self(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const me = PrivateKey.from_seed(0).public_key();
    const other = PrivateKey.from_seed(1).public_key();
    const network, var task = try start_lone(io, transport, scope, &.{});
    defer network.destroy();
    defer task.cancel(io) catch {};
    var subscription = try network.oracle().subscribe();
    defer subscription.deinit();
    // A set without us: neither the latest set nor all peers list us.
    try track_primary(network, 1, &.{other});
    try expect_update(&subscription, 1, &.{other}, &.{other});
    // A set with us: both list us.
    var buffer: [2]PublicKey = undefined;
    const both = sorted_keys(&buffer, &.{ me, other });
    try track_primary(network, 2, both);
    try expect_update(&subscription, 2, both, both);
}

test "subscriptions list ourselves only when tracked" {
    // commonware `test_subscription_includes_self_when_registered`.
    _ = try run_deterministic(0, subscription_includes_self, .{});
}

/// Every node sends until it reaches its expected peers: peer 0 all others, the rest at
/// least one (commonware `test_graceful_shutdown`'s agents).
fn wait_connected(io: Io, keys: []const PublicKey, nodes: []Node) !void {
    var connected: [peers_max]bool = @splat(false);
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
    for (&keys, 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var nodes: [n]Node = undefined;
    try start_nodes(io, transport, scope, base_port, max_message_size_default, &keys, &nodes);
    wait_connected(io, &keys, &nodes) catch |err| {
        stop_nodes(io, &nodes);
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
    _ = try run_deterministic(0, graceful_shutdown, .{});
}

/// commonware runs 100 peers (about 10,000 connections); the default suite runs 20, and the
/// full 100 runs under fuzz soak.
const multi_index_peers = 100;

fn multi_index_count() usize {
    return if (build_options.fuzz_soak > 1) multi_index_peers else 20;
}

/// Starts peer `index` of `keys`, tracking `keys[0]`, `keys[1..3]`, and `keys[2..]` at indices
/// 0, 1, and 2, with channel 0 at 10 per second.
fn start_multi_index(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    keys: []const PublicKey,
    index: usize,
) !Node {
    const bootstrap = [_]Bootstrapper{.{
        .peer = keys[0],
        .ingress = .{ .socket = local_socket(base_port) },
    }};
    const bootstrappers: []const Bootstrapper = if (index == 0) &.{} else &bootstrap;
    const port = base_port + @as(u16, @intCast(index));
    var config = test_config(
        PrivateKey.from_seed(index),
        port,
        bootstrappers,
        max_message_size_default,
    );
    config.max_peers_per_set = @max(keys.len - 1, 2);
    const network = try Net.create(gpa, io, transport, node_scope(scope, index), config);
    errdefer network.destroy();
    var buffer: [multi_index_peers]PublicKey = undefined;
    try track_primary(network, 0, keys[0..1]);
    try track_primary(network, 1, sorted_keys(&buffer, keys[1..3]));
    try track_primary(network, 2, sorted_keys(&buffer, keys[2..]));
    var node: Node = .{
        .network = network,
        .registered = try network.register(0, .per_second(10)),
        .task = undefined,
    };
    node.task = try io.concurrent(run_node, .{network});
    return node;
}

/// Peer 0 sends its identity to all until every other peer has it; each other peer
/// receives it once.
fn await_multi_index(io: Io, keys: []const PublicKey, nodes: []Node) !void {
    const n = nodes.len;
    var received: [multi_index_peers]bool = @splat(false);
    received[0] = true;
    var sent_all = false;
    var rounds: u32 = 0;
    while (!sent_all or std.mem.indexOfScalar(bool, received[0..n], false) != null) {
        try testing.expect(rounds < 3_000);
        rounds += 1;
        if (!sent_all) {
            const payload: []const []const u8 = &.{&keys[0].key.bytes};
            const sent = try nodes[0].registered.sender.send(.all, payload, true);
            defer gpa.free(sent);
            sent_all = sent.len == n - 1;
        }
        for (nodes[1..], 1..) |*node, index| {
            if (received[index]) continue;
            var message = node.registered.receiver.try_recv() catch continue;
            defer message.deinit();
            try testing.expectEqualSlices(u8, &message.peer.key.bytes, message.payload);
            received[index] = true;
        }
        try io.sleep(.fromMilliseconds(100), .real);
    }
}

fn multi_index_oracle(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const n = multi_index_count();
    var keys: [multi_index_peers]PublicKey = undefined;
    for (keys[0..n], 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var nodes: [multi_index_peers]Node = undefined;
    var started: usize = 0;
    defer stop_nodes(io, nodes[0..started]);
    for (nodes[0..n], 0..) |*node, index| {
        node.* = try start_multi_index(io, transport, scope, keys[0..n], index);
        started += 1;
    }
    try await_multi_index(io, keys[0..n], nodes[0..n]);
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    try expect_no_rate_limiting(text);
}

test "peers tracked across several indices all connect" {
    // commonware `test_multi_index_oracle`.
    _ = try run_deterministic(0, multi_index_oracle, .{});
}

const restart_peers = 5;
/// An address no deterministic listener uses, so dialing it fails.
const unreachable_ip = codec.Ipv4.init(10, 255, 255, 1);

/// Peer 0 at `base_port`, which every other peer bootstraps from.
fn first_bootstrapper(keys: []const PublicKey) [1]Bootstrapper {
    return .{.{ .peer = keys[0], .ingress = .{ .socket = local_socket(base_port) } }};
}

/// Peer `index` on `port`, bootstrapping from `bootstrap` (unless it is peer 0), advertising
/// `unreachable_ip` instead of loopback when `hidden`. The config borrows `bootstrap`.
fn restart_config(
    bootstrap: *const [1]Bootstrapper,
    index: usize,
    port: u16,
    hidden: bool,
) Net.Config {
    const bootstrappers: []const Bootstrapper = if (index == 0) &.{} else bootstrap;
    const signer = PrivateKey.from_seed(index);
    var config = test_config(signer, port, bootstrappers, max_message_size_default);
    if (hidden) config.dialable = .{ .socket = .{ .ip = .{ .v4 = unreachable_ip }, .port = port } };
    return config;
}

fn stop_node(io: Io, node: *Node) void {
    stop_nodes(io, node[0..1]);
    node.* = undefined;
}

/// Sends `index`'s identity to all until every other peer is a recipient.
fn send_until_all(io: Io, node: *Node, keys: []const PublicKey, index: usize) !void {
    const payload: []const []const u8 = &.{&keys[index].key.bytes};
    for (0..600) |_| {
        const sent = try node.registered.sender.send(.all, payload, true);
        defer gpa.free(sent);
        if (sent.len == keys.len - 1) return;
        try io.sleep(.fromMilliseconds(100), .real);
    }
    return error.TestUnexpectedResult;
}

/// Sends `from`'s identity to `to` until it is a recipient.
fn send_until_one(io: Io, node: *Node, keys: []const PublicKey, from: usize, to: usize) !void {
    const payload: []const []const u8 = &.{&keys[from].key.bytes};
    for (0..600) |_| {
        const sent = try node.registered.sender.send(.{ .one = keys[to] }, payload, true);
        defer gpa.free(sent);
        if (sent.len == 1) return;
        try io.sleep(.fromMilliseconds(100), .real);
    }
    return error.TestUnexpectedResult;
}

/// Receives until every other peer's identity arrived at `node`.
fn receive_from_all(io: Io, node: *Node, keys: []const PublicKey) !void {
    var heard: [peers_max]bool = @splat(false);
    var count: usize = 0;
    var rounds: u32 = 0;
    while (count < keys.len - 1) : (rounds += 1) {
        try testing.expect(rounds < 6_000);
        var message = node.registered.receiver.try_recv() catch {
            try io.sleep(.fromMilliseconds(10), .real);
            continue;
        };
        defer message.deinit();
        try testing.expectEqualSlices(u8, &message.peer.key.bytes, message.payload);
        for (keys, 0..) |key, from| {
            if (!key.eql(message.peer) or heard[from]) continue;
            heard[from] = true;
            count += 1;
        }
    }
}

/// Every peer reaches all others, and each hears from all others.
fn expect_full_connectivity(io: Io, keys: []const PublicKey, nodes: []Node) !void {
    for (nodes, 0..) |*node, index| try send_until_all(io, node, keys, index);
    for (nodes) |*node| try receive_from_all(io, node, keys);
}

/// Stops peer `index` and starts it again on `port` with a fresh registration; afterwards it
/// reaches every peer, every peer reaches it, and it hears from all.
fn restart_and_reconnect(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    keys: []const PublicKey,
    sorted: []const PublicKey,
    nodes: []Node,
    index: usize,
    port: u16,
) !void {
    stop_node(io, &nodes[index]);
    const bootstrap = first_bootstrapper(keys);
    const config = restart_config(&bootstrap, index, port, false);
    const node_scope_ = scope.child("peer_restarted").with_attribute("index", index)
        .with_attribute("port", port).child("network");
    nodes[index] = try start_node(io, transport, node_scope_, config, sorted, .per_second(100));
    try send_until_all(io, &nodes[index], keys, index);
    for (nodes, 0..) |*node, from| {
        if (from != index) try send_until_one(io, node, keys, from, index);
    }
    try receive_from_all(io, &nodes[index], keys);
}

/// Starts `restart_peers` peers (peer `hidden` advertising an unreachable address) and waits
/// for full connectivity.
fn start_restart_cluster(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    keys: []PublicKey,
    sorted: []PublicKey,
    nodes: []Node,
    hidden: ?usize,
) !void {
    for (keys, 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    @memcpy(sorted, keys);
    std.sort.pdq(PublicKey, sorted, {}, PublicKey.less_than);
    const bootstrap = first_bootstrapper(keys);
    var started: usize = 0;
    errdefer stop_nodes(io, nodes[0..started]);
    for (nodes, 0..) |*node, index| {
        const port = base_port + @as(u16, @intCast(index));
        const config = restart_config(&bootstrap, index, port, hidden == index);
        const quota: rate_limit.Quota = .per_second(100);
        node.* = try start_node(io, transport, node_scope(scope, index), config, sorted, quota);
        started += 1;
    }
    try expect_full_connectivity(io, keys, nodes);
}

fn many_peer_restart(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var keys: [restart_peers]PublicKey = undefined;
    var sorted: [restart_peers]PublicKey = undefined;
    var nodes: [restart_peers]Node = undefined;
    try start_restart_cluster(io, transport, scope, &keys, &sorted, &nodes, null);
    defer stop_nodes(io, &nodes);
    var port: u16 = base_port + 100;
    for (0..3) |_| {
        for (1..restart_peers) |index| {
            port += 1;
            try restart_and_reconnect(io, transport, scope, &keys, &sorted, &nodes, index, port);
        }
    }
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    try expect_no_rate_limiting(text);
}

test "peers restarting on new addresses reconnect" {
    // commonware `test_many_peer_restart_with_new_address`.
    _ = try run_deterministic(0, many_peer_restart, .{});
}

fn restart_must_dial(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var keys: [restart_peers]PublicKey = undefined;
    var sorted: [restart_peers]PublicKey = undefined;
    var nodes: [restart_peers]Node = undefined;
    // Peer 2 advertises an unreachable address: after peer 1 restarts, only peer 2 can dial
    // the connection between them, once gossip brings it peer 1's new address.
    try start_restart_cluster(io, transport, scope, &keys, &sorted, &nodes, 2);
    defer stop_nodes(io, &nodes);
    try restart_and_reconnect(io, transport, scope, &keys, &sorted, &nodes, 1, base_port + 100);
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    try expect_no_rate_limiting(text);
}

test "a restarted peer reconnects to a peer it cannot dial" {
    // commonware `test_peer_restart_with_new_address_must_dial`.
    _ = try run_deterministic(0, restart_must_dial, .{});
}

fn simultaneous_restart(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var keys: [restart_peers]PublicKey = undefined;
    var sorted: [restart_peers]PublicKey = undefined;
    var nodes: [restart_peers]Node = undefined;
    try start_restart_cluster(io, transport, scope, &keys, &sorted, &nodes, null);
    // Every peer but the bootstrapper stops, then all restart on new ports together.
    var running: usize = restart_peers;
    defer stop_nodes(io, nodes[0..running]);
    // Peer 0 keeps running.
    stop_nodes(io, nodes[1..]);
    running = 1;
    try io.sleep(.fromSeconds(2), .real);
    const bootstrap = first_bootstrapper(&keys);
    for (1..restart_peers) |index| {
        const port = base_port + 100 + @as(u16, @intCast(index));
        const config = restart_config(&bootstrap, index, port, false);
        const node_scope_ = scope.child("peer_restarted").with_attribute("index", index)
            .child("network");
        const quota: rate_limit.Quota = .per_second(100);
        nodes[index] = try start_node(io, transport, node_scope_, config, &sorted, quota);
        running = index + 1;
    }
    try expect_full_connectivity(io, &keys, &nodes);
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    try expect_no_rate_limiting(text);
}

test "peers restarting together reconnect" {
    // commonware `test_simultaneous_peer_restart`.
    _ = try run_deterministic(0, simultaneous_restart, .{});
}

fn peer_config(seed: u64, port: u16, bootstrappers: []const Bootstrapper) Net.Config {
    return test_config(PrivateKey.from_seed(seed), port, bootstrappers, max_message_size_default);
}

fn socket_ingress(port: u16) p2p.Ingress {
    return .{ .socket = local_socket(port) };
}

/// Sends from `node` to all until exactly `expected` are recipients.
fn send_until_exactly(
    io: Io,
    node: *Node,
    payload: []const u8,
    expected: []const PublicKey,
) !void {
    for (0..1_200) |_| {
        const sent = try node.registered.sender.send(.all, &.{payload}, true);
        defer gpa.free(sent);
        if (sent.len == expected.len) {
            for (expected) |want| try testing.expect(contains(sent, want));
            return;
        }
        try io.sleep(.fromMilliseconds(100), .real);
    }
    return error.TestUnexpectedResult;
}

fn contains(keys: []const PublicKey, key: PublicKey) bool {
    for (keys) |each| if (each.eql(key)) return true;
    return false;
}

/// The next message on `node` from `from`, skipping others.
fn expect_from(node: *Node, from: PublicKey) !void {
    for (0..1_000) |_| {
        var message = try node.registered.receiver.recv();
        defer message.deinit();
        if (message.peer.eql(from)) return;
    }
    return error.TestUnexpectedResult;
}

fn duplicate_addresses_disconnected(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const port_0 = base_port;
    const port_1 = base_port + 1;
    var keys: [3]PublicKey = undefined;
    for (&keys, 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var sorted = keys;
    std.sort.pdq(PublicKey, &sorted, {}, PublicKey.less_than);
    // Peer 0 knows peers 1 and 2 at the same address.
    const bootstrap_0 = [_]Bootstrapper{
        .{ .peer = keys[1], .ingress = socket_ingress(port_1) },
        .{ .peer = keys[2], .ingress = socket_ingress(port_1) },
    };
    const config_0 = peer_config(0, port_0, &bootstrap_0);
    const quota: rate_limit.Quota = .per_second(100);
    var nodes: [2]Node = undefined;
    nodes[0] = try start_node(io, transport, node_scope(scope, 0), config_0, &sorted, quota);
    var started: usize = 1;
    defer stop_nodes(io, nodes[0..started]);
    try io.sleep(.fromSeconds(30), .real);
    {
        const checked = switch (try nodes[0].registered.sender.check(.all)) {
            .checked => |checked| checked,
            .limited => return error.TestUnexpectedResult,
        };
        defer checked.deinit();
        try testing.expectEqual(@as(usize, 0), checked.recipients().len);
    }
    // Peer 1 knows peer 0 only at a wrong address, so peer 0 must dial it.
    const bootstrap_1 = [_]Bootstrapper{.{
        .peer = keys[0],
        .ingress = socket_ingress(port_0 + 100),
    }};
    const config_1 = peer_config(1, port_1, &bootstrap_1);
    nodes[1] = try start_node(io, transport, node_scope(scope, 1), config_1, &sorted, quota);
    started = 2;
    try io.sleep(.fromSeconds(30), .real);
    try send_until_exactly(io, &nodes[0], &keys[0].key.bytes, keys[1..2]);
    try expect_from(&nodes[1], keys[0]);
}

test "a peer sharing an address with an absent peer still connects" {
    // commonware `test_duplicate_addresses_disconnected` (25 seeds).
    for (0..25) |seed| _ = try run_deterministic(seed, duplicate_addresses_disconnected, .{});
}

fn duplicate_addresses_connected(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const port_0 = base_port;
    const port_1 = base_port + 1;
    const port_2 = base_port + 2;
    var keys: [3]PublicKey = undefined;
    for (&keys, 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    var sorted = keys;
    std.sort.pdq(PublicKey, &sorted, {}, PublicKey.less_than);
    const quota: rate_limit.Quota = .per_second(100);
    const bootstrap_0 = [_]Bootstrapper{
        .{ .peer = keys[1], .ingress = socket_ingress(port_1) },
        .{ .peer = keys[2], .ingress = socket_ingress(port_1) },
    };
    const config_0 = peer_config(0, port_0, &bootstrap_0);
    // Peer 2 listens on its own port but advertises peer 1's address.
    const bootstrap_2 = [_]Bootstrapper{.{ .peer = keys[0], .ingress = socket_ingress(port_0) }};
    var config_2 = peer_config(2, port_2, &bootstrap_2);
    config_2.dialable = socket_ingress(port_1);
    var nodes: [3]Node = undefined;
    nodes[0] = try start_node(io, transport, node_scope(scope, 0), config_0, &sorted, quota);
    var started: usize = 1;
    defer stop_nodes(io, nodes[0..started]);
    nodes[1] = try start_node(io, transport, node_scope(scope, 2), config_2, &sorted, quota);
    started = 2;
    try io.sleep(.fromSeconds(30), .real);
    try send_until_exactly(io, &nodes[0], &keys[2].key.bytes, keys[2..3]);
    try expect_from(&nodes[1], keys[0]);
    // Peer 1 knows peer 0 only at a wrong address; it still reaches both.
    const bootstrap_1 = [_]Bootstrapper{.{
        .peer = keys[0],
        .ingress = socket_ingress(port_0 + 100),
    }};
    const config_1 = peer_config(1, port_1, &bootstrap_1);
    nodes[2] = try start_node(io, transport, node_scope(scope, 1), config_1, &sorted, quota);
    started = 3;
    try io.sleep(.fromSeconds(30), .real);
    try send_until_exactly(io, &nodes[2], &keys[1].key.bytes, &.{ keys[0], keys[2] });
    try expect_from(&nodes[0], keys[1]);
    try expect_from(&nodes[1], keys[1]);
}

test "a peer advertising another's address does not block it" {
    // commonware `test_duplicate_addresses_connected`.
    _ = try run_deterministic(0, duplicate_addresses_connected, .{});
}

fn traced_pair(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    collector: *traces.Collector,
) !void {
    const keys = sorted_pair();
    const bootstrap_1 = pair_bootstrapper(1);
    var config_0 = pair_config(0, &.{}, max_message_size_default);
    var config_1 = pair_config(1, &bootstrap_1, max_message_size_default);
    config_0.tracer = collector.tracer("");
    config_1.tracer = collector.tracer("");
    const quota: rate_limit.Quota = .per_second(100);
    var nodes = [_]Node{
        try start_node(io, transport, node_scope(scope, 0), config_0, &keys, quota),
        try start_node(io, transport, node_scope(scope, 1), config_1, &keys, quota),
    };
    defer stop_nodes(io, &nodes);
    const identities = [_]PublicKey{
        PrivateKey.from_seed(0).public_key(),
        PrivateKey.from_seed(1).public_key(),
    };
    try wait_connected(io, &identities, &nodes);
}

fn is_listener_handshake(_: void, event: traces.collector.RecordedEvent) bool {
    const target = "commonware_p2p::authenticated::discovery::actors::listener";
    if (!std.mem.eql(u8, event.target, target)) return false;
    if (!std.mem.eql(u8, event.metadata.content, "completed handshake")) return false;
    event.metadata.expect_field_contains("address", "127.0.0.1:") catch return false;
    return event.metadata.fields.len == 2;
}

test "the network emits commonware's tracing events" {
    var collector = traces.Collector.init(gpa, .{});
    defer collector.deinit();
    _ = try run_deterministic(0, traced_pair, .{&collector});
    try collector.get_by_level(.info).expect_message_exact("network started");
    const debug = collector.get_by_level(.debug);
    // Peer 1 dials its bootstrapper, peer 0; peer 0 accepts and reserves the connection.
    for ([_][]const u8{
        "dialed peer",
        "upgraded connection",
        "accepted incoming connection",
        "completed handshake",
        "reserved connection",
        "peer started",
    }) |message| try debug.expect_message_exact(message);
    try debug.expect_event({}, is_listener_handshake);
    try testing.expectEqual(@as(u64, 0), collector.dropped);
}

const Dns = runtime.resolver.Dns;

/// `run_deterministic` that also passes the runner's DNS table after the metrics scope.
fn run_with_dns(seed: u64, comptime function: anytype, args: anytype) !struct { [8]u8, u64 } {
    const timeout_ns = 600 * std.time.ns_per_s;
    const config: runtime.deterministic.Config = .{ .seed = seed, .timeout_ns = timeout_ns };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    const args_all = .{ runner.io(), runner.network(), runner.metrics(), &runner.dns } ++ args;
    try (try runner.start(function, args_all));
    return .{ runner.auditor.state(), runner.now_ns() };
}

fn dns_ingress(comptime host: []const u8, port: u16) p2p.Ingress {
    return .{ .dns = .{ .host = utils.Hostname.literal(host), .port = port } };
}

fn localhost() codec.IpAddr {
    return .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) };
}

/// The identities of peers `0..keys.len`, and the same sorted.
fn dns_keys(keys: []PublicKey, sorted: []PublicKey) void {
    for (keys, 0..) |*key, index| key.* = PrivateKey.from_seed(index).public_key();
    @memcpy(sorted, keys);
    std.sort.pdq(PublicKey, sorted, {}, PublicKey.less_than);
}

/// Starts peer `index` on `base_port + index`, resolving through `dns`.
fn start_dns_node(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    dns: *Dns,
    sorted: []const PublicKey,
    index: usize,
    bootstrappers: []const Bootstrapper,
    allow_private_ips: bool,
) !Node {
    const port = base_port + @as(u16, @intCast(index));
    var config = peer_config(index, port, bootstrappers);
    config.resolver = dns.resolver();
    config.allow_private_ips = allow_private_ips;
    return start_node(io, transport, node_scope(scope, index), config, sorted, .per_second(100));
}

/// commonware `run_dns_connectivity`: peers 1 and 2 find peer 0 through `boot.local`.
fn dns_connectivity(io: Io, transport: *Transport, scope: metrics.Scope, dns: *Dns) !void {
    const n = 3;
    try dns.register("boot.local", &.{localhost()});
    var keys: [n]PublicKey = undefined;
    var sorted: [n]PublicKey = undefined;
    dns_keys(&keys, &sorted);
    const bootstrap = [_]Bootstrapper{.{
        .peer = keys[0],
        .ingress = dns_ingress("boot.local", base_port),
    }};
    var nodes: [n]Node = undefined;
    var started: usize = 0;
    defer stop_nodes(io, nodes[0..started]);
    for (&nodes, 0..) |*node, index| {
        const bootstrappers: []const Bootstrapper = if (index == 0) &.{} else &bootstrap;
        node.* = try start_dns_node(io, transport, scope, dns, &sorted, index, bootstrappers, true);
        started += 1;
    }
    try expect_full_connectivity(io, &keys, &nodes);
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    try expect_no_rate_limiting(text);
}

test "peers bootstrap through a DNS name" {
    // commonware `test_dns_bootstrapper_resolution`.
    _ = try run_with_dns(0, dns_connectivity, .{});
}

test "DNS bootstrapping is deterministic" {
    // commonware `test_dns_resolution_determinism`.
    const first = try run_with_dns(42, dns_connectivity, .{});
    const second = try run_with_dns(42, dns_connectivity, .{});
    try testing.expectEqualSlices(u8, &first[0], &second[0]);
    try testing.expectEqual(first[1], second[1]);
}

fn recipients_of_all(node: *Node, keys: []const PublicKey, me: usize) !usize {
    const sent = try node.registered.sender.send(.all, &.{&keys[me].key.bytes}, true);
    defer gpa.free(sent);
    return sent.len;
}

fn dns_failure_then_success(io: Io, transport: *Transport, scope: metrics.Scope, dns: *Dns) !void {
    var keys: [2]PublicKey = undefined;
    var sorted: [2]PublicKey = undefined;
    dns_keys(&keys, &sorted);
    const bootstrap = [_]Bootstrapper{.{
        .peer = keys[0],
        .ingress = dns_ingress("boot.local", base_port),
    }};
    var nodes: [2]Node = undefined;
    var started: usize = 0;
    defer stop_nodes(io, nodes[0..started]);
    nodes[0] = try start_dns_node(io, transport, scope, dns, &sorted, 0, &.{}, true);
    started += 1;
    nodes[1] = try start_dns_node(io, transport, scope, dns, &sorted, 1, &bootstrap, true);
    started += 1;
    // `boot.local` resolves to nothing yet, so peer 1 cannot reach its bootstrapper.
    try io.sleep(.fromSeconds(2), .real);
    try testing.expectEqual(0, try recipients_of_all(&nodes[0], &keys, 0));
    try dns.register("boot.local", &.{localhost()});
    try expect_full_connectivity(io, &keys, &nodes);
}

test "a bootstrapper whose name resolves later is dialed once it does" {
    // commonware `test_dns_resolution_failure_then_success`.
    _ = try run_with_dns(0, dns_failure_then_success, .{});
}

fn dns_private_ip_not_dialed(io: Io, transport: *Transport, scope: metrics.Scope, dns: *Dns) !void {
    try dns.register("boot.local", &.{localhost()});
    var keys: [2]PublicKey = undefined;
    var sorted: [2]PublicKey = undefined;
    dns_keys(&keys, &sorted);
    const bootstrap = [_]Bootstrapper{.{
        .peer = keys[0],
        .ingress = dns_ingress("boot.local", base_port),
    }};
    var nodes: [2]Node = undefined;
    var started: usize = 0;
    defer stop_nodes(io, nodes[0..started]);
    nodes[0] = try start_dns_node(io, transport, scope, dns, &sorted, 0, &.{}, true);
    started += 1;
    // Peer 1 refuses private addresses, and its bootstrapper resolves only to loopback.
    nodes[1] = try start_dns_node(io, transport, scope, dns, &sorted, 1, &bootstrap, false);
    started += 1;
    try io.sleep(.fromSeconds(5), .real);
    try testing.expectEqual(0, try recipients_of_all(&nodes[1], &keys, 1));
    try io.sleep(.fromSeconds(1), .real);
    try testing.expectError(error.Empty, nodes[0].registered.receiver.try_recv());
}

test "a name resolving only to private addresses is not dialed" {
    // commonware `test_dns_resolving_to_private_ip_not_dialed`.
    _ = try run_with_dns(0, dns_private_ip_not_dialed, .{});
}

/// `127.0.0.<base + 1..3>` (nobody listens there), then loopback, where the peer listens.
fn mixed_ips(base: u8) [4]codec.IpAddr {
    var ips: [4]codec.IpAddr = undefined;
    for (ips[0..3], 1..) |*ip, offset| {
        ip.* = .{ .v4 = codec.Ipv4.init(127, 0, 0, base + @as(u8, @intCast(offset))) };
    }
    ips[3] = localhost();
    return ips;
}

fn dns_mixed_ips(io: Io, transport: *Transport, scope: metrics.Scope, dns: *Dns) !void {
    try dns.register("peer-0.local", &mixed_ips(100));
    try dns.register("peer-1.local", &mixed_ips(110));
    var keys: [2]PublicKey = undefined;
    var sorted: [2]PublicKey = undefined;
    dns_keys(&keys, &sorted);
    const port_1 = base_port + 1;
    const bootstrap_0 = [_]Bootstrapper{.{
        .peer = keys[1],
        .ingress = dns_ingress("peer-1.local", port_1),
    }};
    const bootstrap_1 = [_]Bootstrapper{.{
        .peer = keys[0],
        .ingress = dns_ingress("peer-0.local", base_port),
    }};
    var nodes: [2]Node = undefined;
    var started: usize = 0;
    defer stop_nodes(io, nodes[0..started]);
    nodes[0] = try start_dns_node(io, transport, scope, dns, &sorted, 0, &bootstrap_0, true);
    started += 1;
    nodes[1] = try start_dns_node(io, transport, scope, dns, &sorted, 1, &bootstrap_1, true);
    started += 1;
    // Dials pick a resolved address at random; the peers connect once a dial picks loopback.
    for (0..1_200) |_| {
        _ = try recipients_of_all(&nodes[1], &keys, 1);
        try io.sleep(.fromMilliseconds(100), .real);
        var message = nodes[0].registered.receiver.try_recv() catch continue;
        defer message.deinit();
        try testing.expect(message.peer.eql(keys[1]));
        try testing.expectEqualSlices(u8, &keys[1].key.bytes, message.payload);
        return;
    }
    return error.TestUnexpectedResult;
}

test "peers connect through names that also resolve to dead addresses" {
    // commonware `test_dns_mixed_ips_connectivity` (seeds 0..25; fewer in Debug).
    const seeds: u64 = if (peers_full) 25 else 3;
    for (0..seeds) |seed| _ = try run_with_dns(seed, dns_mixed_ips, .{});
}

/// Runs one network on port 30001 under `config`, dials it `attempts` times from loopback,
/// and returns the encoded metrics (caller-freed). commonware's listener `check_rate_limits`.
fn dial_listener(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    config: Net.Config,
    attempts: usize,
) ![]u8 {
    const network = try Net.create(gpa, io, transport, scope, config);
    defer network.destroy();
    var task = try io.concurrent(run_node, .{network});
    defer task.cancel(io) catch {};
    const address = network_mod.to_address(local_socket(30_001));
    for (0..attempts) |_| {
        var connection = while (true) {
            break transport.dial(address) catch |err| switch (err) {
                error.ConnectionFailed => {
                    try io.sleep(.fromMilliseconds(1), .awake);
                    continue;
                },
                else => return err,
            };
        };
        // Give the listener time to accept (and possibly drop) the connection.
        try io.sleep(.fromMilliseconds(10), .awake);
        connection.deinit();
    }
    return scope.encode(gpa);
}

fn listener_config(per_ip: rate_limit.Quota, per_subnet: rate_limit.Quota) Net.Config {
    var config = test_config(PrivateKey.from_seed(1), 30_001, &.{}, 1024);
    config.allowed_handshake_rate_per_ip = per_ip;
    config.allowed_handshake_rate_per_subnet = per_subnet;
    return config;
}

fn expect_metric(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) {
        std.debug.print("missing \"{s}\" in:\n{s}\n", .{ needle, text });
        return error.TestMetricMissing;
    }
}

fn check_rate_limits(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    per_ip: u32,
    per_subnet: u32,
    ip_limited: []const u8,
    subnet_limited: []const u8,
) !void {
    const config = listener_config(.per_hour(per_ip), .per_hour(per_subnet));
    // One admitted handshake, then three attempts the limits drop at once.
    const text = try dial_listener(io, transport, scope, config, 4);
    defer gpa.free(text);
    try expect_metric(text, ip_limited);
    try expect_metric(text, subnet_limited);
}

test "the listener rate limits handshakes per ip, per subnet, and both" {
    const ip = "handshake_ip_rate_limited_total ";
    const subnet = "handshake_subnet_rate_limited_total ";
    _ = try run_deterministic(0, check_rate_limits, .{ 1, 100, ip ++ "3", subnet ++ "0" });
    _ = try run_deterministic(0, check_rate_limits, .{ 100, 1, ip ++ "0", subnet ++ "3" });
    _ = try run_deterministic(0, check_rate_limits, .{ 1, 1, ip ++ "3", subnet ++ "3" });
}

fn blocks_private(io: Io, transport: *Transport, scope: metrics.Scope, allow: bool) !void {
    var config = listener_config(.per_hour(100), .per_hour(100));
    config.allow_private_ips = allow;
    const text = try dial_listener(io, transport, scope, config, 1);
    defer gpa.free(text);
    const expected = if (allow) "handshakes_blocked_total 0" else "handshakes_blocked_total 1";
    try expect_metric(text, expected);
}

test "the listener drops private addresses unless allowed" {
    _ = try run_deterministic(0, blocks_private, .{false});
    _ = try run_deterministic(0, blocks_private, .{true});
}

fn epoch_at_ms(ms: u64) utils.SystemTime {
    return utils.SystemTime.UNIX_EPOCH.saturating_add(.from_millis(ms));
}

fn deadline_ms(config: *const Net.Config, now: u64, empty: bool, next_query_ms: ?u64) u64 {
    const next = if (next_query_ms) |ms| epoch_at_ms(ms) else null;
    return Net.next_deadline(config, epoch_at_ms(now), empty, next).epoch_millis();
}

test "the dialer waits dial_frequency, or the tracker's hint clamped to the cooldown" {
    // commonware's dialer cadence tests: dial_frequency 200 ms, cooldown 250 ms.
    var config = test_config(PrivateKey.from_seed(0), 3000, &.{}, 1024);
    // Queued peers drain one per dial_frequency, whatever the hint.
    try testing.expectEqual(@as(u64, 1200), deadline_ms(&config, 1000, false, 1010));
    // A hint before dial_frequency waits for dial_frequency.
    try testing.expectEqual(@as(u64, 1200), deadline_ms(&config, 1000, true, 1050));
    // A hint within the window is followed; without one the cooldown bounds the wait.
    try testing.expectEqual(@as(u64, 1230), deadline_ms(&config, 1000, true, 1230));
    try testing.expectEqual(@as(u64, 1250), deadline_ms(&config, 1000, true, 5000));
    try testing.expectEqual(@as(u64, 1250), deadline_ms(&config, 1000, true, null));
    // A cooldown shorter than dial_frequency still waits dial_frequency.
    config.peer_connection_cooldown = .from_millis(50);
    try testing.expectEqual(@as(u64, 1200), deadline_ms(&config, 1000, true, null));
    // An unbounded cooldown saturates, and the hint drives the refresh.
    config.peer_connection_cooldown = utils.Duration.max;
    try testing.expectEqual(@as(u64, 4000), deadline_ms(&config, 1000, true, 4000));
    const saturated = Net.next_deadline(&config, epoch_at_ms(1000), true, null);
    try testing.expect(saturated.order(epoch_at_ms(std.math.maxInt(u32))) == .gt);
}

/// Three bootstrappers that never answer: the dialer dials one per tick.
fn dial_cadence(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var bootstrappers: [3]Bootstrapper = undefined;
    for (&bootstrappers, 0..) |*bootstrapper, index| {
        const port = 4000 + @as(u16, @intCast(index));
        bootstrapper.* = .{
            .peer = PrivateKey.from_seed(10 + index).public_key(),
            .ingress = .{ .socket = local_socket(port) },
        };
    }
    var config = test_config(PrivateKey.from_seed(0), 3000, &bootstrappers, 1024);
    config.peer_connection_cooldown = .from_secs(10);
    const network = try Net.create(gpa, io, transport, scope, config);
    defer network.destroy();
    var task = try io.concurrent(run_node, .{network});
    defer task.cancel(io) catch {};
    // Ticks at 0, 200, and 400 ms dial each bootstrapper once; the long cooldown keeps them
    // from being dialed again.
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectEqual(@as(u64, 1), dial_attempts(network, &bootstrappers));
    try io.sleep(.fromMilliseconds(500), .awake);
    try testing.expectEqual(@as(u64, 3), dial_attempts(network, &bootstrappers));
    for (bootstrappers) |bootstrapper| {
        const counter = network.counters.attempts.metric().get(.{ .peer = bootstrapper.peer });
        try testing.expectEqual(@as(u64, 1), counter.?.get());
    }
    try io.sleep(.fromMilliseconds(600), .awake);
    try testing.expectEqual(@as(u64, 3), dial_attempts(network, &bootstrappers));
}

fn dial_attempts(network: *Net, bootstrappers: []const Bootstrapper) u64 {
    var total: u64 = 0;
    for (bootstrappers) |bootstrapper| {
        const family = network.counters.attempts.metric();
        if (family.get(.{ .peer = bootstrapper.peer })) |counter| total += counter.get();
    }
    return total;
}

test "the dialer drains its queue one peer per dial_frequency" {
    _ = try run_deterministic(0, dial_cadence, .{});
}

/// A bootstrapper whose listener never answers: the handshake timeout ends the dial and
/// releases its reservation (commonware `test_dial_timeout_releases_reservation`, whose
/// separate `dial_timeout` race is the handshake timeout here).
fn stalled_dial(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const silent = try transport.bind(network_mod.to_address(local_socket(4100)));
    defer silent.deinit();
    const bootstrappers = [_]Bootstrapper{.{
        .peer = PrivateKey.from_seed(10).public_key(),
        .ingress = .{ .socket = local_socket(4100) },
    }};
    var config = test_config(PrivateKey.from_seed(0), 3000, &bootstrappers, 1024);
    config.handshake_timeout = .from_secs(1);
    config.peer_connection_cooldown = .from_secs(10);
    const network = try Net.create(gpa, io, transport, scope, config);
    defer network.destroy();
    var task = try io.concurrent(run_node, .{network});
    defer task.cancel(io) catch {};
    const reserved = network.tracker.directory.metrics.reserved.metric();
    try io.sleep(.fromMilliseconds(500), .awake);
    try testing.expectEqual(@as(i64, 1), reserved.get());
    try io.sleep(.fromMilliseconds(1_000), .awake);
    try testing.expectEqual(@as(i64, 0), reserved.get());
}

test "a dial that never completes its handshake releases its reservation" {
    _ = try run_deterministic(0, stalled_dial, .{});
}

const Rejection = enum { tracker, router };

/// Admits every peer: the remote end of a spawner test authenticates anyone.
const AdmitAll = struct {
    pub fn admit(_: AdmitAll, _: PublicKey) Io.Cancelable!bool {
        return true;
    }
};

/// Accepts one connection as `signer` and reports whether any frame arrived before the
/// connection closed.
fn greeting_heard(
    io: Io,
    listener: *Transport.Listener,
    signer: PrivateKey,
    namespace: []const u8,
    max_frame_size: u32,
) anyerror!bool {
    const accepted = try listener.accept();
    const timeout: Io.Duration = .fromSeconds(5);
    const remote = stream.utils.Timeout(Upgrader).init(upgrader(signer), timeout);
    var upgraded = try remote.listen(
        gpa,
        io,
        namespace,
        max_frame_size,
        AdmitAll{},
        accepted.stream,
        accepted.sink,
    );
    defer upgraded.deinit(gpa);
    _ = upgraded.connection.receiver.recv() catch return false;
    return true;
}

/// Runs `serve` for a reserved peer that the tracker or router then rejects (commonware's
/// spawner `tracker_rejection_sends_no_greeting` and `router_rejection_sends_no_greeting`).
fn rejected_serve(io: Io, transport: *Transport, scope: metrics.Scope, rejection: Rejection) !void {
    const remote_signer = PrivateKey.from_seed(1);
    const peer = remote_signer.public_key();
    const bootstrappers = [_]Bootstrapper{.{
        .peer = peer,
        .ingress = .{ .socket = local_socket(4200) },
    }};
    const config = test_config(PrivateKey.from_seed(2), 3000, &bootstrappers, 1024);
    const network = try Net.create(gpa, io, transport, scope, config);
    defer network.destroy();
    const address = network_mod.to_address(local_socket(4200));
    const listener = try transport.bind(address);
    defer listener.deinit();
    const namespace = network.stream_namespace;
    const max_frame_size = network.max_frame_size;
    const args = .{ io, listener, remote_signer, namespace, max_frame_size };
    var remote = try io.concurrent(greeting_heard, args);
    defer _ = remote.cancel(io) catch {};
    const dialed = try transport.dial(address);
    var upgraded = try network.upgrader.dial(
        gpa,
        io,
        namespace,
        max_frame_size,
        peer,
        dialed.stream,
        dialed.sink,
    );
    const metadata = network.tracker.listen(peer).?;
    switch (rejection) {
        .tracker => try testing.expectEqual(p2p.Feedback.ok, network.tracker.block(peer)),
        .router => network.router.close(),
    }
    try network.serve(peer, &upgraded, metadata);
    try testing.expect(!try remote.await(io));
    const reserved = network.tracker.directory.metrics.reserved.metric();
    try testing.expectEqual(@as(i64, 0), reserved.get());
}

test "serve sends no greeting when the tracker or router rejects the peer" {
    _ = try run_deterministic(0, rejected_serve, .{Rejection.tracker});
    _ = try run_deterministic(0, rejected_serve, .{Rejection.router});
}

const stream_limit = "maximum message size exceeds stream limit";

test "a payload limit of u32 max panics" {
    // commonware `test_max_message_size_exceeds_stream_limit`.
    try utils.death.expect_panic(@src(), stream_limit, struct {
        fn body() !void {
            try create_with_limit(std.math.maxInt(u32));
        }
    }.body);
}

test "a payload limit one above the stream boundary panics" {
    // commonware `test_max_message_size_above_stream_boundary`.
    try utils.death.expect_panic(@src(), stream_limit, struct {
        fn body() !void {
            try create_with_limit(data.max_size(Upgrader.max_size) + 1);
        }
    }.body);
}

/// Creates (and frees) a network whose payload limit is `size`.
fn create_with_limit(size: u32) !void {
    var transport = Transport.init(gpa, Io.failing);
    defer transport.deinit();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const config = test_config(PrivateKey.from_seed(0), 0, &.{}, size);
    const network = try Net.create(gpa, Io.failing, &transport, .init(&registry), config);
    network.destroy();
}
