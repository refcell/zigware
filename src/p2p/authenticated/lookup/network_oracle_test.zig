//! Single-node tests of a lookup network's oracle (commonware `lookup/mod.rs` tests): peer-set
//! subscriptions and operations after shutdown.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const stream = @import("stream");
const metrics = runtime.telemetry.metrics;
const p2p = @import("../../root.zig");
const network_mod = @import("network.zig");

const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Upgrader = stream.SakeCups(PrivateKey, cryptography.ChaCha20Poly1305);
const Transport = runtime.network.deterministic.Network;
const Net = network_mod.Network(Upgrader, Transport);
const Entry = Net.Tracker.PeerMap.Entry;
const gpa = testing.allocator;

const base_port: u16 = 3000;

fn key(seed: u64) PublicKey {
    return PrivateKey.from_seed(seed).public_key();
}

fn entry(seed: u64) Entry {
    const socket: codec.SocketAddr = .{
        .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) },
        .port = base_port + @as(u16, @intCast(seed)),
    };
    return .{ .key = key(seed), .value = .{ .symmetric = socket } };
}

/// The peers with key seeds in `[first, end)`, sorted by key.
fn entries(buffer: []Entry, first: u64, end: u64) []Entry {
    const slice = buffer[0..@intCast(end - first)];
    for (slice, first..) |*item, seed| item.* = entry(seed);
    std.sort.pdq(Entry, slice, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return PublicKey.order(a.key, b.key) == .lt;
        }
    }.less);
    return slice;
}

fn track(oracle: Net.Oracle, index: u64, peers: []const Entry) p2p.Feedback {
    return oracle.track(index, .init_primary(.init(peers)));
}

fn test_config(port: u16) Net.Config {
    var config = Net.Config.local(.{
        .upgrader = .init(.{
            .signer = PrivateKey.from_seed(0),
            .synchrony_bound_ms = 5_000,
            .max_handshake_age_ms = 10_000,
            .version = .v1,
        }, .v1),
        .namespace = "test_namespace",
        .listen = network_mod.to_address(entry(port - base_port).value.symmetric),
        .max_peers_per_set = 32,
        .max_message_size = 1024 * 1024,
        .mailbox_size = 1_000,
    });
    config.ping_frequency = .from_secs(1);
    config.dial_frequency = .from_millis(200);
    return config;
}

fn run_network(network: *Net) anyerror!void {
    return network.run();
}

fn expect_keys(actual: []const PublicKey, expected: []const Entry) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try testing.expect(want.key.eql(got));
}

fn contains(peers: []const PublicKey, peer: PublicKey) bool {
    for (peers) |candidate| {
        if (candidate.eql(peer)) return true;
    }
    return false;
}

/// commonware `test_subscription_includes_self_when_registered`.
fn includes_self(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const network = try Net.create(gpa, io, transport, scope, test_config(base_port));
    defer network.destroy();
    var task = try io.concurrent(run_network, .{network});
    defer task.cancel(io) catch {};
    var subscription = try network.oracle().subscribe();
    defer subscription.deinit();
    var buffer: [2]Entry = undefined;
    try testing.expectEqual(.ok, track(network.oracle(), 1, entries(&buffer, 1, 2)));
    var first = (try subscription.recv()).?;
    defer first.deinit();
    try testing.expectEqual(1, first.index);
    try expect_keys(first.latest.primary, entries(&buffer, 1, 2));
    try expect_keys(first.all.primary, entries(&buffer, 1, 2));
    try testing.expectEqual(0, first.latest.secondary.len + first.all.secondary.len);
    try testing.expect(!contains(first.all.primary, key(0)));
    // Once a set lists us, updates include us.
    try testing.expectEqual(.ok, track(network.oracle(), 2, entries(&buffer, 0, 2)));
    var second = (try subscription.recv()).?;
    defer second.deinit();
    try testing.expectEqual(2, second.index);
    try expect_keys(second.latest.primary, entries(&buffer, 0, 2));
    try expect_keys(second.all.primary, entries(&buffer, 0, 2));
    try testing.expectEqual(0, second.latest.secondary.len + second.all.secondary.len);
}

test "subscriptions include us once a tracked set does" {
    try run(includes_self, .{});
}

/// commonware `test_unordered_peer_sets`: an index below the latest is ignored.
fn unordered_sets(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const network = try Net.create(gpa, io, transport, scope, test_config(base_port));
    defer network.destroy();
    var task = try io.concurrent(run_network, .{network});
    defer task.cancel(io) catch {};
    var subscription = try network.oracle().subscribe();
    defer subscription.deinit();
    var set10: [2]Entry = undefined;
    _ = entries(&set10, 0, 2);
    try testing.expectEqual(.ok, track(network.oracle(), 10, &set10));
    var first = (try subscription.recv()).?;
    defer first.deinit();
    try testing.expectEqual(10, first.index);
    try expect_keys(first.latest.primary, &set10);
    try expect_keys(first.all.primary, &set10);
    var set9: [8]Entry = undefined;
    try testing.expectEqual(.ok, track(network.oracle(), 9, entries(&set9, 2, 10)));
    var set11: [6]Entry = undefined;
    try testing.expectEqual(.ok, track(network.oracle(), 11, entries(&set11, 4, 10)));
    // Set 9 published nothing; set 11's update spans sets 10 and 11.
    var second = (try subscription.recv()).?;
    defer second.deinit();
    try testing.expectEqual(11, second.index);
    try expect_keys(second.latest.primary, &set11);
    var union_buffer: [8]Entry = undefined;
    try testing.expectEqual(8, set10.len + set11.len);
    @memcpy(union_buffer[0..2], &set10);
    @memcpy(union_buffer[2..], &set11);
    std.sort.pdq(Entry, &union_buffer, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return PublicKey.order(a.key, b.key) == .lt;
        }
    }.less);
    try expect_keys(second.all.primary, &union_buffer);
    try testing.expectEqual(0, second.all.secondary.len);
}

test "peer sets tracked out of order are ignored" {
    try run(unordered_sets, .{});
}

/// commonware `test_operations_after_shutdown_do_not_panic`.
fn after_shutdown(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    const network = try Net.create(gpa, io, transport, scope, test_config(base_port));
    defer network.destroy();
    var registered = try network.register(0, .per_second(100));
    defer registered.receiver.deinit();
    defer registered.sender.deinit();
    var self_entry = [_]Entry{entry(0)};
    try testing.expectEqual(.ok, track(network.oracle(), 0, &self_entry));
    var task = try io.concurrent(run_network, .{network});
    task.cancel(io) catch {};
    try io.sleep(.fromMilliseconds(100), .real);
    const oracle = network.oracle();
    try testing.expectEqual(.closed, track(oracle, 1, &self_entry));
    if (try oracle.peer_set(gpa, 0)) |peers| peers.free(gpa);
    var subscription = try oracle.subscribe();
    subscription.deinit();
    try testing.expectEqual(.closed, oracle.block(key(0)));
    const sent = try registered.sender.send(.all, &.{&key(0).key.bytes}, true);
    defer gpa.free(sent);
    try testing.expectEqual(0, sent.len);
}

test "operations after shutdown do not panic" {
    try run(after_shutdown, .{});
}

fn run(comptime function: anytype, args: anytype) !void {
    const timeout_ns = 60 * std.time.ns_per_s;
    const config: runtime.deterministic.Config = .{ .seed = 0, .timeout_ns = timeout_ns };
    const Args = @TypeOf(args);
    try runtime.deterministic.soak(gpa, config, args, struct {
        fn run(context: Args, runner: *runtime.deterministic.Runner) anyerror!void {
            const args_all = .{ runner.io(), runner.network(), runner.metrics() } ++ context;
            try (try runner.start(function, args_all));
        }
    }.run);
}
