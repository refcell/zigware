//! Custom-handshake tests of the lookup network (commonware `lookup/mod.rs` tests): a
//! handshake whose transport identity differs from the application identity the network
//! routes by, and that can reject, fail, or stall an attempt on demand.
//!
//! commonware's `test_construction_enforces_handshake_message_limit` checks that `Network::new`
//! panics when the message limit exceeds the stream's; Zig tests cannot catch panics, so only
//! the accepted boundary is tested (network_test.zig, "the largest payload ...").

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
const network_mod = @import("network.zig");

const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Sake = stream.sake.Sake(PrivateKey);
const Upgrader = stream.cups.Cups(TestHandshake, cryptography.ChaCha20Poly1305);
const Transport = runtime.network.deterministic.Network;
const Net = network_mod.Network(Upgrader, Transport);
const Entry = Net.Tracker.PeerMap.Entry;
const gpa = testing.allocator;

const max_message_size: u32 = 1_024;
const keys_max = 3;
const log_max = 64;

/// Keys seen by a handshake; keeps the first `log_max`.
const Log = struct {
    keys: [log_max]PublicKey = undefined,
    count: std.atomic.Value(u32) = .init(0),

    fn push(log: *Log, key: PublicKey) void {
        const index = log.count.fetchAdd(1, .monotonic);
        if (index < log_max) log.keys[index] = key;
    }

    fn items(log: *const Log) []const PublicKey {
        return log.keys[0..@min(log.count.load(.monotonic), log_max)];
    }

    fn contains(log: *const Log, key: PublicKey) bool {
        for (log.items()) |item| {
            if (item.eql(key)) return true;
        }
        return false;
    }

    fn all(log: *const Log, key: PublicKey) bool {
        for (log.items()) |item| {
            if (!item.eql(key)) return false;
        }
        return true;
    }
};

/// What a handshake saw, and switches that make it reject, fail, or stall (commonware
/// `Observations`).
const Observations = struct {
    dials: Log = .{},
    inbound: Log = .{},
    rejections: std.atomic.Value(u32) = .init(0),
    listens: std.atomic.Value(u32) = .init(0),
    pending: std.atomic.Value(u32) = .init(0),
    failures: std.atomic.Value(u32) = .init(0),
    reject_inbound: std.atomic.Value(bool) = .init(false),
    fail: std.atomic.Value(bool) = .init(false),
    stall_next: std.atomic.Value(bool) = .init(false),
};

/// Pairs of transport and application keys every handshake shares.
const Identities = struct {
    transport: [keys_max]PublicKey,
    application: [keys_max]PublicKey,
    count: usize,

    fn to_transport(identities: *const Identities, application: PublicKey) ?PublicKey {
        for (identities.application[0..identities.count], 0..) |key, index| {
            if (key.eql(application)) return identities.transport[index];
        }
        return null;
    }

    fn to_application(identities: *const Identities, transport: PublicKey) ?PublicKey {
        for (identities.transport[0..identities.count], 0..) |key, index| {
            if (key.eql(transport)) return identities.application[index];
        }
        return null;
    }
};

/// One peer's handshake state, which its `TestHandshake` points to.
const State = struct {
    application_key: PublicKey,
    sake: Sake,
    identities: *const Identities,
    observations: *Observations,
};

/// SAKE under transport keys, exposing application keys (commonware `TestHandshake`). A
/// pointer keeps the upgrader small: each attempt copies it into a task closure.
const TestHandshake = struct {
    state: *const State,

    pub fn public_key(handshake: TestHandshake) PublicKey {
        return handshake.state.application_key;
    }

    /// Stalls until canceled when `stall_next` was set, then fails when `fail` is set.
    fn authenticate(handshake: TestHandshake, io: Io) !void {
        const observations = handshake.state.observations;
        if (observations.stall_next.swap(false, .monotonic)) {
            _ = observations.pending.fetchAdd(1, .monotonic);
            while (true) try io.sleep(.fromSeconds(3_600), .real);
        }
        if (observations.fail.load(.monotonic)) {
            _ = observations.failures.fetchAdd(1, .monotonic);
            return error.AuthenticationFailed;
        }
    }

    pub fn dial(
        handshake: TestHandshake,
        io: Io,
        namespace: []const u8,
        peer: PublicKey,
        source: anytype,
        sink: anytype,
    ) !cryptography.Transcript {
        const state = handshake.state;
        state.observations.dials.push(peer);
        const transport = state.identities.to_transport(peer) orelse
            return error.UnknownApplicationIdentity;
        try handshake.authenticate(io);
        return state.sake.dial(io, namespace, transport, source, sink);
    }

    pub fn listen(
        handshake: TestHandshake,
        io: Io,
        namespace: []const u8,
        bouncer: anytype,
        source: anytype,
        sink: anytype,
    ) !stream.Accepted(PublicKey) {
        const state = handshake.state;
        _ = state.observations.listens.fetchAdd(1, .monotonic);
        const wrapped: Bouncer(@TypeOf(bouncer)) = .{
            .inner = bouncer,
            .handshake = handshake,
            .io = io,
        };
        const accepted = try state.sake.listen(io, namespace, wrapped, source, sink);
        // Proof: the bouncer admitted only transport keys with an application key.
        const application = state.identities.to_application(accepted.peer) orelse
            unreachable;
        state.observations.inbound.push(application);
        return .{ .peer = application, .transcript = accepted.transcript };
    }
};

/// Admits a transport key by its application key, then authenticates.
fn Bouncer(comptime Inner: type) type {
    return struct {
        inner: Inner,
        handshake: TestHandshake,
        io: Io,

        pub fn admit(bouncer: @This(), transport: PublicKey) Io.Cancelable!bool {
            const observations = bouncer.handshake.state.observations;
            const identities = bouncer.handshake.state.identities;
            const application = identities.to_application(transport) orelse
                return false;
            const acceptable = try bouncer.inner.admit(application);
            if (!acceptable or observations.reject_inbound.load(.monotonic)) {
                _ = observations.rejections.fetchAdd(1, .monotonic);
                return false;
            }
            bouncer.handshake.authenticate(bouncer.io) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                return false;
            };
            return true;
        }
    };
}

/// Transport key seeds and application key seeds, and the handshakes built from them.
fn Handshakes(comptime n: usize) type {
    comptime assert(n <= keys_max);
    return struct {
        identities: Identities,
        observations: [n]Observations,
        states: [n]State,

        /// Initializes in place: the states point into `handshakes`.
        fn init(handshakes: *@This(), seeds: [n][2]u64) void {
            handshakes.identities.count = n;
            for (seeds, 0..) |seed, index| {
                const signer = PrivateKey.from_seed(seed[0]);
                const application = PrivateKey.from_seed(seed[1]).public_key();
                handshakes.identities.transport[index] = signer.public_key();
                handshakes.identities.application[index] = application;
                handshakes.observations[index] = .{};
                handshakes.states[index] = .{
                    .application_key = application,
                    .sake = .{
                        .signer = signer,
                        .synchrony_bound_ms = 5_000,
                        .max_handshake_age_ms = 10_000,
                        .version = .v1,
                    },
                    .identities = &handshakes.identities,
                    .observations = &handshakes.observations[index],
                };
            }
        }

        fn handshake(handshakes: *const @This(), index: usize) TestHandshake {
            return .{ .state = &handshakes.states[index] };
        }
    };
}

fn local_socket(port: u16) codec.SocketAddr {
    return .{ .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) }, .port = port };
}

/// commonware's `config`: `local` with a 50 ms handshake timeout and fast redials.
fn custom_config(handshake: TestHandshake, port: u16) Net.Config {
    var config = Net.Config.local(.{
        .upgrader = .init(handshake, .v1),
        .namespace = "_COMMONWARE_P2P_CUSTOM_HANDSHAKE_TEST",
        .listen = network_mod.to_address(local_socket(port)),
        .max_peers_per_set = 2,
        .max_message_size = max_message_size,
        .mailbox_size = 1_000,
    });
    // Recovery within the test deadline must come from the handshake timeout.
    config.handshake_timeout = .from_millis(50);
    config.dial_timeout = .from_secs(20);
    config.peer_connection_cooldown = .from_millis(10);
    config.dial_frequency = .from_millis(5);
    config.max_concurrent_handshakes = 2;
    return config;
}

const Node = struct {
    network: *Net,
    registered: Net.Registered,
    task: Io.Future(anyerror!void),

    fn deinit(node: *Node, io: Io) void {
        node.task.cancel(io) catch {};
        node.registered.sender.deinit();
        while (node.registered.receiver.try_recv()) |message| {
            var owned = message;
            owned.deinit();
        } else |_| {}
        node.registered.receiver.deinit();
        node.network.destroy();
        node.* = undefined;
    }
};

/// One peer with its application key and port, for a tracked map.
const Peer = struct { key: PublicKey, port: u16 };

/// `peers` as a map sorted by key, in `buffer`.
fn peer_map(buffer: []Entry, peers: []const Peer) Net.Tracker.PeerMap {
    const entries = buffer[0..peers.len];
    for (entries, peers) |*entry, peer| {
        entry.* = .{ .key = peer.key, .value = .{ .symmetric = local_socket(peer.port) } };
    }
    std.sort.pdq(Entry, entries, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return PublicKey.order(a.key, b.key) == .lt;
        }
    }.less);
    return .init(entries);
}

/// Starts a network with `config` tracking `primary` and `secondary` at set 0.
fn start(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    config: Net.Config,
    primary: []const Peer,
    secondary: []const Peer,
) !Node {
    const network = try Net.create(gpa, io, transport, scope, config);
    errdefer network.destroy();
    var primary_buffer: [keys_max]Entry = undefined;
    var secondary_buffer: [keys_max]Entry = undefined;
    const tracked: Net.Tracker.Tracked = .{
        .primary = peer_map(&primary_buffer, primary),
        .secondary = peer_map(&secondary_buffer, secondary),
    };
    try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(0, tracked));
    var node: Node = .{
        .network = network,
        .registered = try network.register(0, .per_second(100)),
        .task = undefined,
    };
    node.task = try io.concurrent(run_network, .{network});
    return node;
}

fn run_network(network: *Net) anyerror!void {
    return network.run();
}

/// Sends `message` to `recipient` every 10 ms until `receiver` gets a message, and returns
/// its sender (commonware `repeat_send` and `recv`).
fn send_until_received(
    io: Io,
    from: *Node,
    recipient: PublicKey,
    message: []const u8,
    to: *Node,
) !PublicKey {
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        try testing.expect(attempts < 1_000);
        const sent = try from.registered.sender.send(.{ .one = recipient }, &.{message}, true);
        gpa.free(sent);
        if (to.registered.receiver.try_recv()) |received| {
            var owned = received;
            defer owned.deinit();
            try testing.expectEqualStrings(message, owned.payload);
            return owned.peer;
        } else |_| {}
        try io.sleep(.fromMilliseconds(10), .real);
    }
}

/// Waits until `counter` is nonzero (commonware `wait_for_counter`).
fn wait_for_counter(io: Io, counter: *const std.atomic.Value(u32)) !void {
    var attempts: u32 = 0;
    while (counter.load(.monotonic) == 0) : (attempts += 1) {
        try testing.expect(attempts < 10_000);
        try io.sleep(.fromMilliseconds(1), .real);
    }
}

fn now_ns(io: Io) u64 {
    const now = Io.Clock.real.now(io).nanoseconds;
    assert(now >= 0);
    return @intCast(now);
}

/// A listener at `port` that only accepts the dialer at `port + 1`, which dials it.
fn start_pair(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    port: u16,
    listener: TestHandshake,
    dialer: TestHandshake,
) !struct { Node, Node } {
    const listener_peer: Peer = .{ .key = listener.public_key(), .port = port };
    const dialer_peer: Peer = .{ .key = dialer.public_key(), .port = port + 1 };
    var listener_node = try start(
        io,
        transport,
        scope.child("listener"),
        custom_config(listener, port),
        &.{listener_peer},
        &.{dialer_peer},
    );
    errdefer listener_node.deinit(io);
    const dialer_node = try start(
        io,
        transport,
        scope.child("dialer"),
        custom_config(dialer, port + 1),
        &.{ listener_peer, dialer_peer },
        &.{},
    );
    return .{ listener_node, dialer_node };
}

const pair_seeds = [2][2]u64{ .{ 0, 100 }, .{ 1, 101 } };

fn routes_bidirectionally(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var handshakes: Handshakes(2) = undefined;
    handshakes.init(pair_seeds);
    const listener = handshakes.handshake(0);
    const dialer = handshakes.handshake(1);
    var listener_node, var dialer_node =
        try start_pair(io, transport, scope, 5_100, listener, dialer);
    defer listener_node.deinit(io);
    defer dialer_node.deinit(io);
    const listener_key = listener.public_key();
    const dialer_key = dialer.public_key();
    const from_dialer =
        try send_until_received(io, &dialer_node, listener_key, "from dialer", &listener_node);
    try testing.expect(from_dialer.eql(dialer_key));
    const from_listener =
        try send_until_received(io, &listener_node, dialer_key, "from listener", &dialer_node);
    try testing.expect(from_listener.eql(listener_key));
    const observations = &handshakes.observations;
    try testing.expect(observations[1].dials.items().len > 0);
    try testing.expect(observations[1].dials.all(listener_key));
    try testing.expect(observations[0].inbound.items().len > 0);
    try testing.expect(observations[0].inbound.all(dialer_key));
}

test "a custom handshake routes application identities both ways" {
    // commonware `test_custom_handshake_routes_application_identities_bidirectionally`.
    try run_timed(0, routes_bidirectionally, .{});
}

fn failures_release_for_retry(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var handshakes: Handshakes(2) = undefined;
    handshakes.init(pair_seeds);
    const observations = &handshakes.observations;
    observations[0].reject_inbound.store(true, .monotonic);
    const listener = handshakes.handshake(0);
    const dialer = handshakes.handshake(1);
    var listener_node, var dialer_node =
        try start_pair(io, transport, scope, 5_200, listener, dialer);
    defer listener_node.deinit(io);
    defer dialer_node.deinit(io);
    // A rejected listen, then a failed dial, each release the peer for another attempt.
    try wait_for_counter(io, &observations[0].rejections);
    try testing.expectEqual(@as(usize, 0), observations[0].inbound.items().len);
    observations[1].fail.store(true, .monotonic);
    observations[0].reject_inbound.store(false, .monotonic);
    try wait_for_counter(io, &observations[1].failures);
    // A stalled dial is released by the handshake timeout.
    const stalled_at_ns = now_ns(io);
    observations[1].stall_next.store(true, .monotonic);
    observations[1].fail.store(false, .monotonic);
    try wait_for_counter(io, &observations[1].pending);
    const listener_key = listener.public_key();
    const peer =
        try send_until_received(io, &dialer_node, listener_key, "accepted", &listener_node);
    try testing.expect(peer.eql(dialer.public_key()));
    try testing.expect(now_ns(io) - stalled_at_ns >= 50 * std.time.ns_per_ms);
}

test "custom handshake failures release the peer for a retry" {
    // commonware `test_custom_handshake_failures_release_for_retry`.
    try run_timed(0, failures_release_for_retry, .{});
}

const pending_seeds = [3][2]u64{ .{ 10, 110 }, .{ 11, 111 }, .{ 12, 112 } };
const central_port: u16 = 5_300;
const pending_timeout_secs = 5;

/// `local` and `others`, all dialed when `dial` and otherwise only accepted (commonware
/// `tracked_peers`), started at `local.port`.
fn start_tracking(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    handshake: TestHandshake,
    local: Peer,
    others: []const Peer,
    dial: bool,
) !Node {
    assert(others.len < keys_max);
    var config = custom_config(handshake, local.port);
    config.handshake_timeout = .from_secs(pending_timeout_secs);
    config.max_peers_per_set = 3;
    var primary: [keys_max]Peer = undefined;
    primary[0] = local;
    if (!dial) return start(io, transport, scope, config, primary[0..1], others);
    @memcpy(primary[1..][0..others.len], others);
    return start(io, transport, scope, config, primary[0 .. 1 + others.len], &.{});
}

/// commonware `assert_pending_authentication_does_not_block_peer`: the central peer's
/// handshake with a blocked peer stalls, and a healthy peer still connects to it before the
/// stalled handshake times out.
fn pending_authentication(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    central_dials: bool,
) !void {
    var handshakes: Handshakes(3) = undefined;
    handshakes.init(pending_seeds);
    const observations = &handshakes.observations;
    observations[0].stall_next.store(true, .monotonic);
    var peers: [3]Peer = undefined;
    for (&peers, 0..) |*peer, index| peer.* = .{
        .key = handshakes.identities.application[index],
        .port = central_port + @as(u16, @intCast(index)),
    };
    const central, const blocked, const healthy = peers;
    const stalled_at_ns = now_ns(io);
    var central_node = try start_tracking(io, transport, scope.child("central"), handshakes
        .handshake(0), central, &.{ blocked, healthy }, central_dials);
    defer central_node.deinit(io);
    var blocked_node = try start_tracking(io, transport, scope.child("blocked"), handshakes
        .handshake(1), blocked, &.{central}, !central_dials);
    defer blocked_node.deinit(io);
    try wait_for_counter(io, &observations[0].pending);
    try wait_for_counter(io, &observations[if (central_dials) 1 else 0].listens);
    var healthy_node = try start_tracking(io, transport, scope.child("healthy"), handshakes
        .handshake(2), healthy, &.{central}, !central_dials);
    defer healthy_node.deinit(io);
    const message = "healthy peer progressed";
    const peer = if (central_dials)
        try send_until_received(io, &central_node, healthy.key, message, &healthy_node)
    else
        try send_until_received(io, &healthy_node, central.key, message, &central_node);
    try testing.expect(peer.eql(if (central_dials) central.key else healthy.key));
    const elapsed_ns = now_ns(io) - stalled_at_ns;
    try testing.expect(elapsed_ns < pending_timeout_secs * std.time.ns_per_s);
    try testing.expectEqual(@as(u32, 1), observations[0].pending.load(.monotonic));
    try expect_pending_attempts(&handshakes, peers, central_dials);
}

/// Who dialed and listened while the central peer's first handshake stalled.
fn expect_pending_attempts(
    handshakes: *const Handshakes(3),
    peers: [3]Peer,
    central_dials: bool,
) !void {
    const central, const blocked, const healthy = peers;
    const observations = &handshakes.observations;
    if (central_dials) {
        try testing.expect(observations[0].dials.contains(blocked.key));
        try testing.expect(observations[0].dials.contains(healthy.key));
        try testing.expect(observations[2].listens.load(.monotonic) > 0);
    } else {
        try testing.expectEqual(@as(usize, 0), observations[0].dials.items().len);
        try testing.expect(observations[0].listens.load(.monotonic) >= 2);
        try testing.expect(observations[1].dials.contains(central.key));
        try testing.expect(observations[2].dials.contains(central.key));
    }
}

test "a pending authentication does not block another peer" {
    // commonware `test_pending_authentication_does_not_block_another_peer`.
    for ([_]bool{ true, false }) |central_dials| {
        try run_timed(0, pending_authentication, .{central_dials});
    }
}

/// Runs `function(io, transport, scope, args...)` on a deterministic runner seeded with
/// `seed` that fails after 10 simulated seconds (commonware `Runner::timed`).
fn run_timed(seed: u64, comptime function: anytype, args: anytype) !void {
    const config: runtime.deterministic.Config = .{
        .seed = seed,
        .timeout_ns = 10 * std.time.ns_per_s,
    };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    const args_all = .{ runner.io(), runner.network(), runner.metrics() } ++ args;
    try (try runner.start(function, args_all));
}
