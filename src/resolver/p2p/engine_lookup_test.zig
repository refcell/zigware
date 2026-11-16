//! Resolver engine tests on p2p's authenticated lookup network over the deterministic runtime
//! (commonware `p2p/mod.rs` tests that use `start_lookup_peer`): peers that restart keep
//! their key and dial at a new address.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const stream = @import("stream");
const utils = @import("utils");
const p2p = @import("p2p");
const engine_mod = @import("engine.zig");
const base = @import("engine_test.zig");
const Produced = @import("produced.zig").Produced;
const MockKey = @import("mocks/key.zig").Key;

const metrics = runtime.telemetry.metrics;
const oneshot = utils.channel.oneshot;
const gpa = testing.allocator;
const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const lookup = p2p.authenticated.lookup;
const Upgrader = stream.SakeCups(PrivateKey, cryptography.ChaCha20Poly1305);
const Transport = runtime.network.deterministic.Network;
const Net = lookup.Network(Upgrader, Transport);
const Entry = Net.Tracker.PeerMap.Entry;
const Consumer = base.Consumer;

/// Holds every produced response until the test releases it (commonware `GatedProducer`).
const GatedProducer = struct {
    pub const Key = MockKey;

    /// A requested key and the sender of its response, in request order.
    const Request = struct { key: MockKey, response: oneshot.Sender(Produced) };

    const Shared = struct {
        io: Io,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        requests: std.ArrayList(Request) = .empty,
    };

    shared: *Shared,

    fn init(io: Io) Allocator.Error!GatedProducer {
        const shared = try gpa.create(Shared);
        shared.* = .{ .io = io };
        return .{ .shared = shared };
    }

    fn deinit(producer: GatedProducer) void {
        const shared = producer.shared;
        for (shared.requests.items) |*request| request.response.deinit();
        shared.requests.deinit(gpa);
        gpa.destroy(shared);
    }

    pub fn produce(
        producer: GatedProducer,
        key: MockKey,
    ) Allocator.Error!oneshot.Receiver(Produced) {
        const shared = producer.shared;
        var pair = try oneshot.channel(Produced, gpa, shared.io);
        errdefer pair.receiver.deinit();
        errdefer pair.sender.deinit();
        shared.mutex.lockUncancelable(shared.io);
        defer shared.mutex.unlock(shared.io);
        try shared.requests.append(gpa, .{ .key = key, .response = pair.sender });
        shared.condition.broadcast(shared.io);
        return pair.receiver;
    }

    /// Waits for the next request.
    fn next(producer: GatedProducer) Io.Cancelable!Request {
        const shared = producer.shared;
        try shared.mutex.lock(shared.io);
        defer shared.mutex.unlock(shared.io);
        while (shared.requests.items.len == 0) {
            try shared.condition.wait(shared.io, &shared.mutex);
        }
        return shared.requests.orderedRemove(0);
    }

    fn pending(producer: GatedProducer) usize {
        const shared = producer.shared;
        shared.mutex.lockUncancelable(shared.io);
        defer shared.mutex.unlock(shared.io);
        return shared.requests.items.len;
    }
};

fn EngineWith(comptime Pro: type) type {
    return engine_mod.Engine(engine_mod.Params(
        PublicKey,
        Net.Oracle,
        Net.Oracle,
        Consumer,
        Pro,
        Net.Sender,
        Net.Receiver,
    ));
}

/// A lookup network and the resolver engine on it (commonware `LookupPeer`).
fn LookupPeer(comptime Pro: type) type {
    return struct {
        const Self = @This();
        const EngineT = EngineWith(Pro);

        io: Io,
        network: *Net,
        task: Io.Future(anyerror!void),
        engine: EngineT.Spawned,

        fn oracle(peer: *Self) Net.Oracle {
            return peer.network.oracle();
        }

        /// Aborts the engine, then the network (commonware aborts both handles), and frees
        /// them; the mailbox stays usable until `deinit`.
        fn stop(peer: *Self) void {
            peer.engine.future.cancel(peer.io) catch {};
            peer.task.cancel(peer.io) catch {};
            peer.network.destroy();
            peer.engine.mailbox.deinit();
            peer.* = undefined;
        }
    };
}

fn run_network(network: *Net) anyerror!void {
    return network.run();
}

fn socket(port: u16) codec.SocketAddr {
    return .{ .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) }, .port = port };
}

/// Starts an authenticated lookup network tracking `entries` at set 0, and a resolver engine
/// on it (commonware `start_lookup_peer`).
fn start_lookup_peer(
    comptime Pro: type,
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    signer: PrivateKey,
    port: u16,
    entries: []const Entry,
    consumer: Consumer,
    producer: Pro,
) !LookupPeer(Pro) {
    const config = Net.Config.local(.{
        .upgrader = .init(.{
            .signer = signer,
            .synchrony_bound_ms = 5_000,
            .max_handshake_age_ms = 10_000,
            .version = .v1,
        }, .v1),
        .namespace = "_COMMONWARE_RESOLVER_TEST",
        .listen = lookup.network.to_address(socket(port)),
        .max_peers_per_set = 2,
        .max_message_size = 1024 * 1024,
        .mailbox_size = base.mailbox_size,
    });
    const network = try Net.create(gpa, io, transport, scope.child("network"), config);
    errdefer network.destroy();
    // Make peer membership and the resolver channel available when connections start.
    const tracked: Net.Tracker.Tracked = .init_primary(.init(entries));
    try testing.expectEqual(p2p.Feedback.ok, network.oracle().track(0, tracked));
    var connection = try network.register(0, .per_second(base.rate_limit));
    errdefer connection.deinit();
    const task = try io.concurrent(run_network, .{network});
    // Keep requests active while the test holds their responses.
    const engine = try LookupPeer(Pro).EngineT.spawn(gpa, io, scope.child("actor"), .{
        .peer_provider = network.oracle(),
        .blocker = network.oracle(),
        .consumer = consumer,
        .producer = producer,
        .mailbox_size = base.mailbox_size,
        .me = signer.public_key(),
        .fetch_timeout = .from_secs(30),
        .fetch_retry_delay = base.fetch_retry_delay,
        .priority_requests = false,
        .priority_responses = false,
    }, connection.sender, connection.receiver);
    return .{ .io = io, .network = network, .task = task, .engine = engine };
}

const requester_port: u16 = 3000;
const server_port: u16 = 3001;
const restarted_port: u16 = 3002;

/// The requester at `requester_at` and the server, sorted by key.
fn peers(requester_at: u16, entries: *[2]Entry) []const Entry {
    entries.* = .{
        .{ .key = base.key_of(1), .value = .{ .symmetric = socket(requester_at) } },
        .{ .key = base.key_of(2), .value = .{ .symmetric = socket(server_port) } },
    };
    if (PublicKey.order(entries[0].key, entries[1].key) == .gt) {
        std.mem.swap(Entry, &entries[0], &entries[1]);
    }
    return entries;
}

/// Sends a held response; the requester's engine may already have dropped the receiver.
fn release(response: *?oneshot.Sender(Produced), value: []const u8) !void {
    var sender = response.*.?;
    response.* = null;
    sender.send(.{ .bytes = value }) catch |err| switch (err) {
        error.Closed => {},
    };
}

fn sleep_s(io: Io, seconds: i64) !void {
    try io.sleep(.fromSeconds(seconds), .real);
}

/// The requester's key, the deterministic network, and the server's gated producer.
const Restart = struct {
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    producer: GatedProducer,
    empty_producer: base.Producer,
    entries: [2]Entry = undefined,

    fn requester() PrivateKey {
        return .from_seed(1);
    }

    fn server() PrivateKey {
        return .from_seed(2);
    }

    fn start_server(restart: *Restart, consumer: Consumer) !LookupPeer(GatedProducer) {
        const entries = peers(requester_port, &restart.entries);
        const scope = restart.scope.child("server");
        return start_lookup_peer(
            GatedProducer,
            restart.io,
            restart.transport,
            scope,
            server(),
            server_port,
            entries,
            consumer,
            restart.producer,
        );
    }

    fn start_requester(
        restart: *Restart,
        label: []const u8,
        port: u16,
        consumer: Consumer,
    ) !LookupPeer(base.Producer) {
        const entries = peers(port, &restart.entries);
        const scope = restart.scope.child(label);
        return start_lookup_peer(
            base.Producer,
            restart.io,
            restart.transport,
            scope,
            requester(),
            port,
            entries,
            consumer,
            restart.empty_producer,
        );
    }

    /// Fetches `value`'s key after the peers connect and returns the server's held response.
    fn fetch_held(restart: *Restart, peer: anytype, value: u8) !oneshot.Sender(Produced) {
        try sleep_s(restart.io, 5);
        try base.fetch(&peer.engine.mailbox, value);
        const request = try restart.producer.next();
        if (!request.key.eql(base.key(value))) {
            var response = request.response;
            response.deinit();
            return error.TestUnexpectedResult;
        }
        return request.response;
    }
};

/// A delayed response must not answer a different request after the requester restarts.
fn stale_response_after_requester_restart(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
) !void {
    const old_value = "data for key 1";
    const new_value = "data for key 2";
    var restart: Restart = .{
        .io = io,
        .transport = transport,
        .scope = scope,
        .producer = try GatedProducer.init(io),
        .empty_producer = try base.Producer.init(gpa, io),
    };
    defer restart.producer.deinit();
    defer restart.empty_producer.deinit();

    // Start a server that holds each response until the test releases it.
    const server_consumer = try Consumer.init(gpa, io);
    defer server_consumer.deinit();
    var server_peer = try restart.start_server(server_consumer);
    defer server_peer.stop();

    // Allow the peers to connect before fetching so the held response belongs to the
    // requester's first request ID.
    const requester_consumer = try Consumer.init(gpa, io);
    defer requester_consumer.deinit();
    var first = try restart.start_requester("requester", requester_port, requester_consumer);
    // `send` and `deinit` both release a sender; whichever runs first clears this.
    var old_response: ?oneshot.Sender(Produced) = try restart.fetch_held(&first, 1);
    defer if (old_response) |*sender| sender.deinit();

    // Stop the requester while the server still holds its response.
    first.stop();

    // Reconnect before fetching a different key with the new requester's first ID. Its
    // consumer rejects the old value if it is attributed to the new key.
    const entries = peers(restarted_port, &restart.entries);
    const tracked: Net.Tracker.Tracked = .init_primary(.init(entries));
    try testing.expectEqual(p2p.Feedback.ok, server_peer.oracle().track(1, tracked));
    const consumer = try Consumer.init(gpa, io);
    defer consumer.deinit();
    try consumer.add_expected(base.key(2), new_value);
    var restarted = try restart.start_requester("requester_restarted", restarted_port, consumer);
    defer restarted.stop();
    var new_response: ?oneshot.Sender(Produced) = try restart.fetch_held(&restarted, 2);
    defer if (new_response) |*sender| sender.deinit();

    // Give the old response time to arrive while the new request is pending, so the
    // requester handles it before the genuine response can complete the request.
    try release(&old_response, old_value);
    try sleep_s(io, 1);
    try release(&new_response, new_value);

    // The requester accepts the new value without retrying or blocking the server.
    var event = try consumer.next_event();
    defer event.deinit(gpa);
    try testing.expect(event.key.eql(base.key(2)));
    try testing.expectEqualStrings(new_value, event.value);
    var blocked_subscription = try restarted.oracle().blocked();
    if (try blocked_subscription.try_recv(gpa)) |blocked| {
        defer gpa.free(blocked);
        const server_key = Restart.server().public_key();
        for (blocked) |peer| try testing.expect(peer.order(server_key) != .eq);
    }
    try testing.expectEqual(@as(usize, 0), restart.producer.pending());
}

fn run_deterministic(comptime function: anytype) !void {
    const timeout_ns = 120 * std.time.ns_per_s;
    const config: runtime.deterministic.Config = .{ .seed = 0, .timeout_ns = timeout_ns };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try (try runner.start(function, .{ runner.io(), runner.network(), runner.metrics() }));
}

test "stale response after requester restart is ignored" {
    try run_deterministic(stale_response_after_requester_restart);
}
