//! P2P resolver plumbing reused by the standard and coding marshal variants (commonware
//! `marshal/resolver/p2p.rs`).
//!
//! `Resolver(D, P, C, B, NetS, NetR).init` starts a `resolver.p2p` engine whose consumer and
//! producer is a marshal `Handler`, returning the receiver the actor reads, the mailbox it
//! fetches through, and the engine's future. The engine borrows the handler: release
//! `handler` after the engine stops (commonware drops the engine's clones with it).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const resolver_api = @import("resolver");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;
const handler = @import("handler.zig");
const soak = @import("../mocks/soak.zig");

/// Configuration for the p2p resolver (commonware `resolver::p2p::Config`).
pub fn Config(comptime P: type, comptime C: type, comptime B: type) type {
    return struct {
        /// The public key that identifies this node.
        public_key: P,
        /// The provider of the peer set fetches go to. A fetch without targets may go to any
        /// peer of the latest set, primary or secondary; a targeted fetch (such as one from
        /// `Mailbox.hint_finalized`) goes only to its targets in that set.
        peer_provider: C,
        /// Blocks peers that send invalid responses.
        blocker: B,
        /// The size of the request mailbox backlog (non-zero).
        mailbox_size: u32,
        /// Timeout for requests (non-zero).
        fetch_timeout: utils.Duration,
        /// Delay after an unresolved attempt before retrying its fetch. Zero permits
        /// immediate retries, subject to the sender's rate limit.
        fetch_retry_delay: utils.Duration,
        /// Whether requests are sent with priority over other network messages.
        priority_requests: bool,
        /// Whether responses are sent with priority over other network messages.
        priority_responses: bool,
    };
}

/// The mailbox for issuing marshal backfill requests (commonware `resolver::p2p::Mailbox`).
pub fn Mailbox(comptime D: type, comptime P: type) type {
    return resolver_api.p2p.Mailbox(handler.Key(D), P, handler.Annotation);
}

/// The p2p resolver of marshal commitments `D` over peers `P`, peer provider `C`, blocker
/// `B`, and the backfill channel halves `NetS` and `NetR` (`NetR.capacity()`).
pub fn Resolver(
    comptime D: type,
    comptime P: type,
    comptime C: type,
    comptime B: type,
    comptime NetS: type,
    comptime NetR: type,
) type {
    return struct {
        pub const Handler = handler.Handler(D);
        pub const Engine = resolver_api.p2p.Engine(resolver_api.p2p.engine.Params(
            P,
            C,
            B,
            Handler,
            Handler,
            NetS,
            NetR,
        ));

        /// What `init` starts.
        pub const Started = struct {
            /// The actor's end of the handler mailbox.
            receiver: actor.mailbox.Receiver(handler.Message(D)),
            /// The engine's consumer and producer; release it after the engine stops.
            handler: Handler,
            /// Issues backfill fetches.
            mailbox: Engine.Mailbox,
            /// The engine task; cancel it to stop the engine, which frees itself.
            future: Io.Future(Engine.Error!void),
        };

        /// Starts the resolver over the backfill channel, registering its metrics under
        /// `scope` (`handler` and `resolver`). The handler holds as many messages as the
        /// channel, since peer requests overflowing it are dropped.
        pub fn init(
            gpa: Allocator,
            io: Io,
            scope: metrics.Scope,
            config: Config(P, C, B),
            sender: NetS,
            receiver: NetR,
        ) !Started {
            assert(config.mailbox_size > 0);
            const capacity: u32 = @intCast(receiver.capacity());
            const handler_scope = scope.child("handler");
            var channel = try handler.init(D, gpa, io, &handler_scope, capacity);
            errdefer channel.receiver.deinit();
            errdefer channel.handler.deinit();
            const spawned = try Engine.spawn(gpa, io, scope.child("resolver"), .{
                .peer_provider = config.peer_provider,
                .blocker = config.blocker,
                .consumer = channel.handler,
                .producer = channel.handler,
                .mailbox_size = config.mailbox_size,
                .me = config.public_key,
                .fetch_timeout = config.fetch_timeout,
                .fetch_retry_delay = config.fetch_retry_delay,
                .priority_requests = config.priority_requests,
                .priority_responses = config.priority_responses,
            }, sender, receiver);
            return .{
                .receiver = channel.receiver,
                .handler = channel.handler,
                .mailbox = spawned.mailbox,
                .future = spawned.future,
            };
        }
    };
}

const testing = std.testing;
const runtime = @import("runtime");
const p2p = @import("p2p");
const cryptography = @import("cryptography");

const test_gpa = testing.allocator;
const TestKey = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(TestKey);
const TestDigest = cryptography.Sha256.Digest;
const TestResolver = Resolver(
    TestDigest,
    TestKey,
    Net.Manager,
    Net.Control,
    Net.Sender,
    Net.Receiver,
);

fn test_peer(seed: u64) TestKey {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

fn start_peer(
    io: Io,
    network: *Net,
    registry: *metrics.Registry,
    me: TestKey,
) !TestResolver.Started {
    const control = network.oracle().control(me);
    const connection = try control.register(0, p2p.Quota.per_second(100));
    const scope = metrics.Scope.init(registry).child("marshal").with_attribute("peer", me);
    return TestResolver.init(test_gpa, io, scope, .{
        .public_key = me,
        .peer_provider = network.oracle().manager(),
        .blocker = control,
        .mailbox_size = 16,
        .fetch_timeout = .from_millis(400),
        .fetch_retry_delay = .from_millis(100),
        .priority_requests = false,
        .priority_responses = false,
    }, connection.sender, connection.receiver);
}

fn stop_peer(io: Io, started: *TestResolver.Started) void {
    started.mailbox.deinit();
    started.future.cancel(io) catch {};
    started.receiver.deinit();
    started.handler.deinit();
}

fn fetch_body(io: Io) anyerror!void {
    const network = try Net.init(test_gpa, io, .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = 2,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    });
    defer network.deinit();
    var task = try io.concurrent(Net.run, .{network});
    defer {
        network.close();
        task.await(io) catch {};
    }
    var registry = metrics.Registry.init(test_gpa);
    defer registry.deinit();
    var peers = [_]TestKey{ test_peer(1), test_peer(2) };
    p2p.TrackedPeers(TestKey).PeerSet.sort(&peers);
    _ = network.oracle().manager().track(0, .init_primary(.init(&peers)));
    const link: p2p.simulated.Link = .{
        .latency = .from_millis(10),
        .jitter = .from_millis(1),
        .success_rate = 1.0,
    };
    try network.oracle().add_link(peers[0], peers[1], link);
    try network.oracle().add_link(peers[1], peers[0], link);
    var asker = try start_peer(io, network, &registry, peers[0]);
    defer stop_peer(io, &asker);
    var server = try start_peer(io, network, &registry, peers[1]);
    defer stop_peer(io, &server);

    // The asker's fetch reaches the server's actor as a produce request.
    const request: handler.Request(TestDigest) = .{ .finalized = .new(5) };
    const key, const annotation = request.split();
    _ = try asker.mailbox.fetch(.{ .key = key, .subscriber = annotation });
    var produce = (try server.receiver.recv()).?;
    try testing.expectEqual(5, produce.body.produce.key.finalized.get());
    try produce.body.produce.response.send(.{ .bytes = "finalized block" });

    // The served bytes come back to the asker's actor as a delivery.
    const delivered = (try asker.receiver.recv()).?;
    var deliver = delivered.body.deliver;
    defer test_gpa.free(deliver.value);
    defer test_gpa.free(deliver.delivery.subscribers);
    try testing.expectEqualStrings("finalized block", deliver.value);
    try testing.expect(deliver.delivery.key.eql(key));
    try testing.expect(deliver.delivery.subscribers[0].eql(annotation));
    try deliver.response.send(.{ .resolved = .complete });
}

test "p2p resolver delivers what a peer's handler produces" {
    const timeout_ns = 60 * std.time.ns_per_s;
    try soak.run_io(test_gpa, .{ .timeout_ns = timeout_ns }, fetch_body);
}
