//! commonware `glue/src/stateful/db/p2p/actor.rs` live tests: resolver actors serving keyless
//! databases to each other over p2p's simulated network, on the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("../mod.zig");
const state_sync = @import("../state_sync.zig");
const glue_sync = @import("../sync.zig");
const keyless = @import("../keyless.zig");
const actor_mod = @import("actor.zig");

const gpa = testing.allocator;
const qmdb = storage.qmdb;
const ring = utils.channel.ring;
const metrics = runtime.telemetry.metrics;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const PublicKey = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(PublicKey);
const Family = storage.mmr.Family;
const U64 = utils.sequence.U64;
const contiguous = storage.journal.contiguous;
const Encoding = qmdb.value.Fixed(U64);
const KeylessDb = keyless.Keyless(
    Family,
    Encoding,
    contiguous.fixed.Journal(qmdb.keyless.Operation(Family, Encoding)),
    Sha256,
);
const TestActor = actor_mod.Actor(actor_mod.Params(
    PublicKey,
    Net.Manager,
    Net.Control,
    KeylessDb,
    Net.Sender,
    Net.Receiver,
));
const Request = TestActor.Request;
const Response = TestActor.Response;
const Mailbox = TestActor.Mailbox;
const peers_max = 3;

/// One node's storage, page cache, and metrics.
const Node = struct {
    io: Io,
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(node: *Node, io: Io) !void {
        node.* = .{
            .io = io,
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(node: *Node) void {
        node.registry.deinit();
        node.cache_ref.deinit();
        node.storage.deinit();
    }

    fn env(node: *Node) db.Env {
        return .{
            .gpa = gpa,
            .io = node.io,
            .storage = node.storage.interface(),
            .scope = metrics.Scope.init(&node.registry).child("db"),
        };
    }

    fn config(node: *Node) KeylessDb.Config {
        return .{
            .merkle = .{
                .journal_partition = "actor-journal",
                .metadata_partition = "actor-metadata",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &node.cache_ref,
            },
            .log = .{
                .partition = "actor-log",
                .items_per_blob = 7,
                .cache_ref = &node.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
        };
    }

    /// Opens a keyless database with `batches` applied batches whose values start at `base`.
    fn open(node: *Node, batches: u64, base: u64) !KeylessDb.Shared {
        const shared = try KeylessDb.Shared.open(node.env(), node.config(), null);
        errdefer shared.deinit();
        for (0..batches) |i| {
            var batch = try shared.new_batches();
            errdefer batch.deinit();
            for (0..4) |j| try batch.append(U64.init(base + i * 10 + j));
            var merkleized = try batch.merkleize();
            defer merkleized.deinit();
            try shared.apply(&merkleized);
        }
        const barrier = try shared.finalize();
        try barrier.durable();
        return shared;
    }
};

/// Peers on a simulated network with reliable links, each with a node and a running actor.
const Cluster = struct {
    io: Io,
    network: *Net,
    task: Io.Future((Io.Cancelable || std.mem.Allocator.Error)!void),
    peers: [peers_max]PublicKey = undefined,
    count: usize,
    nodes: [peers_max]Node = undefined,
    databases: [peers_max]?KeylessDb.Shared = @splat(null),
    actors: [peers_max]?TestActor.Created = @splat(null),
    futures: [peers_max]?Io.Future(TestActor.Error!void) = @splat(null),

    /// `seeds` name the peers, sorted by public key, all tracked at peer set 0.
    fn init(cluster: *Cluster, io: Io, seeds: []const u64) !void {
        assert(seeds.len <= peers_max);
        const network = try Net.init(gpa, io, .{
            .max_size = 1024 * 1024,
            .max_peers_per_set = seeds.len,
            .disconnect_on_block = true,
            .tracked_peer_sets = 1,
        });
        cluster.* = .{
            .io = io,
            .network = network,
            .task = try io.concurrent(Net.run, .{network}),
            .count = seeds.len,
        };
        for (seeds, 0..) |seed, i| {
            cluster.peers[i] = cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
            try cluster.nodes[i].init(io);
        }
        const peers = cluster.peers[0..seeds.len];
        p2p.TrackedPeers(PublicKey).PeerSet.sort(peers);
        const tracked = cluster.oracle().manager().track(0, .init_primary(.init(peers)));
        try testing.expectEqual(p2p.Feedback.ok, tracked);
    }

    fn deinit(cluster: *Cluster) void {
        for (0..cluster.count) |i| {
            if (cluster.futures[i]) |*future| future.cancel(cluster.io) catch |err| {
                std.debug.panic("actor: {t}", .{err});
            };
            if (cluster.actors[i]) |*created| created.mailbox.deinit();
        }
        cluster.network.close();
        cluster.task.await(cluster.io) catch |err| switch (err) {
            error.Canceled => {},
            else => std.debug.panic("network: {t}", .{err}),
        };
        cluster.network.deinit();
        for (0..cluster.count) |i| {
            if (cluster.databases[i]) |database| database.deinit();
            cluster.nodes[i].deinit();
        }
    }

    fn oracle(cluster: *const Cluster) Net.Oracle {
        return cluster.network.oracle();
    }

    /// Links peers `a` and `b` both ways with 1 ms latency and no loss.
    fn link(cluster: *const Cluster, a: usize, b: usize) !void {
        const value: p2p.simulated.Link = .{
            .latency = .from_millis(1),
            .jitter = .from_millis(0),
            .success_rate = 1.0,
        };
        try cluster.oracle().add_link(cluster.peers[a], cluster.peers[b], value);
        try cluster.oracle().add_link(cluster.peers[b], cluster.peers[a], value);
    }

    /// Starts peer `i`'s actor, serving its database if it has one.
    fn start(cluster: *Cluster, i: usize, quota: u32) !*Mailbox {
        const me = cluster.peers[i];
        const control = cluster.oracle().control(me);
        var connection = try control.register(0, p2p.Quota.per_second(quota));
        const scope = metrics.Scope.init(&cluster.nodes[i].registry).child("actor");
        const created = TestActor.create(gpa, cluster.io, scope, .{
            .peer_provider = cluster.oracle().manager(),
            .blocker = control,
            .database = cluster.databases[i],
            .mailbox_size = 16,
            .me = me,
            .fetch_timeout = .from_secs(2),
            .fetch_retry_delay = .from_millis(50),
            .max_serve_ops = 16,
            .priority_requests = false,
            .priority_responses = false,
        }) catch |err| {
            connection.deinit();
            return err;
        };
        cluster.actors[i] = created;
        cluster.futures[i] = try created.actor.start(connection.sender, connection.receiver);
        return &cluster.actors[i].?.mailbox;
    }

    fn fetch_requests(cluster: *const Cluster, i: usize) u64 {
        return cluster.actors[i].?.actor.metrics.fetch_requests.metric().get();
    }
};

/// Runs `body` on a deterministic runtime that fails after 10 simulated seconds.
fn run(comptime body: fn (Io) anyerror!void) !void {
    const timeout_ns = 10 * std.time.ns_per_s;
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .timeout_ns = timeout_ns });
    defer runner.deinit();
    try try runner.start(body, .{runner.io()});
}

/// The encoding of `database`'s own response to `request`.
fn expected_payload(database: KeylessDb.Shared, request: Request) ![]u8 {
    var source: state_sync.SharedSource(KeylessDb) = .{ .shared = database };
    var served = try source.serve(gpa, request);
    defer served.response.deinit(gpa);
    assert(served.feedback == null);
    return codec.encode(Response, gpa, served.response);
}

fn serve_accepted(mailbox: *Mailbox, request: Request, expected: []const u8) !void {
    var copy = mailbox.clone();
    defer copy.deinit();
    var served = try copy.serve(gpa, request);
    defer served.response.deinit(gpa);
    const encoded = try codec.encode(Response, gpa, served.response);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, expected, encoded);
    served.feedback.?.accept();
}

fn coalesced(io: Io) !void {
    var cluster: Cluster = undefined;
    try cluster.init(io, &.{ 1, 2 });
    defer cluster.deinit();
    try cluster.link(0, 1);
    cluster.databases[1] = try cluster.nodes[1].open(2, 0);
    const mailbox = try cluster.start(0, 100);
    _ = try cluster.start(1, 100);
    const size = (try cluster.databases[1].?.committed_targets()).end;
    const request: Request = .{ .operations = .{ .size = size, .start = 0, .max_ops = 1 } };
    const expected = try expected_payload(cluster.databases[1].?, request);
    defer gpa.free(expected);
    // Both callers register independently while the resolver coalesces their key.
    var first = try io.concurrent(serve_accepted, .{ mailbox, request, expected });
    var delayed = try io.concurrent(serve_accepted, .{ mailbox, request, expected });
    try first.await(io);
    try delayed.await(io);
    try testing.expectEqual(@as(u64, 2), cluster.fetch_requests(0));
}

test "stateful p2p actor live: coalesced same-key calls complete" {
    try run(coalesced);
}

/// Syncs a fresh keyless database on `node` from `mailbox` to `target`.
fn sync_through(
    node: *Node,
    mailbox: *Mailbox,
    target: KeylessDb.SyncTarget,
    sync_config: state_sync.SyncEngineConfig,
) !KeylessDb.SyncTarget {
    var tips = try ring.channel(glue_sync.TipUpdate(Digest, KeylessDb.SyncTarget), gpa, node.io, 1);
    tips.sender.deinit();
    const anchor: glue_sync.Anchor(Digest) = .{
        .height = .new(1),
        .round = .new(.zero(), .new(1)),
        .digest = .{ .bytes = @splat(1) },
    };
    const env = node.env();
    const config = node.config();
    const synced = try state_sync.sync_shared(
        KeylessDb,
        Digest,
        env,
        config,
        mailbox,
        anchor,
        target,
        tips.receiver,
        sync_config,
    );
    defer synced.databases.deinit();
    return synced.databases.committed_targets();
}

fn multiple_batches(io: Io) !void {
    var cluster: Cluster = undefined;
    try cluster.init(io, &.{ 1, 2 });
    defer cluster.deinit();
    try cluster.link(0, 1);
    cluster.databases[1] = try cluster.nodes[1].open(4, 0);
    const mailbox = try cluster.start(0, 100);
    _ = try cluster.start(1, 100);
    const target = try cluster.databases[1].?.committed_targets();
    // Small fetch and apply batches exercise repeated source polling between journal writes,
    // with several candidate responses allowed to wait in parallel.
    var destination: Node = undefined;
    try destination.init(io);
    defer destination.deinit();
    const reached = try sync_through(&destination, mailbox, target, .{
        .fetch_batch_size = 2,
        .apply_batch_size = 1,
        .max_outstanding_requests = 4,
    });
    try testing.expect(db.targets_eql(KeylessDb.SyncTarget, &reached, &target));
    try testing.expect(cluster.fetch_requests(0) > 4);
}

test "stateful p2p actor live: multiple batches sync through the live mailbox" {
    try run(multiple_batches);
}

/// Links `client` to `good` once the network records a block.
fn link_after_block(cluster: *Cluster, client: usize, good: usize) !void {
    while (true) {
        const blocked = try cluster.oracle().blocked(gpa);
        gpa.free(blocked);
        if (blocked.len > 0) return cluster.link(client, good);
        try cluster.io.sleep(.fromMilliseconds(1), .awake);
    }
}

fn invalid_peer(io: Io) !void {
    var cluster: Cluster = undefined;
    try cluster.init(io, &.{ 1, 2, 3 });
    defer cluster.deinit();
    // Sorted peers: the first serves a different history of the same size.
    const bad = 0;
    const good = 1;
    const client = 2;
    // Only the bad peer is reachable until the client blocks it, so the first candidate is
    // invalid whatever peer the fetcher would sample (commonware relies on its seeded order).
    try cluster.link(client, bad);
    cluster.databases[bad] = try cluster.nodes[bad].open(2, 100);
    cluster.databases[good] = try cluster.nodes[good].open(2, 0);
    const target = try cluster.databases[good].?.committed_targets();
    const bad_target = try cluster.databases[bad].?.committed_targets();
    try testing.expectEqual(target.end, bad_target.end);
    try testing.expect(!std.meta.eql(target.root, bad_target.root));
    _ = try cluster.start(bad, 1000);
    _ = try cluster.start(good, 1000);
    const mailbox = try cluster.start(client, 1000);

    var destination: Node = undefined;
    try destination.init(io);
    defer destination.deinit();
    var linker = try io.concurrent(link_after_block, .{ &cluster, client, good });
    defer linker.cancel(io) catch {};
    const started = Io.Clock.Timestamp.now(io, .awake);
    const reached = try sync_through(&destination, mailbox, target, .{
        .fetch_batch_size = 16,
        .apply_batch_size = 16,
        .max_outstanding_requests = 1,
    });
    // The rejected peer is blocked and the same registration retries at once, well before
    // the 2 s request timeout.
    const elapsed = started.durationTo(Io.Clock.Timestamp.now(io, .awake));
    try testing.expect(elapsed.raw.toNanoseconds() < std.time.ns_per_s);
    try testing.expect(db.targets_eql(KeylessDb.SyncTarget, &reached, &target));
    const blocked = try cluster.oracle().blocked(gpa);
    defer gpa.free(blocked);
    try testing.expectEqual(@as(usize, 1), blocked.len);
    try testing.expect(std.meta.eql(blocked[0].origin, cluster.peers[client]));
    try testing.expect(std.meta.eql(blocked[0].recipient, cluster.peers[bad]));
    try testing.expectEqual(@as(u64, 1), cluster.fetch_requests(client));
}

test "stateful p2p actor live: an invalid peer retries the same qmdb source registration" {
    try run(invalid_peer);
}
