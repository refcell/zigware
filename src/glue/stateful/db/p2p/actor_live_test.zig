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
const actor_package = @import("actor");
const resolver = @import("resolver");
const db = @import("../mod.zig");
const state_sync = @import("../state_sync.zig");
const glue_sync = @import("../sync.zig");
const keyless = @import("../keyless.zig");
const actor_mod = @import("actor.zig");

const gpa = testing.allocator;
const qmdb = storage.qmdb;
const ring = utils.channel.ring;
const mpsc = utils.channel.mpsc;
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

    fn pending_requests(cluster: *const Cluster, i: usize) u64 {
        return @intCast(cluster.actors[i].?.actor.metrics.pending_requests.metric().get());
    }

    /// Two linked peers with identical databases, both actors running (commonware's
    /// `spawn_live_pair`): independent replicas let one serve while the other is locked.
    fn init_pair(cluster: *Cluster, io: Io) !void {
        try cluster.init(io, &.{ 1, 2 });
        errdefer cluster.deinit();
        try cluster.link(0, 1);
        for (0..2) |i| cluster.databases[i] = try cluster.nodes[i].open(2, 0);
        const root_0 = (try cluster.databases[0].?.committed_targets()).root;
        const root_1 = (try cluster.databases[1].?.committed_targets()).root;
        assert(std.meta.eql(root_0, root_1));
        for (0..2) |i| _ = try cluster.start(i, 100);
    }

    /// Stops every actor (commonware's `shutdown_actors`); the actor tasks free themselves.
    fn stop(cluster: *Cluster) void {
        for (0..cluster.count) |i| {
            if (cluster.futures[i]) |*future| future.cancel(cluster.io) catch |err| {
                std.debug.panic("actor: {t}", .{err});
            };
            cluster.futures[i] = null;
        }
    }

    /// Waits up to one simulated second for peer `i` to dispatch `count` fetches.
    fn wait_for_fetches(cluster: *const Cluster, i: usize, count: u64) !void {
        for (0..1000) |_| {
            if (cluster.fetch_requests(i) >= count) return;
            try cluster.io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestUnexpectedResult;
    }

    /// Waits up to one simulated second for peer `i` to release every closed request.
    fn wait_for_no_pending(cluster: *const Cluster, i: usize) !void {
        for (0..1000) |_| {
            if (cluster.pending_requests(i) == 0) return;
            try cluster.io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestUnexpectedResult;
    }
};

/// A serve running in its own task, polled through `done` (commonware polls the future).
const Background = struct {
    mailbox: Mailbox,
    request: Request,
    done: std.atomic.Value(bool) = .init(false),
    result: (Mailbox.Error || Io.Cancelable)!Served = error.Canceled,
    future: ?Io.Future(void) = null,

    const Served = storage.qmdb.sync.Served(Response);

    fn start(background: *Background, io: Io, mailbox: *Mailbox, request: Request) !void {
        background.* = .{ .mailbox = mailbox.clone(), .request = request };
        background.future = try io.concurrent(run_serve, .{background});
    }

    fn run_serve(background: *Background) void {
        background.result = background.mailbox.serve(gpa, background.request);
        background.done.store(true, .release);
    }

    fn is_done(background: *const Background) bool {
        return background.done.load(.acquire);
    }

    /// Waits up to `timeout_ms` simulated milliseconds for the serve to finish.
    fn wait(background: *const Background, io: Io, timeout_ms: u64) !bool {
        for (0..timeout_ms) |_| {
            if (background.is_done()) return true;
            try io.sleep(.fromMilliseconds(1), .awake);
        }
        return background.is_done();
    }

    /// Joins the task and releases an unclaimed response.
    fn deinit(background: *Background, io: Io) void {
        if (background.future) |*future| future.cancel(io);
        if (background.result) |*served| {
            served.response.deinit(gpa);
            if (served.feedback) |*feedback| feedback.deinit();
        } else |_| {}
        background.mailbox.deinit();
    }

    /// Takes the finished response, checks its encoding, and accepts it.
    fn expect_accepted(background: *Background, expected: []const u8) !void {
        assert(background.is_done());
        var served = try background.result;
        background.result = error.Canceled;
        defer served.response.deinit(gpa);
        const encoded = try codec.encode(Response, gpa, served.response);
        defer gpa.free(encoded);
        try testing.expectEqualSlices(u8, expected, encoded);
        served.feedback.?.accept();
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

fn concurrent_serves(io: Io) !void {
    var cluster: Cluster = undefined;
    try cluster.init_pair(io);
    defer cluster.deinit();
    const database_0 = cluster.databases[0].?;
    const database_1 = cluster.databases[1].?;
    const size = (try database_0.committed_targets()).end;
    // Distinct request types keep the two reads from being coalesced.
    const request_1: Request = .{ .operations = .{ .size = size, .start = 0, .max_ops = 1 } };
    const request_2: Request = .{ .boundary = .{ .size = size, .start = 0 } };
    const expected_1 = try expected_payload(database_0, request_1);
    defer gpa.free(expected_1);
    const expected_2 = try expected_payload(database_1, request_2);
    defer gpa.free(expected_2);
    const peer_expected = try expected_payload(database_1, request_1);
    defer gpa.free(peer_expected);

    // Keep one peer's database unavailable while the other peer requests its data.
    var slot = try database_0.write();
    var slot_held = true;
    defer if (slot_held) slot.put();
    var blocked: Background = undefined;
    try blocked.start(io, &cluster.actors[1].?.mailbox, request_1);
    defer blocked.deinit(io);
    try cluster.wait_for_fetches(1, 1);
    try io.sleep(.fromMilliseconds(5), .awake);
    try testing.expect(!blocked.is_done());

    // The busy actor must still fetch data from the other peer.
    try serve_accepted(&cluster.actors[0].?.mailbox, request_1, peer_expected);

    // A newly attached database serves a second request while the first read waits.
    try cluster.actors[0].?.mailbox.attach_database(database_1);
    var second: Background = undefined;
    try second.start(io, &cluster.actors[1].?.mailbox, request_2);
    defer second.deinit(io);
    const second_done = try second.wait(io, 1000);
    const first_pending = !blocked.is_done();

    // Restore access before asserting. The first read must use its original database.
    slot.put();
    slot_held = false;
    try testing.expect(second_done);
    try testing.expect(first_pending);
    try second.expect_accepted(expected_2);
    try testing.expect(try blocked.wait(io, 1000));
    try blocked.expect_accepted(expected_1);
}

test "stateful p2p actor live: concurrent serves preserve actor progress" {
    try run(concurrent_serves);
}

fn pending_feedback(io: Io) !void {
    var cluster: Cluster = undefined;
    try cluster.init_pair(io);
    defer cluster.deinit();
    const size = (try cluster.databases[0].?.committed_targets()).end;
    const request: Request = .{ .operations = .{ .size = size, .start = 0, .max_ops = 1 } };
    const boundary: Request = .{ .boundary = .{ .size = size, .start = 0 } };
    const expected = try expected_payload(cluster.databases[0].?, request);
    defer gpa.free(expected);
    const expected_boundary = try expected_payload(cluster.databases[1].?, boundary);
    defer gpa.free(expected_boundary);
    const mailbox_0 = &cluster.actors[0].?.mailbox;
    var pending = try mailbox_0.serve(gpa, request);
    var pending_held = true;
    defer if (pending_held) pending.feedback.?.deinit();
    {
        defer pending.response.deinit(gpa);
        const encoded = try codec.encode(Response, gpa, pending.response);
        defer gpa.free(encoded);
        try testing.expectEqualSlices(u8, expected, encoded);
    }

    // An undecided response must not block another fetch or an incoming peer read.
    try serve_accepted(mailbox_0, boundary, expected_boundary);
    try serve_accepted(&cluster.actors[1].?.mailbox, request, expected);

    // Closing the undecided receipt cancels it without waiting for a verdict.
    pending.feedback.?.deinit();
    pending_held = false;
    try cluster.wait_for_no_pending(0);
    var replacement = try mailbox_0.serve(gpa, request);
    var feedback = replacement.feedback.?;
    var feedback_held = true;
    defer if (feedback_held) feedback.deinit();
    {
        defer replacement.response.deinit(gpa);
        const encoded = try codec.encode(Response, gpa, replacement.response);
        defer gpa.free(encoded);
        try testing.expectEqualSlices(u8, expected, encoded);
    }

    // Shutdown must release both a held receipt and a fetch waiting on peer storage.
    var slot = try cluster.databases[1].?.write();
    var waiting: Background = undefined;
    try waiting.start(io, mailbox_0, boundary);
    defer waiting.deinit(io);
    try cluster.wait_for_fetches(0, 4);
    cluster.stop();
    slot.put();
    try testing.expect(try waiting.wait(io, 1000));
    try testing.expectError(error.ResponseDropped, waiting.result);
    feedback_held = false;
    try testing.expect(try feedback.reject() == null);
}

test "stateful p2p actor live: pending feedback allows fetches, serves, and cancellation" {
    try run(pending_feedback);
}

fn late_subscriber_case(io: Io, accept: bool) !void {
    var cluster: Cluster = undefined;
    try cluster.init_pair(io);
    defer cluster.deinit();
    const size = (try cluster.databases[1].?.committed_targets()).end;
    const request: Request = .{ .operations = .{ .size = size, .start = 0, .max_ops = 1 } };
    const expected = try expected_payload(cluster.databases[1].?, request);
    defer gpa.free(expected);
    const mailbox_0 = &cluster.actors[0].?.mailbox;
    var first = try mailbox_0.serve(gpa, request);
    first.response.deinit(gpa);
    var first_feedback = first.feedback.?;
    var first_held = true;
    defer if (first_held) first_feedback.deinit();
    var late: Background = undefined;
    try late.start(io, mailbox_0, request);
    defer late.deinit(io);

    // A later distinct request completes only after the resolver admits the late subscriber.
    // Glue admission alone would not establish this order.
    const boundary: Request = .{ .boundary = .{ .size = size, .start = 0 } };
    const expected_boundary = try expected_payload(cluster.databases[1].?, boundary);
    defer gpa.free(expected_boundary);
    try serve_accepted(mailbox_0, boundary, expected_boundary);
    try testing.expect(!late.is_done());

    // With the peer database locked, only the resolver's cached bytes can finish the late
    // call. Restore the database before asserting the bounded result.
    var slot = try cluster.databases[1].?.write();
    first_held = false;
    if (accept) first_feedback.accept() else first_feedback.deinit();
    const late_done = try late.wait(io, 1000);
    slot.put();
    try testing.expect(late_done);
    try late.expect_accepted(expected);
    try cluster.wait_for_no_pending(0);
}

fn late_subscriber(io: Io) !void {
    try late_subscriber_case(io, true);
    try late_subscriber_case(io, false);
}

test "stateful p2p actor live: a late subscriber receives the cached response after a verdict" {
    try run(late_subscriber);
}

/// The subscription ids a ready-queue `retain` predicate saw.
const Observed = struct {
    ids: [4]u64 = undefined,
    len: usize = 0,

    fn record(observed: *Observed, _: Request, subscriber: TestActor.Subscriber) bool {
        assert(observed.len < observed.ids.len);
        observed.ids[observed.len] = subscriber.id;
        observed.len += 1;
        return true;
    }
};

/// Registers a caller for `request` on an actor that is not running; returns the caller's
/// candidate receiver.
fn register_caller(
    io: Io,
    created: *TestActor.Created,
    engine_mailbox: *TestActor.Engine.Mailbox,
    request: Request,
) !mpsc.Receiver(sync_candidate) {
    const pair = try mpsc.channel(sync_candidate, gpa, io, 1);
    try created.actor.handle_mailbox_message(engine_mailbox, .{ .get_operations = .{
        .request = request,
        .response = pair.sender,
    } });
    return pair.receiver;
}

const sync_candidate = storage.qmdb.sync.source.Candidate(Response);

/// A config for an actor without a database that the test drives by hand.
fn idle_config(cluster: *const Cluster, control: Net.Control) TestActor.Cfg {
    return .{
        .peer_provider = cluster.oracle().manager(),
        .blocker = control,
        .database = null,
        .mailbox_size = 16,
        .me = cluster.peers[0],
        .fetch_timeout = .from_secs(5),
        .fetch_retry_delay = .from_millis(10),
        .max_serve_ops = 16,
        .priority_requests = false,
        .priority_responses = false,
    };
}

fn admission(io: Io) !void {
    var cluster: Cluster = undefined;
    try cluster.init(io, &.{1});
    defer cluster.deinit();
    const me = cluster.peers[0];
    const control = cluster.oracle().control(me);
    const connection = try control.register(0, p2p.Quota.per_second(100));
    var handler_pair = try actor_package.mailbox.new(TestActor.EngineMessage, gpa, io, 8);
    defer handler_pair.receiver.deinit();
    var handler: TestActor.Handler = .{ .gpa = gpa, .io = io, .sender = handler_pair.sender };
    defer handler.deinit();
    const engine_pair = try actor_package.mailbox.new(TestActor.Engine.Message, gpa, io, 8);
    var engine_mailbox: TestActor.Engine.Mailbox = .{ .gpa = gpa, .sender = engine_pair.sender };
    defer engine_mailbox.deinit();
    const scope = metrics.Scope.init(&cluster.nodes[0].registry);
    const engine = try TestActor.Engine.create(gpa, io, scope.child("resolver"), .{
        .peer_provider = cluster.oracle().manager(),
        .blocker = control,
        .consumer = handler,
        .producer = handler,
        .mailbox_size = 8,
        .me = me,
        .fetch_timeout = .from_secs(5),
        .fetch_retry_delay = .from_millis(10),
        .priority_requests = false,
        .priority_responses = false,
    }, engine_pair.receiver, connection.sender, connection.receiver);
    var engine_started = false;
    defer if (!engine_started) engine.destroy();
    var created = try TestActor.create(gpa, io, scope.child("actor"), idle_config(
        &cluster,
        control,
    ));
    defer created.actor.destroy();
    defer created.mailbox.deinit();
    const request: Request = .{ .operations = .{ .size = 1, .start = 0, .max_ops = 1 } };

    // Queue the fetch and its exact cancellation before the resolver starts.
    var canceled = try register_caller(io, &created, &engine_mailbox, request);
    canceled.deinit();
    try created.actor.next_work(&engine_mailbox);
    var replacement = try register_caller(io, &created, &engine_mailbox, request);
    var replacement_held = true;
    defer if (replacement_held) replacement.deinit();

    // This ready-queue predicate runs after both registrations and the cancellation.
    // Observing only the second id proves the canceled subscription was removed.
    var observed: Observed = .{};
    const predicate = resolver.Predicate(Request, TestActor.Subscriber).init(
        &observed,
        Observed.record,
    );
    _ = try engine_mailbox.retain(predicate);
    var task = try io.concurrent(TestActor.Engine.run, .{engine});
    engine_started = true;
    defer _ = task.cancel(io) catch {};
    for (0..1000) |_| {
        if (observed.len > 0) break;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    try io.sleep(.fromMilliseconds(5), .awake);
    try testing.expectEqual(@as(usize, 1), observed.len);
    try testing.expectEqual(created.actor.next_id - 1, observed.ids[0]);
    try testing.expectEqual(@as(i64, 1), created.actor.metrics.pending_requests.metric().get());

    replacement.deinit();
    replacement_held = false;
    try created.actor.next_work(&engine_mailbox);
    try testing.expectEqual(@as(i64, 0), created.actor.metrics.pending_requests.metric().get());
}

test "stateful p2p actor live: a cancellation before resolver admission keeps the replacement" {
    try run(admission);
}
