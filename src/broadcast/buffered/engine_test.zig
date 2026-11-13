//! Engine tests, ported from commonware `broadcast/src/buffered/mod.rs`, on the simulated
//! network and the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const broadcast_digested = @import("../digested.zig");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");

const engine_module = @import("engine.zig");
const ingress = @import("ingress.zig");
const TestMessage = @import("mocks.zig").TestMessage;

const metrics = runtime.telemetry.metrics;
const oneshot = utils.channel.oneshot;
const Key = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const TestEngine = engine_module.Engine(TestMessage, Net.Manager, Net.Control, Net);
const Mailbox = TestEngine.Mailbox;
const Item = broadcast_digested.Digested(TestMessage);
const Recipients = p2p.Recipients(Key);
const Feedback = p2p.Feedback;
const gpa = testing.allocator;

/// Number of messages to cache per sender.
const cache_size = 10;
/// Enough time to receive a cached message.
const a_jiffy_ms = 10;
/// Network latency of every link.
const network_speed_ms = 100;
/// Enough time for a message to propagate through the network.
const network_speed_with_buffer_ms = 200;
/// Default rate limit set high enough to not interfere with normal operation.
const test_quota = p2p.Quota.per_second(1_024);
const peers_max = 10;

fn sleep_ms(io: Io, ms: u64) !void {
    try io.sleep(.fromMilliseconds(@intCast(ms)), .awake);
}

fn item(content: []const u8) !Item {
    return Item.compute(gpa, try TestMessage.shared(gpa, content));
}

/// A simulated network with one registration per peer and the engines started on it.
const Sim = struct {
    io: Io,
    network: *Net,
    network_task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    registry: *metrics.Registry,
    peers: [peers_max]Key = undefined,
    count: usize,
    registrations: [peers_max]?Net.Registered = @splat(null),
    mailboxes: [peers_max]?Mailbox = @splat(null),
    engines: [peers_max]?Io.Future(TestEngine.Error!void) = @splat(null),

    const Options = struct {
        peers: usize,
        success_rate: f64 = 1.0,
        tracked_peer_sets: usize = 1,
        /// Track every peer as primary at id 0.
        track: bool = true,
    };

    /// Peers sorted by public key, all linked, each registered on channel 0.
    fn init(io: Io, options: Options) !*Sim {
        assert(options.peers <= peers_max);
        const network = try Net.init(gpa, io, .{
            .max_size = 1024 * 1024,
            .max_peers_per_set = options.peers,
            .disconnect_on_block = true,
            .tracked_peer_sets = options.tracked_peer_sets,
        });
        const sim = try gpa.create(Sim);
        const registry = try gpa.create(metrics.Registry);
        registry.* = .init(gpa);
        sim.* = .{
            .io = io,
            .network = network,
            .network_task = try io.concurrent(Net.run, .{network}),
            .registry = registry,
            .count = options.peers,
        };
        for (0..options.peers) |index| {
            sim.peers[index] = cryptography.ed25519.PrivateKey.from_seed(index).public_key();
        }
        std.sort.pdq(Key, sim.peers[0..sim.count], {}, Key.less_than);
        const oracle = network.oracle();
        for (sim.peers[0..sim.count], 0..) |peer, index| {
            sim.registrations[index] = try oracle.control(peer).register(0, test_quota);
        }
        const link: p2p.simulated.Link = .{
            .latency = utils.Duration.from_millis(network_speed_ms),
            .jitter = utils.Duration.from_millis(0),
            .success_rate = options.success_rate,
        };
        for (sim.peers[0..sim.count]) |from| {
            for (sim.peers[0..sim.count]) |to| {
                if (!from.eql(to)) try oracle.add_link(from, to, link);
            }
        }
        if (options.track) try sim.track(0, sim.peers[0..sim.count], &.{});
        return sim;
    }

    fn track(sim: *Sim, id: u64, primary: []const Key, secondary: []const Key) !void {
        const tracked: p2p.TrackedPeers(Key) = .{
            .primary = .init(try sorted(primary)),
            .secondary = .init(try sorted(secondary)),
        };
        defer gpa.free(tracked.primary.items);
        defer gpa.free(tracked.secondary.items);
        const feedback = sim.network.oracle().manager().track(id, tracked);
        try testing.expectEqual(Feedback.ok, feedback);
    }

    fn sorted(peers: []const Key) ![]Key {
        const copy = try gpa.dupe(Key, peers);
        std.sort.pdq(Key, copy, {}, Key.less_than);
        return copy;
    }

    fn config(sim: *const Sim, index: usize) TestEngine.Config {
        const peer = sim.peers[index];
        return .{
            .public_key = peer,
            .mailbox_size = 1024,
            .deque_size = cache_size,
            .priority = false,
            .codec_config = .full(),
            .peer_provider = sim.network.oracle().manager(),
            .blocker = sim.network.oracle().control(peer),
        };
    }

    /// Creates peer `index`'s engine without starting it.
    fn create(sim: *Sim, index: usize, engine_config: TestEngine.Config) !*TestEngine {
        const scope = metrics.Scope.init(sim.registry).child("peer")
            .with_attribute("public_key", sim.peers[index]);
        const created = try TestEngine.init(gpa, sim.io, &scope, engine_config);
        assert(sim.mailboxes[index] == null);
        sim.mailboxes[index] = created.mailbox;
        return created.engine;
    }

    /// Starts `engine` on peer `index`'s registration.
    fn start(sim: *Sim, index: usize, engine: *TestEngine) !void {
        const registered = sim.registrations[index].?;
        sim.registrations[index] = null;
        sim.engines[index] = try engine.start(registered.sender, registered.receiver);
    }

    fn spawn(sim: *Sim, index: usize) !void {
        try sim.start(index, try sim.create(index, sim.config(index)));
    }

    /// Spawns every peer's engine and lets each apply the initial peer set.
    fn spawn_all(sim: *Sim) !void {
        for (0..sim.count) |index| {
            if (sim.registrations[index] != null) try sim.spawn(index);
        }
        try sleep_ms(sim.io, a_jiffy_ms);
    }

    fn mailbox(sim: *Sim, index: usize) Mailbox {
        return sim.mailboxes[index].?;
    }

    /// Stops peer `index`'s engine (commonware `Handle::abort`).
    fn abort(sim: *Sim, index: usize) void {
        if (sim.engines[index]) |*future| {
            future.cancel(sim.io) catch |err| std.debug.panic("engine: {t}", .{err});
        }
        sim.engines[index] = null;
    }

    fn deinit(sim: *Sim) void {
        for (0..sim.count) |index| {
            sim.abort(index);
            if (sim.mailboxes[index]) |*value| value.deinit();
            if (sim.registrations[index]) |*value| value.deinit();
        }
        sim.network.close();
        sim.network_task.await(sim.io) catch |err| std.debug.panic("run: {t}", .{err});
        sim.network.deinit();
        sim.registry.deinit();
        gpa.destroy(sim.registry);
        gpa.destroy(sim);
    }
};

fn run_deterministic(seed: u64, comptime function: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = seed });
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
}

fn broadcast(mailbox: Mailbox, recipients: Recipients, message: Item) !Feedback {
    return mailbox.broadcast(recipients, message.clone());
}

fn expect_accepted(mailbox: Mailbox, recipients: Recipients, message: Item) !void {
    try testing.expect((try broadcast(mailbox, recipients, message)).accepted());
}

/// Whether `mailbox` returns `expected` for its digest (or nothing, when null).
fn expect_get(mailbox: Mailbox, digest: TestMessage.Digest, expected: ?Item) !void {
    var got = try mailbox.get(digest);
    defer if (got) |*value| value.deinit();
    if (expected) |want| {
        try testing.expect(got != null);
        try testing.expectEqualStrings(want.inner().content, got.?.inner().content);
    } else {
        try testing.expect(got == null);
    }
}

/// Subscribes and waits for the message.
fn expect_subscribe(mailbox: Mailbox, expected: Item) !void {
    var receiver = try mailbox.subscribe(expected.digest());
    defer receiver.deinit();
    var got = try receiver.recv();
    defer got.deinit();
    try testing.expectEqualStrings(expected.inner().content, got.inner().content);
}

/// Subscribes and waits up to `timeout_ms`; null on timeout (commonware `context.timeout`).
fn subscribe_timeout(io: Io, mailbox: Mailbox, digest: TestMessage.Digest, timeout_ms: u64) !?Item {
    var receiver = try mailbox.subscribe(digest);
    defer receiver.deinit();
    const Receiver = oneshot.Receiver(Item);
    const Outcome = union(enum) {
        received: oneshot.RecvError!Item,
        timeout: Io.Cancelable!void,
    };
    var buffer: [2]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);
    try select.concurrent(.received, Receiver.recv, .{&receiver});
    const duration: Io.Duration = .fromMilliseconds(@intCast(timeout_ms));
    select.concurrent(.timeout, Io.sleep, .{ io, duration, .awake }) catch |err| {
        select.cancelDiscard();
        return err;
    };
    const first = try select.await();
    while (select.cancel()) |rest| {
        if (rest == .received) if (rest.received) |value| value.discard() else |_| {};
    }
    return switch (first) {
        .received => |result| result catch null,
        .timeout => null,
    };
}

test "broadcast" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 4 });
            defer sim.deinit();
            try sim.spawn_all();

            // Send a single broadcast message from the first peer.
            var message = try item("hello world test message");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);
            try sleep_ms(io, 1_000);
            // Every peer received the message.
            for (0..sim.count) |index| try expect_subscribe(sim.mailbox(index), message);

            // Send another message; every peer that received it returns it.
            var again = try item("hello world again");
            defer again.deinit();
            try expect_accepted(sim.mailbox(0), .all, again);
            try sleep_ms(io, 1_000);
            var found: usize = 0;
            for (0..sim.count) |index| {
                var got = try sim.mailbox(index).get(again.digest()) orelse continue;
                defer got.deinit();
                try testing.expectEqualStrings(again.inner().content, got.inner().content);
                found += 1;
            }
            try testing.expect(found > 0);
        }
    }.run);
}

test "self retrieval" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 1 });
            defer sim.deinit();
            try sim.spawn_all();
            const mailbox = sim.mailbox(0);
            var m1 = try item("hello world");
            defer m1.deinit();

            // Retrieval before broadcasting finds nothing; a subscription waits.
            try expect_get(mailbox, m1.digest(), null);
            var before = try mailbox.subscribe(m1.digest());
            defer before.deinit();
            try expect_accepted(mailbox, .all, m1);
            var received = try before.recv();
            received.deinit();

            // After broadcasting, get and subscribe answer at once.
            try expect_get(mailbox, m1.digest(), m1);
            const start = Io.Clock.awake.now(io);
            try expect_subscribe(mailbox, m1);
            const elapsed = start.durationTo(Io.Clock.awake.now(io));
            try testing.expect(elapsed.toMilliseconds() < a_jiffy_ms);
        }
    }.run);
}

test "shared broadcast reuses message" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 1 });
            defer sim.deinit();
            try sim.spawn_all();
            var message = try item("shared broadcast");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);
            var cached = (try sim.mailbox(0).get(message.digest())).?;
            defer cached.deinit();
            try testing.expectEqual(message.inner(), cached.inner());
        }
    }.run);
}

test "packet loss" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 10, .success_rate = 0.1 });
            defer sim.deinit();
            try sim.spawn_all();
            var message = try item("hello world test message");
            defer message.deinit();
            // Retry until every peer has the message.
            for (0..100) |attempt| {
                try expect_accepted(sim.mailbox(0), .all, message);
                try sleep_ms(io, network_speed_with_buffer_ms);
                var all_received = true;
                for (0..sim.count) |index| {
                    const mailbox = sim.mailbox(index);
                    var got = try subscribe_timeout(io, mailbox, message.digest(), a_jiffy_ms);
                    if (got) |*value| value.deinit() else all_received = false;
                }
                if (all_received) {
                    try testing.expect(attempt > 0); // not received on the first try
                    return;
                }
            }
            return error.NotAllPeersReceived;
        }
    }.run);
}

test "get cached" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 2 });
            defer sim.deinit();
            try sim.spawn_all();
            var message = try item("cached message");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            // Get from cache (instant).
            const start = Io.Clock.awake.now(io);
            try expect_subscribe(sim.mailbox(1), message);
            const elapsed = start.durationTo(Io.Clock.awake.now(io));
            try testing.expect(elapsed.toMilliseconds() < a_jiffy_ms);
        }
    }.run);
}

test "get nonexistent" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 2 });
            defer sim.deinit();
            try sim.spawn_all();
            var message = try item("future message");
            defer message.deinit();
            var receiver = try sim.mailbox(0).subscribe(message.digest());
            defer receiver.deinit();
            // Two other requests are dropped.
            var dummy1 = try sim.mailbox(0).subscribe(message.digest());
            var dummy2 = try sim.mailbox(1).subscribe(message.digest());
            dummy1.deinit();
            dummy2.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            var received = try receiver.recv();
            defer received.deinit();
            try testing.expectEqualStrings(message.inner().content, received.inner().content);
        }
    }.run);
}

test "cache eviction single peer" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 2 });
            defer sim.deinit();
            try sim.spawn_all();
            var messages: [cache_size + 1]Item = undefined;
            for (&messages, 0..) |*message, index| {
                var buffer: [32]u8 = undefined;
                message.* = try item(try std.fmt.bufPrint(&buffer, "message {d}", .{index}));
            }
            defer for (&messages) |*message| message.deinit();
            for (messages) |message| try expect_accepted(sim.mailbox(0), .all, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            // Every message but the first is cached; the first times out.
            for (messages[1..]) |message| try expect_subscribe(sim.mailbox(1), message);
            const digest = messages[0].digest();
            const late = try subscribe_timeout(io, sim.mailbox(1), digest, a_jiffy_ms);
            try testing.expect(late == null);
        }
    }.run);
}

/// Broadcasts `count` fresh messages named `<prefix><index>` from `mailbox`.
fn broadcast_spam(mailbox: Mailbox, prefix: []const u8, count: usize) !void {
    for (0..count) |index| {
        var buffer: [32]u8 = undefined;
        var spam = try item(try std.fmt.bufPrint(&buffer, "{s}{d}", .{ prefix, index }));
        defer spam.deinit();
        try expect_accepted(mailbox, .all, spam);
    }
}

test "cache eviction multi peer" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 3 });
            defer sim.deinit();
            try sim.spawn_all();
            var m1 = try item("message M1");
            defer m1.deinit();
            // M1 enters A's and C's deques in B's engine.
            try expect_accepted(sim.mailbox(0), .all, m1);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_accepted(sim.mailbox(2), .all, m1);
            try sleep_ms(io, network_speed_with_buffer_ms);

            // A evicts M1 from its deque; C still holds it.
            try broadcast_spam(sim.mailbox(0), "A", cache_size);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_subscribe(sim.mailbox(1), m1);

            // C evicts M1 too; B no longer has it.
            try broadcast_spam(sim.mailbox(2), "C", cache_size);
            try sleep_ms(io, network_speed_with_buffer_ms);
            const evicted = try subscribe_timeout(io, sim.mailbox(1), m1.digest(), a_jiffy_ms);
            try testing.expect(evicted == null);
        }
    }.run);
}

test "selective recipients" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 4 });
            defer sim.deinit();
            try sim.spawn_all();
            var message = try item("selective-broadcast");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .{ .one = sim.peers[1] }, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            // Only the target peer has the message.
            try expect_get(sim.mailbox(1), message.digest(), message);
            try expect_get(sim.mailbox(2), message.digest(), null);
        }
    }.run);
}

test "overflow coalesces duplicate broadcasts" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const duplicates = 16;
            const sim = try Sim.init(io, .{ .peers = 3 });
            defer sim.deinit();
            // Keep raw registrations for both recipients to count the copies they get.
            var first = sim.registrations[1].?;
            var second = sim.registrations[2].?;
            sim.registrations[1] = null;
            sim.registrations[2] = null;
            defer first.deinit();
            defer second.deinit();

            // Give the sender a one-slot inbox and fill it before its engine starts.
            var config = sim.config(0);
            config.mailbox_size = 1;
            const engine = try sim.create(0, config);
            var message = try item("coalesced");
            defer message.deinit();
            var subscription = try sim.mailbox(0).subscribe(message.digest());
            defer subscription.deinit();
            for (0..duplicates) |_| {
                try expect_accepted(sim.mailbox(0), .{ .one = sim.peers[1] }, message);
            }
            try expect_accepted(sim.mailbox(0), .{ .one = sim.peers[2] }, message);

            // The coalesced broadcast resolves the subscription and reaches each recipient once.
            try sim.start(0, engine);
            var received = try subscription.recv();
            received.deinit();
            const encoded = try codec.encode(TestMessage, gpa, message.inner().*);
            defer gpa.free(encoded);
            for ([_]*Net.Receiver{ &first.receiver, &second.receiver }) |receiver| {
                var raw = try receiver.recv();
                defer raw.deinit();
                try testing.expect(raw.peer.eql(sim.peers[0]));
                try testing.expectEqualSlices(u8, encoded, raw.payload);
            }
            try sleep_ms(io, network_speed_with_buffer_ms);
            for ([_]*Net.Receiver{ &first.receiver, &second.receiver }) |receiver| {
                try testing.expectError(error.Empty, receiver.try_recv());
            }
        }
    }.run);
}

test "ref count across peers" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 3 });
            defer sim.deinit();
            try sim.spawn_all();
            var dup = try item("dup");
            defer dup.deinit();
            // Broadcast from both senders; the observer has it.
            try expect_accepted(sim.mailbox(0), .all, dup);
            try expect_accepted(sim.mailbox(1), .all, dup);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(2), dup.digest(), dup);

            // Evict from p0's deque only.
            try broadcast_spam(sim.mailbox(0), "p0-", cache_size);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(2), dup.digest(), dup);

            // Evict from p1's deque as well.
            try broadcast_spam(sim.mailbox(1), "p1-", cache_size);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(2), dup.digest(), null);
        }
    }.run);
}

fn retrieval_hash(seed: u64) ![32]u8 {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = seed });
    defer runner.deinit();
    return try (try runner.start(struct {
        fn run(io: Io) ![32]u8 {
            const sim = try Sim.init(io, .{ .peers = 1 });
            defer sim.deinit();
            try sim.spawn_all();
            var messages = [_]Item{
                try item("content-1"),
                try item("content-2"),
                try item("content-3"),
            };
            defer for (&messages) |*message| message.deinit();
            for (messages) |message| try expect_accepted(sim.mailbox(0), .all, message);
            var hasher = cryptography.Sha256.init();
            for (messages) |message| {
                var value = try sim.mailbox(0).get(message.digest()) orelse continue;
                defer value.deinit();
                hasher.update(value.inner().content);
            }
            return hasher.finalize().bytes;
        }
    }.run, .{runner.io()}));
}

test "deterministic retrieval" {
    for (0..10) |seed| {
        const first = try retrieval_hash(seed);
        const second = try retrieval_hash(seed);
        try testing.expectEqualSlices(u8, &first, &second);
    }
}

test "invalid message blocks peer" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 3 });
            defer sim.deinit();
            const victim = sim.peers[2];
            // The attacker sends directly so malformed bytes bypass message encoding.
            var attacker = sim.registrations[0].?;
            sim.registrations[0] = null;
            defer attacker.deinit();
            try sim.spawn_all();

            // Malformed bytes block the attacker at the victim.
            const sent = try attacker.sender.send(.{ .one = victim }, &.{&.{0xFF}}, false);
            defer gpa.free(sent);
            try testing.expectEqual(@as(usize, 1), sent.len);
            try testing.expect(sent[0].eql(victim));
            try sleep_ms(io, network_speed_with_buffer_ms);

            // A later well-formed message from the blocked attacker is never buffered.
            var from_attacker = try item("from-blocked-peer");
            defer from_attacker.deinit();
            const encoded = try codec.encode(TestMessage, gpa, from_attacker.inner().*);
            defer gpa.free(encoded);
            gpa.free(try attacker.sender.send(.{ .one = victim }, &.{encoded}, false));

            // Valid traffic from an honest peer still flows.
            var from_honest = try item("from-honest-peer");
            defer from_honest.deinit();
            try expect_accepted(sim.mailbox(1), .{ .one = victim }, from_honest);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_subscribe(sim.mailbox(2), from_honest);
            try expect_get(sim.mailbox(2), from_attacker.digest(), null);
        }
    }.run);
}

/// The values of every `waiters` gauge sample in the registry's output.
fn waiter_values(sim: *Sim, values: []i64) ![]i64 {
    const text = try sim.registry.encode(gpa);
    defer gpa.free(text);
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "#")) continue;
        if (std.mem.indexOf(u8, line, "_waiters") == null) continue;
        const space = std.mem.lastIndexOfScalar(u8, line, ' ').?;
        values[count] = try std.fmt.parseInt(i64, line[space + 1 ..], 10);
        count += 1;
    }
    return values[0..count];
}

test "dropped waiters for missing digest are cleaned up" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 1 });
            defer sim.deinit();
            try sim.spawn(0);
            const mailbox = sim.mailbox(0);
            // Two subscribers wait for a digest that never arrives.
            var missing = try item("never-arrives");
            defer missing.deinit();
            var rx1 = try mailbox.subscribe(missing.digest());
            var rx2 = try mailbox.subscribe(missing.digest());

            // Once processed, the waiters show in the metrics.
            var before_cleanup = try item("before-cleanup");
            defer before_cleanup.deinit();
            try expect_get(mailbox, before_cleanup.digest(), null);
            try sleep_ms(io, a_jiffy_ms);
            var buffer: [4]i64 = undefined;
            const before = try waiter_values(sim, &buffer);
            try testing.expect(before.len > 0);
            try testing.expect(std.mem.max(i64, before) > 0);

            // Cancel both subscriptions, then trigger another mailbox event.
            rx1.deinit();
            rx2.deinit();
            var after_cleanup = try item("after-cleanup");
            defer after_cleanup.deinit();
            try expect_get(mailbox, after_cleanup.digest(), null);
            try sleep_ms(io, a_jiffy_ms);
            const after = try waiter_values(sim, &buffer);
            try testing.expect(after.len > 0);
            for (after) |value| try testing.expectEqual(@as(i64, 0), value);
        }
    }.run);
}

test "operations after shutdown do not panic" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 2 });
            defer sim.deinit();
            try sim.spawn_all();
            var message = try item("test message");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);

            // Abort every engine.
            for (0..sim.count) |index| sim.abort(index);
            try sleep_ms(io, 100);

            const mailbox = sim.mailbox(0);
            try testing.expectEqual(Feedback.closed, try broadcast(mailbox, .all, message));
            var receiver = try mailbox.subscribe(message.digest());
            defer receiver.deinit();
            try testing.expectError(error.Closed, receiver.recv());
            try expect_get(mailbox, message.digest(), null);
        }
    }.run);
}

fn clean_shutdown(seed: u64) !void {
    try run_deterministic(seed, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 2 });
            defer sim.deinit();
            try sim.spawn_all();
            try sleep_ms(io, 100);
            var message = try item("test message");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(1), message.digest(), message);
            // Aborting frees each engine and everything it owns (the allocator checks).
            for (0..sim.count) |index| sim.abort(index);
            try sleep_ms(io, 100);
            try testing.expectEqual(Feedback.closed, try broadcast(sim.mailbox(1), .all, message));
        }
    }.run);
}

test "clean shutdown" {
    for (0..25) |seed| try clean_shutdown(seed);
}

test "closed network receiver stops engine" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 1 });
            defer sim.deinit();
            // Registering the channel again closes the receiver the engine starts with.
            const control = sim.network.oracle().control(sim.peers[0]);
            var replacement = try control.register(0, test_quota);
            defer replacement.deinit();
            const engine = try sim.create(0, sim.config(0));
            try sim.start(0, engine);
            // The engine stops once its ingress reports the closed receiver.
            try sim.engines[0].?.await(io);
            sim.engines[0] = null;

            var message = try item("after-stop");
            defer message.deinit();
            try testing.expectEqual(Feedback.closed, try broadcast(sim.mailbox(0), .all, message));
            try expect_get(sim.mailbox(0), message.digest(), null);
        }
    }.run);
}

test "peer set update evicts disconnected peer buffers" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 3 });
            defer sim.deinit();
            try sim.spawn_all();
            var message = try item("eviction-test");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(1), message.digest(), message);

            // A peer set update excluding A evicts A's deque.
            try sim.track(1, sim.peers[1..3], &.{});
            try sleep_ms(io, a_jiffy_ms);
            try expect_get(sim.mailbox(1), message.digest(), null);
        }
    }.run);
}

test "peer set update keeps peers in overlap until their set ages out" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 3, .tracked_peer_sets = 2 });
            defer sim.deinit();
            try sim.spawn_all();
            var message = try item("eviction-latest-test");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(1), message.digest(), message);

            // Sets 0 and 1 are both tracked, so A is still a primary and keeps its deque.
            try sim.track(1, sim.peers[1..3], &.{});
            try sleep_ms(io, a_jiffy_ms);
            try expect_get(sim.mailbox(1), message.digest(), message);

            // A still buffers fresh messages through the overlap window.
            var fresh = try item("overlap-latest-test");
            defer fresh.deinit();
            try expect_accepted(sim.mailbox(0), .all, fresh);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(1), fresh.digest(), fresh);

            // Tracking another set without A ages set 0 out, evicting A's deque.
            try sim.track(2, sim.peers[1..3], &.{});
            try sleep_ms(io, a_jiffy_ms);
            try expect_get(sim.mailbox(1), message.digest(), null);
            try expect_get(sim.mailbox(1), fresh.digest(), null);
        }
    }.run);
}

test "initial latest peer set blocks sender not in latest primary" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 3, .track = false });
            defer sim.deinit();
            // A is only a secondary, so its messages are ineligible for caching.
            try sim.track(0, sim.peers[1..3], sim.peers[0..1]);
            try sim.spawn_all();
            var message = try item("startup-latest-primary-only");
            defer message.deinit();
            // Accepted locally; cache policy is separate.
            try expect_accepted(sim.mailbox(0), .all, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(0), message.digest(), null);
            try expect_get(sim.mailbox(1), message.digest(), null);
        }
    }.run);
}

test "broadcast queued before start respects initial latest primary" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 1 });
            defer sim.deinit();
            const engine = try sim.create(0, sim.config(0));
            // Queue a local broadcast before the engine applies its initial peer set.
            var message = try item("queued-before-start");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);
            try sim.start(0, engine);
            try expect_get(sim.mailbox(0), message.digest(), message);
        }
    }.run);
}

test "engine starts before initial peer set and delivers after tracking" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 2, .track = false });
            defer sim.deinit();
            try sim.spawn_all();
            // Without a primary set, neither local nor remote caches admit the message.
            var before = try item("before-tracking");
            defer before.deinit();
            try expect_accepted(sim.mailbox(0), .all, before);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(0), before.digest(), null);
            try expect_get(sim.mailbox(1), before.digest(), null);

            // Make both peers primary members, then broadcast again.
            try sim.track(0, sim.peers[0..2], &.{});
            try sleep_ms(io, a_jiffy_ms);
            var after = try item("after-tracking");
            defer after.deinit();
            try expect_accepted(sim.mailbox(0), .all, after);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(1), after.digest(), after);
        }
    }.run);
}

test "peer set update preserves shared messages" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, .{ .peers = 3 });
            defer sim.deinit();
            try sim.spawn_all();
            // A and C broadcast the same message: B holds it in both deques.
            var message = try item("shared-msg");
            defer message.deinit();
            try expect_accepted(sim.mailbox(0), .all, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_accepted(sim.mailbox(2), .all, message);
            try sleep_ms(io, network_speed_with_buffer_ms);
            try expect_get(sim.mailbox(1), message.digest(), message);

            // Evicting A keeps the message, which C's deque still holds.
            try sim.track(1, sim.peers[1..3], &.{});
            try sleep_ms(io, a_jiffy_ms);
            try expect_get(sim.mailbox(1), message.digest(), message);
        }
    }.run);
}
