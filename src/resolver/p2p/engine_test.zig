//! Tests for the p2p resolver engine, ported from commonware `resolver/src/p2p/mod.rs`, on
//! p2p's simulated network and the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const p2p = @import("p2p");
const cryptography = @import("cryptography");
const resolver = @import("../root.zig");
const engine_mod = @import("engine.zig");
const fetcher_mod = @import("fetcher.zig");
const MockKey = @import("mocks/key.zig").Key;
const MockConsumer = @import("mocks/consumer.zig").Consumer;
const MockProducer = @import("mocks/producer.zig").Producer;
const metrics = runtime.telemetry.metrics;

const gpa = testing.allocator;
const Duration = utils.Duration;
pub const PublicKey = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(PublicKey);
const Tracked = p2p.TrackedPeers(PublicKey);
pub const Consumer = MockConsumer(MockKey, void);
pub const Producer = MockProducer(MockKey);
/// The engine over consumer `C` and producer `Pro` on the simulated network.
pub fn EngineOf(comptime C: type, comptime Pro: type) type {
    return engine_mod.Engine(engine_mod.Params(
        PublicKey,
        Net.Manager,
        Net.Control,
        C,
        Pro,
        Net.Sender,
        Net.Receiver,
    ));
}
pub const Engine = EngineOf(Consumer, Producer);
pub const Mailbox = Engine.Mailbox;
const Fetch = resolver.Fetch(MockKey, void);
const Predicate = resolver.Predicate(MockKey, void);

pub const mailbox_size: u32 = 1024;
pub const rate_limit: u32 = 10;
pub const timeout = Duration.from_millis(400);
pub const fetch_retry_delay = Duration.from_millis(100);
pub const link: p2p.simulated.Link = .{
    .latency = Duration.from_millis(10),
    .jitter = Duration.from_millis(1),
    .success_rate = 1.0,
};
pub const link_unreliable: p2p.simulated.Link = .{
    .latency = Duration.from_millis(10),
    .jitter = Duration.from_millis(1),
    .success_rate = 0.5,
};

pub const peers_max = 8;

/// A simulated network with registered peers, the engines spawned on it, and the consumers
/// and producers they use. `deinit` stops the engines, then the network.
pub fn SetupWith(comptime C: type) type {
    return SetupOf(C, Producer);
}

/// `SetupWith` over producer `Pro` (`init(gpa, io)`, `insert(key, value)`, `deinit`).
pub fn SetupOf(comptime C: type, comptime Pro: type) type {
    return struct {
        const Self = @This();
        pub const EngineT = EngineOf(C, Pro);
        pub const MailboxT = EngineT.Mailbox;

        io: Io,
        network: *Net,
        task: Io.Future((Io.Cancelable || Allocator.Error)!void),
        registry: metrics.Registry,
        peers: [peers_max]PublicKey = undefined,
        peer_count: usize = 0,
        connections: [peers_max]?Net.Registered = @splat(null),
        engines: [peers_max]?EngineT.Spawned = @splat(null),
        /// Engines aborted with `stop`; their mailboxes stay usable (sends report closed).
        stopped: [peers_max]bool = @splat(false),
        consumers: std.ArrayList(C) = .empty,
        producers: std.ArrayList(Pro) = .empty,

        pub const Options = struct {
            quota: p2p.Quota = p2p.Quota.per_second(rate_limit),
            tracked_peer_sets: usize = 3,
            /// Track every peer at id 0 before any engine starts.
            track: bool = true,
            /// Sort peers by public key (as some commonware tests do).
            sort: bool = false,
        };

        pub fn init(io: Io, seeds: []const u64, options: Options) !*Self {
            assert(seeds.len > 0 and seeds.len <= peers_max);
            const network = try Net.init(gpa, io, .{
                .max_size = 1024 * 1024,
                .max_peers_per_set = seeds.len,
                .disconnect_on_block = true,
                .tracked_peer_sets = options.tracked_peer_sets,
            });
            errdefer network.deinit();
            const setup = try gpa.create(Self);
            errdefer gpa.destroy(setup);
            setup.* = .{
                .io = io,
                .network = network,
                .task = try io.concurrent(Net.run, .{network}),
                .registry = .init(gpa),
            };
            for (seeds, 0..) |seed, index| setup.peers[index] = key_of(seed);
            setup.peer_count = seeds.len;
            if (options.sort) Tracked.PeerSet.sort(setup.peers[0..seeds.len]);
            if (options.track) try setup.track(0, setup.peer_list());
            for (setup.peer_list(), 0..) |peer, index| {
                const control = setup.oracle().control(peer);
                setup.connections[index] = try control.register(0, options.quota);
            }
            return setup;
        }

        pub fn deinit(setup: *Self) void {
            for (&setup.engines, setup.stopped) |*slot, stopped| {
                const spawned = &(slot.* orelse continue);
                spawned.mailbox.deinit();
                if (!stopped) {
                    spawned.future.await(setup.io) catch |err| {
                        std.debug.panic("engine: {t}", .{err});
                    };
                }
                slot.* = null;
            }
            for (&setup.connections) |*slot| if (slot.*) |*connection| connection.deinit();
            setup.network.close();
            setup.task.await(setup.io) catch |err| std.debug.panic("network: {t}", .{err});
            setup.network.deinit();
            for (setup.consumers.items) |item| item.deinit();
            setup.consumers.deinit(gpa);
            for (setup.producers.items) |item| item.deinit();
            setup.producers.deinit(gpa);
            setup.registry.deinit();
            gpa.destroy(setup);
        }

        pub fn peer_list(setup: *const Self) []const PublicKey {
            return setup.peers[0..setup.peer_count];
        }

        pub fn oracle(setup: *const Self) Net.Oracle {
            return setup.network.oracle();
        }

        /// Tracks `peers` network-wide at `id`.
        pub fn track(setup: *const Self, id: u64, peers: []const PublicKey) !void {
            const sorted = try gpa.dupe(PublicKey, peers);
            defer gpa.free(sorted);
            Tracked.PeerSet.sort(sorted);
            const feedback = setup.oracle().manager().track(id, .init_primary(.init(sorted)));
            try testing.expectEqual(p2p.Feedback.ok, feedback);
        }

        /// Tracks the peers at indices `primary` and `secondary` network-wide at `id`.
        pub fn track_roles(
            setup: *const Self,
            id: u64,
            primary: []const usize,
            secondary: []const usize,
        ) !void {
            var primary_keys: [peers_max]PublicKey = undefined;
            var secondary_keys: [peers_max]PublicKey = undefined;
            for (primary, 0..) |index, slot| primary_keys[slot] = setup.peers[index];
            for (secondary, 0..) |index, slot| secondary_keys[slot] = setup.peers[index];
            const primary_set = primary_keys[0..primary.len];
            const secondary_set = secondary_keys[0..secondary.len];
            Tracked.PeerSet.sort(primary_set);
            Tracked.PeerSet.sort(secondary_set);
            const tracked: Tracked = .{
                .primary = .init(primary_set),
                .secondary = .init(secondary_set),
            };
            const feedback = setup.oracle().manager().track(id, tracked);
            try testing.expectEqual(p2p.Feedback.ok, feedback);
        }

        /// Adds links both ways between peers `from` and `to`.
        pub fn add_link(
            setup: *const Self,
            value: p2p.simulated.Link,
            from: usize,
            to: usize,
        ) !void {
            const a = setup.peers[from];
            const b = setup.peers[to];
            try setup.oracle().add_link(a, b, value);
            try setup.oracle().add_link(b, a, value);
        }

        /// A consumer owned by the setup.
        pub fn make_consumer(setup: *Self) !C {
            const value = try C.init(gpa, setup.io);
            errdefer value.deinit();
            try setup.consumers.append(gpa, value);
            return value;
        }

        /// A producer owned by the setup, serving `entries`.
        pub fn make_producer(setup: *Self, entries: []const struct { u8, []const u8 }) !Pro {
            const value = try Pro.init(gpa, setup.io);
            errdefer value.deinit();
            try setup.producers.append(gpa, value);
            for (entries) |entry| try value.insert(.init(entry[0]), entry[1]);
            return value;
        }

        /// Spawns peer `index`'s engine on its registered channel; returns its mailbox.
        pub fn spawn(
            setup: *Self,
            index: usize,
            consumer_value: C,
            producer_value: Pro,
        ) !*MailboxT {
            const me = setup.peers[index];
            const connection = setup.connections[index].?;
            setup.connections[index] = null;
            const scope = metrics.Scope.init(&setup.registry).child("actor")
                .with_attribute("peer", me);
            const control = setup.oracle().control(me);
            setup.engines[index] = try EngineT.spawn(gpa, setup.io, scope, .{
                .peer_provider = setup.oracle().manager(),
                .blocker = control,
                .consumer = consumer_value,
                .producer = producer_value,
                .mailbox_size = mailbox_size,
                .me = me,
                .fetch_timeout = timeout,
                .fetch_retry_delay = fetch_retry_delay,
                .priority_requests = false,
                .priority_responses = false,
            }, connection.sender, connection.receiver);
            return &setup.engines[index].?.mailbox;
        }

        /// Aborts peer `index`'s engine (commonware `Handle::abort`): its task is canceled
        /// and the engine frees everything it owns.
        pub fn stop(setup: *Self, index: usize) void {
            const spawned = &setup.engines[index].?;
            assert(!setup.stopped[index]);
            spawned.future.cancel(setup.io) catch {};
            setup.stopped[index] = true;
        }

        pub fn sleep(setup: *const Self, duration: Duration) !void {
            const nanos: i96 = @intCast(duration.as_nanos());
            try setup.io.sleep(.fromNanoseconds(nanos), .real);
        }

        /// The encoded metrics (caller frees).
        pub fn encode(setup: *Self) ![]u8 {
            return metrics.Scope.init(&setup.registry).encode(gpa);
        }

        /// Waits until `blocker` blocks `blocked`.
        pub fn wait_for_blocked(setup: *Self, blocker: usize, blocked: usize) !void {
            // Bounded by the runner's timeout.
            while (true) {
                const pairs = try setup.oracle().blocked(gpa);
                defer gpa.free(pairs);
                for (pairs) |pair| {
                    const by = pair.origin.order(setup.peers[blocker]) == .eq;
                    if (by and pair.recipient.order(setup.peers[blocked]) == .eq) return;
                }
                try setup.sleep(Duration.from_millis(10));
            }
        }
    };
}

pub const Setup = SetupWith(Consumer);

pub fn key_of(seed: u64) PublicKey {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

pub fn key(value: u8) MockKey {
    return .init(value);
}

/// Runs `body` on a deterministic runtime that fails after `timeout_s` simulated seconds.
pub fn run(timeout_s: ?u64, comptime body: fn (Io) anyerror!void) !void {
    const timeout_ns: ?u64 = if (timeout_s) |seconds| seconds * std.time.ns_per_s else null;
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .timeout_ns = timeout_ns });
    defer runner.deinit();
    try try runner.start(body, .{runner.io()});
}

pub fn fetch(mailbox: anytype, value: u8) !void {
    _ = try mailbox.fetch(Fetch.from_key(key(value)));
}

pub fn retain_except(mailbox: anytype, value: u8) !void {
    const predicate = Predicate.init(value, struct {
        fn keep(canceled: u8, item: MockKey, _: void) bool {
            return item.value != canceled;
        }
    }.keep);
    _ = try mailbox.retain(predicate);
}

/// Waits for the consumer's next delivery and checks it.
pub fn expect_event(consumer: Consumer, value: u8, data: []const u8) !void {
    var event = try consumer.next_event();
    defer event.deinit(gpa);
    try testing.expectEqual(key(value), event.key);
    try testing.expectEqualStrings(data, event.value);
}

/// Waits `ms` and checks the consumer received nothing.
pub fn expect_no_event(setup: *Setup, consumer: Consumer, ms: u64) !void {
    try setup.sleep(Duration.from_millis(ms));
    if (consumer.try_event()) |event| {
        var owned = event;
        owned.deinit(gpa);
        return error.UnexpectedEvent;
    }
}

test "fetch success" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 2, "data for key 2" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            try fetch(mailbox1, 2);
            try expect_event(consumer, 2, "data for key 2");
        }
    }.body);
}

test "retain drops fetch" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{1}, .{});
            defer setup.deinit();
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            try fetch(mailbox1, 3);
            try retain_except(mailbox1, 3);
            try expect_no_event(setup, consumer, 100);
        }
    }.body);
}

test "peer no data" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            _ = try setup.spawn(1, try setup.make_consumer(), try setup.make_producer(&.{}));
            const prod3 = try setup.make_producer(&.{.{ 3, "data for key 3" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);

            try fetch(mailbox1, 3);
            try expect_event(consumer, 3, "data for key 3");
        }
    }.body);
}

test "no peers available" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{1}, .{});
            defer setup.deinit();
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            try fetch(mailbox1, 4);
            try setup.sleep(Duration.from_secs(5));
            // With no peers, no event arrives.
            try expect_no_event(setup, consumer, 100);
        }
    }.body);
}

test "fetch before initial peer set waits for update" {
    try run(10, struct {
        fn body(io: Io) !void {
            const options: Setup.Options = .{
                .tracked_peer_sets = 1,
                .track = false,
                .sort = true,
            };
            const setup = try Setup.init(io, &.{ 1, 2 }, options);
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 2, "data for key 2" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            try fetch(mailbox1, 2);
            try expect_no_event(setup, consumer, 200);
            try setup.track(0, setup.peer_list());
            try expect_event(consumer, 2, "data for key 2");
        }
    }.body);
}

test "concurrent fetch requests" {
    try run(null, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, .{});
            defer setup.deinit();
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 2, "data for key 2" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            const prod3 = try setup.make_producer(&.{.{ 3, "data for key 3" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);

            // Choppy links between the requester and the two producers.
            try setup.add_link(link_unreliable, 0, 1);
            try setup.add_link(link_unreliable, 0, 2);

            // Repeat so the requester tries both of its peers.
            for (0..10) |_| {
                try fetch(mailbox1, 2);
                try fetch(mailbox1, 3);
                var found: [2]bool = @splat(false);
                for (0..2) |_| {
                    var event = try consumer.next_event();
                    defer event.deinit(gpa);
                    const expected: []const u8 =
                        if (event.key.value == 2) "data for key 2" else "data for key 3";
                    try testing.expect(event.key.value == 2 or event.key.value == 3);
                    try testing.expectEqualStrings(expected, event.value);
                    found[event.key.value - 2] = true;
                }
                try testing.expect(found[0] and found[1]);
            }
        }
    }.body);
}

test "retain drops key" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 6, "data for key 6" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            // Pruning before the fetch has no effect.
            try retain_except(mailbox1, 6);
            try expect_no_event(setup, consumer, 100);
            try fetch(mailbox1, 6);
            try expect_event(consumer, 6, "data for key 6");
            // Pruning after delivery has no effect.
            try retain_except(mailbox1, 6);
            try expect_no_event(setup, consumer, 100);
            // A pruned fetch delivers nothing.
            try fetch(mailbox1, 7);
            try retain_except(mailbox1, 7);
            try expect_no_event(setup, consumer, 100);
        }
    }.body);
}

test "blocking peer" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            try setup.add_link(link, 1, 2);
            const prod2 = try setup.make_producer(&.{
                .{ 1, "invalid for A" },
                .{ 2, "valid for B" },
            });
            const prod3 = try setup.make_producer(&.{.{ 1, "valid for A" }});
            const consumer = try setup.make_consumer();
            try consumer.add_expected(key(1), "valid for A");
            try consumer.add_expected(key(2), "valid for B");
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);

            // Fetch key A repeatedly so peer 2 is blocked.
            for (0..20) |_| {
                try fetch(mailbox1, 1);
                try expect_event(consumer, 1, "valid for A");
            }

            // Key B's only source is blocked, so it never arrives.
            try fetch(mailbox1, 2);
            try setup.sleep(Duration.from_secs(5));
            try expect_no_event(setup, consumer, 100);
            try retain_except(mailbox1, 2);

            const blocked = try setup.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(@as(usize, 1), blocked.len);
            try testing.expect(blocked[0].origin.order(setup.peers[0]) == .eq);
            try testing.expect(blocked[0].recipient.order(setup.peers[1]) == .eq);
        }
    }.body);
}

test "duplicate fetch key" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 5, "data for key 5" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            try fetch(mailbox1, 5);
            try fetch(mailbox1, 5);
            try expect_event(consumer, 5, "data for key 5");
            // The duplicate fetch produces no second delivery.
            try expect_no_event(setup, consumer, 500);
        }
    }.body);
}

test "changing peer sets" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 1, "data from peer 2" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            try fetch(mailbox1, 1);
            try expect_event(consumer, 1, "data from peer 2");

            // Peer 3 starts serving later.
            const prod3 = try setup.make_producer(&.{.{ 2, "data from peer 3" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);
            try setup.sleep(Duration.from_millis(200));
            try fetch(mailbox1, 2);
            try expect_event(consumer, 2, "data from peer 3");
        }
    }.body);
}

/// The sum of `name`'s samples whose labels carry `status="<status>"`.
pub fn status_total(text: []const u8, name: []const u8, status: []const u8) !u64 {
    var buffer: [64]u8 = undefined;
    const label = try std.fmt.bufPrint(&buffer, "status=\"{s}\"", .{status});
    var samples = metrics.metric_samples(text, name);
    var total: u64 = 0;
    while (samples.next()) |sample| {
        if (std.mem.indexOf(u8, sample.labels, label) == null) continue;
        total += try std.fmt.parseInt(u64, sample.value, 10);
    }
    return total;
}

pub fn fetch_success_total(setup: *Setup) !u64 {
    const text = try setup.encode();
    defer gpa.free(text);
    return status_total(text, "actor_fetch_total", "Success");
}

/// Expects `expected` successful fetches. The mock consumer records an event before the engine
/// reads its verdict (a separate task here, the same poll in commonware), so this lets the
/// engine run for up to 10ms of simulated time first.
pub fn expect_success_total(setup: *Setup, expected: u64) !void {
    for (0..10) |_| {
        if (try fetch_success_total(setup) == expected) return;
        try setup.sleep(Duration.from_millis(1));
    }
    try testing.expectEqual(expected, try fetch_success_total(setup));
}

pub fn fetch_targeted(
    setup: *const Setup,
    mailbox: *Mailbox,
    value: u8,
    targets: []const usize,
) !void {
    var peers: [peers_max]PublicKey = undefined;
    for (targets, 0..) |target, index| peers[index] = setup.peers[target];
    _ = try mailbox.fetch_targeted(Fetch.from_key(key(value)), peers[0..targets.len]);
}

test "fetch targeted" {
    try run(10, struct {
        fn body(io: Io) !void {
            // Both servers stay reachable so the healthy non-target could answer a fallback.
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            // The target serves invalid data, while the non-target holds a valid copy.
            const consumer = try setup.make_consumer();
            try consumer.add_expected(key(1), "valid data");
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 1, "invalid data" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            const prod3 = try setup.make_producer(&.{.{ 1, "valid data" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);
            try setup.sleep(Duration.from_millis(100));

            // Target only peer 2 and wait for its invalid response to get it blocked.
            try fetch_targeted(setup, mailbox1, 1, &.{1});
            try setup.wait_for_blocked(0, 1);
            const blocked = try setup.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(@as(usize, 1), blocked.len);

            // The healthy non-target stays unused while the only target is blocked.
            try expect_no_event(setup, consumer, 1000);
            try expect_success_total(setup, 0);

            // Adding peer 3 as a target lets the fetch succeed, exactly once.
            try fetch_targeted(setup, mailbox1, 1, &.{2});
            try expect_event(consumer, 1, "valid data");
            try expect_success_total(setup, 1);
        }
    }.body);
}

test "fetch targeted no fallback" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3, 4 }, .{});
            defer setup.deinit();
            for (1..4) |peer| try setup.add_link(link, 0, peer);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            _ = try setup.spawn(1, try setup.make_consumer(), try setup.make_producer(&.{}));
            _ = try setup.spawn(2, try setup.make_consumer(), try setup.make_producer(&.{}));
            const prod4 = try setup.make_producer(&.{.{ 1, "data from peer 4" }});
            _ = try setup.spawn(3, try setup.make_consumer(), prod4);
            try setup.sleep(Duration.from_millis(100));

            // Neither target has the data, and peer 4 is never tried.
            try fetch_targeted(setup, mailbox1, 1, &.{ 1, 2 });
            try expect_no_event(setup, consumer, 3000);
        }
    }.body);
}

test "fetch all targeted" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3, 4 }, .{});
            defer setup.deinit();
            for (1..4) |peer| try setup.add_link(link, 0, peer);
            const consumer = try setup.make_consumer();
            try consumer.add_expected(key(1), "data for key 1");
            try consumer.add_expected(key(2), "data for key 2");
            try consumer.add_expected(key(3), "data for key 3");
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            const prod3 = try setup.make_producer(&.{.{ 3, "data for key 3" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);
            const prod4 = try setup.make_producer(&.{.{ 2, "data for key 2" }});
            _ = try setup.spawn(3, try setup.make_consumer(), prod4);
            try setup.sleep(Duration.from_millis(100));

            // Key 1 targets peer 2, key 2 targets peer 4, and key 3 may use any peer.
            const T = resolver.Targeted(MockKey, void, PublicKey);
            const items = [_]T{
                .{ .fetch = Fetch.from_key(key(1)), .targets = &.{setup.peers[1]} },
                .{ .fetch = Fetch.from_key(key(2)), .targets = &.{setup.peers[3]} },
            };
            _ = try mailbox1.fetch_all_targeted(&items);
            try fetch(mailbox1, 3);

            var found: [3]bool = @splat(false);
            for (0..3) |_| {
                var event = try consumer.next_event();
                defer event.deinit(gpa);
                try testing.expect(event.key.value >= 1 and event.key.value <= 3);
                found[event.key.value - 1] = true;
            }
            try testing.expect(found[0] and found[1] and found[2]);
            try expect_success_total(setup, 3);
        }
    }.body);
}

test "fetch clears targets" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            _ = try setup.spawn(1, try setup.make_consumer(), try setup.make_producer(&.{}));
            const prod3 = try setup.make_producer(&.{.{ 1, "valid data" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);
            try setup.sleep(Duration.from_millis(100));

            // Target peer 2 (no data), let it fail, then clear targets with a plain fetch.
            try fetch_targeted(setup, mailbox1, 1, &.{1});
            try setup.sleep(Duration.from_millis(500));
            try fetch(mailbox1, 1);
            try expect_event(consumer, 1, "valid data");
        }
    }.body);
}

test "fetch targeted does not restrict all" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            _ = try setup.spawn(1, try setup.make_consumer(), try setup.make_producer(&.{}));
            const prod3 = try setup.make_producer(&.{.{ 1, "valid data" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);
            try setup.sleep(Duration.from_millis(100));

            // An unrestricted fetch stays unrestricted after a targeted one.
            try fetch(mailbox1, 1);
            try setup.sleep(Duration.from_millis(50));
            try fetch_targeted(setup, mailbox1, 1, &.{1});
            try expect_event(consumer, 1, "valid data");
        }
    }.body);
}

test "retain" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 5, "data for key 5" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            // Retaining everything before fetching has no effect.
            const keep_all = Predicate.init({}, struct {
                fn keep(_: void, _: MockKey, _: void) bool {
                    return true;
                }
            }.keep);
            _ = try mailbox1.retain(keep_all);
            try expect_no_event(setup, consumer, 100);

            // With no link the fetch stays in flight; pruning it must clean up its entry.
            try fetch(mailbox1, 5);
            try retain_except(mailbox1, 5);
            try setup.add_link(link, 0, 1);
            // A leftover entry would make this fetch a silently ignored duplicate.
            try fetch(mailbox1, 5);
            try expect_event(consumer, 5, "data for key 5");
        }
    }.body);
}

/// Setup for consumers with `u16` subscribers.
const TaggedSetup = SetupWith(MockConsumer(MockKey, u16));
const TaggedFetch = resolver.Fetch(MockKey, u16);

fn fetch_tagged(mailbox: anytype, value: u8, subscriber: u16) !void {
    _ = try mailbox.fetch(.{ .key = key(value), .subscriber = subscriber });
}

test "retain uses subscribers" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try TaggedSetup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 5, "data for key 5" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            try fetch_tagged(mailbox1, 5, 50);
            try fetch_tagged(mailbox1, 5, 51);
            try setup.sleep(Duration.from_millis(100));
            // Dropping one subscriber keeps the fetch alive for the other.
            const keep_51 = resolver.Predicate(MockKey, u16).init({}, struct {
                fn keep(_: void, _: MockKey, subscriber: u16) bool {
                    return subscriber == 51;
                }
            }.keep);
            _ = try mailbox1.retain(keep_51);
            try setup.sleep(Duration.from_millis(100));
            try setup.add_link(link, 0, 1);
            var event = try consumer.next_event();
            defer event.deinit(gpa);
            try testing.expectEqual(key(5), event.key);
            try testing.expectEqualStrings("data for key 5", event.value);
            try testing.expectEqualSlices(u16, &.{51}, event.subscribers);
        }
    }.body);
}

fn deliver_subscribers(io: Io, first: u16, second: u16) !void {
    const setup = try TaggedSetup.init(io, &.{ 1, 2 }, .{});
    defer setup.deinit();
    const consumer = try setup.make_consumer();
    const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const prod2 = try setup.make_producer(&.{.{ 5, "data for key 5" }});
    _ = try setup.spawn(1, try setup.make_consumer(), prod2);

    try fetch_tagged(mailbox1, 5, first);
    try fetch_tagged(mailbox1, 5, second);
    try setup.add_link(link, 0, 1);
    // The delivery carries every subscriber, in ascending order.
    var event = try consumer.next_event();
    defer event.deinit(gpa);
    try testing.expectEqual(key(5), event.key);
    const ascending = [_]u16{ @min(first, second), @max(first, second) };
    try testing.expectEqualSlices(u16, &ascending, event.subscribers);
    try testing.expectEqualStrings("data for key 5", event.value);
}

test "deliver receives subscribers" {
    try run(10, struct {
        fn body(io: Io) !void {
            try deliver_subscribers(io, 51, 50);
        }
    }.body);
}

test "deliver receives multiple subscribers" {
    try run(10, struct {
        fn body(io: Io) !void {
            try deliver_subscribers(io, 49, 50);
        }
    }.body);
}

fn now_of(setup: *const Setup) utils.SystemTime {
    return utils.SystemTime.from_timestamp(Io.Clock.real.now(setup.io));
}

/// Collects `count` events and checks each key's value is "data for key <key>".
fn expect_keyed_events(consumer: Consumer, count: usize) !void {
    var seen: u32 = 0;
    for (0..count) |_| {
        var event = try consumer.next_event();
        defer event.deinit(gpa);
        var buffer: [32]u8 = undefined;
        const expected = try std.fmt.bufPrint(&buffer, "data for key {d}", .{event.key.value});
        try testing.expectEqualStrings(expected, event.value);
        const bit = @as(u32, 1) << @intCast(event.key.value);
        try testing.expect(seen & bit == 0);
        seen |= bit;
    }
    try testing.expectEqual(count, @popCount(seen));
}

test "rate limit spillover" {
    try run(30, struct {
        fn body(io: Io) !void {
            // One request per second per peer.
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, .{ .quota = p2p.Quota.per_second(1) });
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            const entries = .{ .{ 0, "data for key 0" }, .{ 1, "data for key 1" } };
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            _ = try setup.spawn(1, try setup.make_consumer(), try setup.make_producer(&entries));
            _ = try setup.spawn(2, try setup.make_consumer(), try setup.make_producer(&entries));
            try setup.sleep(Duration.from_millis(100));

            // Two fetches spill over to the two peers, completing well under a second.
            const start = now_of(setup);
            try fetch(mailbox1, 0);
            try fetch(mailbox1, 1);
            try expect_keyed_events(consumer, 2);
            const elapsed = fetcher_mod.duration_since(now_of(setup), start);
            try testing.expect(elapsed.order(Duration.from_millis(500)) == .lt);
        }
    }.body);
}

test "rate limit retry after reset" {
    try run(30, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2 }, .{ .quota = p2p.Quota.per_second(1) });
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{
                .{ 1, "data for key 1" },
                .{ 2, "data for key 2" },
                .{ 3, "data for key 3" },
            });
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            try setup.sleep(Duration.from_millis(100));

            // Three fetches to one peer at 1/s: the last two wait for the limit to reset.
            const start = now_of(setup);
            for ([_]u8{ 1, 2, 3 }) |value| try fetch(mailbox1, value);
            try expect_keyed_events(consumer, 3);
            const elapsed = fetcher_mod.duration_since(now_of(setup), start);
            try testing.expect(elapsed.order(Duration.from_secs(2)) == .gt);
        }
    }.body);
}

test "self exclusion" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            // Both peers have the data; the requester never fetches from itself.
            const prod1 = try setup.make_producer(&.{.{ 1, "shared data" }});
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, prod1);
            const prod2 = try setup.make_producer(&.{.{ 1, "shared data" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            try setup.sleep(Duration.from_millis(100));
            try fetch(mailbox1, 1);
            try expect_event(consumer, 1, "shared data");
        }
    }.body);
}

const untracked: Setup.Options = .{ .tracked_peer_sets = 1, .track = false };

test "fetch uses secondary peers" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, untracked);
            defer setup.deinit();
            // Peers 1 and 2 are primary (2 has no data); peer 3 is secondary with the data.
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            try setup.track_roles(1, &.{ 0, 1 }, &.{2});
            try setup.sleep(Duration.from_millis(100));
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            _ = try setup.spawn(1, try setup.make_consumer(), try setup.make_producer(&.{}));
            const prod3 = try setup.make_producer(&.{.{ 1, "secondary only data" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);

            try fetch(mailbox1, 1);
            try expect_event(consumer, 1, "secondary only data");
        }
    }.body);
}

test "fetch targeted reaches secondary peer" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, untracked);
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            try setup.track_roles(1, &.{ 0, 1 }, &.{2});
            try setup.sleep(Duration.from_millis(100));
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            _ = try setup.spawn(1, try setup.make_consumer(), try setup.make_producer(&.{}));
            const prod3 = try setup.make_producer(&.{
                .{ 1, "secondary only data" },
                .{ 2, "secondary only data" },
            });
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);

            // With both peers targeted, only the secondary peer can serve the key.
            try fetch_targeted(setup, mailbox1, 1, &.{ 1, 2 });
            try expect_event(consumer, 1, "secondary only data");
            // Targeting only the secondary peer also succeeds.
            try fetch_targeted(setup, mailbox1, 2, &.{2});
            try expect_event(consumer, 2, "secondary only data");
        }
    }.body);
}

const two_sets: Setup.Options = .{ .tracked_peer_sets = 2, .track = false };

test "fetch uses latest set only" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, two_sets);
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            try setup.track_roles(0, &.{ 0, 1 }, &.{});
            try setup.sleep(Duration.from_millis(100));
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            // Peer 2 is the old primary, kept only in the overlap window; it has keys 7 and 8.
            const prod2 = try setup.make_producer(&.{
                .{ 7, "old primary data" },
                .{ 8, "old primary data" },
            });
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            // Peer 3 is the latest secondary, with only key 9.
            const prod3 = try setup.make_producer(&.{.{ 9, "old primary data" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);
            try setup.sleep(Duration.from_millis(100));
            try setup.track_roles(1, &.{0}, &.{2});
            try setup.sleep(Duration.from_millis(100));

            // Neither a plain nor a targeted fetch reaches the overlap-only peer.
            try fetch(mailbox1, 7);
            try expect_no_event(setup, consumer, 1000);
            try fetch_targeted(setup, mailbox1, 8, &.{1});
            try expect_no_event(setup, consumer, 1000);
            // The latest set's secondary peer serves a fetch without targets.
            try fetch(mailbox1, 9);
            try expect_event(consumer, 9, "old primary data");
        }
    }.body);
}

test "fetch after cutover relies on latest primary history" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2, 3 }, two_sets);
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            try setup.add_link(link, 0, 2);
            try setup.track_roles(0, &.{ 0, 1 }, &.{});
            try setup.sleep(Duration.from_millis(100));
            const consumer = try setup.make_consumer();
            try consumer.add_expected(key(9), "latest primary history");
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            // Peer 2 (overlap only) would be blocked for its stale history if queried.
            const prod2 = try setup.make_producer(&.{.{ 9, "stale overlap history" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            const prod3 = try setup.make_producer(&.{.{ 9, "latest primary history" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);
            try setup.sleep(Duration.from_millis(100));
            try setup.track_roles(1, &.{ 0, 2 }, &.{});
            try setup.sleep(Duration.from_millis(100));

            try fetch(mailbox1, 9);
            try expect_event(consumer, 9, "latest primary history");
            const blocked = try setup.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(@as(usize, 0), blocked.len);
        }
    }.body);
}

test "secondary peer requests are served" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            // Peer 1 is primary with the data; peer 2 is secondary and requests it.
            try setup.add_link(link, 0, 1);
            try setup.track_roles(1, &.{0}, &.{1});
            try setup.sleep(Duration.from_millis(100));
            const prod1 = try setup.make_producer(&.{.{ 9, "served to secondary" }});
            _ = try setup.spawn(0, try setup.make_consumer(), prod1);
            const consumer = try setup.make_consumer();
            try consumer.add_expected(key(9), "served to secondary");
            const mailbox2 = try setup.spawn(1, consumer, try setup.make_producer(&.{}));
            try fetch_targeted(setup, mailbox2, 9, &.{0});
            try expect_event(consumer, 9, "served to secondary");
        }
    }.body);
}

test {
    _ = @import("engine_delivery_test.zig");
}

test "operations after shutdown do not panic" {
    try run(10, struct {
        fn body(io: Io) !void {
            const setup = try Setup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(link, 0, 1);
            const consumer = try setup.make_consumer();
            const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            try fetch(mailbox1, 1);
            try expect_event(consumer, 1, "data for key 1");

            setup.stop(0);
            setup.stop(1);
            try setup.sleep(Duration.from_millis(100));
            // Every mailbox operation reports a closed engine instead of failing.
            try fetch(mailbox1, 2);
            try retain_except(mailbox1, 2);
            const keep_all = Predicate.init({}, struct {
                fn keep(_: void, _: MockKey, _: void) bool {
                    return true;
                }
            }.keep);
            _ = try mailbox1.retain(keep_all);
            try fetch_targeted(setup, mailbox1, 3, &.{1});
        }
    }.body);
}

fn clean_shutdown(io: Io) !void {
    const setup = try Setup.init(io, &.{ 1, 2 }, .{});
    defer setup.deinit();
    try setup.add_link(link, 0, 1);
    const consumer = try setup.make_consumer();
    const mailbox1 = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
    _ = try setup.spawn(1, try setup.make_consumer(), prod2);
    try setup.sleep(Duration.from_millis(100));
    try fetch(mailbox1, 1);
    try expect_event(consumer, 1, "data for key 1");
    // Aborting frees every engine resource; testing.allocator reports any leak, and the
    // runner returns only once no task is left running.
    setup.stop(0);
    setup.stop(1);
    try setup.sleep(Duration.from_millis(100));
}

test "clean shutdown" {
    for (0..25) |seed| {
        var runner = try runtime.deterministic.Runner.init(gpa, .{
            .seed = seed,
            .timeout_ns = 30 * std.time.ns_per_s,
        });
        defer runner.deinit();
        try try runner.start(clean_shutdown, .{runner.io()});
    }
}
