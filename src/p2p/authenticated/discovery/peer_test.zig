//! Tests of one discovery connection (commonware `discovery/actors/peer/actor.rs` tests). The
//! stream halves are scripted: the receiver replays encoded payloads and then ends the
//! connection, and the sender records each write, so the tests see exactly what `Peer.run`
//! reads, rejects, counts, and batches. The authenticated stream has its own tests.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const p2p_types = @import("../../types.zig");
const rate_limit = @import("../../rate_limit.zig");
const outbox_mod = @import("../outbox.zig");
const types = @import("types.zig");
const peer_mod = @import("peer.zig");

const PrivateKey = cryptography.ed25519.PrivateKey;
const Key = cryptography.ed25519.PublicKey;
const Peer = peer_mod.Peer(Key);
const Info = Peer.Info;
const Payload = types.Payload(Key);
const Outbox = outbox_mod.Outbox;
const Frame = outbox_mod.Frame;
const p2p = @import("../../root.zig");
const Unreliable = p2p.Unreliable;
const Feedback = p2p.Feedback;
const Ingress = p2p_types.Ingress;
const SystemTime = utils.SystemTime;
const gpa = testing.allocator;
const CounterFamily = metrics.raw.Family(Peer.Label, metrics.raw.Counter);

const ip_namespace = "test_peer_actor_IP";
const max_message_size: u32 = 64 * 1024;

fn key(seed: u64) Key {
    return PrivateKey.from_seed(seed).public_key();
}

fn localhost(port: u16) Ingress {
    return .{ .socket = .{ .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) }, .port = port } };
}

fn info_of(io: Io, seed: u64, port: u16) Info {
    const signer = PrivateKey.from_seed(seed);
    const timestamp = SystemTime.from_timestamp(Io.Clock.real.now(io)).epoch_millis();
    return Info.sign(signer.public_key(), ip_namespace, localhost(port), timestamp, &signer);
}

/// Every write the connection made: one entry per `send` or `send_many`.
const Writes = struct {
    calls: std.ArrayList([]const []u8) = .empty,

    fn deinit(writes: *Writes) void {
        for (writes.calls.items) |parts| {
            for (parts) |part| gpa.free(part);
            gpa.free(parts);
        }
        writes.calls.deinit(gpa);
    }

    fn record(writes: *Writes, parts: []const []const u8) !void {
        const copies = try gpa.alloc([]u8, parts.len);
        for (copies, parts) |*copy, part| copy.* = try gpa.dupe(u8, part);
        try writes.calls.append(gpa, copies);
    }
};

const Sender = struct {
    writes: *Writes,

    pub fn send(sender: Sender, bytes: []const u8) !void {
        try sender.writes.record(&.{bytes});
    }

    pub fn send_many(sender: Sender, parts: []const []const u8) !void {
        try sender.writes.record(parts);
    }
};

/// Replays `script`, then ends the connection a simulated second later (after the sender
/// has drained its outbox).
const Receiver = struct {
    io: Io,
    script: []const []const u8,
    next: *usize,

    pub fn recv(receiver: Receiver) ![]const u8 {
        if (receiver.next.* < receiver.script.len) {
            receiver.next.* += 1;
            return receiver.script[receiver.next.* - 1];
        }
        try receiver.io.sleep(.fromSeconds(1), .awake);
        return error.EndOfScript;
    }
};

fn encode(payload: Payload) ![]u8 {
    return codec.encode(Payload, gpa, payload);
}

/// Everything one connection needs: the local node is key(2), the remote peer key(1).
const Fixture = struct {
    registry: metrics.Registry,
    families: Peer.Families,
    router: Peer.Channels.Router,
    channels: Peer.Channels,
    registered: Peer.Channels.Registered,
    tracker: Peer.Tracker,
    outbox: Outbox,
    config: Peer.Config,
    writes: Writes = .{},

    fn init(fixture: *Fixture, io: Io) !void {
        fixture.writes = .{};
        fixture.registry = metrics.Registry.init(gpa);
        const scope = metrics.Scope.init(&fixture.registry);
        fixture.families = try .init(scope);
        fixture.router = try .init(gpa, io);
        fixture.channels = .init(gpa, io, &fixture.router, max_message_size, 8);
        fixture.registered = try fixture.channels.register(0, rate_limit.Quota.per_second(1));
        const tracker_scope = scope.child("tracker");
        fixture.tracker = try .init(gpa, io, &tracker_scope, .{
            .myself = info_of(io, 2, 8082),
            .bootstrappers = &.{},
            .allow_private_ips = true,
            .allow_dns = true,
            .max_peers_per_set = 128,
            .tracked_peer_sets = 2,
            .peer_connection_cooldown = .from_millis(200),
            .peer_gossip_max_count = 10,
            .dial_fail_limit = 1,
            .block_duration = .from_secs(100),
        });
        fixture.outbox = Outbox.init(gpa, io, 10);
        fixture.config = .{
            .gossip_bit_vec_frequency = .from_secs(30),
            .send_batch_size = 8,
            .max_message_size = max_message_size,
            .max_bit_vec = 128,
            .max_peers = 10,
            .verifier = .{
                .me = key(2),
                .peer_gossip_max_count = 10,
                .synchrony_bound = .from_secs(60),
                .ip_namespace = ip_namespace,
            },
        };
    }

    fn deinit(fixture: *Fixture) void {
        fixture.writes.deinit();
        fixture.outbox.deinit();
        fixture.tracker.close();
        fixture.tracker.deinit();
        fixture.registered.deinit();
        fixture.channels.deinit();
        fixture.router.deinit();
        fixture.families.deinit();
        fixture.registry.deinit();
    }

    /// Runs the connection with key(1) over `script` until it ends.
    fn run(fixture: *Fixture, io: Io, script: []const []const u8) anyerror!void {
        var next: usize = 0;
        const receiver: Receiver = .{ .io = io, .script = script, .next = &next };
        const sender: Sender = .{ .writes = &fixture.writes };
        const greeting = info_of(io, 2, 8082);
        return Peer.run(
            gpa,
            io,
            &fixture.config,
            &fixture.families,
            key(1),
            greeting,
            sender,
            receiver,
            &fixture.outbox,
            &fixture.tracker,
            &fixture.channels,
        );
    }

    fn count(fixture: *Fixture, family: *CounterFamily, label: Peer.Label) ?u64 {
        _ = fixture;
        const counter = family.get(label) orelse return null;
        return counter.get();
    }
};

fn run(comptime function: anytype) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 600 * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
}

fn expect_rejection(io: Io, script: []const []const u8, expected: anyerror) !void {
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    try testing.expectError(expected, fixture.run(io, script));
}

fn missing_greeting(io: Io) !void {
    var bits = try types.BitMap.ones(gpa, 10);
    defer bits.deinit(gpa);
    const bit_vec = try encode(.{ .bit_vec = .{ .index = 0, .bits = bits } });
    defer gpa.free(bit_vec);
    try expect_rejection(io, &.{bit_vec}, error.MissingGreeting);
}

test "a connection whose first message is not a greeting fails" {
    try run(missing_greeting);
}

fn duplicate_greeting(io: Io) !void {
    const greeting = try encode(.{ .greeting = info_of(io, 1, 8081) });
    defer gpa.free(greeting);
    try expect_rejection(io, &.{ greeting, greeting }, error.DuplicateGreeting);
}

test "a second greeting fails the connection" {
    try run(duplicate_greeting);
}

fn greeting_mismatch(io: Io) !void {
    // A valid greeting, but signed by key(3) on key(1)'s connection.
    const greeting = try encode(.{ .greeting = info_of(io, 3, 8083) });
    defer gpa.free(greeting);
    try expect_rejection(io, &.{greeting}, error.GreetingMismatch);
}

test "a greeting for another key fails the connection" {
    try run(greeting_mismatch);
}

fn invalid_channel(io: Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    const greeting = try encode(.{ .greeting = info_of(io, 1, 8081) });
    defer gpa.free(greeting);
    const data = try encode(.{ .data = .{ .channel = 7, .message = "x" } });
    defer gpa.free(data);
    try testing.expectError(error.InvalidChannel, fixture.run(io, &.{ greeting, data }));
    const received = fixture.families.received.metric();
    try testing.expectEqual(@as(?u64, 1), fixture.count(received, .new_invalid(key(1))));
    // The unregistered channel gets no series of its own.
    try testing.expectEqual(@as(?u64, null), fixture.count(received, .new_data(key(1), 7)));
    const limited = fixture.families.rate_limited.metric();
    try testing.expectEqual(@as(?u64, null), fixture.count(limited, .new_data(key(1), 7)));
}

test "data on an unregistered channel fails without a per-channel series" {
    try run(invalid_channel);
}

fn oversized_data(io: Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    const greeting = try encode(.{ .greeting = info_of(io, 1, 8081) });
    defer gpa.free(greeting);
    const message = try gpa.alloc(u8, max_message_size + 1);
    defer gpa.free(message);
    @memset(message, 0xab);
    const data = try encode(.{ .data = .{ .channel = 0, .message = message } });
    defer gpa.free(data);
    if (fixture.run(io, &.{ greeting, data })) |_| return error.TestExpectedError else |err| {
        try testing.expect(err != error.EndOfScript);
    }
    const received = fixture.families.received.metric();
    try testing.expectEqual(@as(?u64, 1), fixture.count(received, .new_invalid(key(1))));
    try testing.expectError(error.Empty, fixture.registered.receiver.try_recv());
}

test "data one byte over the message limit fails to decode" {
    try run(oversized_data);
}

/// Queues two bit vectors and a peer list (as control frames) and one data frame.
fn queue_outbound(outbox: *Outbox) !void {
    var bits = try types.BitMap.ones(gpa, 10);
    defer bits.deinit(gpa);
    for (0..2) |_| {
        const bytes = try encode(.{ .bit_vec = .{ .index = 0, .bits = bits } });
        const frame = try Frame.adopt(gpa, bytes);
        defer frame.release();
        try testing.expect(outbox.send_control(frame));
    }
    const peers = try Frame.adopt(gpa, try encode(.{ .peers = &.{} }));
    defer peers.release();
    try testing.expect(outbox.send_control(peers));
    const data = try Frame.create(gpa, 0, &.{"from listener"});
    defer data.release();
    try testing.expectEqual(Unreliable(Feedback).new(.ok), outbox.send(data, false));
}

fn greeting_then_queued(io: Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    try queue_outbound(&fixture.outbox);
    const greeting = try encode(.{ .greeting = info_of(io, 1, 8081) });
    defer gpa.free(greeting);
    const data = try encode(.{ .data = .{ .channel = 0, .message = "from dialer" } });
    defer gpa.free(data);
    try testing.expectError(error.EndOfScript, fixture.run(io, &.{ greeting, data }));
    // Data is delivered only after the greeting validated.
    var message = try fixture.registered.receiver.try_recv();
    defer message.deinit();
    try testing.expect(message.peer.eql(key(1)));
    try testing.expectEqualStrings("from dialer", message.payload);
    // Our greeting goes alone, then the queued frames in one batched write, control first.
    const calls = fixture.writes.calls.items;
    try testing.expectEqual(@as(usize, 2), calls.len);
    try testing.expectEqual(@as(usize, 1), calls[0].len);
    try testing.expectEqual(types.greeting_prefix, calls[0][0][0]);
    const prefixes = [_]u8{
        types.bit_vec_prefix, types.bit_vec_prefix, types.peers_prefix, types.data_prefix,
    };
    try testing.expectEqual(prefixes.len, calls[1].len);
    for (prefixes, calls[1]) |prefix, part| try testing.expectEqual(prefix, part[0]);
    try expect_counts(&fixture);
}

fn expect_counts(fixture: *Fixture) !void {
    const peer = key(1);
    const sent = fixture.families.sent.metric();
    for ([_]struct { Peer.Label, u64 }{
        .{ .new_greeting(peer), 1 },
        .{ .new_bit_vec(peer), 2 },
        .{ .new_peers(peer), 1 },
        .{ .new_data(peer, 0), 1 },
    }) |case| try testing.expectEqual(@as(?u64, case[1]), fixture.count(sent, case[0]));
    const received = fixture.families.received.metric();
    try testing.expectEqual(@as(?u64, 1), fixture.count(received, .new_greeting(peer)));
    try testing.expectEqual(@as(?u64, 1), fixture.count(received, .new_data(peer, 0)));
    try testing.expectEqual(@as(?u64, 0), fixture.count(received, .new_invalid(peer)));
}

test "the greeting precedes queued gossip and data, each counted by type" {
    try run(greeting_then_queued);
}
