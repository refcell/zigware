//! Simulated network bandwidth tests (commonware `p2p/src/simulated/mod.rs`).

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const t = @import("network_test.zig");

const Key = t.Key;
const Net = t.Net;
const key = t.key;

fn register(oracle: Net.Oracle, peer: Key) !Net.Registered {
    return oracle.control(peer).register(0, t.test_quota);
}

fn now(io: Io) Io.Timestamp {
    return Io.Clock.real.now(io);
}

fn elapsed_ms(io: Io, start: Io.Timestamp) i96 {
    return @divTrunc(start.durationTo(now(io)).nanoseconds, std.time.ns_per_ms);
}

fn expect_between(value: i96, low: i96, high: i96) !void {
    if (value < low or value > high) {
        std.debug.print("{d} ms is outside [{d}, {d}]\n", .{ value, low, high });
        return error.TestUnexpectedResult;
    }
}

/// Sends `size` bytes of `fill` to `to`, returning how many recipients were attempted.
fn send_filled(sender: *Net.Sender, to: Key, fill: u8, size: usize, priority: bool) !usize {
    const payload = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(payload);
    @memset(payload, fill);
    return t.send_one(sender, to, payload, priority);
}

/// Sleeps `delay_ms`, then sends `size` bytes of `fill` (a spawned sender).
fn send_later(
    io: Io,
    sender: *Net.Sender,
    to: Key,
    fill: u8,
    size: usize,
    delay_ms: i64,
) anyerror!void {
    try io.sleep(.fromMilliseconds(delay_ms), .real);
    try testing.expectEqual(1, try send_filled(sender, to, fill, size, true));
}

/// The first byte of the next message, after checking its length.
fn recv_fill(receiver: *Net.Receiver, size: usize) !u8 {
    var message = try receiver.recv();
    defer message.deinit();
    try testing.expectEqual(size, message.payload.len);
    return message.payload[0];
}

fn random_key(io: Io) Key {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    return key(std.mem.readInt(u64, &bytes, .little));
}

fn bandwidth_between_peers(
    io: Io,
    oracle: Net.Oracle,
    index: u64,
    sender_bps: ?u64,
    receiver_bps: ?u64,
    message_size: usize,
    expected_ms: i96,
) !void {
    const pk1 = random_key(io);
    const pk2 = random_key(io);
    var one = try register(oracle, pk1);
    defer one.deinit();
    var two = try register(oracle, pk2);
    defer two.deinit();
    var keys = [_]Key{ pk1, pk2 };
    _ = oracle.manager().track(index, .init_primary(t.set(&keys)));
    try oracle.limit_bandwidth(pk1, sender_bps, null);
    try oracle.limit_bandwidth(pk2, null, receiver_bps);
    try oracle.add_link(pk1, pk2, t.link_ms(0, 0, 1.0));

    const start = now(io);
    _ = try send_filled(&one.sender, pk2, 42, message_size, true);
    try testing.expectEqual(42, try recv_fill(&two.receiver, message_size));
    try expect_between(elapsed_ms(io, start), expected_ms, expected_ms + 99);
}

test "bandwidth between two peers" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            try bandwidth_between_peers(io, oracle, 0, 1000, 1000, 500, 500);
            try bandwidth_between_peers(io, oracle, 1, 500, 2000, 250, 500);
            try bandwidth_between_peers(io, oracle, 2, 2000, 500, 250, 500);
            try bandwidth_between_peers(io, oracle, 3, null, 1000, 500, 500);
            try bandwidth_between_peers(io, oracle, 4, 1000, null, 500, 500);
            try bandwidth_between_peers(io, oracle, 5, null, null, 500, 0);
        }
    }.run);
}

test "bandwidth contention one-to-many and many-to-one" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            const peer_count = 100;
            const message_size = 1000;
            const bps = 10_000;
            var harness = try t.Harness.start(io, t.config(peer_count + 1, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            var peers: [peer_count + 1]Key = undefined;
            var registered: [peer_count + 1]Net.Registered = undefined;
            for (&peers, &registered, 0..) |*peer, *entry, i| {
                peer.* = key(i);
                entry.* = try register(oracle, peer.*);
            }
            defer for (&registered) |*entry| entry.deinit();
            try harness.track(&peers);
            for (peers) |peer| try oracle.limit_bandwidth(peer, bps, bps);
            for (peers[1..]) |peer| {
                try oracle.add_link(peer, peers[0], t.link_ms(0, 0, 1.0));
                try oracle.add_link(peers[0], peer, t.link_ms(0, 0, 1.0));
            }
            const expected_ms = peer_count * message_size * 1000 / bps;

            var start = now(io);
            for (peers[1..]) |peer| {
                _ = try send_filled(&registered[0].sender, peer, 0, message_size, true);
            }
            for (registered[1..]) |*entry| {
                var message = try entry.receiver.recv();
                defer message.deinit();
                try testing.expect(Key.order(message.peer, peers[0]) == .eq);
                try testing.expectEqual(message_size, message.payload.len);
            }
            try expect_between(elapsed_ms(io, start), expected_ms, expected_ms + 499);

            start = now(io);
            for (registered[1..]) |*entry| {
                _ = try send_filled(&entry.sender, peers[0], 0, message_size, true);
            }
            var seen: [peer_count + 1]bool = @splat(false);
            for (0..peer_count) |_| {
                var message = try registered[0].receiver.recv();
                defer message.deinit();
                const index = for (peers, 0..) |peer, i| {
                    if (Key.order(peer, message.peer) == .eq) break i;
                } else return error.TestUnexpectedResult;
                try testing.expect(index != 0 and !seen[index]);
                seen[index] = true;
            }
            try expect_between(elapsed_ms(io, start), expected_ms, expected_ms + 499);
        }
    }.run);
}

test "high latency message blocks followup" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            var one = try register(oracle, pk1);
            defer one.deinit();
            var two = try register(oracle, pk2);
            defer two.deinit();
            try harness.track(&.{ pk1, pk2 });
            try oracle.limit_bandwidth(pk1, 1000, null);
            try oracle.limit_bandwidth(pk2, null, 1000);
            try oracle.add_link(pk1, pk2, t.link_ms(5000, 0, 1.0));

            const start = now(io);
            _ = try send_filled(&one.sender, pk2, 0, 1000, true);
            try oracle.remove_link(pk1, pk2);
            try oracle.add_link(pk1, pk2, t.link_ms(1, 0, 1.0));
            _ = try send_filled(&one.sender, pk2, 1, 1000, true);

            try testing.expectEqual(0, try recv_fill(&two.receiver, 1000));
            const first = elapsed_ms(io, start);
            try testing.expectEqual(1, try recv_fill(&two.receiver, 1000));
            const second = elapsed_ms(io, start);
            // Egress takes 1 s, then the slow link adds 5 s.
            try expect_between(first, 5990, 6010);
            try expect_between(second - first, 990, 1010);
        }
    }.run);
}

/// `count` senders with `egress` each send `size` bytes to one receiver with `ingress`.
fn many_to_one(io: Io, egress: u64, ingress: u64, size: usize) !void {
    const count = 10;
    var harness = try t.Harness.start(io, t.config(count + 1, 1));
    defer harness.deinit();
    const oracle = harness.oracle();
    var peers: [count + 1]Key = undefined;
    var senders: [count]Net.Registered = undefined;
    for (&senders, peers[0..count], 0..) |*entry, *peer, i| {
        peer.* = key(i);
        entry.* = try register(oracle, peer.*);
        try oracle.limit_bandwidth(peer.*, egress, null);
    }
    defer for (&senders) |*entry| entry.deinit();
    const receiver = key(100);
    peers[count] = receiver;
    var sink = try register(oracle, receiver);
    defer sink.deinit();
    try harness.track(&peers);
    try oracle.limit_bandwidth(receiver, null, ingress);
    for (peers[0..count]) |peer| try oracle.add_link(peer, receiver, t.link_ms(0, 0, 1.0));

    const start = now(io);
    for (&senders, 0..) |*entry, i| {
        _ = try send_filled(&entry.sender, receiver, @intCast(i), size, true);
    }
    for (0..count) |_| {
        _ = try recv_fill(&sink.receiver, size);
        try expect_between(elapsed_ms(io, start), 950, 1100);
    }
}

test "many to one bandwidth sharing" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            try many_to_one(io, 10_000, 100_000, 10_000);
        }
    }.run);
}

test "many slow senders to fast receiver" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            try many_to_one(io, 1_000, 10_000, 1_000);
        }
    }.run);
}

test "one to many fast sender" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            const count = 10;
            var harness = try t.Harness.start(io, t.config(count + 1, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            var peers: [count + 1]Key = undefined;
            peers[0] = key(0);
            var source = try register(oracle, peers[0]);
            defer source.deinit();
            try oracle.limit_bandwidth(peers[0], 100_000, null);
            var receivers: [count]Net.Registered = undefined;
            for (&receivers, peers[1..], 1..) |*entry, *peer, i| {
                peer.* = key(i);
                entry.* = try register(oracle, peer.*);
                try oracle.limit_bandwidth(peer.*, null, 10_000);
                try oracle.add_link(peers[0], peer.*, t.link_ms(0, 0, 1.0));
            }
            defer for (&receivers) |*entry| entry.deinit();
            try harness.track(&peers);

            const start = now(io);
            for (peers[1..], 0..) |peer, i| {
                _ = try send_filled(&source.sender, peer, @intCast(i), 10_000, true);
            }
            for (&receivers, 0..) |*entry, i| {
                const fill = try recv_fill(&entry.receiver, 10_000);
                try testing.expectEqual(@as(u8, @intCast(i)), fill);
                try expect_between(elapsed_ms(io, start), 950, 1100);
            }
        }
    }.run);
}

/// Three senders and one receiver with `ingress`, linked with 1 ms latency.
const Star = struct {
    harness: t.Harness,
    senders: [3]Net.Registered,
    sink: Net.Registered,
    receiver: Key,

    fn init(star: *Star, io: Io, egress: ?u64, ingress: u64) !void {
        star.harness = try t.Harness.start(io, t.config(4, 1));
        const oracle = star.harness.oracle();
        var peers: [4]Key = undefined;
        for (&star.senders, peers[0..3], 0..) |*entry, *peer, i| {
            peer.* = key(i);
            entry.* = try register(oracle, peer.*);
            try oracle.limit_bandwidth(peer.*, egress, null);
        }
        star.receiver = key(100);
        peers[3] = star.receiver;
        star.sink = try register(oracle, star.receiver);
        try star.harness.track(&peers);
        try oracle.limit_bandwidth(star.receiver, null, ingress);
        for (peers[0..3]) |peer| try oracle.add_link(peer, star.receiver, t.link_ms(1, 0, 1.0));
    }

    fn deinit(star: *Star) void {
        for (&star.senders) |*entry| entry.deinit();
        star.sink.deinit();
        star.harness.deinit();
    }
};

test "dynamic bandwidth allocation staggered" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var star: Star = undefined;
            try star.init(io, 30_000, 30_000);
            defer star.deinit();
            const to = star.receiver;
            const start = now(io);
            const senders = &star.senders;
            var tasks: [3]Io.Future(anyerror!void) = .{
                try io.concurrent(send_later, .{ io, &senders[0].sender, to, 0, 30_000, 0 }),
                try io.concurrent(send_later, .{ io, &senders[1].sender, to, 1, 30_000, 500 }),
                try io.concurrent(send_later, .{ io, &senders[2].sender, to, 2, 15_000, 1500 }),
            };
            defer for (&tasks) |*task| task.await(io) catch {};

            try testing.expectEqual(0, try recv_fill(&star.sink.receiver, 30_000));
            try expect_between(elapsed_ms(io, start), 1490, 1600);
            var seen: [3]bool = @splat(false);
            for (0..2) |_| {
                var message = try star.sink.receiver.recv();
                defer message.deinit();
                const fill = message.payload[0];
                try testing.expect(fill == 1 or fill == 2);
                try testing.expect(!seen[fill]);
                seen[fill] = true;
                try expect_between(elapsed_ms(io, start), 1500, 2600);
            }
        }
    }.run);
}

test "dynamic bandwidth varied sizes" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var star: Star = undefined;
            try star.init(io, null, 30_000);
            defer star.deinit();
            const start = now(io);
            const sizes = [_]usize{ 10_000, 20_000, 30_000 };
            for (&star.senders, sizes, 0..) |*entry, size, i| {
                _ = try send_filled(&entry.sender, star.receiver, @intCast(i), size, true);
            }
            var latest: i96 = 0;
            for (0..3) |_| {
                var message = try star.sink.receiver.recv();
                message.deinit();
                latest = @max(latest, elapsed_ms(io, start));
            }
            // 60 KB at 30 KB/s takes at least 2 s.
            try testing.expect(latest >= 2000);
        }
    }.run);
}

/// Two tracked, registered peers with a link from `pk1` to `pk2`.
const Pair = struct {
    harness: t.Harness,
    one: Net.Registered,
    two: Net.Registered,
    pk1: Key,
    pk2: Key,

    fn init(pair: *Pair, io: Io, latency_ms: u64) !void {
        pair.harness = try t.Harness.start(io, t.config(2, 1));
        const oracle = pair.harness.oracle();
        pair.pk1 = key(1);
        pair.pk2 = key(2);
        pair.one = try register(oracle, pair.pk1);
        pair.two = try register(oracle, pair.pk2);
        try pair.harness.track(&.{ pair.pk1, pair.pk2 });
        try oracle.add_link(pair.pk1, pair.pk2, t.link_ms(latency_ms, 0, 1.0));
    }

    fn deinit(pair: *Pair) void {
        pair.one.deinit();
        pair.two.deinit();
        pair.harness.deinit();
    }
};

test "bandwidth pipe is reserved only while transmitting" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var pair: Pair = undefined;
            try pair.init(io, 1000);
            defer pair.deinit();
            const oracle = pair.harness.oracle();
            try oracle.limit_bandwidth(pair.pk1, 1000, null);
            try oracle.limit_bandwidth(pair.pk2, null, 1000);
            const start = now(io);
            for (0..3) |i| _ = try send_filled(&pair.one.sender, pair.pk2, @intCast(i), 500, false);
            for (0..3) |i| {
                const fill = try recv_fill(&pair.two.receiver, 500);
                try testing.expectEqual(@as(u8, @intCast(i)), fill);
                const expected: i96 = @as(i96, @intCast(i)) * 500 + 1500;
                try expect_between(elapsed_ms(io, start), expected, expected + 99);
            }
        }
    }.run);
}

test "dynamic bandwidth affects new transfers" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var pair: Pair = undefined;
            try pair.init(io, 1);
            defer pair.deinit();
            const oracle = pair.harness.oracle();
            try oracle.limit_bandwidth(pair.pk1, 10_000, null);
            try oracle.limit_bandwidth(pair.pk2, null, 10_000);
            var start = now(io);
            _ = try send_filled(&pair.one.sender, pair.pk2, 1, 20_000, false);
            _ = try recv_fill(&pair.two.receiver, 20_000);
            try expect_between(elapsed_ms(io, start), 1999, 2010);

            try oracle.limit_bandwidth(pair.pk1, 2_000, null);
            start = now(io);
            _ = try send_filled(&pair.one.sender, pair.pk2, 2, 10_000, false);
            _ = try recv_fill(&pair.two.receiver, 10_000);
            try expect_between(elapsed_ms(io, start), 4999, 5010);
        }
    }.run);
}

/// A zero limit on `peer` (egress or ingress) holds a message until the limit is lifted.
fn zero_bandwidth(io: Io, egress_side: bool) !void {
    var pair: Pair = undefined;
    try pair.init(io, 0);
    defer pair.deinit();
    const oracle = pair.harness.oracle();
    if (egress_side) {
        try oracle.limit_bandwidth(pair.pk1, 0, null);
    } else {
        try oracle.limit_bandwidth(pair.pk2, null, 0);
    }
    try testing.expectEqual(1, try send_filled(&pair.one.sender, pair.pk2, 1, 20_000, false));
    try io.sleep(.fromSeconds(10), .real);
    try testing.expectError(error.Empty, pair.two.receiver.try_recv());
    if (egress_side) {
        try oracle.limit_bandwidth(pair.pk1, null, null);
    } else {
        try oracle.limit_bandwidth(pair.pk2, null, null);
    }
    try io.sleep(.fromSeconds(1), .real);
    var message = try pair.two.receiver.try_recv();
    message.deinit();
}

test "zero receiver ingress bandwidth" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            try zero_bandwidth(io, false);
        }
    }.run);
}

test "zero sender egress bandwidth" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            try zero_bandwidth(io, true);
        }
    }.run);
}
