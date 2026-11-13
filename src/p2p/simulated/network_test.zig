//! Tests for the simulated network (commonware `p2p/src/simulated/mod.rs` tests), run on the
//! deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils_pkg = @import("utils");
const p2p = @import("../root.zig");
const network_mod = @import("network.zig");
const Quota = @import("../rate_limit.zig").Quota;

const Key = cryptography.ed25519.PublicKey;
const Net = network_mod.Network(Key);
const Config = network_mod.Config;
const Link = network_mod.Link;
const Duration = utils_pkg.Duration;
const Tracked = p2p.TrackedPeers(Key);
const AuditState = [8]u8;

/// Default rate limit set high enough to not interfere with normal operation.
const test_quota = Quota.per_second(std.math.maxInt(u32));

comptime {
    p2p.assert_limited_sender(Net.Sender);
    p2p.assert_receiver(Net.Receiver);
    p2p.assert_manager(Net.Manager);
}

fn key(seed: u64) Key {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

fn config(max_peers_per_set: usize, tracked_peer_sets: usize) Config {
    return .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = max_peers_per_set,
        .disconnect_on_block = true,
        .tracked_peer_sets = tracked_peer_sets,
    };
}

fn link_ms(latency_ms: u64, jitter_ms: u64, success_rate: f64) Link {
    return .{
        .latency = Duration.from_millis(latency_ms),
        .jitter = Duration.from_millis(jitter_ms),
        .success_rate = success_rate,
    };
}

/// A running network: `run` executes concurrently until `deinit`.
const Harness = struct {
    io: Io,
    network: *Net,
    task: Io.Future((Io.Cancelable || Allocator.Error)!void),

    fn start(io: Io, cfg: Config) !Harness {
        const network = try Net.init(testing.allocator, io, cfg);
        errdefer network.deinit();
        const task = try io.concurrent(Net.run, .{network});
        return .{ .io = io, .network = network, .task = task };
    }

    fn oracle(harness: *const Harness) Net.Oracle {
        return harness.network.oracle();
    }

    /// Tracks `peers` network-wide at id 0.
    fn track(harness: *const Harness, peers: []const Key) !void {
        const sorted = try testing.allocator.dupe(Key, peers);
        defer testing.allocator.free(sorted);
        Tracked.PeerSet.sort(sorted);
        const manager = harness.oracle().manager();
        try testing.expectEqual(p2p.Feedback.ok, manager.track(0, .init_primary(.init(sorted))));
        const set = (try manager.peer_set(testing.allocator, 0)).?;
        set.free(testing.allocator);
    }

    fn deinit(harness: *Harness) void {
        harness.network.close();
        harness.task.await(harness.io) catch |err| std.debug.panic("run: {t}", .{err});
        harness.network.deinit();
    }
};

fn run_deterministic(seed: u64, comptime function: fn (Io) anyerror!void) !AuditState {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{ .seed = seed });
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
    return runner.auditor.state();
}

fn expect_message(receiver: *Net.Receiver, from: Key, payload: []const u8) !void {
    var message = try receiver.recv();
    defer message.deinit();
    try testing.expect(Key.order(message.peer, from) == .eq);
    try testing.expectEqualSlices(u8, payload, message.payload);
}

fn send_one(sender: *Net.Sender, to: Key, payload: []const u8, priority: bool) !usize {
    const sent = try sender.send(.{ .one = to }, &.{payload}, priority);
    defer testing.allocator.free(sent);
    return sent.len;
}

test "simple message delivery" {
    _ = try run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try Harness.start(io, config(2, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(0);
            const pk2 = key(1);
            var one = try oracle.control(pk1).register(0, test_quota);
            defer one.sender.deinit();
            defer one.receiver.deinit();
            var two = try oracle.control(pk2).register(0, test_quota);
            defer two.sender.deinit();
            defer two.receiver.deinit();
            // Unused channels.
            var unused1 = try oracle.control(pk1).register(1, test_quota);
            defer unused1.sender.deinit();
            defer unused1.receiver.deinit();
            var unused2 = try oracle.control(pk2).register(2, test_quota);
            defer unused2.sender.deinit();
            defer unused2.receiver.deinit();
            try harness.track(&.{ pk1, pk2 });
            try oracle.add_link(pk1, pk2, link_ms(5, 2, 1.0));
            try oracle.add_link(pk2, pk1, link_ms(5, 2, 1.0));

            try testing.expectEqual(1, try send_one(&one.sender, pk2, "hello from pk1", false));
            try testing.expectEqual(1, try send_one(&two.sender, pk1, "hello from pk2", false));
            try expect_message(&one.receiver, pk2, "hello from pk2");
            try expect_message(&two.receiver, pk1, "hello from pk1");
        }
    }.run);
}

test "send on a channel the recipient did not register" {
    _ = try run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try Harness.start(io, config(2, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(0);
            const pk2 = key(1);
            var one = try oracle.control(pk1).register(0, test_quota);
            defer one.sender.deinit();
            defer one.receiver.deinit();
            var two = try oracle.control(pk2).register(1, test_quota);
            defer two.sender.deinit();
            defer two.receiver.deinit();
            try harness.track(&.{ pk1, pk2 });
            try oracle.add_link(pk1, pk2, link_ms(5, 0, 1.0));

            _ = try send_one(&one.sender, pk2, "hello from pk1", false);
            try io.sleep(.fromSeconds(1), .real);
            try testing.expectError(error.Empty, two.receiver.try_recv());
        }
    }.run);
}

test "linking self and duplicate links fail" {
    _ = try run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try Harness.start(io, config(2, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(0);
            const pk2 = key(1);
            try testing.expectError(error.LinkingSelf, oracle.add_link(pk1, pk1, link_ms(5, 0, 1)));
            try oracle.add_link(pk1, pk2, link_ms(5, 0, 1));
            try testing.expectError(error.LinkExists, oracle.add_link(pk1, pk2, link_ms(5, 0, 1)));
            try oracle.remove_link(pk1, pk2);
            try testing.expectError(error.LinkMissing, oracle.remove_link(pk1, pk2));
        }
    }.run);
}

test "receiver reports channel capacity" {
    _ = try run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try Harness.start(io, config(2, 3));
            defer harness.deinit();
            var registered = try harness.oracle().control(key(0)).register(0, .per_second(7));
            defer registered.sender.deinit();
            defer registered.receiver.deinit();
            try testing.expectEqual(42, registered.receiver.capacity());
        }
    }.run);
}

test "messages arrive in order despite jitter" {
    _ = try run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try Harness.start(io, config(2, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            var one = try oracle.control(pk1).register(0, test_quota);
            defer one.sender.deinit();
            defer one.receiver.deinit();
            var two = try oracle.control(pk2).register(0, test_quota);
            defer two.sender.deinit();
            defer two.receiver.deinit();
            try harness.track(&.{ pk1, pk2 });
            try oracle.add_link(pk1, pk2, link_ms(50, 40, 1.0));

            const messages = [_][]const u8{
                "message 1", "message 2", "message 3", "message 4", "message 5",
            };
            for (messages) |message| _ = try send_one(&one.sender, pk2, message, true);
            for (messages) |message| try expect_message(&two.receiver, pk1, message);
        }
    }.run);
}

test "rate limiting skips recipients over quota" {
    _ = try run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try Harness.start(io, config(2, 3));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            try harness.track(&.{ pk1, pk2 });
            var one = try oracle.control(pk1).register(0, .per_second(1));
            defer one.sender.deinit();
            defer one.receiver.deinit();
            var two = try oracle.control(pk2).register(0, test_quota);
            defer two.sender.deinit();
            defer two.receiver.deinit();
            try oracle.add_link(pk1, pk2, link_ms(0, 0, 1.0));
            try oracle.add_link(pk2, pk1, link_ms(0, 0, 1.0));

            try testing.expectEqual(1, try send_one(&one.sender, pk2, "message1", false));
            try expect_message(&two.receiver, pk1, "message1");
            try testing.expectEqual(0, try send_one(&one.sender, pk2, "message2", false));
            try io.sleep(.fromSeconds(1), .real);
            try testing.expectEqual(1, try send_one(&one.sender, pk2, "message3", false));
            try expect_message(&two.receiver, pk1, "message3");
        }
    }.run);
}

/// Many agents broadcast over lossy links until each received `agent_count` messages.
fn simulate_messages(io: Io) !void {
    const agent_count = 10;
    var harness = try Harness.start(io, config(agent_count, 1));
    defer harness.deinit();
    const oracle = harness.oracle();
    var keys: [agent_count]Key = undefined;
    for (&keys, 0..) |*public_key, i| public_key.* = key(i);
    Tracked.PeerSet.sort(&keys);
    var registered: [agent_count]Net.Registered = undefined;
    for (&registered, keys) |*entry, public_key| {
        entry.* = try oracle.control(public_key).register(0, test_quota);
    }
    defer for (&registered) |*entry| {
        entry.sender.deinit();
        entry.receiver.deinit();
    };
    try harness.track(&keys);
    const only_inbound = key(0);
    for (keys) |from| {
        if (Key.order(from, only_inbound) == .eq) continue;
        for (keys) |to| {
            const result = oracle.add_link(from, to, link_ms(5, 2, 0.75));
            if (Key.order(from, to) == .eq) {
                try testing.expectError(error.LinkingSelf, result);
            } else try result;
        }
    }
    var received: [agent_count]usize = @splat(0);
    var done: usize = 0;
    var rounds: u32 = 0;
    while (done < agent_count) : (rounds += 1) {
        assert(rounds < 100_000);
        var index_bytes: [8]u8 = undefined;
        io.random(&index_bytes);
        const index = std.mem.readInt(u64, &index_bytes, .little) % agent_count;
        const sent = try registered[index].sender.send(.all, &.{"hello"}, false);
        defer testing.allocator.free(sent);
        try testing.expectEqual(agent_count - 1, sent.len);
        try io.sleep(.fromMilliseconds(1), .real);
        for (&registered, &received) |*entry, *count| {
            while (entry.receiver.try_recv()) |message_value| {
                var message = message_value;
                message.deinit();
                count.* += 1;
                if (count.* == agent_count) done += 1;
            } else |err| try testing.expectEqual(error.Empty, err);
        }
    }
}

test "determinism over seeds" {
    var first: [4]AuditState = undefined;
    for (&first, 0..) |*state, seed| state.* = try run_deterministic(seed, simulate_messages);
    for (first, 0..) |state, seed| {
        try testing.expectEqualSlices(u8, &state, &try run_deterministic(seed, simulate_messages));
    }
    try testing.expect(!std.mem.eql(u8, &first[0], &first[1]));
}
