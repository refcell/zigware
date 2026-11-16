//! Tests of split senders and receivers (commonware `simulated/network.rs`
//! `test_split_channel_*` and `simulated/mod.rs`'s split capacity test).

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const p2p = @import("../root.zig");
const t = @import("network_test.zig");
const split = @import("split.zig");

const Key = t.Key;
const Net = t.Net;
const Message = p2p.Message(Key);
const Recipients = p2p.Recipients(Key);

/// Routes every message to one target.
const Fixed = struct {
    target: split.SplitTarget,

    pub fn route(fixed: Fixed, _: *const Message) split.SplitTarget {
        return fixed.target;
    }
};

/// Routes messages from `primary` to the primary half and from `secondary` to the other.
const BySender = struct {
    primary: Key,
    secondary: Key,

    pub fn route(by: BySender, message: *const Message) split.SplitTarget {
        if (message.peer.eql(by.primary)) return .primary;
        if (message.peer.eql(by.secondary)) return .secondary;
        @panic("unexpected sender");
    }
};

/// The primary half sends only to `primary`, the secondary half only to `secondary`.
const ByOrigin = struct {
    primary: Key,
    secondary: Key,

    pub fn forward(
        by: ByOrigin,
        origin: split.SplitOrigin,
        _: Recipients,
        _: []const u8,
    ) ?Recipients {
        return switch (origin) {
            .primary => .{ .one = by.primary },
            .secondary => .{ .one = by.secondary },
        };
    }
};

/// Keeps the original recipients.
const Keep = struct {
    pub fn forward(
        _: Keep,
        _: split.SplitOrigin,
        recipients: Recipients,
        _: []const u8,
    ) ?Recipients {
        return recipients;
    }
};

/// Drops every send.
const Drop = struct {
    pub fn forward(_: Drop, _: split.SplitOrigin, _: Recipients, _: []const u8) ?Recipients {
        return null;
    }
};

fn send_all(sender: anytype, payload: []const u8) !usize {
    const sent = try sender.send(.all, &.{payload}, false);
    defer testing.allocator.free(sent);
    return sent.len;
}

fn link_both(oracle: Net.Oracle, a: Key, b: Key) !void {
    try oracle.add_link(a, b, t.link_ms(0, 0, 1.0));
    try oracle.add_link(b, a, t.link_ms(0, 0, 1.0));
}

test "split receivers keep the channel capacity" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 3));
            defer harness.deinit();
            var registered = try harness.oracle().control(t.key(0)).register(0, .per_second(7));
            defer registered.sender.deinit();
            try testing.expectEqual(42, registered.receiver.capacity());
            const fixed: Fixed = .{ .target = .primary };
            var halves = try registered.receiver.split_with(testing.allocator, io, fixed);
            defer halves.primary.deinit();
            defer halves.secondary.deinit();
            try testing.expectEqual(42, halves.primary.capacity());
            try testing.expectEqual(42, halves.secondary.capacity());
        }
    }.run);
}

test "a split routes each half to a different neighbor" {
    // commonware `test_split_channel_single`.
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(3, 3));
            defer harness.deinit();
            const oracle = harness.oracle();
            const twin = t.key(20);
            const peer_a = t.key(21);
            const peer_b = t.key(22);
            try harness.track(&.{ twin, peer_a, peer_b });
            var a = try oracle.control(peer_a).register(0, t.test_quota);
            defer a.deinit();
            var b = try oracle.control(peer_b).register(0, t.test_quota);
            defer b.deinit();
            const registered = try oracle.control(twin).register(0, t.test_quota);
            const by_origin: ByOrigin = .{ .primary = peer_a, .secondary = peer_b };
            var senders = registered.sender.split_with(by_origin);
            defer senders.primary.deinit();
            defer senders.secondary.deinit();
            const by_sender: BySender = .{ .primary = peer_a, .secondary = peer_b };
            var receivers = try registered.receiver.split_with(testing.allocator, io, by_sender);
            defer receivers.primary.deinit();
            defer receivers.secondary.deinit();
            try link_both(oracle, peer_a, twin);
            try link_both(oracle, peer_b, twin);

            try testing.expectEqual(1, try t.send_one(&a.sender, twin, "from_a", false));
            try testing.expectEqual(1, try t.send_one(&b.sender, twin, "from_b", false));
            // Both halves check against all peers; the forwarder narrows each to one.
            try testing.expectEqual(2, try send_all(&senders.primary, "primary_out"));
            try testing.expectEqual(2, try send_all(&senders.secondary, "secondary_out"));

            try t.expect_message(&receivers.primary, peer_a, "from_a");
            try t.expect_message(&receivers.secondary, peer_b, "from_b");
            try t.expect_message(&a.receiver, twin, "primary_out");
            try t.expect_message(&b.receiver, twin, "secondary_out");
            // Nothing crossed halves.
            try io.sleep(.fromMilliseconds(100), .real);
            try testing.expectError(error.Empty, a.receiver.try_recv());
            try testing.expectError(error.Empty, b.receiver.try_recv());
            try testing.expectError(error.Empty, receivers.primary.try_recv());
            try testing.expectError(error.Empty, receivers.secondary.try_recv());
        }
    }.run);
}

test "a split targeting both delivers one message to each half" {
    // commonware `test_split_channel_both`.
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 3));
            defer harness.deinit();
            const oracle = harness.oracle();
            const twin = t.key(30);
            const peer_c = t.key(31);
            try harness.track(&.{ twin, peer_c });
            var c = try oracle.control(peer_c).register(0, t.test_quota);
            defer c.deinit();
            const registered = try oracle.control(twin).register(0, t.test_quota);
            var senders = registered.sender.split_with(Keep{});
            defer senders.primary.deinit();
            defer senders.secondary.deinit();
            const both: Fixed = .{ .target = .both };
            var receivers = try registered.receiver.split_with(testing.allocator, io, both);
            defer receivers.primary.deinit();
            defer receivers.secondary.deinit();
            try link_both(oracle, peer_c, twin);

            try testing.expectEqual(1, try t.send_one(&c.sender, twin, "to_both", false));
            try t.expect_message(&receivers.primary, peer_c, "to_both");
            try t.expect_message(&receivers.secondary, peer_c, "to_both");
        }
    }.run);
}

test "a split targeting none drops traffic both ways" {
    // commonware `test_split_channel_none`.
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 3));
            defer harness.deinit();
            const oracle = harness.oracle();
            const twin = t.key(30);
            const peer_c = t.key(31);
            try harness.track(&.{ twin, peer_c });
            var c = try oracle.control(peer_c).register(0, t.test_quota);
            defer c.deinit();
            const registered = try oracle.control(twin).register(0, t.test_quota);
            var senders = registered.sender.split_with(Drop{});
            defer senders.primary.deinit();
            defer senders.secondary.deinit();
            const none: Fixed = .{ .target = .none };
            var receivers = try registered.receiver.split_with(testing.allocator, io, none);
            defer receivers.primary.deinit();
            defer receivers.secondary.deinit();
            try link_both(oracle, peer_c, twin);

            const sent = try c.sender.send(.{ .one = twin }, &.{"to_both"}, false);
            defer testing.allocator.free(sent);
            try testing.expectEqual(1, sent.len);
            try testing.expect(sent[0].eql(twin));
            try io.sleep(.fromMilliseconds(100), .real);
            try testing.expectError(error.Empty, receivers.primary.try_recv());
            try testing.expectError(error.Empty, receivers.secondary.try_recv());

            try testing.expectEqual(0, try t.send_one(&senders.primary, peer_c, "to_both", false));
            const secondary = try t.send_one(&senders.secondary, peer_c, "to_both", false);
            try testing.expectEqual(0, secondary);
        }
    }.run);
}

test "split halves report the closed network once drained" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 3));
            const registered = try harness.oracle().control(t.key(0)).register(0, t.test_quota);
            var sender = registered.sender;
            defer sender.deinit();
            const fixed: Fixed = .{ .target = .both };
            var receivers = try registered.receiver.split_with(testing.allocator, io, fixed);
            defer receivers.primary.deinit();
            defer receivers.secondary.deinit();
            harness.deinit();
            try testing.expectError(error.NetworkClosed, receivers.primary.recv());
            try testing.expectError(error.NetworkClosed, receivers.secondary.recv());
        }
    }.run);
}
