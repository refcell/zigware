//! Simulated network channel and link tests (commonware `p2p/src/simulated/mod.rs` and
//! `network.rs` tests). commonware's `should_panic` tests (`test_message_too_big`,
//! `test_max_size_overflow_panics`) have no in-process counterpart: the network panics with
//! the same messages ("message too large", "maximum frame size overflow").

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const t = @import("network_test.zig");

const Key = t.Key;
const Net = t.Net;
const key = t.key;

/// A running network seeded with `peers` at id 0 (commonware `Network::new_with_peers`).
fn start_with_peers(io: Io, cfg: t.Config, peers: []const Key) !t.Harness {
    const sorted = try testing.allocator.dupe(Key, peers);
    defer testing.allocator.free(sorted);
    t.Tracked.PeerSet.sort(sorted);
    const tracked: t.Tracked = .init_primary(.init(sorted));
    const network = try Net.init_with_peers(testing.allocator, io, cfg, tracked);
    errdefer network.deinit();
    const task = try io.concurrent(Net.run, .{network});
    return .{ .io = io, .network = network, .task = task };
}

fn register(oracle: Net.Oracle, peer: Key, channel: u64) !Net.Registered {
    return oracle.control(peer).register(channel, t.test_quota);
}

fn duplicate_channel(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 1));
    defer harness.deinit();
    const oracle = harness.oracle();
    const me = key(0);
    const other = key(1);
    try oracle.add_link(me, other, t.link_ms(10, 1, 1.0));
    try oracle.add_link(other, me, t.link_ms(10, 1, 1.0));
    var mine = try register(oracle, me, 0);
    defer mine.sender.deinit();
    defer mine.receiver.deinit();
    var theirs = try register(oracle, other, 0);
    defer theirs.sender.deinit();
    defer theirs.receiver.deinit();
    try harness.track(&.{ me, other });

    try testing.expectEqual(1, try t.send_one(&mine.sender, other, "hello", false));
    try t.expect_message(&theirs.receiver, me, "hello");
    try testing.expectEqual(1, try t.send_one(&theirs.sender, me, "hello", false));
    try t.expect_message(&mine.receiver, other, "hello");

    // Registering the channel again replaces the first registration.
    var again = try register(oracle, me, 0);
    defer again.sender.deinit();
    defer again.receiver.deinit();
    try testing.expectEqual(1, try t.send_one(&again.sender, other, "hello again", false));
    try t.expect_message(&theirs.receiver, me, "hello again");
    try testing.expectEqual(1, try t.send_one(&theirs.sender, me, "hello again", false));
    try t.expect_message(&again.receiver, other, "hello again");

    // The original receiver is closed, and its sender handles the closed channel.
    try testing.expectError(error.NetworkClosed, mine.receiver.recv());
    _ = try t.send_one(&mine.sender, other, "hello again", false);
}

test "registering a channel again replaces the first registration" {
    // commonware `test_duplicate_channel`.
    _ = try t.run_deterministic(0, duplicate_channel);
}

fn link_before_registration(io: Io) !void {
    const pk1 = key(0);
    const pk2 = key(1);
    var harness = try start_with_peers(io, t.config(2, 3), &.{ pk1, pk2 });
    defer harness.deinit();
    const oracle = harness.oracle();
    try oracle.add_link(pk1, pk2, t.link_ms(0, 0, 1.0));
    var one = try register(oracle, pk1, 0);
    defer one.sender.deinit();
    defer one.receiver.deinit();
    var two = try register(oracle, pk2, 0);
    defer two.sender.deinit();
    defer two.receiver.deinit();
    _ = try t.send_one(&one.sender, pk2, "link-before-register-1", false);
    try t.expect_message(&two.receiver, pk1, "link-before-register-1");
}

test "a link added before channel registration delivers" {
    // commonware `test_add_link_before_channel_registration`.
    _ = try t.run_deterministic(0, link_before_registration);
}

fn register_and_link(io: Io) !void {
    const pk1 = key(1);
    const pk2 = key(2);
    var harness = try start_with_peers(io, t.config(2, 3), &.{ pk1, pk2 });
    defer harness.deinit();
    const oracle = harness.oracle();
    var registered: [5]Net.Registered = undefined;
    registered[0] = try register(oracle, pk1, 0);
    registered[1] = try register(oracle, pk1, 1);
    registered[2] = try register(oracle, pk2, 0);
    registered[3] = try register(oracle, pk2, 1);
    // Registering again overwrites the earlier registration.
    registered[4] = try register(oracle, pk2, 1);
    defer for (&registered) |*entry| {
        entry.sender.deinit();
        entry.receiver.deinit();
    };
    const link = t.link_ms(2, 1, 0.9);
    try oracle.add_link(pk1, pk2, link);
    try testing.expectError(error.LinkExists, oracle.add_link(pk1, pk2, link));
}

test "controls register channels and a link is added once" {
    // commonware `test_register_and_link`.
    _ = try t.run_deterministic(0, register_and_link);
}

/// Sends `payload` once `sender` reaches `expected` recipients (commonware `send_when_ready`).
fn send_when_ready(io: Io, sender: *Net.Sender, to: Key, payload: []const u8) !void {
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        try testing.expect(attempts < 10_000);
        switch (try sender.check(.{ .one = to })) {
            .checked => |checked| {
                if (checked.recipients().len == 1) {
                    _ = checked.send(&.{payload}, false);
                    return;
                }
                checked.deinit();
            },
            .limited => {},
        }
        try io.sleep(.fromMilliseconds(1), .real);
    }
}

fn max_size_applies_to_payload(io: Io) !void {
    const max_size = 64;
    var cfg = t.config(2, 1);
    cfg.max_size = max_size;
    var harness = try t.Harness.start(io, cfg);
    defer harness.deinit();
    const oracle = harness.oracle();
    const sender_key = key(1);
    const recipient_key = key(2);
    try harness.track(&.{ sender_key, recipient_key });
    var sending = try register(oracle, sender_key, 0);
    defer sending.sender.deinit();
    defer sending.receiver.deinit();
    var receiving = try register(oracle, recipient_key, 0);
    defer receiving.sender.deinit();
    defer receiving.receiver.deinit();
    try oracle.add_link(sender_key, recipient_key, t.link_ms(0, 0, 1.0));
    // The channel identifier rides outside the payload limit.
    const payload: [max_size]u8 = @splat(42);
    try send_when_ready(io, &sending.sender, recipient_key, &payload);
    try io.sleep(.fromSeconds(1), .real);
    var message = try receiving.receiver.try_recv();
    defer message.deinit();
    try testing.expect(message.peer.eql(sender_key));
    try testing.expectEqualSlices(u8, &payload, message.payload);
}

test "max_size limits the payload without the channel identifier" {
    // commonware `test_max_size_applies_to_payload`.
    _ = try t.run_deterministic(0, max_size_applies_to_payload);
}

fn fifo_burst_same_recipient(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 3));
    defer harness.deinit();
    const oracle = harness.oracle();
    const sender_key = key(10);
    const recipient_key = key(11);
    try harness.track(&.{ sender_key, recipient_key });
    var sending = try register(oracle, sender_key, 0);
    defer sending.sender.deinit();
    defer sending.receiver.deinit();
    var receiving = try register(oracle, recipient_key, 0);
    defer receiving.sender.deinit();
    defer receiving.receiver.deinit();
    try oracle.limit_bandwidth(sender_key, 5_000, null);
    try oracle.limit_bandwidth(recipient_key, null, 5_000);
    try oracle.add_link(sender_key, recipient_key, t.link_ms(0, 0, 1.0));
    const count = 50;
    for (0..count) |index| {
        const payload: [64]u8 = @splat(@intCast(index));
        const checked = switch (try sending.sender.check(.{ .one = recipient_key })) {
            .checked => |checked| checked,
            .limited => return error.TestUnexpectedResult,
        };
        _ = checked.send(&.{&payload}, false);
    }
    for (0..count) |index| {
        const payload: [64]u8 = @splat(@intCast(index));
        try t.expect_message(&receiving.receiver, sender_key, &payload);
    }
}

test "a burst to one recipient arrives in order under bandwidth limits" {
    // commonware `test_fifo_burst_same_recipient`.
    _ = try t.run_deterministic(0, fifo_burst_same_recipient);
}
