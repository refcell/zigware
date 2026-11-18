//! Simulated network peer-set ordering, role, and broadcast tests (commonware
//! `p2p/src/simulated/network.rs` tests). `test_get_next_socket` has no counterpart: links
//! deliver into channels directly instead of over sockets the network assigns.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const p2p = @import("../root.zig");
const t = @import("network_test.zig");

const Key = t.Key;
const Net = t.Net;
const key = t.key;

/// Tracked peers with primary `primary` and secondary `secondary`, sorted in place.
fn tracked(primary: []Key, secondary: []Key) t.Tracked {
    return .{ .primary = t.set(primary), .secondary = t.set(secondary) };
}

fn contains(keys: []const Key, wanted: Key) bool {
    for (keys) |peer| {
        if (peer.eql(wanted)) return true;
    }
    return false;
}

fn expect_set(expected: []const Key, actual: []const Key) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected) |peer| try testing.expect(contains(actual, peer));
}

fn unordered_peer_sets(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 3));
    defer harness.deinit();
    const manager = harness.oracle().manager();
    var updates = try manager.subscribe();
    defer updates.deinit();
    const pk1 = key(1);
    const pk2 = key(2);
    const pk3 = key(3);
    const pk4 = key(4);
    var none = [_]Key{};
    var first = [_]Key{ pk1, pk2 };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(10, tracked(&first, &none)));
    {
        var update = (try updates.recv()).?;
        defer update.deinit();
        try testing.expectEqual(10, update.index);
        try expect_set(&.{ pk1, pk2 }, update.latest.primary);
        try expect_set(&.{ pk1, pk2 }, update.all.primary);
        try testing.expectEqual(0, update.all.secondary.len);
    }
    // An older index and a repeated one are ignored, so the next update is index 11.
    var older = [_]Key{pk3};
    _ = manager.track(9, tracked(&older, &none));
    var repeated = [_]Key{pk3};
    _ = manager.track(10, tracked(&repeated, &none));
    var newer = [_]Key{pk4};
    try testing.expectEqual(p2p.Feedback.ok, manager.track(11, tracked(&newer, &none)));
    var update = (try updates.recv()).?;
    defer update.deinit();
    try testing.expectEqual(11, update.index);
    try expect_set(&.{pk4}, update.latest.primary);
    try expect_set(&.{ pk1, pk2, pk4 }, update.all.primary);
    try testing.expectEqual(0, update.all.secondary.len);
}

test "peer sets tracked out of order are ignored" {
    // commonware `test_unordered_peer_sets`.
    _ = try t.run_deterministic(0, unordered_peer_sets);
}

fn cross_index_primary_wins(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(3, 3));
    defer harness.deinit();
    const manager = harness.oracle().manager();
    var updates = try manager.subscribe();
    defer updates.deinit();
    const pk_a = key(21);
    const pk_b = key(22);
    const pk_overlap = key(23);
    const pk_secondary = key(24);
    var none = [_]Key{};
    var first = [_]Key{ pk_a, pk_overlap };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(10, tracked(&first, &none)));
    {
        var update = (try updates.recv()).?;
        update.deinit();
    }
    var primary = [_]Key{pk_b};
    var secondary = [_]Key{ pk_overlap, pk_secondary };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(11, tracked(&primary, &secondary)));
    var update = (try updates.recv()).?;
    defer update.deinit();
    try testing.expectEqual(11, update.index);
    try expect_set(&.{pk_b}, update.latest.primary);
    try expect_set(&.{ pk_overlap, pk_secondary }, update.latest.secondary);
    try expect_set(&.{ pk_a, pk_b, pk_overlap }, update.all.primary);
    // The union's secondaries omit peers primary in any tracked set.
    try expect_set(&.{pk_secondary}, update.all.secondary);
}

test "a peer primary at one index is not secondary in the union" {
    // commonware `test_peer_set_update_all_cross_index_primary_wins`.
    _ = try t.run_deterministic(0, cross_index_primary_wins);
}

fn register(oracle: Net.Oracle, peer: Key) !Net.Registered {
    return oracle.control(peer).register(0, t.test_quota);
}

fn overlapping_roles_one_send(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(3, 3));
    defer harness.deinit();
    const oracle = harness.oracle();
    const manager = oracle.manager();
    const pk1 = key(1);
    const pk2 = key(2);
    const pk3 = key(3);
    var primary = [_]Key{ pk1, pk2 };
    var secondary = [_]Key{ pk2, pk3 };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(0, tracked(&primary, &secondary)));
    for ([_][2]Key{ .{ pk1, pk2 }, .{ pk1, pk3 }, .{ pk2, pk3 } }) |pair| {
        try oracle.add_link(pair[0], pair[1], t.link_ms(1, 0, 1.0));
    }
    var one = try register(oracle, pk1);
    defer one.deinit();
    var two = try register(oracle, pk2);
    defer two.deinit();
    var three = try register(oracle, pk3);
    defer three.deinit();
    const checked = switch (try one.sender.check(.all)) {
        .checked => |checked| checked,
        .limited => return error.TestUnexpectedResult,
    };
    var count_2: usize = 0;
    for (checked.recipients()) |peer| count_2 += @intFromBool(peer.eql(pk2));
    try testing.expectEqual(1, count_2);
    try testing.expect(contains(checked.recipients(), pk3));
    const payload: [10]u8 = @splat(42);
    _ = checked.send(&.{&payload}, true);
    try io.sleep(.fromMilliseconds(10), .real);
    try t.expect_message(&two.receiver, pk1, &payload);
    try t.expect_message(&three.receiver, pk1, &payload);
    try testing.expectError(error.Empty, two.receiver.try_recv());
}

test "a peer in both roles receives one copy of a broadcast" {
    // commonware `test_overlapping_primary_secondary_no_duplicate_recipients`.
    _ = try t.run_deterministic(0, overlapping_roles_one_send);
}

fn now_ns(io: Io) i96 {
    return Io.Clock.real.now(io).nanoseconds;
}

fn broadcast_shares_bandwidth(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(3, 3));
    defer harness.deinit();
    const oracle = harness.oracle();
    const sender_key = key(42);
    const recipient_a = key(43);
    const recipient_b = key(44);
    try harness.track(&.{ sender_key, recipient_a, recipient_b });
    var sending = try register(oracle, sender_key);
    defer sending.deinit();
    var a = try register(oracle, recipient_a);
    defer a.deinit();
    var b = try register(oracle, recipient_b);
    defer b.deinit();
    try oracle.limit_bandwidth(sender_key, 1_000, null);
    try oracle.limit_bandwidth(recipient_a, null, 1_000);
    try oracle.limit_bandwidth(recipient_b, null, 1_000);
    try oracle.add_link(sender_key, recipient_a, t.link_ms(0, 0, 1.0));
    try oracle.add_link(sender_key, recipient_b, t.link_ms(0, 0, 1.0));
    const payload: [10_000]u8 = @splat(7);
    const sent = try sending.sender.send(.all, &.{&payload}, false);
    defer testing.allocator.free(sent);
    try testing.expectEqual(2, sent.len);
    const start = now_ns(io);
    // Both transfers share the sender's 1,000 bytes per second: about 20 s each.
    try t.expect_message(&a.receiver, sender_key, &payload);
    const elapsed_a = now_ns(io) - start;
    try t.expect_message(&b.receiver, sender_key, &payload);
    const elapsed_b = now_ns(io) - start;
    try testing.expect(elapsed_a >= 20 * std.time.ns_per_s);
    try testing.expect(elapsed_b >= 20 * std.time.ns_per_s);
    try testing.expect(@abs(elapsed_a - elapsed_b) <= std.time.ns_per_s);
}

test "a broadcast shares the sender's bandwidth across recipients" {
    // commonware `test_broadcast_respects_transmit_latency`.
    _ = try t.run_deterministic(0, broadcast_shares_bandwidth);
}

fn dynamic_peers(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 1));
    defer harness.deinit();
    const oracle = harness.oracle();
    const pk1 = key(0);
    const pk2 = key(1);
    // Channels are registered before the peers are tracked.
    var one = try register(oracle, pk1);
    defer one.deinit();
    var two = try register(oracle, pk2);
    defer two.deinit();
    try harness.track(&.{ pk1, pk2 });
    try oracle.add_link(pk1, pk2, t.link_ms(5, 2, 1.0));
    try oracle.add_link(pk2, pk1, t.link_ms(5, 2, 1.0));
    _ = try t.send_one(&one.sender, pk2, "attempt 1: hello from pk1", false);
    _ = try t.send_one(&two.sender, pk1, "attempt 1: hello from pk2", false);
    try t.expect_message(&one.receiver, pk2, "attempt 1: hello from pk2");
    try t.expect_message(&two.receiver, pk1, "attempt 1: hello from pk1");
}

test "peers registered before they are tracked exchange messages" {
    // commonware `test_dynamic_peers`.
    _ = try t.run_deterministic(0, dynamic_peers);
}
