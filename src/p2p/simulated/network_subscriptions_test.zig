//! Simulated network peer-set subscription and shutdown tests (commonware
//! `p2p/src/simulated/mod.rs` tests).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const p2p = @import("../root.zig");
const t = @import("network_test.zig");

const Key = t.Key;
const Net = t.Net;
const key = t.key;

/// Tracks `keys` (sorted here) as the primary set at `id`.
fn track(manager: Net.Manager, id: u64, keys: []const Key) !void {
    var sorted: [8]Key = undefined;
    std.debug.assert(keys.len <= sorted.len);
    @memcpy(sorted[0..keys.len], keys);
    const peers = t.set(sorted[0..keys.len]);
    try testing.expectEqual(p2p.Feedback.ok, manager.track(id, .init_primary(peers)));
}

/// Asserts `actual` holds exactly `expected`, compared as sets.
fn expect_set(expected: []const Key, actual: []const Key) !void {
    var sorted: [8]Key = undefined;
    std.debug.assert(expected.len <= sorted.len);
    @memcpy(sorted[0..expected.len], expected);
    t.Tracked.PeerSet.sort(sorted[0..expected.len]);
    try testing.expectEqual(expected.len, actual.len);
    for (sorted[0..expected.len], actual) |want, got| try testing.expect(want.eql(got));
}

/// Receives the next update and checks its index, latest primary, and union of primaries;
/// secondaries are always empty here.
fn expect_update(
    subscription: *Net.PeerSetSubscription,
    index: u64,
    latest: []const Key,
    all: []const Key,
) !void {
    var update = (try subscription.recv()).?;
    defer update.deinit();
    try testing.expectEqual(index, update.index);
    try expect_set(latest, update.latest.primary);
    try expect_set(all, update.all.primary);
    try testing.expectEqual(0, update.latest.secondary.len);
    try testing.expectEqual(0, update.all.secondary.len);
}

fn subscribe_to_peer_sets(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 2));
    defer harness.deinit();
    const manager = harness.oracle().manager();
    var subscription = try manager.subscribe();
    defer subscription.deinit();
    const pk1 = key(1);
    const pk2 = key(2);
    const pk3 = key(3);
    try track(manager, 1, &.{ pk1, pk2 });
    try expect_update(&subscription, 1, &.{ pk1, pk2 }, &.{ pk1, pk2 });
    try track(manager, 2, &.{ pk2, pk3 });
    try expect_update(&subscription, 2, &.{ pk2, pk3 }, &.{ pk1, pk2, pk3 });
    try track(manager, 3, &.{ pk1, pk3 });
    try expect_update(&subscription, 3, &.{ pk1, pk3 }, &.{ pk1, pk2, pk3 });
    // Two sets are kept: set 2 leaves, and with it pk2.
    try track(manager, 4, &.{ pk1, pk3 });
    try expect_update(&subscription, 4, &.{ pk1, pk3 }, &.{ pk1, pk3 });
}

test "a subscription reports each tracked set and the window's union" {
    // commonware `test_subscribe_to_peer_sets`.
    _ = try t.run_deterministic(0, subscribe_to_peer_sets);
}

fn next_index(subscription: *Net.PeerSetSubscription) !u64 {
    var update = (try subscription.recv()).?;
    defer update.deinit();
    return update.index;
}

fn multiple_subscriptions(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 3));
    defer harness.deinit();
    const manager = harness.oracle().manager();
    var subscriptions: [3]Net.PeerSetSubscription = undefined;
    for (&subscriptions) |*subscription| subscription.* = try manager.subscribe();
    defer subscriptions[0].deinit();
    defer subscriptions[2].deinit();
    const pk1 = key(1);
    const pk2 = key(2);
    try track(manager, 1, &.{ pk1, pk2 });
    for (&subscriptions) |*subscription| try testing.expectEqual(1, try next_index(subscription));
    // Dropping one subscription leaves the others notified.
    subscriptions[1].deinit();
    try track(manager, 2, &.{ pk1, pk2 });
    try testing.expectEqual(2, try next_index(&subscriptions[0]));
    try testing.expectEqual(2, try next_index(&subscriptions[2]));
}

test "every subscription is notified, and a dropped one is skipped" {
    // commonware `test_multiple_subscriptions`.
    _ = try t.run_deterministic(0, multiple_subscriptions);
}

fn includes_self_when_registered(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 2));
    defer harness.deinit();
    const oracle = harness.oracle();
    const self_key = key(0);
    const other = key(1);
    // Registering a channel creates the peer in the network.
    var registered = try oracle.control(self_key).register(0, t.test_quota);
    defer registered.deinit();
    const manager = oracle.manager();
    var subscription = try manager.subscribe();
    defer subscription.deinit();
    // A set without ourselves lists only the other peer.
    try track(manager, 1, &.{other});
    try expect_update(&subscription, 1, &.{other}, &.{other});
    // A set with ourselves lists both.
    try track(manager, 2, &.{ self_key, other });
    try expect_update(&subscription, 2, &.{ self_key, other }, &.{ self_key, other });
}

test "subscriptions list ourselves only when a set tracks us" {
    // commonware `test_subscription_includes_self_when_registered`.
    _ = try t.run_deterministic(0, includes_self_when_registered);
}

fn returns_current_peer_set(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 3));
    defer harness.deinit();
    const manager = harness.oracle().manager();
    const pk1 = key(0);
    const pk2 = key(1);
    try track(manager, 0, &.{ pk1, pk2 });
    // Subscribing after tracking yields the current set at once.
    var subscription = try manager.subscribe();
    defer subscription.deinit();
    var update = try subscription.try_recv();
    defer update.deinit();
    try testing.expectEqual(0, update.index);
    try expect_set(&.{ pk1, pk2 }, update.latest.primary);
    try testing.expectEqual(0, update.latest.secondary.len);
}

test "a new subscription starts with the current peer set" {
    // commonware `test_subscribe_returns_current_peer_set`.
    _ = try t.run_deterministic(0, returns_current_peer_set);
}

fn clean_shutdown(io: Io) !void {
    const gpa: Allocator = testing.allocator;
    const pk1 = key(1);
    const pk2 = key(2);
    var sorted = [_]Key{ pk1, pk2 };
    const tracked: t.Tracked = .init_primary(t.set(&sorted));
    const network = try Net.init_with_peers(gpa, io, t.config(2, 3), tracked);
    defer network.deinit();
    var task = try io.concurrent(Net.run, .{network});
    const oracle = network.oracle();
    var one = try oracle.control(pk1).register(0, t.test_quota);
    defer one.deinit();
    var two = try oracle.control(pk2).register(0, t.test_quota);
    defer two.deinit();
    try oracle.add_link(pk1, pk2, t.link_ms(10, 0, 1.0));
    try oracle.add_link(pk2, pk1, t.link_ms(10, 0, 1.0));
    try testing.expectEqual(1, try t.send_one(&one.sender, pk2, "test_message", false));
    try t.expect_message(&two.receiver, pk1, "test_message");
    // Canceling the run task stops it; nothing it ran keeps going.
    try testing.expectError(error.Canceled, task.cancel(io));
    try io.sleep(.fromSeconds(1), .real);
    // With the driver stopped, a send is accepted but never delivered.
    _ = try t.send_one(&one.sender, pk2, "after", false);
    try io.sleep(.fromSeconds(1), .real);
    try testing.expectError(error.Empty, two.receiver.try_recv());
}

test "canceling the network's run task stops it cleanly" {
    // commonware `test_clean_shutdown` (seeds 0..25).
    for (0..25) |seed| _ = try t.run_deterministic(seed, clean_shutdown);
}
