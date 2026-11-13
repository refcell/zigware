//! Simulated network tests for links and peer sets (commonware `p2p/src/simulated/mod.rs`).

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const p2p = @import("../root.zig");
const t = @import("network_test.zig");

const Key = t.Key;
const Net = t.Net;
const key = t.key;
const set = t.set;
const delivered = t.delivered;
const expect_recipients = t.expect_recipients;
const quota = t.test_quota;

fn register(oracle: Net.Oracle, peer: Key) !Net.Registered {
    return oracle.control(peer).register(0, quota);
}

fn expect_no_message(io: Io, receiver: *Net.Receiver) !void {
    try io.sleep(.fromSeconds(1), .real);
    try testing.expectError(error.Empty, receiver.try_recv());
}

fn expect_tracked(manager: Net.Manager, id: u64, present: bool) !void {
    const owned = try manager.peer_set(testing.allocator, id);
    defer if (owned) |peers| peers.free(testing.allocator);
    try testing.expectEqual(present, owned != null);
}

fn expect_primary(manager: Net.Manager, id: u64, expected: []const Key) !void {
    const owned = (try manager.peer_set(testing.allocator, id)).?;
    defer owned.free(testing.allocator);
    try testing.expectEqual(expected.len, owned.primary.len);
    for (expected, owned.primary) |want, got| try testing.expect(Key.order(want, got) == .eq);
}

fn next_index(subscription: *Net.PeerSetSubscription) !u64 {
    var update = (try subscription.recv()).?;
    defer update.deinit();
    return update.index;
}

fn track(manager: Net.Manager, id: u64, keys: []const Key) !void {
    const sorted = try testing.allocator.dupe(Key, keys);
    defer testing.allocator.free(sorted);
    try testing.expectEqual(p2p.Feedback.ok, manager.track(id, .init_primary(set(sorted))));
}

test "dynamic links" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(0);
            const pk2 = key(1);
            var one = try register(oracle, pk1);
            defer one.deinit();
            var two = try register(oracle, pk2);
            defer two.deinit();
            try harness.track(&.{ pk1, pk2 });

            _ = try t.send_one(&one.sender, pk2, "attempt 1: hello from pk1", false);
            _ = try t.send_one(&two.sender, pk1, "attempt 1: hello from pk2", false);
            try expect_no_message(io, &one.receiver);
            try expect_no_message(io, &two.receiver);

            try oracle.add_link(pk1, pk2, t.link_ms(5, 2, 1.0));
            try oracle.add_link(pk2, pk1, t.link_ms(5, 2, 1.0));
            _ = try t.send_one(&one.sender, pk2, "attempt 2: hello from pk1", false);
            _ = try t.send_one(&two.sender, pk1, "attempt 2: hello from pk2", false);
            try t.expect_message(&one.receiver, pk2, "attempt 2: hello from pk2");
            try t.expect_message(&two.receiver, pk1, "attempt 2: hello from pk1");

            try oracle.remove_link(pk1, pk2);
            try oracle.remove_link(pk2, pk1);
            _ = try t.send_one(&one.sender, pk2, "attempt 3: hello from pk1", false);
            _ = try t.send_one(&two.sender, pk1, "attempt 3: hello from pk2", false);
            try expect_no_message(io, &one.receiver);
            try expect_no_message(io, &two.receiver);
            try testing.expectError(error.LinkMissing, oracle.remove_link(pk1, pk2));
        }
    }.run);
}

test "peer set window management" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 2));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pks = [_]Key{ key(1), key(2), key(3), key(4) };
            const manager = oracle.manager();
            try track(manager, 1, &.{ pks[0], pks[1] });
            var registered: [4]Net.Registered = undefined;
            for (&registered, pks) |*entry, pk| entry.* = try register(oracle, pk);
            defer for (&registered) |*entry| entry.deinit();
            for (pks) |a| for (pks) |b| {
                if (Key.order(a, b) != .eq) try oracle.add_link(a, b, t.link_ms(1, 0, 1.0));
            };

            try expect_recipients(&registered[0].sender, &.{pks[1]});
            try track(manager, 2, &.{ pks[1], pks[2] });
            try expect_tracked(manager, 2, true);
            const reach1 = try t.all_recipients(&registered[0].sender);
            defer testing.allocator.free(reach1);
            try testing.expect(contains(reach1, pks[2]));

            // Set 3 evicts set 1.
            try track(manager, 3, &.{ pks[2], pks[3] });
            try expect_tracked(manager, 3, true);
            const reach2 = try t.all_recipients(&registered[1].sender);
            defer testing.allocator.free(reach2);
            try testing.expect(!contains(reach2, pks[0]));
            try testing.expect(contains(reach2, pks[2]));
            const reach3 = try t.all_recipients(&registered[2].sender);
            defer testing.allocator.free(reach3);
            try testing.expect(contains(reach3, pks[3]));

            var two = [_]Key{ pks[1], pks[2] };
            try expect_primary(manager, 2, set(&two).items);
            var three = [_]Key{ pks[2], pks[3] };
            try expect_primary(manager, 3, set(&three).items);
            try expect_tracked(manager, 1, false);
        }
    }.run);
}

fn contains(keys: []const Key, wanted: Key) bool {
    for (keys) |candidate| if (Key.order(candidate, wanted) == .eq) return true;
    return false;
}

test "connected subscription updates after track" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 2));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            var one = try register(oracle, pk1);
            defer one.deinit();
            try expect_recipients(&one.sender, &.{});
            const manager = oracle.manager();
            try track(manager, 1, &.{ pk1, pk2 });
            try expect_tracked(manager, 1, true);
            try expect_recipients(&one.sender, &.{pk2});
        }
    }.run);
}

test "sender removed from peer set drops message" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const manager = oracle.manager();
            var subscription = try manager.subscribe();
            defer subscription.deinit();
            const sender_pk = key(1);
            const recipient_pk = key(2);
            try track(manager, 1, &.{ sender_pk, recipient_pk });
            try testing.expectEqual(1, try next_index(&subscription));
            var one = try register(oracle, sender_pk);
            defer one.deinit();
            var two = try register(oracle, recipient_pk);
            defer two.deinit();
            try oracle.add_link(sender_pk, recipient_pk, t.link_ms(1, 0, 1.0));

            try testing.expectEqual(1, try t.send_one(&one.sender, recipient_pk, "tracked", false));
            try t.expect_message(&two.receiver, sender_pk, "tracked");

            try track(manager, 2, &.{ recipient_pk, key(3) });
            try testing.expectEqual(2, try next_index(&subscription));
            // Explicit sends are accepted locally, but the network drops them.
            const attempted = try t.send_one(&one.sender, recipient_pk, "untracked", false);
            try testing.expectEqual(1, attempted);
            try io.sleep(.fromSeconds(10), .real);
            try testing.expectError(error.Empty, two.receiver.try_recv());

            try track(manager, 3, &.{ sender_pk, recipient_pk });
            try testing.expectEqual(3, try next_index(&subscription));
            try testing.expectEqual(1, try t.send_one(&one.sender, recipient_pk, "tracked", false));
            try t.expect_message(&two.receiver, sender_pk, "tracked");
        }
    }.run);
}

/// Links `a` and `b` both ways with 1 ms latency.
fn link_both(oracle: Net.Oracle, a: Key, b: Key) !void {
    try oracle.add_link(a, b, t.link_ms(1, 0, 1.0));
    try oracle.add_link(b, a, t.link_ms(1, 0, 1.0));
}

test "own peer sets require mutual tracking" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(3, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            const pk3 = key(3);
            const control1 = oracle.control(pk1);
            const control2 = oracle.control(pk2);
            var one = try register(oracle, pk1);
            defer one.deinit();
            var two = try register(oracle, pk2);
            defer two.deinit();
            try link_both(oracle, pk1, pk2);

            // A network-wide peer set connects the peers it lists.
            const global = oracle.manager();
            try track(global, 0, &.{ pk1, pk2 });
            try expect_recipients(&one.sender, &.{pk2});
            try testing.expect(try delivered(io, &one.sender, &two.receiver, pk2));

            // Resetting each peer's sets disconnects them.
            try control1.reset_peer_sets();
            try control2.reset_peer_sets();
            try oracle.control(pk3).reset_peer_sets();
            const manager1 = control1.manager();
            const manager2 = control2.manager();
            try expect_tracked(manager2, 0, false);
            try expect_recipients(&one.sender, &.{});
            try expect_recipients(&two.sender, &.{});
            try testing.expect(!try delivered(io, &one.sender, &two.receiver, pk2));

            // Tracking on one side only does not connect.
            try track(manager1, 0, &.{pk2});
            try track(manager2, 0, &.{pk3});
            try expect_tracked(manager2, 0, true);
            try expect_recipients(&one.sender, &.{});
            try testing.expect(!try delivered(io, &one.sender, &two.receiver, pk2));
            try testing.expect(!try delivered(io, &two.sender, &one.receiver, pk1));

            // Peers at different peer set ids connect while each tracks the other.
            try track(manager2, 5, &.{ pk1, pk3 });
            try expect_recipients(&one.sender, &.{pk2});
            try expect_recipients(&two.sender, &.{pk1});
            try testing.expect(try delivered(io, &one.sender, &two.receiver, pk2));
            try testing.expect(try delivered(io, &two.sender, &one.receiver, pk1));

            // Evicting the other peer on one side disconnects both directions.
            try track(manager1, 2, &.{pk3});
            try expect_recipients(&one.sender, &.{});
            try expect_recipients(&two.sender, &.{});
            try testing.expect(!try delivered(io, &one.sender, &two.receiver, pk2));
            try testing.expect(!try delivered(io, &two.sender, &one.receiver, pk1));
        }
    }.run);
}

test "own peer sets with network-wide peers" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(3, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            var one = try register(oracle, pk1);
            defer one.deinit();
            var two = try register(oracle, pk2);
            defer two.deinit();
            try link_both(oracle, pk1, pk2);

            // pk1 tracks pk2 at id 1 itself, so it ignores network-wide sets up to id 1.
            const manager1 = oracle.control(pk1).manager();
            try track(manager1, 1, &.{pk2});
            const global = oracle.manager();
            try track(global, 0, &.{key(3)});
            try expect_recipients(&one.sender, &.{});
            try expect_recipients(&two.sender, &.{});
            try testing.expect(!try delivered(io, &one.sender, &two.receiver, pk2));
            try testing.expect(!try delivered(io, &two.sender, &one.receiver, pk1));

            // A network-wide set listing pk1 connects them; pk1 keeps its own set at id 1.
            try track(global, 1, &.{pk1});
            try expect_primary(manager1, 1, &.{pk2});
            try expect_recipients(&one.sender, &.{pk2});
            try expect_recipients(&two.sender, &.{pk1});
            try testing.expect(try delivered(io, &one.sender, &two.receiver, pk2));
            try testing.expect(try delivered(io, &two.sender, &one.receiver, pk1));
        }
    }.run);
}

fn expect_update(
    subscription: *Net.PeerSetSubscription,
    index: u64,
    latest: ?[]const Key,
    all: ?[]const Key,
) !void {
    var update = (try subscription.recv()).?;
    defer update.deinit();
    try testing.expectEqual(index, update.index);
    if (latest) |expected| try expect_keys(expected, update.latest.primary);
    if (all) |expected| try expect_keys(expected, update.all.primary);
}

fn expect_keys(expected: []const Key, actual: []const Key) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try testing.expect(Key.order(want, got) == .eq);
}

test "own peer sets are reported separately" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 2));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            const pk3 = key(3);
            const global = oracle.manager();
            const own = oracle.control(pk1).manager();
            var global_updates = try global.subscribe();
            defer global_updates.deinit();
            var own_updates = try own.subscribe();
            defer own_updates.deinit();

            try track(own, 1, &.{pk2});
            try expect_update(&own_updates, 1, &.{pk2}, null);
            try expect_tracked(own, 1, true);
            try expect_tracked(global, 1, false);

            var both = [_]Key{ pk2, pk3 };
            const both_sorted = set(&both).items;
            try track(global, 3, &.{pk3});
            try expect_update(&global_updates, 3, null, null);
            try expect_update(&own_updates, 3, null, both_sorted);

            // The peer keeps two sets, so network-wide set 3 stays beside its own set 5.
            try track(own, 5, &.{pk2});
            try expect_update(&own_updates, 5, null, both_sorted);

            // Ignored: its own set at an id it holds, and a network-wide set at an older id.
            try track(own, 5, &.{pk3});
            try track(global, 4, &.{pk2});
            try expect_update(&global_updates, 4, null, null);
            try expect_primary(own, 5, &.{pk2});
            try expect_tracked(own, 4, false);

            // The ignored sets sent no update; the next one is for set 6.
            try track(global, 6, &.{pk3});
            try expect_update(&own_updates, 6, null, null);
        }
    }.run);
}

test "reset peer sets starts empty" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(3, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            const control1 = oracle.control(pk1);
            const control2 = oracle.control(pk2);
            var one = try register(oracle, pk1);
            defer one.deinit();
            var two = try register(oracle, pk2);
            defer two.deinit();
            try oracle.add_link(pk1, pk2, t.link_ms(1, 0, 1.0));

            // Each peer tracks the other through its own manager, so they connect.
            const manager1 = control1.manager();
            const manager2 = control2.manager();
            try track(manager2, 1, &.{pk1});
            try track(manager1, 2, &.{pk2});
            var updates = try manager1.subscribe();
            defer updates.deinit();
            try expect_update(&updates, 2, null, null);
            try expect_recipients(&two.sender, &.{pk1});
            try testing.expect(try delivered(io, &one.sender, &two.receiver, pk2));

            // Another manager for the same peer shares its sets.
            const shared = oracle.control(pk1).manager();
            try expect_tracked(shared, 2, true);
            try track(shared, 3, &.{pk2});
            try expect_update(&updates, 3, null, null);
            try testing.expect(try delivered(io, &one.sender, &two.receiver, pk2));

            // A reset forgets the sets, ends their subscriptions, and disconnects both sides.
            try control1.reset_peer_sets();
            try expect_tracked(manager1, 3, false);
            try testing.expect(try updates.recv() == null);
            try expect_recipients(&one.sender, &.{});
            try expect_recipients(&two.sender, &.{});
            try testing.expect(!try delivered(io, &one.sender, &two.receiver, pk2));

            // An id older than the forgotten sets is accepted.
            try track(manager1, 1, &.{pk2});
            try expect_tracked(manager1, 1, true);
            try testing.expect(try delivered(io, &one.sender, &two.receiver, pk2));
        }
    }.run);
}

test "own peer sets limit connected peers" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(3, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            const pk3 = key(3);
            var one = try register(oracle, pk1);
            defer one.deinit();
            var two = try register(oracle, pk2);
            defer two.deinit();
            var three = try register(oracle, pk3);
            defer three.deinit();
            try oracle.add_link(pk1, pk2, t.link_ms(1, 0, 1.0));
            try oracle.add_link(pk1, pk3, t.link_ms(1, 0, 1.0));

            // pk2 tracks pk1 as a secondary peer; pk3 has no peer sets.
            const manager1 = oracle.control(pk1).manager();
            const manager2 = oracle.control(pk2).manager();
            const secondary = [_]Key{pk1};
            const tracked: t.Tracked = .{ .primary = .init(&.{}), .secondary = .init(&secondary) };
            try testing.expectEqual(p2p.Feedback.ok, manager2.track(1, tracked));
            try track(manager1, 1, &.{ pk2, pk3 });
            try expect_tracked(manager1, 1, true);

            try expect_recipients(&one.sender, &.{pk2});
            testing.allocator.free(try one.sender.send(.all, &.{"ping"}, false));
            var message = try two.receiver.recv();
            message.deinit();
            try expect_no_message(io, &three.receiver);
        }
    }.run);
}

test "network-wide peer sets reach every peer" {
    _ = try t.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try t.Harness.start(io, t.config(2, 3));
            defer harness.deinit();
            const oracle = harness.oracle();
            const pk1 = key(1);
            const pk2 = key(2);
            const global = oracle.manager();
            try track(global, 0, &.{pk1});
            try track(global, 1, &.{key(3)});

            // pk2 is created by a query through its own manager and starts with both sets.
            const control2 = oracle.control(pk2);
            const manager2 = control2.manager();
            try expect_tracked(manager2, 0, true);
            try expect_tracked(manager2, 1, true);

            var one = try register(oracle, pk1);
            defer one.deinit();
            var two = try register(oracle, pk2);
            defer two.deinit();
            try link_both(oracle, pk1, pk2);
            try testing.expect(!try delivered(io, &two.sender, &one.receiver, pk1));

            // A set listing only pk2 connects them: pk2 still tracks pk1 through set 0.
            try track(global, 2, &.{pk2});
            try testing.expect(try delivered(io, &two.sender, &one.receiver, pk1));
            try testing.expect(try delivered(io, &one.sender, &two.receiver, pk2));

            // Resetting pk2 empties its sets; the network-wide sets stay.
            try control2.reset_peer_sets();
            try expect_tracked(manager2, 2, false);
            try expect_tracked(global, 2, true);
            try testing.expect(!try delivered(io, &two.sender, &one.receiver, pk1));

            // The next network-wide set reaches the reset peer and reconnects them.
            try track(global, 3, &.{ pk1, pk2 });
            try testing.expect(try delivered(io, &two.sender, &one.receiver, pk1));
        }
    }.run);
}
