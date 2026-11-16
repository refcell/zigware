//! Simulated network peer-set sizing and seeding tests (commonware
//! `p2p/src/simulated/network.rs` tests). commonware's `should_panic` sizing tests
//! (`test_max_peers_per_set_rejects_primary_secondary_union`,
//! `test_max_peers_per_set_counts_omitted_owner`) have no in-process counterpart: the network
//! panics with the same message ("peer set too large: 3 > 2").

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

fn expect_counts(network: *Net, peer: Key, primary: u32, secondary: u32) !void {
    const counts = network.network_tracker.counts.get(peer).?;
    try testing.expectEqual(primary, counts.primary);
    try testing.expectEqual(secondary, counts.secondary);
}

fn split_peers_seed_initial_update(io: Io) !void {
    var primary = [_]Key{key(11)};
    var secondary = [_]Key{key(12)};
    const peers = tracked(&primary, &secondary);
    const network = try Net.init_with_peers(testing.allocator, io, t.config(2, 3), peers);
    defer network.deinit();
    const manager = network.oracle().manager();
    const owned = (try manager.peer_set(testing.allocator, 0)).?;
    defer owned.free(testing.allocator);
    try testing.expectEqualSlices(Key, &primary, owned.primary);
    try testing.expectEqualSlices(Key, &secondary, owned.secondary);
    var updates = try manager.subscribe();
    defer updates.deinit();
    var update = (try updates.recv()).?;
    defer update.deinit();
    try testing.expectEqual(0, update.index);
    try testing.expectEqualSlices(Key, &primary, update.latest.primary);
    try testing.expectEqualSlices(Key, &secondary, update.latest.secondary);
    try testing.expectEqualSlices(Key, &primary, update.all.primary);
    try testing.expectEqualSlices(Key, &secondary, update.all.secondary);
}

test "a network seeded with split peers reports them at index 0" {
    // commonware `test_new_with_split_peers_seeds_initial_update`.
    _ = try t.run_deterministic(0, split_peers_seed_initial_update);
}

fn larger_union_across_sets(io: Io) !void {
    const network = try Net.init(testing.allocator, io, t.config(2, 2));
    defer network.deinit();
    const manager = network.oracle().manager();
    // Each set holds two identities; their union may be larger than either.
    var first_primary = [_]Key{key(1)};
    var first_secondary = [_]Key{key(2)};
    try testing.expectEqual(p2p.Feedback.ok, manager.track(0, tracked(
        &first_primary,
        &first_secondary,
    )));
    var second_primary = [_]Key{key(2)};
    var second_secondary = [_]Key{key(3)};
    try testing.expectEqual(p2p.Feedback.ok, manager.track(1, tracked(
        &second_primary,
        &second_secondary,
    )));
    try testing.expectEqual(3, network.network_tracker.counts.count());
}

test "max_peers_per_set bounds each set, not the union across sets" {
    // commonware `test_max_peers_per_set_allows_larger_union_across_sets`.
    _ = try t.run_deterministic(0, larger_union_across_sets);
}

fn listed_owner_counts_once(io: Io) !void {
    const network = try Net.init(testing.allocator, io, t.config(2, 1));
    defer network.deinit();
    const owner = key(1);
    // The owner and one other peer fill the limit, so the set is accepted.
    var primary = [_]Key{ owner, key(2) };
    const own = network.oracle().control(owner).manager();
    var none = [_]Key{};
    try testing.expectEqual(p2p.Feedback.ok, own.track(0, tracked(&primary, &none)));
    const owned = (try own.peer_set(testing.allocator, 0)).?;
    defer owned.free(testing.allocator);
    try testing.expectEqual(2, owned.primary.len);
}

test "a set tracked through a peer's own manager counts a listed owner once" {
    // commonware `test_max_peers_per_set_counts_listed_owner_once`.
    _ = try t.run_deterministic(0, listed_owner_counts_once);
}

fn deduplicates_roles_and_sets(io: Io) !void {
    const network = try Net.init(testing.allocator, io, t.config(2, 2));
    defer network.deinit();
    const manager = network.oracle().manager();
    const peer_1 = key(1);
    const peer_2 = key(2);
    // Within a set, a primary identity is not also counted as secondary. Across retained
    // sets, each identity may still hold one reference in each role.
    var first_primary = [_]Key{peer_1};
    var first_secondary = [_]Key{ peer_1, peer_2 };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(0, tracked(
        &first_primary,
        &first_secondary,
    )));
    var second_primary = [_]Key{peer_2};
    var second_secondary = [_]Key{peer_1};
    try testing.expectEqual(p2p.Feedback.ok, manager.track(1, tracked(
        &second_primary,
        &second_secondary,
    )));
    try testing.expectEqual(2, network.network_tracker.counts.count());
    try expect_counts(network, peer_1, 1, 1);
    try expect_counts(network, peer_2, 1, 1);
}

test "peer-set sizing deduplicates roles within a set and counts across sets" {
    // commonware `test_peer_set_size_deduplicates_roles_and_sets`.
    _ = try t.run_deterministic(0, deduplicates_roles_and_sets);
}

const codec = @import("codec");
const SocketManager = Net.SocketManager;
const PeerMap = SocketManager.PeerMap;

fn socket_address(a: u8, b: u8, c: u8, d: u8, port: u16) p2p.Address {
    return .{ .symmetric = .{ .ip = .{ .v4 = codec.Ipv4.init(a, b, c, d) }, .port = port } };
}

/// A map of `entries`, sorted in place.
fn peer_map(entries: []PeerMap.Entry) PeerMap {
    PeerMap.sort(entries);
    return .init(entries);
}

/// Asserts the owned set at `id` has `primary` and `secondary` (each compared as a set).
fn expect_owned(manager: anytype, id: u64, primary: []const Key, secondary: []const Key) !void {
    const owned = (try manager.peer_set(testing.allocator, id)).?;
    defer owned.free(testing.allocator);
    try expect_keys(primary, owned.primary);
    try expect_keys(secondary, owned.secondary);
}

fn expect_keys(expected: []const Key, actual: []const Key) !void {
    var sorted: [4]Key = undefined;
    @memcpy(sorted[0..expected.len], expected);
    t.Tracked.PeerSet.sort(sorted[0..expected.len]);
    try testing.expectEqualSlices(Key, sorted[0..expected.len], actual);
}

fn socket_manager_tracks(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 3));
    defer harness.deinit();
    const manager = harness.oracle().socket_manager();
    const pk1 = key(1);
    const pk2 = key(2);
    var both = [_]PeerMap.Entry{
        .{ .key = pk1, .value = socket_address(127, 0, 0, 1, 4000) },
        .{ .key = pk2, .value = socket_address(127, 0, 0, 1, 4001) },
    };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(1, .init_primary(peer_map(&both))));
    try expect_owned(manager, 1, &.{ pk1, pk2 }, &.{});
    var updates = try manager.subscribe();
    defer updates.deinit();
    {
        var update = (try updates.recv()).?;
        defer update.deinit();
        try testing.expectEqual(1, update.index);
        try expect_keys(&.{ pk1, pk2 }, update.latest.primary);
        try expect_keys(&.{ pk1, pk2 }, update.all.primary);
        try testing.expectEqual(0, update.all.secondary.len);
    }
    var second = [_]PeerMap.Entry{.{ .key = pk2, .value = socket_address(127, 0, 0, 1, 4001) }};
    try testing.expectEqual(p2p.Feedback.ok, manager.track(2, .init_primary(peer_map(&second))));
    var update = (try updates.recv()).?;
    defer update.deinit();
    try testing.expectEqual(2, update.index);
    try expect_keys(&.{pk2}, update.latest.primary);
    try expect_keys(&.{ pk1, pk2 }, update.all.primary);
    // The simulated network ignores addresses, so overwriting one does nothing.
    var moved = [_]PeerMap.Entry{.{ .key = pk1, .value = socket_address(127, 0, 0, 1, 8000) }};
    try testing.expectEqual(p2p.Feedback.ok, manager.overwrite(peer_map(&moved)));
    try expect_owned(manager, 2, &.{pk2}, &.{});
}

test "the socket manager tracks peer sets by key and ignores addresses" {
    // commonware `test_socket_manager` and `test_socket_manager_overwrite`.
    _ = try t.run_deterministic(0, socket_manager_tracks);
}

fn socket_manager_roles(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 3));
    defer harness.deinit();
    const manager = harness.oracle().socket_manager();
    const pk1 = key(1);
    const pk2 = key(2);
    var primary = [_]PeerMap.Entry{.{ .key = pk1, .value = socket_address(127, 0, 0, 1, 4000) }};
    var secondary = [_]PeerMap.Entry{.{ .key = pk2, .value = socket_address(127, 0, 0, 1, 4001) }};
    const peers: SocketManager.Tracked = .{
        .primary = peer_map(&primary),
        .secondary = peer_map(&secondary),
    };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(7, peers));
    try expect_owned(manager, 7, &.{pk1}, &.{pk2});
}

test "the socket manager keeps primary and secondary roles" {
    // commonware `test_socket_manager_track_accepts_addressable_tracked_peers`.
    _ = try t.run_deterministic(0, socket_manager_roles);
}

fn socket_manager_overlap(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(1, 3));
    defer harness.deinit();
    const manager = harness.oracle().socket_manager();
    var updates = try manager.subscribe();
    defer updates.deinit();
    const pk = key(1);
    var primary = [_]PeerMap.Entry{.{ .key = pk, .value = socket_address(127, 0, 0, 1, 4000) }};
    var secondary = [_]PeerMap.Entry{.{ .key = pk, .value = socket_address(127, 0, 0, 1, 5000) }};
    const peers: SocketManager.Tracked = .{
        .primary = peer_map(&primary),
        .secondary = peer_map(&secondary),
    };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(11, peers));
    var update = (try updates.recv()).?;
    defer update.deinit();
    try testing.expectEqual(11, update.index);
    try expect_keys(&.{pk}, update.latest.primary);
    try testing.expectEqual(0, update.latest.secondary.len);
    try testing.expectEqual(0, update.all.secondary.len);
}

test "a key in both addressable maps is tracked as primary only" {
    // commonware `test_socket_manager_track_addressable_overlap_primary_wins`.
    _ = try t.run_deterministic(0, socket_manager_overlap);
}

fn socket_manager_asymmetric(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(2, 3));
    defer harness.deinit();
    const manager = harness.oracle().socket_manager();
    const pk1 = key(1);
    const pk2 = key(2);
    const egress_1 = socket_address(192, 168, 1, 1, 9090).symmetric;
    const egress_2 = socket_address(192, 168, 1, 2, 9090).symmetric;
    const host = @import("utils").Hostname.literal("node2.example.com");
    var both = [_]PeerMap.Entry{
        .{ .key = pk1, .value = .{ .asymmetric = .{
            .ingress = .{ .socket = socket_address(10, 0, 0, 1, 8080).symmetric },
            .egress = egress_1,
        } } },
        .{ .key = pk2, .value = .{ .asymmetric = .{
            .ingress = .{ .dns = .{ .host = host, .port = 8080 } },
            .egress = egress_2,
        } } },
    };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(1, .init_primary(peer_map(&both))));
    try expect_owned(manager, 1, &.{ pk1, pk2 }, &.{});
    var updates = try manager.subscribe();
    defer updates.deinit();
    var update = (try updates.recv()).?;
    defer update.deinit();
    try testing.expectEqual(1, update.index);
    try expect_keys(&.{ pk1, pk2 }, update.latest.primary);
    try testing.expectEqual(0, update.latest.secondary.len);
}

test "the socket manager accepts asymmetric and DNS addresses" {
    // commonware `test_socket_manager_with_asymmetric_addresses`.
    _ = try t.run_deterministic(0, socket_manager_asymmetric);
}

fn manager_roles(io: Io) !void {
    var harness = try t.Harness.start(io, t.config(3, 3));
    defer harness.deinit();
    const manager = harness.oracle().manager();
    const pk1 = key(1);
    const pk2 = key(2);
    const pk3 = key(3);
    var primary_7 = [_]Key{pk1};
    var secondary_7 = [_]Key{pk2};
    try testing.expectEqual(p2p.Feedback.ok, manager.track(7, tracked(&primary_7, &secondary_7)));
    try expect_owned(manager, 7, &.{pk1}, &.{pk2});
    // A key in both roles is primary only.
    var primary_9 = [_]Key{ pk1, pk2 };
    var secondary_9 = [_]Key{ pk2, pk3 };
    try testing.expectEqual(p2p.Feedback.ok, manager.track(9, tracked(&primary_9, &secondary_9)));
    try expect_owned(manager, 9, &.{ pk1, pk2 }, &.{pk3});
    var updates = try manager.subscribe();
    defer updates.deinit();
    var update = (try updates.recv()).?;
    defer update.deinit();
    try testing.expectEqual(9, update.index);
    try expect_keys(&.{ pk1, pk2 }, update.latest.primary);
    try expect_keys(&.{pk3}, update.latest.secondary);
    try expect_keys(&.{ pk1, pk2 }, update.all.primary);
    try expect_keys(&.{pk3}, update.all.secondary);
}

test "the manager keeps roles, and a key in both is primary only" {
    // commonware `test_manager_track_accepts_tracked_peers` and
    // `test_manager_track_tracked_peers_overlap_primary_wins` (one network, two sets).
    _ = try t.run_deterministic(0, manager_roles);
}
