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
