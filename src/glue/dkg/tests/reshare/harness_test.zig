//! commonware `glue::dkg::tests::reshare::harness`'s unit tests: how a validator's peer manager
//! starts. Phase 1 covers the discovery network; the lookup network comes with its variant.

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p");
const runtime = @import("runtime");
const harness = @import("harness.zig");

const gpa = testing.allocator;
const Key = harness.Key;
const Net = p2p.simulated.Network(Key);

fn key(seed: u64) Key {
    return @import("cryptography").ed25519.PrivateKey.from_seed(seed).public_key();
}

fn expect_no_set(manager: Net.Manager, id: u64) !void {
    const owned = try manager.peer_set(gpa, id);
    if (owned) |set| set.free(gpa);
    try testing.expect(owned == null);
}

fn expect_primary(manager: Net.Manager, id: u64, expected: []const Key) !void {
    const owned = (try manager.peer_set(gpa, id)) orelse return error.MissingPeerSet;
    defer owned.free(gpa);
    try testing.expectEqual(expected.len, owned.primary.len);
    for (expected) |wanted| {
        for (owned.primary) |held| {
            if (held.eql(wanted)) break;
        } else return error.MissingPeer;
    }
}

/// How the harness builds a node's manager (commonware `Network::manager`).
fn node_manager(oracle: Net.Oracle, node: Key) !Net.Manager {
    const control = oracle.control(node);
    try control.reset_peer_sets();
    return control.manager();
}

fn empty_peer_sets_body(ctx: runtime.deterministic.Context) anyerror!void {
    const io = ctx.io();
    const network = try Net.init(gpa, io, .{
        .max_size = 1024,
        .max_peers_per_set = 2,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    });
    defer network.deinit();
    const node = key(1);
    const other = key(2);
    // Imitate the simulation plan by tracking both participants for every peer.
    var everyone = [_]Key{ node, other };
    const plan = network.oracle().manager();
    try testing.expectEqual(p2p.Feedback.ok, plan.track(0, .init_primary(.init(&everyone))));
    try expect_primary(plan, 0, &everyone);

    // A starting node's manager holds no peer sets.
    const manager = try node_manager(network.oracle(), node);
    try expect_no_set(manager, 0);

    // The node tracks its own set 0 and leaves the network-wide set unchanged.
    var mine = [_]Key{other};
    try testing.expectEqual(p2p.Feedback.ok, manager.track(0, .init_primary(.init(&mine))));
    try expect_primary(manager, 0, &mine);
    try expect_primary(plan, 0, &everyone);

    // A restarted node's manager holds no peer sets.
    const restarted = try node_manager(network.oracle(), node);
    try expect_no_set(restarted, 0);
}

// commonware `manager_starts_node_with_empty_peer_sets` (discovery).
test "reshare harness: a node's manager starts with empty peer sets" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(empty_peer_sets_body, .{});
}

// commonware `restart_after_epoch_zero_pruning_does_not_reseed_share`: a player whose store
// pruned its epoch-zero share stays without it after a restart, and still registers a scheme
// that reports its committee position.
test "reshare harness: a restart after pruning epoch zero does not reseed the share" {
    var engine = try harness.ReshareEngine.create(gpa);
    defer engine.deinit();
    const players = engine.initial.output.players;
    const player = players.items[0];
    const index = for (engine.participants(), 0..) |participant, at| {
        if (participant.eql(player)) break at;
    } else unreachable; // Every epoch-zero player is a participant.
    const store = &engine.stores[index];
    try testing.expect(store.has_share(.zero()));
    try store.prune(.new(1));
    try testing.expect(try store.get_share(.zero()) == null);

    const V = harness.Validator;
    var provider: V.Provider = .{
        .gpa = gpa,
        .namespace = @import("validator.zig").namespace,
        .key = player,
        .ledger = null,
    };
    defer provider.deinit();
    const scheme = try V.install_epoch_zero(gpa, &provider, &engine.initial, player, store);
    const membership = scheme.me() orelse return error.NotAMember;
    try testing.expect(membership == .member);
    try testing.expectEqual(0, membership.index().index);
}
