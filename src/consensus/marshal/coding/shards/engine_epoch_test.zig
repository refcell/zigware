//! Shard engine tests on hand-built engines (cross-epoch committees and a churning scheme
//! provider), ported from commonware `marshal/coding/shards/engine.rs`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Io = std.Io;
const parallel = @import("parallel");

const harness = @import("engine_harness.zig");

const gpa = harness.gpa;
const Key = harness.Key;
const PrivateKey = harness.PrivateKey;
const Net = harness.Net;
const Scheme = harness.Scheme;
const ShardEngine = harness.ShardEngine;
const metrics = harness.metrics;

/// A simulated network and engines started on it by hand.
const Sim = struct {
    const engines_max = 4;

    io: Io,
    network: *Net,
    network_task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    registry: *metrics.Registry,
    providers: [engines_max]harness.MultiEpochProvider = @splat(.{}),
    mailboxes: [engines_max]?harness.Mailbox = @splat(null),
    tasks: [engines_max]?Io.Future(ShardEngine.Error!void) = @splat(null),
    registrations: [engines_max]?Net.Registered = @splat(null),
    engines: usize = 0,
    registered: usize = 0,

    fn init(io: Io, config: @import("p2p").simulated.Config) !*Sim {
        const sim = try gpa.create(Sim);
        errdefer gpa.destroy(sim);
        const registry = try gpa.create(metrics.Registry);
        registry.* = .init(gpa);
        const network = try Net.init(gpa, io, config);
        sim.* = .{
            .io = io,
            .network = network,
            .network_task = try io.concurrent(Net.run, .{network}),
            .registry = registry,
        };
        return sim;
    }

    /// Registers `key` on channel 0 without an engine; the sender sends raw shards.
    fn register(sim: *Sim, key: Key) !*Net.Registered {
        assert(sim.registered < engines_max);
        const slot = &sim.registrations[sim.registered];
        slot.* = try sim.network.oracle().control(key).register(0, harness.test_quota);
        sim.registered += 1;
        return &slot.*.?;
    }

    fn link(sim: *Sim, from: Key, to: Key) !void {
        try sim.network.oracle().add_link(from, to, harness.default_link);
    }

    /// Starts an engine for `key` whose provider holds `schemes` (owned) at epochs 0, 1, ...
    /// With `remaining`, its epoch 0 lookups churn to null after that many.
    fn spawn(sim: *Sim, key: Key, schemes: []const Scheme, remaining: ?*i64) !harness.Mailbox {
        const index = sim.engines;
        assert(index < engines_max);
        for (schemes, 0..) |scheme, epoch| try sim.providers[index].add(epoch, scheme);
        const oracle = sim.network.oracle();
        const registered = try oracle.control(key).register(0, harness.test_quota);
        const scope = metrics.Scope.init(sim.registry).child("engine")
            .with_attribute("index", index);
        const created = try ShardEngine.init(gpa, sim.io, &scope, .{
            .scheme_provider = .{ .provider = &sim.providers[index], .remaining = remaining },
            .blocker = oracle.control(key),
            .block_codec_config = {},
            .strategy = parallel.sequential,
            .mailbox_size = 1024,
            .peer_buffer_size = 64,
            .records = 16,
            .peer_provider = oracle.manager(),
        });
        sim.mailboxes[index] = created.mailbox;
        sim.tasks[index] = try created.engine.start(registered.sender, registered.receiver);
        sim.engines += 1;
        return created.mailbox;
    }

    fn deinit(sim: *Sim) void {
        for (0..engines_max) |index| {
            if (sim.tasks[index]) |*future| {
                future.cancel(sim.io) catch |err| std.debug.panic("engine: {t}", .{err});
            }
            if (sim.mailboxes[index]) |*value| value.deinit();
            if (sim.registrations[index]) |*value| value.deinit();
            sim.providers[index].deinit();
        }
        sim.network.close();
        sim.network_task.await(sim.io) catch |err| std.debug.panic("run: {t}", .{err});
        sim.network.deinit();
        sim.registry.deinit();
        gpa.destroy(sim.registry);
        gpa.destroy(sim);
    }
};

fn set_of(keys: []const Key) !Scheme.Participants {
    return Scheme.Participants.init(gpa, keys);
}

fn signer(keys: []const Key, key: PrivateKey) !Scheme {
    return (try Scheme.signer(gpa, harness.scheme_namespace, try set_of(keys), key)).?;
}

/// The future peer (seed 4), a participant of epoch 1 only, buffers a shard for a commitment
/// that the receiver then gathers in a round of `epoch`.
fn buffered_shard_from_tracked_primary(io: Io, epoch: u64) !void {
    var config = harness.network_config(4, 4);
    config.max_peers_per_set = 2;
    const sim = try Sim.init(io, config);
    defer sim.deinit();
    // Epoch 0: seeds 0..4. Epoch 1: the first three of those and seed 4.
    var keys: [4]PrivateKey = undefined;
    var epoch0: [4]Key = undefined;
    harness.sorted_keys(&keys, &epoch0, 0);
    const future = PrivateKey.from_seed(4).public_key();
    var epoch1: [4]Key = .{ epoch0[0], epoch0[1], epoch0[2], future };
    std.sort.pdq(Key, &epoch1, {}, Key.less_than);
    const receiver = keys[0];
    const future_registration = try sim.register(future);
    try sim.link(future, receiver.public_key());
    try harness.track(sim.network, 0, &.{ receiver.public_key(), future }, &.{});
    try harness.sleep_ms(io, 10);
    const schemes = [_]Scheme{ try signer(&epoch0, receiver), try signer(&epoch1, receiver) };
    const mailbox = try sim.spawn(receiver.public_key(), &schemes, null);
    // Both epochs have four participants, so one coding config serves either.
    const coding_config = harness.types.coding_config_for_participants(4);
    var block = try harness.encode(coding_config, 1, 100);
    defer block.deinit(gpa);
    var epoch1_set = try set_of(&epoch1);
    defer epoch1_set.deinit(gpa);
    const future_index = epoch1_set.index(future).?.get();
    var shard = try harness.shard_of(&block, future_index);
    defer shard.deinit(gpa);
    try harness.send_shard(&future_registration.sender, receiver.public_key(), &shard);
    try harness.sleep_ms(io, 2 * harness.link_latency_ms);
    try testing.expectEqual(@as(usize, 0), try harness.blocked_count(sim.network));
    try mailbox.gather(block.commitment(), harness.round(epoch, 1));
    try harness.sleep_ms(io, 2 * harness.link_latency_ms);
    if (epoch == 1) {
        try testing.expectEqual(@as(usize, 0), try harness.blocked_count(sim.network));
    } else {
        try harness.expect_blocked(sim.network, receiver.public_key(), future);
    }
}

test "cross epoch buffered shard not blocked" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try buffered_shard_from_tracked_primary(io, 1);
        }
    }.run);
}

test "buffered shard from outside committee blocks sender on gather" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try buffered_shard_from_tracked_primary(io, 0);
        }
    }.run);
}

test "shard broadcast survives provider churn" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, harness.network_config(4, 4));
            defer sim.deinit();
            var keys: [4]PrivateKey = undefined;
            var peers: [4]Key = undefined;
            harness.sorted_keys(&keys, &peers, 0);
            // Peer 0 leads, peer 1 relays its assigned shard, and peer 2 reconstructs.
            const leader = try sim.register(peers[0]);
            for (peers) |from| for (peers) |to| if (!from.eql(to)) try sim.link(from, to);
            try harness.track(sim.network, 0, &peers, &.{});
            try harness.sleep_ms(io, 10);
            // The gather is one lookup and assigned-shard validation the second; any later
            // epoch 0 lookup churns to null.
            var remaining: i64 = 2;
            const relay_scheme = try signer(&peers, keys[1]);
            const relay = try sim.spawn(peers[1], &.{relay_scheme}, &remaining);
            const receiver_scheme = try signer(&peers, keys[2]);
            const receiver = try sim.spawn(peers[2], &.{receiver_scheme}, null);
            const coding_config = harness.types.coding_config_for_participants(4);
            var block = try harness.encode(coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try relay.gather(commitment, harness.at(1));
            try receiver.gather(commitment, harness.at(1));
            try harness.sleep_ms(io, harness.link_latency_ms);
            for ([_]usize{ 1, 2 }) |index| {
                var shard = try harness.shard_of(&block, index);
                defer shard.deinit(gpa);
                try harness.send_shard(&leader.sender, peers[index], &shard);
            }
            try harness.sleep_ms(io, 3 * harness.link_latency_ms);
            var got = (try receiver.get(commitment)) orelse return error.NotReconstructed;
            got.deinit(gpa);
        }
    }.run);
}
