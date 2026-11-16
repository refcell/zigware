//! Shard engine tests, ported from commonware `marshal/coding/shards/engine.rs`, on the
//! simulated network and the deterministic runtime.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;

const harness = @import("engine_harness.zig");
const oneshot = harness.oneshot;

const gpa = harness.gpa;
const Coded = harness.Coded;
const Fixture = harness.Fixture;
const Unstarted = harness.Unstarted;
const at = harness.at;
const sleep_ms = harness.sleep_ms;

/// Waits for the local assigned shard of `commitment` to verify.
fn expect_assigned(mailbox: harness.Mailbox, commitment: Coded.Commitment) !void {
    var receiver = try mailbox.subscribe_assigned_shard_verified(commitment);
    defer receiver.deinit();
    try receiver.recv();
}

fn expect_reconstructed(mailbox: harness.Mailbox, expected: *const Coded) !void {
    var got = (try mailbox.get(expected.commitment())) orelse return error.NotReconstructed;
    defer got.deinit(gpa);
    try testing.expect(got.commitment().eql(expected.commitment()));
    try testing.expectEqual(expected.height().get(), got.height().get());
}

fn expect_cached(mailbox: harness.Mailbox, commitment: Coded.Commitment, cached: bool) !void {
    var got = try mailbox.get(commitment);
    defer if (got) |*value| value.deinit(gpa);
    try testing.expectEqual(cached, got != null);
}

test "e2e dispersal and reconstruction" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try fixture.mailbox(0).disperse(at(1), block.clone());
            // Inform every other peer of the commitment so it processes the shards.
            for (1..10) |index| try fixture.mailbox(index).gather(commitment, at(1));
            try fixture.latency(1);
            for (0..10) |index| try expect_assigned(fixture.mailbox(index), commitment);
            try fixture.latency(1);
            for (0..10) |index| try expect_reconstructed(fixture.mailbox(index), &block);
        }
    }.run);
}

fn expect_block(got: Coded, expected: *const Coded) !void {
    var owned = got;
    defer owned.deinit(gpa);
    try testing.expect(owned.commitment().eql(expected.commitment()));
    try testing.expectEqual(expected.height().get(), owned.height().get());
}

test "block subscriptions" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            // Subscribe before dispersing.
            var by_commitment = try fixture.mailbox(1).subscribe(commitment);
            defer by_commitment.deinit();
            var by_digest = try fixture.mailbox(2).subscribe_by_digest(block.digest());
            defer by_digest.deinit();
            try fixture.mailbox(0).disperse(at(1), block.clone());
            for (1..10) |index| try fixture.mailbox(index).gather(commitment, at(1));
            try fixture.latency(2);
            for (0..10) |index| try expect_assigned(fixture.mailbox(index), commitment);
            try fixture.latency(1);
            try expect_block(try by_commitment.recv(), &block);
            try expect_block(try by_digest.recv(), &block);
        }
    }.run);
}

test "proposer preproposal subscriptions resolve after local cache" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            // Subscribe on the proposer before it caches the locally proposed block.
            const mailbox = fixture.mailbox(0);
            var shard_sub = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            var by_commitment = try mailbox.subscribe(commitment);
            defer by_commitment.deinit();
            var by_digest = try mailbox.subscribe_by_digest(block.digest());
            defer by_digest.deinit();
            try mailbox.disperse(at(1), block.clone());
            try fixture.latency(1);
            try harness.expect_resolves(io, &shard_sub);
            try expect_block(try harness.expect_resolves(io, &by_commitment), &block);
            try expect_block(try harness.expect_resolves(io, &by_digest), &block);
        }
    }.run);
}

test "shard subscription rejects invalid shard" {
    try harness.run_deterministic(struct {
        // Peer 0 is byzantine, peer 1 an honest proposer, and peer 2 the receiver.
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{});
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            var valid = try harness.shard_of(&block, 2);
            defer valid.deinit(gpa);
            // An index that is neither the receiver's nor peer 0's triggers a block.
            var invalid = try valid.clone(gpa);
            defer invalid.deinit(gpa);
            invalid.index = 3;
            try fixture.mailbox(2).gather(commitment, at(1));
            var shard_sub = try fixture.mailbox(2).subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            try fixture.send(0, 2, &invalid);
            try fixture.latency(2);
            try harness.expect_pending(&shard_sub);
            try harness.expect_blocked(fixture.network, fixture.peers[2], fixture.peers[0]);
            // The honest proposer's valid shard resolves the subscription.
            try fixture.send(1, 2, &valid);
            try fixture.latency(2);
            try harness.expect_resolves(io, &shard_sub);
        }
    }.run);
}

/// Disperses a copy of `block` from peer `index` at `view`.
fn disperse(fixture: *Fixture, index: usize, view: u64, block: *const Coded) !void {
    try fixture.mailbox(index).disperse(at(view), block.clone());
}

test "window evicts lowest cached rounds" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .records = 4 });
            defer fixture.deinit();
            var blocks: [6]Coded = undefined;
            const config = fixture.coding_config;
            for (&blocks, 1..) |*block, id| block.* = try harness.make_block(config, id);
            defer for (&blocks) |*block| block.deinit(gpa);
            const reproposed, const low, const middle, const refreshed = .{
                &blocks[0], &blocks[1], &blocks[2], &blocks[3],
            };
            // Re-proposals raise the first and fourth blocks above the other two.
            const mailbox = fixture.mailbox(0);
            try disperse(fixture, 0, 1, reproposed);
            try disperse(fixture, 0, 2, low);
            try disperse(fixture, 0, 3, middle);
            try disperse(fixture, 0, 1, refreshed);
            try disperse(fixture, 0, 5, reproposed);
            try disperse(fixture, 0, 4, refreshed);
            for (blocks[0..4]) |*block| try expect_cached(mailbox, block.commitment(), true);
            // Two blocks proposed in later rounds evict the two lowest-round blocks.
            try disperse(fixture, 0, 6, &blocks[4]);
            try disperse(fixture, 0, 7, &blocks[5]);
            try expect_cached(mailbox, low.commitment(), false);
            try expect_cached(mailbox, middle.commitment(), false);
            try expect_cached(mailbox, reproposed.commitment(), true);
            try expect_cached(mailbox, refreshed.commitment(), true);
            for (blocks[4..]) |*block| try expect_cached(mailbox, block.commitment(), true);
        }
    }.run);
}

test "eviction keeps subscriptions open" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .records = 2 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            const mailbox = fixture.mailbox(2);
            var block = try harness.make_block(config, 1);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            var cached = try harness.make_block(config, 2);
            defer cached.deinit(gpa);
            // The receiver tracks the commitment at view 1 and caches its own proposal at 2.
            try mailbox.gather(commitment, at(1));
            var assigned = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer assigned.deinit();
            var subscription = try mailbox.subscribe(commitment);
            defer subscription.deinit();
            try disperse(fixture, 2, 2, &cached);
            try expect_cached(mailbox, cached.commitment(), true);
            // Records at views 3 and 4 evict both; the subscriptions stay open.
            for ([_]u64{ 3, 4 }) |view| {
                try mailbox.gather(try harness.commitment_of(config, view), at(view));
            }
            try expect_cached(mailbox, cached.commitment(), false);
            try harness.expect_pending(&assigned);
            try harness.expect_pending(&subscription);
            // A gather at view 5 recreates the record; the assigned shard and one gossip
            // shard reconstruct the block and resolve both subscriptions.
            try mailbox.gather(commitment, at(5));
            for ([_][2]usize{ .{ 0, 2 }, .{ 1, 1 } }) |pair| {
                var shard = try harness.shard_of(&block, pair[1]);
                defer shard.deinit(gpa);
                try fixture.send(pair[0], 2, &shard);
            }
            try assigned.recv();
            try expect_block(try subscription.recv(), &block);
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
        }
    }.run);
}

test "declined proposal still dispersed" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .records = 2 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            const proposer = fixture.mailbox(0);
            const receiver = fixture.mailbox(1);
            // The proposer fills its window with proposals at views 5 and 6.
            for ([_]u64{ 5, 6 }) |view| {
                try proposer.disperse(at(view), try harness.make_block(config, view));
            }
            // The receiver gathers a commitment at view 4, and both peers subscribe to it.
            var block = try harness.make_block(config, 4);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try receiver.gather(commitment, at(4));
            var verified = try receiver.subscribe_assigned_shard_verified(commitment);
            defer verified.deinit();
            var ready = try proposer.subscribe_assigned_shard_verified(commitment);
            defer ready.deinit();
            var subscription = try proposer.subscribe(commitment);
            defer subscription.deinit();
            // The declined proposal is dispersed and resolves the proposer's subscriptions,
            // but only the blocks at views 5 and 6 stay cached.
            try disperse(fixture, 0, 4, &block);
            try verified.recv();
            try ready.recv();
            try expect_block(try subscription.recv(), &block);
            try expect_cached(proposer, commitment, false);
            for ([_]u64{ 5, 6 }) |view| {
                try expect_cached(proposer, try harness.commitment_of(config, view), true);
            }
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
        }
    }.run);
}

test "records bounded over many views" {
    try harness.run_deterministic(struct {
        const records = 4;
        const views = 3 * records + 1;

        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .records = records });
            defer fixture.deinit();
            var commitments: [views]Coded.Commitment = undefined;
            for (&commitments, 1..) |*commitment, view| {
                commitment.* = try propose_and_reconstruct(fixture, view);
                try expect_bounded(fixture);
            }
            // Each engine retains exactly the blocks of the last `records` views.
            for (0..fixture.count()) |index| {
                for (commitments, 0..) |commitment, position| {
                    const retained = position >= views - records;
                    try expect_cached(fixture.mailbox(index), commitment, retained);
                }
            }
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
        }

        /// Peer 0 proposes, and every other participant reconstructs the block.
        fn propose_and_reconstruct(fixture: *Fixture, view: u64) !Coded.Commitment {
            var block = try harness.encode(fixture.coding_config, view, view);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try disperse(fixture, 0, view, &block);
            var subscriptions: [harness.peers_max]?oneshot.Receiver(Coded) = @splat(null);
            defer for (&subscriptions) |*value| if (value.*) |*receiver| receiver.deinit();
            for (1..fixture.count()) |index| {
                const mailbox = fixture.mailbox(index);
                try mailbox.gather(commitment, at(view));
                subscriptions[index] = try mailbox.subscribe(commitment);
            }
            for (subscriptions[1..fixture.count()]) |*subscription| {
                try expect_block(try subscription.*.?.recv(), &block);
            }
            return commitment;
        }

        /// No engine caches more blocks or holds more reconstruction states than the window.
        fn expect_bounded(fixture: *Fixture) !void {
            const names = [_][]const u8{
                "reconstructed_blocks_cache_count",
                "reconstruction_states_count",
            };
            for (names) |name| {
                var counts: [harness.peers_max]i64 = undefined;
                const found = try fixture.gauges(name, &counts);
                try testing.expectEqual(fixture.count(), found);
                for (counts[0..found]) |count| try testing.expect(count <= records);
            }
        }
    }.run);
}

test "later epoch evicts earlier epoch records" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .epochs = &.{1}, .records = 2 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            const receiver = fixture.mailbox(2);
            // The receiver caches its own proposals at high views of epoch 0.
            for ([_]u64{ 1, 2 }, [_]u64{ 100, 101 }) |id, view| {
                try receiver.disperse(harness.round(0, view), try harness.make_block(config, id));
            }
            for ([_]u64{ 1, 2 }) |id| {
                try expect_cached(receiver, try harness.commitment_of(config, id), true);
            }
            // Proposals at the first views of epoch 1 evict both.
            for ([_]u64{ 3, 4 }, [_]u64{ 1, 2 }) |id, view| {
                try receiver.disperse(harness.round(1, view), try harness.make_block(config, id));
            }
            for ([_]u64{ 1, 2, 3, 4 }) |id| {
                const commitment = try harness.commitment_of(config, id);
                try expect_cached(receiver, commitment, id > 2);
            }
        }
    }.run);
}

test "local reproposal refreshes existing reconstruction state" {
    try harness.run_deterministic(struct {
        fn make(config: anytype, id: u64) !Coded {
            return harness.encode(config, id, id * 100);
        }

        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .records = 3 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            const mailbox = fixture.mailbox(0);
            var live = try make(config, 1);
            defer live.deinit(gpa);
            var state_first = try make(config, 3);
            defer state_first.deinit(gpa);
            var lower = try make(config, 4);
            defer lower.deinit(gpa);
            // Gather `live` at view 1 and re-propose it at 8; gather `state_first` at 8 and
            // then propose it at 5.
            try mailbox.gather(live.commitment(), at(1));
            try disperse(fixture, 0, 8, &live);
            try mailbox.gather(state_first.commitment(), at(8));
            try disperse(fixture, 0, 5, &state_first);
            try expect_cached(mailbox, live.commitment(), true);
            // A later assigned-shard subscription resolves from the local re-proposal.
            try expect_ready(mailbox, live.commitment());
            // Blocks at views 6 and 9 exceed the window by one; both earlier records were
            // last observed at view 8, so the block at view 6 is evicted.
            try disperse(fixture, 0, 6, &lower);
            try mailbox.disperse(at(9), try make(config, 5));
            try expect_cached(mailbox, lower.commitment(), false);
            try expect_cached(mailbox, live.commitment(), true);
            try expect_cached(mailbox, state_first.commitment(), true);
            try expect_ready(mailbox, live.commitment());
        }

        fn expect_ready(mailbox: harness.Mailbox, commitment: Coded.Commitment) !void {
            var shard_sub = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            try expect_cached(mailbox, commitment, true);
            try shard_sub.try_recv();
        }
    }.run);
}

/// Peer 2 gathers `block`'s commitment, and peer 0 (the leader) sends it peer 2's shard,
/// then `second`.
fn leader_sends_twice(
    fixture: *Fixture,
    block: *const Coded,
    second: *const harness.ShardType,
) !void {
    try fixture.mailbox(2).gather(block.commitment(), at(1));
    var first = try harness.shard_of(block, 2);
    defer first.deinit(gpa);
    try fixture.send(0, 2, &first);
    try fixture.latency(2);
    try fixture.send(0, 2, second);
    try fixture.latency(2);
}

test "duplicate leader shard ignored" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{});
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            var duplicate = try harness.shard_of(&block, 2);
            defer duplicate.deinit(gpa);
            try leader_sends_twice(fixture, &block, &duplicate);
            // The leader is not blocked for an identical duplicate.
            const peers = fixture.peers;
            try testing.expect(!try harness.is_blocked(fixture.network, peers[2], peers[0]));
        }
    }.run);
}

test "equivocating leader shard blocks peer" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{});
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            // Peer 2's shard of a different block, retargeted at the same commitment.
            var other = try harness.encode(fixture.coding_config, 1, 200);
            defer other.deinit(gpa);
            var equivocating = try harness.shard_for(&other, 2, block.commitment());
            defer equivocating.deinit(gpa);
            try leader_sends_twice(fixture, &block, &equivocating);
            try harness.expect_blocked(fixture.network, fixture.peers[2], fixture.peers[0]);
        }
    }.run);
}
