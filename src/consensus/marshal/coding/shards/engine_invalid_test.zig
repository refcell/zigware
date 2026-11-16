//! Shard engine tests of invalid shards on running engines, ported from commonware
//! `marshal/coding/shards/engine.rs`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;

const harness = @import("engine_harness.zig");

const gpa = harness.gpa;
const Coded = harness.Coded;
const Commitment = harness.Commitment;
const Fixture = harness.Fixture;
const at = harness.at;

/// Sends a copy of `block`'s shard at `index` from peer `from` to peer `to`.
fn send_index(fixture: *Fixture, from: usize, to: usize, block: *const Coded, index: usize) !void {
    var shard = try harness.shard_of(block, index);
    defer shard.deinit(gpa);
    try fixture.send(from, to, &shard);
}

/// Each peer of `senders` sends peer `to` its own shard of `block`.
fn send_own(fixture: *Fixture, to: usize, block: *const Coded, senders: []const usize) !void {
    for (senders) |index| try send_index(fixture, index, to, block, index);
}

/// Sends `block`'s shard at `index` from `other` (a different block) under `block`'s
/// commitment, which fails verification.
fn send_forged(
    fixture: *Fixture,
    from: usize,
    to: usize,
    block: *const Coded,
    other: *const Coded,
    index: usize,
) !void {
    var forged = try harness.shard_for(other, index, block.commitment());
    defer forged.deinit(gpa);
    try fixture.send(from, to, &forged);
}

fn expect_cached(mailbox: harness.Mailbox, commitment: Commitment, cached: bool) !void {
    var got = try mailbox.get(commitment);
    defer if (got) |*value| value.deinit(gpa);
    try testing.expectEqual(cached, got != null);
}

/// Two blocks: the one under test (height 1) and another whose shards fail to verify under
/// its commitment (height 2).
const Pair = struct {
    block: Coded,
    other: Coded,

    fn init(fixture: *const Fixture) !Pair {
        var block = try harness.encode(fixture.coding_config, 1, 100);
        errdefer block.deinit(gpa);
        return .{ .block = block, .other = try harness.encode(fixture.coding_config, 2, 200) };
    }

    fn deinit(pair: *Pair) void {
        pair.block.deinit(gpa);
        pair.other.deinit(gpa);
    }
};

test "invalid assigned shard blocks only sender" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{});
            defer fixture.deinit();
            var pair = try Pair.init(fixture);
            defer pair.deinit();
            const commitment = pair.block.commitment();
            const mailbox = fixture.mailbox(2);
            var shard_sub = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            try mailbox.gather(commitment, at(1));
            // Peer 1, not the proposer, sends a forged shard at peer 2's assigned index.
            try send_forged(fixture, 1, 2, &pair.block, &pair.other, 2);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[2], fixture.peers[1]);
            try harness.expect_pending(&shard_sub);
            // The proposer's genuine shard for the same index still verifies.
            try send_index(fixture, 0, 2, &pair.block, 2);
            try harness.expect_resolves(io, &shard_sub);
        }
    }.run);
}

test "shard index mismatch blocks peer" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            try fixture.mailbox(3).gather(block.commitment(), at(1));
            try send_index(fixture, 0, 3, &block, 3);
            try fixture.latency(2);
            // Peer 1's shard relabeled with peer 4's index.
            var wrong = try harness.shard_of(&block, 1);
            defer wrong.deinit(gpa);
            wrong.index = 4;
            try fixture.send(1, 3, &wrong);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[3], fixture.peers[1]);
        }
    }.run);
}

test "invalid shard crypto blocks peer" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var pair = try Pair.init(fixture);
            defer pair.deinit();
            try fixture.mailbox(3).gather(pair.block.commitment(), at(1));
            try send_index(fixture, 0, 3, &pair.block, 3);
            try fixture.latency(2);
            try send_forged(fixture, 1, 3, &pair.block, &pair.other, 1);
            try fixture.latency(2);
            // Valid shards from peers 2 and 4 reach quorum (1 assigned + 3 pending), and batch
            // validation rejects peer 1's.
            try send_own(fixture, 3, &pair.block, &.{ 2, 4 });
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[3], fixture.peers[1]);
        }
    }.run);
}

test "reconstruction recovers after quorum with one invalid shard" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var pair = try Pair.init(fixture);
            defer pair.deinit();
            const commitment = pair.block.commitment();
            const mailbox = fixture.mailbox(3);
            try mailbox.gather(commitment, at(1));
            // Exactly the minimum: the assigned shard, a forged shard, and two valid ones.
            try send_index(fixture, 0, 3, &pair.block, 3);
            try send_forged(fixture, 1, 3, &pair.block, &pair.other, 1);
            try send_own(fixture, 3, &pair.block, &.{ 2, 4 });
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[3], fixture.peers[1]);
            try expect_cached(mailbox, commitment, false);
            // One more valid shard meets the threshold.
            try send_own(fixture, 3, &pair.block, &.{5});
            try fixture.latency(2);
            try expect_cached(mailbox, commitment, true);
        }
    }.run);
}

test "surplus pending shard replaces invalid shard" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var pair = try Pair.init(fixture);
            defer pair.deinit();
            const commitment = pair.block.commitment();
            // Before the gather: peer 1's forged shard and the four valid shards needed.
            try send_forged(fixture, 1, 3, &pair.block, &pair.other, 1);
            try send_own(fixture, 3, &pair.block, &.{ 2, 4, 5, 6 });
            try fixture.latency(2);
            // The gather ingests all five; the invalid one is replaced by the surplus shard.
            const mailbox = fixture.mailbox(3);
            var subscription = try mailbox.subscribe(commitment);
            defer subscription.deinit();
            try mailbox.gather(commitment, at(1));
            try fixture.latency(1);
            var got = try subscription.try_recv();
            defer got.deinit(gpa);
            try testing.expect(got.commitment().eql(commitment));
            try harness.expect_blocked(fixture.network, fixture.peers[3], fixture.peers[1]);
        }
    }.run);
}

test "invalid pending shard blocked on drain" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var pair = try Pair.init(fixture);
            defer pair.deinit();
            // The forged shard and two valid shards wait in their senders' buffers.
            try send_forged(fixture, 1, 3, &pair.block, &pair.other, 1);
            try fixture.latency(2);
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
            try send_own(fixture, 3, &pair.block, &.{ 2, 4 });
            try fixture.latency(2);
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
            // The gather and the assigned shard reach quorum; batch validation blocks peer 1.
            try fixture.mailbox(3).gather(pair.block.commitment(), at(1));
            try send_index(fixture, 0, 3, &pair.block, 3);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[3], fixture.peers[1]);
        }
    }.run);
}
