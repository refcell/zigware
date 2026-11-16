//! Shard engine tests of peer buffers, decoding, and gather timing on running engines, ported
//! from commonware `marshal/coding/shards/engine.rs`.

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

fn expect_cached(mailbox: harness.Mailbox, commitment: Commitment, cached: bool) !void {
    var got = try mailbox.get(commitment);
    defer if (got) |*value| value.deinit(gpa);
    try testing.expectEqual(cached, got != null);
}

fn expect_no_blocks(fixture: *Fixture) !void {
    try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
}

/// Waits up to five seconds for the block with `commitment` (commonware's `select!`).
fn expect_subscription(io: Io, mailbox: harness.Mailbox, commitment: Commitment) !void {
    var subscription = try mailbox.subscribe(commitment);
    defer subscription.deinit();
    var got = try harness.expect_resolves(io, &subscription);
    defer got.deinit(gpa);
    try testing.expect(got.commitment().eql(commitment));
}

test "peer shards buffered until gather" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            const mailbox = fixture.mailbox(3);
            var shard_sub = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            // The proposer's shard and three gossip shards, all before the gather.
            try send_index(fixture, 0, 3, &block, 3);
            try send_own(fixture, 3, &block, &.{ 1, 2, 4 });
            try fixture.latency(2);
            try harness.expect_pending(&shard_sub);
            try expect_cached(mailbox, commitment, false);
            // The gather drains the buffered shards and progresses at once.
            try mailbox.gather(commitment, at(1));
            try harness.expect_resolves(io, &shard_sub);
            try fixture.latency(2);
            try expect_cached(mailbox, commitment, true);
            try expect_no_blocks(fixture);
        }
    }.run);
}

test "inline reconstruction completes before next message" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try send_index(fixture, 0, 3, &block, 3);
            try send_own(fixture, 3, &block, &.{ 1, 2, 4 });
            try fixture.latency(2);
            // The request queued right behind the gather observes the cached block.
            try fixture.mailbox(3).gather(commitment, at(1));
            try expect_cached(fixture.mailbox(3), commitment, true);
            try expect_no_blocks(fixture);
        }
    }.run);
}

test "gather reconstructs from buffered gossip shards" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            const mailbox = fixture.mailbox(3);
            var block_sub = try mailbox.subscribe(commitment);
            defer block_sub.deinit();
            // Four sender-indexed shards are enough to reconstruct.
            try send_own(fixture, 3, &block, &.{ 1, 2, 4, 5 });
            try fixture.latency(2);
            try expect_cached(mailbox, commitment, false);
            try mailbox.gather(commitment, at(1));
            var got = try harness.expect_resolves(io, &block_sub);
            got.deinit(gpa);
            try expect_cached(mailbox, commitment, true);
            // Reconstruction from gossip leaves the assigned shard unverified.
            var assigned = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer assigned.deinit();
            try harness.expect_pending(&assigned);
            try send_index(fixture, 0, 3, &block, 3);
            try harness.expect_resolves(io, &assigned);
            try expect_no_blocks(fixture);
        }
    }.run);
}

test "late subscription uses cache after peer buffer pressure" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const options: Fixture.Options = .{ .primary = 10, .peer_buffer_size = 1 };
            const fixture = try Fixture.init(io, options);
            defer fixture.deinit();
            const config = fixture.coding_config;
            var target = try harness.encode(config, 1, 1);
            defer target.deinit(gpa);
            const target_commitment = target.commitment();
            const mailbox = fixture.mailbox(3);
            try send_own(fixture, 3, &target, &.{ 1, 2, 4, 5 });
            try fixture.latency(2);
            try mailbox.gather(target_commitment, at(1));
            try expect_subscription(io, mailbox, target_commitment);
            // A later gather leaves the target cached, whatever the peer buffers hold.
            try mailbox.gather(target_commitment, at(4));
            try expect_cached(mailbox, target_commitment, true);
            try buffer_pressure(fixture);
            // Coding's marshal buffer subscribes only after the pressure.
            try expect_subscription(io, mailbox, target_commitment);
            try expect_no_blocks(fixture);
        }

        /// Peer 1 sends two blocks' shards into its one-shard buffer: only the second
        /// survives, so only its commitment reconstructs.
        fn buffer_pressure(fixture: *Fixture) !void {
            var blocks: [2]Coded = undefined;
            for (&blocks, [_]u64{ 2, 3 }) |*block, id| {
                block.* = try harness.encode(fixture.coding_config, id, id);
            }
            defer for (&blocks) |*block| block.deinit(gpa);
            for (&blocks) |*block| try send_index(fixture, 1, 3, block, 1);
            try fixture.latency(2);
            const mailbox = fixture.mailbox(3);
            for (&blocks, [_]bool{ false, true }) |*block, reconstructs| {
                try send_own(fixture, 3, block, &.{ 2, 4, 5 });
                try fixture.latency(2);
                try mailbox.gather(block.commitment(), at(1));
                if (reconstructs) {
                    try expect_subscription(fixture.io, mailbox, block.commitment());
                } else {
                    try expect_cached(mailbox, block.commitment(), false);
                }
            }
        }
    }.run);
}

test "replacement proposal in same round reaches peers" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var abandoned = try harness.encode(fixture.coding_config, 1, 100);
            defer abandoned.deinit(gpa);
            var replacement = try harness.encode(fixture.coding_config, 1, 200);
            defer replacement.deinit(gpa);
            try testing.expect(!abandoned.commitment().eql(replacement.commitment()));
            // Both candidates are relayed before any participant learns the proposal.
            try fixture.mailbox(0).disperse(at(1), abandoned.clone());
            try fixture.mailbox(0).disperse(at(1), replacement.clone());
            try fixture.latency(2);
            // Only the replacement is ever proposed.
            const commitment = replacement.commitment();
            for (1..10) |index| try fixture.mailbox(index).gather(commitment, at(1));
            for (0..10) |index| {
                var receiver = try fixture.mailbox(index).subscribe_assigned_shard_verified(
                    commitment,
                );
                defer receiver.deinit();
                try receiver.recv();
            }
            try fixture.latency(2);
            for (0..10) |index| {
                var got = (try fixture.mailbox(index).get(commitment)) orelse
                    return error.NotReconstructed;
                defer got.deinit(gpa);
                try testing.expect(got.digest().eql(replacement.digest()));
            }
            for (1..10) |index| {
                try expect_cached(fixture.mailbox(index), abandoned.commitment(), false);
            }
            try expect_no_blocks(fixture);
        }
    }.run);
}

test "shards after gather processed immediately" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            const mailbox = fixture.mailbox(3);
            var shard_sub = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            try mailbox.gather(commitment, at(1));
            try send_index(fixture, 0, 3, &block, 3);
            try harness.expect_resolves(io, &shard_sub);
            try send_own(fixture, 3, &block, &.{ 1, 2, 4 });
            try fixture.latency(2);
            try expect_cached(mailbox, commitment, true);
            try expect_no_blocks(fixture);
        }
    }.run);
}

test "invalid shard codec blocks peer" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{});
            defer fixture.deinit();
            const garbage = [_]u8{ 0xFF, 0xFE, 0xFD, 0xFC, 0xFB };
            const to: harness.p2p.Recipients(harness.Key) = .{ .one = fixture.peers[0] };
            const attempted = try fixture.sender(1).send(to, &.{&garbage}, true);
            gpa.free(attempted);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[0], fixture.peers[1]);
        }
    }.run);
}

test "oversized shard blocks peer" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{});
            defer fixture.deinit();
            // Peer 1's shard of the largest block, coded under the committee's config but
            // claiming more minimum shards: too wide for the claimed config.
            const max = std.math.maxInt(u64);
            var block = try harness.encode(fixture.coding_config, max, max);
            defer block.deinit(gpa);
            const honest = block.commitment();
            const claimed: @TypeOf(fixture.coding_config) = .{
                .minimum_shards = 3,
                .extra_shards = 1,
            };
            const lying = Commitment.init(honest.block(), honest.root(), honest.context(), claimed);
            var shard = try harness.shard_for(&block, 1, lying);
            defer shard.deinit(gpa);
            try fixture.send(1, 2, &shard);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[2], fixture.peers[1]);
        }
    }.run);
}

test "duplicate buffered shard does not block before gather" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{});
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            // Peer 2 never gathers; peer 1 sends peer 2's shard twice.
            for (0..2) |_| {
                try send_index(fixture, 1, 2, &block, 2);
                try fixture.latency(2);
                try expect_no_blocks(fixture);
            }
        }
    }.run);
}

test "invalid leader shard crypto blocks leader" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{});
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            var other = try harness.encode(fixture.coding_config, 2, 200);
            defer other.deinit(gpa);
            // Peer 2's shard of the other block under this block's commitment fails to verify.
            var wrong = try harness.shard_for(&other, 2, block.commitment());
            defer wrong.deinit(gpa);
            try fixture.mailbox(2).gather(block.commitment(), at(1));
            try fixture.send(0, 2, &wrong);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[2], fixture.peers[0]);
        }
    }.run);
}
