//! Shard engine tests of failed reconstruction, equivocation, and withholding leaders on
//! running engines, ported from commonware `marshal/coding/shards/engine.rs`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;

const harness = @import("engine_harness.zig");

const gpa = harness.gpa;
const Coded = harness.Coded;
const Commitment = harness.Commitment;
const Fixture = harness.Fixture;
const at = harness.at;

/// Peer 0 sends peer `to` its shard of `block`, and peers 1, 2, and 4 their own, all under
/// `commitment`: the minimum of four for ten participants.
fn send_quorum(fixture: *Fixture, to: usize, block: *const Coded, commitment: Commitment) !void {
    for ([_][2]usize{ .{ 0, to }, .{ 1, 1 }, .{ 2, 2 }, .{ 4, 4 } }) |pair| {
        var shard = try harness.shard_for(block, pair[1], commitment);
        defer shard.deinit(gpa);
        try fixture.send(pair[0], to, &shard);
    }
}

fn expect_cached(mailbox: harness.Mailbox, commitment: Commitment, cached: bool) !void {
    var got = try mailbox.get(commitment);
    defer if (got) |*value| value.deinit(gpa);
    try testing.expectEqual(cached, got != null);
}

test "failed reconstruction digest mismatch then recovery" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            var claimed = try harness.encode(config, 1, 100);
            defer claimed.deinit(gpa);
            var actual = try harness.encode(config, 2, 200);
            defer actual.deinit(gpa);
            // The claimed block's digest with the actual block's root and context: the shards
            // verify, but decode to a block with another digest.
            const real = actual.commitment();
            const digest = claimed.digest();
            const fake = Commitment.init(digest, real.root(), real.context(), config);
            const mailbox = fixture.mailbox(3);
            try mailbox.gather(fake, at(1));
            var block_sub = try mailbox.subscribe(fake);
            defer block_sub.deinit();
            var digest_sub = try mailbox.subscribe_by_digest(digest);
            defer digest_sub.deinit();
            try send_quorum(fixture, 3, &actual, fake);
            try fixture.latency(2);
            // The exact-commitment subscription closes; the digest subscription survives.
            try expect_cached(mailbox, fake, false);
            try harness.expect_closed(&block_sub);
            try harness.expect_pending(&digest_sub);
            // The claimed block's real commitment still reconstructs.
            try mailbox.gather(claimed.commitment(), at(2));
            try send_quorum(fixture, 3, &claimed, claimed.commitment());
            try fixture.latency(2);
            try expect_cached(mailbox, claimed.commitment(), true);
            var by_digest = try digest_sub.recv();
            defer by_digest.deinit(gpa);
            try testing.expect(by_digest.commitment().eql(claimed.commitment()));
        }
    }.run);
}

test "failed reconstruction context mismatch then recovery" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            var block = try harness.encode(config, 1, 100);
            defer block.deinit(gpa);
            const real = block.commitment();
            const wrong_context = harness.Sha256.hash(&.{"wrong_context"});
            try testing.expect(!real.context().eql(wrong_context));
            const fake = Commitment.init(block.digest(), real.root(), wrong_context, config);
            const mailbox = fixture.mailbox(3);
            try mailbox.gather(fake, at(1));
            var block_sub = try mailbox.subscribe(fake);
            defer block_sub.deinit();
            try send_quorum(fixture, 3, &block, fake);
            try fixture.latency(2);
            try expect_cached(mailbox, fake, false);
            try harness.expect_closed(&block_sub);
            // The real commitment still reconstructs.
            try mailbox.gather(real, at(2));
            try send_quorum(fixture, 3, &block, real);
            try fixture.latency(2);
            try expect_cached(mailbox, real, true);
        }
    }.run);
}

test "same round equivocation preserves certifiable recovery" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            var block_a = try harness.encode(config, 1, 111);
            defer block_a.deinit(gpa);
            var block_b = try harness.encode(config, 1, 222);
            defer block_b.deinit(gpa);
            const mailbox = fixture.mailbox(3);
            // The receiver learns both commitments in round 7.
            try mailbox.gather(block_a.commitment(), at(7));
            try mailbox.gather(block_b.commitment(), at(7));
            var certifiable = try mailbox.subscribe(block_b.commitment());
            defer certifiable.deinit();
            // The equivocating leader sends the receiver its shard of B, then A reconstructs.
            var shard_b = try harness.shard_of(&block_b, 3);
            defer shard_b.deinit(gpa);
            try fixture.send(0, 3, &shard_b);
            try send_quorum(fixture, 3, &block_a, block_a.commitment());
            try fixture.latency(4);
            try expect_cached(mailbox, block_a.commitment(), true);
            // B stays recoverable.
            for ([_]usize{ 1, 2, 4 }) |index| {
                var shard = try harness.shard_of(&block_b, index);
                defer shard.deinit(gpa);
                try fixture.send(index, 3, &shard);
            }
            var got = try harness.expect_resolves(io, &certifiable);
            defer got.deinit(gpa);
            try testing.expect(got.commitment().eql(block_b.commitment()));
            // Cross-commitment equivocation within a round is tolerated.
            const peers = fixture.peers;
            try testing.expect(!try harness.is_blocked(fixture.network, peers[3], peers[0]));
        }
    }.run);
}

test "leader unrelated shard blocks peer" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var tracked = try harness.encode(fixture.coding_config, 1, 100);
            defer tracked.deinit(gpa);
            var unrelated = try harness.encode(fixture.coding_config, 2, 200);
            defer unrelated.deinit(gpa);
            try fixture.mailbox(3).gather(tracked.commitment(), at(1));
            // Peer 1's slot of another block, retargeted: neither the leader's nor the
            // receiver's index.
            var shard = try harness.shard_for(&unrelated, 1, tracked.commitment());
            defer shard.deinit(gpa);
            try fixture.send(0, 3, &shard);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[3], fixture.peers[0]);
        }
    }.run);
}

/// Peer 0 proposes with its link to peer 1 severed, and every other peer gathers.
fn withhold_from_victim(fixture: *Fixture, block: *const Coded) !void {
    try fixture.network.oracle().remove_link(fixture.peers[0], fixture.peers[1]);
    try fixture.mailbox(0).disperse(at(1), block.clone());
    for (1..10) |index| try fixture.mailbox(index).gather(block.commitment(), at(1));
}

test "withholding leader victim reconstructs via gossip" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try withhold_from_victim(fixture, &block);
            try fixture.latency(2);
            var block_sub = try fixture.mailbox(1).subscribe(commitment);
            defer block_sub.deinit();
            var got = try harness.expect_resolves(io, &block_sub);
            defer got.deinit(gpa);
            try testing.expectEqual(block.height().get(), got.height().get());
            for (2..10) |index| try expect_cached(fixture.mailbox(index), commitment, true);
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
        }
    }.run);
}

test "shard subscription pending after reconstruction without assigned shard" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            const victim = fixture.mailbox(1);
            var shard_sub = try victim.subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            var block_sub = try victim.subscribe(commitment);
            defer block_sub.deinit();
            try withhold_from_victim(fixture, &block);
            try fixture.latency(4);
            // The victim reconstructs from gossip, but its own shard never verified.
            var got = try block_sub.recv();
            defer got.deinit(gpa);
            try testing.expect(got.commitment().eql(commitment));
            var late_sub = try victim.subscribe_assigned_shard_verified(commitment);
            defer late_sub.deinit();
            try harness.sleep_ms(io, 10);
            try harness.expect_pending(&shard_sub);
            try harness.expect_pending(&late_sub);
        }
    }.run);
}
