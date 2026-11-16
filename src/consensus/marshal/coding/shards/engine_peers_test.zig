//! Shard engine tests of peer classification and blocking on running engines, ported from
//! commonware `marshal/coding/shards/engine.rs`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;

const harness = @import("engine_harness.zig");

const gpa = harness.gpa;
const Coded = harness.Coded;
const Fixture = harness.Fixture;
const at = harness.at;

/// Sends a copy of `block`'s shard at `index` from peer `from` to peer `to`.
fn send_index(fixture: *Fixture, from: usize, to: usize, block: *const Coded, index: usize) !void {
    var shard = try harness.shard_of(block, index);
    defer shard.deinit(gpa);
    try fixture.send(from, to, &shard);
}

/// Peer 1 sends peer 3's shard, which is neither the receiver's nor peer 1's own, to a
/// participant or to a non-participant. When `buffered`, the shard arrives before the
/// receiver gathers the commitment.
fn wrong_index_shard_blocks_sender(io: Io, non_participant: bool, buffered: bool) !void {
    const fixture = try Fixture.init(io, .{ .secondary = 1 });
    defer fixture.deinit();
    var block = try harness.encode(fixture.coding_config, 1, 100);
    defer block.deinit(gpa);
    const commitment = block.commitment();
    const receiver: usize = if (non_participant) 4 else 2;
    const mailbox = fixture.mailbox(receiver);
    if (!buffered) try mailbox.gather(commitment, at(1));
    try send_index(fixture, 1, receiver, &block, 3);
    try fixture.latency(2);
    if (buffered) {
        // The shard waits in peer 1's buffer until the gather drains it.
        try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
        try mailbox.gather(commitment, at(1));
        try harness.sleep_ms(io, 10);
    }
    try harness.expect_blocked(fixture.network, fixture.peers[receiver], fixture.peers[1]);
}

test "wrong index shard blocks sender" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try wrong_index_shard_blocks_sender(io, false, false);
        }
    }.run);
}

test "buffered wrong index shard blocks sender on gather" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try wrong_index_shard_blocks_sender(io, false, true);
        }
    }.run);
}

test "non participant wrong index shard blocks sender" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try wrong_index_shard_blocks_sender(io, true, false);
        }
    }.run);
}

test "non participant buffered wrong index shard blocks sender on gather" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try wrong_index_shard_blocks_sender(io, true, true);
        }
    }.run);
}

test "assigned shard from non leader accepted" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{});
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            const mailbox = fixture.mailbox(2);
            var shard_sub = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            try mailbox.gather(commitment, at(1));
            // The assigned shard is commitment-bound, so another participant may deliver it.
            try send_index(fixture, 1, 2, &block, 2);
            try harness.expect_resolves(io, &shard_sub);
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
        }
    }.run);
}

test "cross epoch observations do not refresh eviction round" {
    try harness.run_deterministic(struct {
        fn make(config: anytype, id: u64) !Coded {
            return harness.encode(config, id, id * 100);
        }

        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .epochs = &.{1}, .records = 2 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            const receiver = fixture.mailbox(2);
            var cached = try make(config, 1);
            defer cached.deinit(gpa);
            var incomplete = try make(config, 2);
            defer incomplete.deinit(gpa);
            // The receiver caches its own proposal and tracks another commitment at view 1.
            try receiver.disperse(at(1), cached.clone());
            try receiver.gather(incomplete.commitment(), at(1));
            // A proposal and gathers from epoch 1 conflict with both records and are ignored.
            const conflicting = harness.round(1, 10);
            try receiver.disperse(conflicting, incomplete.clone());
            try receiver.gather(cached.commitment(), conflicting);
            try receiver.gather(incomplete.commitment(), conflicting);
            // Blocks cached at views 2 and 3 exceed the window by two; the ignored
            // observations left both records at view 1, so the window evicts them.
            var later: [2]Coded = .{ try make(config, 3), try make(config, 4) };
            defer for (&later) |*block| block.deinit(gpa);
            for (&later, [_]u64{ 2, 3 }) |*block, view| {
                try receiver.disperse(at(view), block.clone());
            }
            try expect_cached(receiver, cached.commitment(), false);
            for (&later) |*block| try expect_cached(receiver, block.commitment(), true);
        }
    }.run);
}

fn expect_cached(mailbox: harness.Mailbox, commitment: Coded.Commitment, cached: bool) !void {
    var got = try mailbox.get(commitment);
    defer if (got) |*value| value.deinit(gpa);
    try testing.expectEqual(cached, got != null);
}

/// A peer outside the committee (seed 10 000), linked to peer 2 and tracked as a secondary
/// peer of set 2.
const Outsider = struct {
    key: harness.Key,
    registered: harness.Net.Registered,

    fn init(fixture: *Fixture) !Outsider {
        const key = harness.PrivateKey.from_seed(10_000).public_key();
        const oracle = fixture.network.oracle();
        var registered = try oracle.control(key).register(0, harness.test_quota);
        errdefer registered.deinit();
        try oracle.add_link(key, fixture.peers[2], harness.default_link);
        try harness.track(fixture.network, 2, fixture.peers[0..fixture.count()], &.{key});
        try harness.sleep_ms(fixture.io, 10);
        return .{ .key = key, .registered = registered };
    }

    fn send(outsider: *Outsider, fixture: *Fixture, block: *const Coded, index: usize) !void {
        var shard = try harness.shard_of(block, index);
        defer shard.deinit(gpa);
        try harness.send_shard(&outsider.registered.sender, fixture.peers[2], &shard);
    }

    fn deinit(outsider: *Outsider) void {
        outsider.registered.deinit();
    }
};

test "shard from non participant blocks peer" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .future = 1 });
            defer fixture.deinit();
            var outsider = try Outsider.init(fixture);
            defer outsider.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            try fixture.mailbox(2).gather(block.commitment(), at(1));
            try outsider.send(fixture, &block, 2);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[2], outsider.key);
        }
    }.run);
}

test "shard from secondary peer before gather is not buffered" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .future = 1 });
            defer fixture.deinit();
            var outsider = try Outsider.init(fixture);
            defer outsider.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            const mailbox = fixture.mailbox(2);
            var shard_sub = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            try outsider.send(fixture, &block, 2);
            try fixture.latency(2);
            try mailbox.gather(commitment, at(1));
            try fixture.latency(2);
            // The dropped shard's sender is not blocked, and nothing was buffered.
            const network = fixture.network;
            try testing.expect(!try harness.is_blocked(network, fixture.peers[2], outsider.key));
            try harness.expect_pending(&shard_sub);
        }
    }.run);
}

test "duplicate shard ignored" {
    try harness.run_deterministic(struct {
        // Ten peers need four shards, leaving time for a duplicate before reconstruction.
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            try fixture.mailbox(2).gather(block.commitment(), at(1));
            // The proposer's shard, then peer 1's shard twice.
            try send_index(fixture, 0, 2, &block, 2);
            try fixture.latency(2);
            for (0..2) |_| {
                try send_index(fixture, 1, 2, &block, 1);
                try fixture.latency(2);
            }
            const peers = fixture.peers;
            try testing.expect(!try harness.is_blocked(fixture.network, peers[2], peers[1]));
        }
    }.run);
}

test "equivocating shard blocks peer" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            var other = try harness.encode(fixture.coding_config, 1, 200);
            defer other.deinit(gpa);
            var equivocating = try harness.shard_for(&other, 1, block.commitment());
            defer equivocating.deinit(gpa);
            try fixture.mailbox(2).gather(block.commitment(), at(1));
            try send_index(fixture, 0, 2, &block, 2);
            try fixture.latency(2);
            try send_index(fixture, 1, 2, &block, 1);
            try fixture.latency(2);
            try fixture.send(1, 2, &equivocating);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, fixture.peers[2], fixture.peers[1]);
        }
    }.run);
}

test "reconstruction keeps lower view records" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            var block_a = try harness.encode(config, 1, 100);
            defer block_a.deinit(gpa);
            var block_b = try harness.encode(config, 2, 200);
            defer block_b.deinit(gpa);
            const mailbox = fixture.mailbox(2);
            // A's record at view 1 holds one shard from peer 1.
            try mailbox.gather(block_a.commitment(), at(1));
            try send_index(fixture, 1, 2, &block_a, 1);
            try fixture.latency(2);
            // B at view 2 reconstructs from the proposer's shard and three gossip shards.
            try mailbox.gather(block_b.commitment(), at(2));
            try send_index(fixture, 0, 2, &block_b, 2);
            for ([_]usize{ 1, 3, 4 }) |index| try send_index(fixture, index, 2, &block_b, index);
            try fixture.latency(4);
            try expect_cached(mailbox, block_b.commitment(), true);
            // A's record remains: resending A's shard is an exact duplicate.
            try send_index(fixture, 1, 2, &block_a, 1);
            try fixture.latency(2);
            const peers = fixture.peers;
            try testing.expect(!try harness.is_blocked(fixture.network, peers[2], peers[1]));
            // A shard conflicting with peer 1's contribution to A blocks peer 1.
            var other = try harness.encode(config, 1, 300);
            defer other.deinit(gpa);
            var conflicting = try harness.shard_for(&other, 1, block_a.commitment());
            defer conflicting.deinit(gpa);
            try fixture.send(1, 2, &conflicting);
            try fixture.latency(2);
            try harness.expect_blocked(fixture.network, peers[2], peers[1]);
        }
    }.run);
}

test "later gather refreshes reconstruction state round" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10, .records = 2 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            const mailbox = fixture.mailbox(3);
            var live = try harness.encode(config, 2, 200);
            defer live.deinit(gpa);
            const commitment = live.commitment();
            // The receiver tracks the commitment at view 1, subscribes, then sees it at view 4.
            try mailbox.gather(commitment, at(1));
            var live_sub = try mailbox.subscribe(commitment);
            defer live_sub.deinit();
            try mailbox.gather(commitment, at(4));
            // Blocks cached at views 2 and 5 exceed the window by one; the later gather
            // raised the commitment to view 4, so the block at view 2 is evicted.
            var lower = try harness.encode(config, 3, 300);
            defer lower.deinit(gpa);
            try mailbox.disperse(at(2), lower.clone());
            try mailbox.disperse(at(5), try harness.encode(config, 4, 400));
            try expect_cached(mailbox, lower.commitment(), false);
            try harness.expect_pending(&live_sub);
            // The assigned shard and three gossip shards reconstruct the block.
            try send_index(fixture, 0, 3, &live, 3);
            for ([_]usize{ 1, 2, 4 }) |index| try send_index(fixture, index, 3, &live, index);
            const latency = fixture.options.link.latency.as_millis_u64();
            var got = (try harness.recv_within(io, &live_sub, 10 * latency)) orelse
                return error.Timeout;
            defer got.deinit(gpa);
            try testing.expect(got.commitment().eql(commitment));
        }
    }.run);
}

test "cached observations refresh reconstruction state round" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10, .records = 2 });
            defer fixture.deinit();
            const config = fixture.coding_config;
            const mailbox = fixture.mailbox(3);
            var live = try harness.encode(config, 2, 200);
            defer live.deinit(gpa);
            const commitment = live.commitment();
            // Reconstruct from gossip while the assigned shard stays unverified.
            try mailbox.gather(commitment, at(1));
            for ([_]usize{ 1, 2, 4, 5 }) |index| try send_index(fixture, index, 3, &live, index);
            try fixture.latency(4);
            try expect_cached(mailbox, commitment, true);
            // A gather for the cached commitment at view 4 raises its round.
            var assigned_sub = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer assigned_sub.deinit();
            try mailbox.gather(commitment, at(4));
            var lower = try harness.encode(config, 3, 300);
            defer lower.deinit(gpa);
            try mailbox.disperse(at(2), lower.clone());
            try mailbox.disperse(at(5), try harness.encode(config, 4, 400));
            try expect_cached(mailbox, lower.commitment(), false);
            try harness.expect_pending(&assigned_sub);
            try expect_cached(mailbox, commitment, true);
            // The proposer's delivery of the assigned shard resolves the subscription.
            try send_index(fixture, 0, 3, &live, 3);
            const latency = fixture.options.link.latency.as_millis_u64();
            _ = (try harness.recv_within(io, &assigned_sub, 10 * latency)) orelse
                return error.Timeout;
        }
    }.run);
}

// When peer gossip reconstructs the block before the leader's direct shard arrives, the
// late leader shard is still accepted and verified (so the receiver relays it to slower
// peers), and gossip after both is ignored without blocking anyone.
test "late leader shard accepted after quorum transition" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            const leader: usize = 0;
            const victim: usize = 1;
            const oracle = fixture.network.oracle();
            try oracle.remove_link(fixture.peers[leader], fixture.peers[victim]);
            try fixture.mailbox(leader).disperse(at(1), block.clone());
            for (1..10) |index| try fixture.mailbox(index).gather(commitment, at(1));
            try fixture.latency(4);
            // The victim reconstructs from gossip before verifying its own shard.
            var block_sub = try fixture.mailbox(victim).subscribe(commitment);
            defer block_sub.deinit();
            var reconstructed = try harness.expect_resolves(io, &block_sub);
            defer reconstructed.deinit(gpa);
            try testing.expect(reconstructed.commitment().eql(commitment));
            const mailbox = fixture.mailbox(victim);
            var shard_sub = try mailbox.subscribe_assigned_shard_verified(commitment);
            defer shard_sub.deinit();
            try harness.expect_pending(&shard_sub);
            // Restore the link and resend the leader's shard, which arrives late.
            try oracle.add_link(fixture.peers[leader], fixture.peers[victim], harness.default_link);
            try send_index(fixture, leader, victim, &block, victim);
            try fixture.latency(2);
            try harness.expect_resolves(io, &shard_sub);
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
            // Gossip after reconstruction and assigned-shard verification is dropped silently.
            try send_index(fixture, 2, victim, &block, 2);
            try fixture.latency(2);
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
        }
    }.run);
}
