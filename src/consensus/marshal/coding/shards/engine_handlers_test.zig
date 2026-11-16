//! Shard engine tests that drive an unstarted engine through its handlers, ported from
//! commonware `marshal/coding/shards/engine.rs`. Reconstruction runs inline, so where
//! commonware awaits a job and calls `complete`, the handler that supplied the last shard
//! has already cached the block.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const cryptography = @import("cryptography");

const harness = @import("engine_harness.zig");

const gpa = harness.gpa;
const Coded = harness.Coded;
const Commitment = harness.Commitment;
const Unstarted = harness.Unstarted;
const at = harness.at;
const make_block = harness.make_block;
const commitment_of = harness.commitment_of;
const shard_of = harness.shard_of;

fn record_of(engine: *Unstarted, commitment: Commitment) !*harness.ShardEngine.Record {
    return engine.engine.records.get(commitment) orelse error.MissingRecord;
}

fn expect_no_blocks(engine: *Unstarted) !void {
    try testing.expectEqual(@as(usize, 0), try harness.blocked_count(engine.network));
}

/// Applies every shard of `block` at `indices`, each from the peer at its index.
fn deliver_own(engine: *Unstarted, block: *const Coded, indices: []const usize) !void {
    for (indices) |index| try engine.shard(index, try shard_of(block, index));
}

test "subquorum reconstruction evicted by window" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const engine = try Unstarted.init(io, .{ .count = 10, .index = 3, .records = 4 });
            defer engine.deinit();
            const config = engine.coding_config;
            // The candidate at view 10 receives three of the four shards needed.
            var block = try make_block(config, 1);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try engine.gather(commitment, at(10));
            var subscription = try engine.subscribe(commitment);
            defer subscription.deinit();
            try deliver_own(engine, &block, &.{ 1, 2, 4 });
            // Records for three later views fill the window, and the candidate survives.
            for (11..14) |view| {
                try engine.gather(try commitment_of(config, view), at(view));
                engine.engine.trim();
                try testing.expect(engine.has_record(commitment));
            }
            // The record for the next view evicts the candidate. Its subscription stays open.
            try engine.gather(try commitment_of(config, 14), at(14));
            engine.engine.trim();
            try testing.expect(!engine.has_record(commitment));
            try testing.expectEqual(@as(usize, 4), engine.engine.records.count());
            try harness.expect_pending(&subscription);
            // The last shard enters its sender's buffer and rebuilds nothing.
            try engine.shard(5, try shard_of(&block, 5));
            try testing.expectEqual(@as(usize, 1), engine.buffered(5, commitment));
            try testing.expect(!engine.has_record(commitment));
            try harness.expect_pending(&subscription);
            try expect_no_blocks(engine);
        }
    }.run);
}

/// The first commitment, from id 100 on, that sorts above `lowest`.
fn commitment_above(config: anytype, lowest: Commitment) !Coded {
    for (100..200) |id| {
        var block = try make_block(config, id);
        if (block.commitment().order(lowest) == .gt) return block;
        block.deinit(gpa);
    }
    return error.NotFound;
}

test "full window declines rounds at or below lowest" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const engine = try Unstarted.init(io, .{ .records = 2 });
            defer engine.deinit();
            const config = engine.coding_config;
            for ([_]u64{ 5, 6 }) |view| {
                try engine.gather(try commitment_of(config, view), at(view));
                engine.engine.trim();
            }
            try testing.expectEqual(@as(usize, 2), engine.engine.records.count());
            // A sender-indexed shard for a commitment without a record is buffered.
            var block = try make_block(config, 1);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try engine.shard(1, try shard_of(&block, 1));
            try testing.expectEqual(@as(usize, 1), engine.buffered(1, commitment));
            // Gathers at and below the lowest retained view create no record.
            for ([_]u64{ 5, 4 }) |view| {
                try engine.gather(commitment, at(view));
                engine.engine.trim();
                try testing.expect(!engine.has_record(commitment));
                try testing.expectEqual(@as(usize, 1), engine.buffered(1, commitment));
            }
            try declined_block_resolves_subscriber(engine);
            // A gather above the lowest view creates the record and drains the buffer.
            try engine.gather(commitment, at(7));
            engine.engine.trim();
            try testing.expect(engine.has_record(commitment));
            try testing.expectEqual(@as(usize, 0), engine.buffered(1, commitment));
            try testing.expectEqual(@as(usize, 2), engine.engine.records.count());
            for (engine.engine.records.items()) |entry| {
                try testing.expect(entry.value.round.order(at(5)) == .gt);
            }
        }

        /// A block from the lowest retained view resolves its subscriber without a record.
        /// Its commitment sorts above the one retained at that view, which the window would
        /// evict first if the block were retained.
        fn declined_block_resolves_subscriber(engine: *Unstarted) !void {
            const lowest = try commitment_of(engine.coding_config, 5);
            var declined = try commitment_above(engine.coding_config, lowest);
            defer declined.deinit(gpa);
            const declined_commitment = declined.commitment();
            var subscription = try engine.subscribe(declined_commitment);
            defer subscription.deinit();
            try engine.engine.cache_block(at(5), declined.clone());
            engine.engine.trim();
            var delivered = try subscription.try_recv();
            defer delivered.deinit(gpa);
            try testing.expect(delivered.commitment().eql(declined_commitment));
            try testing.expect(!engine.has_record(declined_commitment));
            try testing.expect(engine.has_record(lowest));
            try testing.expectEqual(@as(usize, 2), engine.engine.records.count());
        }
    }.run);
}

test "same view records never evict later views" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const engine = try Unstarted.init(io, .{ .index = 2, .records = 4 });
            defer engine.deinit();
            const config = engine.coding_config;
            // The engine caches its own proposals at views 1, 2, 10, and 11.
            var proposed: [4]Commitment = undefined;
            for ([_]u64{ 1, 2, 10, 11 }, &proposed) |view, *commitment| {
                const block = try make_block(config, view);
                commitment.* = block.commitment();
                try engine.engine.disperse_shards(at(view), block);
                engine.engine.trim();
            }
            try testing.expectEqual(@as(usize, 4), engine.engine.records.count());
            // An equivocating leader at view 5: both commitments evict views 1 and 2.
            const tied = [2]Commitment{
                try commitment_of(config, 20),
                try commitment_of(config, 21),
            };
            for (tied) |commitment| {
                try engine.gather(commitment, at(5));
                engine.engine.trim();
            }
            try testing.expect(!engine.has_record(proposed[0]));
            try testing.expect(!engine.has_record(proposed[1]));
            for ([_]Commitment{ proposed[2], proposed[3], tied[0], tied[1] }) |commitment| {
                try testing.expect(engine.has_record(commitment));
            }
            // Further commitments at and below view 5 create no record.
            for ([_][2]u64{ .{ 22, 5 }, .{ 23, 4 } }) |pair| {
                const declined = try commitment_of(config, pair[0]);
                try engine.gather(declined, at(pair[1]));
                try testing.expect(!engine.has_record(declined));
            }
            try testing.expectEqual(@as(usize, 4), engine.engine.records.count());
            // A record above view 5 evicts the lower commitment of the tied pair.
            const lower_first = tied[0].order(tied[1]) == .lt;
            const lower = if (lower_first) tied[0] else tied[1];
            const higher = if (lower_first) tied[1] else tied[0];
            try engine.gather(try commitment_of(config, 24), at(12));
            engine.engine.trim();
            try testing.expect(!engine.has_record(lower));
            for ([_]Commitment{ higher, proposed[2], proposed[3] }) |commitment| {
                try testing.expect(engine.has_record(commitment));
            }
            try expect_no_blocks(engine);
        }
    }.run);
}

test "cached record retains no shards" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const engine = try Unstarted.init(io, .{});
            defer engine.deinit();
            const observer = try engine.observe(1);
            var block = try harness.encode(engine.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            // Gossip shards from peers 2 and 3 reconstruct the block before the assigned
            // shard arrives.
            try engine.gather(commitment, at(1));
            try deliver_own(engine, &block, &.{ 2, 3 });
            const record = try record_of(engine, commitment);
            try testing.expect(record.block != null);
            try testing.expect(record.reconstruction.?.quorum == null);
            // A shard that conflicts with peer 2's contribution is ignored without blocking.
            var other = try harness.encode(engine.coding_config, 1, 200);
            defer other.deinit(gpa);
            try engine.shard(2, try harness.shard_for(&other, 2, commitment));
            try expect_no_blocks(engine);
            // The proposer's late assigned shard is verified, resolves readiness, and is
            // gossiped.
            var verified = try engine.subscribe_assigned(commitment);
            defer verified.deinit();
            try harness.expect_pending(&verified);
            var assigned = try shard_of(&block, 0);
            defer assigned.deinit(gpa);
            try engine.shard(1, try assigned.clone(gpa));
            try verified.try_recv();
            const gossip = (try harness.recv_within(io, observer, 1_000)) orelse
                return error.NoGossip;
            try harness.expect_gossip(gossip, engine.me(), &assigned);
            try expect_no_blocks(engine);
        }
    }.run);
}

/// A record verifies and gossips its assigned shard, whether the proposer's delivery waits in
/// its buffer for the gather (`early`) or reaches the record after it cached the block, and
/// whether the local scheme can sign or only reports membership (`member`).
fn record_verifies_assigned_shard(io: Io, member: bool, early: bool) !void {
    const engine = try Unstarted.init(io, .{ .member = member });
    defer engine.deinit();
    const scheme = engine.provider.scheme(.zero()).?;
    const index = scheme.participants().index(engine.me()).?;
    const role: cryptography.certificate.Membership =
        if (member) .{ .member = index } else .{ .signer = index };
    try testing.expect(scheme.me().?.eql(role));
    const observer = try engine.observe(1);
    var block = try harness.encode(engine.coding_config, 1, 100);
    defer block.deinit(gpa);
    const commitment = block.commitment();
    var assigned = try shard_of(&block, 0);
    defer assigned.deinit(gpa);
    var verified = try engine.subscribe_assigned(commitment);
    defer verified.deinit();
    // Without a record, the proposer's delivery waits in its buffer; the gather drains it,
    // and readiness resolves before the block is reconstructed.
    if (early) {
        try engine.shard(1, try assigned.clone(gpa));
        try testing.expectEqual(@as(usize, 1), engine.buffered(1, commitment));
        try harness.expect_pending(&verified);
    }
    try engine.gather(commitment, at(1));
    if (early) {
        try testing.expectEqual(@as(usize, 0), engine.buffered(1, commitment));
        try verified.try_recv();
    }
    // Two shards decode the block: the assigned shard and one gossip shard, or two gossip
    // shards while the assigned shard has yet to arrive.
    const gossip: []const usize = if (early) &.{2} else &.{ 2, 3 };
    try deliver_own(engine, &block, gossip);
    try testing.expect((try record_of(engine, commitment)).block != null);
    if (!early) {
        try harness.expect_pending(&verified);
        try engine.shard(1, try assigned.clone(gpa));
        try testing.expectEqual(@as(usize, 0), engine.buffered(1, commitment));
        try verified.try_recv();
    }
    try expect_gossiped_once(engine, observer, commitment, &assigned);
}

/// The assigned shard is gossiped once: a repeated gather and a duplicate delivery gossip
/// nothing more.
fn expect_gossiped_once(
    engine: *Unstarted,
    observer: *harness.Net.Receiver,
    commitment: Commitment,
    assigned: *const harness.ShardType,
) !void {
    const gossip = (try harness.recv_within(engine.io, observer, 1_000)) orelse
        return error.NoGossip;
    try harness.expect_gossip(gossip, engine.me(), assigned);
    try engine.gather(commitment, at(1));
    try engine.shard(1, try assigned.clone(gpa));
    if (try harness.recv_within(engine.io, observer, 100)) |again| {
        harness.free_value(again);
        return error.GossipedTwice;
    }
    try expect_no_blocks(engine);
}

test "gather verifies buffered assigned shard" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try record_verifies_assigned_shard(io, false, true);
        }
    }.run);
}

test "cached record verifies late assigned shard" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try record_verifies_assigned_shard(io, false, false);
        }
    }.run);
}

test "member gather verifies buffered assigned shard" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try record_verifies_assigned_shard(io, true, true);
        }
    }.run);
}

test "member cached record verifies late assigned shard" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try record_verifies_assigned_shard(io, true, false);
        }
    }.run);
}

test "cached record classifies shards until assigned shard verified" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const engine = try Unstarted.init(io, .{});
            defer engine.deinit();
            try engine.track_all();
            var block = try harness.encode(engine.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try engine.gather(commitment, at(1));
            try deliver_own(engine, &block, &.{ 2, 3 });
            try testing.expect((try record_of(engine, commitment)).block != null);
            // Peer 1's gossip shard is ignored without blocking it.
            try engine.shard(1, try shard_of(&block, 1));
            try expect_no_blocks(engine);
            // Peer 2 delivers peer 3's shard and is blocked at once.
            try engine.shard(2, try shard_of(&block, 3));
            try testing.expectEqual(@as(usize, 0), engine.buffered(2, commitment));
            try harness.expect_blocked(engine.network, engine.me(), engine.peers[2]);
            // Peer 1 delivers the assigned shard, which is verified. Its delivery of peer 3's
            // shard is then ignored without blocking it.
            try engine.shard(1, try shard_of(&block, 0));
            const state = (try record_of(engine, commitment)).reconstruction.?;
            try testing.expect(state.assigned_verified);
            try engine.shard(1, try shard_of(&block, 3));
            try testing.expectEqual(@as(usize, 0), engine.buffered(1, commitment));
            try testing.expectEqual(@as(usize, 1), try harness.blocked_count(engine.network));
        }
    }.run);
}

test "repeated gather only refreshes round" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const engine = try Unstarted.init(io, .{});
            defer engine.deinit();
            const observer = try engine.observe(1);
            var block = try harness.encode(engine.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            // The first gather creates the record; peer 1's assigned shard is gossiped.
            try engine.gather(commitment, at(1));
            var assigned = try shard_of(&block, 0);
            defer assigned.deinit(gpa);
            try engine.shard(1, try assigned.clone(gpa));
            const gossip = (try harness.recv_within(io, observer, 1_000)) orelse
                return error.NoGossip;
            try harness.expect_gossip(gossip, engine.me(), &assigned);
            // A repeated gather for the reconstructing record raises its round.
            try engine.gather(commitment, at(3));
            var record = try record_of(engine, commitment);
            try testing.expect(record.block == null);
            try testing.expect(record.round == at(3));
            // Peer 2's gossip shard and the assigned shard decode the block.
            try engine.shard(2, try shard_of(&block, 2));
            // A repeated gather for the cached record raises its round.
            try engine.gather(commitment, at(5));
            record = try record_of(engine, commitment);
            try testing.expect(record.block != null);
            try testing.expect(record.round == at(5));
            // Neither repeated gather gossiped the assigned shard again or blocked anyone.
            if (try harness.recv_within(io, observer, 100)) |again| {
                harness.free_value(again);
                return error.GossipedTwice;
            }
            try expect_no_blocks(engine);
        }
    }.run);
}

test "failed reconstruction closes subscriptions" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const engine = try Unstarted.init(io, .{});
            defer engine.deinit();
            const config = engine.coding_config;
            // The commitment claims the digest of one block and the coding root of another.
            var claimed = try harness.encode(config, 1, 100);
            defer claimed.deinit(gpa);
            var actual = try harness.encode(config, 2, 200);
            defer actual.deinit(gpa);
            const real = actual.commitment();
            const digest = claimed.digest();
            const commitment = Commitment.init(digest, real.root(), real.context(), config);
            // The engine tracks the commitment and subscribes before any shard arrives.
            try engine.gather(commitment, at(1));
            var assigned = try engine.subscribe_assigned(commitment);
            defer assigned.deinit();
            var subscription = try engine.subscribe(commitment);
            defer subscription.deinit();
            // Gossip shards from peers 2 and 3 decode to a block with another digest.
            for ([_]usize{ 2, 3 }) |index| {
                try engine.shard(index, try harness.shard_for(&actual, index, commitment));
            }
            // The failure removes the record and closes both subscriptions without blocking.
            try testing.expect(!engine.has_record(commitment));
            try harness.expect_closed(&assigned);
            try harness.expect_closed(&subscription);
            try expect_no_blocks(engine);
        }
    }.run);
}
