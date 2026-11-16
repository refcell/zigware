//! Shard engine tests of non-participants and committee members without a signing share on
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

fn expect_cached(mailbox: harness.Mailbox, commitment: Commitment, cached: bool) !void {
    var got = try mailbox.get(commitment);
    defer if (got) |*value| value.deinit(gpa);
    try testing.expectEqual(cached, got != null);
}

fn expect_no_blocks(fixture: *Fixture) !void {
    try testing.expectEqual(@as(usize, 0), try harness.blocked_count(fixture.network));
}

fn expect_assigned(io: Io, mailbox: harness.Mailbox, commitment: Commitment) !void {
    var receiver = try mailbox.subscribe_assigned_shard_verified(commitment);
    defer receiver.deinit();
    try harness.expect_resolves(io, &receiver);
}

fn expect_block(io: Io, mailbox: harness.Mailbox, commitment: Commitment) !void {
    var receiver = try mailbox.subscribe(commitment);
    defer receiver.deinit();
    var got = try harness.expect_resolves(io, &receiver);
    defer got.deinit(gpa);
    try testing.expect(got.commitment().eql(commitment));
}

test "disperse routes participant and non participant shards" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .secondary = 1 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try fixture.mailbox(0).disperse(at(1), block.clone());
            for (1..5) |index| try fixture.mailbox(index).gather(commitment, at(1));
            try fixture.latency(2);
            for (0..4) |index| try expect_assigned(io, fixture.mailbox(index), commitment);
            try fixture.latency(1);
            // The non-participant reconstructs from the leader's shard and the participants'
            // gossip; with no assigned shard, its readiness stays pending.
            const outsider = fixture.mailbox(4);
            try expect_cached(outsider, commitment, true);
            var ready = try outsider.subscribe_assigned_shard_verified(commitment);
            defer ready.deinit();
            try expect_cached(outsider, commitment, true);
            try harness.expect_pending(&ready);
            try expect_no_blocks(fixture);
        }
    }.run);
}

test "non participant reconstructs after gather" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .secondary = 1 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try fixture.mailbox(0).disperse(at(1), block.clone());
            for (1..4) |index| try fixture.mailbox(index).gather(commitment, at(1));
            try fixture.latency(1);
            // The non-participant gathers while shards are already propagating.
            const outsider = fixture.mailbox(4);
            var block_sub = try outsider.subscribe(commitment);
            defer block_sub.deinit();
            try outsider.gather(commitment, at(1));
            var got = try harness.expect_resolves(io, &block_sub);
            defer got.deinit(gpa);
            try testing.expectEqual(block.height().get(), got.height().get());
            try expect_no_blocks(fixture);
        }
    }.run);
}

/// Peer 1 runs a member scheme that cannot sign; the leader's shard reaches it after the
/// gather or, when `buffered`, before. Peer 3 cannot reach peer 2, so peer 2 reconstructs
/// (minimum two shards) only if the member gossips its verified shard.
fn member_accepts_assigned_shard(io: Io, buffered: bool) !void {
    const fixture = try Fixture.init(io, .{ .shareless_member = 1 });
    defer fixture.deinit();
    var block = try harness.encode(fixture.coding_config, 1, 100);
    defer block.deinit(gpa);
    const commitment = block.commitment();
    try fixture.network.oracle().remove_link(fixture.peers[3], fixture.peers[2]);
    const member = fixture.mailbox(1);
    if (!buffered) {
        try member.gather(commitment, at(1));
        try fixture.latency(2);
    }
    try fixture.mailbox(0).disperse(at(1), block.clone());
    try fixture.latency(2);
    if (buffered) {
        try expect_no_blocks(fixture);
        try member.gather(commitment, at(1));
        try fixture.latency(2);
    }
    // The leader's shard at the member's index verifies as its assigned shard.
    try expect_no_blocks(fixture);
    try expect_assigned(io, member, commitment);
    for (2..4) |index| try fixture.mailbox(index).gather(commitment, at(1));
    try expect_block(io, member, commitment);
    try expect_block(io, fixture.mailbox(2), commitment);
    try expect_no_blocks(fixture);
}

test "committee member without share accepts assigned shard after gather" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try member_accepts_assigned_shard(io, false);
        }
    }.run);
}

test "committee member without share accepts assigned shard after buffered delivery" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            try member_accepts_assigned_shard(io, true);
        }
    }.run);
}

test "committee member without share disperses proposal" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .shareless_member = 0 });
            defer fixture.deinit();
            var block = try harness.encode(fixture.coding_config, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try fixture.mailbox(1).gather(commitment, at(1));
            try fixture.latency(2);
            try fixture.mailbox(0).disperse(at(1), block.clone());
            try expect_assigned(io, fixture.mailbox(1), commitment);
            try expect_no_blocks(fixture);
        }
    }.run);
}
