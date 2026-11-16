//! Shard engine tests on a custom coding scheme, ported from commonware
//! `marshal/coding/shards/engine.rs`. commonware's `Gated` and `Recording` schemes back its
//! reconstruction job tests, which have no counterpart: reconstruction runs inline.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Io = std.Io;
const coding = @import("coding");
const parallel = @import("parallel");

const harness = @import("engine_harness.zig");
const engine_module = @import("engine.zig");

const gpa = harness.gpa;
const C = harness.C;

/// Reed-Solomon coding that checks only the assigned shard (index 3) eagerly and every
/// other shard in one batch of seven (commonware `BatchChecking`).
const BatchChecking = struct {
    pub const Commitment = C.Commitment;
    pub const Shard = C.Shard;
    pub const CheckedShard = C.CheckedShard;
    pub const ShardRef = C.ShardRef;
    pub const Error = C.Error;

    /// The batches `check_many` has checked.
    var batches: u32 = 0;

    pub fn max_shard_size(config: coding.Config, data: usize) usize {
        return C.max_shard_size(config, data);
    }

    pub fn encode(
        allocator: Allocator,
        config: coding.Config,
        data: []const u8,
        strategy: anytype,
    ) @typeInfo(@TypeOf(C.encode)).@"fn".return_type.? {
        return C.encode(allocator, config, data, strategy);
    }

    pub fn check(
        config: coding.Config,
        commitment: *const Commitment,
        index: u16,
        shard: *const Shard,
        strategy: anytype,
    ) Error!CheckedShard {
        assert(index == 3); // Only the assigned shard is checked eagerly.
        return C.check(config, commitment, index, shard, strategy);
    }

    pub fn check_many(
        allocator: Allocator,
        config: coding.Config,
        commitment: *const Commitment,
        shards: []const ShardRef,
        out: []Error!CheckedShard,
        strategy: anytype,
    ) Allocator.Error!void {
        assert(shards.len == 7);
        batches += 1;
        try C.check_many(allocator, config, commitment, shards, out, strategy);
    }

    pub fn decode(
        allocator: Allocator,
        config: coding.Config,
        commitment: *const Commitment,
        checked: []const CheckedShard,
        strategy: anytype,
    ) Error![]u8 {
        return C.decode(allocator, config, commitment, checked, strategy);
    }
};

const Engine = engine_module.Engine(harness.TypesOf(BatchChecking));
const Unstarted = harness.UnstartedOf(Engine);

test "pending shards batch validated at quorum" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            BatchChecking.batches = 0;
            const engine = try Unstarted.init(io, .{ .count = 22, .index = 3 });
            defer engine.deinit();
            const empty = harness.B.init(.empty, .new(1), 100);
            const config = engine.coding_config;
            const shared = try Engine.Coded.Inner.compute(gpa, empty);
            var block = try Engine.Coded.encode(gpa, shared, config, parallel.sequential);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try engine.gather(commitment, harness.at(1));
            // Peer-indexed shards queue until the assigned shard completes the quorum.
            for ([_]usize{ 1, 2, 4, 5, 6, 7, 8 }) |index| {
                try engine.shard(index, (try block.shard(gpa, @intCast(index))).?);
            }
            try testing.expectEqual(@as(u32, 0), BatchChecking.batches);
            try testing.expect(engine.engine.records.get(commitment).?.block == null);
            // The proposer supplies the eagerly checked assigned shard; eight checked shards
            // reconstruct the block.
            try engine.shard(0, (try block.shard(gpa, 3)).?);
            try testing.expectEqual(@as(u32, 1), BatchChecking.batches);
            const record = engine.engine.records.get(commitment).?;
            const cached = record.block orelse return error.NotReconstructed;
            try testing.expect(cached.commitment().eql(commitment));
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(engine.network));
        }
    }.run);
}
