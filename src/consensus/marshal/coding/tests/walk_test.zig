//! commonware `marshal/coding/mod.rs` ancestry-walk tests added by #5715 and #5717:
//! `test_coding_walk_ends_at_mismatched_parent_digest`, `issue_5716_regression`, and
//! `pr_5717_regression`.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const shared = @import("../../mocks/harness.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const Ctx = common.Ctx;
const H = common.H;
const quorum = shared.quorum;
const WalkingMarshaled = common.MarshaledOf(common.WalkingVerifyingApp);

/// The validators' fixture, seeded as commonware's `test_rng`.
fn fixture() !common.Fixture {
    var rng = utils.rng.test_rng();
    return H.fixture(gpa, &rng);
}

/// A coded block at `round` whose context names `parent` (view, commitment) and whose parent
/// field names `parent_field`.
fn block_at(
    leader: common.K,
    round: common.Round,
    parent: struct { u64, common.Commitment },
    parent_field: common.D,
    height: u64,
    timestamp: u64,
) !common.Block {
    const context: common.CodingCtx = .{
        .round = round,
        .leader = leader,
        .parent = .{ .new(parent[0]), parent[1] },
    };
    return common.coded(gpa, context, parent_field, height, timestamp);
}

fn Walk(comptime linked: bool) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("validator"),
                "walk-mismatched-parent-digest",
                provider,
                buffer,
            );
            defer stack.stop();

            // The parent's context names genesis, and its parent field names genesis only
            // when `linked`. The candidate names the parent in both places.
            const me = validators.participants[0];
            const genesis = try common.genesis_block(gpa);
            const genesis_commitment = try common.genesis_coding_commitment(gpa, &genesis);
            const parent_field = if (linked)
                genesis.digest()
            else
                common.Sha256.hash(&.{"not the context parent"});
            const parent_round = common.round_at(0, 1);
            var parent =
                try block_at(me, parent_round, .{ 0, genesis_commitment }, parent_field, 1, 100);
            defer parent.deinit(gpa);
            const round = common.round_at(0, 2);
            var candidate =
                try block_at(me, round, .{ 1, parent.commitment() }, parent.digest(), 2, 200);
            defer candidate.deinit(gpa);
            try testing.expect(try stack.mailbox.verified(parent_round, parent.clone()));
            try testing.expect(try stack.mailbox.verified(round, candidate.clone()));

            // Verify the candidate with an application that reads its ancestry down to
            // genesis and accepts only if it gets there.
            var shard_stack: common.ShardStack = undefined;
            const participants = validators.participants;
            const shards_ctx = ctx.child("shards");
            try common.start_shard_mailbox(&shard_stack, shards_ctx, participants, provider);
            defer shard_stack.stop();
            var walked: std.ArrayList(common.D) = .empty;
            defer walked.deinit(gpa);
            const app: common.WalkingVerifyingApp = .{ .gpa = gpa, .blocks = &walked };
            const config = common.marshaled_config(
                WalkingMarshaled,
                app,
                stack.mailbox.clone(),
                shard_stack.shards(),
                provider,
            );
            var marshaled = try WalkingMarshaled.init(ctx.child("marshaled"), config);
            defer marshaled.deinit();
            var verify = try marshaled.start_verify(candidate.context(), candidate.commitment());
            defer verify.deinit();
            var certify = try marshaled.start_certify(round, candidate.commitment());
            defer certify.deinit();
            const verdict = try certify.recv();

            // A linked parent leads the walk to genesis. A mismatched one ends it at the
            // parent, and nothing is requested from peers in either case.
            const expected = [_]common.D{ candidate.digest(), parent.digest(), genesis.digest() };
            const walk_len: usize = if (linked) 3 else 2;
            try testing.expectEqual(walk_len, walked.items.len);
            for (expected[0..walk_len], walked.items) |want, got| {
                try testing.expect(want.eql(got));
            }
            try testing.expectEqual(linked, verdict);
            try testing.expectEqual(0, stack.resolver.fetch_count());
        }
    };
}

test "coding walk ends at mismatched parent digest" {
    try common.run(Walk(true).body);
    try common.run(Walk(false).body);
}
