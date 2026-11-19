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

/// The active fetches, sorted by key then subscriber; the caller frees the slice.
fn active_sorted(resolver: common.RecordingResolver) ![]common.Fetch {
    const active = try resolver.active_fetches(gpa);
    std.mem.sort(common.Fetch, active, {}, struct {
        fn less(_: void, a: common.Fetch, b: common.Fetch) bool {
            const by_key = a.key.order(b.key);
            if (by_key != .eq) return by_key == .lt;
            return a.subscriber.order(b.subscriber) == .lt;
        }
    }.less);
    return active;
}

/// Sleeps until `resolver` holds at least `count` active fetches.
fn wait_active(ctx: Ctx, resolver: common.RecordingResolver, count: usize) !void {
    var waited: u32 = 0;
    while (true) : (waited += 1) {
        if (waited > 5_000) return error.TestTimedOut;
        const active = try resolver.active_fetches(gpa);
        defer gpa.free(active);
        if (active.len >= count) return;
        try ctx.sleep(.fromMilliseconds(1));
    }
}

/// A block of the 5716 chain: in epoch 0 at `view`, led by `leader`, whose context and parent
/// field both name `parent`.
fn chain_block(
    leader: common.K,
    view: u64,
    parent: struct { u64, common.Commitment },
    height: u64,
    timestamp: u64,
) !common.Block {
    const round = common.round_at(0, view);
    return block_at(leader, round, parent, parent[1].block(), height, timestamp);
}

/// commonware `issue_5716_regression`: with optimistic validation a coding validator verifies
/// a block whose parent was never checked against a grandparent it does not hold. The walk
/// below the parent requests the grandparent by commitment under a height only the parent
/// vouches for, and the request ends once the processed round floor covers the round
/// consensus bound to the grandparent.
fn issue_5716(ctx: Ctx) anyerror!void {
    var validators = try fixture();
    defer validators.deinit(gpa);
    const provider: common.Provider = .init(&validators.schemes[0]);
    var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
    defer buffer.deinit();
    const validator_ctx = ctx.child("validator");
    var stack =
        try common.start_coding_actor_with_recording(validator_ctx, "issue-5716", provider, buffer);
    defer stack.stop();

    // The leader of views 1 to 3 withholds its first block. Its second block follows the first
    // in consensus and claims a height far above it, and its third follows the second.
    const leader = validators.participants[1];
    const genesis = try common.genesis_block(gpa);
    const genesis_commitment = try common.genesis_coding_commitment(gpa, &genesis);
    var withheld = try chain_block(leader, 1, .{ 0, genesis_commitment }, 1, 100);
    defer withheld.deinit(gpa);
    var parent = try chain_block(leader, 2, .{ 1, withheld.commitment() }, 15, 200);
    defer parent.deinit(gpa);
    var candidate = try chain_block(leader, 3, .{ 2, parent.commitment() }, 16, 300);
    defer candidate.deinit(gpa);
    const withheld_round = common.round_at(0, 1);
    try testing.expect(try stack.mailbox.verified(common.round_at(0, 2), parent.clone()));
    try testing.expect(try stack.mailbox.verified(common.round_at(0, 3), candidate.clone()));

    // Verify both with an application that reads a block's ancestry down to genesis.
    var shard_stack: common.ShardStack = undefined;
    const participants = validators.participants;
    try common.start_shard_mailbox(&shard_stack, ctx.child("shards"), participants, provider);
    defer shard_stack.stop();
    var walked: std.ArrayList(common.D) = .empty;
    defer walked.deinit(gpa);
    const app: common.WalkingVerifyingApp = .{ .gpa = gpa, .blocks = &walked };
    const marshal = stack.mailbox.clone();
    const config =
        common.marshaled_config(WalkingMarshaled, app, marshal, shard_stack.shards(), provider);
    var marshaled = try WalkingMarshaled.init(ctx.child("marshaled"), config);
    defer marshaled.deinit();
    var parent_verify = try marshaled.start_verify(parent.context(), parent.commitment());
    defer parent_verify.deinit();
    var verify = try marshaled.start_verify(candidate.context(), candidate.commitment());
    defer verify.deinit();

    // Verifying the parent requests the withheld block by round. The walk below the parent
    // requests it by commitment, under the height the parent implies and the round the
    // parent's context names.
    try wait_active(ctx, stack.resolver, 2);
    try expect_5716_requests(stack.resolver, &withheld, withheld_round);
    try testing.expectEqual(2, walked.items.len);
    try testing.expect(walked.items[0].eql(candidate.digest()));
    try testing.expect(walked.items[1].eql(parent.digest()));

    // A block on genesis finalizes in view 4 at height 1. The withheld block was proposed in
    // view 1, so it can never finalize, and the chain is far below the parent's claim.
    try finalize_view_4(ctx, &stack, &validators, leader, genesis_commitment);
    const active = try stack.resolver.active_fetches(gpa);
    defer gpa.free(active);
    // Both requests end once the round floor covers the withheld block's round.
    try testing.expectEqual(0, active.len);
}

fn expect_5716_requests(
    resolver: common.RecordingResolver,
    withheld: *const common.Block,
    withheld_round: common.Round,
) !void {
    const active = try active_sorted(resolver);
    defer gpa.free(active);
    try testing.expectEqual(2, active.len);
    const by_commitment: common.Fetch = .{
        .key = .{ .block = withheld.commitment() },
        .subscriber = .{ .untrusted = .{ .height = .new(14), .round = withheld_round } },
    };
    const by_round: common.Fetch = .{
        .key = .{ .notarized = withheld_round },
        .subscriber = .{ .notarization = withheld_round },
    };
    for ([_]common.Fetch{ by_commitment, by_round }, active) |want, got| {
        try testing.expect(want.key.eql(got.key));
        try testing.expect(want.subscriber.eql(got.subscriber));
    }
}

/// Finalizes a height-1 block on genesis at view 4 and waits until marshal processes it.
fn finalize_view_4(
    ctx: Ctx,
    stack: *common.ActorStack,
    validators: *const common.Fixture,
    leader: common.K,
    genesis_commitment: common.Commitment,
) !void {
    var finalized = try chain_block(leader, 4, .{ 0, genesis_commitment }, 1, 400);
    defer finalized.deinit(gpa);
    const round = common.round_at(0, 4);
    try testing.expect(try stack.mailbox.verified(round, finalized.clone()));
    const proposal = common.Proposal.init(round, .zero(), finalized.commitment());
    var finalization = try H.make_finalization(gpa, validators, proposal, quorum);
    defer finalization.deinit(gpa);
    _ = stack.mailbox.report(.{ .finalization = finalization });
    var waited: u32 = 0;
    while (true) : (waited += 1) {
        if (waited > 5_000) return error.TestTimedOut;
        const processed = try stack.mailbox.get_processed();
        if (processed) |value| if (std.meta.eql(value, .{ .block = .new(1) })) return;
        try ctx.sleep(.fromMilliseconds(1));
    }
}

test "issue 5716 regression" {
    try common.run(issue_5716);
}

/// Epochs whose cache archives are open under the metrics root `validator_actor_cache`,
/// ascending (commonware `opened_cache_epochs`): each open epoch's finalizations archive
/// registers an `items_tracked` gauge labeled with the epoch.
fn opened_cache_epochs(ctx: Ctx, out: []u64) ![]u64 {
    const text = try ctx.scope.encode(gpa);
    defer gpa.free(text);
    const needle = "validator_actor_cache_cache_finalizations_items_tracked{";
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, needle)) continue;
        const label = "epoch=\"";
        const start = (std.mem.indexOf(u8, line, label) orelse return error.TestNoEpoch) +
            label.len;
        const end = start + (std.mem.indexOfScalar(u8, line[start..], '"') orelse
            return error.TestNoEpoch);
        if (count == out.len) return error.TestTooManyEpochs;
        out[count] = try std.fmt.parseInt(u64, line[start..end], 10);
        count += 1;
    }
    std.sort.pdq(u64, out[0..count], {}, std.sort.asc(u64));
    return out[0..count];
}

fn expect_opened(ctx: Ctx, expected: []const u64) !void {
    var buffer: [8]u64 = undefined;
    try testing.expectEqualSlices(u64, expected, try opened_cache_epochs(ctx, &buffer));
}

/// The newest recorded fetch, after waiting for more than `count`.
fn next_fetch(ctx: Ctx, resolver: common.RecordingResolver, count: usize) !common.Fetch {
    var waited: u32 = 0;
    while (resolver.fetch_count() <= count) : (waited += 1) {
        if (waited > 5_000) return error.TestTimedOut;
        try ctx.sleep(.fromMilliseconds(1));
    }
    const fetches = try resolver.fetches(gpa);
    defer gpa.free(fetches);
    return fetches[count];
}

/// commonware `pr_5717_regression`: a coding validator votes before it holds a block, so a
/// notarized coded block can claim any height. A walk from one requests its parent under the
/// height the child implies, and the parent can claim a height in an epoch consensus has not
/// reached. Marshal delivers the parent to the walk without caching it or opening a cache
/// for that epoch; once a round of that epoch is cached, the same response is cached too.
fn pr_5717(ctx: Ctx) anyerror!void {
    var validators = try fixture();
    defer validators.deinit(gpa);
    const provider: common.Provider = .init(&validators.schemes[0]);
    var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
    defer buffer.deinit();
    const validator_ctx = ctx.child("validator");
    var stack =
        try common.start_coding_actor_with_recording(validator_ctx, "pr-5717", provider, buffer);
    defer stack.stop();

    // Consensus is in epoch 0. The leader of views 1 and 2 proposes a block and its child at
    // heights that map to epoch 64.
    const leader = validators.participants[1];
    const height = shared.blocks_per_epoch * 64;
    const genesis = try common.genesis_block(gpa);
    const genesis_commitment = try common.genesis_coding_commitment(gpa, &genesis);
    const parent_round = common.round_at(0, 1);
    var parent = try block_at(
        leader,
        parent_round,
        .{ 0, genesis_commitment },
        genesis_commitment.block(),
        height,
        height,
    );
    defer parent.deinit(gpa);
    const round = common.round_at(0, 2);
    var child = try block_at(
        leader,
        round,
        .{ 1, parent.commitment() },
        parent.digest(),
        height + 1,
        height + 1,
    );
    defer child.deinit(gpa);
    const parent_bytes = try common.encode_coded(gpa, &parent);
    defer gpa.free(parent_bytes);

    // The validator holds the child, as once its notarization is fetched, and an
    // application walks from it.
    try testing.expect(try stack.mailbox.verified(round, child.clone()));
    const fallback: @import("../../core/mailbox.zig").DigestFallback = .{ .fetch_by_round = round };
    var ancestry = (try stack.mailbox.ancestry_from(fallback, child.digest(), null)) orelse
        return error.StreamMissing;
    defer ancestry.deinit();
    try expect_next(&ancestry, child.digest());

    // The walk requests the parent under the height the child implies.
    const request: common.Fetch = .{
        .key = .{ .block = parent.commitment() },
        .subscriber = .{ .untrusted = .{ .height = .new(height), .round = parent_round } },
    };
    const first = try next_fetch(ctx, stack.resolver, 0);
    try expect_fetch(request, first);

    // A peer serves the parent, and the walk reads it. Marshal answers a query only after it
    // has finished with the delivery: it did not cache the parent, and epoch 0 is still the
    // only epoch with a cache.
    try testing.expect(try stack.resolver.deliver(first, parent_bytes));
    try expect_next(&ancestry, parent.digest());
    try testing.expect(try stack.mailbox.get_block(.{ .digest = parent.digest() }) == null);
    try expect_opened(ctx, &.{0});

    try serve_after_epoch_reached(ctx, &stack, leader, &parent, parent_bytes, request);
}

/// Consensus reaches epoch 64 and the validator stores a candidate of that epoch; the same
/// request is served again, and the parent is cached under epoch 64.
fn serve_after_epoch_reached(
    ctx: Ctx,
    stack: *common.ActorStack,
    leader: common.K,
    parent: *const common.Block,
    parent_bytes: []const u8,
    request: common.Fetch,
) !void {
    const height = request.subscriber.untrusted.height.get();
    const genesis = try common.genesis_block(gpa);
    const genesis_commitment = try common.genesis_coding_commitment(gpa, &genesis);
    const reached = common.round_at(64, 1);
    var candidate = try block_at(
        leader,
        reached,
        .{ 0, genesis_commitment },
        genesis_commitment.block(),
        height + 2,
        height + 2,
    );
    defer candidate.deinit(gpa);
    try testing.expect(try stack.mailbox.verified(reached, candidate.clone()));

    const fallback: @import("../../core/mailbox.zig").CommitmentFallback = .{
        .fetch_by_commitment = .{
            .height = request.subscriber.untrusted.height,
            .round = request.subscriber.untrusted.round,
        },
    };
    var again = try stack.mailbox.subscribe_by_commitment(parent.commitment(), fallback);
    defer again.deinit();
    const second = try next_fetch(ctx, stack.resolver, 1);
    try expect_fetch(request, second);
    try testing.expect(try stack.resolver.deliver(second, parent_bytes));
    var received = try again.recv();
    defer received.deinit(gpa);
    try testing.expect(received.digest().eql(parent.digest()));
    var stored = (try stack.mailbox.get_block(.{ .digest = parent.digest() })) orelse
        return error.ParentNotCached;
    stored.deinit(gpa);
    try expect_opened(ctx, &.{ 0, 64 });
}

fn expect_next(ancestry: *common.Ancestry, digest: common.D) !void {
    var block = (try ancestry.next()) orelse return error.StreamEnded;
    defer block.deinit();
    try testing.expect(block.digest().eql(digest));
}

fn expect_fetch(want: common.Fetch, got: common.Fetch) !void {
    try testing.expect(want.key.eql(got.key));
    try testing.expect(want.subscriber.eql(got.subscriber));
}

test "pr 5717 regression" {
    try common.run(pr_5717);
}
