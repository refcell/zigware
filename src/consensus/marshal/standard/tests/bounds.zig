//! Round bounds on ancestry fetches (commonware #5717, `standard/mod.rs`
//! `test_standard_propose_requests_ancestry_under_its_round` and `issue_5718_regression`), and
//! `mailbox_provides_application_blocks`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks_block = @import("../../mocks/block.zig");
const mocks = @import("../../mocks/root.zig");
const ancestry = @import("../../ancestry.zig");
const handler = @import("../../resolver/handler.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const soak = @import("../../mocks/soak.zig");
const Ctx = runtime.deterministic.Context;
const Round = types.Round;
const D = harness.D;
const Block = common.Block;
const Started = common.Started(harness.Provider, App, common.RecordingBuffer);
const Marshal = Started.A.Mailbox;
const Stream = ancestry.AncestorStream(Marshal);
const Walking = mocks.verifying.WalkingVerifyingApp(harness.B, Ctx, harness.Ctx, Stream);
const Inline =
    @import("../inline.zig").Inline(Ctx, harness.S, Walking, harness.B, types.FixedEpocher);
const Deferred =
    @import("../deferred.zig").Deferred(Ctx, harness.S, Walking, harness.B, types.FixedEpocher);

test "standard mailbox provides application blocks" {
    // commonware `mailbox_provides_application_blocks`: the mailbox is a `BlockProvider` of the
    // application block.
    comptime ancestry.assert_block_provider(Marshal);
    try testing.expect(Marshal.Block == harness.B);
    try testing.expect(ancestry.ParentReceiver(Marshal) == Marshal.ParentReceiver);
}

fn run_for(seconds: u64, comptime body: fn (Ctx) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = seconds * std.time.ns_per_s };
    try soak.run(gpa, config, body, .{});
}

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

fn epocher() types.FixedEpocher {
    return .new(utils.NonZero(u64).init(harness.blocks_per_epoch).?);
}

/// A block by `leader` at view `view` over `(parent_view, parent)`, naming `parent`.
fn block_at(leader: harness.K, view: u64, parent_view: u64, parent: D, height: u64) !Block {
    const context: harness.Ctx = .{ .round = round_at(view), .leader = leader, .parent = .{
        .new(parent_view),
        parent,
    } };
    const raw = try harness.B.init(gpa, context, parent, .new(height), view * 100);
    return mocks_block.ready(harness.B, gpa, raw);
}

fn start(ctx: Ctx, fixture: *const harness.Fixture, comptime prefix: []const u8) !Started {
    const io = ctx.io();
    return common.start_standard_actor(
        harness.Provider,
        App,
        common.RecordingBuffer,
        ctx.child("validator"),
        prefix,
        .init(&fixture.schemes[0]),
        try App.init(gpa, io),
        try common.RecordingBuffer.init(gpa, io),
        .{ .genesis = try H.genesis_block(gpa, harness.num_validators) },
    );
}

fn has_fetches(resolver: common.RecordingResolver) bool {
    return resolver.fetch_count() > 0;
}

/// commonware `test_standard_propose_requests_ancestry_under_its_round`: a proposal is built
/// for one round, so each ancestor the build requests carries that round.
fn ProposeUnderRound(comptime W: type) type {
    return struct {
        fn propose(wrapper: *W, context: harness.Ctx) Io.Cancelable!?D {
            return wrapper.propose(undefined, context);
        }

        fn body(ctx: Ctx) anyerror!void {
            const io = ctx.io();
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            const name = if (W == Inline) "inline" else "deferred";
            var started = try start(ctx, &fixture, "propose-ancestry-round-" ++ name);
            defer started.crash();
            var genesis = try H.genesis_block(gpa, harness.num_validators);
            defer genesis.deinit();
            // The parent to build on is stored; the block below it is missing.
            const leader = fixture.participants[1];
            var missing = try block_at(leader, 1, 0, genesis.digest(), 1);
            defer missing.deinit();
            var parent = try block_at(leader, 2, 1, missing.digest(), 2);
            defer parent.deinit();
            try testing.expect(try started.mailbox.verified(round_at(2), parent.clone()));
            var walked: std.ArrayList(D) = .empty;
            defer walked.deinit(gpa);
            const app: Walking = .{ .gpa = gpa, .blocks = &walked };
            const marshal = started.mailbox.clone();
            const wrapper = try W.create(ctx.child("wrapper"), app, marshal, epocher());
            defer wrapper.destroy();
            defer io.sleep(.fromMilliseconds(100), .awake) catch {};
            const round = round_at(3);
            const context: harness.Ctx = .{
                .round = round,
                .leader = fixture.participants[0],
                .parent = .{ .new(2), parent.digest() },
            };
            var proposal = try io.concurrent(propose, .{ wrapper, context });
            defer _ = proposal.cancel(io) catch {};
            try common.wait_until(ctx, 5_000, "ancestry fetch", started.resolver, has_fetches);
            const fetches = try started.resolver.fetches(gpa);
            defer gpa.free(fetches);
            try testing.expectEqual(1, fetches.len);
            try testing.expect(fetches[0].key.eql(.{ .block = missing.digest() }));
            const expected: handler.Annotation = .{ .untrusted = .{
                .height = .new(1),
                .round = round,
            } };
            try testing.expect(fetches[0].subscriber.eql(expected));
        }
    };
}

test "inline propose requests ancestry under its round" {
    try run_for(30, ProposeUnderRound(Inline).body);
}

test "deferred propose requests ancestry under its round" {
    try run_for(30, ProposeUnderRound(Deferred).body);
}

/// The active fetches as (key, subscriber), sorted by key then subscriber.
fn active_sorted(resolver: common.RecordingResolver) ![]common.Fetch {
    const fetches = try resolver.active_fetches(gpa);
    const less = struct {
        fn less(_: void, a: common.Fetch, b: common.Fetch) bool {
            const by_key = a.key.order(b.key);
            if (by_key != .eq) return by_key == .lt;
            return a.subscriber.order(b.subscriber) == .lt;
        }
    }.less;
    std.mem.sort(common.Fetch, fetches, {}, less);
    return fetches;
}

fn two_active(resolver: common.RecordingResolver) bool {
    const fetches = resolver.active_fetches(gpa) catch return false;
    defer gpa.free(fetches);
    return fetches.len >= 2;
}

const Processed = struct { mailbox: *Marshal, height: u64 };

fn processed(state: Processed) bool {
    const position = state.mailbox.get_processed() catch return false;
    const value = position orelse return false;
    return value == .block and value.block.get() == state.height;
}

/// Votes for `block` through `wrapper`; the vote must be given.
fn vote(wrapper: *Deferred, block: *const Block) !void {
    const voted = try wrapper.verify(undefined, block.inner().context(), block.digest());
    try testing.expectEqual(@as(?bool, true), voted);
}

/// commonware `issue_5718_regression`: Deferred votes before storing a block, so after a crash
/// a validator can verify descendants of a block it lost. The walk below an unchecked
/// descendant requests the lost block by digest under a height only that descendant vouches
/// for, and the request ends once the round floor covers the verification's round.
fn issue_5718_body(ctx: Ctx) anyerror!void {
    const io = ctx.io();
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    var started = try start(ctx, &fixture, "issue-5718");
    defer started.crash();
    var genesis = try H.genesis_block(gpa, harness.num_validators);
    defer genesis.deinit();
    // The lost first block; the second follows it but claims height 15; the third follows.
    const leader = fixture.participants[1];
    var lost = try block_at(leader, 1, 0, genesis.digest(), 1);
    defer lost.deinit();
    var parent = try block_at(leader, 2, 1, lost.digest(), 15);
    defer parent.deinit();
    var candidate = try block_at(leader, 3, 2, parent.digest(), 16);
    defer candidate.deinit();
    try testing.expect(try started.mailbox.verified(round_at(2), parent.clone()));
    try testing.expect(try started.mailbox.verified(round_at(3), candidate.clone()));
    var walked: std.ArrayList(D) = .empty;
    defer walked.deinit(gpa);
    const app: Walking = .{ .gpa = gpa, .blocks = &walked };
    const marshal = started.mailbox.clone();
    const wrapper = try Deferred.create(ctx.child("deferred"), app, marshal, epocher());
    defer wrapper.destroy();
    defer io.sleep(.fromMilliseconds(100), .awake) catch {};
    try vote(wrapper, &parent);
    try vote(wrapper, &candidate);
    // The parent's verification requests the lost block by round; the walk below the parent
    // requests it by digest under the parent's implied height and the candidate's round.
    try common.wait_until(ctx, 5_000, "two active fetches", started.resolver, two_active);
    {
        const active = try active_sorted(started.resolver);
        defer gpa.free(active);
        try testing.expectEqual(2, active.len);
        try testing.expect(active[0].key.eql(.{ .block = lost.digest() }));
        const bound: handler.Annotation = .{ .untrusted = .{
            .height = .new(14),
            .round = round_at(3),
        } };
        try testing.expect(active[0].subscriber.eql(bound));
        try testing.expect(active[1].key.eql(.{ .notarized = round_at(1) }));
        try testing.expect(active[1].subscriber.eql(.{ .notarization = round_at(1) }));
    }
    try testing.expectEqualSlices(D, &.{ candidate.digest(), parent.digest() }, walked.items);
    // A block on genesis finalizes in view 4 at height 1; the candidate can never finalize.
    var finalized = try block_at(leader, 4, 0, genesis.digest(), 1);
    defer finalized.deinit();
    try testing.expect(try started.mailbox.verified(round_at(4), finalized.clone()));
    const proposal = harness.Proposal.init(round_at(4), .zero(), finalized.digest());
    var finalization = try harness.make_finalization(gpa, &fixture, proposal, harness.quorum);
    _ = started.mailbox.report(.{ .finalization = finalization });
    finalization.deinit(gpa);
    const state: Processed = .{ .mailbox = &started.mailbox, .height = 1 };
    try common.wait_until(ctx, 5_000, "processed height 1", state, processed);
    // Both requests end once the round floor covers the candidate's round.
    const active = try started.resolver.active_fetches(gpa);
    defer gpa.free(active);
    try testing.expectEqual(0, active.len);
}

test "issue 5718 regression: walk fetches retire at the round floor" {
    try run_for(30, issue_5718_body);
}
