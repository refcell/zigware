//! Local block handling and recoverability after restarts (commonware
//! `marshal/standard/mod.rs`, lines 176-432 and 514-562). The recoverable family runs the
//! generic scenarios in `mocks/scenarios_recoverable.zig` on the standard harness.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks = @import("../../mocks/root.zig");
const mocks_block = @import("../../mocks/block.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = mocks.Application(B);
const Validator = H.Validator(App);
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;
const D = harness.D;
const B = harness.B;
const DigestCounter = mocks_block.DigestCounter;
const Marshal = @FieldType(Validator, "mailbox");
const Stream = @import("../../ancestry.zig").AncestorStream(Marshal);
const Mock = mocks.verifying.MockVerifyingApp(B, Ctx, harness.Ctx, Stream);
const InlineWrapper = @import("../inline.zig").Inline(Ctx, harness.S, Mock, B, types.FixedEpocher);
const DeferredWrapper =
    @import("../deferred.zig").Deferred(Ctx, harness.S, Mock, B, types.FixedEpocher);

fn epocher() types.FixedEpocher {
    return .new(utils.NonZero(u64).init(harness.blocks_per_epoch).?);
}

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// Validator 0 under `ctx.child(name)` with three pending acks and a manually acknowledging
/// application (commonware `setup_validator_with(.., NZUsize!(3), manual_ack())`).
fn start_manual(
    ctx: Ctx,
    comptime name: []const u8,
    network: *harness.TestNetwork,
    fixture: *const harness.Fixture,
) !*Validator {
    const provider: harness.Provider = .init(&fixture.schemes[0]);
    const application = try App.manual_ack(gpa, ctx.io());
    const me = fixture.participants[0];
    return Validator.setup(ctx.child(name), network.network, me, provider, 3, application);
}

fn pending_count(application: App) !usize {
    const heights = try application.pending_ack_heights(gpa);
    defer gpa.free(heights);
    return heights.len;
}

/// Waits up to a second of simulated time for `cond(arg)`.
fn wait_for(ctx: Ctx, arg: anytype, comptime cond: fn (@TypeOf(arg)) anyerror!bool) !void {
    const start = ctx.current();
    while (!try cond(arg)) {
        const elapsed = start.durationTo(ctx.current()).toNanoseconds();
        if (elapsed > std.time.ns_per_s) return error.WaitTimedOut;
        try ctx.sleep(.fromMilliseconds(1));
    }
}

const HeightHeld = struct { application: App, height: u64 };

fn holds_height(state: HeightHeld) anyerror!bool {
    return state.application.contains(.new(state.height));
}

fn three_pending(application: App) anyerror!bool {
    return try pending_count(application) == 3;
}

/// Proposes, relays, certifies, and finalizes block `height` through a wrapper of kind `W`,
/// checking that none of it reads the block's digest again; returns its digest.
fn propose_and_finalize(
    comptime W: type,
    ctx: Ctx,
    fixture: *const harness.Fixture,
    validator: *Validator,
    height: u64,
    parent: D,
) !D {
    const round = round_at(height);
    const context: harness.Ctx = .{
        .round = round,
        .leader = fixture.participants[0],
        .parent = .{ .new(height - 1), parent },
    };
    const block = try B.init(gpa, context, parent, .new(height), 0x1DE_0000 + height);
    DigestCounter.track(block.digest_value.as_slice());
    const app = Mock.init(gpa).with_propose_result(block);
    const child = ctx.child("proposal").with_attribute("height", height);
    const wrapper = try W.create(child, app, validator.mailbox.clone(), epocher());
    defer wrapper.destroy();
    const digest = (try wrapper.propose(undefined, context)) orelse return error.NoProposal;
    // Proposal hashing: one digest per built block.
    try testing.expectEqual(height, DigestCounter.count());
    try testing.expectEqual(.ok, wrapper.broadcast(digest, .{ .propose = .{ .round = round } }));
    try testing.expectEqual(@as(?bool, true), try wrapper.certify(undefined, round, digest));
    var cached = (try validator.mailbox.get_block(.{ .digest = digest })) orelse
        return error.BlockMissing;
    defer cached.deinit();
    try testing.expect(std.meta.eql(cached.inner().*, block));
    // Sealing and relaying read no digest.
    try testing.expectEqual(height, DigestCounter.count());
    const proposal = harness.Proposal.init(round, .new(height - 1), digest);
    var finalization = try harness.make_finalization(gpa, fixture, proposal, harness.quorum);
    defer finalization.deinit(gpa);
    try testing.expectEqual(.ok, wrapper.report(.{ .finalization = finalization }));
    const held: HeightHeld = .{ .application = validator.application, .height = height };
    try wait_for(ctx, held, holds_height);
    // Live dispatch reads no digest.
    try testing.expectEqual(height, DigestCounter.count());
    // Let detached tasks (a store behind a sent verdict) finish before the wrapper goes.
    try ctx.sleep(.fromMilliseconds(100));
    return digest;
}

/// Walks the parents of the block `tip` down to genesis, reading no digest.
fn walk_ancestry(validator: *Validator, tip: D) !void {
    var cursor = (try validator.mailbox.get_block(.{ .digest = tip })) orelse
        return error.BlockMissing;
    defer cursor.deinit();
    var expected: u64 = 3;
    while (expected > 0) {
        expected -= 1;
        var parent = try validator.mailbox.subscribe_parent(&cursor);
        defer parent.deinit();
        const next = try parent.recv();
        cursor.deinit();
        cursor = next;
        try testing.expectEqual(Height.new(expected), cursor.inner().height());
    }
    try testing.expectEqual(3, DigestCounter.count());
}

/// Local blocks compute their digest once on the live path, and a restart reads each one
/// once more when it restores the successor and replays the blocks.
fn DigestOnce(comptime W: type) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            DigestCounter.reset();
            defer DigestCounter.reset();
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var network: harness.TestNetwork =
                try .start(gpa, ctx.io(), 1, fixture.participants, 1024 * 1024);
            defer network.stop();
            const validator = try start_manual(ctx, "validator", &network, &fixture);
            try testing.expectEqual(Height.new(0), try validator.application.acknowledged());
            var genesis = try H.genesis_block(gpa, harness.num_validators);
            defer genesis.deinit();
            var digests: [3]D = undefined;
            var parent = genesis.digest();
            for (&digests, 1..) |*digest, height| {
                digest.* = try propose_and_finalize(W, ctx, &fixture, validator, height, parent);
                parent = digest.*;
            }
            try walk_ancestry(validator, parent);
            try testing.expectEqual(3, try pending_count(validator.application));
            validator.crash();
            try expect_restart_replays(ctx, &network, &fixture, &digests);
        }
    };
}

/// Restarts the validator and checks that it restores the successor and replays each block
/// with one digest read apiece, and that keyed archive reads read none.
fn expect_restart_replays(
    ctx: Ctx,
    network: *harness.TestNetwork,
    fixture: *const harness.Fixture,
    digests: *const [3]D,
) !void {
    const restarted = try start_manual(ctx, "restart", network, fixture);
    defer restarted.crash();
    try testing.expectEqual(@as(?Height, .zero()), restarted.height);
    // Startup checks the stored successor against its finalization before replay.
    try testing.expectEqual(4, DigestCounter.count());
    try wait_for(ctx, restarted.application, three_pending);
    // One restoration per replay.
    try testing.expectEqual(7, DigestCounter.count());
    for (digests) |digest| {
        for (0..2) |_| {
            var block = (try restarted.mailbox.get_block(.{ .digest = digest })) orelse
                return error.BlockMissing;
            defer block.deinit();
            try testing.expect(block.digest().eql(digest));
        }
    }
    // Keyed archive reads read no digest.
    try testing.expectEqual(7, DigestCounter.count());
}

test "inline local blocks compute digest once and replay once" {
    try run(DigestOnce(InlineWrapper).body);
}

test "deferred local blocks compute digest once and replay once" {
    try run(DigestOnce(DeferredWrapper).body);
}

/// The parent walkback of a standard block subscribes by the parent commitment.
fn parent_by_commitment_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    const Started = common.Started(harness.Provider, App, common.RecordingBuffer);
    var started: Started = try common.start_standard_actor(
        harness.Provider,
        App,
        common.RecordingBuffer,
        ctx.child("validator"),
        "standard-provider-parent-commitment",
        .init(&fixture.schemes[0]),
        try App.manual_ack(gpa, ctx.io()),
        try common.RecordingBuffer.init(gpa, ctx.io()),
        .{ .genesis = try H.genesis_block(gpa, harness.num_validators) },
    );
    defer started.crash();
    const parent = try harness.make_raw_block(gpa, harness.genesis_parent(), .new(1), 100);
    const child = try harness.make_raw_block(gpa, parent.digest(), .new(2), 200);
    var shared = try mocks_block.ready(B, gpa, child);
    defer shared.deinit();
    var subscription = try started.mailbox.subscribe_parent(&shared);
    defer subscription.deinit();
    try ctx.sleep(.fromMilliseconds(100));
    try testing.expectEqual(1, started.buffer.?.commitment_subscription_count());
}

test "standard block provider parent fetches by commitment" {
    try run(parent_by_commitment_body);
}

const build_options = @import("build_options");
const recoverable = @import("../../mocks/scenarios_recoverable.zig");

/// commonware's seeds 0..16 under `-Dslow-tests`; two otherwise, to keep Debug runs fast.
const contract_seeds: []const u64 = if (build_options.slow_tests)
    &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }
else
    &.{ 0, 1 };

test "standard proposed success implies recoverable after restart" {
    try recoverable.SuccessRecoverable(H, .proposed).run(gpa, contract_seeds);
}

test "standard verified success implies recoverable after restart" {
    try recoverable.SuccessRecoverable(H, .verified).run(gpa, contract_seeds);
}

test "standard certified success implies recoverable after restart" {
    try recoverable.SuccessRecoverable(H, .certified).run(gpa, contract_seeds);
}

test "standard certify at later view survives earlier view pruning" {
    try recoverable.LaterViewSurvivesPruning(H).run(gpa);
}

test "standard certify persists equivocated block" {
    try recoverable.CertifyPersistsEquivocated(H).run(gpa);
}

test "standard verified after restart reverify same round implies recoverable" {
    try recoverable.ReverifySameRound(H, .verified).run(gpa);
}

test "standard certify after restart reverify same round implies recoverable" {
    try recoverable.ReverifySameRound(H, .certified).run(gpa);
}
