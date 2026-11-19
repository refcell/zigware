//! The standard wrappers' propose and prepare paths and their reproposal, ancestry, and
//! application verification checks (commonware `marshal/standard/mod.rs`, lines 4994-5931).
//! The sync-failure panic tests that follow (5932-6150) have no Zig counterpart.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks = @import("../../mocks/root.zig");
const mocks_block = @import("../../mocks/block.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = mocks.Application(harness.B);
const Validator = H.Validator(App);
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;
const D = harness.D;
const B = harness.B;
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

/// A validator on an unlinked network with a wrapper of kind `W` over its marshal
/// (commonware `setup_validator` plus `Wrapper::new`).
fn Env(comptime W: type) type {
    return struct {
        const Self = @This();

        fixture: harness.Fixture,
        network: harness.TestNetwork,
        validator: *Validator,
        wrapper: *W,
        genesis: B,

        fn init(self: *Self, ctx: Ctx, app: Mock) !void {
            try self.init_named(ctx, "wrapper", app);
        }

        /// Like `init`, with the wrapper under `ctx.child(name)`.
        fn init_named(self: *Self, ctx: Ctx, comptime name: []const u8, app: Mock) !void {
            var rng = utils.rng.test_rng();
            self.fixture = try harness.fixture(gpa, &rng);
            errdefer self.fixture.deinit(gpa);
            const participants = self.fixture.participants;
            self.network = try .start(gpa, ctx.io(), 1, participants, 1024 * 1024);
            errdefer self.network.stop();
            const child = ctx.child("validator").with_attribute("index", 0);
            const provider: harness.Provider = .init(&self.fixture.schemes[0]);
            const application = try App.init(gpa, ctx.io());
            self.validator =
                try Validator.setup(
                    child,
                    self.network.network,
                    self.me(),
                    provider,
                    1,
                    application,
                );
            errdefer self.validator.crash();
            const marshal = self.validator.mailbox.clone();
            self.wrapper = try W.create(ctx.child(name), app, marshal, epocher());
            self.genesis = try harness.make_raw_block(gpa, harness.genesis_parent(), .zero(), 0);
        }

        fn deinit(self: *Self, ctx: Ctx) void {
            // Let detached tasks (a store behind a sent verdict) finish before the wrapper goes.
            ctx.sleep(.fromMilliseconds(100)) catch {};
            self.wrapper.destroy();
            self.validator.crash();
            self.network.stop();
            self.fixture.deinit(gpa);
        }

        /// Another wrapper over the same marshal, under `ctx.child(name)`; the caller destroys
        /// it.
        fn another(self: *Self, ctx: Ctx, comptime name: []const u8, app: Mock) !*W {
            const marshal = self.validator.mailbox.clone();
            return W.create(ctx.child(name), app, marshal, epocher());
        }

        fn me(self: *const Self) harness.K {
            return self.fixture.participants[0];
        }

        /// Persists `block` as verified at `round`.
        fn store(self: *Self, round: Round, block: B) !void {
            const ready = try mocks_block.ready(B, gpa, block);
            try testing.expect(try self.validator.mailbox.verified(round, ready));
        }

        fn verify(self: *Self, context: harness.Ctx, digest: D) !bool {
            return (try self.wrapper.verify(undefined, context, digest)) orelse
                error.VerifyResultMissing;
        }

        fn certify(self: *Self, round: Round, digest: D) !bool {
            return (try self.wrapper.certify(undefined, round, digest)) orelse
                error.CertifyResultMissing;
        }
    };
}

/// A block at `height` with `context`, over `parent`, stamped `timestamp`.
fn block_with(context: harness.Ctx, parent: D, height: u64, timestamp: u64) !B {
    return B.init(gpa, context, parent, .new(height), timestamp);
}

fn context_of(round: Round, leader: harness.K, parent_view: u64, parent: D) harness.Ctx {
    return .{ .round = round, .leader = leader, .parent = .{ .new(parent_view), parent } };
}

fn VerifyReproposal(comptime W: type) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env(W) = undefined;
            try env.init(ctx, Mock.init(gpa));
            defer env.deinit(ctx);
            const genesis = env.genesis.digest();
            const leader = harness.default_leader();
            const boundary_height = harness.blocks_per_epoch - 1;
            const boundary_round = round_at(boundary_height);
            const boundary_context = context_of(boundary_round, leader, 0, genesis);
            const boundary = try block_with(boundary_context, genesis, boundary_height, 1900);
            try env.store(boundary_round, boundary);
            try ctx.sleep(.fromMilliseconds(10));
            // Valid re-proposal: the boundary block in the same epoch.
            const valid = context_of(
                round_at(boundary_height + 1),
                env.me(),
                boundary_height,
                boundary.digest(),
            );
            try testing.expect(try env.verify(valid, boundary.digest()));
            // Invalid re-proposal: a non-boundary block.
            const non_boundary_round = round_at(10);
            const non_boundary_context = context_of(non_boundary_round, leader, 0, genesis);
            const non_boundary = try block_with(non_boundary_context, genesis, 10, 1000);
            try env.store(non_boundary_round, non_boundary);
            try ctx.sleep(.fromMilliseconds(10));
            const invalid = context_of(round_at(15), env.me(), 10, non_boundary.digest());
            try testing.expect(!try env.verify(invalid, non_boundary.digest()));
            // Invalid re-proposal: a cross-epoch context.
            const cross_round: Round = .new(.new(1), .new(boundary_height + 1));
            const cross = context_of(cross_round, env.me(), boundary_height, boundary.digest());
            try testing.expect(!try env.verify(cross, boundary.digest()));
            if (W == DeferredWrapper) {
                // Deferred-only crash-recovery path: certify without a prior verify.
                try testing.expect(try env.certify(round_at(21), boundary.digest()));
            }
        }
    };
}

test "inline verify reproposal validation" {
    try run(VerifyReproposal(InlineWrapper).body);
}

test "deferred verify reproposal validation" {
    try run(VerifyReproposal(DeferredWrapper).body);
}

/// Inline rejects in `verify`; deferred passes `verify` optimistically and rejects in
/// `certify`.
fn expect_rejected(comptime W: type, env: *Env(W), context: harness.Ctx, digest: D) !void {
    const verified = try env.verify(context, digest);
    if (W == InlineWrapper) return testing.expect(!verified);
    try testing.expect(verified);
    try testing.expect(!try env.certify(context.round, digest));
}

fn RejectsInvalidAncestry(comptime W: type) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env(W) = undefined;
            try env.init(ctx, Mock.init(gpa));
            defer env.deinit(ctx);
            const genesis = env.genesis.digest();
            // Case 1: a non-contiguous height (parent genesis, height 2).
            const malformed_context = context_of(round_at(2), env.me(), 0, genesis);
            const malformed = try block_with(malformed_context, genesis, 2, 200);
            try env.store(round_at(2), malformed);
            try ctx.sleep(.fromMilliseconds(10));
            try expect_rejected(W, &env, malformed_context, malformed.digest());
            // Case 2: a mismatched parent commitment with contiguous heights.
            const parent_context = context_of(round_at(1), env.me(), 0, genesis);
            const parent = try block_with(parent_context, genesis, 1, 300);
            try env.store(round_at(1), parent);
            const mismatched_context = context_of(round_at(3), env.me(), 1, parent.digest());
            const mismatched = try block_with(mismatched_context, genesis, 2, 400);
            try env.store(round_at(3), mismatched);
            try ctx.sleep(.fromMilliseconds(10));
            try expect_rejected(W, &env, mismatched_context, mismatched.digest());
        }
    };
}

test "inline verify rejects invalid ancestry" {
    try run(RejectsInvalidAncestry(InlineWrapper).body);
}

test "deferred verify rejects invalid ancestry" {
    try run(RejectsInvalidAncestry(DeferredWrapper).body);
}

fn ApplicationVerifyFailure(comptime W: type) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env(W) = undefined;
            try env.init(ctx, Mock.with_verify_result(gpa, false));
            defer env.deinit(ctx);
            const genesis = env.genesis.digest();
            // A valid parent, so the structural checks pass.
            const parent_context = context_of(round_at(1), env.me(), 0, genesis);
            const parent = try block_with(parent_context, genesis, 1, 100);
            try env.store(round_at(1), parent);
            // A valid child: only the application's verification fails.
            const round = round_at(2);
            const context = context_of(round, env.me(), 1, parent.digest());
            const block = try block_with(context, parent.digest(), 2, 200);
            try env.store(round, block);
            try ctx.sleep(.fromMilliseconds(10));
            const verified = try env.verify(context, block.digest());
            if (W == InlineWrapper) {
                // Inline fails in verify and still certifies, trusting the notarization.
                try testing.expect(!verified);
                try testing.expect(try env.certify(round, block.digest()));
            } else {
                // Deferred passes verify and fails in certify.
                try testing.expect(verified);
                try testing.expect(!try env.certify(round, block.digest()));
            }
        }
    };
}

test "inline application verify failure" {
    try run(ApplicationVerifyFailure(InlineWrapper).body);
}

test "deferred application verify failure" {
    try run(ApplicationVerifyFailure(DeferredWrapper).body);
}

fn PrepareTask(comptime W: type) type {
    return struct {
        fn run(wrapper: *W, context: harness.Ctx) Io.Cancelable!?Handoff {
            return wrapper.prepare(undefined, context);
        }
    };
}

const Io = std.Io;
const Handoff = @import("../../../traits.zig").Handoff(D);
const ProposalGate = mocks.verifying.ProposalGate;

/// Whether the metrics exposition holds `needle`.
fn exposition_contains(ctx: Ctx, needle: []const u8) !bool {
    const text = try ctx.encode(gpa);
    defer gpa.free(text);
    return std.mem.indexOf(u8, text, needle) != null;
}

/// A failed build answers no proposal and a `wait` handoff, and a dropped prepare cancels
/// the application's build.
fn propose_failures(comptime W: type, ctx: Ctx, env: *Env(W), context: harness.Ctx) !void {
    // The mock cannot build, so the proposal is dropped and the build is not timed.
    try testing.expectEqual(@as(?D, null), try env.wrapper.propose(undefined, context));
    try testing.expect(try exposition_contains(ctx, "wrapper_under_test_build_duration_count 0"));
    // A failed build answers wait, so consensus can still ask for an ordinary proposal.
    const failing = try env.another(ctx, "failed", Mock.init(gpa).with_handoff(.{ .stage = {} }));
    defer failing.destroy();
    const handoff = (try failing.prepare(undefined, context)) orelse return error.NoHandoff;
    try testing.expect(handoff == .wait);
    // Dropping a prepare response cancels the application's build.
    const io = ctx.io();
    var gated = try ProposalGate.init(gpa, io);
    defer gated.gate.deinit();
    defer gated.started.deinit();
    defer gated.dropped.deinit();
    const gated_app = Mock.init(gpa).with_handoff(.{ .vote = {} }).with_proposal_gate(&gated.gate);
    const canceled = try env.another(ctx, "cancelled", gated_app);
    defer canceled.destroy();
    var response = try io.concurrent(PrepareTask(W).run, .{ canceled, context });
    try gated.started.recv();
    _ = response.cancel(io) catch {};
    try testing.expectError(error.Closed, gated.dropped.recv());
}

/// The boundary block is re-proposed whether or not the application builds, its gate
/// certifies, and a handoff on it is staged regardless of the application's decision.
fn propose_boundary(comptime W: type, ctx: Ctx, env: *Env(W)) !void {
    const genesis = env.genesis.digest();
    const leader = harness.default_leader();
    const boundary_height = harness.blocks_per_epoch - 1;
    const boundary_round = round_at(boundary_height);
    const boundary_context = context_of(boundary_round, leader, 0, genesis);
    const boundary = try block_with(boundary_context, genesis, boundary_height, 1900);
    const digest = boundary.digest();
    try env.store(boundary_round, boundary);
    try ctx.sleep(.fromMilliseconds(10));
    const reproposal_round = round_at(boundary_height + 1);
    const reproposal = context_of(reproposal_round, env.me(), boundary_height, digest);
    // An epoch-boundary proposal re-proposes the parent digest.
    const proposed = (try env.wrapper.propose(undefined, reproposal)) orelse
        return error.NoProposal;
    try testing.expect(proposed.eql(digest));
    // The re-proposal registers a gate certify awaits, and is stored at its round.
    try testing.expect(try env.certify(reproposal_round, digest));
    var stored = (try env.validator.mailbox.get_verified(reproposal_round)) orelse
        return error.ReproposalMissing;
    stored.deinit();
    // A handoff takes the boundary re-proposal path without asking the application.
    const pipeline_round = round_at(boundary_height + 2);
    const pipeline_context = context_of(pipeline_round, leader, boundary_height, digest);
    const unwanted = try block_with(pipeline_context, digest, boundary_height + 1, 2000);
    const app = Mock.init(gpa).with_handoff(.{ .vote = {} }).with_propose_result(unwanted);
    const pipeline = try env.another(ctx, "pipeline", app);
    defer pipeline.destroy();
    const handoff = (try pipeline.prepare(undefined, pipeline_context)) orelse
        return error.NoHandoff;
    try testing.expect(handoff == .stage and handoff.stage.eql(digest));
    const certified = (try pipeline.certify(undefined, pipeline_round, digest)) orelse
        return error.CertifyResultMissing;
    try testing.expect(certified);
}

fn ProposePaths(comptime W: type) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env(W) = undefined;
            try env.init_named(ctx, "wrapper_under_test", Mock.init(gpa));
            defer env.deinit(ctx);
            const context = context_of(round_at(1), env.me(), 0, env.genesis.digest());
            try propose_failures(W, ctx, &env, context);
            try propose_boundary(W, ctx, &env);
        }
    };
}

test "inline propose paths" {
    try run(ProposePaths(InlineWrapper).body);
}

test "deferred propose paths" {
    try run(ProposePaths(DeferredWrapper).body);
}

/// A validator restarted on `network` under `ctx.child(name)`, reopening the same storage.
fn restart(
    ctx: Ctx,
    comptime name: []const u8,
    network: *harness.TestNetwork,
    fixture: *const harness.Fixture,
) !*Validator {
    const child = ctx.child(name).with_attribute("index", 0);
    const provider: harness.Provider = .init(&fixture.schemes[0]);
    const application = try App.init(gpa, ctx.io());
    const me = fixture.participants[0];
    return Validator.setup(child, network.network, me, provider, 1, application);
}

fn expect_verified(marshal: anytype, round: Round, digest: D) !void {
    var block = (try marshal.get_verified(round)) orelse return error.VerifiedMissing;
    defer block.deinit();
    try testing.expect(block.digest().eql(digest));
}

fn expect_stored(marshal: anytype, digest: D) !void {
    var block = (try marshal.get_block(.{ .digest = digest })) orelse return error.BlockLost;
    block.deinit();
}

/// Persists the stale block a pre-crash relay broadcast stored for `round` by `me`, whose
/// parent replay has since replaced; returns its digest.
fn persist_stale(ctx: Ctx, validator: *Validator, me: harness.K, round: Round, genesis: D) !D {
    const replaced = harness.Sha256.hash(&.{"replaced parent"});
    const stale = try block_with(context_of(round, me, 1, replaced), genesis, 1, 100);
    var persisted = try utils.channel.oneshot.channel(void, gpa, ctx.io());
    defer persisted.receiver.deinit();
    const ready = try mocks_block.ready(B, gpa, stale);
    _ = try validator.mailbox.proposed(round, ready, .all, persisted.sender);
    try persisted.receiver.recv();
    return stale.digest();
}

fn RebuildsAfterRestart(comptime W: type) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            const me = fixture.participants[0];
            var network: harness.TestNetwork =
                try .start(gpa, ctx.io(), 1, fixture.participants, 1024 * 1024);
            defer network.stop();
            const genesis_block = try harness.make_raw_block(
                gpa,
                harness.genesis_parent(),
                .zero(),
                0,
            );
            const genesis = genesis_block.digest();
            const round = round_at(2);
            const first = try restart(ctx, "validator", &network, &fixture);
            const stale = try persist_stale(ctx, first, me, round, genesis);
            first.crash();
            const restarted = try restart(ctx, "restarted", &network, &fixture);
            // The restarted marshal restores the stale block.
            try expect_verified(restarted.mailbox, round, stale);
            const context = context_of(round, me, 0, genesis);
            const fresh = try block_with(context, genesis, 1, 200);
            const app = Mock.init(gpa).with_propose_result(fresh);
            const marshal = restarted.mailbox.clone();
            const wrapper = try W.create(ctx.child("wrapper"), app, marshal, epocher());
            const digest = (try wrapper.propose(undefined, context)) orelse return error.NoProposal;
            // A restarted leader builds a fresh block.
            try testing.expect(digest.eql(fresh.digest()));
            _ = wrapper.broadcast(digest, .{ .propose = .{ .round = round } });
            // The fresh block certifies through the relay handshake.
            const certified = try wrapper.certify(undefined, round, digest);
            try testing.expectEqual(@as(?bool, true), certified);
            // The stale block stays stored first at the round.
            try expect_verified(restarted.mailbox, round, stale);
            try ctx.sleep(.fromMilliseconds(100));
            wrapper.destroy();
            restarted.crash();
            const recovered = try restart(ctx, "recovered", &network, &fixture);
            defer recovered.crash();
            // Both blocks are recoverable from storage.
            try expect_stored(recovered.mailbox, stale);
            try expect_stored(recovered.mailbox, digest);
            const certifier =
                try W.create(
                    ctx.child("certifier"),
                    Mock.init(gpa),
                    recovered.mailbox.clone(),
                    epocher(),
                );
            defer certifier.destroy();
            // The fresh block certifies from storage after a restart.
            const recertified = try certifier.certify(undefined, round, digest);
            try testing.expectEqual(@as(?bool, true), recertified);
            try ctx.sleep(.fromMilliseconds(100));
        }
    };
}

test "inline propose rebuilds after restart" {
    try run(RebuildsAfterRestart(InlineWrapper).body);
}

test "deferred propose rebuilds after restart" {
    try run(RebuildsAfterRestart(DeferredWrapper).body);
}

/// Whether the runtime spawned a task whose label contains `label` (commonware
/// `spawned_task`).
fn spawned_task(metrics: []const u8, label: []const u8) bool {
    var lines = std.mem.splitScalar(u8, metrics, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "runtime_tasks_spawned_total{")) continue;
        if (std.mem.indexOf(u8, line, label) != null) return true;
    }
    return false;
}

/// A prepare by a new wrapper under `name` with `app` answers `expected`. Returns the
/// wrapper, which the caller destroys once it has read the wrapper's metrics.
fn expect_prepared(
    comptime W: type,
    ctx: Ctx,
    env: *Env(W),
    comptime name: []const u8,
    app: Mock,
    context: harness.Ctx,
    expected: Handoff,
) !*W {
    const wrapper = try env.another(ctx, name, app);
    errdefer wrapper.destroy();
    const handoff = (try wrapper.prepare(undefined, context)) orelse return error.NoHandoff;
    try testing.expect(std.meta.eql(handoff, expected));
    return wrapper;
}

fn prepare_building(
    comptime W: type,
    ctx: Ctx,
    env: *Env(W),
    context: harness.Ctx,
    child: B,
) !void {
    const cases = .{
        .{ "staging", Handoff{ .stage = child.digest() } },
        .{ "voting", Handoff{ .vote = child.digest() } },
    };
    inline for (cases) |case| {
        const label = case[0];
        const decision: @import("../../../traits.zig").Handoff(void) = switch (case[1]) {
            .stage => .{ .stage = {} },
            .vote => .{ .vote = {} },
            .wait => unreachable,
        };
        const app = Mock.init(gpa).with_handoff(decision).with_propose_result(child);
        // A prepared block carries the application's decision.
        const wrapper = try expect_prepared(W, ctx, env, label, app, context, case[1]);
        defer wrapper.destroy();
        const metrics = try ctx.encode(gpa);
        defer gpa.free(metrics);
        // A prepare fetches the parent once, times the build, and runs in a task.
        const fetched = label ++ "_parent_fetch_duration_count 1";
        try testing.expect(std.mem.indexOf(u8, metrics, fetched) != null);
        const timed = label ++ "_build_duration_count 1";
        try testing.expect(std.mem.indexOf(u8, metrics, timed) != null);
        try testing.expect(spawned_task(metrics, label ++ "_prepare"));
    }
}

fn PreparePaths(comptime W: type) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env(W) = undefined;
            try env.init(ctx, Mock.init(gpa));
            defer env.deinit(ctx);
            const genesis = env.genesis.digest();
            const context = context_of(round_at(1), env.me(), 0, genesis);
            const child = try block_with(context, genesis, 1, 100);
            // The default declines once the parent is fetched.
            const declining =
                try expect_prepared(W, ctx, &env, "declining", Mock.init(gpa), context, .wait);
            defer declining.destroy();
            const fetched = "declining_parent_fetch_duration_count 1";
            try testing.expect(try exposition_contains(ctx, fetched));
            // A block stored for the round before a restart does not decide the view.
            const rebuilt_round = round_at(2);
            const replaced = harness.Sha256.hash(&.{"replaced parent"});
            const stored_context = context_of(rebuilt_round, env.me(), 1, replaced);
            try env.store(rebuilt_round, try block_with(stored_context, genesis, 1, 101));
            const rebuilt_context = context_of(rebuilt_round, env.me(), 0, genesis);
            const rebuilt = try block_with(rebuilt_context, genesis, 1, 102);
            const app = Mock.init(gpa).with_handoff(.{ .vote = {} }).with_propose_result(rebuilt);
            const rebuilt_vote: Handoff = .{ .vote = rebuilt.digest() };
            const rebuilding =
                try expect_prepared(W, ctx, &env, "rebuilding", app, rebuilt_context, rebuilt_vote);
            rebuilding.destroy();
            try prepare_building(W, ctx, &env, context, child);
        }
    };
}

test "inline prepare paths" {
    try run(PreparePaths(InlineWrapper).body);
}

test "deferred prepare paths" {
    try run(PreparePaths(DeferredWrapper).body);
}

/// Deferred votes before checking a block's parent link, so a handoff build may walk
/// ancestry only through the parent its tip's own context names: an unlinked parent
/// declines without asking the application.
fn unvalidated_link_body(ctx: Ctx) anyerror!void {
    var env: Env(DeferredWrapper) = undefined;
    try env.init(ctx, Mock.init(gpa));
    defer env.deinit(ctx);
    const genesis = env.genesis.digest();
    // Both tips carry an authentic context naming genesis; only the second links to it.
    const tip_round = round_at(1);
    const tip_context = context_of(tip_round, harness.default_leader(), 0, genesis);
    const forged_parent = harness.Sha256.hash(&.{"forged parent link"});
    const forged = try block_with(tip_context, forged_parent, 1, 100);
    const linked = try block_with(tip_context, genesis, 1, 101);
    inline for (.{ .{ "forged", false }, .{ "linked", true } }) |case| {
        const tip = if (case[1]) linked else forged;
        try env.store(tip_round, tip);
        const context = context_of(round_at(2), env.me(), 1, tip.digest());
        const child = try block_with(context, tip.digest(), 2, 200);
        const app = Mock.init(gpa).with_handoff(.{ .stage = {} }).with_propose_result(child);
        const expected: Handoff = if (case[1]) .{ .stage = child.digest() } else .wait;
        // A handoff build requires a parent linked to its context.
        const wrapper = try expect_prepared(
            DeferredWrapper,
            ctx,
            &env,
            case[0],
            app,
            context,
            expected,
        );
        wrapper.destroy();
    }
}

test "deferred handoff rejects unvalidated parent link" {
    try run(unvalidated_link_body);
}
