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
            self.wrapper = try W.create(ctx.child("wrapper"), app, marshal, epocher());
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
