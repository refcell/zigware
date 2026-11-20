//! Tests for the inline standard wrapper (commonware `marshal/standard/inline.rs` tests).
//!
//! commonware runs these against a full marshal actor from its test harness. Until the Zig
//! harness lands, a fake actor serves the core mailbox here: it answers subscriptions from a
//! fixed set of blocks and acknowledges every store at once, recording what it stored.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const actor = @import("actor");
const runtime = @import("runtime");
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../../types.zig");
const traits = @import("../../traits.zig");
const ed25519_scheme = @import("../../simplex/scheme/ed25519.zig");
const mocks = @import("../mocks/root.zig");
const inline_mod = @import("inline.zig");

const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const B = mocks.EmptyBlock(Sha256);
const Ctx = runtime.deterministic.Context;
const S = ed25519_scheme.Scheme(D);
const V = @import("variant.zig").Standard(B);
const Marshal = @import("../core/mailbox.zig").Mailbox(S, V);
const Stream = @import("../ancestry.zig").AncestorStream(Marshal);
const ConsensusContext = @import("../../simplex/types.zig").Context(D, S.PublicKey);
const soak = @import("../mocks/soak.zig");
const App = mocks.verifying.MockVerifyingApp(B, Ctx, ConsensusContext, Stream);
const Epocher = types.FixedEpocher;
const Wrapper = inline_mod.Inline(Ctx, S, App, B, Epocher);
const Message = Wrapper.Marshal.M;
const Round = types.Round;
const gpa = testing.allocator;

comptime {
    traits.assert_automaton(Wrapper);
    traits.assert_certifiable_automaton(Wrapper);
    traits.assert_relay(Wrapper);
    traits.assert_reporter(Wrapper);
    // The simplex engine's automaton calls fail only by cancelation.
    for (.{ Wrapper.propose, Wrapper.verify, Wrapper.prepare, Wrapper.certify }) |call| {
        const Return = @typeInfo(@TypeOf(call)).@"fn".return_type.?;
        std.debug.assert(@typeInfo(Return).error_union.error_set == Io.Cancelable);
    }
}

/// Epochs of 10 heights: height 9 is the last of epoch 0.
fn epocher() Epocher {
    return .new(utils.NonZero(u64).init(10).?);
}

/// The fake marshal actor's state.
const Fake = struct {
    blocks: []const B,
    verified: u32 = 0,
    certified: u32 = 0,
    hints: u32 = 0,

    fn find(fake: *const Fake, digest: D) ?B {
        for (fake.blocks) |block| {
            if (block.digest().eql(digest)) return block;
        }
        return null;
    }

    /// Answers a subscription from the known blocks, or drops it (the block never arrives).
    fn answer(fake: *const Fake, digest: D, response: anytype) void {
        var sender = response;
        const block = fake.find(digest) orelse return sender.deinit();
        const shared = mocks.ready(B, gpa, block) catch return sender.deinit();
        sender.send(shared) catch {
            var owned = shared;
            owned.deinit();
        };
    }

    fn store(counter: *u32, body: anytype) void {
        var block = body.block;
        block.deinit();
        var ack = body.ack;
        ack.send({}) catch {};
        counter.* += 1;
    }

    fn serve(fake: *Fake, receiver: *actor.mailbox.Receiver(Message)) Io.Cancelable!void {
        while (try receiver.recv()) |message| {
            switch (message.body) {
                .subscribe_by_digest => |body| fake.answer(body.digest, body.response),
                .subscribe_by_commitment => |body| fake.answer(body.commitment, body.response),
                .verified => |body| store(&fake.verified, body),
                .certified => |body| store(&fake.certified, body),
                .hint_notarized => fake.hints += 1,
                else => Message.discard(message),
            }
        }
    }
};

const genesis = B.init(D.empty, .zero(), 0);

fn block_on(parent: B, height: u64) B {
    return B.init(parent.digest(), .new(height), height * 100);
}

fn context_for(round: Round, parent_view: u64, parent_digest: D) Wrapper.Context {
    const leader = cryptography.ed25519.PrivateKey.from_seed(0).public_key();
    return .{ .round = round, .leader = leader, .parent = .{ .new(parent_view), parent_digest } };
}

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// A wrapper over `app` whose marshal is the fake serving `fake`; `body(io, wrapper, fake)`.
fn with_wrapper(
    ctx: Ctx,
    fake: *Fake,
    app: App,
    comptime body: fn (Io, *Wrapper, *Fake) anyerror!void,
) !void {
    const io = ctx.io();
    var pair = try actor.mailbox.new(Message, gpa, io, 64);
    defer pair.receiver.deinit();
    const marshal: Wrapper.Marshal = .init(gpa, io, pair.sender, 1);
    var server = try io.concurrent(Fake.serve, .{ fake, &pair.receiver });
    defer server.cancel(io) catch {};
    const wrapper = try Wrapper.create(ctx.child("inline"), app, marshal, epocher());
    defer wrapper.destroy();
    try body(io, wrapper, fake);
    // Let detached tasks (a store behind a sent verdict) finish before the wrapper goes.
    try io.sleep(.fromMilliseconds(100), .awake);
}

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };
    try soak.run(gpa, config, body, .{});
}

var parent_block: B = undefined;
var child_block: B = undefined;
var boundary_block: B = undefined;
var proposal_block: B = undefined;

/// Genesis, the parent at 1, the child at 2, then the epoch boundary block at 9.
fn chain() [4]B {
    parent_block = block_on(genesis, 1);
    child_block = block_on(parent_block, 2);
    boundary_block = block_on(genesis, 9);
    proposal_block = block_on(child_block, 3);
    return .{ genesis, parent_block, child_block, boundary_block };
}

fn certify_after_verify(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    _ = io;
    const round = round_at(2);
    const context = context_for(round, 1, parent_block.digest());
    const digest = child_block.digest();
    try testing.expectEqual(@as(?bool, true), try wrapper.verify(undefined, context, digest));
    // The verify task's store opened the gate: certify answers without fetching again.
    try testing.expectEqual(@as(?bool, true), try wrapper.certify(undefined, round, digest));
    try testing.expectEqual(@as(u32, 1), fake.verified);
    try testing.expectEqual(@as(u32, 0), fake.certified);
    try testing.expectEqual(@as(u32, 1), fake.hints);
}

test "certify returns at once after verify fetched the block" {
    // commonware `test_certify_returns_immediately_after_verify_fetches_block`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const blocks = chain();
            var fake: Fake = .{ .blocks = &blocks };
            try with_wrapper(ctx, &fake, App.init(gpa), certify_after_verify);
        }
    }.body);
}

fn certify_alone(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    _ = io;
    const digest = child_block.digest();
    try testing.expectEqual(@as(?bool, true), try wrapper.certify(undefined, round_at(2), digest));
    try testing.expectEqual(@as(u32, 1), fake.certified);
    try testing.expectEqual(@as(u32, 0), fake.hints);
}

test "certify succeeds without a verify task" {
    // commonware `test_certify_succeeds_without_verify_task`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const blocks = chain();
            var fake: Fake = .{ .blocks = &blocks };
            try with_wrapper(ctx, &fake, App.init(gpa), certify_alone);
        }
    }.body);
}

fn rejects(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    _ = io;
    _ = fake;
    const digest = child_block.digest();
    // The application rejects.
    const context = context_for(round_at(2), 1, parent_block.digest());
    try testing.expectEqual(@as(?bool, false), try wrapper.verify(undefined, context, digest));
    // The context names another parent: the parent check rejects before the application.
    const wrong = context_for(round_at(3), 1, genesis.digest());
    try testing.expectEqual(@as(?bool, false), try wrapper.verify(undefined, wrong, digest));
    // A block outside the context's epoch is rejected by the precheck.
    const other_epoch: Round = .new(.new(1), .new(4));
    const late = context_for(other_epoch, 1, parent_block.digest());
    try testing.expectEqual(@as(?bool, false), try wrapper.verify(undefined, late, digest));
}

test "verify rejects bad parents, wrong epochs, and application rejections" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const blocks = chain();
            var fake: Fake = .{ .blocks = &blocks };
            try with_wrapper(ctx, &fake, App.with_verify_result(gpa, false), rejects);
        }
    }.body);
}

fn missing_block(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    _ = io;
    _ = fake;
    const context = context_for(round_at(2), 1, parent_block.digest());
    const unknown = block_on(child_block, 3).digest();
    try testing.expectEqual(@as(?bool, null), try wrapper.verify(undefined, context, unknown));
}

test "verify stops without a verdict when the block never arrives" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const blocks = chain();
            var fake: Fake = .{ .blocks = &blocks };
            try with_wrapper(ctx, &fake, App.init(gpa), missing_block);
        }
    }.body);
}

fn proposals(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    _ = io;
    _ = fake;
    // An ordinary proposal builds through the application.
    const context = context_for(round_at(3), 2, child_block.digest());
    const built = try wrapper.propose(undefined, context);
    try testing.expect(built.?.eql(proposal_block.digest()));
    // On the epoch's last block, the proposal re-proposes it without the application.
    const boundary = context_for(round_at(10), 9, boundary_block.digest());
    const reproposed = try wrapper.propose(undefined, boundary);
    try testing.expect(reproposed.?.eql(boundary_block.digest()));
    // A parent that never arrives skips the proposal.
    const missing = context_for(round_at(11), 10, D.fill(5));
    try testing.expectEqual(@as(?D, null), try wrapper.propose(undefined, missing));
    // Prepare declines with the application's default handoff.
    const later = context_for(round_at(4), 2, child_block.digest());
    const prepared = try wrapper.prepare(undefined, later);
    try testing.expect(prepared.?.is_wait());
}

test "propose builds, re-proposes the boundary block, and skips a missing parent" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const blocks = chain();
            var fake: Fake = .{ .blocks = &blocks };
            const app = App.init(gpa).with_propose_result(proposal_block);
            try with_wrapper(ctx, &fake, app, proposals);
        }
    }.body);
}
