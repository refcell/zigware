//! Tests for the deferred standard wrapper (commonware `marshal/standard/deferred.rs` tests).
//!
//! commonware runs these against a full marshal actor from its test harness. Until the Zig
//! harness lands, a fake actor serves the core mailbox here. It holds subscriptions until
//! their block is delivered (stored, or handed in as the broadcast buffer would), and
//! acknowledges every store at once. The restart halves of the restart tests wait for the
//! harness; here the fake's store counts stand in for durability.

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
const simplex_types = @import("../../simplex/types.zig");
const mocks = @import("../mocks/root.zig");
const deferred_mod = @import("deferred.zig");

const oneshot = utils.channel.oneshot;
const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const Ctx = runtime.deterministic.Context;
const S = ed25519_scheme.Scheme(D);
const ConsensusContext = simplex_types.Context(D, S.PublicKey);
const B = mocks.Block(Sha256, ConsensusContext);
const V = @import("variant.zig").Standard(B);
const Marshal = @import("../core/mailbox.zig").Mailbox(S, V);
const Stream = @import("../ancestry.zig").AncestorStream(Marshal);
const soak = @import("../mocks/soak.zig");
const Message = Marshal.M;
const Epocher = types.FixedEpocher;
const Round = types.Round;
const Mock = mocks.verifying.MockVerifyingApp(B, Ctx, ConsensusContext, Stream);
const Gated = mocks.verifying.GatedVerifyingApp(B, Ctx, ConsensusContext, Stream);
const Recording = mocks.verifying.RecordingVerifyingApp(B, Ctx, ConsensusContext, Stream);
const Verification = mocks.verifying.Verification(D);
const Wrapper = deferred_mod.Deferred(Ctx, S, Mock, B, Epocher);
const gpa = testing.allocator;

/// Heights per epoch, as in commonware's harness: height 19 is the last of epoch 0.
const blocks_per_epoch = 20;

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

fn epocher() Epocher {
    return .new(utils.NonZero(u64).init(blocks_per_epoch).?);
}

/// The fake marshal actor's state.
const Fake = struct {
    known: std.ArrayList(B) = .empty,
    waiting: std.ArrayList(Waiter) = .empty,
    verified: u32 = 0,
    certified: u32 = 0,
    proposed: u32 = 0,
    hints: u32 = 0,

    const Waiter = struct { digest: D, response: oneshot.Sender(V.Block) };

    fn deinit(fake: *Fake) void {
        fake.close_waiters();
        fake.known.deinit(gpa);
        fake.waiting.deinit(gpa);
    }

    fn close_waiters(fake: *Fake) void {
        for (fake.waiting.items) |*waiter| waiter.response.deinit();
        fake.waiting.clearRetainingCapacity();
    }

    fn find(fake: *const Fake, digest: D) ?B {
        for (fake.known.items) |block| {
            if (block.digest().eql(digest)) return block;
        }
        return null;
    }

    fn send(block: B, response: oneshot.Sender(V.Block)) void {
        var sender = response;
        const shared = mocks.ready(B, gpa, block) catch return sender.deinit();
        sender.send(shared) catch {
            var owned = shared;
            owned.deinit();
        };
    }

    /// Makes `block` available, answering the subscriptions waiting on it (the broadcast
    /// buffer's delivery).
    fn deliver(fake: *Fake, block: B) !void {
        const digest = block.digest();
        if (fake.find(digest) == null) try fake.known.append(gpa, block);
        var kept: usize = 0;
        for (fake.waiting.items) |waiter| {
            if (waiter.digest.eql(digest)) {
                send(block, waiter.response);
            } else {
                fake.waiting.items[kept] = waiter;
                kept += 1;
            }
        }
        fake.waiting.shrinkRetainingCapacity(kept);
    }

    fn subscribe(fake: *Fake, digest: D, response: oneshot.Sender(V.Block)) void {
        if (fake.find(digest)) |block| return send(block, response);
        fake.waiting.append(gpa, .{ .digest = digest, .response = response }) catch {
            var sender = response;
            sender.deinit();
        };
    }

    fn store(fake: *Fake, counter: *u32, block: V.Block, ack: oneshot.Sender(void)) void {
        var owned = block;
        defer owned.deinit();
        fake.deliver(owned.inner().*) catch {};
        var sender = ack;
        sender.send({}) catch {};
        counter.* += 1;
    }

    fn serve(fake: *Fake, receiver: *actor.mailbox.Receiver(Message)) Io.Cancelable!void {
        defer fake.close_waiters();
        while (try receiver.recv()) |message| {
            switch (message.body) {
                .subscribe_by_digest => |body| fake.subscribe(body.digest, body.response),
                .subscribe_by_commitment => |body| fake.subscribe(body.commitment, body.response),
                .verified => |body| fake.store(&fake.verified, body.block, body.ack),
                .certified => |body| fake.store(&fake.certified, body.block, body.ack),
                .proposed => |body| {
                    var recipients = body.recipients;
                    recipients.deinit(message.gpa);
                    fake.store(&fake.proposed, body.block, body.ack);
                },
                .hint_notarized => fake.hints += 1,
                else => Message.discard(message),
            }
        }
    }
};

/// A consensus call run beside the test, so the test can see whether it answered yet.
fn Call(comptime W: type) type {
    return struct {
        const Self = @This();
        result: ?(anyerror!?bool) = null,

        fn verify(call: *Self, wrapper: *W, context: ConsensusContext, digest: D) void {
            call.result = wrapper.verify(undefined, context, digest);
        }

        fn certify(call: *Self, wrapper: *W, round: Round, digest: D) void {
            call.result = wrapper.certify(undefined, round, digest);
        }

        /// The answer, or null while the call is pending.
        fn answered(call: *const Self) !??bool {
            const result = call.result orelse return null;
            return try result;
        }
    };
}

/// A wrapper over `app` whose marshal is the fake serving `fake`; `body(io, wrapper, fake)`.
fn with_wrapper(
    comptime W: type,
    ctx: Ctx,
    fake: *Fake,
    app: @FieldType(W, "application"),
    epochs: @FieldType(W, "epocher"),
    comptime body: fn (Io, *W, *Fake) anyerror!void,
) !void {
    const io = ctx.io();
    var pair = try actor.mailbox.new(Message, gpa, io, 64);
    defer pair.receiver.deinit();
    const marshal: Marshal = .init(gpa, io, pair.sender, 1);
    var server = try io.concurrent(Fake.serve, .{ fake, &pair.receiver });
    const wrapper = W.create(ctx.child("deferred"), app, marshal, epochs) catch |err| {
        server.cancel(io) catch {};
        return err;
    };
    defer wrapper.destroy();
    // Close the fake's subscriptions, then let the tasks they free unwind.
    defer io.sleep(.fromMilliseconds(100), .awake) catch {};
    defer server.cancel(io) catch {};
    try body(io, wrapper, fake);
}

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };
    try soak.run(gpa, config, body, .{});
}

fn participant(index: u64) S.PublicKey {
    return cryptography.ed25519.PrivateKey.from_seed(index).public_key();
}

fn round_at(epoch: u64, view: u64) Round {
    return .new(.new(epoch), .new(view));
}

fn context_for(round: Round, leader: u64, parent_view: u64, parent: D) ConsensusContext {
    const parent_link: @FieldType(ConsensusContext, "parent") = .{ .new(parent_view), parent };
    return .{ .round = round, .leader = participant(leader), .parent = parent_link };
}

/// The block at `height` on `parent`, proposed under `context`.
fn block_in(context: ConsensusContext, parent: D, height: u64, timestamp: u64) !B {
    return B.init(gpa, context, parent, .new(height), timestamp);
}

/// Stores `block` as verified at `round` through the wrapper's marshal.
fn store_verified(wrapper: anytype, round: Round, block: B) !void {
    try testing.expect(try wrapper.marshal.verified(round, try mocks.ready(B, gpa, block)));
}

fn genesis() !B {
    return block_in(context_for(round_at(0, 0), 0, 0, D.empty), D.empty, 0, 0);
}

/// The blocks a test builds before its body runs.
var blocks: [4]B = undefined;

fn certify_lower_view(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    _ = fake;
    const parent = blocks[0];
    const a = blocks[1];
    const b = blocks[2];
    try store_verified(wrapper, round_at(0, 1), parent);
    try store_verified(wrapper, a.context().round, a);
    try store_verified(wrapper, b.context().round, b);
    try io.sleep(.fromMilliseconds(10), .awake);
    _ = try wrapper.verify(undefined, a.context(), a.digest());
    _ = try wrapper.verify(undefined, b.context(), b.digest());
    // Certifying the later view first leaves the earlier view's gate to certify.
    const certified_b = try wrapper.certify(undefined, b.context().round, b.digest());
    try testing.expectEqual(@as(?bool, true), certified_b);
    const certified_a = try wrapper.certify(undefined, a.context().round, a.digest());
    try testing.expectEqual(@as(?bool, true), certified_a);
}

test "certify a lower view after a higher view" {
    // commonware `test_certify_lower_view_after_higher_view`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const root = try genesis();
            const parent_context = context_for(round_at(0, 1), 0, 0, root.digest());
            const parent = try block_in(parent_context, root.digest(), 1, 100);
            const parent_digest = parent.digest();
            const context_a = context_for(round_at(0, 5), 0, 1, parent_digest);
            const context_b = context_for(round_at(0, 10), 0, 1, parent_digest);
            blocks[0] = parent;
            blocks[1] = try block_in(context_a, parent_digest, 2, 200);
            blocks[2] = try block_in(context_b, parent_digest, 2, 300);
            var fake: Fake = .{};
            defer fake.deinit();
            try with_wrapper(Wrapper, ctx, &fake, Mock.init(gpa), epocher(), certify_lower_view);
        }
    }.body);
}

/// A `FixedEpocher` that knows only epochs up to `max_epoch`.
const LimitedEpocher = struct {
    inner: Epocher,
    max_epoch: u64,

    pub fn containing(self: LimitedEpocher, height: types.Height) ?types.EpochInfo {
        const bounds = self.inner.containing(height) orelse return null;
        return if (bounds.epoch.get() > self.max_epoch) null else bounds;
    }

    pub fn first(self: LimitedEpocher, epoch: types.Epoch) ?types.Height {
        return if (epoch.get() > self.max_epoch) null else self.inner.first(epoch);
    }

    pub fn last(self: LimitedEpocher, epoch: types.Epoch) ?types.Height {
        return if (epoch.get() > self.max_epoch) null else self.inner.last(epoch);
    }
};

const Limited = deferred_mod.Deferred(Ctx, S, Mock, B, LimitedEpocher);

fn unsupported_epoch(io: Io, wrapper: *Limited, fake: *Fake) !void {
    _ = fake;
    const parent = blocks[0];
    const block = blocks[1];
    try store_verified(wrapper, round_at(0, 19), parent);
    try store_verified(wrapper, block.context().round, block);
    try io.sleep(.fromMilliseconds(10), .awake);
    const verdict = try wrapper.verify(undefined, block.context(), block.digest());
    try testing.expectEqual(@as(?bool, false), verdict);
}

test "verify rejects a block in an unsupported epoch" {
    // commonware `test_marshaled_rejects_unsupported_epoch`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const root = try genesis();
            const parent_context = context_for(round_at(0, 19), 0, 0, root.digest());
            const parent = try block_in(parent_context, root.digest(), 19, 1000);
            const context = context_for(round_at(1, 20), 0, 19, parent.digest());
            blocks[0] = parent;
            blocks[1] = try block_in(context, parent.digest(), 20, 2000);
            var fake: Fake = .{};
            defer fake.deinit();
            const limited: LimitedEpocher = .{ .inner = epocher(), .max_epoch = 0 };
            try with_wrapper(Limited, ctx, &fake, Mock.init(gpa), limited, unsupported_epoch);
        }
    }.body);
}

fn mismatched_context(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    _ = fake;
    const parent = blocks[0];
    const block = blocks[1];
    try store_verified(wrapper, round_at(0, 1), parent);
    try store_verified(wrapper, block.context().round, block);
    try io.sleep(.fromMilliseconds(10), .awake);
    // Consensus asks under another round and leader than the block embeds.
    const other = context_for(round_at(0, 3), 1, 1, parent.digest());
    const verdict = try wrapper.verify(undefined, other, block.digest());
    try testing.expectEqual(@as(?bool, false), verdict);
}

test "verify rejects a block whose embedded context differs from consensus's" {
    // commonware `test_marshaled_rejects_mismatched_context`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const root = try genesis();
            const parent_context = context_for(round_at(0, 1), 0, 0, root.digest());
            const parent = try block_in(parent_context, root.digest(), 1, 100);
            const context = context_for(round_at(0, 2), 0, 1, parent.digest());
            blocks[0] = parent;
            blocks[1] = try block_in(context, parent.digest(), 2, 200);
            var fake: Fake = .{};
            defer fake.deinit();
            try with_wrapper(Wrapper, ctx, &fake, Mock.init(gpa), epocher(), mismatched_context);
        }
    }.body);
}

fn verify_dropped(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    const block = blocks[1];
    try fake.deliver(blocks[0]);
    // Consensus drops the verification while the block is still missing.
    var call: Call(Wrapper) = .{};
    const args = .{ &call, wrapper, block.context(), block.digest() };
    var verify = try io.concurrent(Call(Wrapper).verify, args);
    try io.sleep(.fromMilliseconds(10), .awake);
    verify.cancel(io);
    try io.sleep(.fromMilliseconds(10), .awake);
    try store_verified(wrapper, block.context().round, block);
    // The closed gate recovers through the block's embedded context.
    const certified = try wrapper.certify(undefined, block.context().round, block.digest());
    try testing.expectEqual(@as(?bool, true), certified);
}

test "certify recovers after consensus drops the verification" {
    // commonware `test_deferred_certify_recovers_after_verify_receiver_drop`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const root = try genesis();
            const context = context_for(round_at(0, 1), 0, 0, root.digest());
            blocks[0] = root;
            blocks[1] = try block_in(context, root.digest(), 1, 100);
            var fake: Fake = .{};
            defer fake.deinit();
            try with_wrapper(Wrapper, ctx, &fake, Mock.init(gpa), epocher(), verify_dropped);
        }
    }.body);
}

const GatedWrapper = deferred_mod.Deferred(Ctx, S, Gated, B, Epocher);

/// The gated application's handles: `started` hears verification start, `release` lets it
/// finish.
var gated: struct { started: oneshot.Receiver(void), release: ?oneshot.Sender(void) } = undefined;

fn store_overlaps(io: Io, wrapper: *GatedWrapper, fake: *Fake) !void {
    const child = blocks[1];
    try fake.deliver(blocks[0]);
    try fake.deliver(child);
    const verdict = try wrapper.verify(undefined, child.context(), child.digest());
    try testing.expectEqual(@as(?bool, true), verdict);
    // The application is gated, yet the store beside it already reached marshal.
    try gated.started.recv();
    try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expectEqual(@as(u32, 1), fake.verified);
    var release = gated.release.?;
    gated.release = null;
    try release.send({});
    const certified = try wrapper.certify(undefined, child.context().round, child.digest());
    try testing.expectEqual(@as(?bool, true), certified);
}

test "the store overlaps the application's verification" {
    // commonware `test_deferred_store_overlaps_app_verify`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const root = try genesis();
            const parent_context = context_for(round_at(0, 1), 0, 0, root.digest());
            const parent = try block_in(parent_context, root.digest(), 1, 100);
            const context = context_for(round_at(0, 2), 0, 1, parent.digest());
            blocks[0] = parent;
            blocks[1] = try block_in(context, parent.digest(), 2, 200);
            var state = try mocks.verifying.Gated.init(gpa, ctx.io());
            defer state.state.deinit();
            gated = .{ .started = state.started, .release = state.release };
            defer gated.started.deinit();
            defer if (gated.release) |*release| release.deinit();
            var fake: Fake = .{};
            defer fake.deinit();
            const app: Gated = .{ .state = &state.state };
            try with_wrapper(GatedWrapper, ctx, &fake, app, epocher(), store_overlaps);
        }
    }.body);
}

/// How far verification of block A has progressed when the conflicting block B of its round
/// is certified.
const Progress = enum { awaiting_block, awaiting_parent, verifying };

const RecordingWrapper = deferred_mod.Deferred(Ctx, S, Recording, B, Epocher);

var progress: Progress = undefined;
var observed: mocks.verifying.Observed(D) = undefined;

fn expect_observed(expected: []const Verification) !void {
    try testing.expectEqual(expected.len, observed.items.items.len);
    for (expected) |want| {
        var found = false;
        for (observed.items.items) |seen| found = found or std.meta.eql(seen, want);
        try testing.expect(found);
    }
}

fn releases_conflicting(io: Io, wrapper: *RecordingWrapper, fake: *Fake) !void {
    const parent = blocks[0];
    const a = blocks[1];
    const b = blocks[2];
    // Deliver everything except what verification of A waits for.
    const withheld: ?B = switch (progress) {
        .awaiting_block => a,
        .awaiting_parent => parent,
        .verifying => null,
    };
    for (blocks[0..3]) |block| {
        if (withheld == null or !withheld.?.digest().eql(block.digest())) try fake.deliver(block);
    }
    const Calls = Call(RecordingWrapper);
    var verify_a: Calls = .{};
    const verify_args = .{ &verify_a, wrapper, a.context(), a.digest() };
    var verifying = try io.concurrent(Calls.verify, verify_args);
    defer verifying.cancel(io);
    // commonware waits 10 ms; here each task hand-off costs a 1 ms scheduler cycle, and
    // reaching the application takes about a dozen.
    try io.sleep(.fromMilliseconds(50), .awake);
    // A's optimistic verdict arrives only when A is available; the application starts on A
    // only when its parent is too.
    const optimistic: ??bool = if (progress == .awaiting_block) null else true;
    try testing.expectEqual(optimistic, try verify_a.answered());
    const started = progress == .verifying;
    if (started) try expect_observed(&.{.{ .started = a.digest() }}) else try expect_observed(&.{});
    // B is notarized, so consensus certifies it, claiming the round.
    var certify_b: Calls = .{};
    const round = b.context().round;
    var certifying = try io.concurrent(Calls.certify, .{ &certify_b, wrapper, round, b.digest() });
    defer certifying.cancel(io);
    try io.sleep(.fromMilliseconds(10), .awake);
    // A wait for a block that lost its round ends without a verdict.
    if (progress == .awaiting_block) {
        const ended: ??bool = @as(?bool, null);
        try testing.expectEqual(ended, try verify_a.answered());
    }
    if (withheld) |block| try fake.deliver(block);
    try io.sleep(.fromMilliseconds(100), .awake);
    // B's verification started; A's only if it began before B was certified, then stopped.
    if (started) {
        try expect_observed(&.{
            .{ .started = a.digest() },
            .{ .cancelled = a.digest() },
            .{ .started = b.digest() },
        });
    } else {
        try expect_observed(&.{.{ .started = b.digest() }});
    }
}

fn conflicting_body(ctx: Ctx) anyerror!void {
    const root = try genesis();
    const parent_context = context_for(round_at(0, 1), 0, 0, root.digest());
    const parent = try block_in(parent_context, root.digest(), 1, 100);
    // The leader equivocates: A and B share round 2's context.
    const context = context_for(round_at(0, 2), 1, 1, parent.digest());
    blocks[0] = parent;
    blocks[1] = try block_in(context, parent.digest(), 2, 200);
    blocks[2] = try block_in(context, parent.digest(), 2, 201);
    try testing.expect(!blocks[1].digest().eql(blocks[2].digest()));
    var fake: Fake = .{};
    defer fake.deinit();
    const app: Recording = .{ .observed = &observed };
    try with_wrapper(RecordingWrapper, ctx, &fake, app, epocher(), releases_conflicting);
}

test "certify releases a conflicting verification" {
    // commonware `test_certify_releases_conflicting_verification`, every case.
    for ([_]Progress{ .awaiting_block, .awaiting_parent, .verifying }) |case| {
        progress = case;
        // Verifications pending at shutdown record their cancellation, so the log outlives
        // the runtime.
        observed = .init(gpa);
        defer observed.deinit();
        try run(conflicting_body);
    }
}

fn reproposed_boundary(io: Io, wrapper: *GatedWrapper, fake: *Fake) !void {
    _ = io;
    const boundary = blocks[0];
    const round = round_at(0, 20);
    // The pre-crash relay broadcast persisted the boundary block at the re-proposal round.
    try store_verified(wrapper, round, boundary);
    const context = context_for(round, 0, 19, boundary.digest());
    const digest = (try wrapper.propose(undefined, context)).?;
    try testing.expect(digest.eql(boundary.digest()));
    _ = wrapper.broadcast(digest, .{ .propose = .{ .round = round } });
    const certified = try wrapper.certify(undefined, round, digest);
    try testing.expectEqual(@as(?bool, true), certified);
    // The relay handed the staged re-proposal to marshal, which persisted it.
    try testing.expectEqual(@as(u32, 1), fake.proposed);
    // A re-proposal never reaches the application's verification.
    try testing.expectError(error.Empty, gated.started.try_recv());
}

test "propose re-proposes a persisted boundary block and certifies it" {
    // commonware `test_propose_reuses_reproposed_boundary_block_on_restart` (no restart).
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const root = try genesis();
            const context = context_for(round_at(0, 19), 0, 0, root.digest());
            blocks[0] = try block_in(context, root.digest(), 19, 1900);
            var state = try mocks.verifying.Gated.init(gpa, ctx.io());
            defer state.state.deinit();
            gated = .{ .started = state.started, .release = state.release };
            defer gated.started.deinit();
            defer if (gated.release) |*release| release.deinit();
            var fake: Fake = .{};
            defer fake.deinit();
            const app: Gated = .{ .state = &state.state };
            try with_wrapper(GatedWrapper, ctx, &fake, app, epocher(), reproposed_boundary);
        }
    }.body);
}

fn propose_then_certify(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    _ = io;
    const parent = blocks[0];
    const child = blocks[1];
    try store_verified(wrapper, round_at(0, 1), parent);
    const digest = (try wrapper.propose(undefined, child.context())).?;
    try testing.expect(digest.eql(child.digest()));
    // Certifying the leader's own proposal persists it before it answers.
    const certified = try wrapper.certify(undefined, child.context().round, digest);
    try testing.expectEqual(@as(?bool, true), certified);
    try testing.expectEqual(@as(u32, 2), fake.verified);
    try testing.expect(fake.find(digest) != null);
}

test "propose then certify persists the block" {
    // commonware `test_deferred_propose_then_certify_persists_block` (no restart).
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const root = try genesis();
            const parent_context = context_for(round_at(0, 1), 0, 0, root.digest());
            const parent = try block_in(parent_context, root.digest(), 1, 100);
            const context = context_for(round_at(0, 2), 0, 1, parent.digest());
            blocks[0] = parent;
            blocks[1] = try block_in(context, parent.digest(), 2, 200);
            var fake: Fake = .{};
            defer fake.deinit();
            const app = Mock.init(gpa).with_propose_result(blocks[1]);
            try with_wrapper(Wrapper, ctx, &fake, app, epocher(), propose_then_certify);
        }
    }.body);
}

/// The equivocation scenario: this validator certified view 1 but only nullified view 2,
/// which the network notarized. The view-3 block builds on view 2 and reached the local
/// buffer; the equivocating context names view 1 as its parent instead.
const Equivocation = struct {
    embedded: ConsensusContext,
    equivocating: ConsensusContext,
    digest: D,
};

var equivocation: Equivocation = undefined;

fn equivocation_setup(wrapper: *Wrapper, fake: *Fake) !void {
    const certified = blocks[0];
    const notarized = blocks[1];
    const block = blocks[2];
    try store_verified(wrapper, round_at(0, 1), certified);
    try store_verified(wrapper, round_at(0, 2), notarized);
    try fake.deliver(block);
    equivocation = .{
        .embedded = block.context(),
        .equivocating = context_for(round_at(0, 3), 1, 1, certified.digest()),
        .digest = block.digest(),
    };
}

fn equivocation_blocks() !void {
    const root = try genesis();
    const certified_context = context_for(round_at(0, 1), 0, 0, root.digest());
    const certified = try block_in(certified_context, root.digest(), 1, 100);
    const notarized_context = context_for(round_at(0, 2), 1, 1, certified.digest());
    const notarized = try block_in(notarized_context, certified.digest(), 2, 200);
    const context = context_for(round_at(0, 3), 1, 2, notarized.digest());
    blocks[0] = certified;
    blocks[1] = notarized;
    blocks[2] = try block_in(context, notarized.digest(), 3, 300);
}

fn run_equivocation(
    ctx: Ctx,
    app: Mock,
    comptime body: fn (Io, *Wrapper, *Fake) anyerror!void,
) !void {
    try equivocation_blocks();
    var fake: Fake = .{};
    defer fake.deinit();
    try with_wrapper(Wrapper, ctx, &fake, app, epocher(), body);
}

fn not_poisoned(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    try equivocation_setup(wrapper, fake);
    try io.sleep(.fromMilliseconds(10), .awake);
    const round = equivocation.embedded.round;
    // The equivocating proposal must not be notarized here.
    const verdict = try wrapper.verify(undefined, equivocation.equivocating, equivocation.digest);
    try testing.expectEqual(@as(?bool, false), verdict);
    // The honest notarization is judged under the block's embedded context.
    const certified = try wrapper.certify(undefined, round, equivocation.digest);
    try testing.expectEqual(@as(?bool, true), certified);
}

test "certify is not poisoned by an equivocating parent's verify" {
    // commonware `test_certify_not_poisoned_by_equivocating_parent_verify`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try run_equivocation(ctx, Mock.init(gpa), not_poisoned);
        }
    }.body);
}

fn honors_rejection(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    try equivocation_setup(wrapper, fake);
    try io.sleep(.fromMilliseconds(10), .awake);
    const round = equivocation.embedded.round;
    const verdict = try wrapper.verify(undefined, equivocation.embedded, equivocation.digest);
    try testing.expectEqual(@as(?bool, true), verdict);
    const certified = try wrapper.certify(undefined, round, equivocation.digest);
    try testing.expectEqual(@as(?bool, false), certified);
}

test "certify honors the application's rejection" {
    // commonware `test_certify_honors_application_rejection`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try run_equivocation(ctx, Mock.with_verify_result(gpa, false), honors_rejection);
        }
    }.body);
}

fn rejection_without_verify(io: Io, wrapper: *Wrapper, fake: *Fake) !void {
    try equivocation_setup(wrapper, fake);
    try io.sleep(.fromMilliseconds(10), .awake);
    // No gate exists, so certification verifies under the embedded context.
    const round = equivocation.embedded.round;
    const certified = try wrapper.certify(undefined, round, equivocation.digest);
    try testing.expectEqual(@as(?bool, false), certified);
}

test "certify without a prior verify honors the application's rejection" {
    // commonware `test_certify_without_prior_verify_honors_application_rejection`.
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const app = Mock.with_verify_result(gpa, false);
            try run_equivocation(ctx, app, rejection_without_verify);
        }
    }.body);
}
