//! The standard actor's buffered floor anchors and the standard wrappers' certify, verify,
//! propose, and prepare paths (commonware `marshal/standard/mod.rs`, lines 2592-6220).
//!
//! Tests that need a peer serve blocks the way commonware's harness does; the standard
//! harness's `propose` stores nothing, so a server persists a block it must serve as verified.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks_block = @import("../../mocks/block.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const Validator = H.Validator(App);
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;
const D = harness.D;
const Block = common.Block;
const core_mailbox = @import("../../core/mailbox.zig");
const BlockReceiver = utils.channel.oneshot.Receiver(Block);

fn run_for(seconds: u64, comptime body: fn (Ctx) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = seconds * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

fn hash(text: []const u8) D {
    return harness.Sha256.hash(&.{text});
}

/// `ready(make_raw_block(parent, height, timestamp))`.
fn block_at(parent: D, height: u64, timestamp: u64) !Block {
    const raw = try harness.make_raw_block(gpa, parent, .new(height), timestamp);
    return mocks_block.ready(harness.B, gpa, raw);
}

/// The block at `height` on the chain from the empty-input hash, timestamped by height.
fn chain_tip(height: u64) !Block {
    var parent = hash("");
    var block: ?Block = null;
    for (1..height + 1) |at| {
        if (block) |*previous| previous.deinit();
        block = try block_at(parent, at, at);
        parent = block.?.digest();
    }
    return block.?;
}

/// The quorum finalization of `block` at `view` over `parent_view`.
fn finalize(
    fixture: *const harness.Fixture,
    view: u64,
    parent_view: u64,
    block: *const Block,
) !harness.Finalization {
    const proposal = harness.Proposal.init(round_at(view), .new(parent_view), block.digest());
    return harness.make_finalization(gpa, fixture, proposal, harness.quorum);
}

/// Reports `finalization` (taken) to the actor.
fn report(mailbox: anytype, finalization: harness.Finalization) void {
    var value = finalization;
    _ = mailbox.report(.{ .finalization = value });
    value.deinit(gpa);
}

/// Broadcasts `block` (borrowed) through a harness validator's buffer to everyone.
fn buffer_deliver(validator: *Validator, block: *const Block) !void {
    _ = try validator.extra.mailbox.broadcast(.all, block.clone());
}

/// Whether `app` holds a block at `height`.
const Holds = struct { app: App, height: u64 };

fn holds(state: Holds) bool {
    return state.app.contains(.new(state.height));
}

fn wait_holds(ctx: Ctx, app: App, height: u64) !void {
    const state: Holds = .{ .app = app, .height = height };
    try common.wait_until(ctx, 20_000, "application block", state, holds);
}

/// A simulated network of `peers` (unlinked) and the fixture that signs for them.
const Net = struct {
    fixture: harness.Fixture,
    network: harness.TestNetwork,

    fn start(ctx: Ctx, peers: usize) !*Net {
        const net = try gpa.create(Net);
        errdefer gpa.destroy(net);
        var rng = utils.rng.test_rng();
        net.fixture = try harness.fixture(gpa, &rng);
        errdefer net.fixture.deinit(gpa);
        const participants = net.fixture.participants[0..peers];
        const size = harness.max_message_size(H.Variant);
        net.network = try .start(gpa, ctx.io(), 1, participants, size);
        return net;
    }

    fn stop(net: *Net) void {
        net.network.stop();
        net.fixture.deinit(gpa);
        gpa.destroy(net);
    }

    /// Validator `index` under `ctx.child(name)` with an auto-acknowledging application.
    fn validator(net: *Net, ctx: Ctx, comptime name: []const u8, index: usize) !*Validator {
        const app = try App.init(gpa, ctx.io());
        const provider: harness.Provider = .init(&net.fixture.schemes[index]);
        const child = ctx.child(name).with_attribute("index", index);
        const me = net.fixture.participants[index];
        return Validator.setup(child, net.network.network, me, provider, 1, app);
    }

    fn link(net: *Net, peers: usize) !void {
        try net.network.link_all(net.fixture.participants[0..peers], harness.link);
    }
};

fn expect_tip(app: App, height: u64, digest: D) !void {
    const tip = app.tip() orelse return error.NoTip;
    try testing.expectEqual(height, tip.height.get());
    try testing.expect(tip.digest.eql(digest));
}

fn buffered_anchor_body(ctx: Ctx) anyerror!void {
    // No links, so the resolver fetch `set_floor` starts never completes: the anchor can
    // arrive only through the buffer.
    const net = try Net.start(ctx, harness.num_validators);
    defer net.stop();
    const validator = try net.validator(ctx, "validator", 0);
    defer validator.crash();
    const mailbox = validator.mailbox;
    var anchor = try chain_tip(5);
    defer anchor.deinit();
    var subscription = try mailbox.subscribe_by_digest(anchor.digest(), .wait);
    defer subscription.deinit();
    try mailbox.set_floor(try finalize(&net.fixture, 5, 4, &anchor));
    // Barrier: mailbox messages are FIFO, so `set_floor` recorded the pending anchor.
    try testing.expectEqual(null, try mailbox.get_block(.{ .height = .new(5) }));
    try buffer_deliver(validator, &anchor);
    var received = try subscription.recv();
    defer received.deinit();
    try testing.expect(received.digest().eql(anchor.digest()));
    // The anchor installs the floor and dispatch resumes there.
    try wait_holds(ctx, validator.application, 5);
    try expect_tip(validator.application, 5, anchor.digest());
    var stored = (try mailbox.get_block(.{ .height = .new(5) })).?;
    defer stored.deinit();
    try testing.expect(stored.digest().eql(anchor.digest()));
}

test "standard buffered block installs floor anchor" {
    // commonware `test_standard_buffered_block_installs_floor_anchor`.
    try run_for(30, buffered_anchor_body);
}

fn buffered_anchor_installs_floor(ctx: Ctx, subscribe: bool) !void {
    const net = try Net.start(ctx, harness.num_validators);
    defer net.stop();
    const validator = try net.validator(ctx, "validator", 0);
    defer validator.crash();
    const mailbox = validator.mailbox;
    var anchor = try block_at(hash("floor-parent"), 5, 500);
    defer anchor.deinit();
    try mailbox.set_floor(try finalize(&net.fixture, 5, 4, &anchor));
    try testing.expectEqual(null, try mailbox.get_block(.{ .height = .new(5) }));
    // The anchor reaches the buffer while only the pending floor's waiter awaits it.
    try buffer_deliver(validator, &anchor);
    // commonware's actor polls buffer waiters before its mailbox, so the floor waiter wins
    // over a later query. zigware's actor handles events in arrival order and its waiter
    // reaches the inbox a few scheduler cycles after the buffer sees the block, so let it.
    try ctx.sleep(.fromMilliseconds(20));
    if (subscribe) {
        // A query queued behind the subscription observes the installed floor.
        var subscription = try mailbox.subscribe_by_commitment(anchor.digest(), .wait);
        defer subscription.deinit();
        var installed = (try mailbox.get_anchor()).?;
        defer installed.block.deinit();
        try testing.expect(installed.block.digest().eql(anchor.digest()));
        var received = try subscription.recv();
        defer received.deinit();
        try testing.expect(received.digest().eql(anchor.digest()));
    }
    try wait_holds(ctx, validator.application, 5);
    try expect_tip(validator.application, 5, anchor.digest());
}

test "standard unsubscribed buffered anchor installs floor" {
    // commonware `test_standard_unsubscribed_buffered_anchor_installs_floor`.
    try run_for(30, struct {
        fn body(ctx: Ctx) anyerror!void {
            try buffered_anchor_installs_floor(ctx, false);
        }
    }.body);
}

test "standard late subscription observes buffered anchor floor" {
    // commonware `test_standard_late_subscription_observes_buffered_anchor_floor`.
    try run_for(30, struct {
        fn body(ctx: Ctx) anyerror!void {
            try buffered_anchor_installs_floor(ctx, true);
        }
    }.body);
}

const Holding = common.Started(
    harness.Provider,
    common.HoldingBlockReporter,
    common.RecordingBuffer,
);

fn start_holding(
    ctx: Ctx,
    prefix: []const u8,
    fixture: *const harness.Fixture,
    reporter: common.HoldingBlockReporter,
    buffer: common.RecordingBuffer,
    start: common.Start,
) !Holding {
    const provider: harness.Provider = .init(&fixture.schemes[0]);
    return common.start_standard_actor(
        harness.Provider,
        common.HoldingBlockReporter,
        common.RecordingBuffer,
        ctx,
        prefix,
        provider,
        reporter,
        buffer,
        start,
    );
}

const Subscriptions = struct { buffer: common.RecordingBuffer, count: usize };

fn subscribed(state: Subscriptions) bool {
    return state.buffer.commitment_subscription_count() == state.count;
}

fn wait_subscriptions(ctx: Ctx, buffer: common.RecordingBuffer, count: usize) !void {
    const state: Subscriptions = .{ .buffer = buffer, .count = count };
    try common.wait_until(ctx, 5000, "buffer subscriptions", state, subscribed);
}

fn start_floor_buffered_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    var anchor = try block_at(hash("floor-parent"), 5, 500);
    defer anchor.deinit();
    var created = try common.HoldingBlockReporter.init_after(gpa, ctx.io(), .zero());
    defer created.started.deinit();
    var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
    defer buffer.deinit();
    var started = try start_holding(
        ctx.child("validator"),
        "start-floor-buffered-anchor",
        &fixture,
        created.reporter,
        buffer.clone(),
        .{ .floor = try finalize(&fixture, 5, 4, &anchor) },
    );
    defer started.crash();
    // The startup floor waits on the buffer for its anchor; the resolver never delivers.
    try wait_subscriptions(ctx, buffer, 1);
    try testing.expect(buffer.deliver_commitment_subscription(0, anchor.clone()));
    try testing.expectEqual(5, (try created.started.recv()).get());
}

test "standard start floor buffered anchor installs floor" {
    // commonware `test_standard_start_floor_buffered_anchor_installs_floor`.
    try run_for(30, start_floor_buffered_body);
}

fn closed_floor_waiter_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    var anchor = try block_at(hash("floor-parent"), 5, 500);
    defer anchor.deinit();
    const commitment = anchor.digest();
    var created = try common.HoldingBlockReporter.init_after(gpa, ctx.io(), .zero());
    defer created.started.deinit();
    var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
    defer buffer.deinit();
    var started = try start_holding(
        ctx.child("validator"),
        "closed-floor-waiter",
        &fixture,
        created.reporter,
        buffer.clone(),
        .{ .genesis = try H.genesis_block(gpa, harness.num_validators) },
    );
    defer started.crash();
    const mailbox = started.mailbox;
    try mailbox.set_floor(try finalize(&fixture, 5, 4, &anchor));
    try wait_subscriptions(ctx, buffer, 1);
    // A caller waits on the same anchor through its own buffer waiter.
    var subscription = try mailbox.subscribe_by_commitment(commitment, .wait);
    defer subscription.deinit();
    try wait_subscriptions(ctx, buffer, 2);
    // Waiters are polled before the mailbox, so the closure is handled before the query.
    buffer.close_commitment_subscription(0);
    try testing.expectEqual(null, try mailbox.get_block(.{ .height = .new(5) }));
    // The caller's subscription stays open, and its anchor reaches the caller and the floor.
    try testing.expect(!buffer.commitment_subscription_closed(1));
    try testing.expect(buffer.deliver_commitment_subscription(1, anchor.clone()));
    var received = try subscription.recv();
    defer received.deinit();
    try testing.expect(received.digest().eql(commitment));
    try testing.expectEqual(5, (try created.started.recv()).get());
}

test "standard closed floor waiter preserves subscriptions" {
    // commonware `test_standard_closed_floor_waiter_preserves_subscriptions`.
    try run_for(30, closed_floor_waiter_body);
}

/// Whether `mailbox` processed the block at `height`.
fn wait_processed(ctx: Ctx, mailbox: anytype, height: u64) !void {
    var waited: u32 = 0;
    while (true) : (waited += 1) {
        if (waited > 400) return error.TestTimedOut;
        if (try mailbox.get_processed()) |processed| switch (processed) {
            .block => |at| if (at.get() == height) return,
            .absent => {},
        };
        try ctx.sleep(.fromMilliseconds(50));
    }
}

fn expect_pending(receiver: anytype) !void {
    try testing.expectError(error.Empty, receiver.try_recv());
}

fn expect_block(receiver: anytype, digest: D) !void {
    var block = try receiver.recv();
    defer block.deinit();
    try testing.expect(block.digest().eql(digest));
}

/// The subscriptions on the missing parent of `floor_preserves_subscriptions`.
const ParentWaiters = struct {
    by_round: BlockReceiver,
    by_height: BlockReceiver,
    wait: BlockReceiver,
    parent: Validator.Actor.Mailbox.ParentReceiver,

    fn deinit(self: *ParentWaiters) void {
        self.by_round.deinit();
        self.by_height.deinit();
        self.wait.deinit();
        self.parent.deinit();
    }

    fn expect_pending_all(self: *ParentWaiters) !void {
        try expect_pending(&self.by_round);
        try expect_pending(&self.by_height);
        try expect_pending(&self.wait);
        try expect_pending(&self.parent);
    }

    fn expect_all(self: *ParentWaiters, digest: D) !void {
        try expect_block(&self.by_round, digest);
        try expect_block(&self.by_height, digest);
        try expect_block(&self.wait, digest);
        try expect_block(&self.parent, digest);
    }
};

fn parent_waiters(mailbox: anytype, missing: D, child: *const Block) !ParentWaiters {
    var by_round = try mailbox.subscribe_by_digest(missing, .{ .fetch_by_round = round_at(2) });
    errdefer by_round.deinit();
    const by_commitment: core_mailbox.CommitmentFallback = .{ .fetch_by_commitment = .new(2) };
    var by_height = try mailbox.subscribe_by_commitment(missing, by_commitment);
    errdefer by_height.deinit();
    var wait = try mailbox.subscribe_by_digest(missing, .wait);
    errdefer wait.deinit();
    return .{
        .by_round = by_round,
        .by_height = by_height,
        .wait = wait,
        .parent = try mailbox.subscribe_parent(child),
    };
}

fn floor_preserves_body(ctx: Ctx) anyerror!void {
    // No links: waiters resolve only through the buffer or closure.
    const net = try Net.start(ctx, harness.num_validators);
    defer net.stop();
    const validator = try net.validator(ctx, "validator", 0);
    defer validator.crash();
    var mailbox = validator.mailbox;
    var anchor = try chain_tip(5);
    defer anchor.deinit();
    // Every acquisition mode for one unavailable parent, as a verification that stays
    // active while unrelated progress advances the floor.
    var missing = try block_at(hash("missing-parent"), 2, 999);
    defer missing.deinit();
    var child = try block_at(missing.digest(), 3, 1_000);
    defer child.deinit();
    var waiters = try parent_waiters(&mailbox, missing.digest(), &child);
    defer waiters.deinit();
    var anchor_wait = try mailbox.subscribe_by_digest(anchor.digest(), .{
        .fetch_by_round = round_at(5),
    });
    defer anchor_wait.deinit();
    try mailbox.set_floor(try finalize(&net.fixture, 5, 4, &anchor));
    try buffer_deliver(validator, &anchor);
    try expect_block(&anchor_wait, anchor.digest());
    try wait_processed(ctx, mailbox, 5);
    // Parent availability, not the processed floor, decides when the subscriptions end.
    try ctx.sleep(.fromMilliseconds(100));
    try waiters.expect_pending_all();
    // A below-floor request skips remote acquisition and waits for local ingress.
    var late = try parent_waiters(&mailbox, missing.digest(), &child);
    defer late.deinit();
    _ = try mailbox.get_processed();
    try ctx.sleep(.fromMilliseconds(100));
    try late.expect_pending_all();
    // Later local availability satisfies every registered caller.
    try buffer_deliver(validator, &missing);
    try waiters.expect_all(missing.digest());
    try late.expect_all(missing.digest());
}

test "standard floor preserves registered subscriptions" {
    // commonware `test_standard_floor_preserves_registered_subscriptions`.
    try run_for(30, floor_preserves_body);
}

fn resolver_anchor_body(ctx: Ctx) anyerror!void {
    // Two peers, linked only after the floor is set: the anchor arrives through the
    // resolver fetch `set_floor` starts.
    const net = try Net.start(ctx, 2);
    defer net.stop();
    const victim = try net.validator(ctx, "victim", 0);
    defer victim.crash();
    const server = try net.validator(ctx, "server", 1);
    defer server.crash();
    var anchor = try chain_tip(5);
    defer anchor.deinit();
    try H.verify(server, round_at(5), &anchor);
    const mailbox = victim.mailbox;
    var subscription = try mailbox.subscribe_by_digest(anchor.digest(), .wait);
    defer subscription.deinit();
    try mailbox.set_floor(try finalize(&net.fixture, 5, 4, &anchor));
    try testing.expectEqual(null, try mailbox.get_block(.{ .height = .new(5) }));
    try net.link(2);
    try expect_block(&subscription, anchor.digest());
    try wait_holds(ctx, victim.application, 5);
    try expect_tip(victim.application, 5, anchor.digest());
}

test "standard resolver floor anchor install wakes subscriber" {
    // commonware `test_standard_resolver_floor_anchor_install_wakes_subscriber`.
    try run_for(60, resolver_anchor_body);
}

/// Finalizes `blocks` (borrowed) in order at `validator`, at views equal to their heights.
fn finalize_chain(net: *Net, validator: *Validator, blocks: []const Block) !void {
    for (blocks) |*block| {
        const height = block.inner().height().get();
        try H.verify(validator, round_at(height), block);
        report(&validator.mailbox, try finalize(&net.fixture, height, height - 1, block));
    }
}

fn below_floor_body(ctx: Ctx) anyerror!void {
    const net = try Net.start(ctx, 2);
    defer net.stop();
    const victim = try net.validator(ctx, "victim", 0);
    defer victim.crash();
    const server = try net.validator(ctx, "server", 1);
    defer server.crash();
    // Advance the victim's processed floor to height 3 on the canonical chain.
    var canonical: [3]Block = undefined;
    var made: usize = 0;
    defer for (canonical[0..made]) |*block| block.deinit();
    var parent = hash("");
    for (&canonical, 1..) |*block, height| {
        block.* = try block_at(parent, height, height);
        parent = block.digest();
        made += 1;
    }
    try finalize_chain(net, victim, &canonical);
    try wait_holds(ctx, victim.application, 3);
    // A conflicting finalization commits to a fork block at or below the processed floor
    // (reachable only when a Byzantine quorum double-finalizes).
    var fork = try block_at(canonical[0].digest(), 2, 999);
    defer fork.deinit();
    try H.verify(server, round_at(4), &fork);
    var mailbox = victim.mailbox;
    var subscription = try mailbox.subscribe_by_digest(fork.digest(), .wait);
    defer subscription.deinit();
    try mailbox.set_floor(try finalize(&net.fixture, 4, 1, &fork));
    try testing.expectEqual(null, try mailbox.get_block(.{ .digest = fork.digest() }));
    try net.link(2);
    // The at-or-below-floor delivery still wakes subscribers.
    try expect_block(&subscription, fork.digest());
    // The pending floor was consumed, so dispatch continues on the canonical chain.
    var next = try block_at(canonical[2].digest(), 4, 4);
    defer next.deinit();
    try testing.expect(try mailbox.verified(round_at(5), next.clone()));
    report(&mailbox, try finalize(&net.fixture, 5, 3, &next));
    try wait_holds(ctx, victim.application, 4);
}

test "standard below-floor anchor delivery wakes subscriber" {
    // commonware `test_standard_below_floor_anchor_delivery_wakes_subscriber`.
    try run_for(60, below_floor_body);
}

// Inline and deferred wrappers over the harness mailbox (commonware's `WrapperKind`).

const mocks = @import("../../mocks/root.zig");
const oneshot = utils.channel.oneshot;
const Marshal = @FieldType(Validator, "mailbox");
const Stream = @import("../../ancestry.zig").AncestorStream(Marshal);
const Mock = mocks.verifying.MockVerifyingApp(harness.B, Ctx, harness.Ctx, Stream);
const InlineWrapper = @import("../inline.zig").Inline(
    Ctx,
    harness.S,
    Mock,
    harness.B,
    types.FixedEpocher,
);
const DeferredWrapper = @import("../deferred.zig").Deferred(
    Ctx,
    harness.S,
    Mock,
    harness.B,
    types.FixedEpocher,
);

fn epocher() types.FixedEpocher {
    return .new(utils.NonZero(u64).init(harness.blocks_per_epoch).?);
}

/// Publishes a staged digest once, so the test knows staging registered its entries.
const Publish = struct {
    sender: ?oneshot.Sender(D),

    pub fn call(self: *Publish, digest: D) void {
        if (self.sender) |*sender| sender.send(digest) catch {};
        self.sender = null;
    }
};

fn StageTask(comptime W: type) type {
    return struct {
        fn run(
            registry: W.Registry,
            round: Round,
            digest: D,
            block: Block,
            publish: *Publish,
        ) void {
            registry.stage(round, digest, block, publish, "test") catch {};
        }
    };
}

/// commonware `stage_block`: stages `block` (taken) at `round` in a task that waits for its
/// durability ack, returning once staging published its digest.
fn stage_block(
    comptime W: type,
    io: Io,
    wrapper: *W,
    publish: *Publish,
    round: Round,
    block: Block,
) !Io.Future(void) {
    const digest = block.digest();
    var pair = try oneshot.channel(D, gpa, io);
    defer pair.receiver.deinit();
    publish.* = .{ .sender = pair.sender };
    const args = .{ wrapper.registry, round, digest, block, publish };
    var task = try io.concurrent(StageTask(W).run, args);
    errdefer task.cancel(io);
    const published = try pair.receiver.recv();
    try testing.expect(published.eql(digest));
    return task;
}

/// Takes and releases the gate at `(round, digest)`; whether there was one.
fn take_gate(wrapper: anytype, round: Round, digest: D) bool {
    var gate = wrapper.registry.take(round, digest) orelse return false;
    gate.deinit();
    return true;
}

/// Takes and releases the staged proposal at `(round, digest)`; whether there was one.
fn take_staged(wrapper: anytype, round: Round, digest: D) !bool {
    const taken = try wrapper.registry.take_staged(round, digest) orelse return false;
    var staged = taken[0];
    staged.block.deinit();
    staged.ack.deinit();
    return true;
}

/// commonware `epoch_zero_entries_remain`: stages proposals (with their gates) at epoch 0
/// view 5 and at `notarized`, reports a notarization at `notarized`, and returns whether the
/// epoch-0 entries remain.
fn epoch_zero_entries_remain(comptime W: type, ctx: Ctx, notarized: Round) !bool {
    const io = ctx.io();
    const net = try Net.start(ctx, harness.num_validators);
    defer net.stop();
    const validator = try net.validator(ctx, "validator", 0);
    defer validator.crash();
    const marshal = validator.mailbox.clone();
    const wrapper = try W.create(ctx.child("wrapper"), Mock.init(gpa), marshal, epocher());
    defer wrapper.destroy();
    var publishes: [2]Publish = undefined;
    const earlier_round = round_at(5);
    const earlier = try block_at(hash(""), 1, 100);
    const earlier_digest = earlier.digest();
    var first = try stage_block(W, io, wrapper, &publishes[0], earlier_round, earlier);
    defer first.cancel(io);
    const block = try block_at(hash(""), 2, 200);
    const digest = block.digest();
    var second = try stage_block(W, io, wrapper, &publishes[1], notarized, block);
    defer second.cancel(io);
    const proposal = harness.Proposal.init(notarized, .zero(), digest);
    var notarization = try harness.make_notarization(gpa, &net.fixture, proposal, harness.quorum);
    defer notarization.deinit(gpa);
    _ = wrapper.report(.{ .notarization = notarization });
    // Certification of the notarized round follows its notarization, so both entries stay.
    try testing.expect(take_gate(wrapper, notarized, digest));
    try testing.expect(try take_staged(wrapper, notarized, digest));
    const gate = take_gate(wrapper, earlier_round, earlier_digest);
    const staged = try take_staged(wrapper, earlier_round, earlier_digest);
    // A report keeps or releases a round's gate and proposal together.
    try testing.expectEqual(gate, staged);
    return gate;
}

fn EpochCase(
    comptime W: type,
    comptime epoch: u64,
    comptime view: u64,
    comptime keeps: bool,
) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            const notarized: Round = .new(.new(epoch), .new(view));
            try testing.expectEqual(keeps, try epoch_zero_entries_remain(W, ctx, notarized));
        }
    };
}

test "inline later epoch activity releases earlier epoch" {
    // commonware `test_inline_later_epoch_activity_releases_earlier_epoch`.
    try run_for(30, EpochCase(InlineWrapper, 1, 1, false).body);
}

test "deferred later epoch activity releases earlier epoch" {
    // commonware `test_deferred_later_epoch_activity_releases_earlier_epoch`.
    try run_for(30, EpochCase(DeferredWrapper, 1, 1, false).body);
}

test "inline same epoch activity keeps gates" {
    // commonware `test_inline_same_epoch_activity_keeps_gates`.
    try run_for(30, EpochCase(InlineWrapper, 0, 7, true).body);
}

test "deferred same epoch activity keeps gates" {
    // commonware `test_deferred_same_epoch_activity_keeps_gates`.
    try run_for(30, EpochCase(DeferredWrapper, 0, 7, true).body);
}
