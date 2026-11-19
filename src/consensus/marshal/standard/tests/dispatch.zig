//! The standard actor's cache writes, notarized decode, finalization sync, staged dispatch,
//! relay sends, forward, and hint_finalized (commonware `standard/mod.rs`, lines
//! 10612-12604).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const cryptography = @import("cryptography");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks_block = @import("../../mocks/block.zig");
const mocks_store = @import("../../mocks/store.zig");
const common = @import("common.zig");
const parallel = @import("parallel");
const core = @import("../../core/root.zig");
const core_variant = @import("../../core/variant.zig");
const standard_variant = @import("../variant.zig");
const codec = @import("codec");
const handler = @import("../../resolver/handler.zig");
const inline_mod = @import("../inline.zig");
const deferred_mod = @import("../deferred.zig");
const simplex = @import("../../../simplex/root.zig");
const gates_api = @import("../../application/gates.zig");
const relay_api = @import("../../application/relay.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;
const B = harness.B;
const oneshot = utils.channel.oneshot;
const Started = common.Started(harness.Provider, App, common.RecordingBuffer);

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

/// A fixture and a buffered actor started at genesis (commonware `start_standard_actor` with
/// a `RecordingBuffer` and a manually acknowledging application).
const Env = struct {
    fixture: harness.Fixture,
    started: Started,

    fn init(self: *Env, ctx: Ctx, comptime label: []const u8) !void {
        try self.init_at(ctx, label, 0);
    }

    /// Like `init`, as validator `index`.
    fn init_at(self: *Env, ctx: Ctx, comptime label: []const u8, index: usize) !void {
        var rng = utils.rng.test_rng();
        self.fixture = try harness.fixture(gpa, &rng);
        errdefer self.fixture.deinit(gpa);
        var name: [128]u8 = undefined;
        const me = self.fixture.participants[index];
        const prefix = try std.fmt.bufPrint(&name, label ++ "-{f}", .{me});
        self.started = try common.start_standard_actor(
            harness.Provider,
            App,
            common.RecordingBuffer,
            ctx.child("validator").with_attribute("index", index),
            prefix,
            .init(&self.fixture.schemes[index]),
            try App.manual_ack(gpa, ctx.io()),
            try common.RecordingBuffer.init(gpa, ctx.io()),
            .{ .genesis = try H.genesis_block(gpa, harness.num_validators) },
        );
    }

    fn deinit(self: *Env) void {
        self.started.crash();
        self.fixture.deinit(gpa);
    }

    fn buffer(self: *const Env) common.RecordingBuffer {
        return self.started.buffer.?;
    }

    fn finalize(
        self: *const Env,
        round: Round,
        parent_view: u64,
        block: anytype,
    ) !harness.Finalization {
        const proposal = harness.Proposal.init(round, .new(parent_view), block.digest());
        return harness.make_finalization(gpa, &self.fixture, proposal, harness.quorum);
    }
};

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// Block 1 over genesis's parent, stamped `timestamp`.
fn block_one(timestamp: u64) !B {
    return harness.make_raw_block(gpa, harness.genesis_parent(), .new(1), timestamp);
}

fn ready(block: B) !common.Block {
    return mocks_block.ready(B, gpa, block);
}

fn send_count_nonzero(buffer: common.RecordingBuffer) bool {
    return buffer.send_count() > 0;
}

fn targeted_nonempty(resolver: common.RecordingResolver) bool {
    return !resolver.targeted_is_empty();
}

fn proposed_conflicting_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "proposed-conflict");
    defer env.deinit();
    const round = round_at(1);
    const block_a = try block_one(100);
    const block_b = try block_one(200);
    try testing.expect(!block_a.digest().eql(block_b.digest()));
    const mailbox = &env.started.mailbox;
    var persist_a = try oneshot.channel(void, gpa, ctx.io());
    defer persist_a.receiver.deinit();
    _ = try mailbox.proposed(round, try ready(block_a), .all, persist_a.sender);
    var persist_b = try oneshot.channel(void, gpa, ctx.io());
    defer persist_b.receiver.deinit();
    _ = try mailbox.proposed(round, try ready(block_b), .all, persist_b.sender);
    // Each ack arrives once its proposal is durable.
    try persist_a.receiver.recv();
    try persist_b.receiver.recv();
    const sends = try env.buffer().sends(gpa);
    defer common.RecordingBuffer.free_sends(gpa, sends);
    // Both conflicting proposals dispatch.
    try testing.expectEqual(2, sends.len);
    try testing.expect(sends[0].block.digest().eql(block_a.digest()));
    try testing.expect(sends[1].block.digest().eql(block_b.digest()));
}

test "standard proposed conflicting blocks both ack" {
    try run(proposed_conflicting_body);
}

fn forward_cached_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "forward-cached");
    defer env.deinit();
    const round = round_at(1);
    const block = try block_one(100);
    const digest = block.digest();
    const mailbox = &env.started.mailbox;
    try testing.expect(try mailbox.verified(round, try ready(block)));
    // A cached block forwards to exactly the given peers.
    const targets = env.fixture.participants[1..3];
    _ = try mailbox.forward(round, digest, .{ .some = try gpa.dupe(harness.K, targets) });
    try common.wait_until(ctx, 5000, "buffer.send", env.buffer(), send_count_nonzero);
    const sends = try env.buffer().sends(gpa);
    defer common.RecordingBuffer.free_sends(gpa, sends);
    try testing.expectEqual(1, sends.len);
    try testing.expect(std.meta.eql(sends[0].round, round));
    try testing.expect(sends[0].block.digest().eql(digest));
    try testing.expect(sends[0].recipients == .some);
    try testing.expectEqualSlices(harness.K, targets, sends[0].recipients.some);
}

test "standard forward cached block sends to peers" {
    try run(forward_cached_body);
}

fn hint_below_floor_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "hint-below-floor");
    defer env.deinit();
    const mailbox = &env.started.mailbox;
    // Raise the floor above the hint about to be sent.
    const parent = cryptography.Sha256.hash(&.{"floor-parent"});
    const commitment = H.genesis_parent_commitment(harness.num_validators);
    const anchor = try H.make_test_block(
        gpa,
        parent,
        commitment,
        .new(10),
        10,
        harness.num_validators,
    );
    const floor_round = round_at(10);
    try mailbox.set_floor(try env.finalize(floor_round, 9, &anchor));
    try testing.expect(try mailbox.verified(floor_round, anchor));
    try ctx.sleep(.fromMilliseconds(50));
    // A hint at or below the floor is stale and fetches nothing.
    try mailbox.hint_finalized(.new(5), env.fixture.participants[1..2]);
    try ctx.sleep(.fromMilliseconds(50));
    try testing.expect(env.started.resolver.targeted_is_empty());
}

test "standard hint finalized below floor is a no-op" {
    try run(hint_below_floor_body);
}

fn has_finalization(mailbox: anytype, height: Height) !bool {
    var finalization = (try mailbox.get_finalization(height)) orelse return false;
    finalization.deinit(gpa);
    return true;
}

fn hint_already_finalized_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "hint-already-final");
    defer env.deinit();
    const round = round_at(1);
    const block = try block_one(100);
    var finalization = try env.finalize(round, 0, &block);
    defer finalization.deinit(gpa);
    const mailbox = &env.started.mailbox;
    try testing.expect(try mailbox.verified(round, try ready(block)));
    _ = mailbox.report(.{ .finalization = finalization });
    while (!try has_finalization(mailbox, .new(1))) try ctx.sleep(.fromMilliseconds(10));
    // A locally finalized height needs no fetch.
    try mailbox.hint_finalized(.new(1), env.fixture.participants[1..2]);
    try ctx.sleep(.fromMilliseconds(50));
    try testing.expect(env.started.resolver.targeted_is_empty());
}

test "standard hint finalized skips when already finalized" {
    try run(hint_already_finalized_body);
}

fn hint_targeted_fetch_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "hint-targets");
    defer env.deinit();
    const target = env.fixture.participants[1];
    try env.started.mailbox.hint_finalized(.new(7), &.{target});
    const resolver = env.started.resolver;
    try common.wait_until(ctx, 5000, "fetch_targeted", resolver, targeted_nonempty);
    const keys = try resolver.targeted_keys(gpa);
    defer gpa.free(keys);
    // Exactly one targeted fetch, for the finalization at height 7, from the hinted peer.
    try testing.expectEqual(1, keys.len);
    try testing.expect(keys[0] == .finalized);
    try testing.expectEqual(Height.new(7), keys[0].finalized);
    try testing.expectEqualSlices(harness.K, &.{target}, resolver.targeted_targets(0));
}

test "standard hint finalized emits a targeted fetch" {
    try run(hint_targeted_fetch_body);
}

fn send_count_two(buffer: common.RecordingBuffer) bool {
    return buffer.send_count() >= 2;
}

fn forward_unknown_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "forward-unknown");
    defer env.deinit();
    const unknown = cryptography.Sha256.hash(&.{"unknown-block"});
    const peers = try gpa.dupe(harness.K, env.fixture.participants[1..2]);
    _ = try env.started.mailbox.forward(round_at(1), unknown, .{ .some = peers });
    try ctx.sleep(.fromMilliseconds(50));
    // A forward for an unknown block must not dispatch.
    try testing.expectEqual(0, env.buffer().send_count());
}

test "standard forward unknown block is a no-op" {
    try run(forward_unknown_body);
}

fn proposed_persists_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "proposed-cache");
    defer env.deinit();
    const round = round_at(1);
    const block = try block_one(100);
    const digest = block.digest();
    const mailbox = &env.started.mailbox;
    const targets = env.fixture.participants[1..2];
    var persist = try oneshot.channel(void, gpa, ctx.io());
    defer persist.receiver.deinit();
    const recipients: common.Recipients = .{ .some = try gpa.dupe(harness.K, targets) };
    _ = try mailbox.proposed(round, try ready(block), recipients, persist.sender);
    try common.wait_until(ctx, 5000, "proposed send", env.buffer(), send_count_nonzero);
    {
        const sends = try env.buffer().sends(gpa);
        defer common.RecordingBuffer.free_sends(gpa, sends);
        // The proposal dispatches exactly once.
        try testing.expectEqual(1, sends.len);
        try testing.expect(std.meta.eql(sends[0].round, round));
        try testing.expect(sends[0].block.digest().eql(digest));
    }
    // The block persists after the broadcast, so the ack resolves durable.
    try persist.receiver.recv();
    // A forward for the same commitment serves the persisted block from storage.
    _ = try mailbox.forward(round, digest, .{ .some = try gpa.dupe(harness.K, targets) });
    try common.wait_until(ctx, 5000, "forward send", env.buffer(), send_count_two);
    const sends = try env.buffer().sends(gpa);
    defer common.RecordingBuffer.free_sends(gpa, sends);
    try testing.expectEqual(2, sends.len);
    try testing.expect(sends[1].block.digest().eql(digest));
}

test "standard proposed broadcasts then persists" {
    try run(proposed_persists_body);
}

const TestGates = gates_api.Gates(common.D, common.V);
const Plan = simplex.Plan(harness.K);
const StageFuture = std.Io.Future(anyerror!void);

/// Publishes the staged digest once.
const Publisher = struct {
    sender: ?oneshot.Sender(common.D),

    pub fn call(self: *Publisher, digest: common.D) void {
        if (self.sender) |*sender| sender.send(digest) catch {};
        self.sender = null;
    }
};

fn stage_task(
    registry: TestGates,
    round: Round,
    block: common.Block,
    published: oneshot.Sender(common.D),
) anyerror!void {
    var owned = registry;
    defer owned.deinit();
    var publisher: Publisher = .{ .sender = published };
    defer if (publisher.sender) |*sender| sender.deinit();
    try owned.stage(round, block.digest(), block, &publisher, "test");
}

/// A staging task (commonware `stage_block`'s handle): it ends once the block is durable or
/// its staged ack is dropped.
const Stager = struct {
    io: std.Io,
    future: StageFuture,
    joined: bool = false,

    /// Stages `block` for `round` in `registry` as a prepare or propose build does, and
    /// returns once the block's digest is published.
    fn start(ctx: Ctx, registry: TestGates, round: Round, block: B) !Stager {
        const io = ctx.io();
        const digest = block.digest();
        var published = try oneshot.channel(common.D, gpa, io);
        defer published.receiver.deinit();
        const args = .{ registry.clone(), round, try ready(block), published.sender };
        var future = try io.concurrent(stage_task, args);
        errdefer future.cancel(io) catch {};
        // Staging must publish the block digest.
        try testing.expect((try published.receiver.recv()).eql(digest));
        return .{ .io = io, .future = future };
    }

    fn join(self: *Stager) !void {
        self.joined = true;
        try self.future.await(self.io);
    }

    fn deinit(self: *Stager) void {
        if (!self.joined) self.future.cancel(self.io) catch {};
    }
};

fn relay(env: *Env, registry: TestGates, digest: common.D, plan: Plan) !void {
    const mailbox = env.started.mailbox;
    const feedback = try relay_api.broadcast(harness.S, common.V, registry, mailbox, digest, plan);
    try testing.expectEqual(.ok, feedback);
}

fn has_verified(env: *Env, round: Round) !bool {
    var block = (try env.started.mailbox.get_verified(round)) orelse return false;
    common.V.deinit_block(gpa, &block);
    return true;
}

fn expect_ready(gate: *gates_api.Gate) !void {
    const outcome = try gate.recv();
    try testing.expect(outcome == .ready and outcome.ready);
}

/// Hands a claimed proposal to marshal as certification does.
const Persist = struct {
    mailbox: *Started.A.Mailbox,
    round: Round,

    pub fn call(self: Persist, block: common.Block, ack: gates_api.Ack) void {
        self.mailbox.verified_deferred(self.round, block, ack) catch @panic("OOM");
    }
};

fn relay_after_claim_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "relay-claim");
    defer env.deinit();
    const round = round_at(1);
    const block = try block_one(100);
    const digest = block.digest();
    var registry: TestGates = try .init(gpa, ctx.io());
    defer registry.deinit();
    var stager = try Stager.start(ctx, registry, round, block);
    defer stager.deinit();
    // The early relay sends the candidate. Each lookup below goes through the same marshal
    // mailbox as the relays, so it observes every send they requested.
    try relay(&env, registry, digest, .{ .prepare = .{ .round = round } });
    // An early relay must not store the candidate.
    try testing.expect(!try has_verified(&env, round));
    try testing.expectEqual(1, env.buffer().send_count());
    // Certification claims the candidate and persists it.
    const persist: Persist = .{ .mailbox = &env.started.mailbox, .round = round };
    var gate = registry.claim(round, digest, persist) orelse return error.GateMissing;
    defer gate.deinit();
    try expect_ready(&gate);
    // The lock-in finds nothing staged and must not send the candidate again.
    try relay(&env, registry, digest, .{ .propose = .{ .round = round } });
    try testing.expect(try has_verified(&env, round));
    try testing.expectEqual(1, env.buffer().send_count());
    try stager.join();
}

test "standard propose relay after claim sends once" {
    try run(relay_after_claim_body);
}

fn restage_after_prune_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "relay-restage");
    defer env.deinit();
    const round = round_at(1);
    const block = try block_one(100);
    const digest = block.digest();
    var registry: TestGates = try .init(gpa, ctx.io());
    defer registry.deinit();
    var first = try Stager.start(ctx, registry, round, block);
    defer first.deinit();
    try relay(&env, registry, digest, .{ .prepare = .{ .round = round } });
    try testing.expect(!try has_verified(&env, round));
    try testing.expectEqual(1, env.buffer().send_count());
    // A finalization past the round prunes the candidate, which ends its staging.
    registry.retain_after(round_at(2));
    try first.join();
    // The candidate is staged again for the decided round. Neither relay sends it, and the
    // lock-in persists it through the staged ack.
    var second = try Stager.start(ctx, registry, round, block);
    defer second.deinit();
    var gate = registry.take(round, digest) orelse return error.GateMissing;
    defer gate.deinit();
    try relay(&env, registry, digest, .{ .prepare = .{ .round = round } });
    try relay(&env, registry, digest, .{ .propose = .{ .round = round } });
    try expect_ready(&gate);
    try testing.expect(try has_verified(&env, round));
    // A candidate staged again for a decided round must not be sent again.
    try testing.expectEqual(1, env.buffer().send_count());
    try second.join();
}

test "standard restage after prune sends once" {
    try run(restage_after_prune_body);
}

fn expect_single_send_to_all(env: *Env, round: Round, digest: common.D) !void {
    const sends = try env.buffer().sends(gpa);
    defer common.RecordingBuffer.free_sends(gpa, sends);
    try testing.expectEqual(1, sends.len);
    try testing.expect(std.meta.eql(sends[0].round, round));
    try testing.expect(sends[0].block.digest().eql(digest));
    try testing.expect(sends[0].recipients == .all);
}

fn expect_nothing_staged(registry: TestGates, round: Round, digest: common.D) !void {
    const taken = try registry.take_staged(round, digest);
    try testing.expect(taken == null);
}

fn relay_sends_staged_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "relay-hit");
    defer env.deinit();
    const round = round_at(1);
    const block = try block_one(100);
    const digest = block.digest();
    var registry: TestGates = try .init(gpa, ctx.io());
    defer registry.deinit();
    // Stage the proposal as propose would.
    var stager = try Stager.start(ctx, registry, round, block);
    defer stager.deinit();
    var gate = registry.take(round, digest) orelse return error.GateMissing;
    defer gate.deinit();
    // The relay takes the staged proposal and dispatches it exactly once.
    try relay(&env, registry, digest, .{ .propose = .{ .round = round } });
    try common.wait_until(ctx, 5000, "staged send", env.buffer(), send_count_nonzero);
    try expect_single_send_to_all(&env, round, digest);
    try expect_nothing_staged(registry, round, digest);
    // The relayed proposal persists through the staged ack, so the gate resolves durably.
    try expect_ready(&gate);
    try stager.join();
}

test "standard propose relay sends staged block" {
    try run(relay_sends_staged_body);
}

fn prepare_relay_once_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "relay-prepare");
    defer env.deinit();
    const round = round_at(1);
    const block = try block_one(100);
    const digest = block.digest();
    var registry: TestGates = try .init(gpa, ctx.io());
    defer registry.deinit();
    // Stage the candidate as prepare would.
    var stager = try Stager.start(ctx, registry, round, block);
    defer stager.deinit();
    var gate = registry.take(round, digest) orelse return error.GateMissing;
    defer gate.deinit();
    // The early relay sends the candidate and keeps it staged, unstored.
    try relay(&env, registry, digest, .{ .prepare = .{ .round = round } });
    while (env.buffer().send_count() == 0) try ctx.sleep(.fromMilliseconds(1));
    try testing.expectEqual(1, env.buffer().send_count());
    try testing.expect(!try has_verified(&env, round));
    // An early relay must not resolve the certification gate.
    try testing.expect(!gate.is_ready());
    // A repeated prepare relay must not send the candidate again. The lock-in below goes
    // through the same marshal mailbox, so its handshake orders this relay first.
    try relay(&env, registry, digest, .{ .prepare = .{ .round = round } });
    // The lock-in stores the candidate without sending it again.
    try relay(&env, registry, digest, .{ .propose = .{ .round = round } });
    try expect_nothing_staged(registry, round, digest);
    try expect_ready(&gate);
    try testing.expect(try has_verified(&env, round));
    try expect_single_send_to_all(&env, round, digest);
    try stager.join();
}

test "standard prepare relay sends once and propose stores" {
    try run(prepare_relay_once_body);
}

const Prunable = common.PrunableStores(B);
const RecordedBlocks = mocks_store.Recording(Prunable.Blocks, B);
const StagingActor = common.Actor(
    harness.Provider,
    App,
    common.RecordingBuffer,
    Prunable.Certificates,
    RecordedBlocks,
);

/// A block's identity in the recorded puts. commonware records the stored `Arc`'s address;
/// standard storage keeps a value copy here, so the put carries the block's timestamp.
fn timestamp_address(block: *const B) usize {
    return @intCast(block.timestamp);
}

/// An actor over prunable stores whose finalized blocks record their puts and gets, with a
/// buffer handing out a new object per hit (commonware's `Recording` over
/// `prunable_finalized_stores`, `NZUsize!(1)` pending acks, and a holding resolver).
const Staging = struct {
    fixture: harness.Fixture,
    stores: *Prunable,
    log: *mocks_store.Log,
    mailbox: StagingActor.Mailbox,
    resolver: common.RecordingResolver,
    application: App,
    buffer: common.RecordingBuffer,
    handle: runtime.context.Handle(anyerror!void),

    fn init(self: *Staging, ctx: Ctx, comptime prefix: []const u8, application: App) !void {
        try self.open(ctx, prefix, application, null);
    }

    /// Like `init`, with `preexisting` already in the finalized-block archive.
    fn open(
        self: *Staging,
        ctx: Ctx,
        comptime prefix: []const u8,
        application: App,
        preexisting: ?B,
    ) !void {
        var app = application;
        errdefer app.deinit();
        var rng = utils.rng.test_rng();
        self.fixture = try harness.fixture(gpa, &rng);
        errdefer self.fixture.deinit(gpa);
        self.stores = try gpa.create(Prunable);
        errdefer gpa.destroy(self.stores);
        try self.stores.open(ctx, prefix);
        errdefer self.stores.deinit();
        if (preexisting) |block| {
            try self.stores.blocks_store().put(block.digest(), &block);
            try self.stores.blocks_store().sync();
        }
        self.log = try gpa.create(mocks_store.Log);
        errdefer gpa.destroy(self.log);
        self.log.* = .init(gpa);
        errdefer self.log.deinit();
        const blocks: RecordedBlocks = .init(
            self.stores.blocks_store(),
            self.log,
            &timestamp_address,
        );
        const provider: harness.Provider = .init(&self.fixture.schemes[0]);
        const page_cache = &self.stores.cache_ref;
        const config = try common.test_config(StagingActor, gpa, prefix, provider, 1, page_cache);
        const initialized =
            try StagingActor.init(ctx.child("actor"), self.stores.certificates(), blocks, config);
        self.mailbox = initialized.mailbox;
        var holding =
            try common.RecordingResolver.holding(gpa, ctx.io(), &ctx.scope.child("resolver"));
        self.resolver = holding.resolver;
        self.buffer = try common.RecordingBuffer.init(gpa, ctx.io());
        self.buffer.hand_fresh_copies();
        self.application = app;
        self.handle = try initialized.actor.start(
            app.clone(),
            self.buffer.clone(),
            holding.receiver,
            holding.resolver.clone(),
        );
    }

    fn deinit(self: *Staging) void {
        const ended = self.handle.abort() catch {};
        ended catch {};
        self.mailbox.deinit();
        self.application.deinit();
        self.buffer.deinit();
        self.resolver.deinit();
        self.stores.deinit();
        gpa.destroy(self.stores);
        self.log.deinit();
        gpa.destroy(self.log);
        self.fixture.deinit(gpa);
    }

    fn finalize(self: *const Staging, view: u64, block: B) !harness.Finalization {
        const proposal = harness.Proposal.init(round_at(view), .new(view - 1), block.digest());
        return harness.make_finalization(gpa, &self.fixture, proposal, harness.quorum);
    }

    /// Reports the finalization of `block` at `view`, then reads the block back: mailbox
    /// messages are FIFO, so a served read proves the finalization arm has run.
    fn finalize_and_read(self: *Staging, view: u64, block: B) !void {
        var finalization = try self.finalize(view, block);
        defer finalization.deinit(gpa);
        _ = self.mailbox.report(.{ .finalization = finalization });
        var archived = (try self.mailbox.get_block(.{ .height = block.height() })) orelse
            return error.BlockMissing;
        defer archived.deinit();
        try testing.expect(archived.digest().eql(block.digest()));
    }

    fn wait_for_height(self: *Staging, ctx: Ctx, height: u64) !void {
        while (!self.application.contains(.new(height))) try ctx.sleep(.fromMilliseconds(1));
    }

    fn pending_is(self: *Staging, expected: []const u64) !bool {
        const heights = try self.application.pending_ack_heights(gpa);
        defer gpa.free(heights);
        if (heights.len != expected.len) return false;
        for (heights, expected) |height, want| if (height.get() != want) return false;
        return true;
    }

    fn wait_pending(self: *Staging, ctx: Ctx, expected: []const u64) !void {
        while (!try self.pending_is(expected)) try ctx.sleep(.fromMilliseconds(1));
    }

    /// The number of archive reads of the block at `height` recorded so far.
    fn reads_at(self: *const Staging, height: u64) usize {
        var count: usize = 0;
        for (self.log.ops.items) |op| {
            if (op.eql(.{ .get = .new(height) })) count += 1;
        }
        return count;
    }
};

fn genesis_digest() !common.D {
    var genesis = try H.genesis_block(gpa, harness.num_validators);
    defer genesis.deinit();
    return genesis.digest();
}

fn staged_without_read_body(ctx: Ctx) anyerror!void {
    var env: Staging = undefined;
    try env.init(ctx, "staged-dispatch", try App.init(gpa, ctx.io()));
    defer env.deinit();
    // Genesis is dispatched from the archive and acknowledged on delivery, so the pipeline
    // is idle before the finalization arrives.
    try env.wait_for_height(ctx, 0);
    // Finalize a block the buffer serves.
    const block = try harness.make_raw_block(gpa, try genesis_digest(), .new(1), 100);
    try env.buffer.insert(try ready(block));
    var finalization = try env.finalize(1, block);
    defer finalization.deinit(gpa);
    _ = env.mailbox.report(.{ .finalization = finalization });
    try env.wait_for_height(ctx, 1);
    var delivered = env.application.block(.new(1)) orelse return error.BlockMissing;
    defer delivered.deinit();
    try testing.expect(delivered.digest().eql(block.digest()));
    // Dispatch delivers the block object the buffer handed to marshal.
    const handed = env.buffer.handed_count();
    try testing.expect(handed > 0);
    try testing.expect(env.buffer.handed_same(handed - 1, delivered));
    const ops = env.log.ops.items;
    const written = for (ops, 0..) |op, index| {
        if (op == .put and op.put.height.get() == 1) break index;
    } else return error.BlockNotWritten;
    // Storage holds the block dispatched to the application.
    try testing.expectEqual(timestamp_address(delivered.inner()), ops[written].put.payload_address);
    // Dispatch must not read the finalized block back from the archive.
    for (ops[written..]) |op| try testing.expect(!op.eql(.{ .get = .new(1) }));
}

test "standard dispatch delivers staged block without archive read" {
    try run(staged_without_read_body);
}

fn staged_dedup(ctx: Ctx, comptime preexisting: bool) anyerror!void {
    const block = try harness.make_raw_block(gpa, try genesis_digest(), .new(1), 100);
    var env: Staging = undefined;
    const app = try App.manual_ack(gpa, ctx.io());
    try env.open(ctx, "staged-dedup", app, if (preexisting) block else null);
    defer env.deinit();
    // Hold genesis so both finalizations precede dispatch at height one.
    try env.wait_pending(ctx, &.{0});
    // Repeated finalizations retain the first staged object.
    try env.buffer.insert(try ready(block));
    for (0..2) |round| {
        try env.finalize_and_read(1, block);
        // The buffer served the finalized block.
        try testing.expectEqual(round + 1, env.buffer.handed_count());
    }
    // The first buffered object stays staged even if already archived.
    try testing.expect(!env.buffer.handed_released(0));
    // A duplicate finalization must not replace the staged object.
    try testing.expect(env.buffer.handed_released(1));
    try testing.expectEqual(Height.new(0), try env.application.acknowledged());
    try env.wait_for_height(ctx, 1);
    var delivered = env.application.block(.new(1)) orelse return error.BlockMissing;
    defer delivered.deinit();
    // Dispatch reuses the first staged object.
    try testing.expect(env.buffer.handed_same(0, delivered));
    var archived = (try env.mailbox.get_block(.{ .height = .new(1) })) orelse
        return error.BlockMissing;
    defer archived.deinit();
    // Dispatch delivers the block retained by the archive.
    try testing.expect(delivered.digest().eql(archived.digest()));
}

fn staged_dedup_body(ctx: Ctx) anyerror!void {
    try staged_dedup(ctx, false);
}

fn staged_dedup_preexisting_body(ctx: Ctx) anyerror!void {
    try staged_dedup(ctx, true);
}

test "standard staged dispatch deduplicates finalizations" {
    try run(staged_dedup_body);
}

test "standard staged dispatch deduplicates preexisting block" {
    try run(staged_dedup_preexisting_body);
}

const anchor_height = 5;

/// Staging retains at most twice the ack capacity until dispatch or a floor skips the
/// blocks.
fn staged_bounded(ctx: Ctx, comptime skip_to_floor: bool) anyerror!void {
    var env: Staging = undefined;
    try env.init(ctx, "staged-bounded", try App.manual_ack(gpa, ctx.io()));
    defer env.deinit();
    // Hold the genesis acknowledgement so nothing else can dispatch.
    try env.wait_pending(ctx, &.{0});
    // Build a chain whose tip is the floor anchor.
    var chain: [anchor_height]B = undefined;
    var parent = try genesis_digest();
    for (&chain, 1..) |*block, height| {
        block.* = try harness.make_raw_block(gpa, parent, .new(height), height);
        parent = block.digest();
    }
    // Two blocks fit in staging. A third must not displace either.
    for (chain[0..3], 1..) |block, height| {
        try env.buffer.insert(try ready(block));
        try env.finalize_and_read(height, block);
        try testing.expectEqual(height, env.buffer.handed_count());
    }
    // Staging retains two blocks without evicting either on overflow.
    try testing.expect(!env.buffer.handed_released(0));
    try testing.expect(!env.buffer.handed_released(1));
    // Staging stops at twice the pending-ack capacity.
    try testing.expect(env.buffer.handed_released(2));
    try testing.expect(try env.pending_is(&.{0}));
    if (skip_to_floor) {
        // A floor anchor releases the blocks it skips.
        const anchor = chain[anchor_height - 1];
        try env.buffer.insert(try ready(anchor));
        try env.mailbox.set_floor(try env.finalize(anchor_height, anchor));
        try env.wait_for_height(ctx, anchor_height);
        for (0..3) |index| try testing.expect(env.buffer.handed_released(index));
        for (chain[0..3]) |block| try testing.expect(!env.application.contains(block.height()));
    } else {
        // Drain the backlog: only the overflow block needs an archive read.
        env.log.ops.clearRetainingCapacity();
        for (0..4) |height| {
            try testing.expectEqual(Height.new(height), try env.application.acknowledged());
        }
        for (1..4) |height| {
            try testing.expectEqual(@intFromBool(height == 3), env.reads_at(height));
        }
    }
}

fn staged_bounded_drain_body(ctx: Ctx) anyerror!void {
    try staged_bounded(ctx, false);
}

fn staged_bounded_floor_body(ctx: Ctx) anyerror!void {
    try staged_bounded(ctx, true);
}

test "standard staged blocks bounded drain" {
    try run(staged_bounded_drain_body);
}

test "standard staged blocks bounded floor" {
    try run(staged_bounded_floor_body);
}

/// Repeated finalization of an in-flight block must not consume staging capacity.
fn no_restage_body(ctx: Ctx) anyerror!void {
    var env: Staging = undefined;
    try env.init(ctx, "restaged-ack", try App.manual_ack(gpa, ctx.io()));
    defer env.deinit();
    try testing.expectEqual(Height.new(0), try env.application.acknowledged());
    // Finalize block 1 and hold its acknowledgement once dispatched.
    const block = try harness.make_raw_block(gpa, try genesis_digest(), .new(1), 100);
    try env.buffer.insert(try ready(block));
    var finalization = try env.finalize(1, block);
    defer finalization.deinit(gpa);
    _ = env.mailbox.report(.{ .finalization = finalization });
    try env.wait_pending(ctx, &.{1});
    // The block is already in flight, so another finalization needs no retained copy.
    try env.finalize_and_read(1, block);
    const handed = env.buffer.handed_count();
    // The buffer served the finalized block again.
    try testing.expect(handed >= 2);
    try testing.expect(try env.pending_is(&.{1}));
    // An already-dispatched block must not consume staging capacity.
    try testing.expect(env.buffer.handed_released(handed - 1));
}

test "standard does not restage dispatched block" {
    try run(no_restage_body);
}

/// The `processed_height` gauge in a Prometheus exposition: the first non-comment line of the
/// form `<prefix>processed_height <value>` or `<prefix>processed_height{labels} <value>`.
fn parse_processed_height(metrics: []const u8) ?u64 {
    const name = "processed_height";
    var lines = std.mem.splitScalar(u8, metrics, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (std.mem.startsWith(u8, line, "#")) continue;
        const index = std.mem.indexOf(u8, line, name) orelse continue;
        var rest = line[index + name.len ..];
        if (std.mem.startsWith(u8, rest, "{")) {
            const end = std.mem.indexOfScalar(u8, rest, '}') orelse continue;
            rest = rest[end + 1 ..];
        }
        if (rest.len == 0 or !std.ascii.isWhitespace(rest[0])) continue;
        var values = std.mem.tokenizeAny(u8, rest, " \t");
        const value = values.next() orelse return null;
        return std.fmt.parseInt(u64, value, 10) catch null;
    }
    return null;
}

test "parse processed height reads plain and labelled gauges" {
    const exposition =
        \\# HELP marshal_processed_height The processed height.
        \\marshal_processed_height_total 9
        \\marshal_processed_height{epoch="0"} 7
    ;
    try testing.expectEqual(@as(?u64, 7), parse_processed_height(exposition));
    try testing.expectEqual(@as(?u64, 3), parse_processed_height("a_processed_height 3\n"));
    try testing.expectEqual(@as(?u64, null), parse_processed_height("# processed_height 3\n"));
}

const Validator = H.Validator(App);
const max_pending_acks = 4;
const invariant_blocks = 12;

/// The bound marshal's `processed_height` keeps on every block the application received:
/// the highest is at most `max_pending_acks` above it.
fn check_invariant(ctx: Ctx, application: App) !void {
    const blocks = try application.blocks(gpa);
    defer App.free_blocks(gpa, blocks);
    var highest: ?u64 = null;
    for (blocks) |entry| highest = @max(highest orelse 0, entry.height.get());
    const top = highest orelse return;
    const text = try ctx.encode(gpa);
    defer gpa.free(text);
    const processed = parse_processed_height(text) orelse return error.GaugeMissing;
    const gap = top -| processed;
    if (gap > max_pending_acks) {
        std.log.err("highest={d} processed={d} gap={d}", .{ top, processed, gap });
        return error.InvariantViolated;
    }
}

/// Submits `invariant_blocks` verified blocks and their finalizations to `validator`.
fn submit_chain(validator: *Validator, fixture: *const harness.Fixture) !void {
    var parent = cryptography.Sha256.hash(&.{""});
    var parent_commitment = H.genesis_parent_commitment(harness.num_validators);
    for (1..invariant_blocks + 1) |i| {
        var block = try H.make_test_block(
            gpa,
            parent,
            parent_commitment,
            .new(i),
            i,
            harness.num_validators,
        );
        defer block.deinit();
        const commitment = H.commitment(&block);
        parent = H.digest(&block);
        parent_commitment = commitment;
        const epoch = epocher().containing(H.height(&block)).?.epoch;
        const round: Round = .new(epoch, .new(i));
        try H.verify(validator, round, &block);
        const proposal = harness.Proposal.init(round, .new(i -| 1), commitment);
        var finalization = try harness.make_finalization(gpa, fixture, proposal, harness.quorum);
        defer finalization.deinit(gpa);
        _ = validator.mailbox.report(.{ .finalization = finalization });
    }
}

/// Regression test for the `Update.block` pruning contract: for every block at height `h`
/// the application received, `processed_height` is at least `h - max_pending_acks`. The gauge
/// is monotonic, so the test drives the pipeline (fill, drain) and checks after each step.
fn processed_invariant_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    const participants = fixture.participants;
    var network: harness.TestNetwork = try .start(gpa, ctx.io(), 1, participants, 1024 * 1024);
    defer network.stop();
    const provider: harness.Provider = .init(&fixture.schemes[0]);
    const child = ctx.child("validator").with_attribute("index", 0);
    const app = try App.manual_ack(gpa, ctx.io());
    const validator =
        try Validator.setup(
            child,
            network.network,
            participants[0],
            provider,
            max_pending_acks,
            app,
        );
    defer validator.crash();
    const application = validator.application;
    try testing.expectEqual(Height.new(0), try application.acknowledged());
    // Marshal dispatches up to max_pending_acks blocks at a time and stalls until acked.
    try submit_chain(validator, &fixture);
    // More finalizations than max_pending_acks were submitted, so the pipeline stalls at
    // max_pending_acks unacknowledged blocks: the peak-gap observation point.
    while (application.block_count() < max_pending_acks) try ctx.sleep(.fromMilliseconds(10));
    try check_invariant(ctx, application);
    // Drain: acknowledge blocks as they arrive and recheck after each dispatch cycle.
    while (true) {
        const acked = try application.acknowledged();
        try check_invariant(ctx, application);
        if (acked.get() == invariant_blocks) break;
    }
}

test "standard update block processed height invariant" {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 60 * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try try runner.start_context(processed_invariant_body, .{});
}

const Marshal = Started.A.Mailbox;
const Stream = @import("../../ancestry.zig").AncestorStream(Marshal);
const Mock = @import("../../mocks/verifying.zig").MockVerifyingApp(B, Ctx, harness.Ctx, Stream);
const InlineWrapper = inline_mod.Inline(Ctx, harness.S, Mock, B, types.FixedEpocher);
const DeferredWrapper = deferred_mod.Deferred(Ctx, harness.S, Mock, B, types.FixedEpocher);
const boundary_height = harness.blocks_per_epoch - 1;

/// Verifies the chain from genesis to the epoch's last block, each led by `leader`, and
/// returns that boundary block.
fn verify_to_boundary(env: *Env, leader: harness.K) !B {
    var genesis = try H.genesis_block(gpa, harness.num_validators);
    defer genesis.deinit();
    var boundary = genesis.inner().*;
    for (1..boundary_height + 1) |height| {
        const parent = boundary.digest();
        const context: harness.Ctx = .{
            .round = round_at(height),
            .leader = leader,
            .parent = .{ .new(height - 1), parent },
        };
        boundary = try B.init(gpa, context, parent, .new(height), height * 100);
        try testing.expect(try env.started.mailbox.verified(round_at(height), try ready(boundary)));
    }
    return boundary;
}

/// Reports the quorum notarization of `digest` at `view` over `parent_view`.
fn notarize(env: *Env, view: u64, parent_view: u64, digest: common.D) !void {
    const proposal = harness.Proposal.init(round_at(view), .new(parent_view), digest);
    var notarization = try harness.make_notarization(gpa, &env.fixture, proposal, harness.quorum);
    defer notarization.deinit(gpa);
    _ = env.started.mailbox.report(.{ .notarization = notarization });
}

/// Certifies the boundary block, then verifies its re-proposal by the outgoing leader.
fn certify_boundary(env: *Env, wrapper: anytype, io: std.Io, outgoing: harness.K) !common.D {
    const boundary = try verify_to_boundary(env, outgoing);
    const digest = boundary.digest();
    try notarize(env, boundary_height, boundary_height - 1, digest);
    // The boundary must certify.
    try testing.expectEqual(
        @as(?bool, true),
        try wrapper.certify(io, round_at(boundary_height), digest),
    );
    // The boundary is not finalized.
    try testing.expect(
        try env.started.mailbox.get_info(.{ .height = .new(boundary_height) }) == null,
    );
    const outgoing_context: harness.Ctx = .{
        .round = round_at(boundary_height + 1),
        .leader = outgoing,
        .parent = .{ .new(boundary_height), digest },
    };
    // The outgoing boundary re-proposal must verify.
    try testing.expectEqual(@as(?bool, true), try wrapper.verify(io, outgoing_context, digest));
    return digest;
}

/// A boundary payload relayed before parent replacement is not sent again at lock-in.
fn boundary_restage(comptime Wrapper: type) fn (Ctx) anyerror!void {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            const io = ctx.io();
            var env: Env = undefined;
            try env.init_at(ctx, "boundary-restage", 1);
            defer env.deinit();
            const outgoing = env.fixture.participants[0];
            const incoming = env.fixture.participants[1];
            const app = Mock.init(gpa).with_handoff(.{ .stage = {} });
            const marshal = env.started.mailbox.clone();
            const wrapper = try Wrapper.create(ctx.child("wrapper"), app, marshal, epocher());
            defer wrapper.destroy();
            // Let detached tasks (a store behind a sent verdict) finish before the wrapper goes.
            defer io.sleep(.fromMilliseconds(100), .awake) catch {};
            const digest = try certify_boundary(&env, wrapper, io, outgoing);
            const view = boundary_height + 2;
            const round = round_at(view);
            const held: harness.Ctx = .{
                .round = round,
                .leader = incoming,
                .parent = .{ .new(boundary_height + 1), digest },
            };
            // Prepare must reuse the boundary payload.
            const handoff = (try wrapper.prepare(io, held)) orelse return error.NoHandoff;
            try testing.expect(handoff == .stage and handoff.stage.eql(digest));
            try testing.expectEqual(
                .ok,
                wrapper.broadcast(digest, .{ .prepare = .{ .round = round } }),
            );
            while (env.buffer().send_count() == 0) try ctx.sleep(.fromMilliseconds(1));
            try testing.expectEqual(1, env.buffer().send_count());
            // The held candidate must not be stored.
            try testing.expect(!try has_verified(&env, round));
            // After the outgoing view is nullified, the incoming leader proposes on the
            // certified predecessor. Both parent contexts name the boundary block.
            var replacement = held;
            replacement.parent = .{ .new(boundary_height), digest };
            try testing.expect(!std.meta.eql(held.parent, replacement.parent));
            // The replacement must reuse the same payload.
            const proposed = (try wrapper.propose(io, replacement)) orelse return error.NoProposal;
            try testing.expect(proposed.eql(digest));
            // Restaging must not store the replacement before lock-in.
            try testing.expect(!try has_verified(&env, round));
            try testing.expectEqual(
                .ok,
                wrapper.broadcast(digest, .{ .propose = .{ .round = round } }),
            );
            try notarize(&env, view, boundary_height, digest);
            // Certification must await the replacement stage's durability acknowledgement.
            try testing.expectEqual(@as(?bool, true), try wrapper.certify(io, round, digest));
            var stored = (try env.started.mailbox.get_verified(round)) orelse
                return error.ReplacementMissing;
            defer stored.deinit();
            // The replacement is stored at the incoming round.
            try testing.expect(stored.digest().eql(digest));
            // Replacing the parent must not resend the same boundary payload.
            try expect_single_send_to_all(&env, round, digest);
        }
    }.body;
}

fn epocher() types.FixedEpocher {
    return .new(utils.NonZero(u64).init(harness.blocks_per_epoch).?);
}

test "standard boundary restage sends once" {
    try run(boundary_restage(InlineWrapper));
    try run(boundary_restage(DeferredWrapper));
}

const pace_ms = 100;

const PacedActor = common.Actor(
    harness.Provider,
    App,
    common.Unbuffered,
    common.PacedCertificates(Prunable.Certificates),
    common.PacedBlocks(Prunable.Blocks, B),
);

/// An unbuffered actor whose finalized stores take `pace_ms` to sync (commonware's
/// `paced_finalized_stores` with an auto-acknowledging application).
const Paced = struct {
    fixture: harness.Fixture,
    stores: *Prunable,
    mailbox: PacedActor.Mailbox,
    resolver: common.RecordingResolver,
    application: App,
    handle: runtime.context.Handle(anyerror!void),

    fn init(self: *Paced, ctx: Ctx, comptime prefix: []const u8, pending_acks: u32) !void {
        var rng = utils.rng.test_rng();
        self.fixture = try harness.fixture(gpa, &rng);
        errdefer self.fixture.deinit(gpa);
        self.stores = try gpa.create(Prunable);
        errdefer gpa.destroy(self.stores);
        try self.stores.open(ctx, prefix);
        errdefer self.stores.deinit();
        const certificates, const blocks = self.stores.paced(ctx, pace_ms);
        const provider: harness.Provider = .init(&self.fixture.schemes[0]);
        const page_cache = &self.stores.cache_ref;
        const config =
            try common.test_config(PacedActor, gpa, prefix, provider, pending_acks, page_cache);
        const initialized =
            try PacedActor.init(ctx.child("actor"), certificates, blocks, config);
        self.mailbox = initialized.mailbox;
        var holding =
            try common.RecordingResolver.holding(gpa, ctx.io(), &ctx.scope.child("resolver"));
        self.resolver = holding.resolver;
        self.application = try App.init(gpa, ctx.io());
        self.handle = try initialized.actor.start(
            self.application.clone(),
            .{ .gpa = gpa },
            holding.receiver,
            holding.resolver.clone(),
        );
    }

    fn deinit(self: *Paced) void {
        const ended = self.handle.abort() catch {};
        ended catch {};
        self.mailbox.deinit();
        self.application.deinit();
        self.resolver.deinit();
        self.stores.deinit();
        gpa.destroy(self.stores);
        self.fixture.deinit(gpa);
    }

    /// Reports the finalization of `digest` at `view` over `parent_view`.
    fn finalize(self: *Paced, view: u64, parent_view: u64, digest: common.D) !void {
        const proposal = harness.Proposal.init(round_at(view), .new(parent_view), digest);
        var finalization = try harness.make_finalization(
            gpa,
            &self.fixture,
            proposal,
            harness.quorum,
        );
        defer finalization.deinit(gpa);
        _ = self.mailbox.report(.{ .finalization = finalization });
    }

    fn holds(self: *const Paced, height: u64) bool {
        return self.application.contains(.new(height));
    }

    /// Waits up to `deadline_ms` for the application to hold the block at `height`.
    fn wait_holds(self: *const Paced, ctx: Ctx, deadline_ms: u64, height: u64) !void {
        const start = ctx.current();
        while (!self.holds(height)) {
            if (ms_since(ctx, start) > deadline_ms) return error.WaitTimedOut;
            try ctx.sleep(.fromMilliseconds(1));
        }
    }
};

fn ms_since(ctx: Ctx, start: anytype) u64 {
    const elapsed = start.durationTo(ctx.current()).toNanoseconds();
    return @intCast(@divFloor(elapsed, std.time.ns_per_ms));
}

/// A slow finalized-archive sync must not block the marshal mailbox: a `get_verified` (a
/// prunable-cache read) issued while the sync is in flight is answered at once, and the
/// finalized block reaches the application only after the paced sync (the durability
/// barrier).
fn sync_not_blocking_body(ctx: Ctx) anyerror!void {
    var env: Paced = undefined;
    try env.init(ctx, "paced-finalized-sync", 1);
    defer env.deinit();
    // Genesis flows through dispatch first, so the ack pipeline is idle.
    try env.wait_holds(ctx, 1000, 0);
    // Store a verified block for round 1 in the (unpaced) prunable cache.
    const round = round_at(1);
    const block = try harness.make_raw_block(gpa, try genesis_digest(), .new(1), 100);
    try testing.expect(try env.mailbox.verified(round, try ready(block)));
    // The finalization buffers the block into the finalized archives and starts the sync.
    const finalized_at = ctx.current();
    try env.finalize(1, 0, block.digest());
    // A get_verified 1ms later must not queue behind the sync.
    try ctx.sleep(.fromMilliseconds(1));
    const requested_at = ctx.current();
    var verified = (try env.mailbox.get_verified(round)) orelse return error.VerifiedMissing;
    defer verified.deinit();
    try testing.expect(verified.digest().eql(block.digest()));
    try testing.expect(ms_since(ctx, requested_at) < 5);
    // Durability barrier: no dispatch until the paced sync completes.
    try testing.expect(!env.holds(1));
    try ctx.sleep(.fromMilliseconds(90));
    try testing.expect(!env.holds(1));
    try env.wait_holds(ctx, 50, 1);
    try testing.expect(ms_since(ctx, finalized_at) >= pace_ms);
}

test "standard finalization sync does not block mailbox" {
    try run(sync_not_blocking_body);
}

fn certify_call(
    mailbox: Started.A.Mailbox,
    round: Round,
    block: common.Block,
    returned: *bool,
) !bool {
    defer returned.* = true;
    return mailbox.certified(round, block);
}

/// Releases every parked sync until `stop` is set (startup waits on started syncs).
fn release_until(ctx: Ctx, pending: *runtime.storage.mocks.DelayedSync, stop: *const bool) void {
    while (!stop.*) {
        pending.release_all();
        ctx.sleep(.fromMilliseconds(1)) catch return;
    }
}

/// Cache syncs are pooled off the actor loop (commonware hands acks a sync handle and
/// pools the notarization's). With the notarization's and the certified block's syncs held,
/// the mailbox still answers and `certified` waits; on release it returns true, and on
/// failure the actor ends with the error (commonware panics, as in
/// `test_mailbox_certified_sync_failure_panics`).
fn certify_sync_body(ctx: Ctx, comptime fail: bool) anyerror!void {
    var pending: runtime.storage.mocks.DelayedSync = .init(gpa, ctx.io());
    defer pending.deinit();
    var delayed: runtime.storage.mocks.DelayedSynced = .init(gpa, ctx.storage, &pending);
    var actor_ctx = ctx;
    actor_ctx.storage = delayed.storage();
    const io = ctx.io();
    var stop = false;
    var releaser = try io.concurrent(release_until, .{ ctx, &pending, &stop });
    defer if (!stop) releaser.cancel(io);
    var env: Env = undefined;
    try env.init(actor_ctx, "certify-sync");
    var ended = false;
    defer if (!ended) {
        pending.unblock();
        env.deinit();
    };
    const round = round_at(1);
    // Quiesce startup: after a mailbox round trip nothing is parked.
    _ = try env.started.mailbox.get_verified(round);
    stop = true;
    releaser.cancel(io);
    pending.release_all();
    try testing.expectEqual(0, pending.parked());
    const block = try block_one(100);
    try notarize(&env, 1, 0, block.digest());
    // The notarization's sync parks; then the certified block's.
    while (pending.parked() == 0) try ctx.sleep(.fromMilliseconds(1));
    const notarization_held = pending.parked();
    var returned = false;
    const args = .{ env.started.mailbox, round, try ready(block), &returned };
    var call = try io.concurrent(certify_call, args);
    defer _ = call.cancel(io) catch {};
    while (pending.parked() == notarization_held) try ctx.sleep(.fromMilliseconds(1));
    // The held syncs do not block the mailbox, and the barrier is not acknowledged.
    try testing.expect(try env.started.mailbox.get_verified(round_at(2)) == null);
    const held = pending.parked();
    try ctx.sleep(.fromMilliseconds(50));
    try testing.expectEqual(held, pending.parked());
    try testing.expect(!returned);
    if (fail) {
        // The dropped acknowledgement reports not durable, and the actor ends with the error.
        pending.fail_all();
        try testing.expect(!try call.await(io));
        ended = true;
        defer env.fixture.deinit(gpa);
        try testing.expectError(error.Io, env.started.join());
        return;
    }
    pending.release_all();
    try testing.expect(try call.await(io));
}

test "standard certify barrier sync is pooled off the actor loop" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            return certify_sync_body(ctx, false);
        }
    }.body);
}

test "standard failed certify barrier sync stops the actor" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            return certify_sync_body(ctx, true);
        }
    }.body);
}

fn processed_is_one(ctx: Ctx) bool {
    const text = ctx.encode(gpa) catch return false;
    defer gpa.free(text);
    return parse_processed_height(text) == 1;
}

/// Enqueues the delivery of `value` for `key` to `subscriber`, returning its response.
fn enqueue(
    resolver: common.RecordingResolver,
    key: common.Key,
    subscriber: handler.Annotation,
    value: []const u8,
) !utils.channel.oneshot.Receiver(common.Outcome) {
    var sender = resolver.handler_clone();
    defer sender.deinit();
    const subscribers = [_]handler.Annotation{subscriber};
    return sender.deliver(.{ .key = key, .subscribers = &subscribers }, value);
}

/// Enqueues the repair delivery of `block`, finalized by height.
fn enqueue_repair(resolver: common.RecordingResolver, block: B) !oneshot.Receiver(common.Outcome) {
    const bytes = try codec.encode(B, gpa, block);
    defer gpa.free(bytes);
    const subscriber: handler.Annotation = .{ .finalized = .{ .by_height = block.height() } };
    return enqueue(resolver, .{ .block = block.digest() }, subscriber, bytes);
}

fn expect_complete(response: *oneshot.Receiver(common.Outcome)) !void {
    defer response.deinit();
    const outcome = try response.recv();
    try testing.expect(outcome == .resolved and outcome.resolved == .complete);
}

/// The anchor fetch for `digest` among the resolver's fetches, once issued.
fn find_block_fetch(resolver: common.RecordingResolver, digest: common.D) !?common.Fetch {
    const fetches = try resolver.fetches(gpa);
    defer gpa.free(fetches);
    for (fetches) |fetch| {
        if (fetch.key == .block and fetch.key.block.eql(digest)) return fetch;
    }
    return null;
}

/// Finalizes block 1 until processed, then installs a pending floor anchor for a forked
/// block 1 at view 5, returning the fork and its anchor fetch.
fn stale_anchor_setup(ctx: Ctx, env: *Paced, block: B) !struct { B, common.Fetch } {
    try testing.expect(try env.mailbox.verified(round_at(1), try ready(block)));
    try env.finalize(1, 0, block.digest());
    try common.wait_until(ctx, 5000, "block 1 processed", ctx, processed_is_one);
    // A valid certificate at a round above the round floor whose block is unknown locally,
    // so marshal fetches it. Its height (at or below processed) routes the arriving anchor
    // into the stale-anchor branch.
    const fork = try harness.make_raw_block(gpa, try genesis_digest(), .new(1), 999);
    const proposal = harness.Proposal.init(round_at(5), .new(4), fork.digest());
    try env.mailbox.set_floor(
        try harness.make_finalization(gpa, &env.fixture, proposal, harness.quorum),
    );
    const start = ctx.current();
    while (true) {
        if (try find_block_fetch(env.resolver, fork.digest())) |fetch| return .{ fork, fetch };
        if (ms_since(ctx, start) > 5000) return error.AnchorFetchMissing;
        try ctx.sleep(.fromMilliseconds(1));
    }
}

/// A buffered finalized-archive write freezes dispatch even when a stale floor anchor
/// triggers dispatch before the batch's sync starts. The repair blocks arrive in ascending
/// height order, so the batch keeps the lowest written height.
fn stale_anchor_body(ctx: Ctx) anyerror!void {
    var env: Paced = undefined;
    try env.init(ctx, "stale-floor-anchor", 4);
    defer env.deinit();
    const block = try harness.make_raw_block(gpa, try genesis_digest(), .new(1), 100);
    const fork, const anchor_fetch = try stale_anchor_setup(ctx, &env, block);
    // Enqueue every delivery back-to-back so the actor drains them in one resolver batch:
    // two repair blocks at and above the dispatch frontier, then the stale floor anchor.
    const next = try harness.make_raw_block(gpa, block.digest(), .new(2), 200);
    var next_response = try enqueue_repair(env.resolver, next);
    const above = try harness.make_raw_block(gpa, next.digest(), .new(3), 300);
    var above_response = try enqueue_repair(env.resolver, above);
    const fork_bytes = try codec.encode(B, gpa, fork);
    defer gpa.free(fork_bytes);
    var anchor_response =
        try enqueue(env.resolver, anchor_fetch.key, anchor_fetch.subscriber, fork_bytes);
    const delivered_at = ctx.current();
    try expect_complete(&next_response);
    try expect_complete(&above_response);
    try expect_complete(&anchor_response);
    // Durability barrier: the stale-anchor branch dispatches before the batch's sync
    // starts, so the repair block at height 2 stays held until the paced sync completes.
    try ctx.sleep(.fromMilliseconds(1));
    try testing.expect(!env.holds(2));
    try ctx.sleep(.fromMilliseconds(90));
    try testing.expect(!env.holds(2));
    try env.wait_holds(ctx, 50, 3);
    try testing.expect(env.holds(2));
    try testing.expect(ms_since(ctx, delivered_at) >= pace_ms);
}

test "standard stale floor anchor holds dispatch until durable" {
    try run(stale_anchor_body);
}

const stagger_ms = 50;

/// Overlapping pooled syncs release the dispatch gate per batch: block 1 dispatches once
/// its own sync completes, and block 2 waits for the second.
fn overlapping_syncs_body(ctx: Ctx) anyerror!void {
    var env: Paced = undefined;
    try env.init(ctx, "overlapping-finalized-syncs", 4);
    defer env.deinit();
    try env.wait_holds(ctx, 5000, 0);
    // Store both verified blocks, then finalize them one stagger apart so their syncs
    // overlap.
    const first = try harness.make_raw_block(gpa, try genesis_digest(), .new(1), 100);
    try testing.expect(try env.mailbox.verified(round_at(1), try ready(first)));
    const second = try harness.make_raw_block(gpa, first.digest(), .new(2), 200);
    try testing.expect(try env.mailbox.verified(round_at(2), try ready(second)));
    const started_at = ctx.current();
    try env.finalize(1, 0, first.digest());
    try ctx.sleep(.fromMilliseconds(stagger_ms));
    try env.finalize(2, 1, second.digest());
    // Block 1 dispatches as soon as the first sync completes.
    try env.wait_holds(ctx, 150, 1);
    const first_dispatched = ms_since(ctx, started_at);
    try testing.expect(first_dispatched >= pace_ms);
    try testing.expect(first_dispatched < stagger_ms + pace_ms);
    // Block 2 stays held until its own sync completes.
    try testing.expect(!env.holds(2));
    try ctx.sleep(.fromMilliseconds(20));
    try testing.expect(!env.holds(2));
    try env.wait_holds(ctx, 50, 2);
    try testing.expect(ms_since(ctx, started_at) >= stagger_ms + pace_ms);
}

test "standard overlapping finalized syncs release per batch" {
    try run(overlapping_syncs_body);
}

/// Counts block decodes through a zero-byte mock context (commonware `DecodeCounter`).
const DecodeCounter = struct {
    pub const fixed_size = 0;
    pub const max_encode_size = 0;
    /// The number of decodes (commonware's `DECODES`); tests compare before and after.
    var decodes: usize = 0;

    pub fn write(_: DecodeCounter, _: *codec.Writer) void {}

    pub fn encode_size(_: DecodeCounter) usize {
        return 0;
    }

    pub fn read(_: std.mem.Allocator, _: *codec.Reader, _: void) codec.Error!DecodeCounter {
        decodes += 1;
        return .{};
    }
};

const CountedBlock = mocks_block.Block(cryptography.Sha256, DecodeCounter);
const CountedVariant = standard_variant.Standard(CountedBlock);
const CountedApp = @import("../../mocks/application.zig").Application(CountedBlock);
const CountedStores = common.PrunableStores(CountedBlock);
const CountedActor = core.Actor(struct {
    pub const Scheme = harness.S;
    pub const Provider = harness.Provider;
    pub const Epocher = types.FixedEpocher;
    pub const Strategy = parallel.Sequential;
    pub const ApplicationBlock = CountedBlock;
    pub const Block = CountedVariant.Block;
    pub const Commitment = common.D;
    pub const Variant = CountedVariant;
    pub const Acknowledgement = harness.Exact;
    pub const Certificates = CountedStores.Certificates;
    pub const Blocks = CountedStores.Blocks;
    pub const Application = CountedApp;
    pub const Buffer = core_variant.NoBuffer(CountedVariant, harness.K);
    pub const Resolver = common.RecordingResolver;
});

/// The validators' fixture over another namespace, whose certificates fail verification.
fn forged_fixture(rng: anytype) !harness.Fixture {
    const forged = "forged";
    const n = harness.num_validators;
    if (harness.fast_schemes) return simplex.scheme.ed25519.fixture(harness.D, gpa, rng, forged, n);
    return simplex.scheme.bls12381_threshold.vrf.fixture(harness.S, gpa, rng, forged, n);
}

/// commonware `test_config` with a counted genesis.
fn counted_config(
    prefix: []const u8,
    provider: harness.Provider,
    stores: *CountedStores,
) !CountedActor.Config {
    const genesis = try CountedBlock.init(gpa, .{}, cryptography.Sha256.hash(&.{""}), .zero(), 0);
    return .{
        .provider = provider,
        .epocher = epocher(),
        .start = .{ .genesis = try mocks_block.ready(CountedBlock, gpa, genesis) },
        .partition_prefix = prefix,
        .mailbox_size = 100,
        .view_retention = .new(10),
        .prunable_items_per_section = 10,
        .page_cache = &stores.cache_ref,
        .replay_buffer = 1024,
        .key_write_buffer = 1024,
        .value_write_buffer = 1024,
        .block_codec_config = {},
        .max_repair = 10,
        .max_pending_acks = 1,
        .strategy = parallel.sequential,
    };
}

/// Delivers the notarization of `block` from `fixture` as the response for round 1.
fn deliver_notarized(
    resolver: common.RecordingResolver,
    fixture: *const harness.Fixture,
    block: CountedBlock,
) !common.Outcome {
    const round = round_at(1);
    const proposal = harness.Proposal.init(round, .zero(), block.digest());
    var notarization = try harness.make_notarization(gpa, fixture, proposal, harness.quorum);
    defer notarization.deinit(gpa);
    const Value = struct { harness.Notarization, CountedBlock };
    const bytes = try codec.encode(Value, gpa, .{ notarization, block });
    defer gpa.free(bytes);
    var response = try enqueue(
        resolver,
        .{ .notarized = round },
        .{ .notarization = round },
        bytes,
    );
    defer response.deinit();
    return response.recv();
}

/// A notarized delivery's block is decoded only after its certificate verifies.
fn notarized_decode_body(ctx: Ctx) anyerror!void {
    const prefix = "notarized-decode";
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    var forged = try forged_fixture(&rng);
    defer forged.deinit(gpa);
    const stores = try gpa.create(CountedStores);
    defer gpa.destroy(stores);
    try stores.open(ctx, prefix);
    defer stores.deinit();
    const config = try counted_config(prefix, .init(&fixture.schemes[0]), stores);
    const initialized =
        try CountedActor.init(
            ctx.child("actor"),
            stores.certificates(),
            stores.blocks_store(),
            config,
        );
    var mailbox = initialized.mailbox;
    defer mailbox.deinit();
    var holding = try common.RecordingResolver.holding(gpa, ctx.io(), &ctx.scope.child("resolver"));
    defer holding.resolver.deinit();
    var application = try CountedApp.init(gpa, ctx.io());
    defer application.deinit();
    var handle = try initialized.actor.start(
        application.clone(),
        .{ .gpa = gpa },
        holding.receiver,
        holding.resolver.clone(),
    );
    defer {
        const ended = handle.abort() catch {};
        ended catch {};
    }
    const genesis = try CountedBlock.init(gpa, .{}, cryptography.Sha256.hash(&.{""}), .zero(), 0);
    const parent = genesis.digest();
    const block = try CountedBlock.init(gpa, .{}, parent, .new(1), 1);
    _ = try mailbox.get_processed();
    const before = DecodeCounter.decodes;
    // A notarization from another committee fails verification before the block decodes.
    const rejected = try deliver_notarized(holding.resolver, &forged, block);
    try testing.expect(rejected == .invalid);
    try testing.expectEqual(before, DecodeCounter.decodes);
    // A verified notarization decodes the block.
    const accepted = try deliver_notarized(holding.resolver, &fixture, block);
    try testing.expect(accepted == .resolved and accepted.resolved == .complete);
    try testing.expect(DecodeCounter.decodes > before);
}

test "standard notarized delivery decodes after verification" {
    try run(notarized_decode_body);
}
