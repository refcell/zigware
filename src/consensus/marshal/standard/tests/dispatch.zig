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
        var rng = utils.rng.test_rng();
        self.fixture = try harness.fixture(gpa, &rng);
        errdefer self.fixture.deinit(gpa);
        var name: [128]u8 = undefined;
        const me = self.fixture.participants[0];
        const prefix = try std.fmt.bufPrint(&name, label ++ "-{f}", .{me});
        self.started = try common.start_standard_actor(
            harness.Provider,
            App,
            common.RecordingBuffer,
            ctx.child("validator").with_attribute("index", 0),
            prefix,
            .init(&self.fixture.schemes[0]),
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
    const epocher = types.FixedEpocher.new(utils.NonZero(u64).init(harness.blocks_per_epoch).?);
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
        const epoch = epocher.containing(H.height(&block)).?.epoch;
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
