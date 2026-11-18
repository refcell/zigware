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
