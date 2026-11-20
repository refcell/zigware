//! commonware `marshal/coding/mod.rs` tests 4989-6420: the coding `Marshaled` wrapper's
//! propose, prepare, relay, restart, and certify-release paths.

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const cryptography = @import("cryptography");
const types = @import("../../../types.zig");
const shared = @import("../../mocks/harness.zig");
const harness = @import("../harness.zig");
const marshaled = @import("../marshaled.zig");
const common = @import("common.zig");
const soak = @import("../../mocks/soak.zig");

const gpa = testing.allocator;
const Ctx = common.Ctx;
const H = common.H;
const Round = common.Round;
const Mock = common.MockVerifyingApp;
const M = common.MarshaledOf(Mock);
const Validator = common.ValidatorStack.Validator;

/// commonware seeds 0..16 under `-Dslow-tests`; two otherwise, to keep Debug runs fast.
const seeds: []const u64 = if (build_options.slow_tests)
    &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }
else
    &.{ 0, 1 };

/// The validators' fixture, seeded as commonware's `test_rng`.
fn fixture() !common.Fixture {
    var rng = utils.rng.test_rng();
    return H.fixture(gpa, &rng);
}

/// Runs `body` under a 60 s hang guard and `seed` (commonware `Runner::timed(60s)` or a seeded
/// config).
fn run_seeded(seed: u64, comptime body: fn (Ctx) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{
        .seed = seed,
        .timeout_ns = 60 * std.time.ns_per_s,
    };
    try soak.run(gpa, config, body, .{});
}

/// Whether the metrics exposition holds `needle`.
fn exposition_contains(ctx: Ctx, needle: []const u8) !bool {
    const text = try ctx.encode(gpa);
    defer gpa.free(text);
    return std.mem.indexOf(u8, text, needle) != null;
}

/// One validator from `CodingHarness::setup_validator` on its own network that can restart on
/// the same storage. Must not move.
const Env = struct {
    validators: common.Fixture,
    network: shared.TestNetwork,
    validator: *Validator,

    fn init(self: *Env, ctx: Ctx) !void {
        self.validators = try fixture();
        errdefer self.validators.deinit(gpa);
        const participants = self.validators.participants;
        self.network = try .start(gpa, ctx.io(), 1, participants, 1024 * 1024);
        errdefer self.network.stop();
        self.validator = try self.setup(ctx.child("validator"));
    }

    fn setup(self: *Env, child: Ctx) !*Validator {
        const app = try common.App.init(gpa, child.io());
        const node_ctx = child.with_attribute("index", 0);
        return Validator.setup(node_ctx, self.network.network, self.me(), self.provider(), 1, app);
    }

    /// Aborts the marshal actor and restarts it under `ctx.child(name)` on the same storage.
    fn restart(self: *Env, ctx: Ctx, comptime name: []const u8) !void {
        self.validator.crash();
        self.validator = try self.setup(ctx.child(name));
    }

    fn deinit(self: *Env) void {
        self.validator.crash();
        self.network.stop();
        self.validators.deinit(gpa);
        self.* = undefined;
    }

    fn me(self: *const Env) common.K {
        return self.validators.participants[0];
    }

    fn provider(self: *const Env) common.Provider {
        return .init(&self.validators.schemes[0]);
    }

    /// A wrapper over the validator's marshal and shards under `ctx.child(name)`.
    fn wrap(self: *Env, ctx: Ctx, comptime name: []const u8, app: Mock) !M {
        return self.wrap_as(Mock, ctx, name, app);
    }

    /// A wrapper over application `A` (owned), as `wrap`.
    fn wrap_as(
        self: *Env,
        comptime A: type,
        ctx: Ctx,
        comptime name: []const u8,
        app: A,
    ) !common.MarshaledOf(A) {
        const W = common.MarshaledOf(A);
        const marshal = self.validator.mailbox.clone();
        const shard_mailbox = self.validator.extra.clone();
        const config = common.marshaled_config(W, app, marshal, shard_mailbox, self.provider());
        return .init(ctx.child(name), config);
    }
};

/// A recording actor and a shards engine on their own network, as commonware's
/// `start_coding_actor_with_recording` plus `start_shard_mailbox`. Must not move.
const Recorded = struct {
    validators: common.Fixture,
    buffer: common.RecordingCodingBuffer,
    actor: common.ActorStack,
    shards: common.ShardStack,

    fn init(self: *Recorded, ctx: Ctx, prefix: []const u8) !void {
        self.validators = try fixture();
        errdefer self.validators.deinit(gpa);
        self.buffer = try .init(gpa, ctx.io());
        errdefer self.buffer.deinit();
        const signer = self.provider();
        const actor_ctx = ctx.child("validator");
        self.actor =
            try common.start_coding_actor_with_recording(actor_ctx, prefix, signer, self.buffer);
        errdefer self.actor.stop();
        const participants = self.validators.participants;
        try common.start_shard_mailbox(&self.shards, ctx.child("shards"), participants, signer);
    }

    fn deinit(self: *Recorded) void {
        self.shards.stop();
        self.actor.stop();
        self.buffer.deinit();
        self.validators.deinit(gpa);
        self.* = undefined;
    }

    fn provider(self: *const Recorded) common.Provider {
        return .init(&self.validators.schemes[0]);
    }

    fn wrap(self: *Recorded, ctx: Ctx, comptime name: []const u8, app: Mock) !M {
        const marshal = self.actor.mailbox.clone();
        const shard_mailbox = self.shards.shards();
        const config = common.marshaled_config(M, app, marshal, shard_mailbox, self.provider());
        return .init(ctx.child(name), config);
    }
};

/// The context of a height-1 proposal by `leader` at view 1 over genesis.
fn first_context(leader: common.K) !common.CodingCtx {
    const genesis = try common.genesis_block(gpa);
    return .{
        .round = common.round_at(0, 1),
        .leader = leader,
        .parent = .{ .zero(), try common.genesis_coding_commitment(gpa, &genesis) },
    };
}

/// The height-1 application block `context` names over genesis.
fn first_block(context: common.CodingCtx, timestamp: u64) !common.CodingB {
    const genesis = try common.genesis_block(gpa);
    return harness.make_coding_block(gpa, context, genesis.digest(), .new(1), timestamp);
}

test "coding default prepare declines" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var recorded: Recorded = undefined;
            try recorded.init(ctx, "default-prepare");
            defer recorded.deinit();
            var wrapper = try recorded.wrap(ctx, "declining", Mock.init(gpa));
            defer wrapper.deinit();
            const context = try first_context(recorded.validators.participants[0]);
            const decision = (try wrapper.prepare(ctx.io(), context)) orelse
                return error.PrepareDecisionMissing;
            // The default prepare declines.
            try testing.expect(decision == .wait);
            // A declining prepare still fetches the parent.
            const fetched = "declining_parent_fetch_duration_count 1";
            try testing.expect(try exposition_contains(ctx, fetched));
        }
    }.body);
}

/// A provider that holds no epochs (commonware `EmptyProvider`).
const EmptyProvider = struct {
    pub fn scoped(_: EmptyProvider, _: anytype) ?cryptography.certificate.Scoped(common.S) {
        return null;
    }

    pub fn scheme(_: EmptyProvider, _: anytype) ?*const common.S {
        return null;
    }
};

const Unprovided = marshaled.Marshaled(struct {
    pub const Context = Ctx;
    pub const Application = Mock;
    pub const Block = common.CodingB;
    pub const Coding = harness.RS;
    pub const Hasher = common.Sha256;
    pub const Provider = EmptyProvider;
    pub const Strategy = parallel.Sequential;
    pub const Epocher = types.FixedEpocher;
});

test "marshaled missing scheme skips propose and verify" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env = undefined;
            try env.init(ctx);
            defer env.deinit();
            var wrapper = try Unprovided.init(ctx.child("marshaled"), .{
                .application = Mock.init(gpa),
                .marshal = env.validator.mailbox.clone(),
                .shards = env.validator.extra.clone(),
                .scheme_provider = .{},
                .strategy = parallel.sequential,
                .epocher = .new(utils.NonZero(u64).init(shared.blocks_per_epoch).?),
            });
            defer wrapper.deinit();
            const context: common.CodingCtx = .{
                .round = common.round_at(0, 1),
                .leader = env.me(),
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            // Propose with a missing scheme drops its sender.
            try testing.expectEqual(null, try wrapper.propose(ctx.io(), context));
            // Verify with a missing scheme drops its sender.
            const payload = harness.genesis_commitment();
            try testing.expectEqual(null, try wrapper.verify(ctx.io(), context, payload));
        }
    }.body);
}

/// commonware `certify_persists_block_before_resolving_at`: once `certify` resolves true, the
/// block survives aborting the marshal actor at once and restarting it.
fn certify_persists_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx);
    defer env.deinit();
    const shards = &env.validator.extra;
    const genesis = try common.genesis_block(gpa);
    // A reconstructable parent (height 1) and child (height 2) in the shards engine, neither
    // durably persisted.
    const parent_round = common.round_at(0, 1);
    const parent_context: common.CodingCtx = .{
        .round = parent_round,
        .leader = shared.default_leader(),
        .parent = .{ .zero(), harness.genesis_commitment() },
    };
    const parent = try common.coded(gpa, parent_context, genesis.digest(), 1, 100);
    const parent_commitment = parent.commitment();
    const parent_digest = parent.digest();
    try shards.disperse(parent_round, parent);
    const child_round = common.round_at(0, 2);
    const child_context: common.CodingCtx = .{
        .round = child_round,
        .leader = env.me(),
        .parent = .{ .new(1), parent_commitment },
    };
    const child = try common.coded(gpa, child_context, parent_digest, 2, 200);
    const child_commitment = child.commitment();
    const child_digest = child.digest();
    try shards.disperse(child_round, child);
    try ctx.sleep(.fromMilliseconds(10));

    var wrapper = try env.wrap(ctx, "marshaled", Mock.init(gpa));
    // Optimistic verify returns shard validity.
    const validity = try wrapper.verify(ctx.io(), child_context, child_commitment);
    try testing.expectEqual(true, validity);
    // Certify is the safety gate before finalize voting.
    try testing.expectEqual(true, try wrapper.certify(ctx.io(), child_round, child_commitment));
    wrapper.deinit();
    // Aborting marshal right after certify must find the block already persisted.
    try env.restart(ctx, "validator_restart");
    var restored = (try env.validator.mailbox.get_block(.{ .digest = child_digest })) orelse
        return error.CertifiedBlockLost;
    restored.deinit(gpa);
}

test "marshaled certify persists block before resolving" {
    for (seeds) |seed| try run_seeded(seed, certify_persists_body);
}

/// Stages the leader's own height-1 block through `propose`, returning the wrapper and the
/// block's digest and commitment.
fn propose_own(ctx: Ctx, env: *Env) !struct { M, common.D, common.Commitment } {
    const context = try first_context(env.me());
    const block = try first_block(context, 100);
    const config = common.committee_config();
    var expected = try common.encode_block(gpa, try first_block(context, 100), config);
    defer expected.deinit(gpa);
    const digest = expected.digest();
    var wrapper = try env.wrap(ctx, "marshaled", Mock.init(gpa).with_propose_result(block));
    errdefer wrapper.deinit();
    // Propose stages the block and returns its commitment.
    const commitment = (try wrapper.propose(ctx.io(), context)) orelse return error.NoProposal;
    try testing.expect(commitment.eql(expected.commitment()));
    return .{ wrapper, digest, commitment };
}

test "marshaled proposed block persists across restart" {
    try run_seeded(0, struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env = undefined;
            try env.init(ctx);
            defer env.deinit();
            var wrapper, const digest, const commitment = try propose_own(ctx, &env);
            // The leader certifies its own proposal, which awaits the deferred propose sync.
            const round = common.round_at(0, 1);
            try testing.expectEqual(true, try wrapper.certify(ctx.io(), round, commitment));
            wrapper.deinit();
            // Without a relay broadcast, the leader recovers its own block after a restart.
            try env.restart(ctx, "validator_restart");
            var restored = (try env.validator.mailbox.get_block(.{ .digest = digest })) orelse
                return error.ProposedBlockLost;
            restored.deinit(gpa);
        }
    }.body);
}

test "marshaled propose relay sends staged block" {
    try run_seeded(0, struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env = undefined;
            try env.init(ctx);
            defer env.deinit();
            var wrapper, const digest, const commitment = try propose_own(ctx, &env);
            defer wrapper.deinit();
            const round = common.round_at(0, 1);
            // The relay broadcasts the staged proposal's shards, seeding the shard cache.
            var subscription = try env.validator.extra.subscribe(commitment);
            defer subscription.deinit();
            _ = wrapper.broadcast(commitment, .{ .propose = .{ .round = round } });
            var cached = try subscription.recv();
            defer cached.deinit(gpa);
            try testing.expect(cached.digest().eql(digest));
            // The relayed proposal is persisted through the staged ack, so certification
            // resolves durably.
            try testing.expectEqual(true, try wrapper.certify(ctx.io(), round, commitment));
        }
    }.body);
}

const Plan = M.Plan;
const Handoff = @import("../../../traits.zig").Handoff(common.Commitment);

/// The commitment of `block` coded for the committee.
fn commitment_of(block: common.CodingB) !common.Commitment {
    var coded = try common.encode_block(gpa, block, common.committee_config());
    defer coded.deinit(gpa);
    return coded.commitment();
}

/// The commitment of the block verified at `round`, or null.
fn verified_commitment(marshal: common.Marshal, round: Round) !?common.Commitment {
    var block = (try marshal.get_verified(round)) orelse return null;
    defer block.deinit(gpa);
    return block.commitment();
}

/// Waits (simulated time) until `done(arg)` holds; the runner timeout is the hang guard.
fn wait_until(ctx: Ctx, comptime done: anytype, arg: anytype) !void {
    while (!done(arg)) try ctx.sleep(.fromMilliseconds(1));
}

fn sent_twice(buffer: common.RecordingCodingBuffer) bool {
    return buffer.send_count() >= 2;
}

test "coding prepare relay sends once and propose stores" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var recorded: Recorded = undefined;
            try recorded.init(ctx, "prepare-relay");
            defer recorded.deinit();
            const marshal = recorded.actor.mailbox;
            const context = try first_context(recorded.validators.participants[0]);
            const round = context.round;
            // Two candidates for the round, each staged by its own wrapper's propose.
            const abandoned_block = try first_block(context, 100);
            const replacement_block = try first_block(context, 200);
            const abandoned_commitment = try commitment_of(abandoned_block);
            const replacement_commitment = try commitment_of(replacement_block);
            const abandoned_app = Mock.init(gpa).with_propose_result(abandoned_block);
            var abandoned = try recorded.wrap(ctx, "abandoned", abandoned_app);
            defer abandoned.deinit();
            const replacement_app = Mock.init(gpa).with_propose_result(replacement_block);
            var replacement = try recorded.wrap(ctx, "replacement", replacement_app);
            defer replacement.deinit();
            const staged_a = (try abandoned.propose(ctx.io(), context)) orelse
                return error.NoProposal;
            try testing.expect(staged_a.eql(abandoned_commitment));
            const staged_b = (try replacement.propose(ctx.io(), context)) orelse
                return error.NoProposal;
            try testing.expect(staged_b.eql(replacement_commitment));
            // The early relay sends each held candidate and stores neither.
            const prepare: Plan = .{ .prepare = .{ .round = round } };
            try testing.expect(abandoned.broadcast(abandoned_commitment, prepare) == .ok);
            try testing.expect(replacement.broadcast(replacement_commitment, prepare) == .ok);
            try wait_until(ctx, sent_twice, recorded.buffer);
            try testing.expectEqual(null, try verified_commitment(marshal, round));
            // The lock-in stores the replacement without sending it again, and certification
            // resolves through the staged durability handshake.
            const propose: Plan = .{ .propose = .{ .round = round } };
            try testing.expect(replacement.broadcast(replacement_commitment, propose) == .ok);
            const certified = try replacement.certify(ctx.io(), round, replacement_commitment);
            try testing.expectEqual(true, certified);
            const stored = (try verified_commitment(marshal, round)) orelse
                return error.ReplacementNotStored;
            try testing.expect(stored.eql(replacement_commitment));
            // An abandoned candidate is never stored.
            const abandoned_digest = abandoned_block.digest();
            try testing.expect(try marshal.get_block(.{ .digest = abandoned_digest }) == null);
            // Each candidate is sent once, to everyone.
            try testing.expectEqual(2, recorded.buffer.send_count());
            for ([_]common.Commitment{ abandoned_commitment, replacement_commitment }, 0..) |c, i| {
                const sent_round, const sent_commitment = recorded.buffer.sent(i);
                try testing.expect(std.meta.eql(sent_round, round));
                try testing.expect(sent_commitment.eql(c));
                try testing.expect(recorded.buffer.sent_to_all(i));
            }
        }
    }.body);
}

test "coding propose relay after claim sends once" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var recorded: Recorded = undefined;
            try recorded.init(ctx, "propose-relay-claim");
            defer recorded.deinit();
            const marshal = recorded.actor.mailbox;
            const context = try first_context(recorded.validators.participants[0]);
            const round = context.round;
            const block = try first_block(context, 100);
            const expected = try commitment_of(block);
            const app = Mock.init(gpa).with_propose_result(block);
            var wrapper = try recorded.wrap(ctx, "marshaled", app);
            defer wrapper.deinit();
            const commitment = (try wrapper.propose(ctx.io(), context)) orelse
                return error.NoProposal;
            try testing.expect(commitment.eql(expected));
            // The early relay sends the candidate's shards. Each lookup goes through the
            // same marshal mailbox as the relays, so it observes every send they requested.
            const prepare: Plan = .{ .prepare = .{ .round = round } };
            try testing.expect(wrapper.broadcast(commitment, prepare) == .ok);
            try testing.expectEqual(null, try verified_commitment(marshal, round));
            try testing.expectEqual(1, recorded.buffer.send_count());
            // Certification claims the candidate and persists it.
            try testing.expectEqual(true, try wrapper.certify(ctx.io(), round, commitment));
            // The lock-in finds nothing staged and must not send the candidate again.
            const propose: Plan = .{ .propose = .{ .round = round } };
            try testing.expect(wrapper.broadcast(commitment, propose) == .ok);
            const stored = (try verified_commitment(marshal, round)) orelse
                return error.CandidateNotStored;
            try testing.expect(stored.eql(commitment));
            try testing.expectEqual(1, recorded.buffer.send_count());
        }
    }.body);
}

fn subscribed(buffer: common.RecordingCodingBuffer) bool {
    return buffer.commitment_subscription_count() > 0;
}

fn fetched_any(resolver: common.RecordingResolver) bool {
    return resolver.fetch_count() > 0;
}

test "coding prepare waits for parent without fetching" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var recorded: Recorded = undefined;
            try recorded.init(ctx, "prepare-parent-wait");
            defer recorded.deinit();
            const participants = recorded.validators.participants;
            const resolver = recorded.actor.resolver;
            var parent = try common.missing_candidate(gpa, participants[1]);
            const parent_round = parent.context.round;
            const context: common.CodingCtx = .{
                .round = common.round_at(0, parent_round.view.get() + 1),
                .leader = participants[0],
                .parent = .{ parent_round.view, parent.block.commitment() },
            };
            const parent_digest = parent.block.digest();
            const child = try harness.make_coding_block(gpa, context, parent_digest, .new(2), 7);
            const child_commitment = try commitment_of(child);
            const app = Mock.init(gpa).with_handoff(.{ .stage = {} }).with_propose_result(child);
            var wrapper = try recorded.wrap(ctx, "marshaled", app);
            defer wrapper.deinit();
            // The actor issues any peer fetch before it registers the local wait, so a
            // registered wait shows the prepare's parent lookup was handled.
            var decision = try wrapper.start_prepare(context);
            defer decision.deinit();
            try wait_until(ctx, subscribed, recorded.buffer);
            // Prepare must not fetch its parent.
            try testing.expectEqual(0, resolver.fetch_count());
            // An ordinary propose on the same parent fetches it by round.
            var proposal = try wrapper.start_propose(context);
            defer proposal.deinit();
            try wait_until(ctx, fetched_any, resolver);
            // Local delivery of the parent completes both requests without another fetch.
            try testing.expect(try recorded.actor.mailbox.verified(parent_round, parent.block));
            const handoff = try decision.recv();
            try testing.expect(std.meta.eql(handoff, Handoff{ .stage = child_commitment }));
            try testing.expect((try proposal.recv()).eql(child_commitment));
            // Only the propose may fetch the parent, by round.
            try testing.expectEqual(1, resolver.fetch_count());
            const by_round: common.ResolverKey = .{ .notarized = parent_round };
            try testing.expect(resolver.fetched(by_round, .{ .notarization = parent_round }));
        }
    }.body);
}

/// A handoff on a parent at `height` stored for view `view` answers stage when `built`, and
/// wait otherwise (the parent can never certify in the request's epoch).
fn prepare_on_parent(
    ctx: Ctx,
    env: *Env,
    comptime name: []const u8,
    view: u64,
    height: u64,
    built: bool,
) !void {
    const genesis = try common.genesis_block(gpa);
    const parent_round = common.round_at(0, view);
    const parent_context: common.CodingCtx = .{
        .round = parent_round,
        .leader = env.validators.participants[1],
        .parent = .{ .zero(), try common.genesis_coding_commitment(gpa, &genesis) },
    };
    const parent = try common.coded(gpa, parent_context, genesis.digest(), height, view);
    const parent_digest = parent.digest();
    const parent_commitment = parent.commitment();
    try testing.expect(try env.validator.mailbox.verified(parent_round, parent));
    const context: common.CodingCtx = .{
        .round = common.round_at(0, view + 1),
        .leader = env.me(),
        .parent = .{ .new(view), parent_commitment },
    };
    const child = try harness.make_coding_block(gpa, context, parent_digest, .new(2), 7);
    const expected: Handoff = if (built) .{ .stage = try commitment_of(child) } else .wait;
    const app = Mock.init(gpa).with_handoff(.{ .stage = {} }).with_propose_result(child);
    var wrapper = try env.wrap(ctx, name, app);
    defer wrapper.deinit();
    const decision = (try wrapper.prepare(ctx.io(), context)) orelse
        return error.PrepareDecisionMissing;
    if (!std.meta.eql(decision, expected)) {
        std.log.err("parent height {d}: unexpected handoff", .{height});
        return error.UnexpectedHandoff;
    }
}

test "coding prepare skips parent outside epoch" {
    try run_seeded(0, struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env = undefined;
            try env.init(ctx);
            defer env.deinit();
            const epoch_length = shared.blocks_per_epoch;
            try prepare_on_parent(ctx, &env, "max", 1, std.math.maxInt(u64), false);
            try prepare_on_parent(ctx, &env, "later", 3, 3 * epoch_length, false);
            try prepare_on_parent(ctx, &env, "inside", 5, 1, true);
        }
    }.body);
}

test "coding prepare builds on epoch genesis" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env = undefined;
            try env.init(ctx);
            defer env.deinit();
            const genesis = try common.genesis_block(gpa);
            const epoch_length = utils.NonZero(u64).init(shared.blocks_per_epoch).?;
            const epocher = types.FixedEpocher.new(epoch_length);
            // The last block of epoch 0 is the genesis of epoch 1.
            const boundary_height = epocher.last(.zero()).?;
            const boundary_round = common.round_at(0, shared.blocks_per_epoch);
            const boundary_context: common.CodingCtx = .{
                .round = boundary_round,
                .leader = env.validators.participants[1],
                .parent = .{ .zero(), try common.genesis_coding_commitment(gpa, &genesis) },
            };
            const boundary =
                try common.coded(gpa, boundary_context, genesis.digest(), boundary_height.get(), 1);
            const boundary_digest = boundary.digest();
            const boundary_commitment = boundary.commitment();
            try testing.expect(try env.validator.mailbox.verified(boundary_round, boundary));
            // The first proposal of epoch 1 names the boundary block at view zero.
            const context: common.CodingCtx = .{
                .round = common.round_at(1, 1),
                .leader = env.me(),
                .parent = .{ .zero(), boundary_commitment },
            };
            const child_height = boundary_height.next();
            const child =
                try harness.make_coding_block(gpa, context, boundary_digest, child_height, 2);
            const child_commitment = try commitment_of(child);
            const app = Mock.init(gpa).with_handoff(.{ .stage = {} }).with_propose_result(child);
            var wrapper = try env.wrap(ctx, "marshaled", app);
            defer wrapper.deinit();
            const decision = (try wrapper.prepare(ctx.io(), context)) orelse
                return error.PrepareDecisionMissing;
            try testing.expect(std.meta.eql(decision, Handoff{ .stage = child_commitment }));
        }
    }.body);
}

/// Persists the stale block a pre-crash relay broadcast stored for `round` by `me`, built on
/// a parent replay has since replaced; returns its digest and commitment.
fn persist_stale(ctx: Ctx, env: *Env, round: Round) !struct { common.D, common.Commitment } {
    const genesis = try common.genesis_block(gpa);
    const replaced: common.Commitment = .init(
        common.Sha256.hash(&.{"replaced-parent-block"}),
        common.Sha256.hash(&.{"replaced-parent-inner"}),
        common.Sha256.hash(&.{"replaced-parent-ctx"}),
        common.committee_config(),
    );
    const context: common.CodingCtx = .{
        .round = round,
        .leader = env.me(),
        .parent = .{ .new(1), replaced },
    };
    const stale = try common.coded(gpa, context, genesis.digest(), 1, 100);
    const result = .{ stale.digest(), stale.commitment() };
    var persisted = try utils.channel.oneshot.channel(void, gpa, ctx.io());
    defer persisted.receiver.deinit();
    _ = try env.validator.mailbox.proposed(round, stale, .all, persisted.sender);
    try persisted.receiver.recv();
    return result;
}

fn expect_stored(env: *Env, digest: common.D) !void {
    var block = (try env.validator.mailbox.get_block(.{ .digest = digest })) orelse
        return error.BlockLost;
    block.deinit(gpa);
}

test "prepare rebuilds despite verified block on restart" {
    try run_seeded(0, struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env = undefined;
            try env.init(ctx);
            defer env.deinit();
            const round = common.round_at(0, 2);
            const stale_digest, const stale_commitment = try persist_stale(ctx, &env, round);
            try env.restart(ctx, "restarted");
            // The restarted marshal restores the stale block.
            const marshal = env.validator.mailbox;
            const restored = (try verified_commitment(marshal, round)) orelse
                return error.StaleBlockLost;
            try testing.expect(restored.eql(stale_commitment));
            var context = try first_context(env.me());
            context.round = round;
            const fresh = try first_block(context, 200);
            const fresh_digest = fresh.digest();
            const fresh_commitment = try commitment_of(fresh);
            const app = Mock.init(gpa).with_handoff(.{ .vote = {} }).with_propose_result(fresh);
            var wrapper = try env.wrap(ctx, "marshaled", app);
            // A restarted leader builds a fresh block under the application's decision.
            const decision = (try wrapper.prepare(ctx.io(), context)) orelse
                return error.PrepareDecisionMissing;
            try testing.expect(std.meta.eql(decision, Handoff{ .vote = fresh_commitment }));
            _ = wrapper.broadcast(fresh_commitment, .{ .propose = .{ .round = round } });
            // The fresh block certifies through the relay handshake.
            try testing.expectEqual(true, try wrapper.certify(ctx.io(), round, fresh_commitment));
            // The stale block stays stored first at the round.
            const first = (try verified_commitment(marshal, round)) orelse
                return error.StaleBlockLost;
            try testing.expect(first.eql(stale_commitment));
            try ctx.sleep(.fromMilliseconds(100));
            wrapper.deinit();
            try env.restart(ctx, "recovered");
            // Both blocks are recoverable from storage.
            try expect_stored(&env, stale_digest);
            try expect_stored(&env, fresh_digest);
            var certifier = try env.wrap(ctx, "certifier", Mock.init(gpa));
            defer certifier.deinit();
            // The fresh block certifies from storage after a restart.
            const recertified = try certifier.certify(ctx.io(), round, fresh_commitment);
            try testing.expectEqual(true, recertified);
            try ctx.sleep(.fromMilliseconds(100));
        }
    }.body);
}

const verifying = @import("../../mocks/verifying.zig");
const GatedApp =
    verifying.GatedVerifyingApp(common.CodingB, Ctx, common.CodingCtx, common.Ancestry);
const RecordingApp =
    verifying.RecordingVerifyingApp(common.CodingB, Ctx, common.CodingCtx, common.Ancestry);

/// The epoch-0 boundary block over `parent` at height `blocks_per_epoch - 1`, by the default
/// leader at its own view.
fn boundary_block(parent_commitment: common.Commitment, parent: common.D) !common.Block {
    const height = shared.blocks_per_epoch - 1;
    const context: common.CodingCtx = .{
        .round = common.round_at(0, height),
        .leader = shared.default_leader(),
        .parent = .{ .zero(), parent_commitment },
    };
    return common.coded(gpa, context, parent, height, 1900);
}

test "propose reuses reproposed boundary block on restart" {
    try run_seeded(0, struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env = undefined;
            try env.init(ctx);
            defer env.deinit();
            const genesis = try common.genesis_block(gpa);
            const genesis_commitment = try common.genesis_coding_commitment(gpa, &genesis);
            // The pre-crash relay broadcast of the re-proposal stored the boundary block at
            // the re-proposal round.
            const boundary = try boundary_block(genesis_commitment, genesis.digest());
            const boundary_commitment = boundary.commitment();
            const boundary_view = shared.blocks_per_epoch - 1;
            const round = common.round_at(0, boundary_view + 1);
            try testing.expect(try env.validator.mailbox.verified(round, boundary));
            const context: common.CodingCtx = .{
                .round = round,
                .leader = env.me(),
                .parent = .{ .new(boundary_view), boundary_commitment },
            };
            // The application cannot build and its verification never completes, so the
            // checks below hold only if the stored parent is re-proposed as-is.
            var gate = try verifying.Gated.init(gpa, ctx.io());
            defer gate.state.deinit();
            defer gate.started.deinit();
            defer gate.release.deinit();
            const app: GatedApp = .{ .state = &gate.state };
            var wrapper = try env.wrap_as(GatedApp, ctx, "marshaled", app);
            defer wrapper.deinit();
            const commitment = (try wrapper.propose(ctx.io(), context)) orelse
                return error.NoProposal;
            try testing.expect(commitment.eql(boundary_commitment));
            _ = wrapper.broadcast(commitment, .{ .propose = .{ .round = round } });
            // The re-proposal certifies through the relay handshake, without app verification.
            try testing.expectEqual(true, try wrapper.certify(ctx.io(), round, commitment));
            try testing.expectError(error.Empty, gate.started.try_recv());
        }
    }.body);
}

/// The log of `RecordingApp`; it outlives the runtime, since verifications pending at
/// shutdown record their cancellation.
var observed: verifying.Observed(common.D) = undefined;

fn expect_observed(expected: []const verifying.Verification(common.D)) !void {
    try testing.expectEqual(expected.len, observed.items.items.len);
    for (expected, observed.items.items) |want, seen| {
        try testing.expect(std.meta.eql(want, seen));
    }
}

fn releases_verification_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx);
    defer env.deinit();
    const marshal = env.validator.mailbox;
    const participants = env.validators.participants;
    // The parent at view 1 is available locally.
    const parent_context = try first_context(shared.default_leader());
    const config = common.committee_config();
    const parent = try common.encode_block(gpa, try first_block(parent_context, 100), config);
    const parent_digest = parent.digest();
    const parent_commitment = parent.commitment();
    try testing.expect(try marshal.verified(parent_context.round, parent));
    // Participant 1 equivocates at view 2: children A and B share one context.
    const round = common.round_at(0, 2);
    const context: common.CodingCtx = .{
        .round = round,
        .leader = participants[1],
        .parent = .{ .new(1), parent_commitment },
    };
    const a = try common.coded(gpa, context, parent_digest, 2, 200);
    const b = try common.coded(gpa, context, parent_digest, 2, 201);
    const a_commitment = a.commitment();
    const b_commitment = b.commitment();
    const b_digest = b.digest();
    try testing.expect(!a_commitment.eql(b_commitment));
    const app: RecordingApp = .{ .observed = &observed };
    var wrapper = try env.wrap_as(RecordingApp, ctx, "marshaled", app);
    defer wrapper.deinit();
    // The leader withholds A's shards. Consensus asks to verify it.
    var verify_a = try wrapper.start_verify(context, a_commitment);
    defer verify_a.deinit();
    try ctx.sleep(.fromMilliseconds(10));
    try expect_observed(&.{});
    // B is reconstructed and notarized, so consensus asks to certify it.
    try testing.expect(try marshal.verified(round, b));
    var certify_b = try wrapper.start_certify(round, b_commitment);
    defer certify_b.deinit();
    try ctx.sleep(.fromMilliseconds(50));
    try expect_observed(&.{.{ .started = b_digest }});
    // A is reconstructed: the application must not verify a block that conflicts with the
    // certified one.
    try testing.expect(try marshal.verified(round, a));
    try ctx.sleep(.fromMilliseconds(100));
    try expect_observed(&.{.{ .started = b_digest }});
}

test "certify releases conflicting verification" {
    observed = .init(gpa);
    defer observed.deinit();
    try run_seeded(0, releases_verification_body);
}

test "certify releases conflicting reproposal" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var env: Env = undefined;
            try env.init(ctx);
            defer env.deinit();
            var wrapper = try env.wrap(ctx, "marshaled", Mock.init(gpa));
            defer wrapper.deinit();
            // The epoch boundary block, which this validator does not hold.
            const missing_parent = common.Sha256.hash(&.{"parent"});
            var boundary = try boundary_block(harness.genesis_commitment(), missing_parent);
            defer boundary.deinit(gpa);
            const boundary_commitment = boundary.commitment();
            const boundary_view = shared.blocks_per_epoch - 1;
            // B, led by participant 1 on the boundary block, is what the network notarizes.
            const round = common.round_at(0, boundary_view + 1);
            const context: common.CodingCtx = .{
                .round = round,
                .leader = env.validators.participants[1],
                .parent = .{ .new(boundary_view), boundary_commitment },
            };
            var b = try common.coded(gpa, context, boundary.digest(), boundary_view + 1, 200);
            defer b.deinit(gpa);
            const b_commitment = b.commitment();
            try testing.expect(!boundary_commitment.eql(b_commitment));
            // Verifying the re-proposal waits for the boundary block.
            var verify = try wrapper.start_verify(context, boundary_commitment);
            defer verify.deinit();
            try ctx.sleep(.fromMilliseconds(10));
            try testing.expectError(error.Empty, verify.try_recv());
            // Certifying B claims the round, so the wait for the boundary block ends.
            var certify_b = try wrapper.start_certify(round, b_commitment);
            defer certify_b.deinit();
            try ctx.sleep(.fromMilliseconds(10));
            try testing.expectError(error.Closed, verify.try_recv());
        }
    }.body);
}
