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
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try try runner.start_context(body, .{});
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
        const marshal = self.validator.mailbox.clone();
        const shard_mailbox = self.validator.extra.clone();
        const config = common.marshaled_config(M, app, marshal, shard_mailbox, self.provider());
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
