//! The coding variant's test harness (the coding parts of commonware
//! `marshal/mocks/harness.rs`: `CodingB`, `CodingCtx`, `genesis_commitment`,
//! `make_coding_block`, and `CodingHarness`), on top of marshal's shared harness
//! (`mocks/harness.zig`).
//!
//! Coding blocks are erasure coded for the committee: a test block at `height` embeds a
//! context over the parent's coding commitment, and genesis uses a trusted commitment under
//! `genesis_coding_config`, which is never coded.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const runtime = @import("runtime");
const utils = @import("utils");
const coding = @import("coding");
const parallel = @import("parallel");

const types = @import("types.zig");
const commitment_module = @import("../../commitment.zig");
const variant = @import("variant.zig");
const shared = @import("../mocks/harness.zig");
const shards = @import("shards/root.zig");
const store = @import("../store.zig");
const core = @import("../core/root.zig");
const resolver_p2p = @import("../resolver/p2p.zig");
const mocks_block = @import("../mocks/block.zig");
const consensus_types = @import("../../types.zig");
const simplex = @import("../../simplex/root.zig");
const simplex_types = @import("../../simplex/types.zig");
const cryptography = @import("cryptography");

const Height = consensus_types.Height;
const Round = consensus_types.Round;
const View = consensus_types.View;
pub const Sha256 = shared.Sha256;
const D = shared.D;
const K = shared.K;

pub const RS = coding.ReedSolomon(Sha256);
/// The coding commitment of a `CodingB` (commonware's `TestCommitment`).
/// Spelled over the digests, since `CodingB`'s context refers to it.
pub const TestCommitment = commitment_module.Commitment(D, RS.Commitment, D);
/// A context over coding commitments.
pub const CodingCtx = simplex_types.Context(TestCommitment, K);
/// The application block of the coding tests.
pub const CodingB = mocks_block.Block(Sha256, CodingCtx);
pub const CodingVariant = variant.Coding(CodingB, RS, Sha256, K);
comptime {
    assert(TestCommitment == types.CommitmentOf(CodingB, RS, Sha256));
}
pub const CodedTestBlock = CodingVariant.Block;
/// The shards engine's commitment records (commonware `RECORDS`).
pub const records: usize = 16;

/// The coding config of genesis commitments: genesis is trusted, so it is never coded.
pub const genesis_coding_config: coding.Config = .{ .minimum_shards = 1, .extra_shards = 1 };

/// The signing scheme over coding commitments: marshal's shared scheme choice (ed25519 under
/// `fast_schemes`, else threshold VRF MinPk) with the coding commitment as its subject digest.
const MinPk = cryptography.bls12381.primitives.MinPk;
pub const CodingScheme = if (shared.fast_schemes)
    simplex.scheme.ed25519.Scheme(TestCommitment)
else
    simplex.scheme.bls12381_threshold.vrf.Scheme(TestCommitment, K, MinPk);
pub const CodingProvider = cryptography.certificate.ConstantProvider(CodingScheme);
pub const CodingFixture = cryptography.certificate.mocks.Fixture(CodingScheme);

/// The validators' signing fixture over the shared namespace.
pub fn coding_fixture(gpa: Allocator, rng: anytype) !CodingFixture {
    const n = shared.num_validators;
    if (shared.fast_schemes) {
        return simplex.scheme.ed25519.fixture(TestCommitment, gpa, rng, shared.namespace, n);
    }
    const vrf = simplex.scheme.bls12381_threshold.vrf;
    return vrf.fixture(CodingScheme, gpa, rng, shared.namespace, n);
}

/// A certificate (`Vote` votes) over `proposal` from the first `signers` validators.
fn certify_votes(
    comptime Vote: type,
    comptime Certificate: type,
    gpa: Allocator,
    validators: *const CodingFixture,
    proposal: simplex_types.Proposal(TestCommitment),
    signers: u32,
) !Certificate {
    assert(signers > 0);
    assert(signers <= shared.num_validators);
    var votes: [shared.num_validators]Vote = undefined;
    for (votes[0..signers], validators.schemes[0..signers]) |*vote, *scheme| {
        vote.* = (try Vote.sign(gpa, scheme, proposal)).?;
    }
    const strategy = parallel.sequential;
    return Certificate.from_votes(gpa, &validators.schemes[0], votes[0..signers], strategy);
}

/// The genesis parent commitment: empty digests under the genesis config.
pub fn genesis_commitment() TestCommitment {
    return .init(.empty, .empty, .empty, genesis_coding_config);
}

/// A block over `context` at `height` with parent digest `parent` (commonware
/// `make_coding_block`).
pub fn make_coding_block(
    gpa: Allocator,
    context: CodingCtx,
    parent: D,
    at: Height,
    timestamp: u64,
) !CodingB {
    return CodingB.init(gpa, context, parent, at, timestamp);
}

/// The height-zero application block that seeds a fresh actor.
pub fn make_coding_genesis_block(gpa: Allocator) !CodingB {
    const context: CodingCtx = .{
        .round = .new(.zero(), .zero()),
        .leader = shared.default_leader(),
        .parent = .{ .zero(), genesis_commitment() },
    };
    return make_coding_block(gpa, context, shared.genesis_parent(), .zero(), 0);
}

/// The coding variant's harness (commonware `CodingHarness`).
pub const CodingHarness = struct {
    pub const ApplicationBlock = CodingB;
    pub const Variant = CodingVariant;
    pub const TestBlock = CodedTestBlock;
    pub const Commitment = TestCommitment;
    pub const Buffer = variant.Buffer(CodingB, RS, Sha256, K);

    pub fn genesis_parent_commitment(_: u32) Commitment {
        return genesis_commitment();
    }

    /// The block at `height` over `parent` and its commitment, coded for `participants`
    /// (owned by the caller).
    pub fn make_test_block(
        gpa: Allocator,
        parent: D,
        parent_commitment: Commitment,
        at: Height,
        timestamp: u64,
        participants: u32,
    ) !TestBlock {
        assert(participants >= 4 and participants <= std.math.maxInt(u16));
        const parent_view: View = if (at.previous()) |previous| .new(previous.get()) else .zero();
        const context: CodingCtx = .{
            .round = .new(.zero(), .new(at.get())),
            .leader = shared.default_leader(),
            .parent = .{ parent_view, parent_commitment },
        };
        const raw = try make_coding_block(gpa, context, parent, at, timestamp);
        const config = types.coding_config_for_participants(@intCast(participants));
        const digested = try broadcast.Digested(CodingB).compute(gpa, raw);
        return TestBlock.encode(gpa, digested, config, parallel.sequential);
    }

    /// The height-zero block under its trusted genesis commitment, whose root is the block
    /// digest (it is never coded).
    pub fn genesis_block(gpa: Allocator, _: u32) !TestBlock {
        const inner = try make_coding_genesis_block(gpa);
        const digest_value = inner.digest();
        const context_digest = try types.hash_context(Sha256, gpa, inner.context());
        const value: Commitment =
            .init(digest_value, digest_value, context_digest, genesis_coding_config);
        const digested = try broadcast.Digested(CodingB).compute(gpa, inner);
        assert(digested.digest().eql(digest_value));
        return TestBlock.precomputed(digested, value);
    }

    pub fn commitment(block: *const TestBlock) Commitment {
        return block.commitment();
    }

    pub fn digest(block: *const TestBlock) D {
        return block.digest();
    }

    pub fn height(block: *const TestBlock) Height {
        return block.height();
    }

    /// Persists `block` (borrowed) as verified, as commonware's default `propose` does.
    pub fn propose(validator: anytype, round: Round, block: *const TestBlock) !void {
        try verify(validator, round, block);
    }

    /// Persists `block` (borrowed) as verified at `validator`.
    pub fn verify(validator: anytype, round: Round, block: *const TestBlock) !void {
        if (!try validator.mailbox.verified(round, block.clone())) return error.ActorStopped;
    }

    /// Persists `block` (borrowed) as certified; false once the actor is gone.
    pub fn certify(validator: anytype, round: Round, block: *const TestBlock) !bool {
        return validator.mailbox.certified(round, block.clone());
    }

    pub const Scheme = CodingScheme;
    pub const Provider = CodingProvider;
    pub const Fixture = CodingFixture;
    pub const fixture = coding_fixture;
    pub const Finalization = simplex_types.Finalization(Scheme, TestCommitment);
    pub const Notarization = simplex_types.Notarization(Scheme, TestCommitment);

    pub fn make_finalization(
        gpa: Allocator,
        validators: *const Fixture,
        proposal: simplex_types.Proposal(TestCommitment),
        signers: u32,
    ) !Finalization {
        const Vote = simplex_types.Finalize(Scheme, TestCommitment);
        return certify_votes(Vote, Finalization, gpa, validators, proposal, signers);
    }

    pub fn make_notarization(
        gpa: Allocator,
        validators: *const Fixture,
        proposal: simplex_types.Proposal(TestCommitment),
        signers: u32,
    ) !Notarization {
        const Vote = simplex_types.Notarize(Scheme, TestCommitment);
        return certify_votes(Vote, Notarization, gpa, validators, proposal, signers);
    }

    /// commonware `CodingHarness::finalize_timeout` (900 s): reconstruction adds rounds.
    pub const finalize_timeout_s: u64 = 900;

    /// One validator with application `App` (cloneable; the actor gets a clone).
    pub fn Validator(comptime App: type) type {
        return CodingValidator(App);
    }
};

/// A validator's archives: finalizations under the coding scheme over coding commitments.
/// The shared `ArchivesOf` fixes the shared scheme, so the coding archives are opened here.
pub const Archives = shared.ArchivesWith(CodingScheme, TestCommitment, CodingVariant.StoredBlock);

/// The shards engine's types in a validator.
pub const ShardTypes = struct {
    pub const Block = CodingB;
    pub const Coding = RS;
    pub const Hasher = Sha256;
    pub const Provider = CodingProvider;
    pub const Blocker = shared.Network.Control;
    pub const PeerProvider = shared.Network.Manager;
    pub const Network = shared.Network;
    pub const Strategy = parallel.Sequential;
};

fn CodingValidator(comptime App: type) type {
    return struct {
        const Self = @This();
        const H = CodingHarness;
        const Network = shared.Network;
        pub const Stored = Archives;
        pub const ShardEngine = shards.Engine(ShardTypes);
        pub const Resolver = resolver_p2p.Resolver(
            TestCommitment,
            K,
            Network.Manager,
            Network.Control,
            Network.Sender,
            Network.Receiver,
        );
        pub const Params = struct {
            pub const Scheme = CodingScheme;
            pub const Provider = CodingProvider;
            pub const Epocher = consensus_types.FixedEpocher;
            pub const Strategy = parallel.Sequential;
            pub const ApplicationBlock = CodingB;
            pub const Block = CodedTestBlock;
            pub const Commitment = TestCommitment;
            pub const Variant = CodingVariant;
            pub const Acknowledgement = shared.Exact;
            pub const Certificates =
                store.Certificates(Stored.FinalizationArchive, CodingScheme, D, TestCommitment);
            pub const Blocks = store.Blocks(Stored.BlockArchive, CodingVariant.StoredBlock);
            pub const Application = App;
            pub const Buffer = H.Buffer;
            pub const Resolver = resolver_p2p.Mailbox(TestCommitment, K);
        };
        pub const Actor = core.Actor(Params);

        gpa: Allocator,
        io: Io,
        prefix: []u8,
        archives: *Stored,
        application: App,
        mailbox: Actor.Mailbox,
        /// The shards engine's mailbox (commonware's `ValidatorExtra`).
        extra: ShardEngine.Mailbox,
        /// The processed height the actor restored.
        height: ?Height,
        actor: runtime.context.Handle(anyerror!void),
        shards_future: Io.Future(ShardEngine.Error!void),
        resolver_future: Io.Future(Resolver.Engine.Error!void),
        resolver_handler: Resolver.Handler,

        /// Starts validator `me` on `network` under `ctx` (commonware
        /// `CodingHarness::setup_validator_with`). Takes ownership of `application`.
        pub fn setup(
            ctx: runtime.deterministic.Context,
            network: *Network,
            me: K,
            provider: CodingProvider,
            max_pending_acks: u32,
            application: App,
        ) !*Self {
            var owned = application;
            errdefer owned.deinit();
            const gpa = ctx.gpa();
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.gpa = gpa;
            self.io = ctx.io();
            self.application = owned;
            self.prefix = try std.fmt.allocPrint(gpa, "validator-{f}", .{me});
            errdefer gpa.free(self.prefix);
            const control = network.oracle().control(me);
            const resolver = try self.start_resolver(ctx, network, control, me);
            errdefer stop_resolver(self.io, resolver);
            self.archives = try gpa.create(Stored);
            errdefer gpa.destroy(self.archives);
            try self.archives.open(ctx, self.prefix);
            errdefer self.archives.deinit();
            try self.start_shards(ctx, network, control, provider);
            errdefer self.stop_shards();
            try self.start_actor(ctx, provider, max_pending_acks, resolver);
            assert(self.height == null or self.height.?.get() >= 0);
            return self;
        }

        fn start_resolver(
            self: *Self,
            ctx: runtime.deterministic.Context,
            network: *Network,
            control: Network.Control,
            me: K,
        ) !Resolver.Started {
            const backfill = try control.register(1, shared.test_quota);
            const started = try Resolver.init(self.gpa, self.io, ctx.scope.child("resolver"), .{
                .public_key = me,
                .peer_provider = network.oracle().manager(),
                .blocker = control,
                .mailbox_size = 100,
                .fetch_timeout = .from_millis(2000),
                .fetch_retry_delay = .from_millis(100),
                .priority_requests = false,
                .priority_responses = false,
            }, backfill.sender, backfill.receiver);
            self.resolver_future = started.future;
            self.resolver_handler = started.handler;
            return started;
        }

        fn stop_resolver(io: Io, started: Resolver.Started) void {
            var owned = started;
            owned.mailbox.deinit();
            owned.receiver.deinit();
            _ = owned.future.cancel(io) catch {};
            owned.handler.deinit();
        }

        fn start_shards(
            self: *Self,
            ctx: runtime.deterministic.Context,
            network: *Network,
            control: Network.Control,
            provider: CodingProvider,
        ) !void {
            const scope = ctx.scope.child("shards");
            const created = try ShardEngine.init(self.gpa, self.io, &scope, .{
                .scheme_provider = provider,
                .blocker = control,
                .block_codec_config = {},
                .strategy = parallel.sequential,
                .mailbox_size = 10,
                .peer_buffer_size = 64,
                .records = records,
                .peer_provider = network.oracle().manager(),
            });
            var mailbox = created.mailbox;
            errdefer mailbox.deinit();
            const channel = try control.register(2, shared.test_quota);
            self.shards_future = try created.engine.start(channel.sender, channel.receiver);
            self.extra = mailbox;
        }

        fn stop_shards(self: *Self) void {
            self.extra.deinit();
            _ = self.shards_future.cancel(self.io) catch {};
        }

        fn start_actor(
            self: *Self,
            ctx: runtime.deterministic.Context,
            provider: CodingProvider,
            max_pending_acks: u32,
            resolver: Resolver.Started,
        ) !void {
            const genesis = try H.genesis_block(self.gpa, shared.num_validators);
            const config: Actor.Config = .{
                .provider = provider,
                .epocher = .new(utils.NonZero(u64).init(shared.blocks_per_epoch).?),
                .start = .{ .genesis = genesis },
                .partition_prefix = self.prefix,
                .mailbox_size = 100,
                .view_retention = .new(10),
                .prunable_items_per_section = 10,
                .page_cache = &self.archives.cache_ref,
                .replay_buffer = 1024,
                .key_write_buffer = 1024,
                .value_write_buffer = 1024,
                .block_codec_config = {},
                .max_repair = 10,
                .max_pending_acks = max_pending_acks,
                .strategy = parallel.sequential,
            };
            const initialized = try Actor.init(
                ctx.child("actor"),
                .{ .archive = &self.archives.finalizations },
                .{ .archive = &self.archives.blocks },
                config,
            );
            self.mailbox = initialized.mailbox;
            self.height = if (initialized.floor.processed) |processed| processed.height() else null;
            self.actor = try initialized.actor.start(
                self.application.clone(),
                H.Buffer.init(self.extra.clone()),
                resolver.receiver,
                resolver.mailbox,
            );
        }

        /// Aborts the actor and its engines and releases the validator's storage, as a crash
        /// would, so a later setup can reopen the same partitions.
        pub fn crash(self: *Self) void {
            const gpa = self.gpa;
            const ended = self.actor.abort() catch {};
            ended catch {};
            _ = self.resolver_future.cancel(self.io) catch {};
            self.resolver_handler.deinit();
            self.stop_shards();
            self.mailbox.deinit();
            self.application.deinit();
            self.archives.deinit();
            gpa.destroy(self.archives);
            gpa.free(self.prefix);
            gpa.destroy(self);
        }
    };
}

test {
    _ = @import("harness_test.zig");
}
