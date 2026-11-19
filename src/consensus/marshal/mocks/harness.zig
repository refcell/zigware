//! The test harness shared by marshal's variants (commonware `marshal/mocks/harness.rs`).
//!
//! It holds the common test types and constants, the simulated network setup, certificate
//! helpers, and the standard harness: `StandardHarness.setup_validator` wires one validator
//! (a `broadcast.buffered` engine, the p2p resolver, two immutable archives, and the actor)
//! on a `p2p.simulated` network. A harness `H` declares `Variant`, `ApplicationBlock`,
//! `TestBlock`, `Commitment`, `Validator`, and the per-variant operations the scenario tests
//! call (`genesis_parent_commitment`, `make_test_block`, `commitment`, `digest`, `height`,
//! `propose`, `verify`, `certify`), so a scenario runs against every variant.
//!
//! Commonware signs with `bls12381_threshold::vrf` (MinPk). Debug builds without
//! `-Dslow-tests` sign with ed25519 instead, as the aggregation tests do: unoptimized BLS
//! takes seconds per certificate.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const build_options = @import("build_options");
const broadcast = @import("broadcast");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const types = @import("../../types.zig");
const simplex = @import("../../simplex/root.zig");
const simplex_types = @import("../../simplex/types.zig");
const config_api = @import("../config.zig");
const limits = @import("../limits.zig");
const store = @import("../store.zig");
const update = @import("../update.zig");
const core = @import("../core/root.zig");
const resolver_p2p = @import("../resolver/p2p.zig");
const standard = @import("../standard/root.zig");
const mocks_block = @import("block.zig");

const Height = types.Height;
const Round = types.Round;
const View = types.View;
const Epoch = types.Epoch;

/// Whether this build signs with ed25519 instead of the threshold VRF scheme.
pub const fast_schemes = builtin.mode == .debug and !build_options.slow_tests;

pub const Sha256 = cryptography.Sha256;
pub const D = Sha256.Digest;
pub const K = cryptography.ed25519.PublicKey;
pub const Ctx = simplex_types.Context(D, K);
pub const B = mocks_block.Block(Sha256, Ctx);
pub const S = if (fast_schemes)
    simplex.scheme.ed25519.Scheme(D)
else
    simplex.scheme.bls12381_threshold.vrf.Scheme(D, K, cryptography.bls12381.primitives.MinPk);
pub const Provider = cryptography.certificate.ConstantProvider(S);
pub const Fixture = cryptography.certificate.mocks.Fixture(S);
pub const Network = p2p.simulated.Network(K);
pub const Finalization = simplex_types.Finalization(S, D);
pub const Notarization = simplex_types.Notarization(S, D);
pub const Proposal = simplex_types.Proposal(D);
pub const Exact = utils.acknowledgement.Exact;

pub const namespace = "test";
pub const num_validators: u32 = 4;
pub const quorum: u32 = 3;
pub const num_blocks: u64 = 160;
pub const blocks_per_epoch: u64 = 20;
pub const page_size: u16 = 1024;
pub const page_cache_size: usize = 10;
pub const test_quota = p2p.Quota.per_second(1024);

pub const link: p2p.simulated.Link = .{
    .latency = .from_millis(100),
    .jitter = .from_millis(1),
    .success_rate = 1.0,
};
pub const unreliable_link: p2p.simulated.Link = .{
    .latency = .from_millis(200),
    .jitter = .from_millis(50),
    .success_rate = 0.7,
};

/// The validators' signing fixture over `namespace`.
pub fn fixture(gpa: Allocator, rng: anytype) !Fixture {
    if (fast_schemes) return simplex.scheme.ed25519.fixture(D, gpa, rng, namespace, num_validators);
    return simplex.scheme.bls12381_threshold.vrf.fixture(S, gpa, rng, namespace, num_validators);
}

/// The default leader key for test block contexts.
pub fn default_leader() K {
    return cryptography.ed25519.PrivateKey.from_seed(0).public_key();
}

/// A raw test block at `height` with a derived context (round = (0, height), parent view =
/// height - 1).
pub fn make_raw_block(gpa: Allocator, parent: D, height: Height, timestamp: u64) !B {
    const parent_view: View = if (height.previous()) |previous| .new(previous.get()) else .zero();
    const context: Ctx = .{
        .round = .new(.zero(), .new(height.get())),
        .leader = default_leader(),
        .parent = .{ parent_view, parent },
    };
    return B.init(gpa, context, parent, height, timestamp);
}

/// The genesis block's parent digest (commonware `Sha256::hash(&[b""])`).
pub fn genesis_parent() D {
    return Sha256.hash(&.{""});
}

/// A simulated network over `participants` (sorted copy tracked as set 0), running until
/// `stop`.
pub const TestNetwork = struct {
    network: *Network,
    task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    io: Io,

    pub fn start(
        gpa: Allocator,
        io: Io,
        tracked_peer_sets: usize,
        participants: []const K,
        max_size: u32,
    ) !TestNetwork {
        assert(participants.len > 0);
        const network = try Network.init(gpa, io, .{
            .max_size = max_size,
            .max_peers_per_set = participants.len,
            .disconnect_on_block = true,
            .tracked_peer_sets = tracked_peer_sets,
        });
        errdefer network.deinit();
        const sorted = try gpa.dupe(K, participants);
        defer gpa.free(sorted);
        p2p.TrackedPeers(K).PeerSet.sort(sorted);
        _ = network.oracle().manager().track(0, .init_primary(.init(sorted)));
        const task = try io.concurrent(Network.run, .{network});
        return .{ .network = network, .task = task, .io = io };
    }

    pub fn stop(self: *TestNetwork) void {
        self.network.close();
        self.task.await(self.io) catch {};
        self.network.deinit();
        self.* = undefined;
    }

    /// Links every ordered pair of distinct `peers` with `value`.
    pub fn link_all(self: *TestNetwork, peers: []const K, value: p2p.simulated.Link) !void {
        for (peers) |from| for (peers) |to| {
            if (from.eql(to)) continue;
            try self.network.oracle().add_link(from, to, value);
        };
    }
};

/// The largest message a validator of variant `V` sends.
pub fn max_message_size(comptime V: type) u32 {
    return p2p.max_message_size(&.{limits.max_payload_size(V, S, num_validators, {})});
}

/// A certificate of `kind` (`Finalize` or `Notarize` votes) over `proposal` from the first
/// `signers` validators.
pub fn certify_votes(
    comptime Vote: type,
    comptime Certificate: type,
    gpa: Allocator,
    validators: *const Fixture,
    proposal: anytype,
    signers: u32,
) !Certificate {
    assert(signers > 0);
    assert(signers <= num_validators);
    var votes: [num_validators]Vote = undefined;
    for (votes[0..signers], validators.schemes[0..signers]) |*vote, *scheme| {
        vote.* = (try Vote.sign(gpa, scheme, proposal)).?;
    }
    const strategy = parallel.sequential;
    return Certificate.from_votes(gpa, &validators.schemes[0], votes[0..signers], strategy);
}

/// A finalization over a proposal committing to `C` (the coding variant's commitment).
pub fn make_finalization_of(
    comptime C: type,
    gpa: Allocator,
    validators: *const Fixture,
    proposal: simplex_types.Proposal(C),
    signers: u32,
) !simplex_types.Finalization(S, C) {
    const Vote = simplex_types.Finalize(S, C);
    const Certificate = simplex_types.Finalization(S, C);
    return certify_votes(Vote, Certificate, gpa, validators, proposal, signers);
}

/// A notarization over a proposal committing to `C`.
pub fn make_notarization_of(
    comptime C: type,
    gpa: Allocator,
    validators: *const Fixture,
    proposal: simplex_types.Proposal(C),
    signers: u32,
) !simplex_types.Notarization(S, C) {
    const Vote = simplex_types.Notarize(S, C);
    const Certificate = simplex_types.Notarization(S, C);
    return certify_votes(Vote, Certificate, gpa, validators, proposal, signers);
}

pub fn make_finalization(
    gpa: Allocator,
    validators: *const Fixture,
    proposal: Proposal,
    signers: u32,
) !Finalization {
    return make_finalization_of(D, gpa, validators, proposal, signers);
}

pub fn make_notarization(
    gpa: Allocator,
    validators: *const Fixture,
    proposal: Proposal,
    signers: u32,
) !Notarization {
    return make_notarization_of(D, gpa, validators, proposal, signers);
}

/// The standard variant's archives: finalizations commit to the block digest.
pub fn Archives(comptime StoredBlock: type) type {
    return ArchivesOf(D, StoredBlock);
}

/// The two immutable archives a validator's actor borrows, and the page cache behind them.
/// Finalizations commit to `C`.
pub fn ArchivesOf(comptime C: type, comptime StoredBlock: type) type {
    return ArchivesWith(S, C, StoredBlock);
}

/// `ArchivesOf` under signing scheme `Scheme` (the coding variant signs over its commitment).
pub fn ArchivesWith(comptime Scheme: type, comptime C: type, comptime StoredBlock: type) type {
    return struct {
        const Self = @This();
        pub const Certificate = simplex_types.Finalization(Scheme, C);
        pub const FinalizationArchive = storage.archive.immutable.Archive([32]u8, Certificate);
        pub const BlockArchive = storage.archive.immutable.Archive([32]u8, StoredBlock);

        gpa: Allocator,
        cache_ref: runtime.buffer.paged.CacheRef,
        finalizations: FinalizationArchive,
        blocks: BlockArchive,
        /// The archives borrow their partition names (the ordinal opens blobs lazily).
        names: [2]Partitions,

        /// Opens both archives under `prefix` on `ctx`'s storage. Must not move afterwards.
        pub fn open(self: *Self, ctx: anytype, prefix: []const u8) !void {
            const gpa = ctx.gpa();
            self.gpa = gpa;
            self.cache_ref = try .init(gpa, page_size, page_cache_size);
            errdefer self.cache_ref.deinit();
            const certificate_config = Scheme.certificate_codec_config_unbounded();
            self.names[0] = try .init(gpa, prefix, "finalizations-by-height");
            errdefer self.names[0].deinit(gpa);
            self.names[1] = try .init(gpa, prefix, "finalized_blocks");
            errdefer self.names[1].deinit(gpa);
            const cache_ref = &self.cache_ref;
            const label = "finalizations_by_height";
            const names = &self.names;
            self.finalizations = try open_archive(
                Certificate,
                ctx,
                cache_ref,
                &names[0],
                label,
                certificate_config,
            );
            errdefer self.finalizations.deinit();
            const label_blocks = "finalized_blocks";
            const names_blocks = &names[1];
            const Stored = StoredBlock;
            self.blocks = try open_archive(Stored, ctx, cache_ref, names_blocks, label_blocks, {});
        }

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            self.blocks.deinit();
            self.finalizations.deinit();
            for (&self.names) |*names| names.deinit(gpa);
            self.cache_ref.deinit();
            self.* = undefined;
        }
    };
}

/// The five partition names of one immutable archive: `<prefix>-<name>-<kind>`.
const Partitions = struct {
    const kinds = [_][]const u8{
        "metadata", "freezer-table", "freezer-key", "freezer-value", "ordinal",
    };

    values: [kinds.len][]u8,

    fn init(gpa: Allocator, prefix: []const u8, name: []const u8) !Partitions {
        var self: Partitions = undefined;
        var made: usize = 0;
        errdefer for (self.values[0..made]) |value| gpa.free(value);
        for (kinds, &self.values) |kind, *value| {
            value.* = try std.fmt.allocPrint(gpa, "{s}-{s}-{s}", .{ prefix, name, kind });
            made += 1;
        }
        return self;
    }

    fn deinit(self: *Partitions, gpa: Allocator) void {
        for (self.values) |value| gpa.free(value);
        self.* = undefined;
    }
};

fn open_archive(
    comptime V: type,
    ctx: anytype,
    cache_ref: *runtime.buffer.paged.CacheRef,
    names: *const Partitions,
    comptime label: []const u8,
    codec_config: anytype,
) !storage.archive.immutable.Archive([32]u8, V) {
    const scope = ctx.scope.child(label);
    return .init(ctx.gpa(), ctx.storage, scope, .{
        .metadata_partition = names.values[0],
        .freezer_table_partition = names.values[1],
        .freezer_table_initial_size = 64,
        .freezer_table_resize_frequency = 10,
        .freezer_table_resize_chunk_size = 10,
        .freezer_key_partition = names.values[2],
        .freezer_key_cache_ref = cache_ref,
        .freezer_value_partition = names.values[3],
        .freezer_value_target_size = 1024,
        .ordinal_partition = names.values[4],
        .items_per_section = 10,
        .freezer_key_write_buffer = 1024,
        .freezer_value_write_buffer = 1024,
        .ordinal_write_buffer = 1024,
        .replay_buffer = 1024,
        .codec_config = codec_config,
    });
}

/// The shared signing decls, under names a harness re-exports.
const harness_fixture = struct {
    const Fixture = root_decls.Fixture;
    const Provider = root_decls.Provider;
    const Finalization = root_decls.Finalization;
    const Notarization = root_decls.Notarization;
    const fixture = root_decls.fixture;
    const make_finalization = root_decls.make_finalization;
    const make_notarization = root_decls.make_notarization;
};
const root_decls = @This();

/// The standard variant's harness (commonware `StandardHarness`): blocks travel whole
/// through `broadcast.buffered`, and the commitment is the block digest.
pub const StandardHarness = struct {
    pub const ApplicationBlock = B;
    pub const Variant = standard.Standard(B);
    pub const TestBlock = broadcast.Digested(B);
    pub const Commitment = D;
    pub const Buffer = standard.Buffer(B, K);
    /// What a test keeps of a validator besides its mailbox: its buffer.
    pub const Extra = Buffer;

    pub fn genesis_parent_commitment(_: u32) D {
        return genesis_parent();
    }

    /// The block at `height` over `parent` (owned by the caller).
    pub fn make_test_block(
        gpa: Allocator,
        parent: D,
        _: D,
        at: Height,
        timestamp: u64,
        _: u32,
    ) !TestBlock {
        return mocks_block.ready(B, gpa, try make_raw_block(gpa, parent, at, timestamp));
    }

    /// The height-zero block that seeds a fresh actor.
    pub fn genesis_block(gpa: Allocator, participants: u32) !TestBlock {
        const parent_commitment = genesis_parent_commitment(participants);
        return make_test_block(gpa, genesis_parent(), parent_commitment, .zero(), 0, participants);
    }

    pub fn commitment(block: *const TestBlock) D {
        return block.digest();
    }

    pub fn digest(block: *const TestBlock) D {
        return block.digest();
    }

    pub fn height(block: *const TestBlock) Height {
        return block.inner().height();
    }

    /// Seconds of simulated time the finalize scenario may take.
    pub const finalize_timeout_s: u64 = 600;

    /// Persists a proposed block (borrowed) as verified without broadcasting it (commonware's
    /// default `propose`): scenarios drive dissemination explicitly.
    pub fn propose(validator: anytype, round: Round, block: *const TestBlock) !void {
        if (!try validator.mailbox.verified(round, block.clone())) return error.ActorStopped;
    }

    // The signing setup and certificates scenarios read from a harness.
    pub const Scheme = S;
    pub const Fixture = harness_fixture.Fixture;
    pub const Provider = harness_fixture.Provider;
    pub const Finalization = harness_fixture.Finalization;
    pub const Notarization = harness_fixture.Notarization;
    pub const fixture = harness_fixture.fixture;
    pub const make_finalization = harness_fixture.make_finalization;
    pub const make_notarization = harness_fixture.make_notarization;

    /// Persists `block` (borrowed) as verified at `validator`.
    pub fn verify(validator: anytype, round: Round, block: *const TestBlock) !void {
        if (!try validator.mailbox.verified(round, block.clone())) return error.ActorStopped;
    }

    /// Persists `block` (borrowed) as certified; false once the actor is gone.
    pub fn certify(validator: anytype, round: Round, block: *const TestBlock) !bool {
        return validator.mailbox.certified(round, block.clone());
    }

    /// One validator with application `App` (cloneable; the actor gets a clone).
    pub fn Validator(comptime App: type) type {
        return StandardValidator(App);
    }

    /// A validator whose finalized archives are prunable (commonware
    /// `setup_prunable_validator`).
    pub fn PrunableValidator(comptime App: type) type {
        return StandardValidatorOver(App, PrunableArchives(B));
    }

    /// Starts validator `me` over prunable finalized archives, signing with validator 0's
    /// scheme as commonware does. The standard harness derives its partition names from `me`,
    /// so `prefix` only documents the scenario. Takes ownership of `application`.
    pub fn setup_prunable_validator(
        ctx: runtime.deterministic.Context,
        network: *Network,
        me: K,
        validators: *const harness_fixture.Fixture,
        prefix: []const u8,
        application: anytype,
    ) !*PrunableValidator(@TypeOf(application)) {
        assert(prefix.len > 0);
        const provider: harness_fixture.Provider = .init(&validators.schemes[0]);
        return PrunableValidator(@TypeOf(application)).setup(
            ctx,
            network,
            me,
            provider,
            1,
            application,
        );
    }

    /// Persists `block` (borrowed) as verified for the pruning scenarios.
    pub const verify_for_prune = verify;
};

fn StandardValidator(comptime App: type) type {
    return StandardValidatorOver(App, Archives(B));
}

/// The standard harness's prunable finalized archives (commonware
/// `setup_prunable_validator`'s `<prefix>-finalizations-by-height-*` and
/// `<prefix>-finalized-blocks-*`), ten items per section; the same shape as
/// `standard/tests/common.zig`'s `PrunableStores`. Must not move once opened.
pub fn PrunableArchives(comptime StoredBlock: type) type {
    return struct {
        const Self = @This();
        const Translator = storage.translator.EightCap;
        pub const FinalizationArchive = storage.archive.prunable.Archive(
            Translator,
            [32]u8,
            Finalization,
        );
        pub const BlockArchive = storage.archive.prunable.Archive(Translator, [32]u8, StoredBlock);
        const kinds = [_][]const u8{
            "finalizations-by-height-metadata", "finalizations-by-height-key",
            "finalizations-by-height-value",    "finalized-blocks-metadata",
            "finalized-blocks-key",             "finalized-blocks-value",
        };

        gpa: Allocator,
        cache_ref: runtime.buffer.paged.CacheRef,
        names: [kinds.len][]u8,
        finalizations: FinalizationArchive,
        blocks: BlockArchive,

        pub fn open(self: *Self, ctx: anytype, prefix: []const u8) !void {
            const gpa = ctx.gpa();
            self.gpa = gpa;
            var made: usize = 0;
            errdefer for (self.names[0..made]) |name| gpa.free(name);
            for (kinds, &self.names) |kind, *name| {
                name.* = try std.fmt.allocPrint(gpa, "{s}-{s}", .{ prefix, kind });
                made += 1;
            }
            assert(made == kinds.len);
            self.cache_ref = try .init(gpa, page_size, page_cache_size);
            errdefer self.cache_ref.deinit();
            const certificate_config = S.certificate_codec_config_unbounded();
            const label = "finalizations_by_height";
            const config = certificate_config;
            self.finalizations = try self.open_prunable(Finalization, ctx, 0, label, config);
            errdefer self.finalizations.deinit();
            self.blocks = try self.open_prunable(StoredBlock, ctx, 3, "finalized_blocks", {});
        }

        pub fn deinit(self: *Self) void {
            self.blocks.deinit();
            self.finalizations.deinit();
            self.cache_ref.deinit();
            for (self.names) |name| self.gpa.free(name);
            self.* = undefined;
        }

        fn open_prunable(
            self: *Self,
            comptime Value: type,
            ctx: anytype,
            comptime first: usize,
            comptime label: []const u8,
            codec_config: anytype,
        ) !storage.archive.prunable.Archive(Translator, [32]u8, Value) {
            return .init(ctx.gpa(), ctx.storage, ctx.scope.child(label), .{
                .translator = .{},
                .metadata_partition = self.names[first],
                .key_partition = self.names[first + 1],
                .key_cache_ref = &self.cache_ref,
                .value_partition = self.names[first + 2],
                .codec_config = codec_config,
                .items_per_section = 10,
                .key_write_buffer = 1024,
                .value_write_buffer = 1024,
                .replay_buffer = 1024,
            });
        }
    };
}

/// A standard validator with application `App` over finalized archives `StoredArchives`
/// (`Archives(B)` or `PrunableArchives(B)`).
fn StandardValidatorOver(comptime App: type, comptime StoredArchives: type) type {
    return struct {
        const Self = @This();
        const H = StandardHarness;
        pub const Stored = StoredArchives;
        pub const Resolver = resolver_p2p.Resolver(
            D,
            K,
            Network.Manager,
            Network.Control,
            Network.Sender,
            Network.Receiver,
        );
        pub const BroadcastEngine = broadcast.buffered.Engine(
            B,
            Network.Manager,
            Network.Control,
            Network,
        );
        pub const Params = struct {
            pub const Scheme = S;
            pub const Provider = harness_provider;
            pub const Epocher = types.FixedEpocher;
            pub const Strategy = parallel.Sequential;
            pub const ApplicationBlock = B;
            pub const Block = H.Variant.Block;
            pub const Commitment = D;
            pub const Variant = H.Variant;
            pub const Acknowledgement = Exact;
            pub const Certificates = store.Certificates(Stored.FinalizationArchive, S, D, D);
            pub const Blocks = store.Blocks(Stored.BlockArchive, B);
            pub const Application = App;
            pub const Buffer = H.Buffer;
            pub const Resolver = resolver_p2p.Mailbox(D, K);
        };
        const harness_provider = Provider;
        pub const Actor = core.Actor(Params);

        gpa: Allocator,
        io: Io,
        prefix: []u8,
        archives: *Stored,
        application: App,
        mailbox: Actor.Mailbox,
        extra: H.Buffer,
        /// The processed height the actor restored.
        height: ?Height,
        actor: runtime.context.Handle(anyerror!void),
        broadcast_future: Io.Future(BroadcastEngine.Error!void),
        resolver_future: Io.Future(Resolver.Engine.Error!void),
        resolver_handler: Resolver.Handler,

        /// Starts validator `me` on `network` under `ctx` (commonware
        /// `setup_validator_with`). Takes ownership of `application`.
        pub fn setup(
            ctx: runtime.deterministic.Context,
            network: *Network,
            me: K,
            provider: Provider,
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
            const buffer = try self.start_broadcast(ctx, network, control, me);
            self.extra = buffer;
            errdefer self.stop_broadcast();
            self.archives = try gpa.create(Stored);
            errdefer gpa.destroy(self.archives);
            try self.archives.open(ctx, self.prefix);
            errdefer self.archives.deinit();
            try self.start_actor(ctx, provider, max_pending_acks, resolver);
            return self;
        }

        fn start_resolver(
            self: *Self,
            ctx: runtime.deterministic.Context,
            network: *Network,
            control: Network.Control,
            me: K,
        ) !Resolver.Started {
            const backfill = try control.register(1, test_quota);
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

        fn start_broadcast(
            self: *Self,
            ctx: runtime.deterministic.Context,
            network: *Network,
            control: Network.Control,
            me: K,
        ) !H.Buffer {
            const scope = ctx.scope.child("broadcast");
            const created = try BroadcastEngine.init(self.gpa, self.io, &scope, .{
                .public_key = me,
                .mailbox_size = 100,
                .deque_size = 10,
                .priority = false,
                .codec_config = {},
                .peer_provider = network.oracle().manager(),
                .blocker = control,
            });
            var mailbox = created.mailbox;
            errdefer mailbox.deinit();
            const channel = try control.register(2, test_quota);
            self.broadcast_future = try created.engine.start(channel.sender, channel.receiver);
            return .init(mailbox);
        }

        fn stop_broadcast(self: *Self) void {
            self.extra.deinit();
            _ = self.broadcast_future.cancel(self.io) catch {};
        }

        fn start_actor(
            self: *Self,
            ctx: runtime.deterministic.Context,
            provider: Provider,
            max_pending_acks: u32,
            resolver: Resolver.Started,
        ) !void {
            const genesis = try H.genesis_block(self.gpa, num_validators);
            const config: Actor.Config = .{
                .provider = provider,
                .epocher = .new(utils.NonZero(u64).init(blocks_per_epoch).?),
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
                self.extra.clone(),
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
            self.stop_broadcast();
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
