//! The `validator` subcommand (commonware `examples/dkg/src/validator.rs`): one node running
//! p2p, broadcast, marshal, the DKG probe, the QMDB resolver, the reshare actor, the
//! orchestrator, and the stateful application until one of them stops.
//!
//! Differences from commonware, all from zigware's building blocks:
//! - Marshal comes from glue's bootstrap `Node`, which names marshal's own partition
//!   `validator-marshal` (commonware: `validator`) and always starts from genesis. A node with
//!   a persisted state-sync floor, or `--state-sync`, fails with `error.StateSyncUnsupported`
//!   until `Node` takes a floor start.
//! - The QMDB resolver and the `Stateful` actor run as plain futures, whose awaits are not
//!   cancelable, so they are stopped at shutdown rather than supervised by `select`.
//! - zigware's `Stateful` attaches its databases to the QMDB resolver only after state sync
//!   (commonware also does after recovering from marshal), so `attach_task` attaches them once
//!   `Stateful` opens them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const application = @import("application.zig");
const bootstrap = @import("bootstrap.zig");
const config = @import("config.zig");
const net_mod = @import("network.zig");
const provider_mod = @import("provider.zig");
const types = @import("types.zig");

const consensus = zigware.consensus;
const glue = zigware.glue;
const glue_dkg = glue.dkg;
const parallel = zigware.parallel;
const runtime = zigware.runtime;
const utils = zigware.utils;
const production = runtime.production;
const simplex = consensus.simplex;
const reshare = glue_dkg.reshare;
const Exact = utils.acknowledgement.Exact;
const Feedback = consensus.Feedback;
const Handle = runtime.context.Handle(anyerror!void);
const Tracer = runtime.telemetry.traces.Tracer;
const Net = net_mod.Net;
const Oracle = Net.Oracle;
const Ctx = production.runner.Context;
const Manager = glue_dkg.network.KeyOnlyManager(Oracle);
const DynamicProvider = provider_mod.DynamicProvider;
/// commonware's tracing targets for this module and for `LogReporter` (in `types`).
const target = "commonware_dkg::validator";
const log_target = "commonware_dkg::types";
/// The reshare actor's target (glue's `reshare.actor` `trace_target`, not re-exported).
const reshare_target = "commonware_glue::dkg::reshare::actor";

/// Partition of the validator's `Secrets` store.
pub const partition: types.Partition = .validator;

/// The marshal variant: whole blocks, committed by digest.
pub const Variant = consensus.marshal.standard.Standard(types.Block);

/// The durable choice between peer state sync and recovery from marshal.
pub const Plan = glue.stateful.SyncPlan(types.Scheme, Variant);

/// How long the probe waits before re-soliciting floors.
pub const probe_retry_timeout_ns: u64 = 500 * std.time.ns_per_ms;

/// The prefix of every validator storage partition.
const partition_prefix = "validator";

const NodeTypes = struct {
    pub const Block = types.Block;
    pub const Scheme = types.Scheme;
    pub const Provider = *DynamicProvider;
    pub const Strategy = parallel.Sequential;
    pub const Network = Net;
    pub const PeerProvider = Oracle;
    pub const Blocker = Oracle;
    pub const Application = Reporter;
    pub const Context = Ctx;
};
const Node = glue_dkg.bootstrap.Node(NodeTypes);
const MarshalMailbox = Node.Mailbox;

const ReshareTypes = struct {
    pub const Block = types.Block;
    pub const Ack = Exact;
    pub const Ancestry = consensus.marshal.ancestry.AncestorStream(MarshalMailbox);
    pub const Signer = types.ed25519.PrivateKey;
    pub const Manager = validator.Manager;
    pub const Blocker = Oracle;
    pub const Provider = types.Participants;
    pub const SecretStore = types.Secrets;
    pub const Registrar = provider_mod.Registrar;
    pub const Marshal = MarshalMailbox;
    pub const Strategy = parallel.Sequential;
};
const validator = @This();
const ReshareActor = reshare.actor.Actor(ReshareTypes);
const ReshareRunner = reshare.actor.run.Runner(ReshareTypes);

const StatefulTypes = struct {
    pub const App = application.App;
    pub const Databases = application.Database;
    pub const Marshal = MarshalMailbox;
    pub const Plan = validator.Plan;
};
const Stateful = glue.stateful.actor.Stateful(StatefulTypes);
const ReshareApp = reshare.Application(Stateful.Mailbox, ReshareTypes);
const Wrapper = consensus.marshal.standard.Deferred(
    Ctx,
    types.Scheme,
    ReshareApp,
    types.Block,
    consensus.types.FixedEpocher,
);

const OrchestratorTypes = struct {
    pub const Context = Ctx;
    pub const Block = types.Block;
    pub const Ack = Exact;
    pub const Scheme = types.Scheme;
    pub const Provider = *DynamicProvider;
    pub const Manager = *validator.Manager;
    pub const Marshal = MarshalMailbox;
    pub const Blocker = Oracle;
    pub const ElectorConfig = simplex.elector.RoundRobin(types.Sha256);
    pub const Elector = simplex.elector.RoundRobinElector;
    pub const Automaton = *Wrapper;
    pub const Relay = *Wrapper;
    pub const Reporter = *Wrapper;
    pub const Strategy = parallel.Sequential;
    pub const Sender = Net.Sender;
    pub const Receiver = Net.Receiver;

    pub fn build_elector(elector: ElectorConfig, gpa: Allocator, n: u32) !Elector {
        return elector.build(gpa, n);
    }
};
const Orchestrator = glue_dkg.orchestrator.Actor(OrchestratorTypes);
const DkgPlan = glue_dkg.state_sync.Plan(types.Scheme, types.Digest, types.MinSig, types.Unit);

const QmdbParams = glue.stateful.db.p2p.Params(
    types.PublicKey,
    Oracle,
    Oracle,
    application.Managed,
    Net.Sender,
    Net.Receiver,
);
const Qmdb = glue.stateful.db.p2p.Actor(QmdbParams);

pub const ProbeTypes = struct {
    pub const Scheme = types.Scheme;
    pub const Variant = validator.Variant;
    pub const Manager = validator.Manager;
    pub const Source = glue_dkg.probe.MarshalSource(MarshalMailbox);
    pub const Blocker = Oracle;
    pub const NetSender = Net.Sender;
    pub const NetReceiver = Net.Receiver;
};
const Probe = glue_dkg.probe.Probe(ProbeTypes);
const ProbeRng = utils.rng.ChaChaRng(20);

/// The largest payload any validator channel carries (commonware `types::max_message_size`).
pub fn max_message_size() u32 {
    const n = types.max_participants;
    const Op = Qmdb.Op;
    const qmdb_payload = glue.stateful.db.p2p.max_payload_size(
        types.Family,
        types.Digest,
        types.sync_batch_size,
        Op.fixed_size.?,
    ) catch unreachable; // `sync_batch_size` fits in u32.
    const payloads = [_]usize{
        glue_dkg.orchestrator.max_payload_size(types.Scheme, types.Digest, n),
        consensus.marshal.max_payload_size(Variant, types.Scheme, n, {}),
        glue_dkg.probe.max_payload_size(Variant, types.Scheme, n, {}),
        glue_dkg.max_payload_size(types.MinSig, types.PublicKey, n),
        qmdb_payload,
    };
    const result = zigware.p2p.sizing.max_message_size(&payloads);
    assert(result >= payloads[4]);
    return result;
}

/// The DKG probe's configuration, bootstrapped from `genesis`'s participants at epoch zero
/// and floored at `plan`'s persisted state-sync floor, if any (commonware `probe_config`).
/// `P` declares the probe's types; `verifier` must outlive the probe.
pub fn probe_config(
    comptime P: type,
    gpa: Allocator,
    manager: P.Manager,
    blocker: P.Blocker,
    genesis: *const types.EpochInfo,
    plan: *const Plan,
    verifier: *const types.Scheme,
) Allocator.Error!glue_dkg.probe.Probe(P).Config {
    comptime assert(P.Scheme == types.Scheme);
    comptime assert(P.Variant == Variant);
    var participants = try genesis.participants(gpa);
    errdefer participants.deinit(gpa);
    const info = try genesis.clone(gpa);
    const floor_epoch: ?types.Epoch = if (plan.floor()) |floor| floor.epoch() else null;
    assert(floor_epoch == null or plan.may_sync());
    return .{
        .discovery = .{
            .manager = manager,
            .bootstrap = .{ .epoch = .zero(), .participants = participants, .directory = .{} },
            .floor_epoch = floor_epoch,
            .verifier = verifier,
            .genesis = info,
            .blocker = blocker,
            .blocks_per_epoch = types.blocks_per_epoch,
            .block_cfg = {},
        },
        .retry_timeout_ns = probe_retry_timeout_ns,
        .mailbox_size = types.mailbox_size,
    };
}

/// Marshal's reporter: the stateful application, then the orchestrator, then the reshare
/// actor, then a log line (commonware's nested `Reporters` ending in `LogReporter`). Each
/// receives its own clone of a finalized block and its acknowledgement.
pub const Reporter = struct {
    stateful: Stateful.Mailbox,
    orchestrator: Orchestrator.Mailbox,
    reshare: ReshareActor.Mailbox,
    tracer: Tracer,

    pub fn report(self: *Reporter, update: consensus.marshal.Update(types.Block, Exact)) Feedback {
        var feedback: Feedback = .ok;
        switch (update) {
            .tip => {
                feedback = consensus.reporter.combine(feedback, self.stateful.report(update));
                feedback = consensus.reporter.combine(feedback, self.orchestrator.report(update));
                feedback = consensus.reporter.combine(feedback, self.reshare.report(update));
            },
            .block => |value| {
                const copies = [_]@TypeOf(value){
                    .{ .block = value.block.clone(), .ack = value.ack.clone() },
                    .{ .block = value.block.clone(), .ack = value.ack.clone() },
                    .{ .block = value.block.clone(), .ack = value.ack.clone() },
                };
                const r1 = self.stateful.report(.{ .block = copies[0] });
                const r2 = self.orchestrator.report(.{ .block = copies[1] });
                const r3 = self.reshare.report(.{ .block = copies[2] });
                feedback = consensus.reporter.combine(consensus.reporter.combine(r1, r2), r3);
                self.log_finalized(value.block.inner());
                var owned = value;
                owned.ack.acknowledge();
                owned.block.deinit();
            },
        }
        return feedback;
    }

    /// commonware `LogReporter`.
    fn log_finalized(self: *const Reporter, block: *const types.Block) void {
        assert(block.context().epoch().get() <= block.height().get());
        self.tracer.event(.info, "finalized block", .{
            .epoch = block.context().epoch().get(),
            .height = block.height().get(),
            .digest = block.digest(),
        });
    }

    pub fn clone(self: *const Reporter) Reporter {
        return .{
            .stateful = self.stateful.clone(),
            .orchestrator = self.orchestrator.clone(),
            .reshare = self.reshare.clone(),
            .tracer = self.tracer,
        };
    }

    pub fn deinit(self: *Reporter) void {
        self.stateful.deinit();
        self.orchestrator.deinit();
        self.reshare.deinit();
        self.* = undefined;
    }
};

/// The validator's channels, registered on the discovery network (commonware's eight
/// `p2p.register` calls).
const Channels = struct {
    votes: net_mod.Channel,
    certificates: net_mod.Channel,
    resolver: net_mod.Channel,
    backfill: net_mod.Channel,
    broadcast: net_mod.Channel,
    qmdb: net_mod.Channel,
    dkg: net_mod.Channel,
    probe: net_mod.Channel,

    fn register(net: *Net) !Channels {
        var result: Channels = undefined;
        const ids = [_]u64{
            types.vote_channel,     types.certificate_channel, types.resolver_channel,
            types.backfill_channel, types.broadcast_channel,   types.qmdb_channel,
            types.dkg_channel,      types.dkg_probe_channel,
        };
        const names = @typeInfo(Channels).@"struct".field_names;
        comptime assert(names.len == ids.len);
        inline for (names, ids) |name, id| {
            @field(result, name) = try net_mod.register(net, id);
        }
        return result;
    }
};

fn node_channel(channel: net_mod.Channel) Node.Channel {
    return .{ .sender = channel.sender, .receiver = channel.receiver };
}

fn orchestrator_channel(channel: net_mod.Channel) Orchestrator.Channel {
    return .{ .sender = channel.sender, .receiver = channel.receiver };
}

/// Everything one validator runs. Heap-allocated: the actors borrow its fields.
const Validator = struct {
    gpa: Allocator,
    io: Io,
    node_config: config.NodeConfig,
    network: config.NetworkConfig,
    genesis_info: types.EpochInfo,
    participants: types.Participants,
    net: *Net,
    channels: Channels,
    provider: DynamicProvider,
    registrar: provider_mod.Registrar,
    secrets: types.Secrets,
    page_cache: runtime.buffer.paged.CacheRef,
    genesis_block: types.Block,
    plan: Plan,
    node: Node,
    verifier: types.Scheme,
    probe: *Probe,
    probe_mailbox: Probe.ProbeMailbox,
    probe_rng: ProbeRng,
    qmdb: Qmdb.Created,
    dkg_plan: DkgPlan,
    fence: glue_dkg.fence.Fence,
    manager: Manager,
    blocker: Oracle,
    reshare_store: ReshareActor.Store,
    reshare_actor: ReshareActor,
    reshare_mailbox: ReshareActor.Mailbox,
    stateful: *Stateful,
    stateful_mailbox: Stateful.Mailbox,
    wrapper: *Wrapper,
    orchestrator: Orchestrator,
    orchestrator_mailbox: Orchestrator.Mailbox,

    /// Loads the node's configuration and genesis, and starts its network.
    fn init_network(self: *Validator, ctx: Ctx, arena: Allocator, dir: Io.Dir) !void {
        const gpa = self.gpa;
        self.node_config = try config.NodeConfig.load(self.io, arena, dir);
        self.network = try config.NetworkConfig.load(self.io, arena, dir);
        try self.network.validate();
        self.genesis_info = try types.read_genesis(self.io, gpa, dir);
        errdefer self.genesis_info.deinit(gpa);
        // A player's genesis comes only from its own `bootstrap`, which hands the epoch-0
        // share to the validator's store before writing genesis: erase the bootstrap store.
        var bootstrap_store = try types.Secrets.init(self.io, gpa, ctx.storage, .bootstrap);
        defer bootstrap_store.deinit();
        try bootstrap_store.destroy();
        self.participants = try .init(gpa, &self.network);
        errdefer self.participants.deinit(gpa);
        const node = &self.node_config;
        var net_config = try net_mod.network_config(arena, node, &self.network, max_message_size());
        net_config.tracer = ctx.tracer("commonware_p2p");
        const scope = ctx.scope.child("network");
        self.net = try Net.create(gpa, self.io, ctx.network, scope, net_config);
        errdefer self.net.destroy();
        self.channels = try Channels.register(self.net);
        self.blocker = self.net.oracle();
        self.manager = Manager.init(self.net.oracle());
    }

    /// Registers epoch zero's scheme from the genesis output and the stored share.
    fn init_schemes(self: *Validator, ctx: Ctx) !void {
        const gpa = self.gpa;
        self.provider = DynamicProvider.init(gpa, self.io);
        errdefer self.provider.deinit();
        self.registrar = .{ .provider = &self.provider };
        self.secrets = try types.Secrets.init(self.io, gpa, ctx.storage, partition);
        errdefer self.secrets.deinit();
        const share = try self.secrets.get_share(.zero());
        const output = &self.genesis_info.output;
        const players = try output.players.clone(gpa);
        const sharing = try output.public.clone(gpa);
        const local = self.node_config.public_key();
        const info = provider_mod.SchemeInfo.init(local, players, sharing, share);
        try self.registrar.register(self.io, .zero(), info);
        const group = output.public.public();
        self.verifier = try types.Scheme.certificate_verifier(gpa, types.namespace, group);
        assert(self.provider.scheme(.zero()) != null);
    }

    fn genesis(self: *const Validator) !types.Block {
        const info = try self.genesis_info.clone(self.gpa);
        const leader = self.network.participants[0];
        const sync_target = application.Database.initial_sync_targets();
        return types.Block.genesis(self.gpa, leader, info, sync_target);
    }

    /// Opens marshal's archives, broadcast, and backfill, then the probe.
    fn init_marshal(self: *Validator, ctx: Ctx, state_sync: bool) !void {
        const gpa = self.gpa;
        self.page_cache = try .init(gpa, types.page_size, types.page_cache_size);
        errdefer self.page_cache.deinit();
        self.genesis_block = try self.genesis();
        errdefer self.genesis_block.deinit(gpa);
        const env = .{ .gpa = gpa, .storage = ctx.storage };
        self.plan = try Plan.init(env, partition_prefix);
        errdefer self.plan.deinit();
        if (self.plan.should_sync(state_sync)) return error.StateSyncUnsupported;
        const raw = try self.genesis();
        const digested = try Node.Variant.Block.precomputed(gpa, raw, raw.digest());
        try self.node.init(ctx, .{
            .public_key = self.node_config.public_key(),
            .peer_provider = self.net.oracle(),
            .blocker = self.net.oracle(),
            .provider = &self.provider,
            .strategy = .{},
            .partition_prefix = partition_prefix,
            .page_cache = &self.page_cache,
            .genesis = digested,
            .block_codec_config = {},
            .blocks_per_epoch = types.blocks_per_epoch,
            .items_per_section = types.items_per_section,
            .mailbox_size = types.mailbox_size,
            .write_buffer = types.io_buffer_size,
            .replay_buffer = types.io_buffer_size,
            .fetch_timeout = .from_secs(2),
            .fetch_retry_delay = .from_millis(100),
        }, node_channel(self.channels.backfill), node_channel(self.channels.broadcast));
        errdefer self.node.deinit();
        try self.init_probe();
    }

    fn init_probe(self: *Validator) !void {
        const oracle = self.net.oracle();
        const settings = try probe_config(
            ProbeTypes,
            self.gpa,
            Manager.init(oracle),
            oracle,
            &self.genesis_info,
            &self.plan,
            &self.verifier,
        );
        const channel = self.channels.probe;
        const created = try Probe.init(
            self.gpa,
            self.io,
            settings,
            channel.sender,
            channel.receiver,
        );
        self.probe = created.probe;
        self.probe_mailbox = created.mailbox;
        var key: [32]u8 = undefined;
        self.io.random(&key);
        self.probe_rng = ProbeRng.init_key(key);
        assert(self.probe_mailbox.sender.capacity() > 0);
    }

    /// Creates the QMDB resolver and the DKG state-sync plan.
    fn init_sync(self: *Validator, ctx: Ctx) !void {
        const oracle = self.net.oracle();
        self.qmdb = try Qmdb.create(self.gpa, self.io, ctx.scope.child("qmdb_resolver"), .{
            .peer_provider = oracle,
            .blocker = oracle,
            .database = null,
            .mailbox_size = types.mailbox_size,
            .me = self.node_config.public_key(),
            .fetch_timeout = .from_secs(2),
            .fetch_retry_delay = .from_millis(100),
            .max_serve_ops = types.sync_batch_size,
            .priority_requests = false,
            .priority_responses = false,
        });
        errdefer self.qmdb.actor.destroy();
        self.dkg_plan = try DkgPlan.init(self.gpa, self.io, ctx.storage, .{
            .partition_prefix = partition_prefix,
            .max_participants = types.max_participants,
            .max_supported_mode = types.max_supported_mode,
        }, null);
        assert(self.plan.floor() == null);
    }

    /// The reshare actor and its event journal. The orchestrator enters an epoch only once the
    /// reshare actor registers its scheme and marks the fence.
    fn init_reshare(self: *Validator, ctx: Ctx) !void {
        const gpa = self.gpa;
        self.fence = glue_dkg.fence.Fence.init(self.io);
        errdefer self.fence.close();
        self.reshare_store = try ReshareActor.Store.init(gpa, ctx.storage, .{
            .partition_prefix = partition_prefix ++ "-reshare",
            .max_participants = types.max_participants,
            .cache_ref = &self.page_cache,
            .write_buffer = types.io_buffer_size,
            .replay_buffer = types.io_buffer_size,
        }, &self.secrets);
        errdefer self.reshare_store.deinit();
        const scope = ctx.scope.child("reshare");
        self.reshare_actor, self.reshare_mailbox = try ReshareActor.init(gpa, self.io, &scope, .{
            .signer = self.node_config.signer,
            .manager = &self.manager,
            .blocker = &self.blocker,
            .participants_provider = &self.participants,
            .strategy = .{},
            .registrar = &self.registrar,
            .marshal = self.node.mailbox.clone(),
            .fence = &self.fence,
            .namespace = types.namespace,
            .sharing_mode = types.sharing_mode,
            .reveal = types.reveal,
            .mailbox_size = types.mailbox_size,
            .max_participants = types.max_participants,
            .blocks_per_epoch = types.blocks_per_epoch,
        });
        self.reshare_actor.tracer = ctx.tracer(reshare_target);
        assert(self.reshare_actor.mode == .reshare);
    }

    /// The stateful application under the reshare wrapper and `Deferred`.
    fn init_application(self: *Validator, ctx: Ctx, arena: Allocator) !void {
        const gpa = self.gpa;
        const env: glue.stateful.db.Env = .{
            .gpa = gpa,
            .io = self.io,
            .storage = ctx.storage,
            .scope = ctx.scope.child("stateful"),
        };
        self.stateful, self.stateful_mailbox = try Stateful.init(gpa, self.io, .{
            .app = .init(gpa, &self.genesis_block),
            .env = env,
            .db_config = try application.db_config(arena, partition_prefix, &self.page_cache),
            .marshal = self.node.mailbox.clone(),
            .mailbox_size = types.mailbox_size,
            .plan = &self.plan,
        });
        errdefer self.stateful.deinit();
        const blocks = types.blocks_per_epoch;
        const inner = self.stateful_mailbox.clone();
        var app = ReshareApp.init(inner, self.reshare_mailbox.clone(), blocks);
        app.tracer = ctx.tracer(reshare.application.trace_target);
        const length = utils.NonZero(u64).init(blocks).?;
        const marshal = self.node.mailbox.clone();
        self.wrapper = try Wrapper.create(ctx.child("deferred"), app, marshal, .new(length));
        assert(self.wrapper.epocher.length == blocks);
    }

    fn init_orchestrator(self: *Validator, ctx: Ctx) !void {
        const child = ctx.child("orchestrator");
        self.orchestrator, self.orchestrator_mailbox = try Orchestrator.init(child, .{
            .blocker = self.net.oracle(),
            .manager = &self.manager,
            .provider = &self.provider,
            .marshal = self.node.mailbox.clone(),
            .automaton = self.wrapper,
            .relay = self.wrapper,
            .reporter = self.wrapper,
            .strategy = .{},
            .simplex = .{
                .elector = .default(),
                .mailbox_size = 3,
                .replay_buffer = types.io_buffer_size,
                .write_buffer = types.io_buffer_size,
                .page_cache = &self.page_cache,
                .leader_timeout = .from_secs(1),
                .certification_timeout = .from_secs(2),
                .timeout_retry = .from_millis(500),
                .fetch_timeout = .from_secs(2),
                .fetch_retry_delay = .from_millis(100),
                .view_retention = .new(10),
                .skip = .{ .enabled = .{ .timeout = .from_secs(5) } },
                .track_historical_votes = false,
                .forward = .disabled,
            },
            .gate = self.fence.gate(),
            .state_sync = &self.dkg_plan,
            .blocks_per_epoch = types.blocks_per_epoch,
            .mailbox_size = types.mailbox_size,
            .partition_prefix = partition_prefix ++ "-orchestrator",
        });
        assert(self.orchestrator.config.blocks_per_epoch == types.blocks_per_epoch);
    }

    fn init(self: *Validator, ctx: Ctx, arena: Allocator, dir: Io.Dir, state_sync: bool) !void {
        self.gpa = ctx.gpa();
        self.io = ctx.io();
        try self.init_network(ctx, arena, dir);
        try self.init_schemes(ctx);
        try self.init_marshal(ctx, state_sync);
        try self.init_sync(ctx);
        try self.init_reshare(ctx);
        try self.init_application(ctx, arena);
        try self.init_orchestrator(ctx);
    }

    fn reporter(self: *Validator, ctx: Ctx) Reporter {
        return .{
            .stateful = self.stateful_mailbox.clone(),
            .orchestrator = self.orchestrator_mailbox.clone(),
            .reshare = self.reshare_mailbox.clone(),
            .tracer = ctx.tracer(log_target),
        };
    }

    fn reshare_task(ctx: Ctx, self: *Validator) anyerror!void {
        const channel = self.channels.dkg;
        const marshal = &self.node.mailbox;
        const actor = &self.reshare_actor;
        const start = try ReshareRunner.resolve_start(actor, ctx.storage, &self.dkg_plan, marshal);
        const store = &self.reshare_store;
        return ReshareRunner.run(actor, store, channel.sender, channel.receiver, start);
    }

    fn orchestrator_task(_: Ctx, self: *Validator) anyerror!void {
        const c = &self.channels;
        const votes = orchestrator_channel(c.votes);
        const certificates = orchestrator_channel(c.certificates);
        return self.orchestrator.run(votes, certificates, orchestrator_channel(c.resolver));
    }

    fn probe_task(_: Ctx, self: *Validator) anyerror!void {
        return self.probe.run(&self.probe_rng, parallel.sequential);
    }

    fn broadcast_task(_: Ctx, self: *Validator) anyerror!void {
        return self.node.watch_broadcast();
    }

    /// Attaches the application database to the QMDB resolver once `Stateful` opens it, so
    /// the node serves peers' state sync (commonware's `attach_databases` after recovery).
    fn attach_task(self: *Validator) anyerror!void {
        const databases = try self.stateful_mailbox.subscribe_databases();
        try self.qmdb.mailbox.attach_database(databases);
    }

    /// Starts every actor and runs until one stops (commonware's `Handle::select`).
    fn supervise(self: *Validator, ctx: Ctx) anyerror!void {
        const io = self.io;
        const qmdb_channel = self.channels.qmdb;
        var qmdb_task = try self.qmdb.actor.start(qmdb_channel.sender, qmdb_channel.receiver);
        defer _ = qmdb_task.cancel(io) catch {};
        var handles: [5]Handle = undefined;
        handles[0] = try ctx.child("dkg_probe").spawn(probe_task, .{self});
        handles[1] = try ctx.child("reshare").spawn(reshare_task, .{self});
        handles[2] = try ctx.child("orchestrator").spawn(orchestrator_task, .{self});
        handles[3] = try self.node.start(self.reporter(ctx));
        handles[4] = try ctx.child("buffer").spawn(broadcast_task, .{self});
        try self.probe_mailbox.attach(.{ .mailbox = self.node.mailbox.clone() });
        var stateful_task = try self.stateful.start();
        defer _ = stateful_task.cancel(io) catch {};
        var attach = try io.concurrent(attach_task, .{self});
        defer _ = attach.cancel(io) catch {};
        return try runtime.context.select(anyerror!void, io, &handles);
    }

    fn deinit(self: *Validator) void {
        const gpa = self.gpa;
        self.orchestrator.deinit();
        self.orchestrator_mailbox.deinit();
        self.wrapper.destroy();
        self.stateful_mailbox.deinit();
        self.stateful.deinit();
        self.reshare_mailbox.deinit();
        self.reshare_actor.deinit();
        self.reshare_store.deinit();
        self.fence.close();
        self.dkg_plan.deinit();
        self.probe_mailbox.deinit();
        self.probe.deinit();
        self.verifier.deinit(gpa);
        self.node.deinit();
        self.plan.deinit();
        self.genesis_block.deinit(gpa);
        self.page_cache.deinit();
        self.secrets.deinit();
        self.provider.deinit();
        self.net.destroy();
        self.participants.deinit(gpa);
        self.genesis_info.deinit(gpa);
        self.* = undefined;
    }
};

fn run_network(net: *Net) Io.Cancelable!void {
    net.run() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => std.debug.panic("network failed: {t}", .{err}),
    };
}

/// Starts every validator actor from `node_dir` and runs until one stops (commonware
/// `validator::run`).
pub fn run(ctx: Ctx, arena: Allocator, node_dir: []const u8, state_sync: bool) !void {
    const gpa = ctx.gpa();
    const io = ctx.io();
    var dir = try Io.Dir.cwd().openDir(io, node_dir, .{});
    defer dir.close(io);
    const self = try gpa.create(Validator);
    defer gpa.destroy(self);
    try self.init(ctx, arena, dir, state_sync);
    defer self.deinit();
    var network_task = try io.concurrent(run_network, .{self.net});
    defer network_task.cancel(io) catch {};
    self.supervise(ctx) catch |err| {
        ctx.tracer(target).event(.@"error", "validator task failed", .{ .err = err });
    };
}
