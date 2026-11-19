//! One reshare validator with peer state sync (commonware `glue::dkg::tests::reshare::harness`'s
//! `ReshareEngine::init` and `start`): the DKG probe, marshal from `bootstrap.Node` started at
//! the stateful plan's floor, the QMDB resolver, the reshare actor with the DKG state-sync
//! plan, the `Stateful` application under the reshare wrapper, and the orchestrator.
//!
//! A startup the plan says should sync counts in the ledger's `state_sync_starts`, waits for the
//! probe's artifact, registers that epoch's verifier for marshal, optionally waits until the
//! sampled committee has processed into the next epoch (`epoch_cross_during_sync`), and
//! persists its floor: the finalization at `state_sync_floor` read from a running validator's
//! marshal, or the artifact's floor. Once marshal runs, a recorder task stores the floor
//! block's height in the ledger (commonware's `sync_floor_recorder`).
//!
//! Differences from commonware, from zigware's building blocks:
//! - The QMDB resolver borrows the `Stateful` actor's databases, so the stateful task stops
//!   the resolver before the actor closes them (src/glue/stateful/tests/single_db.zig).
//! - Marshal reports to the stateful mailbox, the orchestrator, and the reshare actor, and
//!   sends tips to the plan's monitor; the stateful application records processed heights.
//!
//! `T` declares what `validator.Validator(T)` reads.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const reshare = @import("../../reshare/root.zig");
const orchestrator = @import("../../orchestrator/root.zig");
const dkg_state_sync = @import("../../state_sync.zig");
const probe_mod = @import("../../probe/mod.zig");
const network = @import("../../network.zig");
const Fence = @import("../../fence.zig").Fence;
const bootstrap = @import("../../bootstrap/mod.zig");
const stateful = @import("../../../stateful/mod.zig");
const qmdb_p2p = @import("../../../stateful/db/p2p/mod.zig");
const simulate = @import("../../../simulate/mod.zig");
const mocks = @import("../mocks.zig");
const properties = @import("properties.zig");
const support = @import("support.zig");
const lookup = @import("lookup.zig");
const block_mod = @import("state_sync_block.zig");
const app_mod = @import("state_sync_app.zig");
const validator = @import("validator.zig");

const simplex = consensus.simplex;
const Epoch = consensus.Epoch;
const Height = consensus.Height;
const ed25519 = cryptography.ed25519;
const Key = ed25519.PublicKey;
const Sha256 = cryptography.Sha256;
const SharingMode = cryptography.bls12381.primitives.sharing.Mode;
const FixedEpocher = consensus.types.FixedEpocher;
const Exact = utils.acknowledgement.Exact;
const Handle = runtime.context.Handle(anyerror!void);
const RoundRobin = simplex.elector.RoundRobin(Sha256);

pub const namespace = validator.namespace;
pub const max_participants = validator.max_participants;
pub const epoch_length = validator.epoch_length;
/// commonware `SYNC_BATCH_SIZE`.
pub const sync_batch_size: u64 = 16;
/// commonware's `SyncEngineConfig` for the harness.
pub const sync_config: stateful.db.state_sync.SyncEngineConfig = .{
    .fetch_batch_size = sync_batch_size,
    .apply_batch_size = 64,
    .max_outstanding_requests = 8,
};
const io_buffer_size = 2048;
const mailbox_size = 100;
/// How often the epoch-cross hold rechecks the committee (commonware sleeps 50 ms).
const cross_poll_ms = 50;

/// The probe receiver that swaps each peer's first latest-finalization reply for `reply`, if
/// set (commonware's `Swap`). Owns `inner`, `reply`, and the swapped set.
pub fn Swap(comptime R: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = R.PublicKey;
        const Message = p2p.Message(PublicKey);

        gpa: Allocator,
        inner: R,
        reply: ?[]u8,
        swapped: std.ArrayList(PublicKey) = .empty,

        pub fn recv(self: *Self) !Message {
            var message = try self.inner.recv();
            const reply = self.reply orelse return message;
            const latest = message.payload.len > 0 and
                message.payload[0] == @backingInt(probe_mod.wire.Tag.latest_response);
            if (!latest) return message;
            for (self.swapped.items) |peer| if (peer.eql(message.peer)) return message;
            try self.swapped.append(self.gpa, message.peer);
            const copy = try self.gpa.dupe(u8, reply);
            const peer = message.peer;
            message.deinit();
            assert(self.swapped.items.len > 0);
            return .{ .peer = peer, .payload = copy, .gpa = self.gpa };
        }

        pub fn capacity(self: *const Self) usize {
            return self.inner.capacity();
        }

        pub fn deinit(self: *Self) void {
            if (@hasDecl(R, "deinit")) self.inner.deinit();
            if (self.reply) |reply| self.gpa.free(reply);
            self.swapped.deinit(self.gpa);
            self.* = undefined;
        }
    };
}

pub fn StateSyncValidator(comptime T: type) type {
    return struct {
        const Self = @This();
        const Ctx = T.Context;
        pub const V = T.Variant;
        pub const D = T.Directory;
        pub const Block = block_mod.Block(V, D);
        pub const Digested = broadcast.Digested(Block);
        pub const Info = Block.Info;
        pub const Scheme = simplex.scheme.bls12381_threshold.vrf.Scheme(Block.Digest, Key, V);
        pub const Provider = support.Schemes(Scheme);
        pub const App = app_mod.App(Block);
        const Participants = support.ScheduleParticipants(D);
        const Monitor = simulate.events.Monitor(Key);
        const Update = consensus.marshal.Update(Block, Exact);
        const NodeTypes = struct {
            pub const Block = Self.Block;
            pub const Scheme = Self.Scheme;
            pub const Provider = cryptography.certificate.ConstantProvider(Self.Scheme);
            pub const Strategy = parallel.Sequential;
            pub const Network = T.Network;
            pub const PeerProvider = T.PeerProvider;
            pub const Blocker = T.Blocker;
            pub const Application = MarshalReporter;
            pub const Context = T.Context;
        };
        const Node = bootstrap.Node(NodeTypes);
        pub const MarshalMailbox = Node.Mailbox;
        pub const ReshareTypes = struct {
            pub const Block = Self.Block;
            pub const Ack = Exact;
            pub const Ancestry = consensus.marshal.ancestry.AncestorStream(Node.Mailbox);
            pub const Signer = ed25519.PrivateKey;
            pub const Manager = T.Manager;
            pub const Blocker = T.Blocker;
            pub const Provider = Participants;
            pub const SecretStore = T.SecretStore;
            pub const Registrar = Self.Provider;
            pub const Marshal = Node.Mailbox;
            pub const Strategy = parallel.Sequential;
        };
        const Actor = reshare.actor.Actor(ReshareTypes);
        const Runner = reshare.actor.run.Runner(ReshareTypes);
        const DkgPlan = dkg_state_sync.Plan(Scheme, Block.Digest, V, D);
        pub const SyncPlan = stateful.SyncPlan(Scheme, Node.Variant);
        pub const QmdbActor = qmdb_p2p.actor.Actor(qmdb_p2p.actor.Params(
            Key,
            T.PeerProvider,
            T.Blocker,
            app_mod.Any,
            T.Network.Sender,
            T.Network.Receiver,
        ));
        const StatefulTypes = struct {
            pub const App = Self.App;
            pub const Databases = app_mod.Database;
            pub const Marshal = Node.Mailbox;
            pub const Plan = Self.SyncPlan;
            pub const Resolvers = *QmdbActor.Mailbox;
        };
        const Stateful = stateful.actor.Stateful(StatefulTypes);
        const ReshareApp = reshare.Application(Stateful.Mailbox, ReshareTypes);
        const Wrapper = consensus.marshal.standard.Deferred(
            Ctx,
            Scheme,
            ReshareApp,
            Block,
            FixedEpocher,
        );
        pub const ElectorConfig = RoundRobin;
        const OrchestratorTypes = struct {
            pub const Context = T.Context;
            pub const Block = Self.Block;
            pub const Ack = Exact;
            pub const Scheme = Self.Scheme;
            pub const Provider = *const Self.Provider;
            pub const Manager = *T.Manager;
            pub const Marshal = Node.Mailbox;
            pub const Blocker = T.Blocker;
            pub const ElectorConfig = RoundRobin;
            pub const Elector = simplex.elector.RoundRobinElector;
            pub const Automaton = *Wrapper;
            pub const Relay = *Wrapper;
            pub const Reporter = *Wrapper;
            pub const Strategy = parallel.Sequential;
            pub const Sender = T.Network.Sender;
            pub const Receiver = T.Network.Receiver;

            pub fn build_elector(config: RoundRobin, gpa: Allocator, n: u32) !Elector {
                return config.build(gpa, n);
            }
        };
        const Orchestrator = orchestrator.Actor(OrchestratorTypes);
        const ProbeTypes = struct {
            pub const Scheme = Self.Scheme;
            pub const Variant = Node.Variant;
            pub const Manager = T.Manager;
            pub const Source = probe_mod.MarshalSource(Node.Mailbox);
            pub const Blocker = T.Blocker;
            pub const NetSender = T.Network.Sender;
            pub const NetReceiver = Swap(T.Network.Receiver);
        };
        const Probe = probe_mod.Probe(ProbeTypes);
        const Wire = probe_mod.wire.Message(Scheme, Node.Variant);
        const Artifact = Probe.Artifact;
        const Finalization = Artifact.Finalization;
        pub const Channel = Node.Channel;

        /// commonware's eight validator channels, in registration order.
        pub const Channels = struct {
            votes: Channel,
            certificates: Channel,
            resolver: Channel,
            backfill: Channel,
            broadcast: Channel,
            qmdb: Channel,
            dkg: Channel,
            probe: Channel,
        };

        /// A marshal mailbox clone a slot's holder owns, published once marshal is up.
        pub const MarshalSlot = struct { mailbox: ?MarshalMailbox = null };

        pub const Config = struct {
            signer: ed25519.PrivateKey,
            /// Borrowed.
            manager: *T.Manager,
            peer_provider: T.PeerProvider,
            blocker: T.Blocker,
            /// Borrowed; survives restarts.
            secret_store: *T.SecretStore,
            /// Borrowed; survives restarts.
            ledger: *support.Ledger,
            monitor: ?Monitor,
            schedule: properties.CommitteeSchedule,
            /// Epoch zero's info, carried by genesis (borrowed).
            initial: *const Info,
            /// Which transport the directories address (commonware `Network`).
            network: lookup.Network,
            sharing_mode: SharingMode,
            elector: RoundRobin,
            /// Owned by the caller; outlives the validator.
            partition_prefix: []const u8,
            /// Whether the plan delayed this validator (commonware's `delayed`).
            delayed: bool,
            /// The height whose finalization a state-sync startup takes as its floor, from
            /// another validator's marshal; null takes the probe artifact's floor.
            state_sync_floor: ?u64 = null,
            /// Hold a state-sync startup until the sampled committee crosses an epoch.
            epoch_cross_during_sync: bool = false,
            /// On a restart, swap each bootstrap member's first latest reply to the probe for
            /// the finalization at this height from another validator (commonware
            /// `with_stale`).
            stale: ?u64 = null,
            /// Whether this validator ran before in this run.
            restarted: bool = false,
            /// Every validator's marshal slot, by participant index (borrowed). This
            /// validator publishes its own into `marshals[index]`.
            marshals: []MarshalSlot,
            index: usize,
        };

        /// Marshal's reporter: the stateful application, then the orchestrator, then the
        /// reshare actor (commonware's `MonitorReporter` over `Reporters`); tips also reach
        /// the plan's monitor.
        const MarshalReporter = struct {
            pub const Activity = Update;
            key: Key,
            monitor: ?Monitor,
            stateful_mailbox: Stateful.Mailbox,
            orchestrator_mailbox: Orchestrator.Mailbox,
            reshare_mailbox: Actor.Mailbox,

            pub fn report(self: *MarshalReporter, update: Update) consensus.Feedback {
                if (update == .tip) if (self.monitor) |monitor| {
                    const tip = update.tip;
                    _ = monitor.send(.{
                        .pk = self.key,
                        .round = tip.round,
                        .height = tip.height,
                        .block_digest = tip.digest.as_slice(),
                    });
                };
                const first = self.stateful_mailbox.report(copy_of(update));
                const second = self.orchestrator_mailbox.report(copy_of(update));
                const third = self.reshare_mailbox.report(update);
                return consensus.reporter.combine(consensus.reporter.combine(first, second), third);
            }

            fn copy_of(update: Update) Update {
                return switch (update) {
                    .tip => update,
                    .block => |value| .{ .block = .{
                        .block = value.block.clone(),
                        .ack = value.ack.clone(),
                    } },
                };
            }

            pub fn clone(self: *const MarshalReporter) MarshalReporter {
                var copy = self.*;
                copy.stateful_mailbox = self.stateful_mailbox.clone();
                copy.orchestrator_mailbox = self.orchestrator_mailbox.clone();
                copy.reshare_mailbox = self.reshare_mailbox.clone();
                return copy;
            }

            pub fn deinit(self: *MarshalReporter) void {
                self.stateful_mailbox.deinit();
                self.orchestrator_mailbox.deinit();
                self.reshare_mailbox.deinit();
                self.* = undefined;
            }
        };

        gpa: Allocator,
        io: Io,
        config: Config,
        key: Key,
        page_cache: runtime.buffer.paged.CacheRef,
        /// The certificate verifier against the initial group key (marshal's and the probe's).
        verifier: Scheme,
        provider: Self.Provider,
        participants: Participants,
        blocker: T.Blocker,
        genesis_block: Block,
        plan: SyncPlan,
        should_sync: bool,
        probe: Probe.Created,
        probe_rng: utils.rng.TestRng,
        probe_handle: ?Handle,
        /// The probe's artifact, when this startup syncs; moved into the DKG plan.
        artifact: ?Artifact,
        node: Node,
        qmdb: QmdbActor.Mailbox,
        /// Freed by its task once started, else by `deinit`.
        qmdb_actor: *QmdbActor,
        qmdb_started: bool,
        /// Canceled by the stateful task, or by `deinit` if it never ran.
        qmdb_task: ?Io.Future(QmdbActor.Error!void),
        dkg_plan: DkgPlan,
        fence: Fence,
        store: Actor.Store,
        actor: Actor,
        reshare_mailbox: Actor.Mailbox,
        stateful_actor: *Stateful,
        stateful_mailbox: Stateful.Mailbox,
        wrapper: *Wrapper,
        orchestrator_actor: Orchestrator,
        orchestrator_mailbox: Orchestrator.Mailbox,
        orchestrator_ctx: Ctx,
        recorder: ?Handle,
        /// `-reshare`, `-orchestrator`, `-dkg`, and the three QMDB partitions.
        partitions: [6][]u8,

        /// Runs the validator under `ctx` until one of its actors stops.
        pub fn run(ctx: Ctx, config: Config, channels: Channels) anyerror!void {
            const gpa = ctx.gpa();
            const self = try gpa.create(Self);
            defer gpa.destroy(self);
            try self.init(ctx, config, channels);
            defer self.deinit();
            return self.supervise(ctx, channels);
        }

        fn init(self: *Self, ctx: Ctx, config: Config, channels: Channels) !void {
            self.gpa = ctx.gpa();
            self.io = ctx.io();
            self.config = config;
            self.key = config.signer.public_key();
            self.blocker = config.blocker;
            self.probe_handle = null;
            self.artifact = null;
            self.qmdb_task = null;
            self.qmdb_started = false;
            self.recorder = null;
            try self.init_partitions();
            errdefer self.free_partitions();
            try self.init_schemes();
            errdefer self.deinit_schemes();
            try self.init_plan(ctx);
            errdefer self.deinit_plan();
            try self.init_probe(ctx, channels.probe);
            errdefer self.deinit_probe();
            // Until `supervise` hands them to their actors, this validator owns the other
            // channels: a crash in `select_floor` must not leak them.
            var node_took = false;
            errdefer release_unstarted(channels, node_took);
            try self.select_floor();
            try self.init_node(ctx, channels, &node_took);
            errdefer self.node.deinit();
            try self.init_qmdb(ctx);
            errdefer self.deinit_qmdb();
            try self.init_reshare(ctx);
            errdefer self.deinit_reshare();
            try self.init_stateful(ctx);
            errdefer self.deinit_stateful();
            try self.init_orchestrator(ctx);
            assert(self.should_sync == (self.plan.floor() != null) or !self.plan.may_sync());
        }

        fn init_partitions(self: *Self) !void {
            const suffixes = [_][]const u8{
                "-reshare",          "-orchestrator",      "",
                "-qmdb-mmr-journal", "-qmdb-mmr-metadata", "-qmdb-log-journal",
            };
            var made: usize = 0;
            errdefer for (self.partitions[0..made]) |name| self.gpa.free(name);
            for (&self.partitions, suffixes) |*name, suffix| {
                name.* = try std.mem.concat(self.gpa, u8, &.{
                    self.config.partition_prefix,
                    suffix,
                });
                made += 1;
            }
            assert(made == self.partitions.len);
        }

        fn free_partitions(self: *Self) void {
            for (self.partitions) |name| self.gpa.free(name);
        }

        /// The page cache, marshal's verifier, and epoch zero's scheme from the stored share.
        fn init_schemes(self: *Self) !void {
            const gpa = self.gpa;
            const config = &self.config;
            // commonware `PAGE_SIZE` and `PAGE_CACHE_SIZE`.
            self.page_cache = try .init(gpa, 1024, 10);
            errdefer self.page_cache.deinit();
            const identity = config.initial.output.public.public();
            self.verifier = try Scheme.certificate_verifier(gpa, namespace, identity);
            errdefer self.verifier.deinit(gpa);
            self.provider = .{
                .gpa = gpa,
                .namespace = namespace,
                .key = self.key,
                .ledger = config.ledger,
            };
            errdefer self.provider.deinit();
            const share = try config.secret_store.get_share(Epoch.zero());
            var players = try config.initial.output.players.clone(gpa);
            errdefer players.deinit(gpa);
            const sharing = try config.initial.output.public.clone(gpa);
            const info = types.SchemeInfo(V, Key).init(self.key, players, sharing, share);
            _ = try self.provider.install(Epoch.zero(), info);
            self.participants = .{
                .schedule = config.schedule,
                .network = config.network,
            };
            assert(self.provider.scheme(Epoch.zero()) != null);
        }

        fn deinit_schemes(self: *Self) void {
            self.provider.deinit();
            self.verifier.deinit(self.gpa);
            self.page_cache.deinit();
        }

        /// The genesis block and the stateful plan; decides whether this startup syncs.
        fn init_plan(self: *Self, ctx: Ctx) !void {
            const gpa = self.gpa;
            const config = &self.config;
            const info = try config.initial.clone(gpa);
            const leader = config.schedule.participants[0];
            const target = app_mod.Any.initial_sync_target();
            self.genesis_block = try Block.genesis(gpa, leader, info, target);
            errdefer self.genesis_block.deinit(gpa);
            const env = .{ .gpa = gpa, .storage = ctx.storage };
            self.plan = try SyncPlan.init(env, config.partition_prefix);
            self.should_sync = self.plan.should_sync(config.delayed);
            if (self.should_sync) config.ledger.record_state_sync_start(self.key);
            assert(!self.should_sync or self.plan.may_sync());
        }

        fn deinit_plan(self: *Self) void {
            self.plan.deinit();
            self.genesis_block.deinit(self.gpa);
        }

        /// The DKG probe, bootstrapped from epoch zero's participants and floored at a
        /// persisted floor's epoch (commonware's `dkg_probe::Config`), and its task.
        fn init_probe(self: *Self, ctx: Ctx, channel: Channel) !void {
            const gpa = self.gpa;
            const initial = self.config.initial;
            var participants = try initial.participants(gpa);
            errdefer participants.deinit(gpa);
            const directory = try network.DirectoryOps(Key, D).clone(initial.directory, gpa);
            const genesis = try initial.clone(gpa);
            const floor_epoch: ?Epoch = if (self.plan.floor()) |floor| floor.epoch() else null;
            const reply = try self.stale_reply();
            errdefer if (reply) |bytes| gpa.free(bytes);
            self.probe = try Probe.init(gpa, self.io, .{
                .discovery = .{
                    .manager = self.config.manager.*,
                    .bootstrap = .{
                        .epoch = .zero(),
                        .participants = participants,
                        .directory = directory,
                    },
                    .floor_epoch = floor_epoch,
                    .verifier = &self.verifier,
                    .genesis = genesis,
                    .blocker = self.config.blocker,
                    .blocks_per_epoch = epoch_length,
                    .block_cfg = block_cfg,
                },
                .retry_timeout_ns = 500 * std.time.ns_per_ms,
                .mailbox_size = mailbox_size,
            }, channel.sender, .{
                .gpa = gpa,
                .inner = channel.receiver,
                .reply = reply,
            });
            errdefer {
                self.probe.probe.deinit();
                self.probe.mailbox.deinit();
            }
            self.probe_rng = .init(self.config.index);
            self.probe_handle = try ctx.child("dkg_probe").spawn(probe_task, .{self});
            assert(self.probe_handle != null);
        }

        /// The encoded latest reply a stale restart swaps in, or null (owned by the caller).
        fn stale_reply(self: *Self) !?[]u8 {
            const height = self.config.stale orelse return null;
            if (!self.config.restarted) return null;
            var finalization = try self.finalization_from_peer(height);
            defer finalization.deinit(self.gpa);
            const message: Wire = .{ .latest_response = finalization };
            const bytes = try message.encode(self.gpa);
            assert(bytes[0] == @backingInt(probe_mod.wire.Tag.latest_response));
            return bytes;
        }

        const block_cfg: types.InfoCfg = .{
            .max_participants = max_participants,
            .max_supported_mode = mocks.max_supported_mode,
        };

        fn probe_task(_: Ctx, self: *Self) anyerror!void {
            return self.probe.probe.run(&self.probe_rng, parallel.sequential);
        }

        fn deinit_probe(self: *Self) void {
            if (self.probe_handle) |*handle| {
                if (handle.abort()) |result| result catch {} else |_| {}
            }
            self.probe_handle = null;
            if (self.artifact) |*artifact| artifact.deinit();
            self.artifact = null;
            self.probe.probe.deinit();
            self.probe.mailbox.deinit();
        }

        /// commonware's `should_state_sync` branch: the probe's artifact, its epoch's
        /// verifier, the optional epoch-cross hold, and the persisted floor.
        fn select_floor(self: *Self) !void {
            if (!self.should_sync) return;
            const gpa = self.gpa;
            var receiver = try self.probe.mailbox.subscribe();
            defer receiver.deinit();
            // A crash cancels this wait; it must reach `run_node` as Canceled.
            self.artifact = receiver.recv() catch |err| {
                return if (err == error.Canceled) error.Canceled else error.ProbeStopped;
            };
            const artifact = &self.artifact.?;
            const output = &artifact.info.output;
            const players = try output.players.clone(gpa);
            const sharing = try output.public.clone(gpa);
            const info = types.SchemeInfo(V, Key).init(self.key, players, sharing, null);
            // commonware registers on the provider directly, so the ledger records nothing.
            _ = try self.provider.install(artifact.info.epoch, info);
            if (self.config.epoch_cross_during_sync) try self.await_epoch_cross();
            if (self.config.state_sync_floor) |height| {
                var finalization = try self.finalization_from_peer(height);
                defer finalization.deinit(gpa);
                try self.plan.set_floor(&finalization);
            } else {
                try self.plan.set_floor(&artifact.floor);
            }
            assert(self.plan.floor() != null);
        }

        /// Waits until every member of the sampled committee processed past the next epoch's
        /// first height.
        fn await_epoch_cross(self: *Self) !void {
            const artifact = &self.artifact.?;
            const committee = &artifact.info.output.players;
            assert(committee.position(self.key) == null);
            const epocher: FixedEpocher = .new(utils.NonZero(u64).init(epoch_length).?);
            const target = (epocher.first(artifact.info.epoch.next()) orelse
                return error.UnsupportedEpoch).get();
            while (true) {
                var crossed = true;
                for (committee.items) |member| {
                    if (self.config.ledger.processed_of(member) <= target) crossed = false;
                }
                if (crossed) return;
                try self.io.sleep(.fromMilliseconds(cross_poll_ms), .awake);
            }
        }

        /// The finalization at `height` from the first other validator's running marshal.
        fn finalization_from_peer(self: *Self, height: u64) !Finalization {
            for (self.config.marshals, 0..) |slot, at| {
                if (at == self.config.index) continue;
                const mailbox = slot.mailbox orelse continue;
                const found = try mailbox.get_finalization(.new(height));
                return found orelse @panic("configured state-sync floor must be finalized");
            }
            @panic("state-sync floor source must be available");
        }

        /// Releases the channels `supervise` would have taken, and backfill and broadcast
        /// unless the node took them.
        fn release_unstarted(channels: Channels, node_took: bool) void {
            var owned = channels;
            assert(@sizeOf(Channels) > 0);
            for ([_]*Channel{
                &owned.votes, &owned.certificates, &owned.resolver,
                &owned.qmdb,  &owned.dkg,
            }) |channel| release_channel(channel);
            if (node_took) return;
            release_channel(&owned.backfill);
            release_channel(&owned.broadcast);
        }

        fn release_channel(channel: *Channel) void {
            channel.sender.deinit();
            channel.receiver.inner.deinit();
            channel.* = undefined;
        }

        /// Sets `node_took` once `node.init` has taken backfill and broadcast.
        fn init_node(self: *Self, ctx: Ctx, channels: Channels, node_took: *bool) !void {
            assert(!node_took.*);
            const gpa = self.gpa;
            const config = &self.config;
            const raw = try self.genesis_block.clone(gpa);
            const genesis = try Digested.precomputed(gpa, raw, raw.digest());
            var start: ?Node.Start = null;
            if (self.plan.floor()) |floor| start = .{ .floor = try floor.clone(gpa) };
            errdefer if (start) |*value| switch (value.*) {
                .genesis => |*block| block.deinit(),
                .floor => |*finalization| finalization.deinit(gpa),
            };
            node_took.* = true; // `node.init` takes both channels on every path.
            try self.node.init(ctx, .{
                .public_key = self.key,
                .peer_provider = config.peer_provider,
                .blocker = config.blocker,
                .provider = .init(&self.verifier),
                .strategy = .{},
                .partition_prefix = config.partition_prefix,
                .page_cache = &self.page_cache,
                .genesis = genesis,
                .start = start,
                .block_codec_config = block_cfg,
                .blocks_per_epoch = epoch_length,
                .items_per_section = 10,
                .mailbox_size = mailbox_size,
                .write_buffer = io_buffer_size,
                .replay_buffer = io_buffer_size,
                .fetch_timeout = .from_secs(2),
                .fetch_retry_delay = .from_millis(100),
            }, channels.backfill, channels.broadcast);
            start = null; // The node took it.
            const slot = &config.marshals[config.index];
            if (slot.mailbox) |*stale| stale.deinit();
            slot.mailbox = self.node.mailbox.clone();
        }

        fn init_qmdb(self: *Self, ctx: Ctx) !void {
            const created = try QmdbActor.create(self.gpa, self.io, ctx.scope.child("qmdb"), .{
                .peer_provider = self.config.peer_provider,
                .blocker = self.config.blocker,
                .database = null,
                .mailbox_size = mailbox_size,
                .me = self.key,
                .fetch_timeout = .from_secs(2),
                .fetch_retry_delay = .from_millis(100),
                .max_serve_ops = sync_batch_size,
                .priority_requests = false,
                .priority_responses = false,
            });
            self.qmdb = created.mailbox;
            self.qmdb_actor = created.actor;
            assert(self.qmdb_task == null);
        }

        fn deinit_qmdb(self: *Self) void {
            if (!self.qmdb_started) self.qmdb_actor.destroy();
            self.stop_qmdb();
            self.qmdb.deinit();
        }

        /// Stops the resolver; its task frees the actor and its serve tasks when it returns.
        fn stop_qmdb(self: *Self) void {
            var task = self.qmdb_task orelse return;
            self.qmdb_task = null;
            _ = task.cancel(self.io) catch {};
            assert(self.qmdb_task == null);
        }

        fn init_reshare(self: *Self, ctx: Ctx) !void {
            const gpa = self.gpa;
            const config = &self.config;
            var material: ?DkgPlan.Material = null;
            if (self.artifact) |*artifact| {
                var info = try artifact.info.clone(gpa);
                errdefer info.deinit(gpa);
                const floor = try self.plan.floor().?.clone(gpa);
                material = .{ .info = info, .floor = floor };
                artifact.deinit();
                self.artifact = null;
            }
            self.dkg_plan = try DkgPlan.init(gpa, self.io, ctx.storage, .{
                .partition_prefix = self.partitions[2],
                .max_participants = max_participants,
                .max_supported_mode = mocks.max_supported_mode,
            }, material);
            errdefer self.dkg_plan.deinit();
            self.fence = Fence.init(self.io);
            errdefer self.fence.close();
            self.store = try Actor.Store.init(gpa, ctx.storage, .{
                .partition_prefix = self.partitions[0],
                .max_participants = max_participants,
                .cache_ref = &self.page_cache,
                .write_buffer = io_buffer_size,
                .replay_buffer = io_buffer_size,
            }, config.secret_store);
            errdefer self.store.deinit();
            const scope = ctx.scope.child("reshare");
            self.actor, self.reshare_mailbox = try Actor.init(gpa, self.io, &scope, .{
                .signer = config.signer,
                .manager = config.manager,
                .blocker = &self.blocker,
                .participants_provider = &self.participants,
                .strategy = .{},
                .registrar = &self.provider,
                .marshal = self.node.mailbox.clone(),
                .fence = &self.fence,
                .namespace = namespace,
                .sharing_mode = config.sharing_mode,
                .reveal = .v1,
                .mailbox_size = mailbox_size,
                .max_participants = max_participants,
                .blocks_per_epoch = epoch_length,
            });
            assert(self.actor.mode == .reshare);
        }

        fn deinit_reshare(self: *Self) void {
            self.reshare_mailbox.deinit();
            self.actor.deinit();
            self.store.deinit();
            self.fence.close();
            self.dkg_plan.deinit();
        }

        fn db_config(self: *const Self) app_mod.Any.Config {
            return .{
                .merkle = .{
                    .journal_partition = self.partitions[3],
                    .metadata_partition = self.partitions[4],
                    .items_per_blob = 11,
                    .write_buffer = io_buffer_size,
                    .replay_buffer = io_buffer_size,
                    .cache_ref = @constCast(&self.page_cache),
                },
                .log = .{
                    .partition = self.partitions[5],
                    .items_per_blob = 7,
                    .cache_ref = @constCast(&self.page_cache),
                    .write_buffer = io_buffer_size,
                    .replay_buffer = io_buffer_size,
                },
                .translator = .{},
                .init_cache = 1024,
            };
        }

        fn init_stateful(self: *Self, ctx: Ctx) !void {
            const env: stateful.db.Env = .{
                .gpa = self.gpa,
                .io = self.io,
                .storage = ctx.storage,
                .scope = ctx.scope.child("stateful"),
            };
            self.stateful_actor, self.stateful_mailbox = try Stateful.init(self.gpa, self.io, .{
                .app = .{
                    .gpa = self.gpa,
                    .genesis_block = &self.genesis_block,
                    .ledger = self.config.ledger,
                    .key = self.key,
                },
                .env = env,
                .db_config = self.db_config(),
                .marshal = self.node.mailbox.clone(),
                .mailbox_size = mailbox_size,
                .plan = &self.plan,
                .sync_config = sync_config,
                .resolvers = &self.qmdb,
                .floor = self.node.floor,
            });
            assert(self.should_sync == (self.plan.floor() != null) or !self.plan.may_sync());
        }

        fn deinit_stateful(self: *Self) void {
            self.stateful_mailbox.deinit();
            self.stateful_actor.deinit();
        }

        fn init_orchestrator(self: *Self, ctx: Ctx) !void {
            const length = utils.NonZero(u64).init(epoch_length).?;
            const inner = self.stateful_mailbox.clone();
            const app = ReshareApp.init(inner, self.reshare_mailbox.clone(), epoch_length);
            const marshal = self.node.mailbox.clone();
            self.wrapper = try Wrapper.create(ctx.child("deferred"), app, marshal, .new(length));
            errdefer self.wrapper.destroy();
            self.orchestrator_ctx = ctx.child("orchestrator");
            self.orchestrator_actor, self.orchestrator_mailbox = try Orchestrator.init(
                self.orchestrator_ctx,
                self.orchestrator_config(),
            );
        }

        fn orchestrator_config(self: *Self) orchestrator.actor.Config(OrchestratorTypes) {
            return .{
                .blocker = self.config.blocker,
                .manager = self.config.manager,
                .provider = &self.provider,
                .marshal = self.node.mailbox.clone(),
                .automaton = self.wrapper,
                .relay = self.wrapper,
                .reporter = self.wrapper,
                .strategy = .{},
                .simplex = .{
                    .elector = self.config.elector,
                    .mailbox_size = 3,
                    .replay_buffer = io_buffer_size,
                    .write_buffer = io_buffer_size,
                    .page_cache = &self.page_cache,
                    .leader_timeout = .from_secs(1),
                    .certification_timeout = .from_secs(2),
                    .timeout_retry = .from_millis(500),
                    .fetch_timeout = .from_secs(2),
                    .fetch_retry_delay = .from_secs(2),
                    .view_retention = .new(10),
                    .skip = .{ .enabled = .{ .timeout = .from_secs(5) } },
                    .track_historical_votes = false,
                    .forward = .disabled,
                },
                .gate = self.fence.gate(),
                .state_sync = &self.dkg_plan,
                .blocks_per_epoch = epoch_length,
                .mailbox_size = mailbox_size,
                .partition_prefix = self.partitions[1],
            };
        }

        fn ReshareTask(comptime Sender: type, comptime Receiver: type) type {
            return struct {
                fn run(ctx: Ctx, self: *Self, sender: Sender, receiver: Receiver) anyerror!void {
                    const marshal = &self.node.mailbox;
                    const plan = &self.dkg_plan;
                    const start = try Runner.resolve_start(&self.actor, ctx.storage, plan, marshal);
                    return Runner.run(&self.actor, &self.store, sender, receiver, start);
                }
            };
        }

        fn orchestrator_task(
            _: Ctx,
            self: *Self,
            votes: Channel,
            certificates: Channel,
            resolver: Channel,
        ) anyerror!void {
            const convert = struct {
                fn channel(raw: Channel) Orchestrator.Channel {
                    return .{ .sender = raw.sender, .receiver = raw.receiver };
                }
            }.channel;
            const actor = &self.orchestrator_actor;
            return actor.run(convert(votes), convert(certificates), convert(resolver));
        }

        fn buffer_task(_: Ctx, self: *Self) anyerror!void {
            return self.node.watch_broadcast();
        }

        /// Runs the actor, stopping the QMDB resolver first when it ends or is aborted: the
        /// resolver borrows the databases the actor closes on its way out.
        fn stateful_task(_: Ctx, self: *Self) anyerror!void {
            const Done = union(enum) { actor: anyerror!void };
            var buffer: [1]Done = undefined;
            var select: Io.Select(Done) = .init(self.io, &buffer);
            select.concurrent(.actor, Stateful.run, .{self.stateful_actor}) catch |err| {
                self.stop_qmdb();
                return err;
            };
            const done = select.await() catch |err| {
                self.stop_qmdb();
                while (select.cancel()) |_| {}
                return err;
            };
            self.stop_qmdb();
            return done.actor;
        }

        /// Records the height of the floor block once marshal has it (commonware's
        /// `sync_floor_recorder`), without delaying the other actors.
        fn recorder_task(_: Ctx, self: *Self, payload: Block.Digest) anyerror!void {
            var receiver = try self.node.mailbox.subscribe_by_commitment(payload, .wait);
            defer receiver.deinit();
            var block = receiver.recv() catch |err| {
                if (err == error.Canceled) return error.Canceled;
                return;
            };
            defer block.deinit();
            const height = block.inner().height().get();
            self.config.ledger.record_state_sync(self.key, height);
            assert(self.config.ledger.state_sync_of(self.key) == height);
            // Parked until aborted, so it never ends the validator's select.
            while (true) try self.io.sleep(.fromSeconds(3600), .awake);
        }

        fn supervise(self: *Self, ctx: Ctx, channels: Channels) anyerror!void {
            const Task = ReshareTask(T.Network.Sender, T.Network.Receiver);
            const qmdb = channels.qmdb;
            self.qmdb_task = try self.qmdb_actor.start(qmdb.sender, qmdb.receiver);
            self.qmdb_started = true;
            var handles: [6]Handle = undefined;
            handles[0] = try ctx.child("stateful").spawn(stateful_task, .{self});
            handles[1] = try self.node.start(.{
                .key = self.key,
                .monitor = self.config.monitor,
                .stateful_mailbox = self.stateful_mailbox.clone(),
                .orchestrator_mailbox = self.orchestrator_mailbox.clone(),
                .reshare_mailbox = self.reshare_mailbox.clone(),
            });
            const dkg = channels.dkg;
            const reshare_args = .{ self, dkg.sender, dkg.receiver };
            handles[2] = try ctx.child("reshare").spawn(Task.run, reshare_args);
            const args = .{ self, channels.votes, channels.certificates, channels.resolver };
            handles[3] = try self.orchestrator_ctx.spawn(orchestrator_task, args);
            handles[4] = try ctx.child("buffer").spawn(buffer_task, .{self});
            handles[5] = self.probe_handle.?;
            self.probe_handle = null;
            try self.probe.mailbox.attach(.{ .mailbox = self.node.mailbox.clone() });
            if (self.should_sync) {
                const payload = self.plan.floor().?.proposal.payload;
                const recorder_ctx = ctx.child("sync_floor_recorder");
                self.recorder = try recorder_ctx.spawn(recorder_task, .{ self, payload });
            }
            const first = try runtime.context.select(anyerror!void, self.io, &handles);
            return first;
        }

        fn deinit(self: *Self) void {
            if (self.recorder) |*handle| {
                if (handle.abort()) |result| result catch {} else |_| {}
            }
            self.orchestrator_mailbox.deinit();
            self.orchestrator_actor.deinit();
            self.wrapper.destroy();
            self.deinit_stateful();
            self.deinit_reshare();
            self.deinit_qmdb();
            self.node.deinit();
            self.deinit_probe();
            self.deinit_plan();
            self.deinit_schemes();
            self.free_partitions();
            self.* = undefined;
        }
    };
}

const harness = @import("harness.zig");
const Net = p2p.simulated.Network(Key);
pub const Validator = StateSyncValidator(harness.Types);

/// commonware's eight channels: votes, certificates, resolver, backfill, broadcast, qmdb,
/// dkg, and the probe's.
const channel_count = 8;
const dkg_channel = 6;
const test_quota = p2p.Quota.per_second(1024);

/// A validator's view for the properties (commonware `ValidatorState`).
pub const ValidatorState = struct {
    pub const Info = Validator.Info;

    gpa: Allocator,
    key: Key,
    /// Borrowed from the engine definition.
    ledger: *const support.Ledger,
    /// Borrowed from the engine definition; `deinit_state` releases its mailbox, which must
    /// not outlive the run's runtime.
    marshal: *Validator.MarshalSlot,

    pub fn public_key(self: *const ValidatorState) Key {
        return self.key;
    }

    pub fn processed_height(self: *const ValidatorState) u64 {
        return self.ledger.processed_of(self.key);
    }

    pub fn registrations(self: *const ValidatorState) []const properties.Registration {
        return self.ledger.registrations_of(self.key);
    }

    pub fn state_sync_height(self: *const ValidatorState) ?u64 {
        return self.ledger.state_sync_of(self.key);
    }

    /// What this validator's finalized block at `height` carries.
    pub fn boundary(
        self: *const ValidatorState,
        gpa: Allocator,
        height: u64,
    ) !properties.Boundary(Validator.Info) {
        const mailbox = self.marshal.mailbox orelse return .missing;
        var block = try mailbox.get_block(.{ .height = .new(height) }) orelse return .missing;
        defer block.deinit();
        const info = block.inner().epoch_info() orelse {
            return if (try block.inner().payload(gpa)) |payload| other: {
                var owned = payload;
                owned.deinit(gpa);
                break :other .other_payload;
            } else .no_payload;
        };
        return .{ .info = try info.clone(gpa) };
    }
};

/// What the plan starts for one validator.
pub const Started = struct {
    context: simulate.engine.Context,
    config: Validator.Config,
    channels: Validator.Channels,
};

/// The state-sync harness's engine definition (commonware `ReshareEngine` with its state-sync
/// options): `base`'s participants, initial deal, secret stores, and ledger, with every
/// validator a `StateSyncValidator`.
pub const StateSyncEngine = struct {
    pub const PublicKey = Key;
    pub const Engine = Started;
    pub const State = ValidatorState;

    base: harness.ReshareEngine,
    /// Every validator's marshal mailbox while it runs, by participant index.
    marshals: []Validator.MarshalSlot,
    /// How many times each validator started, by participant index.
    boots: []u32,
    elector: Validator.ElectorConfig = .default(),
    /// commonware `with_state_sync_floor`.
    state_sync_floor: ?u64 = null,
    /// commonware `with_epoch_cross_during_sync`.
    epoch_cross_during_sync: bool = false,
    /// commonware `with_stale`.
    stale: ?u64 = null,

    /// Takes `base`.
    pub fn from_base(base: harness.ReshareEngine) !StateSyncEngine {
        const gpa = base.gpa;
        const total = base.keys.len;
        const marshals = try gpa.alloc(Validator.MarshalSlot, total);
        errdefer gpa.free(marshals);
        for (marshals) |*slot| slot.* = .{};
        const boots = try gpa.alloc(u32, total);
        @memset(boots, 0);
        return .{ .base = base, .marshals = marshals, .boots = boots };
    }

    /// commonware `ReshareEngine::with_committee`.
    pub fn with_committee(
        gpa: Allocator,
        network_kind: harness.lookup.Network,
        total: u32,
        committee_size: usize,
    ) !StateSyncEngine {
        const sizes = &.{committee_size};
        var base = try harness.ReshareEngine.with_network(gpa, network_kind, total, sizes, 1);
        errdefer base.deinit();
        return from_base(base);
    }

    pub fn deinit(self: *StateSyncEngine) void {
        const gpa = self.base.gpa;
        for (self.marshals) |*slot| if (slot.mailbox) |*mailbox| mailbox.deinit();
        gpa.free(self.marshals);
        gpa.free(self.boots);
        self.base.deinit();
        self.* = undefined;
    }

    /// commonware `with_processed_hold`.
    pub fn with_processed_hold(self: *StateSyncEngine, key: Key, height: u64) void {
        self.base.ledger.hold = .{ .key = key, .height = height };
    }

    pub fn participants(self: *const StateSyncEngine) []const Key {
        return self.base.keys;
    }

    pub fn ledger(self: *const StateSyncEngine) *const support.Ledger {
        return &self.base.ledger;
    }

    pub fn schedule(self: *const StateSyncEngine) properties.CommitteeSchedule {
        return self.base.schedule();
    }

    pub fn channels(_: *const StateSyncEngine) []const simulate.ChannelSpec {
        const specs = comptime blk: {
            var list: [channel_count]simulate.ChannelSpec = undefined;
            for (&list, 0..) |*spec, index| spec.* = .{ .channel = index, .quota = test_quota };
            break :blk list;
        };
        return &specs;
    }

    pub fn max_message_size(self: *const StateSyncEngine) u32 {
        const qmdb = qmdb_p2p.limits.max_payload_size(
            block_mod.Family,
            Sha256.Digest,
            sync_batch_size,
            codec.fixed_size(Validator.QmdbActor.Op).?,
        ) catch unreachable; // Proof: 16 operations fit a u32.
        // The base bound already admits a megabyte, far above the QMDB payload.
        const base = self.base.max_message_size();
        assert(qmdb < base);
        return base;
    }

    pub fn init(self: *const StateSyncEngine, ctx: simulate.InitContext(Key)) !struct {
        Started,
        ValidatorState,
    } {
        assert(ctx.channels.len == channel_count);
        const self_mut: *StateSyncEngine = @constCast(self);
        const index = ctx.index;
        // A restart means a processed hold served its purpose (commonware's release).
        if (self.boots[index] > 0) self_mut.base.ledger.release_hold(ctx.public_key);
        self_mut.boots[index] += 1;
        // commonware `Network::manager`: a node starts, and restarts, with no peer sets, and
        // tracks sets for itself alone.
        const control = ctx.oracle.control(ctx.public_key);
        try control.reset_peer_sets();
        const manager = &self_mut.base.managers[index];
        manager.* = .init(self.base.gpa, self.base.network, control);
        var wrapped: [channel_count]Validator.Channel = undefined;
        const failures = self.base.failures;
        for (&wrapped, ctx.channels, 0..) |*channel, registered, at| {
            const filter: mocks.Filter = if (at == dkg_channel and failures.len > 0)
                .{ .epochs = failures }
            else
                .none;
            channel.* = .{
                .sender = registered.sender,
                .receiver = .{ .inner = registered.receiver, .filter = filter },
            };
        }
        const state: ValidatorState = .{
            .gpa = self.base.gpa,
            .key = ctx.public_key,
            .ledger = &self.base.ledger,
            .marshal = &self_mut.marshals[index],
        };
        const started: Started = .{
            .context = ctx.context,
            .config = self.config(ctx, manager),
            .channels = .{
                .votes = wrapped[0],
                .certificates = wrapped[1],
                .resolver = wrapped[2],
                .backfill = wrapped[3],
                .broadcast = wrapped[4],
                .qmdb = wrapped[5],
                .dkg = wrapped[6],
                .probe = wrapped[7],
            },
        };
        return .{ started, state };
    }

    fn config(
        self: *const StateSyncEngine,
        ctx: simulate.InitContext(Key),
        manager: *harness.Types.Manager,
    ) Validator.Config {
        const index = ctx.index;
        const base = &self.base;
        assert(base.keys[index].eql(ctx.public_key));
        const base_mut: *harness.ReshareEngine = @constCast(base);
        return .{
            .signer = base.signers[index],
            .manager = manager,
            .peer_provider = manager.provider(),
            .blocker = ctx.oracle.control(ctx.public_key),
            .secret_store = &base_mut.stores[index],
            .ledger = &base_mut.ledger,
            .monitor = ctx.monitor,
            .schedule = base.schedule(),
            .initial = &base.initial,
            .network = base.network,
            .sharing_mode = base.sharing_mode,
            .elector = self.elector,
            .partition_prefix = prefixes[index],
            .delayed = ctx.delayed,
            .state_sync_floor = self.state_sync_floor,
            .epoch_cross_during_sync = self.epoch_cross_during_sync,
            .stale = self.stale,
            .restarted = self.boots[index] > 1,
            .marshals = @constCast(self.marshals),
            .index = index,
        };
    }

    const prefixes = [_][]const u8{
        "reshare-e2e-0",  "reshare-e2e-1",  "reshare-e2e-2",  "reshare-e2e-3",
        "reshare-e2e-4",  "reshare-e2e-5",  "reshare-e2e-6",  "reshare-e2e-7",
        "reshare-e2e-8",  "reshare-e2e-9",  "reshare-e2e-10", "reshare-e2e-11",
        "reshare-e2e-12", "reshare-e2e-13", "reshare-e2e-14", "reshare-e2e-15",
    };

    pub fn start(started: Started) !simulate.engine.Handle {
        return started.context.spawn(run_node, .{started});
    }

    pub fn deinit_state(state: *ValidatorState) void {
        if (state.marshal.mailbox) |*mailbox| mailbox.deinit();
        state.marshal.mailbox = null;
        assert(state.marshal.mailbox == null);
        state.* = undefined;
    }
};

const state_sync_validator = @This();

/// Runs a validator until the plan stops it. A validator that stops on its own fails the run.
fn run_node(ctx: simulate.engine.Context, started: Started) void {
    const result = Validator.run(ctx.child("validator"), started.config, started.channels);
    result catch |err| {
        if (err == error.Canceled) return;
        ctx.io().checkCancel() catch return;
        std.debug.panic("reshare state-sync validator failed: {t}", .{err});
    };
    ctx.io().checkCancel() catch return;
    @panic("reshare state-sync validator stopped");
}

pub const Plan = simulate.Plan(StateSyncEngine);
