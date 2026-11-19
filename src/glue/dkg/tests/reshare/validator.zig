//! One reshare validator (commonware `glue::dkg::tests::reshare::harness`'s
//! `ReshareEngine::init` and `start`), without state sync: the reshare actor in reshare mode,
//! the orchestrator running one Simplex engine per epoch over the reshare application, and
//! marshal's stack from `bootstrap.Node`. Marshal reports to the orchestrator and the reshare
//! actor; the reporter also records each processed height in the ledger (commonware's
//! `App::finalized`) and sends finalized tips to the plan's monitor.
//!
//! Commonware's validator executes a QMDB application through `glue::stateful`; this one
//! builds blocks the way bootstrap's does (the parent's child carrying the reshare payload).
//! The state-synced variant is the harness's next phase (docs/lanes/glue.md).
//!
//! `T` declares `Variant`, `Directory`, `Manager` (a DKG `network` manager), `PeerProvider`
//! (the p2p `Manager` buffered broadcast and backfill read), `Blocker`, `SecretStore`,
//! `Context`, and `Network` (`Sender` and `Receiver`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const reshare = @import("../../reshare/root.zig");
const orchestrator = @import("../../orchestrator/root.zig");
const state_sync = @import("../../state_sync.zig");
const Fence = @import("../../fence.zig").Fence;
const bootstrap = @import("../../bootstrap/mod.zig");
const simulate = @import("../../../simulate/mod.zig");
const properties = @import("properties.zig");
const support = @import("support.zig");

const simplex = consensus.simplex;
const Epoch = consensus.Epoch;
const ed25519 = cryptography.ed25519;
const Key = ed25519.PublicKey;
const Sha256 = cryptography.Sha256;
const SharingMode = cryptography.bls12381.primitives.sharing.Mode;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const FixedEpocher = consensus.types.FixedEpocher;
const Exact = utils.acknowledgement.Exact;

/// commonware `NAMESPACE`.
pub const namespace = "_COMMONWARE_GLUE_DKG_RESHARE_E2E";
/// commonware `MAX_PARTICIPANTS`.
pub const max_participants: u32 = 16;
pub const epoch_length = properties.epoch_length;

pub fn Validator(comptime T: type) type {
    return struct {
        const Self = @This();
        const Ctx = T.Context;
        pub const V = T.Variant;
        pub const D = T.Directory;
        pub const Block = bootstrap.Block(V, D);
        pub const Digested = broadcast.Digested(Block);
        pub const Info = Block.Info;
        /// commonware `Scheme`: the threshold VRF scheme over ed25519 identities.
        pub const Scheme = simplex.scheme.bls12381_threshold.vrf.Scheme(Block.Digest, Key, V);
        pub const Provider = support.Schemes(Scheme);
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
        const Plan = state_sync.Plan(Scheme, Block.Digest, V, D);
        const App = reshare.Application(BlockBuilder, ReshareTypes);
        const Wrapper = consensus.marshal.standard.Deferred(Ctx, Scheme, App, Block, FixedEpocher);
        const OrchestratorTypes = struct {
            pub const Context = T.Context;
            pub const Block = Self.Block;
            pub const Ack = Exact;
            pub const Scheme = Self.Scheme;
            pub const Provider = *const Self.Provider;
            pub const Manager = *T.Manager;
            pub const Marshal = Node.Mailbox;
            pub const Blocker = T.Blocker;
            pub const ElectorConfig = simplex.elector.RoundRobin(Sha256);
            pub const Elector = simplex.elector.RoundRobinElector;
            pub const Automaton = *Wrapper;
            pub const Relay = *Wrapper;
            pub const Reporter = *Wrapper;
            pub const Strategy = parallel.Sequential;
            pub const Sender = T.Network.Sender;
            pub const Receiver = T.Network.Receiver;

            pub fn build_elector(config: ElectorConfig, gpa: Allocator, n: u32) !Elector {
                return config.build(gpa, n);
            }
        };
        const Orchestrator = orchestrator.Actor(OrchestratorTypes);
        pub const Channel = Node.Channel;
        pub const MarshalMailbox = Node.Mailbox;

        /// The eight channels of commonware's validator, minus QMDB and the probe.
        pub const Channels = struct {
            votes: Channel,
            certificates: Channel,
            resolver: Channel,
            backfill: Channel,
            broadcast: Channel,
            dkg: Channel,
        };

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
            directory: D,
            sharing_mode: SharingMode,
            /// Owned by the caller; outlives the validator.
            partition_prefix: []const u8,
            /// Receives a marshal mailbox clone (owned by the slot's holder) once marshal is up.
            published: ?*?MarshalMailbox = null,
        };

        /// Marshal's reporter: the ledger and monitor first, then the orchestrator and the
        /// reshare actor, which share the block and its acknowledgement (commonware's
        /// `MonitorReporter` over `Reporters`).
        const MarshalReporter = struct {
            pub const Activity = Update;
            key: Key,
            ledger: *support.Ledger,
            monitor: ?Monitor,
            orchestrator_mailbox: Orchestrator.Mailbox,
            reshare_mailbox: Actor.Mailbox,

            pub fn report(self: *MarshalReporter, update: Update) consensus.Feedback {
                switch (update) {
                    .tip => |tip| if (self.monitor) |monitor| {
                        _ = monitor.send(.{
                            .pk = self.key,
                            .round = tip.round,
                            .height = tip.height,
                            .block_digest = tip.digest.as_slice(),
                        });
                    },
                    .block => |value| {
                        const height = value.block.inner().height().get();
                        self.ledger.record_processed(self.key, height);
                    },
                }
                const copy: Update = switch (update) {
                    .tip => update,
                    .block => |value| .{ .block = .{
                        .block = value.block.clone(),
                        .ack = value.ack.clone(),
                    } },
                };
                const first = self.orchestrator_mailbox.report(copy);
                const second = self.reshare_mailbox.report(update);
                return consensus.reporter.combine(first, second);
            }

            pub fn clone(self: *const MarshalReporter) MarshalReporter {
                var copy = self.*;
                copy.orchestrator_mailbox = self.orchestrator_mailbox.clone();
                copy.reshare_mailbox = self.reshare_mailbox.clone();
                return copy;
            }

            pub fn deinit(self: *MarshalReporter) void {
                self.orchestrator_mailbox.deinit();
                self.reshare_mailbox.deinit();
                self.* = undefined;
            }
        };

        /// The parent's child carrying the reshare payload (bootstrap's `BlockBuilder`).
        const BlockBuilder = struct {
            pub const Block = Self.Block;
            gpa: Allocator,

            pub fn propose(
                self: *BlockBuilder,
                ctx: anytype,
                context: Self.Block.Context,
                ancestry: anytype,
                input: reshare.application.Input(ReshareTypes),
            ) anyerror!?Digested {
                _ = ctx;
                var owned = ancestry;
                defer owned.deinit();
                var payload = input.payload;
                const parent = owned.peek() orelse {
                    if (payload) |*value| value.deinit(self.gpa);
                    return null;
                };
                const at = parent.inner().height().next();
                const built = Self.Block.init(
                    self.gpa,
                    context,
                    parent.digest(),
                    at,
                    payload,
                ) catch |err| {
                    if (payload) |*value| value.deinit(self.gpa);
                    return err;
                };
                return try Digested.precomputed(self.gpa, built, built.digest());
            }

            pub fn verify(
                self: *BlockBuilder,
                ctx: anytype,
                context: anytype,
                ancestry: anytype,
            ) anyerror!bool {
                _ = .{ self, ctx, context };
                var owned = ancestry;
                owned.deinit();
                return true;
            }
        };

        gpa: Allocator,
        io: Io,
        config: Config,
        page_cache: runtime.buffer.paged.CacheRef,
        /// marshal's certificate verifier against the initial group key.
        verifier: Scheme,
        provider: Self.Provider,
        participants: Participants,
        blocker: T.Blocker,
        node: Node,
        fence: Fence,
        plan: Plan,
        store: Actor.Store,
        actor: Actor,
        reshare_mailbox: Actor.Mailbox,
        wrapper: *Wrapper,
        orchestrator_actor: Orchestrator,
        orchestrator_mailbox: Orchestrator.Mailbox,
        /// The orchestrator's context: its task spawns from it, so the per-epoch engines it
        /// spawns stay below that task and an abort finishes them first.
        orchestrator_ctx: Ctx,
        partitions: [2][]u8,

        /// Runs the validator under `ctx` until one of its actors stops (commonware `start`'s
        /// `Handle::select`).
        pub fn run(ctx: Ctx, config: Config, channels: Channels) anyerror!void {
            const gpa = ctx.gpa();
            const self = try gpa.create(Self);
            defer gpa.destroy(self);
            try self.init(ctx, config, channels);
            defer self.deinit();
            return self.supervise(ctx, channels);
        }

        fn init(self: *Self, ctx: Ctx, config: Config, channels: Channels) !void {
            const gpa = ctx.gpa();
            self.gpa = gpa;
            self.io = ctx.io();
            self.config = config;
            self.blocker = config.blocker;
            const prefix = config.partition_prefix;
            self.partitions[0] = try std.mem.concat(gpa, u8, &.{ prefix, "-reshare" });
            errdefer gpa.free(self.partitions[0]);
            self.partitions[1] = try std.mem.concat(gpa, u8, &.{ prefix, "-orchestrator" });
            errdefer gpa.free(self.partitions[1]);
            // commonware `PAGE_SIZE` and `PAGE_CACHE_SIZE`.
            self.page_cache = try .init(gpa, 1024, 10);
            errdefer self.page_cache.deinit();
            const identity = config.initial.output.public.public();
            self.verifier = try Scheme.certificate_verifier(gpa, namespace, identity);
            errdefer self.verifier.deinit(gpa);
            self.provider = .{
                .gpa = gpa,
                .namespace = namespace,
                .key = config.signer.public_key(),
                .ledger = config.ledger,
            };
            errdefer self.provider.deinit();
            try self.register_epoch_zero();
            self.participants = .{
                .schedule = config.schedule,
                .directory_value = config.directory,
            };
            try self.init_node(ctx, channels);
            errdefer self.node.deinit();
            try self.init_reshare(ctx);
            errdefer self.deinit_reshare();
            try self.init_orchestrator(ctx);
        }

        /// commonware `InitialState::register_epoch_zero`: install epoch zero's scheme from
        /// the stored share before any actor runs, without recording it.
        fn register_epoch_zero(self: *Self) !void {
            const gpa = self.gpa;
            const initial = self.config.initial;
            const share = try self.config.secret_store.get_share(Epoch.zero());
            var players = try initial.output.players.clone(gpa);
            errdefer players.deinit(gpa);
            const sharing = try initial.output.public.clone(gpa);
            const key = self.config.signer.public_key();
            const info = types.SchemeInfo(V, Key).init(key, players, sharing, share);
            _ = try self.provider.install(Epoch.zero(), info);
        }

        fn init_node(self: *Self, ctx: Ctx, channels: Channels) !void {
            const config = &self.config;
            const gpa = self.gpa;
            const raw = try genesis(gpa, config.schedule.participants[0], config.initial);
            const genesis_block = try Digested.precomputed(gpa, raw, raw.digest());
            try self.node.init(ctx, .{
                .public_key = config.signer.public_key(),
                .peer_provider = config.peer_provider,
                .blocker = config.blocker,
                .provider = .init(&self.verifier),
                .strategy = .{},
                .partition_prefix = config.partition_prefix,
                .page_cache = &self.page_cache,
                .genesis = genesis_block,
                .block_codec_config = .{
                    .max_participants = max_participants,
                    .max_supported_mode = @import("../mocks.zig").max_supported_mode,
                },
                .blocks_per_epoch = epoch_length,
                .items_per_section = 10,
                .mailbox_size = 100,
                .write_buffer = 2048,
                .replay_buffer = 2048,
                .fetch_timeout = .from_secs(2),
                .fetch_retry_delay = .from_millis(100),
            }, channels.backfill, channels.broadcast);
            if (config.published) |slot| {
                if (slot.*) |*stale| stale.deinit();
                slot.* = self.node.mailbox.clone();
            }
        }

        /// commonware `Block::genesis`: height zero, carrying epoch zero's info.
        pub fn genesis(gpa: Allocator, leader: Key, initial: *const Info) !Block {
            const empty = Block.Digest.empty;
            const context: Block.Context = .{
                .round = .new(Epoch.zero(), .zero()),
                .leader = leader,
                .parent = .{ .zero(), empty },
            };
            const payload: Block.Payload = .{ .epoch_info = try initial.clone(gpa) };
            return Block.init(gpa, context, empty, .zero(), payload);
        }

        fn init_reshare(self: *Self, ctx: Ctx) !void {
            const gpa = self.gpa;
            const config = &self.config;
            self.fence = Fence.init(self.io);
            errdefer self.fence.close();
            self.plan = Plan.disabled(gpa, self.io);
            errdefer self.plan.deinit();
            self.store = try Actor.Store.init(gpa, ctx.storage, .{
                .partition_prefix = self.partitions[0],
                .max_participants = max_participants,
                .cache_ref = &self.page_cache,
                .write_buffer = 2048,
                .replay_buffer = 2048,
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
                .mailbox_size = 100,
                .max_participants = max_participants,
                .blocks_per_epoch = epoch_length,
            });
            assert(self.actor.mode == .reshare);
        }

        fn deinit_reshare(self: *Self) void {
            self.reshare_mailbox.deinit();
            self.actor.deinit();
            self.store.deinit();
            self.plan.deinit();
            self.fence.close();
        }

        fn init_orchestrator(self: *Self, ctx: Ctx) !void {
            const gpa = self.gpa;
            const length = utils.NonZero(u64).init(epoch_length).?;
            const app = App.init(.{ .gpa = gpa }, self.reshare_mailbox.clone(), epoch_length);
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
                    .elector = .default(),
                    .mailbox_size = 3,
                    .replay_buffer = 2048,
                    .write_buffer = 2048,
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
                .state_sync = &self.plan,
                .blocks_per_epoch = epoch_length,
                .mailbox_size = 100,
                .partition_prefix = self.partitions[1],
            };
        }

        fn ReshareTask(comptime Sender: type, comptime Receiver: type) type {
            return struct {
                fn run(ctx: Ctx, self: *Self, sender: Sender, receiver: Receiver) anyerror!void {
                    const marshal = &self.node.mailbox;
                    const storage = ctx.storage;
                    const plan = &self.plan;
                    const start = try Runner.resolve_start(&self.actor, storage, plan, marshal);
                    assert(start.state_sync == null);
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

        fn supervise(self: *Self, ctx: Ctx, channels: Channels) anyerror!void {
            const Task = ReshareTask(T.Network.Sender, T.Network.Receiver);
            var handles: [4]runtime.context.Handle(anyerror!void) = undefined;
            const dkg = channels.dkg;
            const reshare_args = .{ self, dkg.sender, dkg.receiver };
            handles[0] = try ctx.child("reshare").spawn(Task.run, reshare_args);
            handles[1] = try self.node.start(.{
                .key = self.config.signer.public_key(),
                .ledger = self.config.ledger,
                .monitor = self.config.monitor,
                .orchestrator_mailbox = self.orchestrator_mailbox.clone(),
                .reshare_mailbox = self.reshare_mailbox.clone(),
            });
            const args = .{ self, channels.votes, channels.certificates, channels.resolver };
            // commonware `orchestrator_actor.start`: the task runs on the actor's own context.
            handles[2] = try self.orchestrator_ctx.spawn(orchestrator_task, args);
            handles[3] = try ctx.child("buffer").spawn(buffer_task, .{self});
            const first = try runtime.context.select(anyerror!void, self.io, &handles);
            return first;
        }

        fn deinit(self: *Self) void {
            const gpa = self.gpa;
            self.orchestrator_mailbox.deinit();
            self.orchestrator_actor.deinit();
            self.wrapper.destroy();
            self.deinit_reshare();
            self.node.deinit();
            self.provider.deinit();
            self.verifier.deinit(gpa);
            self.page_cache.deinit();
            for (self.partitions) |partition| gpa.free(partition);
            self.* = undefined;
        }
    };
}
