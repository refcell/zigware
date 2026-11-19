//! The self-contained one-shot DKG engine (commonware `glue::dkg::bootstrap::Engine`).
//!
//! `Engine(T).start` builds the one-shot chain and runs it in one supervised task: a marshal
//! `node.Node` (archives, buffered broadcast, backfill resolver, marshal actor), a reshare
//! actor in DKG mode on the DKG channel, the reshare `Application` over a payload-only block
//! builder, marshal's `Deferred` wrapper, and an Ed25519 Simplex engine on the vote,
//! certificate, and resolver channels. The task ends when any component ends; aborting its
//! handle stops every component. After reporting its completion the engine keeps serving the
//! chain so lagging participants catch up, and at startup it asks the other participants for
//! the final block's finalization. Restart behavior (reporting a stored final block, the
//! share-without-final-block check) is the reshare actor's DKG mode.
//!
//! `T` declares `Variant` (BLS), `Directory`, `Manager` (a DKG `network` manager),
//! `PeerProvider` (the p2p `Manager` buffered broadcast and the resolver read peer sets
//! from; commonware reuses the DKG manager, whose peer-set reads forward to it), `Blocker`,
//! `SecretStore`, `Network` (`Sender` and `Receiver`), and `Context`, the runtime context the
//! engine runs on (`runtime.deterministic.Context` in tests, `runtime.production.runner.Context`
//! in a binary).

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
const types = @import("../types.zig");
const network = @import("../network.zig");
const reshare = @import("../reshare/root.zig");
const Fence = @import("../fence.zig").Fence;
const block_api = @import("block.zig");
const limits = @import("limits.zig");
const node_api = @import("node.zig");

const Epoch = consensus.Epoch;
const ed25519 = cryptography.ed25519;
const Key = ed25519.PublicKey;
const Set = utils.ordered.Set;
const oneshot = utils.channel.oneshot;
const SharingMode = cryptography.bls12381.primitives.sharing.Mode;
const ModeVersion = cryptography.bls12381.primitives.sharing.ModeVersion;
const Reveal = cryptography.bls12381.dkg.feldman_desmedt.Reveal;
const ConsensusScheme = limits.ConsensusScheme;
const simplex = consensus.simplex;

/// The participants provider a one-shot ceremony reads: the configured set and directory
/// for every epoch (commonware bootstrap's `StaticParticipants`).
fn StaticParticipants(comptime D: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = ed25519.PublicKey;
        pub const Directory = D;

        participants_value: Set(ed25519.PublicKey),
        directory_value: D,

        pub fn participants(self: *Self, io: Io, gpa: Allocator, epoch: Epoch) !Set(Key) {
            _ = .{ io, epoch };
            assert(self.participants_value.len() > 0);
            return self.participants_value.clone(gpa);
        }

        pub fn directory(
            self: *Self,
            io: Io,
            gpa: Allocator,
            epoch: Epoch,
            peers: Set(Key),
        ) !D {
            _ = .{ io, epoch, peers };
            return network.DirectoryOps(Key, D).clone(self.directory_value, gpa);
        }
    };
}

/// A registrar that discards every scheme: the one-shot chain registers none (commonware
/// `NoopRegistrar`).
fn NoopRegistrar(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Variant = V;
        pub const PublicKey = ed25519.PublicKey;

        gpa: Allocator,

        pub fn register(
            self: *Self,
            io: Io,
            epoch: Epoch,
            info: types.SchemeInfo(V, Key),
        ) !void {
            _ = .{ io, epoch };
            var dropped = info;
            dropped.deinit(self.gpa);
        }
    };
}

/// Configuration for `Engine` (commonware bootstrap `Config`).
pub fn Config(comptime T: type) type {
    return struct {
        /// Signs the one-shot chain and the DKG messages.
        signer: ed25519.PrivateKey,
        /// Activates the ceremony's peer set; borrowed, outlives the engine.
        manager: *T.Manager,
        /// Peer sets for broadcast and backfill (see the file header).
        peer_provider: T.PeerProvider,
        blocker: T.Blocker,
        /// The ceremony's secret store; borrowed, outlives the engine. Never pruned.
        secret_store: *T.SecretStore,
        namespace: []const u8,
        sharing_mode: SharingMode,
        reveal: Reveal,
        max_supported_mode: ModeVersion,
        /// Borrowed; outlives the engine.
        partition_prefix: []const u8,
        page_size: u16 = 1024,
        page_cache_size: u32 = 16,
        write_buffer: usize,
        replay_buffer: usize,
        mailbox_size: u32,
        fetch_timeout: utils.Duration,
        fetch_retry_delay: utils.Duration,
        items_per_section: u64,
        /// The ceremony participants; borrowed (the engine clones them).
        participants: Set(Key),
        /// Exactly `participants`' transport directory; borrowed (cloned).
        directory: T.Directory,
        blocks_per_epoch: u64,
    };
}

pub fn Engine(comptime T: type) type {
    return struct {
        const Self = @This();
        const Ctx = T.Context;
        pub const V = T.Variant;
        pub const D = T.Directory;
        pub const Block = block_api.Block(V, D);
        pub const Digested = broadcast.Digested(Block);
        const Node = node_api.Node(NodeTypes);
        const Provider = cryptography.certificate.ConstantProvider(ConsensusScheme);
        pub const ReshareTypes = struct {
            pub const Block = Self.Block;
            pub const Ack = utils.acknowledgement.Exact;
            pub const Ancestry = consensus.marshal.ancestry.AncestorStream(Node.Mailbox);
            pub const Signer = ed25519.PrivateKey;
            pub const Manager = T.Manager;
            pub const Blocker = T.Blocker;
            pub const Provider = StaticParticipants(D);
            pub const SecretStore = T.SecretStore;
            pub const Registrar = NoopRegistrar(V);
            pub const Marshal = Node.Mailbox;
            pub const Strategy = parallel.Sequential;
        };
        const NodeTypes = struct {
            pub const Block = Self.Block;
            pub const Scheme = ConsensusScheme;
            pub const Provider = Self.Provider;
            pub const Strategy = parallel.Sequential;
            pub const Network = T.Network;
            pub const PeerProvider = T.PeerProvider;
            pub const Blocker = T.Blocker;
            pub const Application = MarshalReporter;
            pub const Context = T.Context;
        };
        /// Marshal's view of the reshare mailbox: marshal's `Reporter` returns `Feedback`,
        /// and enqueueing only fails on allocation, where Rust aborts.
        const MarshalReporter = struct {
            mailbox: reshare.Mailbox(ReshareTypes),

            pub fn report(
                self: *MarshalReporter,
                update: consensus.marshal.Update(Self.Block, ReshareTypes.Ack),
            ) consensus.Feedback {
                return self.mailbox.report(update);
            }

            pub fn clone(self: *const MarshalReporter) MarshalReporter {
                return .{ .mailbox = self.mailbox.clone() };
            }

            pub fn deinit(self: *MarshalReporter) void {
                self.mailbox.deinit();
                self.* = undefined;
            }
        };
        const Actor = reshare.actor.Actor(ReshareTypes);
        const Runner = reshare.actor.run.Runner(ReshareTypes);
        const App = reshare.Application(BlockBuilder, ReshareTypes);
        const Wrapper = consensus.marshal.standard.Deferred(
            Ctx,
            ConsensusScheme,
            App,
            Self.Block,
            consensus.types.FixedEpocher,
        );
        const SimplexParams = struct {
            pub const Context = Ctx;
            pub const Scheme = ConsensusScheme;
            pub const Elector = simplex.elector.RoundRobinElector;
            pub const Blocker = T.Blocker;
            pub const Digest = Self.Block.Digest;
            pub const Automaton = *Wrapper;
            pub const Relay = *Wrapper;
            pub const Reporter = *Wrapper;
            pub const Strategy = parallel.Sequential;
            pub const Sender = T.Network.Sender;
            pub const Receiver = T.Network.Receiver;
        };
        const Simplex = simplex.engine.Engine(SimplexParams);
        pub const Channel = Node.Channel;
        /// The ceremony's outcome: epoch zero's info, or null when it failed (commonware
        /// `Completion`).
        pub const Completion = Actor.DkgOutcome;

        /// The engine's six channels (commonware `start`'s arguments), taken by `start`.
        pub const Channels = struct {
            votes: Channel,
            certificates: Channel,
            resolver: Channel,
            backfill: Channel,
            broadcast: Channel,
            dkg: Channel,
        };

        pub const Started = struct {
            /// The engine's task; abort it to stop the engine.
            handle: runtime.context.Handle(anyerror!void),
            /// Receives the completion once; closes without one if the engine stops first.
            completion: oneshot.Receiver(Completion),
        };

        /// Builds the inner application's blocks: the parent's child carrying the reshare
        /// payload (commonware `DkgApp`). Verification accepts every block: the reshare
        /// wrapper already checks the payloads, and the chain has no other state.
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
                const payload = input.payload;
                var owned = ancestry;
                defer owned.deinit();
                var carried = payload;
                errdefer if (carried) |*value| value.deinit(self.gpa);
                const parent = owned.peek() orelse {
                    if (carried) |*value| value.deinit(self.gpa);
                    return null;
                };
                const at = parent.inner().height().next();
                carried = null;
                const parent_digest = parent.digest();
                const built = try Self.Block.init(self.gpa, context, parent_digest, at, payload);
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
        config: Config(T),
        namespace: []u8,
        simplex_partition: []u8,
        genesis_digest: Block.Digest,
        scheme: ConsensusScheme,
        page_cache: runtime.buffer.paged.CacheRef,
        node: Node,
        fence: Fence,
        participants_provider: ReshareTypes.Provider,
        registrar: ReshareTypes.Registrar,
        blocker: T.Blocker,
        store: Actor.Store,
        actor: Actor,
        reshare_mailbox: Actor.Mailbox,
        wrapper: *Wrapper,
        elector: simplex.elector.RoundRobinElector,
        simplex_engine: Simplex,

        /// Rejects a `sharing_mode` that `max_supported_mode` does not support (commonware's
        /// `Engine::new` panics).
        pub fn check(config: *const Config(T)) error{UnsupportedSharingMode}!void {
            if (!config.max_supported_mode.supports(config.sharing_mode)) {
                return error.UnsupportedSharingMode;
            }
        }

        /// Starts the engine on `channels` (taken) under `ctx` (commonware `start`).
        pub fn start(ctx: Ctx, config: Config(T), channels: Channels) !Started {
            try check(&config);
            const gpa = ctx.gpa();
            const pair = try oneshot.channel(Completion, gpa, ctx.io());
            var receiver = pair.receiver;
            errdefer receiver.deinit();
            const handle = try ctx.spawn(run, .{ config, channels, pair.sender });
            return .{ .handle = handle, .completion = receiver };
        }

        fn run(
            ctx: Ctx,
            config: Config(T),
            channels: Channels,
            completion: oneshot.Sender(Completion),
        ) anyerror!void {
            if (config.participants.len() == 0) @panic("DKG requires at least one participant");
            const gpa = ctx.gpa();
            const self = try gpa.create(Self);
            defer gpa.destroy(self);
            try self.init(ctx, config, channels, completion);
            defer self.deinit();
            return self.supervise(ctx, channels);
        }

        fn init(
            self: *Self,
            ctx: Ctx,
            config: Config(T),
            channels: Channels,
            completion: oneshot.Sender(Completion),
        ) !void {
            const gpa = ctx.gpa();
            self.gpa = gpa;
            self.io = ctx.io();
            self.config = config;
            self.blocker = config.blocker;
            const suffix = "_INITIAL_CONSENSUS";
            self.namespace = try std.mem.concat(gpa, u8, &.{ config.namespace, suffix });
            errdefer gpa.free(self.namespace);
            const prefix = config.partition_prefix;
            self.simplex_partition = try std.mem.concat(gpa, u8, &.{ prefix, "-simplex" });
            errdefer gpa.free(self.simplex_partition);
            const committee = try config.participants.clone(gpa);
            const signer = config.signer;
            const scheme = try ConsensusScheme.signer(gpa, self.namespace, committee, signer);
            self.scheme = scheme orelse @panic("DKG signer must be a participant");
            errdefer self.scheme.deinit(gpa);
            self.page_cache = try .init(gpa, config.page_size, config.page_cache_size);
            errdefer self.page_cache.deinit();
            try self.init_node(ctx, channels);
            errdefer self.node.deinit();
            try self.init_reshare(ctx, completion);
            errdefer self.deinit_reshare();
            try self.init_consensus(ctx);
        }

        fn max_participants(self: *const Self) u32 {
            return types.max_participants(self.config.participants.len());
        }

        fn init_node(self: *Self, ctx: Ctx, channels: Channels) !void {
            const config = &self.config;
            const leader = config.participants.items[0];
            const raw = try Block.genesis(self.gpa, leader);
            self.genesis_digest = raw.digest();
            var genesis = try Digested.precomputed(self.gpa, raw, raw.digest());
            errdefer genesis.deinit();
            try self.node.init(ctx, .{
                .public_key = config.signer.public_key(),
                .peer_provider = config.peer_provider,
                .blocker = config.blocker,
                .provider = .init(&self.scheme),
                .strategy = .{},
                .partition_prefix = config.partition_prefix,
                .page_cache = &self.page_cache,
                .genesis = genesis,
                .block_codec_config = .{
                    .max_participants = self.max_participants(),
                    .max_supported_mode = config.max_supported_mode,
                },
                .blocks_per_epoch = config.blocks_per_epoch,
                .items_per_section = config.items_per_section,
                .mailbox_size = config.mailbox_size,
                .write_buffer = config.write_buffer,
                .replay_buffer = config.replay_buffer,
                .fetch_timeout = config.fetch_timeout,
                .fetch_retry_delay = config.fetch_retry_delay,
            }, channels.backfill, channels.broadcast);
            try self.hint_final_block();
        }

        /// Asks the other participants for the one-shot chain's final block, so a lagging
        /// node catches up from peers that only serve the chain.
        fn hint_final_block(self: *Self) !void {
            const length = utils.NonZero(u64).init(self.config.blocks_per_epoch).?;
            const last = consensus.types.FixedEpocher.new(length).last(Epoch.zero()).?;
            const me = self.config.signer.public_key();
            const peers = self.config.participants.items;
            const targets = try self.gpa.alloc(Key, peers.len);
            defer self.gpa.free(targets);
            var count: usize = 0;
            for (peers) |peer| if (!peer.eql(me)) {
                targets[count] = peer;
                count += 1;
            };
            assert(count + 1 == peers.len);
            if (count > 0) try self.node.mailbox.hint_finalized(last, targets[0..count]);
        }

        fn init_reshare(self: *Self, ctx: Ctx, completion: oneshot.Sender(Completion)) !void {
            const gpa = self.gpa;
            const config = &self.config;
            const Dir = network.DirectoryOps(Key, D);
            self.participants_provider = .{
                .participants_value = config.participants,
                .directory_value = config.directory,
            };
            self.registrar = .{ .gpa = gpa };
            self.fence = Fence.init(self.io);
            errdefer self.fence.close();
            const prefix = try std.mem.concat(gpa, u8, &.{ config.partition_prefix, "-reshare" });
            defer gpa.free(prefix);
            self.store = try Actor.Store.init(gpa, ctx.storage, .{
                .partition_prefix = prefix,
                .max_participants = self.max_participants(),
                .cache_ref = &self.page_cache,
                .write_buffer = config.write_buffer,
                .replay_buffer = config.replay_buffer,
            }, config.secret_store);
            errdefer self.store.deinit();
            const scope = ctx.scope.child("reshare");
            self.actor, self.reshare_mailbox = try Actor.init(gpa, self.io, &scope, .{
                .signer = config.signer,
                .manager = config.manager,
                .blocker = &self.blocker,
                .participants_provider = &self.participants_provider,
                .strategy = .{},
                .registrar = &self.registrar,
                .marshal = self.node.mailbox.clone(),
                .fence = &self.fence,
                .namespace = config.namespace,
                .sharing_mode = config.sharing_mode,
                .reveal = config.reveal,
                .mailbox_size = config.mailbox_size,
                .max_participants = self.max_participants(),
                .blocks_per_epoch = config.blocks_per_epoch,
            });
            var participants = try config.participants.clone(gpa);
            errdefer participants.deinit(gpa);
            self.actor.mode = .{ .dkg = .{
                .participants = participants,
                .directory = try Dir.clone(config.directory, gpa),
                .completion = completion,
            } };
        }

        fn deinit_reshare(self: *Self) void {
            self.reshare_mailbox.deinit();
            self.actor.deinit();
            self.store.deinit();
            self.fence.close();
        }

        fn init_consensus(self: *Self, ctx: Ctx) !void {
            const gpa = self.gpa;
            const config = &self.config;
            const length = utils.NonZero(u64).init(config.blocks_per_epoch).?;
            const blocks = config.blocks_per_epoch;
            const app = App.init(.{ .gpa = gpa }, self.reshare_mailbox.clone(), blocks);
            const marshal = self.node.mailbox.clone();
            self.wrapper = try Wrapper.create(ctx.child("deferred"), app, marshal, .new(length));
            errdefer self.wrapper.destroy();
            const count: u32 = @intCast(config.participants.len());
            const elector = simplex.elector.RoundRobin(cryptography.Sha256).default();
            self.elector = try elector.build(gpa, count);
            errdefer self.elector.deinit(gpa);
            const genesis = self.genesis_digest;
            try self.simplex_engine.init(ctx.child("simplex"), .{
                .scheme = self.scheme,
                .elector = self.elector,
                .blocker = config.blocker,
                .automaton = self.wrapper,
                .relay = self.wrapper,
                .reporter = self.wrapper,
                .track_historical_votes = false,
                .strategy = .{},
                .partition = self.simplex_partition,
                .mailbox_size = config.mailbox_size,
                .epoch = Epoch.zero(),
                .floor = .{ .genesis = genesis },
                .replay_buffer = @intCast(config.replay_buffer),
                .write_buffer = @intCast(config.write_buffer),
                .page_cache = &self.page_cache,
                .leader_timeout = .from_secs(1),
                .certification_timeout = .from_secs(2),
                .timeout_retry = .from_millis(500),
                .view_retention = .new(10),
                .skip = .{ .enabled = .{ .timeout = .from_secs(5) } },
                .fetch_timeout = config.fetch_timeout,
                .fetch_retry_delay = config.fetch_retry_delay,
                .forward = .disabled,
            });
        }

        fn ReshareTask(comptime Sender: type, comptime Receiver: type) type {
            return struct {
                /// Resolves the startup tip from marshal's processed anchor (commonware
                /// `startup`; bootstrap has no state sync), then runs the actor. A restart
                /// that already applied the final block reports it instead of rerunning.
                fn run(_: Ctx, self: *Self, sender: Sender, receiver: Receiver) anyerror!void {
                    var anchor = try self.node.mailbox.get_anchor();
                    defer if (anchor) |*value| value.block.deinit();
                    const Processed = consensus.marshal.core.floor.Processed;
                    const Anchor = struct { Processed, *const Digested };
                    const processed: ?Anchor = if (anchor) |*value|
                        .{ value.processed, &value.block }
                    else
                        null;
                    const tip = reshare.actor.setup.startup(Digested, processed, null);
                    return Runner.run(&self.actor, &self.store, sender, receiver, .{ .tip = tip });
                }
            };
        }

        fn convert(channel: Channel) simplex.engine.Channel(SimplexParams) {
            return .{ .sender = channel.sender, .receiver = channel.receiver };
        }

        fn simplex_task(
            ctx: Ctx,
            self: *Self,
            votes: Channel,
            certificates: Channel,
            resolver: Channel,
        ) anyerror!void {
            const engine = &self.simplex_engine;
            const certs = convert(certificates);
            return Simplex.run(ctx, engine, convert(votes), certs, convert(resolver));
        }

        /// Starts the reshare actor, marshal, and simplex, and runs until one of them ends
        /// (commonware's `Handle::select`).
        fn supervise(self: *Self, ctx: Ctx, channels: Channels) anyerror!void {
            const Task = ReshareTask(T.Network.Sender, T.Network.Receiver);
            var handles: [3]runtime.context.Handle(anyerror!void) = undefined;
            const dkg = channels.dkg;
            const reshare_args = .{ self, dkg.sender, dkg.receiver };
            handles[0] = try ctx.child("reshare").spawn(Task.run, reshare_args);
            handles[1] = try self.node.start(.{ .mailbox = self.reshare_mailbox.clone() });
            const args = .{ self, channels.votes, channels.certificates, channels.resolver };
            handles[2] = try ctx.child("engine").spawn(simplex_task, args);
            const first = try runtime.context.select(anyerror!void, self.io, &handles);
            return first;
        }

        fn deinit(self: *Self) void {
            const gpa = self.gpa;
            self.simplex_engine.deinit();
            self.elector.deinit(gpa);
            self.wrapper.destroy();
            self.deinit_reshare();
            self.node.deinit();
            self.page_cache.deinit();
            self.scheme.deinit(gpa);
            gpa.free(self.simplex_partition);
            gpa.free(self.namespace);
            self.* = undefined;
        }
    };
}
