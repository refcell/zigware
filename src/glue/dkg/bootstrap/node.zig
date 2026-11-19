//! A standard marshal node: the finalized archives, the buffered broadcast engine, the p2p
//! backfill resolver, and the marshal actor over them (commonware's bootstrap `run` and the
//! orchestrator tests' cluster nodes, which compose the same pieces). The consensus side
//! (simplex and the application wrapper) stays the caller's: it reads `mailbox`, and
//! `start` hands the actor its application once that exists.
//!
//! `T` declares:
//! - `Block`: the application block (`consensus.traits.assert_certifiable_block`), with
//!   `Cfg` its codec configuration;
//! - `Scheme`, `Provider` (marshal's certificate provider), and `Strategy`;
//! - `Network`: provides the p2p `Sender` and `Receiver` (`p2p.simulated.Network(P)` does);
//! - `PeerProvider`: the p2p `Manager` buffered broadcast and the resolver read peer sets
//!   from, and `Blocker`: the p2p `Blocker` both use;
//! - `Application`: marshal's `Reporter` of `Update` (cloned into the actor);
//! - `Context`: the runtime context (`runtime.deterministic.Context` or
//!   `runtime.production.runner.Context`).
//!
//! Partitions are `<prefix>-finalizations-{metadata,key,value}`,
//! `<prefix>-blocks-{metadata,key,value}`, and marshal's own under `<prefix>-marshal`, as
//! commonware's bootstrap names them. A node must not move once initialized.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");

const marshal = consensus.marshal;
const Height = consensus.Height;
const Exact = utils.acknowledgement.Exact;

pub fn Node(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const Block = T.Block;
        pub const Variant = MarshalVariant;
        const MarshalVariant = marshal.standard.Standard(T.Block);
        pub const Digest = Block.Digest;
        pub const PublicKey = T.Scheme.PublicKey;
        pub const Finalization = consensus.simplex.types.Finalization(T.Scheme, Digest);
        const Translator = storage.translator.TwoCap;
        pub const FinalizationArchive = storage.archive.prunable.Archive(
            Translator,
            [32]u8,
            Finalization,
        );
        pub const BlockArchive = storage.archive.prunable.Archive(Translator, [32]u8, Block);
        pub const Resolver = marshal.resolver.p2p.Resolver(
            Digest,
            PublicKey,
            T.PeerProvider,
            T.Blocker,
            T.Network.Sender,
            T.Network.Receiver,
        );
        pub const BroadcastEngine = broadcast.buffered.Engine(
            Block,
            T.PeerProvider,
            T.Blocker,
            T.Network,
        );
        pub const Buffer = marshal.standard.Buffer(Block, PublicKey);
        pub const Params = struct {
            pub const Scheme = T.Scheme;
            pub const Provider = T.Provider;
            pub const Epocher = consensus.types.FixedEpocher;
            pub const Strategy = T.Strategy;
            pub const ApplicationBlock = T.Block;
            pub const Block = MarshalVariant.Block;
            pub const Commitment = Digest;
            pub const Variant = MarshalVariant;
            pub const Acknowledgement = Exact;
            pub const Certificates = marshal.store.Certificates(
                FinalizationArchive,
                T.Scheme,
                Digest,
                Digest,
            );
            pub const Blocks = marshal.store.Blocks(BlockArchive, T.Block);
            pub const Application = T.Application;
            pub const Buffer = Self.Buffer;
            pub const Resolver = marshal.resolver.p2p.Mailbox(Digest, PublicKey);
            pub const Context = T.Context;
        };
        pub const Actor = marshal.core.Actor(Params);
        pub const Mailbox = Actor.Mailbox;
        pub const Channel = struct { sender: T.Network.Sender, receiver: T.Network.Receiver };

        /// commonware's bootstrap `marshal::Config`, `buffered::Config`, and
        /// `marshal_resolver::Config`, merged.
        pub const Config = struct {
            public_key: PublicKey,
            peer_provider: T.PeerProvider,
            blocker: T.Blocker,
            provider: T.Provider,
            strategy: T.Strategy,
            /// Owned by the caller; outlives the node.
            partition_prefix: []const u8,
            /// Borrowed; outlives the node.
            page_cache: *runtime.buffer.paged.CacheRef,
            /// The height-zero block marshal starts from (taken).
            genesis: Variant.Block,
            block_codec_config: Block.Cfg,
            blocks_per_epoch: u64,
            items_per_section: u64,
            mailbox_size: u32,
            write_buffer: usize,
            replay_buffer: usize,
            fetch_timeout: utils.Duration,
            fetch_retry_delay: utils.Duration,
        };

        gpa: Allocator,
        io: Io,
        names: [7][]u8,
        finalizations: FinalizationArchive,
        blocks: BlockArchive,
        buffer: Buffer,
        broadcast_future: Io.Future(BroadcastEngine.Error!void),
        resolver: Resolver.Started,
        /// Set by `init`; started by `start`.
        actor: ?*Actor,
        mailbox: Mailbox,
        /// The processed floor marshal restored, if any.
        processed: ?Height,

        const kinds = [_][]const u8{
            "finalizations-metadata", "finalizations-key", "finalizations-value",
            "blocks-metadata",        "blocks-key",        "blocks-value",
            "marshal",
        };

        /// Opens the archives, starts buffered broadcast on `broadcast_channel` and the
        /// resolver on `backfill` (both taken), and initializes the marshal actor.
        pub fn init(
            self: *Self,
            ctx: T.Context,
            config: Config,
            backfill: Channel,
            broadcast_channel: Channel,
        ) !void {
            self.gpa = ctx.gpa();
            self.io = ctx.io();
            self.actor = null;
            try self.name_partitions(config.partition_prefix);
            errdefer for (self.names) |name| self.gpa.free(name);
            try self.open_archives(ctx, config);
            errdefer self.close_archives();
            try self.start_resolver(ctx, config, backfill);
            errdefer self.stop_resolver();
            try self.start_broadcast(ctx, config, broadcast_channel);
            errdefer self.stop_broadcast();
            try self.init_actor(ctx, config);
            assert(self.actor != null);
        }

        fn name_partitions(self: *Self, prefix: []const u8) !void {
            assert(prefix.len > 0);
            var made: usize = 0;
            errdefer for (self.names[0..made]) |name| self.gpa.free(name);
            for (kinds, &self.names) |kind, *name| {
                name.* = try std.fmt.allocPrint(self.gpa, "{s}-{s}", .{ prefix, kind });
                made += 1;
            }
            assert(made == kinds.len);
        }

        fn open_archives(self: *Self, ctx: T.Context, config: Config) !void {
            const certificates = T.Scheme.certificate_codec_config_unbounded();
            self.finalizations = try self.open_archive(
                Finalization,
                ctx,
                config,
                0,
                "finalizations",
                certificates,
            );
            errdefer self.finalizations.deinit();
            self.blocks = try self.open_archive(
                Block,
                ctx,
                config,
                3,
                "blocks",
                config.block_codec_config,
            );
        }

        fn open_archive(
            self: *Self,
            comptime Value: type,
            ctx: T.Context,
            config: Config,
            comptime first: usize,
            comptime label: []const u8,
            codec_config: anytype,
        ) !storage.archive.prunable.Archive(Translator, [32]u8, Value) {
            assert(config.items_per_section > 0);
            return .init(self.gpa, ctx.storage, ctx.scope.child(label), .{
                .translator = .{},
                .metadata_partition = self.names[first],
                .key_partition = self.names[first + 1],
                .key_cache_ref = config.page_cache,
                .value_partition = self.names[first + 2],
                .codec_config = codec_config,
                .items_per_section = config.items_per_section,
                .key_write_buffer = config.write_buffer,
                .value_write_buffer = config.write_buffer,
                .replay_buffer = config.replay_buffer,
            });
        }

        fn close_archives(self: *Self) void {
            self.blocks.deinit();
            self.finalizations.deinit();
        }

        fn start_resolver(
            self: *Self,
            ctx: T.Context,
            config: Config,
            backfill: Channel,
        ) !void {
            assert(config.mailbox_size > 0);
            self.resolver = try Resolver.init(self.gpa, self.io, ctx.scope.child("backfill"), .{
                .public_key = config.public_key,
                .peer_provider = config.peer_provider,
                .blocker = config.blocker,
                .mailbox_size = config.mailbox_size,
                .fetch_timeout = config.fetch_timeout,
                .fetch_retry_delay = config.fetch_retry_delay,
                .priority_requests = false,
                .priority_responses = false,
            }, backfill.sender, backfill.receiver);
        }

        fn stop_resolver(self: *Self) void {
            _ = self.resolver.future.cancel(self.io) catch {};
            self.resolver.handler.deinit();
        }

        fn start_broadcast(
            self: *Self,
            ctx: T.Context,
            config: Config,
            channel: Channel,
        ) !void {
            const scope = ctx.scope.child("buffer");
            const created = try BroadcastEngine.init(self.gpa, self.io, &scope, .{
                .public_key = config.public_key,
                .mailbox_size = config.mailbox_size,
                .deque_size = 16,
                .priority = false,
                .codec_config = config.block_codec_config,
                .peer_provider = config.peer_provider,
                .blocker = config.blocker,
            });
            var mailbox = created.mailbox;
            errdefer mailbox.deinit();
            self.broadcast_future = try created.engine.start(channel.sender, channel.receiver);
            self.buffer = .init(mailbox);
        }

        fn stop_broadcast(self: *Self) void {
            self.buffer.deinit();
            _ = self.broadcast_future.cancel(self.io) catch {};
        }

        fn init_actor(self: *Self, ctx: T.Context, config: Config) !void {
            const length = utils.NonZero(u64).init(config.blocks_per_epoch) orelse
                return error.InvalidEpochLength;
            const actor_config: Actor.Config = .{
                .provider = config.provider,
                .epocher = .new(length),
                .start = .{ .genesis = config.genesis },
                .partition_prefix = self.names[6],
                .mailbox_size = config.mailbox_size,
                .view_retention = .new(10),
                .prunable_items_per_section = config.items_per_section,
                .page_cache = config.page_cache,
                .replay_buffer = config.replay_buffer,
                .key_write_buffer = config.write_buffer,
                .value_write_buffer = config.write_buffer,
                .block_codec_config = config.block_codec_config,
                .max_repair = 10,
                .max_pending_acks = 1,
                .strategy = config.strategy,
            };
            const initialized = try Actor.init(
                ctx.child("marshal"),
                .{ .archive = &self.finalizations },
                .{ .archive = &self.blocks },
                actor_config,
            );
            self.actor = initialized.actor;
            self.mailbox = initialized.mailbox;
            const processed = initialized.floor.processed;
            self.processed = if (processed) |value| value.height() else null;
        }

        /// Starts the actor with `application` (taken), which receives finalized blocks, and
        /// returns its task. The caller joins or aborts it exactly once, before `deinit`.
        pub fn start(
            self: *Self,
            application: T.Application,
        ) !runtime.context.Handle(anyerror!void) {
            const initialized = self.actor orelse unreachable; // `init` set it; `start` once.
            const handle = try initialized.start(
                application,
                self.buffer.clone(),
                self.resolver.receiver,
                self.resolver.mailbox,
            );
            self.actor = null;
            return handle;
        }

        /// Stops the engines and releases the node's storage handles, as a crash would, so a
        /// later `init` can reopen the same partitions. A started actor's task must have ended.
        pub fn deinit(self: *Self) void {
            if (self.actor) |unstarted| {
                // `start` would have taken the resolver's receiver and mailbox.
                unstarted.deinit();
                self.resolver.mailbox.deinit();
                self.resolver.receiver.deinit();
            }
            self.stop_resolver();
            self.stop_broadcast();
            self.mailbox.deinit();
            self.close_archives();
            for (self.names) |name| self.gpa.free(name);
            self.* = undefined;
        }
    };
}
