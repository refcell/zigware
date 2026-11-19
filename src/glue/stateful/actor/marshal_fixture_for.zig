//! The marshal fixture generic over its block types (`FixtureFor`); marshal_fixture.zig
//! instantiates it with marshal's mock types and re-exports that instantiation under its
//! long-standing names. A separate file because Zig rejects a member that shares a name with
//! a declaration of the enclosing file. Only tests import it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const resolver_api = @import("resolver");
const runtime = @import("runtime");
const storage = @import("storage");

const marshal = consensus.marshal;
const harness = marshal.mocks.harness;
const handler = marshal.resolver.handler;
const Ctx = runtime.deterministic.Context;
const Floor = marshal.core.Floor;
const utils = @import("utils");

/// The fixture over block types `T` (marshal's mock types are `Defaults`). `T` declares `B`
/// (the application block), `D`, `K`, `S` (a simplex scheme), `Finalization`, `Validators` (the
/// signing fixture), `Provider`, `Application` (the reporter marshal starts with), and
/// `genesis(Allocator) !V.Block`.
pub fn FixtureFor(comptime T: type) type {
    return struct {
        pub const B = T.B;
        pub const D = T.D;
        pub const K = T.K;
        pub const S = T.S;
        pub const V = marshal.standard.Standard(B);
        /// The marshal block (digested) the mailbox serves.
        pub const Block = V.Block;
        pub const Finalization = T.Finalization;
        pub const Validators = T.Validators;
        pub const Reporter = T.Application;

        /// A backfill resolver whose archives are pre-seeded, so every fetch is ignored (commonware
        /// `IgnoreResolver`).
        pub const IgnoreResolver = struct {
            pub const Subscriber = handler.Annotation;
            pub const PublicKey = K;
            pub const Key = handler.Key(D);
            const Fetch = resolver_api.Fetch(Key, Subscriber);
            const Feedback = resolver_api.Feedback;

            pub fn clone(self: IgnoreResolver) IgnoreResolver {
                return self;
            }

            pub fn deinit(_: *IgnoreResolver) void {}

            pub fn fetch(_: *IgnoreResolver, _: Fetch) Allocator.Error!Feedback {
                return .ok;
            }

            pub fn fetch_all(_: *IgnoreResolver, _: []const Fetch) Allocator.Error!Feedback {
                return .ok;
            }

            pub fn retain(
                _: *IgnoreResolver,
                _: resolver_api.Predicate(Key, Subscriber),
            ) Allocator.Error!Feedback {
                return .ok;
            }

            pub fn fetch_targeted(_: *IgnoreResolver, _: Fetch, targets: []const K) !Feedback {
                assert(targets.len > 0);
                return .ok;
            }

            pub fn fetch_all_targeted(
                _: *IgnoreResolver,
                _: []const resolver_api.Targeted(Key, Subscriber, K),
            ) Allocator.Error!Feedback {
                return .ok;
            }

            comptime {
                resolver_api.assert_targeted_resolver(IgnoreResolver);
            }
        };

        /// Prunable finalized archives (commonware `prunable_archive_config`): four items per
        /// section, so a floor prunes at commonware's section boundaries. Must not move once
        /// opened.
        pub const PrunableStores = struct {
            const Translator = storage.translator.TwoCap;
            pub const Certificate = Finalization;
            pub const FinalizationArchive = storage.archive.prunable.Archive(
                Translator,
                [32]u8,
                Finalization,
            );
            pub const BlockArchive = storage.archive.prunable.Archive(Translator, [32]u8, B);
            const kinds = [_][]const u8{
                "finalizations-metadata", "finalizations-key", "finalizations-value",
                "blocks-metadata",        "blocks-key",        "blocks-value",
            };

            gpa: Allocator,
            cache_ref: runtime.buffer.paged.CacheRef,
            names: [kinds.len][]u8,
            finalizations: FinalizationArchive,
            blocks: BlockArchive,

            pub fn open(self: *PrunableStores, ctx: Ctx, prefix: []const u8) !void {
                const gpa = ctx.gpa();
                self.gpa = gpa;
                var made: usize = 0;
                errdefer for (self.names[0..made]) |name| gpa.free(name);
                for (kinds, &self.names) |kind, *name| {
                    name.* = try std.fmt.allocPrint(gpa, "{s}-{s}", .{ prefix, kind });
                    made += 1;
                }
                assert(made == kinds.len);
                self.cache_ref = try .init(gpa, harness.page_size, 8);
                errdefer self.cache_ref.deinit();
                const certificates = S.certificate_codec_config_unbounded();
                self.finalizations =
                    try self.archive(Finalization, ctx, 0, "finalizations", certificates);
                errdefer self.finalizations.deinit();
                self.blocks = try self.archive(B, ctx, 3, "finalized_blocks", {});
            }

            pub fn deinit(self: *PrunableStores) void {
                self.blocks.deinit();
                self.finalizations.deinit();
                self.cache_ref.deinit();
                for (self.names) |name| self.gpa.free(name);
                self.* = undefined;
            }

            fn archive(
                self: *PrunableStores,
                comptime Value: type,
                ctx: Ctx,
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
                    .items_per_section = 4,
                    .key_write_buffer = 64,
                    .value_write_buffer = 64,
                    .replay_buffer = 64,
                });
            }
        };

        /// Immutable finalized archives (commonware `archive_config`).
        pub const ImmutableStores = harness.Archives(B);

        /// The marshal actor parameters over finalized stores `Stores`.
        pub fn Params(comptime Stores: type) type {
            return struct {
                pub const Scheme = S;
                pub const Provider = T.Provider;
                pub const Epocher = consensus.types.FixedEpocher;
                pub const Strategy = @import("parallel").Sequential;
                pub const ApplicationBlock = B;
                pub const Block = V.Block;
                pub const Commitment = D;
                pub const Variant = V;
                pub const Acknowledgement = harness.Exact;
                pub const Certificates =
                    marshal.store.Certificates(Stores.FinalizationArchive, S, D, D);
                pub const Blocks = marshal.store.Blocks(Stores.BlockArchive, B);
                pub const Application = Reporter;
                pub const Buffer = marshal.core.NoBuffer(V, K);
                pub const Resolver = IgnoreResolver;
            };
        }

        /// What a fixture starts with (commonware's `Options`).
        pub const Options = struct {
            /// A block to pre-seed in the finalized-blocks archive (borrowed).
            block: ?*const Block = null,
            /// The configured floor (owned by the fixture), else genesis.
            floor: ?Finalization = null,
            max_pending_acks: u32 = 1,
            /// Start the actor with a reporter that acknowledges (true) or holds (false) blocks;
            /// null leaves it unstarted.
            acknowledge: ?bool = true,
            /// A reporter to start with instead (taken), for a `T.Application` without `init` and
            /// `manual_ack`; `acknowledge` must then be non-null.
            reporter: ?Reporter = null,
        };

        /// A marshal actor fixture over stores `Stores` (commonware `MarshalFixture`).
        pub fn Fixture(comptime Stores: type) type {
            return struct {
                const Self = @This();
                pub const Actor = marshal.core.Actor(Params(Stores));
                pub const Mailbox = Actor.Mailbox;

                gpa: Allocator,
                stores: *Stores,
                prefix: []u8,
                mailbox: Mailbox,
                /// The floor the actor restored at init.
                floor: Floor,
                /// The test's handle on the reporter, when started.
                reporter: ?Reporter,
                /// The handler that keeps the actor's resolver receiver open, when started.
                handler: ?handler.Handler(D),
                handle: ?runtime.context.Handle(anyerror!void),
                /// The actor, until it starts (it frees itself once started).
                unstarted: ?*Actor,

                /// Opens the archives under `prefix` on `ctx`'s storage and initializes the actor,
                /// starting it unless `options.acknowledge` is null.
                pub fn init(
                    ctx: Ctx,
                    prefix: []const u8,
                    validators: *const Validators,
                    options: Options,
                ) !Self {
                    const gpa = ctx.gpa();
                    var floor_start = options.floor;
                    errdefer if (floor_start) |*value| value.deinit(gpa);
                    const owned_prefix = try gpa.dupe(u8, prefix);
                    errdefer gpa.free(owned_prefix);
                    const stores = try gpa.create(Stores);
                    errdefer gpa.destroy(stores);
                    try stores.open(ctx, owned_prefix);
                    errdefer stores.deinit();
                    const blocks: Params(Stores).Blocks = .{ .archive = &stores.blocks };
                    if (options.block) |block| {
                        try blocks.put(block.digest(), block.inner());
                        try blocks.sync();
                    }
                    const start: marshal.Start(S, D, V.Block) = if (floor_start) |value|
                        .{ .floor = value }
                    else
                        .{ .genesis = try T.genesis(gpa) };
                    floor_start = null;
                    const initialized = try Actor.init(ctx.child("marshal_actor"), .{
                        .archive = &stores.finalizations,
                    }, blocks, config(stores, owned_prefix, validators, start, options));
                    var self: Self = .{
                        .gpa = gpa,
                        .stores = stores,
                        .prefix = owned_prefix,
                        .mailbox = initialized.mailbox,
                        .floor = initialized.floor,
                        .reporter = null,
                        .handler = null,
                        .handle = null,
                        .unstarted = initialized.actor,
                    };
                    if (options.acknowledge) |acknowledge| {
                        try self.start_actor(ctx, acknowledge, options.reporter);
                    } else assert(options.reporter == null);
                    return self;
                }

                fn config(
                    stores: *Stores,
                    prefix: []const u8,
                    validators: *const Validators,
                    start: marshal.Start(S, D, V.Block),
                    options: Options,
                ) Actor.Config {
                    assert(options.max_pending_acks > 0);
                    return .{
                        .provider = .init(&validators.schemes[0]),
                        .epocher = .new(utils.NonZero(u64).init(std.math.maxInt(u64)).?),
                        .start = start,
                        .partition_prefix = prefix,
                        .mailbox_size = 8,
                        .view_retention = .new(1),
                        .prunable_items_per_section = 4,
                        .page_cache = &stores.cache_ref,
                        .replay_buffer = 64,
                        .key_write_buffer = 64,
                        .value_write_buffer = 64,
                        .block_codec_config = {},
                        .max_repair = 1,
                        .max_pending_acks = options.max_pending_acks,
                        .strategy = @import("parallel").sequential,
                    };
                }

                /// Starts an actor initialized with `options.acknowledge == null`, with reporter
                /// `given` (taken) or else one that acknowledges (true) or holds (false) blocks.
                pub fn start_actor(
                    self: *Self,
                    ctx: Ctx,
                    acknowledge: bool,
                    given: ?Reporter,
                ) !void {
                    const gpa = self.gpa;
                    const actor = self.unstarted.?;
                    var reporter: Reporter = given orelse try default_reporter(ctx, acknowledge);
                    errdefer reporter.deinit();
                    const scope = ctx.scope.child("resolver_handler");
                    var channel = try handler.init(D, gpa, ctx.io(), &scope, 8);
                    errdefer channel.receiver.deinit();
                    errdefer channel.handler.deinit();
                    self.handle =
                        try actor.start(reporter.clone(), .{ .gpa = gpa }, channel.receiver, .{});
                    self.unstarted = null;
                    self.reporter = reporter;
                    self.handler = channel.handler;
                    assert(self.handle != null);
                }

                /// A reporter that acknowledges (true) or holds (false) blocks; a reporter type
                /// without `init` and `manual_ack` must be given.
                fn default_reporter(ctx: Ctx, acknowledge: bool) !Reporter {
                    if (comptime !@hasDecl(Reporter, "manual_ack")) return error.ReporterRequired;
                    const gpa = ctx.gpa();
                    if (acknowledge) return Reporter.init(gpa, ctx.io());
                    return Reporter.manual_ack(gpa, ctx.io());
                }

                /// Aborts the actor (if started) and releases its storage, as a crash would.
                pub fn abort(self: *Self) void {
                    if (self.handle) |*handle| {
                        const ended = handle.abort() catch {};
                        ended catch {};
                    }
                    if (self.unstarted) |actor| actor.deinit();
                    if (self.handler) |*value| value.deinit();
                    if (self.reporter) |*value| value.deinit();
                    self.mailbox.deinit();
                    self.stores.deinit();
                    self.gpa.destroy(self.stores);
                    self.gpa.free(self.prefix);
                    self.* = undefined;
                }
            };
        }
    };
}
