//! The stateful e2e engine shared by the single- and multi-database apps (commonware
//! `glue/src/stateful/tests/common.rs`, and the `EngineDefinition` half of
//! `single_db_app.rs` and `multi_db_app.rs`).
//!
//! `StatefulEngine(S)` is a `simulate` engine definition: every validator runs Simplex over
//! marshal's `Deferred` wrapper, the marshal node (prunable archives, buffered broadcast, and
//! the backfill resolver), the probe, the QMDB sync resolvers, and the `Stateful` actor over
//! `S`'s databases.
//! A validator's `NodeState` reads its marshal (processed height, finalized digests) and its
//! databases (the oldest retained operation) for the plan's properties.
//!
//! `S` is the app: `Block` (with `genesis()`), `App` (default-initialized), `Databases` (a
//! `db.Shared` or `db.Tuple`), `DbConfig` (`init(gpa, prefix, cache)`, `config()`,
//! `deinit(gpa)`), `Resolvers` (`init(*Resolvers, ResolverArgs)`, `handles()`, `stop()`,
//! `deinit()`, `payload_size`), and `oldest_retained(databases)`.
//!
//! Reusable outside these tests: `QmdbResolver` (a resolver task with its stop order),
//! `run_stateful` (the actor task that stops the resolvers first), and `stable_leaders`.
//!
//! Differences from commonware:
//! - The node task builds every actor, so `init` only records the incarnation; commonware's
//!   async `init` builds them before `start`.
//! - The marshal node names marshal's own partitions `<prefix>-marshal` (the dkg bootstrap
//!   node's layout); commonware passes the bare prefix.
//! - With state sync enabled, a delayed validator selects its floor through the probe before
//!   marshal starts, as commonware's `init` does, inside its node task.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const simulate = @import("../../simulate/mod.zig");
const node_api = @import("../../dkg/bootstrap/node.zig");
const db = @import("../db/mod.zig");
const actor_mod = @import("../actor/mod.zig");
const probe_mod = @import("../probe/mod.zig");
const qmdb_p2p = @import("../db/p2p/mod.zig");
const state_sync = @import("../db/state_sync.zig");

const simplex = consensus.simplex;
const Epoch = consensus.Epoch;
const Sha256 = cryptography.Sha256;
const ed25519 = cryptography.ed25519;
pub const Digest = Sha256.Digest;
pub const Key = ed25519.PublicKey;
pub const Net = p2p.simulated.Network(Key);
pub const Context = simulate.engine.Context;
pub const Scheme = simplex.mocks.scheme.Scheme(Digest);
pub const Provider = cryptography.certificate.ConstantProvider(Scheme);
const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
pub const RoundRobin = simplex.elector.RoundRobin(Sha256);
pub const BlockContext = simplex.types.Context(Digest, Key);

pub const namespace = "stateful_e2e_test";
pub const num_validators: u32 = 5;
pub const page_size: u16 = 1024;
pub const page_cache_size: usize = 10;
pub const io_buffer_size: usize = 2048;
const test_quota = p2p.Quota.per_second(1024);
/// Votes, certificates, simplex resolver, backfill, broadcast, QMDB sync, and probe.
pub const channel_count = 7;
pub const qmdb_channel = 5;
const probe_channel = 6;
pub const mailbox_size: u32 = 100;
/// Operations served per QMDB sync request and fetched per batch.
pub const sync_batch_size: u64 = 16;
/// Marshal blocks retained with the slowest state sync.
pub const slow_sync_marshal_retention: u64 = 128;
/// Marshal blocks retained when a validator restarts without state sync: its peers must still
/// hold every block it missed while down.
pub const restart_marshal_retention: u64 = 64;

/// Stable leaders with optimistic validation (commonware `stable_leaders`): terms of four views,
/// a 5 s stall timeout above the leader and certification timeouts, and two optimistic views.
pub fn stable_leaders() RoundRobin {
    const length = consensus.types.TermLength.new(utils.NonZero(u32).init(4).?);
    const elector = RoundRobin.default().with_term(length, .from_secs(5), .new(2));
    assert(elector.terms.length.get() == 4);
    assert(elector.terms.stall_timeout != null);
    return elector;
}

pub fn u64_to_digest(value: u64) Digest {
    var result: Digest = .fill(0);
    std.mem.writeInt(u64, result.bytes[0..8], value, .big);
    return result;
}

pub fn digest_to_u64(value: Digest) u64 {
    return std.mem.readInt(u64, value.bytes[0..8], .big);
}

pub fn counter_key() Digest {
    return Sha256.hash(&.{"counter"});
}

pub fn height_key(at: consensus.Height) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, at.get(), .big);
    return Sha256.hash(&.{&bytes});
}

/// The leader of the genesis context: a fixed key, as commonware's `Block::genesis` uses.
pub fn genesis_context() BlockContext {
    const empty: Digest = .fill(0);
    return .{
        .round = .new(.zero(), .zero()),
        .leader = ed25519.PrivateKey.from_seed(0).public_key(),
        .parent = .{ .zero(), empty },
    };
}

/// What an app's `Resolvers.init` builds its resolvers from.
pub const ResolverArgs = struct {
    ctx: Context,
    oracle: Net.Oracle,
    me: Key,
    /// The QMDB sync channel; the resolvers take it.
    channel: Net.Registered,
};

/// One QMDB sync resolver over database `DB` on sender `NetS` and receiver `NetR`: its
/// mailbox and its actor's task. The resolver borrows the databases the actor attaches, so
/// `stop` must run before the actor closes them (see `run_stateful`).
pub fn QmdbResolver(comptime DB: type, comptime NetS: type, comptime NetR: type) type {
    return struct {
        const Self = @This();
        pub const Actor = qmdb_p2p.actor.Actor(qmdb_p2p.actor.Params(
            Key,
            Net.Manager,
            Net.Control,
            DB,
            NetS,
            NetR,
        ));
        pub const Mailbox = Actor.Mailbox;
        /// The largest sync payload this resolver sends with `sync_batch_size` operations.
        pub const payload_size: usize = qmdb_p2p.limits.max_payload_size(
            Actor.Family,
            Digest,
            sync_batch_size,
            @import("codec").fixed_size(Actor.Op).?,
        ) catch unreachable; // Proof: 16 operations fit a u32.

        io: Io,
        mailbox: Mailbox,
        /// Canceled by `stop`; null once stopped.
        task: ?Io.Future(Actor.Error!void),

        /// Starts the resolver on `sender` and `receiver` (both moved in).
        pub fn init(
            self: *Self,
            args: *const ResolverArgs,
            label: []const u8,
            sender: NetS,
            receiver: NetR,
        ) !void {
            const ctx = args.ctx;
            const created = try Actor.create(ctx.gpa(), ctx.io(), ctx.scope.child(label), .{
                .peer_provider = args.oracle.manager(),
                .blocker = args.oracle.control(args.me),
                .database = null,
                .mailbox_size = mailbox_size,
                .me = args.me,
                .fetch_timeout = .from_secs(2),
                .fetch_retry_delay = .from_millis(100),
                .max_serve_ops = sync_batch_size,
                .priority_requests = false,
                .priority_responses = false,
            });
            self.io = ctx.io();
            self.mailbox = created.mailbox;
            errdefer self.mailbox.deinit();
            self.task = created.actor.start(sender, receiver) catch |err| {
                created.actor.destroy();
                return err;
            };
            assert(self.task != null);
        }

        /// Stops the resolver; its task frees the actor and its serve tasks when it returns.
        pub fn stop(self: *Self) void {
            var task = self.task orelse return;
            self.task = null;
            _ = task.cancel(self.io) catch {};
            assert(self.task == null);
        }

        pub fn deinit(self: *Self) void {
            self.stop();
            self.mailbox.deinit();
            self.* = undefined;
        }
    };
}

/// Runs `actor` (a `Stateful`) until it ends or is canceled, stopping `resolvers` first either
/// way. The resolvers borrow the databases the actor closes on its way out (commonware's
/// resolvers hold `Arc` clones), so a crash cancels them before it cancels the actor.
pub fn run_stateful(
    io: Io,
    comptime Stateful: type,
    actor: *Stateful,
    resolvers: anytype,
) anyerror!void {
    comptime assert(@hasDecl(Stateful, "run"));
    const Done = union(enum) { actor: anyerror!void };
    var buffer: [1]Done = undefined;
    var select: Io.Select(Done) = .init(io, &buffer);
    select.concurrent(.actor, Stateful.run, .{actor}) catch |err| {
        resolvers.stop();
        return err;
    };
    const done = select.await() catch |err| {
        resolvers.stop();
        while (select.cancel()) |_| {}
        return err;
    };
    // An actor that ended on its own has already closed its databases.
    resolvers.stop();
    return done.actor;
}

/// The engine definition for app `S` (see the file comment).
pub fn StatefulEngine(comptime S: type) type {
    return struct {
        const Definition = @This();
        pub const PublicKey = Key;
        pub const Engine = Started;
        pub const State = NodeState;
        pub const Block = S.Block;
        pub const Digested = broadcast.Digested(S.Block);

        const NodeTypes = struct {
            pub const Block = S.Block;
            pub const Scheme = engine.Scheme;
            pub const Provider = engine.Provider;
            pub const Strategy = parallel.Sequential;
            pub const Network = Net;
            pub const PeerProvider = Net.Manager;
            pub const Blocker = Net.Control;
            pub const Application = simulate.MonitorReporter(Key, Adapter);
            pub const Context = simulate.engine.Context;
        };
        const Node = node_api.Node(NodeTypes);
        pub const MarshalMailbox = Node.Mailbox;
        const Variant = Node.Variant;
        const Plan = actor_mod.SyncPlan(Scheme, Variant);
        const StatefulP = struct {
            pub const App = S.App;
            pub const Databases = S.Databases;
            pub const Marshal = MarshalMailbox;
            pub const Plan = Definition.Plan;
            pub const Resolvers = S.Resolvers.Handles;
        };
        const Stateful = actor_mod.Stateful(StatefulP);
        pub const StatefulMailbox = Stateful.Mailbox;
        const ProbeSource = probe_mod.MarshalSource(MarshalMailbox);
        const Probe = probe_mod.Probe(struct {
            pub const Scheme = engine.Scheme;
            pub const Digest = Sha256.Digest;
            pub const Provider = engine.Provider;
            pub const Source = ProbeSource;
            pub const Blocker = Net.Control;
            pub const NetSender = Net.Sender;
            pub const NetReceiver = Net.Receiver;
        });

        /// The stateful mailbox as marshal's `Deferred` application (which passes no upstream
        /// input) and as marshal's finalized-block reporter.
        const Adapter = struct {
            pub const Activity = StatefulMailbox.Update;
            mailbox: StatefulMailbox,

            pub fn propose(
                self: *Adapter,
                ctx: anytype,
                context: BlockContext,
                ancestry: anytype,
            ) anyerror!?Digested {
                return self.mailbox.propose(ctx, context, ancestry, {});
            }

            pub fn verify(
                self: *Adapter,
                ctx: anytype,
                context: BlockContext,
                ancestry: anytype,
            ) anyerror!bool {
                return self.mailbox.verify(ctx, context, ancestry);
            }

            pub fn report(self: *Adapter, activity: Activity) consensus.Feedback {
                return self.mailbox.report(activity);
            }

            pub fn clone(self: *const Adapter) Adapter {
                return .{ .mailbox = self.mailbox.clone() };
            }

            pub fn deinit(self: *Adapter) void {
                self.mailbox.deinit();
                self.* = undefined;
            }
        };

        const Wrapper = consensus.marshal.standard.Deferred(
            Context,
            Scheme,
            Adapter,
            S.Block,
            consensus.types.FixedEpocher,
        );
        const SimplexParams = struct {
            pub const Context = simulate.engine.Context;
            pub const Scheme = engine.Scheme;
            pub const Elector = simplex.elector.RoundRobinElector;
            pub const Blocker = Net.Control;
            pub const Digest = Sha256.Digest;
            pub const Automaton = *Wrapper;
            pub const Relay = *Wrapper;
            pub const Reporter = *Wrapper;
            pub const Strategy = parallel.Sequential;
            pub const Sender = Net.Sender;
            pub const Receiver = Net.Receiver;
        };
        const Simplex = simplex.engine.Engine(SimplexParams);

        /// What a validator's state reads, filled by its node task once marshal and the actor
        /// exist.
        const Inner = struct {
            gpa: Allocator,
            marshal: ?MarshalMailbox = null,
            stateful: ?StatefulMailbox = null,
            /// Whether this incarnation found a floor persisted by an interrupted state sync.
            state_sync_resumed: bool = false,
            /// The height state sync reached (or had completed at), when it was requested.
            state_sync_height: ?u64 = null,
            /// The running incarnation's plan; null while it is down.
            plan: ?*const Plan = null,

            fn deinit(inner: *Inner) void {
                if (inner.marshal) |*mailbox| mailbox.deinit();
                if (inner.stateful) |*mailbox| mailbox.deinit();
                inner.* = undefined;
            }
        };

        /// A validator's state for the plan's properties (commonware `MockValidatorState`).
        pub const NodeState = struct {
            inner: *Inner,

            /// The digest of the finalized block at `at`, if marshal serves it.
            pub fn digest_at_height(self: *const NodeState, at: u64) !?Sha256.Digest {
                const marshal = self.inner.marshal orelse return null;
                var block = try marshal.get_block(.{ .height = .new(at) }) orelse return null;
                defer block.deinit();
                return block.digest();
            }

            /// The oldest operation location the (first full) database still retains.
            pub fn oldest_retained(self: *const NodeState) !u64 {
                const mailbox = self.inner.stateful orelse return error.NotStarted;
                // Borrowed: the set stays with the actor.
                const databases = try mailbox.subscribe_databases();
                return S.oldest_retained(databases);
            }

            pub fn state_sync_height(self: *const NodeState) ?u64 {
                return self.inner.state_sync_height;
            }

            pub fn state_sync_resumed(self: *const NodeState) bool {
                return self.inner.state_sync_resumed;
            }

            /// Whether the running incarnation's plan recorded state sync completion.
            pub fn state_sync_completed(self: *const NodeState) bool {
                const plan = self.inner.plan orelse return false;
                return plan.completed() != null;
            }

            /// Marshal's processed height, zero before it starts or once it stops.
            pub fn processed_height(self: *const NodeState) u64 {
                const marshal = self.inner.marshal orelse return 0;
                // A plan checks its exit as the runner shuts it down: keep that cancel pending,
                // or the root's next request blocks where no cancel can reach it.
                const processed = marshal.get_processed() catch |err| {
                    if (err == error.Canceled) marshal.io.recancel();
                    return 0;
                };
                return if (processed) |value| value.height().get() else 0;
            }
        };

        /// A started validator: what its node task takes.
        pub const Started = struct {
            context: Context,
            index: usize,
            delayed: bool,
            public_key: Key,
            oracle: Net.Oracle,
            channels: [channel_count]Net.Registered,
            monitor: simulate.events.Monitor(Key),
            engine: *const Definition,
            inner: *Inner,
        };

        gpa: Allocator,
        fixture: Fixture,
        /// Leader election (commonware `with_elector`); the default rotates every view.
        elector: RoundRobin = .default(),
        /// Marshal blocks retained beyond the acknowledgement window.
        retained_marshal_blocks: u64 = 10,
        /// A validator whose actors fail (an injected storage fault) stays down until the plan
        /// restarts it, as commonware's engine handle ends; otherwise a failure panics.
        tolerate_failures: bool = false,
        /// Delayed validators join through peer state sync.
        enable_state_sync: bool = false,
        sync_config: state_sync.SyncEngineConfig = .{
            .fetch_batch_size = sync_batch_size,
            .apply_batch_size = 64,
            .max_outstanding_requests = 8,
        },

        pub fn create(gpa: Allocator, n: u32) !Definition {
            assert(n > 0);
            var rng = utils.rng.test_rng();
            const fixture = try simplex.mocks.scheme.fixture(Digest, gpa, &rng, namespace, n);
            assert(fixture.participants.len == n);
            return .{ .gpa = gpa, .fixture = fixture };
        }

        pub fn deinit(self: *Definition) void {
            self.fixture.deinit(self.gpa);
            self.* = undefined;
        }

        pub fn participants(self: *const Definition) []const Key {
            return self.fixture.participants;
        }

        pub fn channels(_: *const Definition) []const simulate.ChannelSpec {
            const specs = comptime blk: {
                var list: [channel_count]simulate.ChannelSpec = undefined;
                for (&list, 0..) |*spec, index| spec.* = .{ .channel = index, .quota = test_quota };
                break :blk list;
            };
            return &specs;
        }

        pub fn max_message_size(self: *const Definition) u32 {
            const count: u32 = @intCast(self.fixture.participants.len);
            return p2p.max_message_size(&.{
                simplex.limits.max_payload_size(Scheme, Digest, count),
                consensus.marshal.max_payload_size(Variant, Scheme, count, {}),
                probe_mod.wire.max_payload_size(Variant, Scheme, count),
                S.Resolvers.payload_size,
            });
        }

        /// Delayed validators join through state sync (commonware `with_state_sync`).
        pub fn with_state_sync(self: *Definition) void {
            self.enable_state_sync = true;
        }

        /// State sync in the smallest batches (commonware `with_slow_state_sync`).
        pub fn with_slow_state_sync(self: *Definition) void {
            self.sync_config = .{
                .fetch_batch_size = 1,
                .apply_batch_size = 1,
                .max_outstanding_requests = 1,
            };
            self.retained_marshal_blocks = slow_sync_marshal_retention;
        }

        /// Retains the blocks a validator restarted without state sync missed (commonware
        /// `with_restart_retention`).
        pub fn with_restart_retention(self: *Definition) void {
            self.retained_marshal_blocks = restart_marshal_retention;
        }

        pub fn with_elector(self: *Definition, elector: RoundRobin) void {
            self.elector = elector;
        }

        pub fn init(self: *const Definition, ctx: simulate.InitContext(Key)) !struct {
            Started,
            NodeState,
        } {
            assert(ctx.channels.len == channel_count);
            assert(ctx.public_key.eql(self.fixture.participants[ctx.index]));
            const inner = try self.gpa.create(Inner);
            inner.* = .{ .gpa = self.gpa };
            var registered: [channel_count]Net.Registered = undefined;
            @memcpy(&registered, ctx.channels);
            const started: Started = .{
                .context = ctx.context,
                .index = ctx.index,
                .delayed = ctx.delayed,
                .public_key = ctx.public_key,
                .oracle = ctx.oracle,
                .channels = registered,
                .monitor = ctx.monitor,
                .engine = self,
                .inner = inner,
            };
            return .{ started, .{ .inner = inner } };
        }

        pub fn start(started: Started) !simulate.engine.Handle {
            return started.context.spawn(run_node, .{started});
        }

        pub fn deinit_state(state: *NodeState) void {
            const inner = state.inner;
            const gpa = inner.gpa;
            inner.deinit();
            gpa.destroy(inner);
            state.* = undefined;
        }

        /// Runs a validator until the plan aborts it; an engine that stops on its own fails the
        /// run.
        fn run_node(ctx: Context, started: Started) void {
            const gpa = ctx.gpa();
            const validator = gpa.create(Validator) catch @panic("out of memory");
            defer gpa.destroy(validator);
            validator.run(ctx, started) catch |err| {
                if (err == error.Canceled) return;
                // A crash aborts this task's subtree, so an actor can end before this task
                // notices.
                ctx.io().checkCancel() catch return;
                if (started.engine.tolerate_failures) return;
                std.debug.panic("stateful validator {d} failed: {t}", .{ started.index, err });
            };
            ctx.io().checkCancel() catch return;
            // An injected fault can end an actor without an error (a closed mailbox).
            if (started.engine.tolerate_failures) return;
            std.debug.panic("stateful validator {d} stopped", .{started.index});
        }

        /// One incarnation's actors. It must not move: the node and the wrapper point into it.
        const Validator = struct {
            gpa: Allocator,
            io: Io,
            prefix: []u8,
            simplex_partition: []u8,
            scheme: Scheme,
            page_cache: runtime.buffer.paged.CacheRef,
            node: Node,
            plan: Plan,
            probe: Probe.Created,
            probe_rng: utils.rng.TestRng,
            probe_task: Io.Future(anyerror!void),
            resolvers: S.Resolvers,
            /// The floor state sync runs toward, when this startup syncs.
            sync_floor: ?consensus.Height = null,
            should_sync: bool,
            prng: std.Random.DefaultPrng,
            db_config: S.DbConfig,
            actor: *Stateful,
            mailbox: StatefulMailbox,
            wrapper: *Wrapper,
            elector: simplex.elector.RoundRobinElector,
            simplex_engine: Simplex,
            /// The validator's state, which reads this incarnation's plan while it runs.
            inner: *Inner,

            fn run(self: *Validator, ctx: Context, started: Started) anyerror!void {
                try self.init(ctx, started);
                defer self.deinit();
                return self.supervise(ctx, started);
            }

            fn init(self: *Validator, ctx: Context, started: Started) !void {
                const gpa = ctx.gpa();
                self.gpa = gpa;
                self.io = ctx.io();
                self.inner = started.inner;
                self.prefix = try std.fmt.allocPrint(gpa, "validator-{d}", .{started.index});
                errdefer gpa.free(self.prefix);
                self.simplex_partition = try std.fmt.allocPrint(gpa, "{s}-simplex", .{self.prefix});
                errdefer gpa.free(self.simplex_partition);
                self.scheme = try started.engine.fixture.schemes[started.index].clone(gpa);
                errdefer self.scheme.deinit(gpa);
                self.page_cache = try .init(gpa, page_size, page_cache_size);
                errdefer self.page_cache.deinit();
                self.plan = try .init(env(ctx, "plan"), self.prefix);
                errdefer self.plan.deinit();
                try self.init_probe(ctx, started);
                errdefer self.deinit_probe();
                try self.select_floor(started);
                try self.init_node(ctx, started);
                errdefer self.node.deinit();
                try self.resolvers.init(.{
                    .ctx = ctx,
                    .oracle = started.oracle,
                    .me = started.public_key,
                    .channel = started.channels[qmdb_channel],
                });
                errdefer self.resolvers.deinit();
                try self.init_stateful(ctx, started);
                errdefer self.deinit_stateful();
                try self.init_consensus(ctx, started);
                assert(self.simplex_partition.len > self.prefix.len);
            }

            fn env(ctx: Context, label: []const u8) db.Env {
                return .{
                    .gpa = ctx.gpa(),
                    .io = ctx.io(),
                    .storage = ctx.storage,
                    .scope = ctx.scope.child(label),
                };
            }

            fn init_probe(self: *Validator, ctx: Context, started: Started) !void {
                const channel = started.channels[probe_channel];
                self.probe = try Probe.init(self.gpa, self.io, .{
                    .provider = .init(&self.scheme),
                    .blocker = started.oracle.control(started.public_key),
                    .mailbox_size = mailbox_size,
                    .minimum_epoch = .zero(),
                    .retry_timeout_ns = 100 * std.time.ns_per_ms,
                }, channel.sender, channel.receiver);
                errdefer {
                    self.probe.probe.deinit();
                    self.probe.mailbox.deinit();
                }
                self.probe_rng = .init(started.index);
                const args = .{ self.probe.probe, &self.probe_rng };
                self.probe_task = try ctx.io().concurrent(run_probe, args);
            }

            fn run_probe(target: *Probe, rng: *utils.rng.TestRng) anyerror!void {
                return target.run(rng, parallel.sequential);
            }

            fn deinit_probe(self: *Validator) void {
                self.probe_task.cancel(self.io) catch {};
                self.probe.probe.deinit();
                self.probe.mailbox.deinit();
            }

            /// Selects and persists a floor when this startup state syncs (commonware's
            /// `init`).
            fn select_floor(self: *Validator, started: Started) !void {
                const requested = started.engine.enable_state_sync and started.delayed;
                self.should_sync = self.plan.should_sync(requested);
                started.inner.state_sync_resumed = self.plan.floor() != null;
                if (self.should_sync) {
                    var receiver = try self.probe.mailbox.subscribe();
                    defer receiver.deinit();
                    var floor = try receiver.recv();
                    defer floor.deinit();
                    try self.plan.set_floor(&floor.finalization);
                    assert(self.plan.floor() != null);
                } else if (requested) {
                    const completed = self.plan.completed();
                    started.inner.state_sync_height = if (completed) |at| at.get() else null;
                }
            }

            fn init_node(self: *Validator, ctx: Context, started: Started) !void {
                const raw = S.Block.genesis();
                var genesis = try Digested.precomputed(self.gpa, raw, raw.digest());
                var start_genesis = Digested.precomputed(self.gpa, raw, raw.digest()) catch |err| {
                    genesis.deinit();
                    return err;
                };
                const planned = self.plan.marshal_start(Digested, start_genesis);
                const marshal_start: Node.Start = planned catch |err| {
                    start_genesis.deinit();
                    genesis.deinit();
                    return err;
                };
                if (marshal_start == .floor) start_genesis.deinit();
                const backfill = started.channels[3];
                const broadcast_channel = started.channels[4];
                try self.node.init(ctx, .{
                    .public_key = started.public_key,
                    .peer_provider = started.oracle.manager(),
                    .blocker = started.oracle.control(started.public_key),
                    .provider = .init(&self.scheme),
                    .strategy = .{},
                    .partition_prefix = self.prefix,
                    .page_cache = &self.page_cache,
                    .genesis = genesis,
                    .start = marshal_start,
                    .block_codec_config = {},
                    .blocks_per_epoch = std.math.maxInt(u64),
                    .items_per_section = 10,
                    .mailbox_size = mailbox_size,
                    .write_buffer = io_buffer_size,
                    .replay_buffer = io_buffer_size,
                    .fetch_timeout = .from_secs(2),
                    .fetch_retry_delay = .from_millis(100),
                }, .{ .sender = backfill.sender, .receiver = backfill.receiver }, .{
                    .sender = broadcast_channel.sender,
                    .receiver = broadcast_channel.receiver,
                });
                // The node took `genesis` and `marshal_start`, even had it failed.
                assert(self.node.actor != null);
            }

            fn init_stateful(self: *Validator, ctx: Context, started: Started) !void {
                var seed: [8]u8 = undefined;
                ctx.io().random(&seed);
                self.prng = .init(std.mem.readInt(u64, &seed, .little));
                self.db_config = try .init(self.gpa, self.prefix, &self.page_cache);
                errdefer self.db_config.deinit(self.gpa);
                const engine_def = started.engine;
                self.actor, self.mailbox = try Stateful.init(self.gpa, self.io, .{
                    .app = .{},
                    .env = env(ctx, "stateful"),
                    .db_config = self.db_config.config(),
                    .marshal = self.node.mailbox.clone(),
                    .mailbox_size = mailbox_size,
                    .plan = &self.plan,
                    .prune_config = .{
                        .maintenance_interval = 5,
                        .retained_marshal_blocks = engine_def.retained_marshal_blocks,
                        .retained_qmdb_blocks = 0,
                    },
                    .max_pending_acks = 1,
                    .random = self.prng.random(),
                    .sync_config = engine_def.sync_config,
                    .resolvers = self.resolvers.handles(),
                    .floor = self.node.floor,
                });
                assert(self.should_sync == (self.plan.floor() != null));
            }

            fn deinit_stateful(self: *Validator) void {
                self.mailbox.deinit();
                self.actor.deinit();
                self.db_config.deinit(self.gpa);
            }

            fn init_consensus(self: *Validator, ctx: Context, started: Started) !void {
                const gpa = self.gpa;
                const adapter: Adapter = .{ .mailbox = self.mailbox.clone() };
                const length = utils.NonZero(u64).init(std.math.maxInt(u64)).?;
                const marshal = self.node.mailbox.clone();
                const epocher: consensus.types.FixedEpocher = .new(length);
                self.wrapper = try Wrapper.create(ctx.child("deferred"), adapter, marshal, epocher);
                errdefer self.wrapper.destroy();
                const count: u32 = @intCast(started.engine.fixture.participants.len);
                self.elector = try started.engine.elector.build(gpa, count);
                errdefer self.elector.deinit(gpa);
                try self.simplex_engine.init(ctx.child("simplex"), .{
                    .scheme = self.scheme,
                    .elector = self.elector,
                    .blocker = started.oracle.control(started.public_key),
                    .automaton = self.wrapper,
                    .relay = self.wrapper,
                    .reporter = self.wrapper,
                    .track_historical_votes = false,
                    .strategy = .{},
                    .partition = self.simplex_partition,
                    .mailbox_size = 3,
                    .epoch = Epoch.zero(),
                    .floor = .{ .genesis = S.Block.genesis().digest() },
                    .replay_buffer = io_buffer_size,
                    .write_buffer = io_buffer_size,
                    .page_cache = &self.page_cache,
                    .leader_timeout = .from_secs(1),
                    .certification_timeout = .from_secs(2),
                    .timeout_retry = .from_millis(500),
                    .view_retention = .new(10),
                    .skip = .{ .enabled = .{ .timeout = .from_secs(5) } },
                    .fetch_timeout = .from_secs(2),
                    .fetch_retry_delay = .from_secs(2),
                    .forward = .disabled,
                });
            }

            fn stateful_task(_: Context, self: *Validator) anyerror!void {
                return run_stateful(self.io, Stateful, self.actor, &self.resolvers);
            }

            fn simplex_task(ctx: Context, self: *Validator, started: Started) anyerror!void {
                const votes = convert(started.channels[0]);
                const certificates = convert(started.channels[1]);
                const resolver = convert(started.channels[2]);
                return Simplex.run(ctx, &self.simplex_engine, votes, certificates, resolver);
            }

            fn convert(channel: Net.Registered) simplex.engine.Channel(SimplexParams) {
                return .{ .sender = channel.sender, .receiver = channel.receiver };
            }

            fn buffer_task(_: Context, self: *Validator) anyerror!void {
                return self.node.watch_broadcast();
            }

            /// Starts the actor, marshal, and simplex, and runs until one of them or buffered
            /// broadcast ends (commonware's engine handle).
            fn supervise(self: *Validator, ctx: Context, started: Started) anyerror!void {
                var handles: [4]runtime.context.Handle(anyerror!void) = undefined;
                const reporter = NodeTypes.Application.init(
                    started.public_key,
                    started.monitor,
                    .{ .mailbox = self.mailbox.clone() },
                );
                handles[1] = try self.node.start(reporter);
                // Until `select` takes every handle, a failure stops marshal here.
                var marshal_owned = true;
                errdefer if (marshal_owned) {
                    const ended = handles[1].abort();
                    if (ended) |result| result catch {} else |_| {}
                };
                started.inner.marshal = self.node.mailbox.clone();
                started.inner.stateful = self.mailbox.clone();
                started.inner.plan = &self.plan;
                // Attaching marshal puts the probe in service; a syncing node consumed its
                // floor.
                try self.probe.mailbox.attach(.{ .mailbox = self.node.mailbox.clone() });
                if (self.should_sync) try self.await_floor_block(started);
                handles[0] = try ctx.child("stateful").spawn(stateful_task, .{self});
                handles[2] = try ctx.child("engine").spawn(simplex_task, .{ self, started });
                handles[3] = try ctx.child("buffer").spawn(buffer_task, .{self});
                marshal_owned = false;
                const first = try runtime.context.select(anyerror!void, self.io, &handles);
                return first;
            }

            /// Records the height of the floor block state sync runs toward, once marshal
            /// serves it.
            fn await_floor_block(self: *Validator, started: Started) !void {
                assert(self.should_sync);
                const payload = self.plan.floor().?.proposal.payload;
                var receiver = try self.node.mailbox.subscribe_by_commitment(payload, .wait);
                defer receiver.deinit();
                var block = try receiver.recv();
                defer block.deinit();
                started.inner.state_sync_height = block.inner().height().get();
            }

            fn deinit(self: *Validator) void {
                const gpa = self.gpa;
                self.inner.plan = null;
                self.simplex_engine.deinit();
                self.elector.deinit(gpa);
                self.wrapper.destroy();
                self.deinit_stateful();
                self.resolvers.deinit();
                self.node.deinit();
                self.deinit_probe();
                self.plan.deinit();
                self.page_cache.deinit();
                self.scheme.deinit(gpa);
                gpa.free(self.simplex_partition);
                gpa.free(self.prefix);
                self.* = undefined;
            }
        };
    };
}

const engine = @This();
