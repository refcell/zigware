//! The single-database stateful e2e engine (commonware `glue/src/stateful/tests/single_db_app.rs`
//! and `common.rs`).
//!
//! `SingleDbEngine` is a `simulate` engine definition: every validator runs Simplex over marshal's
//! `Deferred` wrapper, the marshal node (prunable archives, buffered broadcast, and the backfill
//! resolver), and the `Stateful` actor over one unordered fixed QMDB. Its `App` bumps a counter
//! and records each height, and every block commits to the resulting state through its sync
//! target. A validator's `NodeState` reads its marshal (processed height, finalized digests) and
//! its databases (the oldest retained operation) for the plan's properties.
//!
//! Differences from commonware:
//! - The node task builds every actor, so `init` only records the incarnation; commonware's
//!   async `init` builds them before `start`.
//! - The marshal node names marshal's own partitions `<prefix>-marshal` (the dkg bootstrap
//!   node's layout); commonware passes the bare prefix.
//! - The qmdb sync resolver (channel 5) and probe (channel 6) channels are registered but unused:
//!   this engine has no state sync yet.

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
const simulate = @import("../../simulate/mod.zig");
const node_api = @import("../../dkg/bootstrap/node.zig");
const db = @import("../db/mod.zig");
const actor_mod = @import("../actor/mod.zig");
const processor_mod = @import("../actor/processor/processor.zig");
const testing_mod = @import("../actor/processor/testing.zig");

const simplex = consensus.simplex;
const Height = consensus.Height;
const Epoch = consensus.Epoch;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const ed25519 = cryptography.ed25519;
pub const Key = ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Context = simulate.engine.Context;
pub const Any = testing_mod.Any;
pub const Scheme = simplex.mocks.scheme.Scheme(Digest);
const Provider = cryptography.certificate.ConstantProvider(Scheme);
const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
const SyncTarget = Any.SyncTarget;

pub const namespace = "stateful_e2e_test";
pub const num_validators: u32 = 5;
const page_size: u16 = 1024;
const page_cache_size: usize = 10;
const io_buffer_size: usize = 2048;
const test_quota = p2p.Quota.per_second(1024);
const channel_count = 7;
const mailbox_size: u32 = 100;

/// A block carrying its consensus context and the state it commits to (commonware `Block`):
/// `context || parent || height || state_root || range`, hashed with SHA-256.
pub const Block = struct {
    pub const Digest = Sha256.Digest;
    pub const Context = simplex.types.Context(Sha256.Digest, Key);
    pub const Cfg = void;

    context_value: Block.Context,
    parent_value: Sha256.Digest,
    height_value: Height,
    target: SyncTarget,
    /// The hash of the encoding above (not encoded).
    digest_value: Sha256.Digest,

    pub const max_encode_size: usize = codec.max_encode_size(Block.Context).? +
        Sha256.Digest.fixed_size + Height.max_encode_size + Sha256.Digest.fixed_size +
        2 * codec.varint.max_size(u64);

    pub fn init(
        context_value: Block.Context,
        parent_digest: Sha256.Digest,
        at: Height,
        target: SyncTarget,
    ) Block {
        var block: Block = .{
            .context_value = context_value,
            .parent_value = parent_digest,
            .height_value = at,
            .target = target,
            .digest_value = undefined,
        };
        var buffer: [max_encode_size]u8 = undefined;
        var writer = codec.Writer.init(&buffer);
        block.write(&writer);
        block.digest_value = Sha256.hash(&.{writer.written()});
        assert(writer.written().len == block.encode_size());
        return block;
    }

    /// The height-zero block over the empty database (commonware `Block::genesis`).
    pub fn genesis() Block {
        const leader = ed25519.PrivateKey.from_seed(0).public_key();
        const empty: Sha256.Digest = .fill(0);
        const context_value: Block.Context = .{
            .round = .new(.zero(), .zero()),
            .leader = leader,
            .parent = .{ .zero(), empty },
        };
        return init(context_value, empty, .zero(), Any.initial_sync_target());
    }

    pub fn digest(self: Block) Sha256.Digest {
        return self.digest_value;
    }

    pub fn parent(self: Block) Sha256.Digest {
        return self.parent_value;
    }

    pub fn height(self: Block) Height {
        return self.height_value;
    }

    pub fn context(self: Block) Block.Context {
        return self.context_value;
    }

    pub fn write(self: Block, writer: *codec.Writer) void {
        codec.write(Block.Context, self.context_value, writer);
        self.parent_value.write(writer);
        self.height_value.write(writer);
        self.target.write(writer);
    }

    pub fn encode_size(self: Block) usize {
        const size = codec.encode_size(Block.Context, self.context_value) +
            Sha256.Digest.fixed_size + self.height_value.encode_size() +
            self.target.encode_size();
        assert(size <= max_encode_size);
        return size;
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Block {
        const context_value = try codec.read(Block.Context, gpa, reader);
        const parent_digest = try Sha256.Digest.read(gpa, reader, {});
        const at = try Height.read(gpa, reader, {});
        const target = try SyncTarget.read(gpa, reader, {});
        return init(context_value, parent_digest, at, target);
    }
};

pub const Digested = broadcast.Digested(Block);

pub fn u64_to_digest(value: u64) Sha256.Digest {
    var result: Sha256.Digest = .fill(0);
    std.mem.writeInt(u64, result.bytes[0..8], value, .big);
    return result;
}

pub fn digest_to_u64(value: Sha256.Digest) u64 {
    return std.mem.readInt(u64, value.bytes[0..8], .big);
}

pub fn counter_key() Sha256.Digest {
    return Sha256.hash(&.{"counter"});
}

fn height_key(at: Height) Sha256.Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, at.get(), .big);
    return Sha256.hash(&.{&bytes});
}

/// The application: each block increments `counter` and writes `height -> height` (commonware
/// `App`).
pub const App = struct {
    pub const Block = single.Block;
    pub const Context = single.Block.Context;
    pub const Input = void;
    pub const Merkleized = Any.Merkleized;
    const Built = processor_mod.Proposed(App);

    pub fn sync_targets(block: *const single.Block) SyncTarget {
        return block.target;
    }

    fn execute(batches: Any.Unmerkleized, at: Height) !Any.Merkleized {
        var batch = batches;
        errdefer batch.deinit();
        const key = counter_key();
        const current = if (try batch.get(&key)) |value| digest_to_u64(value) else 0;
        try batch.write(key, u64_to_digest(current + 1));
        try batch.write(height_key(at), u64_to_digest(at.get()));
        return batch.merkleize();
    }

    pub fn process(
        _: *App,
        _: Io,
        _: App.Context,
        ancestry: anytype,
        batches: Any.Unmerkleized,
        _: anytype,
    ) !?Any.Merkleized {
        var owned = batches;
        var block = (ancestry.next() catch |err| {
            owned.deinit();
            return err;
        }) orelse {
            owned.deinit();
            return null;
        };
        defer block.deinit();
        return try execute(owned, block.inner().height());
    }

    pub fn propose(
        _: *App,
        _: Io,
        context: App.Context,
        ancestry: anytype,
        batches: Any.Unmerkleized,
        _: void,
    ) !?Built {
        var owned = batches;
        var parent = (ancestry.next() catch |err| {
            owned.deinit();
            return err;
        }) orelse {
            owned.deinit();
            return null;
        };
        defer parent.deinit();
        const at = parent.inner().height().next();
        var merkleized = try execute(owned, at);
        errdefer merkleized.deinit();
        const bounds = &merkleized.inner.bounds;
        const floor = bounds.inactivity_floor;
        const target: SyncTarget = .init(merkleized.root(), floor, bounds.tip.size);
        return .{ .block = .init(context, parent.digest(), at, target), .merkleized = merkleized };
    }

    pub fn capture(
        _: *App,
        _: Io,
        _: App.Context,
        _: *const single.Block,
        _: anytype,
        _: anytype,
    ) !void {}

    pub fn finalized(
        _: *App,
        _: Io,
        _: App.Context,
        _: *const single.Block,
        _: void,
        _: anytype,
    ) !void {}
};

const single = @This();

const NodeTypes = struct {
    pub const Block = single.Block;
    pub const Scheme = single.Scheme;
    pub const Provider = single.Provider;
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
    pub const App = single.App;
    pub const Databases = Any.Shared;
    pub const Marshal = MarshalMailbox;
    pub const Plan = single.Plan;
};
const Stateful = actor_mod.Stateful(StatefulP);
pub const StatefulMailbox = Stateful.Mailbox;

/// The stateful mailbox as marshal's `Deferred` application (which passes no upstream input)
/// and as marshal's finalized-block reporter.
const Adapter = struct {
    pub const Activity = StatefulMailbox.Update;
    mailbox: StatefulMailbox,

    pub fn propose(
        self: *Adapter,
        ctx: anytype,
        context: Block.Context,
        ancestry: anytype,
    ) anyerror!?Digested {
        return self.mailbox.propose(ctx, context, ancestry, {});
    }

    pub fn verify(
        self: *Adapter,
        ctx: anytype,
        context: Block.Context,
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
    Block,
    consensus.types.FixedEpocher,
);
const SimplexParams = struct {
    pub const Context = simulate.engine.Context;
    pub const Scheme = single.Scheme;
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

/// What a validator's state reads, filled by its node task once marshal and the actor exist.
const Inner = struct {
    gpa: Allocator,
    marshal: ?MarshalMailbox = null,
    stateful: ?StatefulMailbox = null,

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

    /// The oldest operation location the database still retains.
    pub fn oldest_retained(self: *const NodeState) !u64 {
        const mailbox = self.inner.stateful orelse return error.NotStarted;
        // Borrowed: the set stays with the actor.
        const databases = try mailbox.subscribe_databases();
        var guard = try databases.read();
        defer guard.deinit();
        return guard.get().inner.bounds().start;
    }

    /// Marshal's processed height, zero before it starts or once it stops.
    pub fn processed_height(self: *const NodeState) u64 {
        const marshal = self.inner.marshal orelse return 0;
        const processed = marshal.get_processed() catch return 0;
        return if (processed) |value| value.height().get() else 0;
    }
};

/// A started validator: what its node task takes.
pub const Started = struct {
    context: Context,
    index: usize,
    public_key: Key,
    oracle: Net.Oracle,
    channels: [channel_count]Net.Registered,
    monitor: simulate.events.Monitor(Key),
    engine: *const SingleDbEngine,
    inner: *Inner,
};

pub const SingleDbEngine = struct {
    pub const PublicKey = Key;
    pub const Engine = Started;
    pub const State = NodeState;

    gpa: Allocator,
    fixture: Fixture,
    /// Marshal blocks retained beyond the acknowledgement window.
    retained_marshal_blocks: u64 = 10,
    /// A validator whose actors fail (an injected storage fault) stays down until the plan
    /// restarts it, as commonware's engine handle ends; otherwise a failure panics.
    tolerate_failures: bool = false,

    pub fn create(gpa: Allocator, n: u32) !SingleDbEngine {
        assert(n > 0);
        var rng = utils.rng.test_rng();
        const fixture = try simplex.mocks.scheme.fixture(Sha256.Digest, gpa, &rng, namespace, n);
        assert(fixture.participants.len == n);
        return .{ .gpa = gpa, .fixture = fixture };
    }

    pub fn deinit(self: *SingleDbEngine) void {
        self.fixture.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn participants(self: *const SingleDbEngine) []const Key {
        return self.fixture.participants;
    }

    pub fn channels(_: *const SingleDbEngine) []const simulate.ChannelSpec {
        const specs = comptime blk: {
            var list: [channel_count]simulate.ChannelSpec = undefined;
            for (&list, 0..) |*spec, index| spec.* = .{ .channel = index, .quota = test_quota };
            break :blk list;
        };
        return &specs;
    }

    pub fn max_message_size(self: *const SingleDbEngine) u32 {
        const count: u32 = @intCast(self.fixture.participants.len);
        return p2p.max_message_size(&.{
            simplex.limits.max_payload_size(Scheme, Sha256.Digest, count),
            consensus.marshal.max_payload_size(Variant, Scheme, count, {}),
        });
    }

    pub fn init(self: *const SingleDbEngine, ctx: simulate.InitContext(Key)) !struct {
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
};

/// Runs a validator until the plan aborts it; an engine that stops on its own fails the run.
fn run_node(ctx: Context, started: Started) void {
    const gpa = ctx.gpa();
    const validator = gpa.create(Validator) catch @panic("out of memory");
    defer gpa.destroy(validator);
    validator.run(ctx, started) catch |err| {
        if (err == error.Canceled) return;
        // A crash aborts this task's subtree, so an actor can end before this task notices.
        ctx.io().checkCancel() catch return;
        if (started.engine.tolerate_failures) return;
        std.debug.panic("stateful validator {d} failed: {t}", .{ started.index, err });
    };
    ctx.io().checkCancel() catch return;
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
    prng: std.Random.DefaultPrng,
    db_names: [3][]u8,
    actor: *Stateful,
    mailbox: StatefulMailbox,
    wrapper: *Wrapper,
    elector: simplex.elector.RoundRobinElector,
    simplex_engine: Simplex,

    fn run(self: *Validator, ctx: Context, started: Started) anyerror!void {
        // The qmdb resolver and probe channels have no actor yet.
        var unused = started.channels;
        defer for (unused[5..]) |*channel| channel.deinit();
        try self.init(ctx, started);
        defer self.deinit();
        return self.supervise(ctx, started);
    }

    fn init(self: *Validator, ctx: Context, started: Started) !void {
        const gpa = ctx.gpa();
        self.gpa = gpa;
        self.io = ctx.io();
        self.prefix = try std.fmt.allocPrint(gpa, "validator-{d}", .{started.index});
        errdefer gpa.free(self.prefix);
        self.simplex_partition = try std.fmt.allocPrint(gpa, "{s}-simplex", .{self.prefix});
        errdefer gpa.free(self.simplex_partition);
        self.scheme = try started.engine.fixture.schemes[started.index].clone(gpa);
        errdefer self.scheme.deinit(gpa);
        self.page_cache = try .init(gpa, page_size, page_cache_size);
        errdefer self.page_cache.deinit();
        try self.init_node(ctx, started);
        errdefer self.node.deinit();
        self.plan = try .init(env(ctx, "plan"), self.prefix);
        errdefer self.plan.deinit();
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

    fn init_node(self: *Validator, ctx: Context, started: Started) !void {
        const raw = Block.genesis();
        var genesis = try Digested.precomputed(self.gpa, raw, raw.digest());
        errdefer genesis.deinit();
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
        assert(self.node.actor != null);
    }

    fn db_config(self: *Validator) !Any.Config {
        const gpa = self.gpa;
        const parts = [_][]const u8{
            "-qmdb-mmr-journal",
            "-qmdb-mmr-metadata",
            "-qmdb-log-journal",
        };
        var names: [parts.len][]u8 = undefined;
        for (&names, parts) |*name, suffix| {
            name.* = try std.mem.concat(gpa, u8, &.{ self.prefix, suffix });
        }
        self.db_names = names;
        return .{
            .merkle = .{
                .journal_partition = names[0],
                .metadata_partition = names[1],
                .items_per_blob = 11,
                .write_buffer = io_buffer_size,
                .replay_buffer = io_buffer_size,
                .cache_ref = &self.page_cache,
            },
            .log = .{
                .partition = names[2],
                .items_per_blob = 7,
                .cache_ref = &self.page_cache,
                .write_buffer = io_buffer_size,
                .replay_buffer = io_buffer_size,
            },
            .translator = .{},
            .init_cache = 1024,
        };
    }

    fn init_stateful(self: *Validator, ctx: Context, started: Started) !void {
        var seed: [8]u8 = undefined;
        ctx.io().random(&seed);
        self.prng = .init(std.mem.readInt(u64, &seed, .little));
        const config = try self.db_config();
        const engine = started.engine;
        self.actor, self.mailbox = try Stateful.init(self.gpa, self.io, .{
            .app = .{},
            .env = env(ctx, "stateful"),
            .db_config = config,
            .marshal = self.node.mailbox.clone(),
            .mailbox_size = mailbox_size,
            .plan = &self.plan,
            .prune_config = .{
                .maintenance_interval = 5,
                .retained_marshal_blocks = engine.retained_marshal_blocks,
                .retained_qmdb_blocks = 0,
            },
            .max_pending_acks = 1,
            .random = self.prng.random(),
        });
        assert(self.plan.floor() == null);
    }

    fn deinit_stateful(self: *Validator) void {
        self.mailbox.deinit();
        self.actor.deinit();
        for (self.db_names) |name| self.gpa.free(name);
    }

    fn init_consensus(self: *Validator, ctx: Context, started: Started) !void {
        const gpa = self.gpa;
        const adapter: Adapter = .{ .mailbox = self.mailbox.clone() };
        const length = utils.NonZero(u64).init(std.math.maxInt(u64)).?;
        const marshal = self.node.mailbox.clone();
        self.wrapper = try Wrapper.create(ctx.child("deferred"), adapter, marshal, .new(length));
        errdefer self.wrapper.destroy();
        const count: u32 = @intCast(started.engine.fixture.participants.len);
        const elector = simplex.elector.RoundRobin(Sha256).default();
        self.elector = try elector.build(gpa, count);
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
            .floor = .{ .genesis = Block.genesis().digest() },
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
        return self.actor.run();
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

    /// Starts the actor, marshal, and simplex, and runs until one of them or buffered broadcast
    /// ends (commonware's engine handle).
    fn supervise(self: *Validator, ctx: Context, started: Started) anyerror!void {
        var handles: [4]runtime.context.Handle(anyerror!void) = undefined;
        handles[0] = try ctx.child("stateful").spawn(stateful_task, .{self});
        const reporter = NodeTypes.Application.init(
            started.public_key,
            started.monitor,
            .{ .mailbox = self.mailbox.clone() },
        );
        handles[1] = try self.node.start(reporter);
        started.inner.marshal = self.node.mailbox.clone();
        started.inner.stateful = self.mailbox.clone();
        handles[2] = try ctx.child("engine").spawn(simplex_task, .{ self, started });
        handles[3] = try ctx.child("buffer").spawn(buffer_task, .{self});
        const first = try runtime.context.select(anyerror!void, self.io, &handles);
        return first;
    }

    fn deinit(self: *Validator) void {
        const gpa = self.gpa;
        self.simplex_engine.deinit();
        self.elector.deinit(gpa);
        self.wrapper.destroy();
        self.deinit_stateful();
        self.plan.deinit();
        self.node.deinit();
        self.page_cache.deinit();
        self.scheme.deinit(gpa);
        gpa.free(self.simplex_partition);
        gpa.free(self.prefix);
        self.* = undefined;
    }
};
