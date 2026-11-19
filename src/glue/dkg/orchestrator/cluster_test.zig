//! commonware orchestrator `mod.rs` tests that run a cluster: every node composes a real
//! marshal (`bootstrap.Node`: archives, buffered broadcast, backfill resolver) under the
//! orchestrator, on the simulated network. Each node's simplex application only records the
//! contexts it is asked to propose on (commonware `MockApplication`), so finalized blocks
//! reach marshal only when a test seeds the boundary block or a peer serves it.
//! Only the genesis and marshal-shutdown tests run per push; the rest need `-Dslow-tests`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const build_options = @import("build_options");
const mocks = @import("../tests/mocks.zig");
const network = @import("../network.zig");
const Fence = @import("../fence.zig").Fence;
const state_sync = @import("../state_sync.zig");
const node_api = @import("../bootstrap/node.zig");
const actor_mod = @import("actor.zig");
const mailbox_mod = @import("mailbox.zig");

const simplex = consensus.simplex;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const gpa = testing.allocator;
const Ctx = runtime.deterministic.Context;
const Sha256 = cryptography.Sha256;
const Digest = mocks.TestDigest;
const Key = mocks.TestPublicKey;
const Block = mocks.TestBlock;
const Height = consensus.Height;
const Epoch = consensus.Epoch;
const Exact = utils.acknowledgement.Exact;
const Set = utils.ordered.Set(Key);
const Net = p2p.simulated.Network(Key);
const Scheme = simplex.scheme.ed25519.Scheme(Digest);
const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
const Digested = broadcast.Digested(Block);
const namespace = "_COMMONWARE_GLUE_DKG_ORCHESTRATOR_CLUSTER";
const blocks_per_epoch = 2;
const max_nodes = 4;
const max_participants = 16;
const quota = p2p.Quota.per_second(1024);
const backfill_channel = 0;
const vote_channel = 1;
const broadcast_channel = 4;

/// Schemes for every epoch: the committee never changes.
const EpochProvider = struct {
    scheme_value: *const Scheme,

    pub fn scheme(self: *const EpochProvider, epoch: Epoch) ?*const Scheme {
        assert(epoch.get() < std.math.maxInt(u64));
        return self.scheme_value;
    }
};

/// Records each proposal request's context and verifies every payload (commonware
/// `MockApplication`).
const Recorder = struct {
    pub const Context = mocks.TestContext;
    pub const Digest = mocks.TestDigest;
    pub const PublicKey = Key;
    pub const Plan = simplex.lookahead.Plan(Key);
    pub const Activity = simplex.types.Activity(Scheme, mocks.TestDigest);
    const capacity = 256;

    proposals: [capacity]Context = undefined,
    count: u32 = 0,

    pub fn propose(self: *Recorder, io: Io, request: Context) Io.Cancelable!?mocks.TestDigest {
        _ = io;
        assert(self.count <= capacity);
        if (self.count < capacity) {
            self.proposals[self.count] = request;
            self.count += 1;
        }
        return Sha256.hash(&.{"proposal"});
    }

    pub fn verify(
        self: *Recorder,
        io: Io,
        request: Context,
        payload: mocks.TestDigest,
    ) Io.Cancelable!?bool {
        _ = .{ self, io, request, payload };
        return true;
    }

    pub fn broadcast(self: *Recorder, payload: mocks.TestDigest, plan: Plan) consensus.Feedback {
        _ = .{ self, payload, plan };
        return .ok;
    }

    pub fn report(self: *Recorder, activity: Activity) consensus.Feedback {
        _ = .{ self, activity };
        return .ok;
    }

    /// The first recorded proposal in `epoch`, if any.
    fn proposal_in(self: *const Recorder, epoch: Epoch) ?Context {
        assert(self.count <= capacity);
        for (self.proposals[0..self.count]) |proposal| {
            if (proposal.round.epoch.get() == epoch.get()) return proposal;
        }
        return null;
    }
};

const Filtered = mocks.FilteredReceiver(Net.Receiver);
/// The network marshal's resolver and buffered broadcast run on: a deaf node drops every
/// backfill message it receives, so it never serves fetches.
const ClusterNet = struct {
    pub const Sender = Net.Sender;
    pub const Receiver = Filtered;
};
const cluster = @This();

/// The marshal node, orchestrator mailbox, and state-sync plan over blocks whose epoch infos
/// carry `Dir` directories (key-only `Unit`, or in-band `Addresses`).
fn Kit(comptime Dir: type) type {
    return struct {
        const K = @This();
        pub const Block = mocks.MockBlock(Dir);
        pub const Digested = broadcast.Digested(K.Block);
        pub const Mailbox = mailbox_mod.Mailbox(K.Block, Exact);
        pub const MarshalNode = node_api.Node(struct {
            pub const Block = K.Block;
            pub const Scheme = cluster.Scheme;
            pub const Provider = cryptography.certificate.ConstantProvider(cluster.Scheme);
            pub const Strategy = parallel.Sequential;
            pub const Network = ClusterNet;
            pub const PeerProvider = Net.Manager;
            pub const Blocker = Net.Control;
            pub const Application = K.Mailbox;
            pub const Context = Ctx;
        });
        pub const Plan = state_sync.Plan(cluster.Scheme, Digest, mocks.TestBlsVariant, Dir);

        /// The bare genesis block led by `leader`, or (key-only) one carrying epoch zero's
        /// info (commonware `make_genesis_block`).
        fn genesis(leader: Key, dealers: []const Key, players: []const Key) !K.Block {
            if (Dir == utils.sequence.Unit) return make_genesis_block(leader, dealers, players);
            const raw = mocks.genesis_block(leader);
            return .init(raw.context(), raw.parent(), raw.height(), 0);
        }
    };
}

fn OrchestratorTypes(comptime M: type) type {
    return struct {
        pub const Context = Ctx;
        pub const Block = Kit(M.Directory).Block;
        pub const Ack = Exact;
        pub const Scheme = cluster.Scheme;
        pub const Provider = *const EpochProvider;
        pub const Manager = *M;
        pub const Marshal = Kit(M.Directory).MarshalNode.Mailbox;
        pub const Blocker = Net.Control;
        pub const ElectorConfig = simplex.elector.RoundRobin(Sha256);
        pub const Elector = simplex.elector.RoundRobinElector;
        pub const Automaton = *Recorder;
        pub const Relay = *Recorder;
        pub const Reporter = *Recorder;
        pub const Strategy = parallel.Sequential;
        pub const Sender = Net.Sender;
        pub const Receiver = Net.Receiver;

        pub fn build_elector(
            config: ElectorConfig,
            allocator: std.mem.Allocator,
            n: u32,
        ) !Elector {
            return config.build(allocator, n);
        }
    };
}
const KeyOnly = network.KeyOnlyManager(Net.Manager);
const Failing = mocks.FailingManager(Net.Manager);
const Info = @import("../types.zig").EpochInfo(mocks.TestBlsVariant, Key, utils.sequence.Unit);

/// `epoch`'s info: an output dealt to `dealers` from seed `epoch + 1`, with `players` as its
/// players and next players (commonware `make_epoch_info`).
fn make_epoch_info(epoch: u64, dealers: []const Key, players: []const Key) !Info {
    assert(dealers.len > 0);
    assert(players.len >= dealers.len);
    var rng = utils.rng.TestRng.init(epoch + 1);
    const owned = try Set.from_dedup(gpa, dealers);
    const V = mocks.TestBlsVariant;
    var dealt = try fd.deal(V, Key, utils.N3f1, gpa, &rng, .non_zero_counter, owned);
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    errdefer dealt.output.deinit(gpa);
    var player_set = try Set.from_dedup(gpa, players);
    errdefer player_set.deinit(gpa);
    return .{
        .outcome = .success,
        .epoch = .new(epoch),
        .output = dealt.output,
        .players = try player_set.clone(gpa),
        .next_players = player_set,
        .directory = .{},
    };
}

fn with_info(raw: Block, info: Info) !Block {
    assert(raw.encoded == null);
    const block = try raw.with_payload(gpa, max_participants, .{ .epoch_info = info });
    assert(block.encoded != null);
    return block;
}

/// The genesis block led by `leader`, carrying epoch zero's info (commonware
/// `make_genesis_block`).
fn make_genesis_block(leader: Key, dealers: []const Key, players: []const Key) !Block {
    var info = try make_epoch_info(0, dealers, players);
    defer info.deinit(gpa);
    return with_info(mocks.genesis_block(leader), info);
}

/// Epoch zero's final block, carrying epoch one's info (commonware `make_height_one_block`).
fn make_height_one_block(leader: Key, dealers: []const Key, players: []const Key) !Block {
    var genesis = try make_genesis_block(leader, dealers, players);
    defer genesis.deinit(gpa);
    const context: mocks.TestContext = .{
        .round = .new(.zero(), .new(1)),
        .leader = leader,
        .parent = .{ .zero(), genesis.digest() },
    };
    var info = try make_epoch_info(1, dealers, players);
    defer info.deinit(gpa);
    return with_info(.init(context, genesis.digest(), .new(1), 1), info);
}

/// A finalization of `payload` at view 1 of `epoch` signed by every scheme.
fn make_finalization(
    fixture: *const Fixture,
    epoch: Epoch,
    payload: Digest,
) !simplex.types.Finalization(Scheme, Digest) {
    assert(fixture.schemes.len <= max_nodes);
    const proposal = simplex.types.Proposal(Digest).init(.new(epoch, .new(1)), .zero(), payload);
    const Finalize = simplex.types.Finalize(Scheme, Digest);
    var finalizes: [max_nodes]Finalize = undefined;
    const count = fixture.schemes.len;
    for (fixture.schemes, finalizes[0..count]) |*scheme, *vote| {
        vote.* = (try Finalize.sign(gpa, scheme, proposal)).?;
    }
    const Finalization = simplex.types.Finalization(Scheme, Digest);
    const signers = &fixture.schemes[0];
    const result = try Finalization.from_votes(gpa, signers, finalizes[0..count], .{});
    assert(result.view().get() == 1);
    return result;
}

/// How a cluster's epoch infos assign roles and which nodes misbehave (commonware `Layout`).
const Layout = struct {
    /// Leading participants listed as dealers (primary peers); null lists every participant.
    dealers: ?usize = null,
    /// Nodes whose backfill receiver drops every message.
    deaf: []const usize = &.{},

    fn is_deaf(layout: Layout, index: usize) bool {
        assert(index < max_nodes);
        return std.mem.indexOfScalar(usize, layout.deaf, index) != null;
    }
};

/// One validator: its marshal node, its orchestrator, and what they borrow (commonware
/// `Node`). Must not move once started.
fn ClusterNode(comptime M: type) type {
    return struct {
        const Self = @This();
        pub const Types = OrchestratorTypes(M);
        pub const Actor = actor_mod.Actor(Types);
        const K = Kit(M.Directory);

        ctx: Ctx,
        prefix_buffer: [32]u8,
        prefix: []const u8,
        page_cache: runtime.buffer.paged.CacheRef,
        simplex_cache: runtime.buffer.paged.CacheRef,
        node: K.MarshalNode,
        manager: M,
        provider: EpochProvider,
        recorder: Recorder,
        fence: Fence,
        plan: K.Plan,
        orchestrator: Actor,
        mailbox: K.Mailbox,
        channels: [3]Actor.Channel,
        marshal_handle: ?runtime.context.Handle(anyerror!void),
        task: ?Io.Future(anyerror!void),

        pub const Start = struct {
            index: usize,
            boundary: ?*const K.Block,
            gate_epoch: u64,
            dealers: []const Key,
            deaf: bool,
            marshal_started: bool = true,
            /// State-sync material the node starts from (owned); null disables state sync.
            state_sync: ?K.Plan.Material = null,
        };

        fn start(
            self: *Self,
            ctx: Ctx,
            net: *Net,
            fixture: *const Fixture,
            manager: M,
            options: Start,
        ) !void {
            assert(options.index < fixture.participants.len);
            var material = options.state_sync;
            errdefer if (material) |*owned| owned.deinit(gpa);
            self.ctx = ctx;
            self.prefix = try std.fmt.bufPrint(
                &self.prefix_buffer,
                "orchestrator-node-{d}",
                .{options.index},
            );
            self.page_cache = try .init(gpa, 1024, 16);
            errdefer self.page_cache.deinit();
            self.simplex_cache = try .init(gpa, 1024, 8);
            errdefer self.simplex_cache.deinit();
            try self.init_node(net, fixture, options);
            errdefer self.node.deinit();
            self.manager = manager;
            self.provider = .{ .scheme_value = &fixture.schemes[options.index] };
            self.recorder = .{};
            self.fence = Fence.init(ctx.io());
            self.fence.mark(.new(options.gate_epoch));
            self.plan = if (material) |owned| plan: {
                material = null;
                break :plan try K.Plan.init(gpa, ctx.io(), ctx.storage, .{
                    .partition_prefix = self.prefix,
                    .max_participants = max_participants,
                    .max_supported_mode = mocks.max_supported_mode,
                }, owned);
            } else K.Plan.disabled(gpa, ctx.io());
            errdefer self.plan.deinit();
            try self.start_actors(net, fixture, options);
            assert(self.task != null);
        }

        fn init_node(self: *Self, net: *Net, fixture: *const Fixture, options: Start) !void {
            const key = fixture.participants[options.index];
            const control = net.oracle().control(key);
            const raw = try K.genesis(key, options.dealers, fixture.participants);
            const genesis = try K.Digested.precomputed(gpa, raw, raw.digest());
            const backfill = try control.register(backfill_channel, quota);
            const shared = try control.register(broadcast_channel, quota);
            const filtered: Filtered = if (options.deaf)
                .drop_all(backfill.receiver)
            else
                .pass(backfill.receiver);
            try self.node.init(self.ctx.child("marshal_node"), .{
                .public_key = key,
                .peer_provider = net.oracle().manager(),
                .blocker = control,
                .provider = .init(&fixture.schemes[options.index]),
                .strategy = .{},
                .partition_prefix = self.prefix,
                .page_cache = &self.page_cache,
                .genesis = genesis,
                .block_codec_config = {},
                .blocks_per_epoch = blocks_per_epoch,
                .items_per_section = 10,
                .mailbox_size = 16,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .fetch_timeout = .from_millis(200),
                .fetch_retry_delay = .from_millis(100),
            }, .{ .sender = backfill.sender, .receiver = filtered }, .{
                .sender = shared.sender,
                .receiver = .pass(shared.receiver),
            });
            assert(self.node.actor != null);
        }

        fn config(self: *Self, net: *Net, key: Key) actor_mod.Config(Types) {
            return .{
                .blocker = net.oracle().control(key),
                .manager = &self.manager,
                .provider = &self.provider,
                .marshal = self.node.mailbox.clone(),
                .automaton = &self.recorder,
                .relay = &self.recorder,
                .reporter = &self.recorder,
                .strategy = parallel.sequential,
                .simplex = .{
                    .elector = .default(),
                    .mailbox_size = 16,
                    .replay_buffer = 1024,
                    .write_buffer = 1024,
                    .page_cache = &self.simplex_cache,
                    .leader_timeout = .from_millis(100),
                    .certification_timeout = .from_millis(200),
                    .timeout_retry = .from_millis(500),
                    .fetch_timeout = .from_millis(100),
                    .fetch_retry_delay = .from_millis(100),
                    .view_retention = .new(8),
                    .skip = .disabled,
                    .track_historical_votes = false,
                    .forward = .disabled,
                },
                .gate = self.fence.gate(),
                .state_sync = &self.plan,
                .blocks_per_epoch = blocks_per_epoch,
                .mailbox_size = 16,
                .partition_prefix = self.prefix,
            };
        }

        /// Starts marshal with the orchestrator as its application, seeds the boundary, and
        /// starts the orchestrator on its three consensus channels.
        fn start_actors(self: *Self, net: *Net, fixture: *const Fixture, options: Start) !void {
            const key = fixture.participants[options.index];
            self.orchestrator, self.mailbox = try Actor.init(
                self.ctx.child("orchestrator"),
                self.config(net, key),
            );
            self.marshal_handle = null;
            if (options.marshal_started) {
                self.marshal_handle = try self.node.start(self.mailbox.clone());
            }
            if (options.boundary) |block| try self.seed(fixture, block);
            const control = net.oracle().control(key);
            for (&self.channels, vote_channel..) |*channel, index| {
                const registered = try control.register(index, quota);
                channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
            }
            self.task = try self.ctx.io().concurrent(run_actor, .{self});
            assert((self.marshal_handle != null) == options.marshal_started);
        }

        /// Frees the never-started marshal actor while its mailbox stays open (commonware
        /// dropping `marshal_actor`), which drops the requests queued for it.
        fn drop_unstarted_marshal(self: *Self) void {
            assert(self.marshal_handle == null);
            const unstarted = self.node.actor.?;
            unstarted.deinit();
            self.node.resolver.mailbox.deinit();
            self.node.resolver.receiver.deinit();
            self.node.actor = null;
        }

        fn run_actor(self: *Self) anyerror!void {
            return self.orchestrator.run(self.channels[0], self.channels[1], self.channels[2]);
        }

        /// Hands marshal `block` as certified and finalized (the cluster's boundary).
        fn seed(self: *Self, fixture: *const Fixture, block: *const K.Block) !void {
            assert(block.height().get() == 1);
            const copy = try block.clone(gpa);
            const certified = try K.Digested.precomputed(gpa, copy, copy.digest());
            const round = block.context().round;
            try testing.expect(try self.node.mailbox.certified(round, certified));
            var finalization = try make_finalization(fixture, .zero(), block.digest());
            defer finalization.deinit(gpa);
            const feedback = self.node.mailbox.report(.{ .finalization = finalization });
            try testing.expectEqual(consensus.Feedback.ok, feedback);
        }

        /// Waits for the orchestrator's task to end on its own and returns its result.
        fn join(self: *Self) anyerror!void {
            const result = self.task.?.await(self.ctx.io());
            self.task = null;
            return result;
        }

        /// Stops the orchestrator and marshal and releases everything, as a crash would.
        fn stop(self: *Self) void {
            const io = self.ctx.io();
            assert(self.prefix.len > 0);
            if (self.task) |*task| _ = task.cancel(io) catch {};
            self.task = null;
            if (self.marshal_handle) |handle| {
                if (handle.abort()) |result| result catch {} else |_| {}
            }
            self.marshal_handle = null;
            self.mailbox.deinit();
            self.orchestrator.deinit();
            self.plan.deinit();
            self.fence.close();
            self.node.deinit();
            self.simplex_cache.deinit();
            self.page_cache.deinit();
            assert(self.task == null);
        }
    };
}

const link: p2p.simulated.Link = .{
    .latency = .from_millis(1),
    .jitter = .from_millis(0),
    .success_rate = 1.0,
};

/// A simulated network over `fixture`'s participants with every pair linked, and one node per
/// participant (commonware `Cluster`). Only node 0 may lack the boundary block.
const Cluster = ClusterOf(KeyOnly);

fn ClusterOf(comptime M: type) type {
    return struct {
        const Node = ClusterNode(M);

        ctx: Ctx,
        net: *Net,
        network_task: Io.Future((Io.Cancelable || std.mem.Allocator.Error)!void),
        fixture: Fixture,
        boundary: Block,
        nodes: [max_nodes]Node,
        started: usize,

        const Options = struct {
            nodes: u32,
            seed_first: bool,
            gate_epoch: u64 = 1,
            layout: Layout = .{},
            marshal_started: bool = true,
            /// Node 0's state-sync material (owned).
            state_sync: ?Node.K.Plan.Material = null,
        };

        const Self = @This();

        fn start(self: *Self, ctx: Ctx, options: Options) !void {
            assert(options.nodes > 0 and options.nodes <= max_nodes);
            const io = ctx.io();
            var material = options.state_sync;
            errdefer if (material) |*owned| owned.deinit(gpa);
            self.ctx = ctx;
            self.started = 0;
            var rng = utils.rng.TestRng.init(7);
            self.fixture = try simplex.scheme.ed25519.fixture(
                Digest,
                gpa,
                &rng,
                namespace,
                options.nodes,
            );
            errdefer self.fixture.deinit(gpa);
            const participants = self.fixture.participants;
            const dealers = participants[0 .. options.layout.dealers orelse participants.len];
            self.boundary = try make_height_one_block(participants[0], dealers, participants);
            errdefer self.boundary.deinit(gpa);
            self.net = try Net.init(gpa, io, .{
                .max_size = 1024 * 1024,
                .max_peers_per_set = max_nodes,
                .disconnect_on_block = true,
                .tracked_peer_sets = 1,
            });
            errdefer self.net.deinit();
            self.network_task = try io.concurrent(Net.run, .{self.net});
            errdefer {
                for (self.nodes[0..self.started]) |*node| node.stop();
                self.net.close();
                self.network_task.await(io) catch {};
            }
            _ = self.net.oracle().manager().track(0, .init_primary(.init(participants)));
            for (participants) |from| for (participants) |to| {
                if (!from.eql(to)) try self.net.oracle().add_link(from, to, link);
            };
            for (participants, 0..) |_, index| {
                const seeded = options.seed_first or index > 0;
                // Node 0 owns the material from here, even when its start fails.
                const handed = if (index == 0) material else null;
                if (index == 0) material = null;
                try self.nodes[index].start(ctx.child("node"), self.net, &self.fixture, .init(
                    self.net.oracle().manager(),
                ), .{
                    .index = index,
                    .boundary = if (seeded) &self.boundary else null,
                    .gate_epoch = options.gate_epoch,
                    .dealers = dealers,
                    .deaf = options.layout.is_deaf(index),
                    .marshal_started = options.marshal_started,
                    .state_sync = handed,
                });
                self.started += 1;
            }
            assert(self.started == participants.len);
        }

        fn deinit(self: *Self) void {
            const io = self.ctx.io();
            for (self.nodes[0..self.started]) |*node| node.stop();
            self.net.close();
            self.network_task.await(io) catch {};
            self.net.deinit();
            self.boundary.deinit(gpa);
            self.fixture.deinit(gpa);
        }

        /// Stops node `index` and starts it again on the same partitions, with no boundary.
        fn restart(self: *Self, index: usize) !void {
            assert(index < self.started);
            self.nodes[index].stop();
            try self.nodes[index].start(self.ctx.child("restart"), self.net, &self.fixture, .init(
                self.net.oracle().manager(),
            ), .{
                .index = index,
                .boundary = null,
                .gate_epoch = 1,
                .dealers = self.fixture.participants,
                .deaf = false,
            });
        }

        /// Polls node `index`'s marshal every 10 ms of simulated time, up to `ms`, for the
        /// finalized block at `height` (commonware `wait_for_block`).
        fn wait_for_block(self: *Self, index: usize, height: u64, ms: u64) !Digested {
            assert(index < self.started);
            const io = self.ctx.io();
            const mailbox = &self.nodes[index].node.mailbox;
            var waited: u64 = 0;
            while (waited <= ms) : (waited += 10) {
                const found = try mailbox.get_block(.{ .height = .new(height) });
                if (found) |block| return block;
                try io.sleep(.fromMilliseconds(10), .awake);
            }
            return error.BlockDidNotArrive;
        }

        /// The first proposal any of `nodes` was asked for in `epoch`, polling every 10 ms for
        /// up to 500 ms (commonware `wait_for_proposal`).
        fn wait_for_proposal(self: *Self, nodes: []const Node, epoch: u64) !mocks.TestContext {
            assert(nodes.len <= self.started);
            const io = self.ctx.io();
            for (0..50) |_| {
                for (nodes) |*node| {
                    if (node.recorder.proposal_in(.new(epoch))) |proposal| return proposal;
                }
                try io.sleep(.fromMilliseconds(10), .awake);
            }
            return error.MissingProposal;
        }
    };
}

/// Every cluster test but the genesis one runs only with `-Dslow-tests` (nightly), to keep
/// per-push CI short.
fn slow_only() !void {
    if (!build_options.slow_tests) return error.SkipZigTest;
}

fn run_body(comptime body: fn (Ctx) anyerror!void, timeout_s: u64) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .timeout_ns = timeout_s * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

// commonware `cluster_serves_genesis_through_marshal`.
fn genesis_body(ctx: Ctx) anyerror!void {
    var c: Cluster = undefined;
    try c.start(ctx, .{ .nodes = 1, .seed_first = false });
    defer c.deinit();
    var block = (try c.nodes[0].node.mailbox.get_block(.{ .height = .zero() })).?;
    defer block.deinit();
    try testing.expectEqual(@as(u64, 0), block.inner().height().get());
}

test "orchestrator cluster: marshal serves genesis" {
    try run_body(genesis_body, 10);
}

// commonware `initial_epoch_starts_without_mailbox_transition`.
fn initial_epoch_body(ctx: Ctx) anyerror!void {
    var c: Cluster = undefined;
    try c.start(ctx, .{ .nodes = 4, .seed_first = false });
    defer c.deinit();
    const proposal = try c.wait_for_proposal(&c.nodes, 0);
    try testing.expectEqual(@as(u64, 0), proposal.round.epoch.get());
}

test "orchestrator cluster: the initial epoch starts without a mailbox transition" {
    try slow_only();
    try run_body(initial_epoch_body, 30);
}

// commonware `finalized_boundary_enters_next_epoch`.
fn boundary_enters_body(ctx: Ctx) anyerror!void {
    var c: Cluster = undefined;
    try c.start(ctx, .{ .nodes = 4, .seed_first = true });
    defer c.deinit();
    var stored = try c.wait_for_block(0, 1, 500);
    defer stored.deinit();
    const proposal = try c.wait_for_proposal(&c.nodes, 1);
    try testing.expect(stored.digest().eql(c.boundary.digest()));
    try testing.expectEqual(@as(u64, 1), proposal.round.epoch.get());
    try testing.expect(proposal.parent[1].eql(c.boundary.digest()));
}

test "orchestrator cluster: a finalized boundary enters the next epoch" {
    try slow_only();
    try run_body(boundary_enters_body, 30);
}

/// Reports `block` to node `index`'s orchestrator and returns its acknowledgement's waiter.
fn deliver(node: anytype, block: *const Block) !Exact.Waiter {
    const handle = try Exact.handle(gpa, node.ctx.io());
    const copy = try block.clone(gpa);
    const update: consensus.marshal.Update(Block, Exact) = .{ .block = .{
        .block = try Digested.precomputed(gpa, copy, copy.digest()),
        .ack = handle.acknowledgement,
    } };
    try testing.expectEqual(consensus.Feedback.ok, node.mailbox.report(update));
    return handle.waiter;
}

// commonware `future_epoch_vote_hints_marshal_to_fetch_boundary_finalization`: node 0 lacks
// the boundary, and the others' epoch-one votes make it fetch the boundary's finalization.
fn hint_body(ctx: Ctx) anyerror!void {
    var c: Cluster = undefined;
    try c.start(ctx, .{ .nodes = 4, .seed_first = false });
    defer c.deinit();
    var caught_up = try c.wait_for_block(0, 1, 500);
    defer caught_up.deinit();
    try testing.expect(caught_up.digest().eql(c.boundary.digest()));
}

test "orchestrator cluster: a later-epoch vote hints marshal to fetch the boundary" {
    try slow_only();
    try run_body(hint_body, 30);
}

// commonware `boundary_fetch_reaches_secondary_peer`: the other dealers never serve fetches,
// so the boundary's finalization comes from node 3, a player that is not a dealer.
fn secondary_body(ctx: Ctx) anyerror!void {
    var c: Cluster = undefined;
    try c.start(ctx, .{
        .nodes = 4,
        .seed_first = false,
        .layout = .{ .dealers = 3, .deaf = &.{ 1, 2 } },
    });
    defer c.deinit();
    var caught_up = try c.wait_for_block(0, 1, 10_000);
    defer caught_up.deinit();
    try testing.expect(caught_up.digest().eql(c.boundary.digest()));
}

test "orchestrator cluster: a boundary fetch reaches a secondary peer" {
    try slow_only();
    try run_body(secondary_body, 60);
}

// commonware `recovered_node_starts_from_processed_epoch`.
fn recovered_body(ctx: Ctx) anyerror!void {
    var c: Cluster = undefined;
    try c.start(ctx, .{ .nodes = 4, .seed_first = true });
    defer c.deinit();
    var stored = try c.wait_for_block(0, 1, 500);
    defer stored.deinit();
    try testing.expect(stored.digest().eql(c.boundary.digest()));
    try c.restart(0);
    const proposal = try c.wait_for_proposal(c.nodes[0..1], 1);
    try testing.expectEqual(@as(u64, 1), proposal.round.epoch.get());
}

test "orchestrator cluster: a recovered node starts from the processed epoch" {
    try slow_only();
    try run_body(recovered_body, 30);
}

// commonware `address_failure_stops_before_consensus_engine_starts`.
fn address_failure_body(ctx: Ctx) anyerror!void {
    var c: ClusterOf(Failing) = undefined;
    try c.start(ctx, .{ .nodes = 1, .seed_first = false });
    defer c.deinit();
    try c.nodes[0].join();
    try testing.expectEqual(@as(u32, 0), c.nodes[0].recorder.count);
}

test "orchestrator cluster: a peer-set failure stops before the engine starts" {
    try slow_only();
    try run_body(address_failure_body, 5);
}

// commonware `missing_boundary_block_stops_cleanly`: marshal cannot supply the final block
// reported to the orchestrator, so it stops without error.
fn missing_boundary_body(ctx: Ctx) anyerror!void {
    var c: Cluster = undefined;
    try c.start(ctx, .{ .nodes = 1, .seed_first = false });
    defer c.deinit();
    _ = try c.wait_for_proposal(c.nodes[0..1], 0);
    var waiter = try deliver(&c.nodes[0], &c.boundary);
    defer waiter.deinit();
    try c.nodes[0].join();
    try testing.expectError(error.AcknowledgementCanceled, waiter.poll().?);
}

test "orchestrator cluster: a missing boundary block stops cleanly" {
    try slow_only();
    try run_body(missing_boundary_body, 10);
}

// commonware `skipped_final_block_panics` (an error here): marshal reports epoch one's first
// block without epoch zero's final block.
fn skipped_body(ctx: Ctx) anyerror!void {
    var c: Cluster = undefined;
    try c.start(ctx, .{ .nodes = 1, .seed_first = false });
    defer c.deinit();
    _ = try c.wait_for_proposal(c.nodes[0..1], 0);
    const skipped = mocks.child(&c.boundary);
    var waiter = try deliver(&c.nodes[0], &skipped);
    defer waiter.deinit();
    try testing.expectError(error.SkippedFinalBlock, c.nodes[0].join());
}

test "orchestrator cluster: a skipped final block is a contract error" {
    try slow_only();
    try run_body(skipped_body, 10);
}

// commonware `shutdown_interrupts_boundary_gate_wait`: the gate never reaches epoch one, and
// a stop interrupts the wait for it.
fn shutdown_body(ctx: Ctx) anyerror!void {
    var c: Cluster = undefined;
    try c.start(ctx, .{ .nodes = 1, .seed_first = true, .gate_epoch = 0 });
    defer c.deinit();
    const proposal = try c.wait_for_proposal(c.nodes[0..1], 0);
    try testing.expectEqual(@as(u64, 0), proposal.round.epoch.get());
    try ctx.io().sleep(.fromMilliseconds(10), .awake);
    try ctx.child("shutdown").stop(7, .fromSeconds(1));
    try c.nodes[0].join();
}

test "orchestrator cluster: shutdown interrupts the boundary gate wait" {
    try slow_only();
    try run_body(shutdown_body, 10);
}

fn stop_context(ctx: Ctx) anyerror!void {
    return ctx.child("stopper").stop(0, null);
}

// commonware `marshal_shutdown_during_startup_resolution_stops_cleanly`: marshal never starts,
// so the orchestrator's startup read of the processed height parks. A stop is signaled, then
// the marshal actor is dropped, which cancels that read; the orchestrator must stop cleanly
// within a second instead of waiting on marshal forever.
fn marshal_shutdown_body(ctx: Ctx) anyerror!void {
    const io = ctx.io();
    var c: Cluster = undefined;
    try c.start(ctx, .{ .nodes = 1, .seed_first = false, .marshal_started = false });
    defer c.deinit();
    try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expect(c.nodes[0].recorder.count == 0);
    var stopper = try io.concurrent(stop_context, .{ctx});
    defer _ = stopper.cancel(io) catch {};
    try io.sleep(.fromMilliseconds(10), .awake);
    c.nodes[0].drop_unstarted_marshal();
    const before = Io.Clock.awake.now(io);
    try c.nodes[0].join();
    const elapsed = before.durationTo(Io.Clock.awake.now(io));
    try testing.expect(elapsed.toNanoseconds() < std.time.ns_per_s);
    try stopper.await(io);
}

test "orchestrator cluster: marshal shutdown during startup resolution stops cleanly" {
    // Per push: one node whose marshal never starts, so no consensus runs and it ends within
    // about 20 ms of simulated time (about 50 ms of wall time in Debug).
    try run_body(marshal_shutdown_body, 10);
}

/// The cluster's four-node fixture, rebuilt from the same seed so a test can sign
/// certificates before the cluster starts.
fn cluster_fixture() !Fixture {
    var rng = utils.rng.TestRng.init(7);
    return simplex.scheme.ed25519.fixture(Digest, gpa, &rng, namespace, 4);
}

// commonware `state_sync_rejects_mismatched_floor_epoch` (an error here): node 0's state-sync
// artifact is for epoch one, but its floor finalizes a block of epoch zero.
fn mismatched_floor_body(ctx: Ctx) anyerror!void {
    var fixture = try cluster_fixture();
    defer fixture.deinit(gpa);
    const participants = fixture.participants;
    var info = try make_epoch_info(1, participants, participants);
    errdefer info.deinit(gpa);
    var genesis = try make_genesis_block(participants[0], participants, participants);
    defer genesis.deinit(gpa);
    const floor = try make_finalization(&fixture, .zero(), genesis.digest());
    var c: Cluster = undefined;
    const started = c.start(ctx, .{
        .nodes = 4,
        .seed_first = false,
        .state_sync = .{ .info = info, .floor = floor },
    });
    try testing.expectError(error.EpochMismatch, started);
}

test "orchestrator cluster: state sync rejects a floor in another epoch" {
    try slow_only();
    try run_body(mismatched_floor_body, 10);
}

const InBand = mocks.DirectoryManager(KeyOnly);
const Addresses = network.Addresses(Key);
const AddressedInfo = @import("../types.zig").EpochInfo(mocks.TestBlsVariant, Key, Addresses);
const synced_epoch = 3;

/// Every participant at 127.0.0.1, from port 7000 by index.
fn localhost_directory(participants: []const Key) !Addresses {
    assert(participants.len <= max_nodes);
    var pairs: [max_nodes]Addresses.Inner.Pair = undefined;
    for (participants, pairs[0..participants.len], 0..) |peer, *pair, index| {
        const port: u16 = @intCast(7000 + index);
        pair.* = .{ peer, .{ .symmetric = .{ .ip = .{ .v4 = .localhost }, .port = port } } };
    }
    return Addresses.init(gpa, pairs[0..participants.len]);
}

/// The synced epoch's successful info, carrying `directory` (borrowed) in-band.
fn addressed_info(participants: []const Key, directory: *const Addresses) !AddressedInfo {
    var rng = utils.rng.TestRng.init(7);
    const dealers = try Set.from_dedup(gpa, participants);
    const V = mocks.TestBlsVariant;
    var dealt = try fd.deal(V, Key, utils.N3f1, gpa, &rng, .non_zero_counter, dealers);
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    errdefer dealt.output.deinit(gpa);
    var players = try Set.from_dedup(gpa, participants);
    errdefer players.deinit(gpa);
    var next_players = try players.clone(gpa);
    errdefer next_players.deinit(gpa);
    return .{
        .outcome = .success,
        .epoch = .new(synced_epoch),
        .output = dealt.output,
        .players = players,
        .next_players = next_players,
        .directory = try directory.clone(gpa),
    };
}

// commonware `state_sync_entry_activates_peers_from_in_band_directory`: a node entering at a
// state-synced epoch has no application state to resolve addresses from, so it activates the
// committee from the directory the synced artifact carries.
fn in_band_body(ctx: Ctx) anyerror!void {
    const io = ctx.io();
    var fixture = try cluster_fixture();
    defer fixture.deinit(gpa);
    const participants = fixture.participants;
    var net = try Net.init(gpa, io, .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = max_nodes,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    });
    defer net.deinit();
    var network_task = try io.concurrent(Net.run, .{net});
    defer network_task.await(io) catch {};
    defer net.close();
    _ = net.oracle().manager().track(0, .init_primary(.init(participants)));

    var directory = try localhost_directory(participants);
    defer directory.deinit(gpa);
    var info = try addressed_info(participants, &directory);
    defer info.deinit(gpa);
    const Node = ClusterNode(InBand);
    var genesis = try Node.K.genesis(participants[0], participants, participants);
    defer genesis.deinit(gpa);
    const floor = try make_finalization(&fixture, .new(synced_epoch), genesis.digest());
    var node: Node = undefined;
    try node.start(ctx.child("node"), net, &fixture, .init(gpa, .init(net.oracle().manager())), .{
        .index = 0,
        .boundary = null,
        .gate_epoch = synced_epoch,
        .dealers = participants,
        .deaf = false,
        .state_sync = .{ .info = try info.clone(gpa), .floor = floor },
    });
    defer node.manager.deinit();
    defer node.stop();

    const tracked = &node.manager.tracked;
    var polls: u32 = 0;
    while (tracked.items.len == 0) : (polls += 1) {
        if (polls == 1000) return error.NeverTracked;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    try testing.expectEqual(@as(usize, 1), tracked.items.len);
    const entry = &tracked.items[0];
    try testing.expectEqual(@as(u64, synced_epoch), entry.epoch.get());
    var roles = try info.participants(gpa);
    defer roles.deinit(gpa);
    var expected = try roles.tracked_peers(gpa);
    defer expected.deinit(gpa);
    try testing.expectEqualSlices(Key, expected.primary.items, entry.primary);
    try testing.expectEqualSlices(Key, expected.secondary.items, entry.secondary);
    try testing.expect(entry.directory.eql(directory));
}

test "orchestrator cluster: a state-synced entry activates peers from the in-band directory" {
    try slow_only();
    try run_body(in_band_body, 10);
}
