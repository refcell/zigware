//! Tests of commonware's `glue::dkg::orchestrator::actor`, on one validator whose finalized
//! blocks the test reports through the orchestrator's mailbox in place of marshal. Commonware's
//! `should_panic` cases check the actor's `ContractError`s here.

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
const mocks = @import("../tests/mocks.zig");
const Fence = @import("../fence.zig").Fence;
const state_sync = @import("../state_sync.zig");
const actor_mod = @import("actor.zig");

const simplex = consensus.simplex;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const Digest = mocks.TestDigest;
const Key = mocks.TestPublicKey;
const Height = consensus.Height;
const Exact = utils.acknowledgement.Exact;
const Set = utils.ordered.Set(Key);
const Net = p2p.simulated.Network(Key);
const Scheme = simplex.scheme.ed25519.Scheme(Digest);
const Application = simplex.mocks.application.Application(Sha256, Key);
const Relay = simplex.mocks.relay.Relay(Digest, Key);
const MockReporter = simplex.mocks.reporter.Reporter(Scheme, Digest);
const Digested = broadcast.Digested(mocks.TestBlock);
const namespace = "_COMMONWARE_GLUE_DKG_ORCHESTRATOR_TEST";
const blocks_per_epoch = 3;

/// Schemes for epochs up to `max_epoch`.
const EpochProvider = struct {
    scheme_value: *const Scheme,
    max_epoch: u64,

    pub fn scheme(self: *const EpochProvider, epoch: consensus.Epoch) ?*const Scheme {
        return if (epoch.get() <= self.max_epoch) self.scheme_value else null;
    }
};

/// Serves the blocks the test stores, and records finalization hints.
const MockMarshal = struct {
    blocks: std.ArrayList(Digested) = .empty,
    hints: std.ArrayList(Height) = .empty,

    fn deinit(self: *MockMarshal) void {
        for (self.blocks.items) |*block| block.deinit();
        self.blocks.deinit(gpa);
        self.hints.deinit(gpa);
    }

    pub fn get_processed(self: *MockMarshal) !?consensus.marshal.core.floor.Processed {
        _ = self;
        return null;
    }

    pub fn get_block(self: *MockMarshal, identifier: anytype) !?Digested {
        for (self.blocks.items) |block| {
            if (block.inner().height().get() == identifier.height.get()) return block.clone();
        }
        return null;
    }

    pub fn hint_finalized(self: *MockMarshal, height: Height, targets: []const Key) !void {
        assert(targets.len > 0);
        try self.hints.append(gpa, height);
    }
};

const Types = struct {
    pub const Context = runtime.deterministic.Context;
    pub const Block = mocks.TestBlock;
    pub const Ack = Exact;
    pub const Scheme = simplex.scheme.ed25519.Scheme(Digest);
    pub const Provider = *const EpochProvider;
    pub const Manager = *mocks.InertManager;
    pub const Marshal = *MockMarshal;
    pub const Blocker = Net.Control;
    pub const ElectorConfig = simplex.elector.RoundRobin(Sha256);
    pub const Elector = simplex.elector.RoundRobinElector;
    pub const Automaton = *Application;
    pub const Relay = *Application;
    pub const Reporter = *MockReporter;
    pub const Strategy = parallel.Sequential;
    pub const Sender = Net.Sender;
    pub const Receiver = Net.Receiver;

    pub fn build_elector(config: ElectorConfig, allocator: std.mem.Allocator, n: u32) !Elector {
        return config.build(allocator, n);
    }
};
const TestActor = actor_mod.Actor(Types);
const Plan = state_sync.Plan(Scheme, Digest, mocks.TestBlsVariant, utils.sequence.Unit);

/// Epoch `epoch`'s info over `key` alone, with a trusted output dealt from seed zero.
fn singleton_info(key: Key, epoch: u64) !TestActor.Info {
    var rng = utils.rng.TestRng.init(0);
    const participants = try Set.from_dedup(gpa, &.{key});
    const V = mocks.TestBlsVariant;
    var dealt = try fd.deal(V, Key, utils.N3f1, gpa, &rng, .non_zero_counter, participants);
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    return .{
        .outcome = .success,
        .epoch = .new(epoch),
        .output = dealt.output,
        .players = try dealt.output.players.clone(gpa),
        .next_players = try dealt.output.players.clone(gpa),
        .directory = .{},
    };
}

/// `raw` carrying `epoch`'s info over `key`, digested.
fn with_info(raw: mocks.TestBlock, key: Key, epoch: u64) !Digested {
    var info = try singleton_info(key, epoch);
    defer info.deinit(gpa);
    const block = try raw.with_payload(gpa, 16, .{ .epoch_info = info });
    return Digested.precomputed(gpa, block, block.digest());
}

fn digested(raw: mocks.TestBlock) !Digested {
    return Digested.precomputed(gpa, raw, raw.digest());
}

/// Everything one validator's orchestrator borrows.
const Harness = struct {
    ctx: runtime.deterministic.Context,
    network: *Net,
    network_task: Io.Future((Io.Cancelable || std.mem.Allocator.Error)!void),
    fixture: cryptography.certificate.mocks.Fixture(Scheme),
    relay: Relay,
    application: Application,
    reporter: MockReporter,
    page_cache: runtime.buffer.paged.CacheRef,
    manager: mocks.InertManager = .{},
    marshal: MockMarshal = .{},
    provider: EpochProvider,
    fence: Fence,
    plan: Plan,

    fn init(self: *Harness, ctx: runtime.deterministic.Context, max_epoch: u64) !void {
        const io = ctx.io();
        self.ctx = ctx;
        var rng = utils.rng.TestRng.init(7);
        self.fixture = try simplex.scheme.ed25519.fixture(Digest, gpa, &rng, namespace, 1);
        self.network = try Net.init(gpa, io, .{
            .max_size = 1024 * 1024,
            .max_peers_per_set = 4,
            .disconnect_on_block = true,
            .tracked_peer_sets = 1,
        });
        self.network_task = try io.concurrent(Net.run, .{self.network});
        const validators = self.fixture.participants;
        _ = self.network.oracle().manager().track(0, .init_primary(.init(validators)));
        self.relay = .init(gpa, io);
        self.application = try .init(gpa, io, .{
            .relay = &self.relay,
            .me = self.key(),
            .propose_latency = .{ .mean = 10, .std_dev = 0 },
            .verify_latency = .{ .mean = 10, .std_dev = 0 },
            .certify_latency = .{ .mean = 10, .std_dev = 0 },
        });
        try self.application.register();
        self.reporter = .init(gpa, io, &self.fixture.verifier);
        self.page_cache = try .init(gpa, 16_384, 64);
        self.manager = .{};
        self.marshal = .{};
        self.provider = .{ .scheme_value = &self.fixture.schemes[0], .max_epoch = max_epoch };
        self.fence = Fence.init(io);
        self.plan = Plan.disabled(gpa, io);
    }

    fn deinit(self: *Harness) void {
        const io = self.ctx.io();
        self.plan.deinit();
        self.fence.close();
        self.marshal.deinit();
        self.page_cache.deinit();
        self.reporter.deinit();
        self.relay.deregister_all();
        self.application.deinit();
        self.relay.deinit();
        self.network.close();
        self.network_task.await(io) catch {};
        self.network.deinit();
        self.fixture.deinit(gpa);
    }

    fn key(self: *const Harness) Key {
        return self.fixture.participants[0];
    }

    fn config(self: *Harness) actor_mod.Config(Types) {
        return .{
            .blocker = self.network.oracle().control(self.key()),
            .manager = &self.manager,
            .provider = &self.provider,
            .marshal = &self.marshal,
            .automaton = &self.application,
            .relay = &self.application,
            .reporter = &self.reporter,
            .strategy = parallel.sequential,
            .simplex = .{
                .elector = .default(),
                .mailbox_size = 1024,
                .replay_buffer = 1024 * 1024,
                .write_buffer = 1024 * 1024,
                .page_cache = &self.page_cache,
                .leader_timeout = .from_secs(1),
                .certification_timeout = .from_secs(2),
                .timeout_retry = .from_secs(10),
                .fetch_timeout = .from_secs(1),
                .fetch_retry_delay = .from_millis(100),
                .view_retention = .new(10),
                .skip = .disabled,
                .track_historical_votes = false,
                .forward = .disabled,
            },
            .gate = self.fence.gate(),
            .state_sync = &self.plan,
            .blocks_per_epoch = blocks_per_epoch,
            .mailbox_size = 16,
            .partition_prefix = "orchestrator",
        };
    }

    /// The three consensus channels of this validator.
    fn channels(self: *Harness) ![3]TestActor.Channel {
        var result: [3]TestActor.Channel = undefined;
        for (&result, 0..) |*channel, index| {
            const control = self.network.oracle().control(self.key());
            const registered = try control.register(index, p2p.Quota.per_second(1024));
            channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
        }
        return result;
    }
};

fn run_actor(actor: *TestActor, channels: *const [3]TestActor.Channel) anyerror!void {
    return actor.run(channels[0], channels[1], channels[2]);
}

/// Reports `block` (a new handle) and returns its acknowledgement's waiter.
fn deliver(io: Io, mailbox: TestActor.Mailbox, block: *const Digested) !Exact.Waiter {
    const handle = try Exact.handle(gpa, io);
    const update: consensus.marshal.Update(mocks.TestBlock, Exact) = .{
        .block = .{ .block = block.clone(), .ack = handle.acknowledgement },
    };
    _ = try mailbox.report(update);
    return handle.waiter;
}

/// Waits up to `ms` of simulated time for `waiter`; true if it was acknowledged.
fn acknowledged_within(io: Io, waiter: *const Exact.Waiter, ms: u64) !bool {
    var waited: u64 = 0;
    while (waited < ms) : (waited += 10) {
        if (waiter.poll()) |result| {
            try result;
            return true;
        }
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return waiter.poll() != null;
}

// The final block of an epoch is acknowledged only once the gate opens the next epoch and
// its engine starts; a block below it is acknowledged at once, and a block past it is the
// contract violation commonware panics on.
fn epoch_transition_body(ctx: runtime.deterministic.Context) anyerror!void {
    const io = ctx.io();
    var h: Harness = undefined;
    try h.init(ctx, 1);
    defer h.deinit();
    const key = h.key();
    var raw = mocks.genesis_block(key);
    try h.marshal.blocks.append(gpa, try with_info(raw, key, 0));
    raw = mocks.child(&raw);
    var middle = try digested(raw);
    defer middle.deinit();
    raw = mocks.child(&raw);
    try h.marshal.blocks.append(gpa, try with_info(raw, key, 1));
    const final = h.marshal.blocks.items[1];
    var skipped = try digested(mocks.child(&mocks.child(&mocks.child(&mocks.child(&raw)))));
    defer skipped.deinit();

    h.fence.mark(.zero());
    var orchestrator, var mailbox = try TestActor.init(ctx, h.config());
    defer orchestrator.deinit();
    defer mailbox.deinit();
    const channels = try h.channels();
    var task = try io.concurrent(run_actor, .{ &orchestrator, &channels });
    defer _ = task.cancel(io) catch {};

    var first = try deliver(io, mailbox, &middle);
    defer first.deinit();
    try testing.expect(try acknowledged_within(io, &first, 500));
    try testing.expectEqual(@as(u32, 1), h.manager.tracked);

    var boundary = try deliver(io, mailbox, &final);
    defer boundary.deinit();
    try testing.expect(!try acknowledged_within(io, &boundary, 500));
    try testing.expectEqual(@as(u32, 1), h.manager.tracked);
    h.fence.mark(.new(1));
    try testing.expect(try acknowledged_within(io, &boundary, 500));
    try testing.expectEqual(@as(u32, 2), h.manager.tracked);

    var late = try deliver(io, mailbox, &skipped);
    defer late.deinit();
    try testing.expectError(error.SkippedFinalBlock, task.await(io));
    try testing.expect(late.poll() != null);
}

test "orchestrator actor: the final block is acknowledged after the next epoch starts" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .timeout_ns = 60 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(epoch_transition_body, .{});
}

/// Polls every 10 ms of simulated time, up to `ms`, until `hints` holds `len` entries.
fn wait_hints(io: Io, hints: *const std.ArrayList(Height), len: usize, ms: u64) !void {
    var waited: u64 = 0;
    while (hints.items.len < len and waited < ms) : (waited += 10) {
        try io.sleep(.fromMilliseconds(10), .awake);
    }
}

// A vote for a later epoch is a catch-up hint (commonware `handle_backup`): the actor asks
// marshal for its own epoch's final block from that peer. Entering an epoch the provider has
// no scheme for is the contract violation commonware panics on.
fn catch_up_body(ctx: runtime.deterministic.Context) anyerror!void {
    const io = ctx.io();
    var h: Harness = undefined;
    try h.init(ctx, 0);
    defer h.deinit();
    const key = h.key();
    const peer = mocks.TestSigner.from_seed(99).public_key();
    const peers = try Set.from_dedup(gpa, &.{ key, peer });
    defer @constCast(&peers).deinit(gpa);
    _ = h.network.oracle().manager().track(1, .init_primary(.init(peers.items)));
    const link: p2p.simulated.Link = .{
        .latency = .from_millis(1),
        .jitter = .from_millis(0),
        .success_rate = 1.0,
    };
    try h.network.oracle().add_link(peer, key, link);
    try h.network.oracle().add_link(key, peer, link);
    var raw = mocks.genesis_block(key);
    try h.marshal.blocks.append(gpa, try with_info(raw, key, 0));
    raw = mocks.child(&raw);
    var middle = try digested(raw);
    defer middle.deinit();
    raw = mocks.child(&raw);
    try h.marshal.blocks.append(gpa, try with_info(raw, key, 1));
    const final = h.marshal.blocks.items[1];

    h.fence.mark(.zero());
    var orchestrator, var mailbox = try TestActor.init(ctx, h.config());
    defer orchestrator.deinit();
    defer mailbox.deinit();
    const channels = try h.channels();
    var task = try io.concurrent(run_actor, .{ &orchestrator, &channels });
    defer _ = task.cancel(io) catch {};

    var votes = try h.network.oracle().control(peer).register(0, p2p.Quota.per_second(1024));
    defer votes.sender.deinit();
    defer votes.receiver.deinit();
    const future_epoch = [_]u8{5};
    const sent = try votes.sender.send(.{ .one = key }, &.{ &future_epoch, "vote" }, false);
    gpa.free(sent);
    try wait_hints(io, &h.marshal.hints, 1, 1000);
    try testing.expectEqual(@as(usize, 1), h.marshal.hints.items.len);
    try testing.expectEqual(@as(u64, blocks_per_epoch - 1), h.marshal.hints.items[0].get());

    var first = try deliver(io, mailbox, &middle);
    defer first.deinit();
    var boundary = try deliver(io, mailbox, &final);
    defer boundary.deinit();
    h.fence.mark(.new(1));
    try testing.expectError(error.MissingScheme, task.await(io));
    try testing.expect(boundary.poll() != null);
}

test "orchestrator actor: a later-epoch vote hints the boundary finalization" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .timeout_ns = 60 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(catch_up_body, .{});
}
