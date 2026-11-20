//! A deterministic simulation of the stateful probe over marshal's standard harness and
//! `p2p.simulated`: four validators finalize a chain in marshal and serve it through
//! `MarshalSource`, and a joining node outside the committee discovers its floor.
//!
//! Faults come from the run's seed: the joiner's links have latency, jitter, and drops; one
//! validator is partitioned from the joiner for a while; another crashes (its marshal and
//! probe stop) and restarts from its storage. The joiner must select the chain's tip from
//! honest replies within a bounded number of request rounds, and a seed replays the run
//! exactly. Debug runs a short chain on one seed; `-Dslow-tests` (and optimized builds) run a
//! longer chain on several seeds.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const build_options = @import("build_options");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const probe = @import("mod.zig");

const harness = consensus.marshal.mocks.harness;
const H = harness.StandardHarness;
const Cluster = consensus.marshal.mocks.scenarios.Cluster(H);
const Validator = Cluster.Validator;
const Net = harness.Network;
const K = harness.K;
const Ctx = runtime.deterministic.Context;
const Height = consensus.Height;
const Round = consensus.Round;
const TestRng = utils.rng.TestRng;
const num_validators = harness.num_validators;

const slow = !(builtin.mode == .debug and !build_options.slow_tests);
/// Blocks finalized before the joiner arrives.
const chain_length: u64 = if (slow) 40 else 4;
/// Seeds run (each twice, to check replay).
const seeds: u64 = if (slow) 8 else 1;
const probe_channel: u64 = 7;
const retry_timeout_ns: u64 = 500 * std.time.ns_per_ms;
/// Request rounds the joiner may take: at most 4 s of partition and 5 s of downtime cover
/// 18 rounds, and with 80% delivery each later round completes with probability above 40%.
const max_rounds: u32 = 64;
const joiner_link: p2p.simulated.Link = .{
    .latency = .from_millis(50),
    .jitter = .from_millis(25),
    .success_rate = 0.8,
};

/// Counts the request rounds a probe sends (each solicitation is one send).
const CountingSender = struct {
    pub const PublicKey = K;

    inner: Net.Sender,
    sends: *u32,

    pub fn send(
        self: *CountingSender,
        recipients: p2p.Recipients(K),
        parts: []const []const u8,
        priority: bool,
    ) ![]K {
        self.sends.* += 1;
        return self.inner.send(recipients, parts, priority);
    }

    pub fn deinit(self: *CountingSender) void {
        self.inner.deinit();
        self.* = undefined;
    }
};

const Source = probe.MarshalSource(Validator.Actor.Mailbox);
const Probe = probe.Probe(struct {
    pub const Scheme = harness.S;
    pub const Digest = harness.D;
    pub const Provider = harness.Provider;
    pub const Source = Source_;
    pub const Blocker = Net.Control;
    pub const NetSender = CountingSender;
    pub const NetReceiver = Net.Receiver;
});
const Source_ = Source;

/// One running probe.
const Node = struct {
    created: Probe.Created,
    task: Io.Future(anyerror!void),
    rng: TestRng,
    sends: u32 = 0,

    fn run(target: *Probe, rng: *TestRng) anyerror!void {
        return target.run(rng, parallel.sequential);
    }

    /// Starts a probe for `me` on `network`. Must not move afterwards.
    fn start(node: *Node, ctx: Ctx, network: *Net, me: K, provider: harness.Provider) !void {
        const control = network.oracle().control(me);
        const channel = try control.register(probe_channel, harness.test_quota);
        node.sends = 0;
        const sender: CountingSender = .{ .inner = channel.sender, .sends = &node.sends };
        node.created = try Probe.init(ctx.gpa(), ctx.io(), .{
            .provider = provider,
            .blocker = network.oracle().control(me),
            .mailbox_size = 16,
            .minimum_epoch = .zero(),
            .retry_timeout_ns = retry_timeout_ns,
        }, sender, channel.receiver);
        node.rng = .init(me.as_slice()[0]);
        node.task = try ctx.io().concurrent(run, .{ node.created.probe, &node.rng });
    }

    fn stop(node: *Node, io: Io) void {
        node.task.cancel(io) catch {};
        node.created.probe.deinit();
        node.created.mailbox.deinit();
        node.* = undefined;
    }
};

const Faults = struct {
    partitioned: usize,
    crashed: usize,
    heal_ms: u64,
    restart_ms: u64,
};

/// A uniform draw from the runtime's randomness (recorded by its auditor).
fn random_u64(ctx: Ctx) u64 {
    var bytes: [8]u8 = undefined;
    ctx.io().random(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}

fn draw_faults(ctx: Ctx) Faults {
    const partitioned: usize = @intCast(random_u64(ctx) % num_validators);
    const offset: usize = @intCast(1 + random_u64(ctx) % (num_validators - 1));
    const faults: Faults = .{
        .partitioned = partitioned,
        .crashed = (partitioned + offset) % num_validators,
        .heal_ms = 1_000 + random_u64(ctx) % 3_001,
        .restart_ms = 500 + random_u64(ctx) % 4_501,
    };
    assert(faults.partitioned != faults.crashed);
    return faults;
}

/// Finalizes heights 1 through `chain_length` at every validator and waits until each
/// reports the tip as its latest finalized height. Returns the tip's digest.
fn finalize_chain(ctx: Ctx, cluster: *Cluster) !harness.D {
    const gpa = ctx.gpa();
    const epocher = consensus.types.FixedEpocher.new(
        utils.NonZero(u64).init(harness.blocks_per_epoch).?,
    );
    var parent = harness.genesis_parent();
    var parent_commitment = H.genesis_parent_commitment(num_validators);
    for (1..chain_length + 1) |value| {
        const height: Height = .new(value);
        var block = try H.make_test_block(gpa, parent, parent_commitment, height, value, 4);
        defer H.Variant.deinit_block(gpa, &block);
        const round: Round = .new(epocher.containing(height).?.epoch, .new(value));
        for (cluster.nodes) |node| try H.verify(node, round, &block);
        const proposal: harness.Proposal = .init(round, .new(value - 1), H.commitment(&block));
        const validators = &cluster.validators;
        var finalization = try H.make_finalization(gpa, validators, proposal, harness.quorum);
        defer finalization.deinit(gpa);
        for (cluster.nodes) |node| _ = node.mailbox.report(.{ .finalization = finalization });
        parent = H.digest(&block);
        parent_commitment = H.commitment(&block);
    }
    for (cluster.nodes) |node| {
        while (true) {
            const info = try node.mailbox.get_info(.latest);
            if (info) |latest| if (latest.height.get() == chain_length) break;
            try ctx.sleep(.fromMilliseconds(100));
        }
    }
    return parent;
}

const Sim = struct {
    cluster: Cluster,
    nodes: [num_validators]Node,
    running: [num_validators]bool,
    joiner_node: Node,
    joiner: K,

    fn start_server(sim: *Sim, ctx: Ctx, index: usize) !void {
        const network = sim.cluster.network.network;
        const me = sim.cluster.validators.participants[index];
        const provider: harness.Provider = .init(&sim.cluster.validators.verifier);
        try sim.nodes[index].start(ctx, network, me, provider);
        sim.running[index] = true;
        const source: Source = .{ .mailbox = sim.cluster.nodes[index].mailbox.clone() };
        try sim.nodes[index].created.mailbox.attach(source);
    }

    /// Stops validator `index`'s probe and crashes its marshal.
    fn crash(sim: *Sim, io: Io, index: usize) void {
        assert(sim.running[index]);
        sim.nodes[index].stop(io);
        sim.running[index] = false;
        sim.cluster.nodes[index].crash();
    }

    /// Restarts validator `index` from its storage, then its probe.
    fn restart(sim: *Sim, ctx: Ctx, index: usize) !void {
        const node_ctx = ctx.child("validator").with_attribute("index", index);
        const provider: H.Provider = .init(&sim.cluster.validators.schemes[index]);
        const me = sim.cluster.validators.participants[index];
        const network = sim.cluster.network.network;
        const app = sim.cluster.apps[index].clone();
        sim.cluster.nodes[index] = try Validator.setup(node_ctx, network, me, provider, 1, app);
        try sim.start_server(ctx, index);
    }

    /// Tracks the joiner in its own peer set (the harness caps a set at the committee's size)
    /// and links it to every validator.
    fn admit_joiner(sim: *Sim) !void {
        const oracle = sim.cluster.network.network.oracle();
        const participants = sim.cluster.validators.participants;
        const tracked: p2p.TrackedPeers(K) = .init_primary(.init((&sim.joiner)[0..1]));
        try testing.expectEqual(p2p.Feedback.ok, oracle.manager().track(1, tracked));
        for (participants) |peer| {
            try oracle.add_link(sim.joiner, peer, joiner_link);
            try oracle.add_link(peer, sim.joiner, joiner_link);
        }
    }

    fn set_partition(sim: *Sim, index: usize, partitioned: bool) !void {
        const oracle = sim.cluster.network.network.oracle();
        const peer = sim.cluster.validators.participants[index];
        if (partitioned) {
            try oracle.remove_link(sim.joiner, peer);
            try oracle.remove_link(peer, sim.joiner);
        } else {
            try oracle.add_link(sim.joiner, peer, joiner_link);
            try oracle.add_link(peer, sim.joiner, joiner_link);
        }
    }
};

fn body(ctx: Ctx) anyerror!void {
    const gpa = ctx.gpa();
    const io = ctx.io();
    const sim = try gpa.create(Sim);
    defer gpa.destroy(sim);
    try sim.cluster.start(ctx, harness.link);
    defer sim.cluster.stop(gpa);
    const tip = try finalize_chain(ctx, &sim.cluster);

    sim.running = @splat(false);
    defer for (&sim.nodes, sim.running) |*node, running| {
        if (running) node.stop(io);
    };
    for (0..num_validators) |index| try sim.start_server(ctx, index);
    sim.joiner = cryptography.ed25519.PrivateKey.from_seed(1_000).public_key();
    try sim.admit_joiner();
    const network = sim.cluster.network.network;
    const verifier: harness.Provider = .init(&sim.cluster.validators.verifier);
    try sim.joiner_node.start(ctx, network, sim.joiner, verifier);
    defer sim.joiner_node.stop(io);

    const faults = draw_faults(ctx);
    try sim.set_partition(faults.partitioned, true);
    sim.crash(io, faults.crashed);
    var crashed_down = true;
    // The cluster stops every validator it started, so a failed run restarts the crashed one.
    errdefer if (crashed_down) sim.restart(ctx, faults.crashed) catch {};
    var floor = try sim.joiner_node.created.mailbox.subscribe();
    defer floor.deinit();

    const first = @min(faults.heal_ms, faults.restart_ms);
    const second = @max(faults.heal_ms, faults.restart_ms);
    try ctx.sleep(.fromMilliseconds(@intCast(first)));
    try apply(sim, ctx, faults, first, &crashed_down);
    try ctx.sleep(.fromMilliseconds(@intCast(second - first)));
    try apply(sim, ctx, faults, second, &crashed_down);
    assert(!crashed_down);

    var received = try floor.recv();
    defer received.deinit();
    try testing.expectEqual(chain_length, received.finalization.view().get());
    try testing.expect(received.finalization.proposal.payload.eql(tip));
    var rng = TestRng.init(3);
    const scoped = verifier.scoped(received.finalization.epoch()).?;
    try testing.expect(try received.finalization.verify(gpa, &rng, scoped, parallel.sequential));
    try testing.expect(sim.joiner_node.sends > 0);
    try testing.expect(sim.joiner_node.sends <= max_rounds);
}

/// Applies the fault event scheduled at `at_ms` (the heal, the restart, or both).
fn apply(sim: *Sim, ctx: Ctx, faults: Faults, at_ms: u64, crashed_down: *bool) !void {
    if (at_ms == faults.heal_ms) try sim.set_partition(faults.partitioned, false);
    if (at_ms == faults.restart_ms and crashed_down.*) {
        try sim.restart(ctx, faults.crashed);
        crashed_down.* = false;
    }
}

/// Runs `body` on a runner from `config` and returns its audit state.
fn replay(config: runtime.deterministic.Config) ![8]u8 {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, config);
    defer runner.deinit();
    try try runner.start_context(body, .{});
    return runner.auditor.state();
}

test "stateful probe dst: a joiner discovers the tip despite drops, a partition, and a crash" {
    for (0..seeds) |seed| {
        const config: runtime.deterministic.Config = .{
            .seed = seed,
            .timeout_ns = 300 * std.time.ns_per_s,
        };
        // Each soak round replays its own seed and expects the same audit state.
        try runtime.deterministic.soak(testing.allocator, config, {}, struct {
            fn run_round(_: void, runner: *runtime.deterministic.Runner) !void {
                try try runner.start_context(body, .{});
                const first = runner.auditor.state();
                const again = try replay(runner.config);
                try testing.expectEqualSlices(u8, &first, &again);
            }
        }.run_round);
    }
}
