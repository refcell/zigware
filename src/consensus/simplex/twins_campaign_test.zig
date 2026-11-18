//! commonware's twins campaigns (`simplex/mod.rs` `twins_campaign`). Each case runs `f`
//! compromised participants as two twin engines, a primary and a secondary, sharing one key.
//! During the adversarial prefix (one scripted round per leader term), each twin half sends
//! to and hears from only its round's recipient set; afterwards the network is synchronous.
//! Honest validators must then finalize, never disagree, never vote for two payloads in a
//! view, and fault or block only twins.
//!
//! Every engine sends through p2p's split senders: honest validators use a pass-through
//! forwarder and keep the primary half, and a twin's resolver channel is inert (its sends are
//! dropped and its receivers route nothing), like commonware's `inert_channel`.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const elector_mod = @import("elector.zig");
const engine_mod = @import("engine.zig");
const engine_test = @import("engine_test.zig");
const application_mod = @import("mocks/application.zig");
const relay_mod = @import("mocks/relay.zig");
const reporter_mod = @import("mocks/reporter.zig");
const mock_scheme = @import("mocks/scheme.zig");
const twins = @import("mocks/twins.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const Key = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Context = runtime.deterministic.Context;
const Scheme = mock_scheme.Scheme(Sha256.Digest);
const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
const Application = application_mod.Application(Sha256, Key);
const Relay = relay_mod.Relay(Sha256.Digest, Key);
const Reporter = reporter_mod.Reporter(Scheme, Sha256.Digest);
const RoundRobin = elector_mod.RoundRobin(Sha256);
const TwinsElector = twins.Elector(elector_mod.RoundRobinElector);
const IoRng = @import("actors/context.zig").IoRng;
const View = consensus_types.View;
const Epoch = consensus_types.Epoch;
const Round = consensus_types.Round;
const TermLength = consensus_types.TermLength;
const Recipients = p2p.Recipients(Key);
const Link = p2p.simulated.Link;
const Duration = utils.Duration;

const Params = struct {
    pub const Context = runtime.deterministic.Context;
    pub const Scheme = mock_scheme.Scheme(Sha256.Digest);
    pub const Elector = TwinsElector;
    pub const Blocker = Net.Control;
    pub const Digest = Sha256.Digest;
    pub const Automaton = *Application;
    pub const Relay = *Application;
    pub const Reporter = *reporter_mod.Reporter(mock_scheme.Scheme(Sha256.Digest), Sha256.Digest);
    pub const Strategy = parallel.Sequential;
    pub const Sender = Net.SplitSender(Forwarder);
    pub const Receiver = Net.Receiver;
};
const Engine = engine_mod.Engine(Params);
const Channel = engine_mod.Channel(Params);

const epoch: Epoch = .new(333);
const test_quota = p2p.Quota.per_second(1024);
const page_size = 1024;
const page_cache_size = 10;

/// commonware `TwinsCampaign`.
const Campaign = struct {
    n: u32,
    rounds: u32,
    mode: twins.Mode,
    max_cases: u32,
    trailing_finalizations: u32,
    /// Term length and optimistic views of the round-robin elector.
    term_length: u32 = 1,
    optimistic_views: u64 = 0,
    /// Applications vote handoff candidates during the adversarial prefix and wait for
    /// parent certification afterward (commonware `configure_twins_handoff`).
    handoffs: bool = false,
};

/// Handoff candidates honest and twin applications returned across a campaign's cases.
const HandoffCounts = struct { honest: u64 = 0, twin: u64 = 0, early_votes: u64 = 0 };

/// commonware `TWINS_CAMPAIGN`. Debug builds without `-Dslow-tests` run 1 of its 20 cases.
const twins_campaign: Campaign = .{
    .n = 5,
    .rounds = 3,
    .mode = .sampled,
    .max_cases = if (builtin.mode == .debug and !build_options.slow_tests) 1 else 20,
    .trailing_finalizations = 10,
};

/// commonware `TWINS_LINK`, and the fast link `twins_campaign_all_links` also runs.
const twins_link: Link = .{
    .latency = .from_millis(500),
    .jitter = .from_millis(500),
    .success_rate = 1.0,
};
const fast_link: Link = .{
    .latency = .from_millis(10),
    .jitter = .from_millis(10),
    .success_rate = 1.0,
};

/// One case's routing: the participants and each scripted round's twin recipient sets.
const Plan = struct {
    scenario: twins.Scenario,
    term_length: TermLength,
    participants: []const Key,
    primary: [][]Key,
    secondary: [][]Key,

    fn init(scenario: twins.Scenario, term_length: TermLength, participants: []const Key) !Plan {
        const rounds = scenario.rounds;
        const primary = try gpa.alloc([]Key, rounds.len);
        errdefer gpa.free(primary);
        const secondary = try gpa.alloc([]Key, rounds.len);
        errdefer gpa.free(secondary);
        var built: usize = 0;
        errdefer for (primary[0..built], secondary[0..built]) |a, b| {
            gpa.free(a);
            gpa.free(b);
        };
        for (rounds, primary, secondary) |round, *a, *b| {
            a.* = try twins.partition(gpa, Key, round.primary_mask, participants);
            errdefer gpa.free(a.*);
            b.* = try twins.partition(gpa, Key, round.secondary_mask, participants);
            built += 1;
        }
        return .{
            .scenario = scenario,
            .term_length = term_length,
            .participants = participants,
            .primary = primary,
            .secondary = secondary,
        };
    }

    fn deinit(plan: *Plan) void {
        for (plan.primary, plan.secondary) |a, b| {
            gpa.free(a);
            gpa.free(b);
        }
        gpa.free(plan.primary);
        gpa.free(plan.secondary);
        plan.* = undefined;
    }

    /// The view of an encoded vote or certificate: every variant is a tag byte, then a
    /// message that starts with its round.
    fn view_of(payload: []const u8) View {
        var reader: codec.Reader = .init(payload);
        _ = reader.read_byte() catch @panic("twin traffic is well-formed");
        const round = Round.read(gpa, &reader, {}) catch @panic("twin traffic is well-formed");
        return round.view;
    }
};

/// Redirects a split sender's messages (commonware's twin forwarders).
const Forwarder = struct {
    kind: enum { pass, split, drop },
    plan: ?*const Plan = null,

    pub fn forward(
        forwarder: Forwarder,
        origin: p2p.simulated.SplitOrigin,
        recipients: Recipients,
        message: []const u8,
    ) ?Recipients {
        const plan = switch (forwarder.kind) {
            .pass => return recipients,
            .drop => return null,
            .split => forwarder.plan.?,
        };
        const view = Plan.view_of(message);
        const index = twins.term_index(view, plan.term_length);
        // After the prefix both halves reach everyone (the network skips the sender).
        if (index >= plan.primary.len) return .{ .some = plan.participants };
        const sets = if (origin == .primary) plan.primary else plan.secondary;
        return .{ .some = sets[index] };
    }
};

/// Routes a twin's incoming messages to its halves (commonware's twin routers).
const Router = struct {
    plan: ?*const Plan,

    pub fn route(router: Router, message: *const p2p.Message(Key)) p2p.simulated.SplitTarget {
        const plan = router.plan orelse return .none;
        const sender = twins.index_of(Key, message.peer, plan.participants);
        const view = Plan.view_of(message.payload);
        return plan.scenario.route(view, plan.term_length, sender, plan.participants.len);
    }
};

/// One engine (an honest validator or a twin half) and its mocks. Must not move.
const Node = struct {
    application: Application,
    reporter: Reporter,
    page_cache: runtime.buffer.paged.CacheRef,
    engine: Engine,
    partition: [32]u8,
    handle: ?runtime.context.Handle(Engine.RunResult),

    fn abort(node: *Node) void {
        const handle = node.handle orelse return;
        node.handle = null;
        const result = handle.abort() catch return; // Aborted before it returned.
        result catch |err| std.debug.panic("engine failed: {t}", .{err});
    }
};

/// One case's network and engines: `2f` twin halves first, then the honest validators.
const Case = struct {
    ctx: Context,
    fixture: Fixture,
    network: *Net,
    network_task: std.Io.Future((std.Io.Cancelable || Allocator.Error)!void),
    relay: Relay,
    elector: TwinsElector,
    plan: Plan,
    nodes: []Node,
    started: usize,
    twin_mask: u64,
    handoffs: bool,

    fn keys(case: *const Case) []const Key {
        return case.fixture.participants;
    }

    fn oracle(case: *const Case) Net.Oracle {
        return case.network.oracle();
    }

    fn honest_nodes(case: *Case) []Node {
        return case.nodes[2 * @popCount(case.twin_mask) ..];
    }
};

fn register(oracle: Net.Oracle, key: Key) ![3]Net.Registered {
    var channels: [3]Net.Registered = undefined;
    for (&channels, 0..) |*channel, index| {
        channel.* = try oracle.control(key).register(index, test_quota);
    }
    return channels;
}

/// commonware's twins engine configuration.
fn engine_config(case: *Case, node: *Node, index: usize) Engine.Config {
    return .{
        .scheme = case.fixture.schemes[index],
        .elector = case.elector,
        .blocker = case.oracle().control(case.keys()[index]),
        .automaton = &node.application,
        .relay = &node.application,
        .reporter = &node.reporter,
        .track_historical_votes = false,
        .strategy = parallel.sequential,
        .partition = std.mem.sliceTo(&node.partition, 0),
        .mailbox_size = 1024,
        .epoch = epoch,
        .floor = .{ .genesis = application_mod.genesis(Sha256, epoch) },
        .replay_buffer = 1024 * 1024,
        .write_buffer = 1024 * 1024,
        .page_cache = &node.page_cache,
        .leader_timeout = .from_secs(1),
        .certification_timeout = .from_millis(1500),
        .timeout_retry = .from_secs(10),
        .view_retention = .new(10),
        .skip = .{ .enabled = .{ .timeout = .from_secs(11) } },
        .fetch_timeout = .from_secs(1),
        .fetch_retry_delay = .from_millis(100),
        .forward = .disabled,
    };
}

/// Starts the next node's engine for participant `index` on `channels` (owned by the
/// engine from here on); `name` labels its journal partition.
fn start_node(case: *Case, index: usize, name: []const u8, channels: [3]Channel) !void {
    const io = case.ctx.io();
    const node = &case.nodes[case.started];
    const normal: application_mod.Latency = .{ .mean = 10, .std_dev = 5 };
    node.application = try .init(gpa, io, .{
        .relay = &case.relay,
        .me = case.keys()[index],
        .propose_latency = normal,
        .verify_latency = normal,
        .certify_latency = normal,
    });
    errdefer node.application.deinit();
    if (case.handoffs) {
        // Each scripted round drives one full leader term.
        const rounds: u64 = case.plan.scenario.rounds.len;
        node.application.handoff = .vote;
        node.application.handoff_until = .new(rounds * case.plan.term_length.get());
    }
    // commonware's tests build with the `mocks` feature, so a twin's payload that names
    // another round or parent fails verification instead of panicking.
    node.application.reject_mismatches = true;
    try node.application.register();
    node.reporter = .init(gpa, io, &case.fixture.verifier);
    errdefer node.reporter.deinit();
    node.page_cache = try .init(gpa, page_size, page_cache_size);
    errdefer node.page_cache.deinit();
    node.partition = @splat(0);
    _ = try std.fmt.bufPrint(&node.partition, "{s}_{d}", .{ name, index });
    // Per-node metrics, as commonware's `child(..).with_attribute("index", ..)`.
    var node_ctx = case.ctx;
    node_ctx.scope = case.ctx.scope.child(name).with_attribute("index", index);
    try node.engine.init(node_ctx, engine_config(case, node, index));
    node.handle = try node_ctx.child("engine").spawn(Engine.run, .{
        &node.engine, channels[0], channels[1], channels[2],
    });
    case.started += 1;
}

/// Splits participant `index`'s channels into two twin halves and starts both engines.
fn start_twin(case: *Case, index: usize) !void {
    const io = case.ctx.io();
    const registered = try register(case.oracle(), case.keys()[index]);
    const split: Forwarder = .{ .kind = .split, .plan = &case.plan };
    const routed: Router = .{ .plan = &case.plan };
    var halves: [2][3]Channel = undefined;
    for (registered, 0..) |channel, kind| {
        const inert = kind == 2;
        const forwarder: Forwarder = if (inert) .{ .kind = .drop } else split;
        const router: Router = if (inert) .{ .plan = null } else routed;
        const senders = channel.sender.split_with(forwarder);
        const receivers = try channel.receiver.split_with(gpa, io, router);
        halves[0][kind] = .{ .sender = senders.primary, .receiver = receivers.primary };
        halves[1][kind] = .{ .sender = senders.secondary, .receiver = receivers.secondary };
    }
    try start_node(case, index, "twin_primary", halves[0]);
    try start_node(case, index, "twin_secondary", halves[1]);
}

/// Starts honest participant `index` on pass-through senders.
fn start_honest(case: *Case, index: usize) !void {
    const registered = try register(case.oracle(), case.keys()[index]);
    var channels: [3]Channel = undefined;
    for (registered, &channels) |channel, *owned| {
        var senders = channel.sender.split_with(Forwarder{ .kind = .pass });
        senders.secondary.deinit();
        owned.* = .{ .sender = senders.primary, .receiver = channel.receiver };
    }
    try start_node(case, index, "honest", channels);
}

/// Builds the network, elector, and routing plan of `generated` (nothing started yet).
fn init_case(
    case: *Case,
    ctx: Context,
    campaign: Campaign,
    generated: *const twins.Case,
    link: Link,
) !void {
    const io = ctx.io();
    var rng: IoRng = .{ .io = io };
    case.* = undefined;
    case.ctx = ctx;
    case.started = 0;
    case.handoffs = campaign.handoffs;
    case.fixture = try mock_scheme.fixture(Sha256.Digest, gpa, &rng, "consensus", campaign.n);
    errdefer case.fixture.deinit(gpa);
    case.twin_mask = 0;
    for (generated.compromised) |index| case.twin_mask |= @as(u64, 1) << @intCast(index);
    var round_robin = RoundRobin.default();
    if (campaign.term_length > 1) {
        const length = utils.NonZero(u32).init(campaign.term_length).?;
        const lookahead: consensus_types.ViewDelta = .new(campaign.optimistic_views);
        round_robin = round_robin.with_term(.new(length), .from_secs(12), lookahead);
    }
    const fallback = try round_robin.build(gpa, campaign.n);
    case.elector = try TwinsElector.init(gpa, fallback, generated.scenario, campaign.n);
    errdefer case.elector.deinit(gpa);
    case.plan = try .init(generated.scenario, case.elector.terms().length, case.keys());
    errdefer case.plan.deinit();
    case.network = try Net.init(gpa, io, .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = campaign.n + 1,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    });
    case.network_task = try io.concurrent(Net.run, .{case.network});
    case.relay = .init(gpa, io);
    const peers = case.keys();
    _ = case.oracle().manager().track(0, .init_primary(.init(peers)));
    for (peers, 0..) |from, a| for (peers, 0..) |to, b| {
        if (a != b) try case.oracle().add_link(from, to, link);
    };
    const twin_count = generated.compromised.len;
    case.nodes = try gpa.alloc(Node, campaign.n + twin_count);
}

/// Aborts every engine, then frees the mocks, the network, and the fixture.
fn deinit_case(case: *Case) void {
    const io = case.ctx.io();
    // Abort every engine before freeing any mock: live voters relay to all applications.
    for (case.nodes[0..case.started]) |*node| node.abort();
    case.relay.deregister_all();
    for (case.nodes[0..case.started]) |*node| {
        node.engine.deinit();
        node.page_cache.deinit();
        node.reporter.deinit();
        node.application.deinit();
    }
    gpa.free(case.nodes);
    case.relay.deinit();
    case.network.close();
    case.network_task.await(io) catch {};
    case.network.deinit();
    case.plan.deinit();
    case.elector.deinit(gpa);
    case.fixture.deinit(gpa);
    case.* = undefined;
}

/// Honest validators agree on every finalized payload and never vote for two payloads in a
/// view; only twins commit faults or get blocked (commonware's twins safety checks).
fn check_case(case: *Case) !void {
    const honest = case.honest_nodes();
    var highest: u64 = 0;
    for (honest) |*node| {
        node.reporter.assert_no_invalid();
        highest = @max(highest, node.reporter.latest_finalized().get());
        try testing.expectEqual(0, node.reporter.equivocating_signers() & ~case.twin_mask);
    }
    for (1..highest + 1) |view| {
        var expected: ?Sha256.Digest = null;
        for (honest) |*node| {
            const payload = node.reporter.finalized(.new(view)) orelse continue;
            if (expected) |digest| try testing.expect(digest.order(payload) == .eq);
            expected = payload;
        }
    }
    const blocked = try case.oracle().blocked(gpa);
    defer gpa.free(blocked);
    for (blocked) |pair| {
        const index = twins.index_of(Key, pair.recipient, case.keys());
        try testing.expect(case.twin_mask & (@as(u64, 1) << @intCast(index)) != 0);
    }
}

/// Faults reported to honest validators name only twins (read once the engines stopped).
fn check_faults(honest: []Node, twin_mask: u64) !void {
    for (honest) |*node| {
        for (node.reporter.fault_list()) |fault| {
            const bit = @as(u64, 1) << @intCast(fault.signer.get());
            try testing.expect(twin_mask & bit != 0);
        }
    }
}

/// Runs one case: twins first, then honest validators, until every honest validator
/// finalized `trailing_finalizations` views past the adversarial prefix.
fn run_case(
    ctx: Context,
    campaign: Campaign,
    generated: *const twins.Case,
    link: Link,
    counts: *HandoffCounts,
) !void {
    var case: Case = undefined;
    try init_case(&case, ctx, campaign, generated, link);
    defer deinit_case(&case);
    for (generated.compromised) |index| try start_twin(&case, index);
    for (0..campaign.n) |index| {
        if (case.twin_mask & (@as(u64, 1) << @intCast(index)) != 0) continue;
        try start_honest(&case, index);
    }
    assert(case.started == case.nodes.len);
    // Each scripted round drives one full leader term.
    const term_length = case.plan.term_length.get();
    const prefix_end: View = .new(@as(u64, generated.scenario.rounds.len) * term_length);
    for (case.honest_nodes()) |*node| {
        try node.reporter.wait_for_finalizations_above(prefix_end, campaign.trailing_finalizations);
    }
    try check_case(&case);
    if (case.handoffs) {
        const encoded = try ctx.scope.encode(gpa);
        defer gpa.free(encoded);
        counts.early_votes += engine_test.count_nonzero_metric_lines(encoded, &.{
            "_handoff_events_total{",
            "event=\"VotedBeforeCertification\"",
        });
    }
    const twin_halves = 2 * generated.compromised.len;
    for (case.nodes, 0..) |*node, index| {
        const returned = node.application.handoffs_returned.load(.monotonic);
        if (index < twin_halves) counts.twin += returned else counts.honest += returned;
    }
    const honest = case.honest_nodes();
    const twin_mask = case.twin_mask;
    // Faults are read once nothing reports any more.
    for (case.nodes) |*node| node.abort();
    try check_faults(honest, twin_mask);
}

/// commonware `twins_campaign`: generates the campaign's cases from `test_rng` and runs each
/// on a fresh deterministic runner seeded from it.
fn run_campaign(campaign: Campaign, link: Link) !void {
    var rng = utils.rng.test_rng();
    const faults = utils.N3f1.max_faults(campaign.n);
    const cases = try twins.cases(gpa, &rng, .{
        .participants = campaign.n,
        .faults = faults,
        .rounds = campaign.rounds,
        .mode = campaign.mode,
        .max_cases = campaign.max_cases,
    });
    defer twins.free_cases(gpa, cases);
    try testing.expect(cases.len > 0);
    var counts: HandoffCounts = .{};
    for (cases) |*generated| {
        try testing.expectEqual(faults, generated.compromised.len);
        var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = rng.next_u64() });
        defer runner.deinit();
        try (try runner.start_context(run_case, .{ campaign, generated, link, &counts }));
    }
    if (campaign.handoffs) {
        try testing.expect(counts.honest > 0 and counts.twin > 0);
        // Some leader voted its handoff candidate before the parent certified.
        try testing.expect(counts.early_votes > 0);
    }
}

/// commonware `twins_campaign_all_links`: the fast link, then `twins_link`.
fn run_all_links(campaign: Campaign) !void {
    try run_campaign(campaign, fast_link);
    try run_campaign(campaign, twins_link);
}

test "twins sampled" {
    try run_all_links(twins_campaign);
}

test "twins pipelined handoff" {
    var campaign = twins_campaign;
    campaign.handoffs = true;
    try run_all_links(campaign);
}

test "twins sustained" {
    var campaign = twins_campaign;
    campaign.mode = .sustained;
    try run_all_links(campaign);
}

test "twins stable leader" {
    var campaign = twins_campaign;
    campaign.term_length = 3;
    try run_all_links(campaign);
}

test "twins stable leader optimistic" {
    var campaign = twins_campaign;
    campaign.term_length = 3;
    campaign.optimistic_views = 2;
    try run_all_links(campaign);
}

/// commonware's large campaigns: 10 participants and 5 adversarial rounds on `twins_link`.
fn run_large(mode: twins.Mode) !void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    var campaign = twins_campaign;
    campaign.n = 10;
    campaign.rounds = 5;
    campaign.mode = mode;
    try run_campaign(campaign, twins_link);
}

test "twins large sampled" {
    try run_large(.sampled);
}

test "twins large sustained" {
    try run_large(.sustained);
}
