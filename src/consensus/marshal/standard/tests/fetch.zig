//! commonware `marshal/standard/mod.rs` fetch-path tests (lines 4713-4993): a parent fetch
//! driven by a child that lies about its height stays bound to the parent's round, and a
//! parent fetch whose first response is invalid blocks that peer and retries another.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks_block = @import("../../mocks/block.zig");
const mocks = @import("../../mocks/root.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const Ctx = runtime.deterministic.Context;
const Round = types.Round;
const D = harness.D;
const Block = common.Block;

const Started = common.Started(harness.Provider, App, common.RecordingBuffer);
const Validator = H.Validator(App);

/// The mock application and both wrappers over marshal mailbox `M`.
fn Wrappers(comptime M: type) type {
    const Stream = @import("../../ancestry.zig").AncestorStream(M);
    return struct {
        pub const Mock = mocks.verifying.MockVerifyingApp(harness.B, Ctx, harness.Ctx, Stream);
        pub const Inline = @import("../inline.zig").Inline(
            Ctx,
            harness.S,
            Mock,
            harness.B,
            types.FixedEpocher,
        );
        pub const Deferred = @import("../deferred.zig").Deferred(
            Ctx,
            harness.S,
            Mock,
            harness.B,
            types.FixedEpocher,
        );
    };
}

/// Wrappers over a `start_standard_actor` mailbox.
const Direct = Wrappers(Started.A.Mailbox);
/// Wrappers over a harness validator's mailbox.
const Networked = Wrappers(@FieldType(Validator, "mailbox"));

fn run_for(seconds: u64, comptime body: fn (Ctx) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = seconds * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

fn epocher() types.FixedEpocher {
    return .new(utils.NonZero(u64).init(harness.blocks_per_epoch).?);
}

/// A block proposed by `leader` at `round` over `(parent_view, parent)`.
fn proposed_block(
    round: Round,
    leader: harness.K,
    parent_view: u64,
    parent: D,
    height: u64,
    timestamp: u64,
) !Block {
    const context: harness.Ctx = .{ .round = round, .leader = leader, .parent = .{
        .new(parent_view),
        parent,
    } };
    const raw = try harness.B.init(gpa, context, parent, .new(height), timestamp);
    return mocks_block.ready(harness.B, gpa, raw);
}

/// Each wrapper call as an `Io` task, so a test can hold it in flight.
fn Calls(comptime W: type) type {
    return struct {
        fn verify(wrapper: *W, context: harness.Ctx, digest: D) Io.Cancelable!?bool {
            return wrapper.verify(undefined, context, digest);
        }

        fn certify(wrapper: *W, round: Round, digest: D) Io.Cancelable!?bool {
            return wrapper.certify(undefined, round, digest);
        }
    };
}

/// Whether the resolver holds the parent's round-bound fetch: key `Notarized(round)` with a
/// `Notarization(round)` subscriber.
const RoundFetch = struct { resolver: common.RecordingResolver, round: Round };

fn round_fetched(state: RoundFetch) bool {
    const fetches = state.resolver.fetches(gpa) catch return false;
    defer gpa.free(fetches);
    for (fetches) |fetch| {
        const key_match = fetch.key == .notarized and fetch.key.notarized.order(state.round) == .eq;
        const sub_match = fetch.subscriber == .notarization and
            fetch.subscriber.notarization.order(state.round) == .eq;
        if (key_match and sub_match) return true;
    }
    return false;
}

/// Whether `fetch` was driven by the child's claimed height (a block fetch, or one bound to
/// the height below the child's lie).
fn height_driven(fetch: common.Fetch, lied: u64) bool {
    if (fetch.key == .block) return true;
    return switch (fetch.subscriber) {
        .certified => |height| height.get() == lied,
        .untrusted => |untrusted| untrusted.height.get() == lied,
        else => false,
    };
}

/// commonware `test_standard_verify_height_lie_parent_fetch_is_round_bound`: a child that
/// claims height 3 over a height-1 parent must fetch its parent by the parent's round, never
/// by the height the lie implies; once the parent arrives the ancestry is rejected.
fn height_lie(comptime W: type, ctx: Ctx, comptime suffix: []const u8) !void {
    const io = ctx.io();
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    const me = fixture.participants[0];
    var started = try common.start_standard_actor(
        harness.Provider,
        App,
        common.RecordingBuffer,
        ctx.child("validator"),
        "height-lie-" ++ suffix,
        .init(&fixture.schemes[0]),
        try App.manual_ack(gpa, io),
        try common.RecordingBuffer.init(gpa, io),
        .{ .genesis = try H.genesis_block(gpa, harness.num_validators) },
    );
    defer started.crash();
    const marshal = started.mailbox.clone();
    const wrapper = try W.create(ctx.child("wrapper"), Direct.Mock.init(gpa), marshal, epocher());
    defer wrapper.destroy();
    defer io.sleep(.fromMilliseconds(100), .awake) catch {};

    const genesis = try harness.make_raw_block(gpa, harness.genesis_parent(), .zero(), 0);
    const parent_round = round_at(1);
    var parent = try proposed_block(parent_round, me, 0, genesis.digest(), 1, 100);
    defer parent.deinit();
    const child_round = round_at(2);
    var child = try proposed_block(child_round, me, 1, parent.digest(), 3, 200);
    defer child.deinit();
    try testing.expect(try started.mailbox.verified(child_round, child.clone()));

    const child_context = child.inner().context();
    var verify = try io.concurrent(Calls(W).verify, .{ wrapper, child_context, child.digest() });
    defer _ = verify.cancel(io) catch {};
    const state: RoundFetch = .{ .resolver = started.resolver, .round = parent_round };
    try common.wait_until(ctx, 5_000, "round-bound parent fetch", state, round_fetched);
    {
        const fetches = try started.resolver.fetches(gpa);
        defer gpa.free(fetches);
        // The malicious child height must not drive parent fetches.
        for (fetches) |fetch| try testing.expect(!height_driven(fetch, 2));
    }

    try testing.expect(try started.mailbox.verified(parent_round, parent.clone()));
    const verified = try verify.await(io);
    if (W == Direct.Inline) {
        // Inline verify rejects the non-contiguous ancestry.
        try testing.expectEqual(@as(?bool, false), verified);
    } else {
        // Deferred verify passes its pre-checks; certification rejects the ancestry.
        try testing.expectEqual(@as(?bool, true), verified);
        const certified = try wrapper.certify(undefined, child_round, child.digest());
        try testing.expectEqual(@as(?bool, false), certified);
    }
}

fn HeightLie(comptime W: type, comptime suffix: []const u8) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            try height_lie(W, ctx, suffix);
        }
    };
}

test "inline verify height lie parent fetch is round bound" {
    // commonware `test_standard_verify_height_lie_parent_fetch_is_round_bound` (Inline).
    try run_for(30, HeightLie(Direct.Inline, "inline").body);
}

test "deferred verify height lie parent fetch is round bound" {
    // commonware `test_standard_verify_height_lie_parent_fetch_is_round_bound` (Deferred).
    try run_for(30, HeightLie(Direct.Deferred, "deferred").body);
}

const resolver_api = @import("resolver");
const p2p = @import("p2p");
const Malicious = resolver_api.p2p.Engine(resolver_api.p2p.engine.Params(
    harness.K,
    harness.Network.Manager,
    harness.Network.Control,
    common.NoopConsumer,
    common.StaticProducer,
    harness.Network.Sender,
    harness.Network.Receiver,
));

/// Whether `blocker` blocked `blocked` on `network`.
fn has_blocked(network: *harness.Network, blocker: harness.K, blocked: harness.K) !bool {
    const pairs = try network.oracle().blocked(gpa);
    defer gpa.free(pairs);
    for (pairs) |pair| {
        if (pair.origin.eql(blocker) and pair.recipient.eql(blocked)) return true;
    }
    return false;
}

/// Waits up to 5 s for `blocker` to block `blocked`.
fn wait_blocked(io: Io, network: *harness.Network, blocker: harness.K, blocked: harness.K) !void {
    var waited_ms: u64 = 0;
    while (!try has_blocked(network, blocker, blocked)) : (waited_ms += 10) {
        if (waited_ms > 5_000) return error.MaliciousPeerNotBlocked;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
}

/// Starts a resolver for `malicious` that answers the parent round's notarization fetch with
/// bytes that do not decode.
fn start_malicious(
    ctx: Ctx,
    network: *harness.Network,
    malicious: harness.K,
    round: Round,
) !Malicious.Spawned {
    const io = ctx.io();
    const control = network.oracle().control(malicious);
    const backfill = try control.register(1, p2p.Quota.per_second(std.math.maxInt(u32)));
    return Malicious.spawn(gpa, io, ctx.scope.child("malicious_resolver"), .{
        .peer_provider = network.oracle().manager(),
        .blocker = control,
        .consumer = .{ .gpa = gpa, .io = io },
        .producer = .{
            .gpa = gpa,
            .io = io,
            .key = .{ .notarized = round },
            .value = "not a valid notarization",
        },
        .mailbox_size = 100,
        .me = malicious,
        .fetch_timeout = .from_millis(2000),
        .fetch_retry_delay = .from_millis(100),
        .priority_requests = false,
        .priority_responses = false,
    }, backfill.sender, backfill.receiver);
}

/// Harness validator `index` under `ctx.child(name)` with an auto-acknowledging application.
fn setup_node(
    ctx: Ctx,
    comptime name: []const u8,
    network: *harness.TestNetwork,
    fixture: *const harness.Fixture,
    index: usize,
) !*Validator {
    const app = try App.init(gpa, ctx.io());
    const provider: harness.Provider = .init(&fixture.schemes[index]);
    const child = ctx.child(name).with_attribute("index", index);
    const me = fixture.participants[index];
    return Validator.setup(child, network.network, me, provider, 1, app);
}

/// commonware `test_standard_verify_parent_fetch_invalid_first_retries`: the victim's parent
/// fetch first reaches a peer that serves an invalid notarization, blocks it, and once an
/// honest peer holding the parent is reachable, retries there and completes.
fn invalid_first_retries(comptime W: type, ctx: Ctx) !void {
    const io = ctx.io();
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    const victim = fixture.participants[0];
    const malicious = fixture.participants[1];
    const honest = fixture.participants[2];
    const linked = [_]harness.K{ victim, malicious };
    var network: harness.TestNetwork = try .start(gpa, io, 2, &linked, 1 << 20);
    defer network.stop();
    try network.link_all(&linked, harness.link);

    const victim_node = try setup_node(ctx, "victim", &network, &fixture, 0);
    defer victim_node.crash();
    const honest_node = try setup_node(ctx, "honest", &network, &fixture, 2);
    defer honest_node.crash();

    const genesis = try harness.make_raw_block(gpa, harness.genesis_parent(), .zero(), 0);
    const parent_round = round_at(1);
    var parent = try proposed_block(parent_round, victim, 0, genesis.digest(), 1, 100);
    defer parent.deinit();
    const proposal = harness.Proposal.init(parent_round, .zero(), parent.digest());
    var notarization = try harness.make_notarization(gpa, &fixture, proposal, harness.quorum);
    defer notarization.deinit(gpa);
    try H.verify(honest_node, parent_round, &parent);
    _ = honest_node.mailbox.report(.{ .notarization = notarization });
    var held = try honest_node.mailbox.get_block(.{ .digest = parent.digest() });
    try testing.expect(held != null);
    held.?.deinit();

    var spawned = try start_malicious(ctx, network.network, malicious, parent_round);
    defer spawned.mailbox.deinit();
    defer _ = spawned.future.cancel(io) catch {};

    const child_round = round_at(2);
    var child = try proposed_block(child_round, victim, 1, parent.digest(), 2, 200);
    defer child.deinit();
    try H.verify(victim_node, child_round, &child);
    const mock = Networked.Mock.init(gpa);
    const marshal = victim_node.mailbox.clone();
    const wrapper = try W.create(ctx.child("wrapper"), mock, marshal, epocher());
    defer wrapper.destroy();
    defer io.sleep(.fromMilliseconds(100), .awake) catch {};
    const context = child.inner().context();
    const digest = child.digest();
    var call = if (W == Networked.Deferred) call: {
        // Deferred verify optimistically succeeds; certification fetches the parent.
        const optimistic = try wrapper.verify(undefined, context, digest);
        try testing.expectEqual(@as(?bool, true), optimistic);
        break :call try io.concurrent(Calls(W).certify, .{ wrapper, child_round, digest });
    } else try io.concurrent(Calls(W).verify, .{ wrapper, context, digest });
    defer _ = call.cancel(io) catch {};

    // The malicious peer's invalid notarization gets it blocked.
    try wait_blocked(io, network.network, victim, malicious);

    // Once the honest peer is reachable, verification retries against it and completes.
    try network.network.oracle().add_link(victim, honest, harness.link);
    try network.network.oracle().add_link(honest, victim, harness.link);
    const honest_set = [_]harness.K{honest};
    _ = network.network.oracle().manager().track(1, .init_primary(.init(&honest_set)));
    try testing.expectEqual(@as(?bool, true), try call.await(io));
    // The malicious peer stays blocked.
    try testing.expect(try has_blocked(network.network, victim, malicious));
}

fn InvalidFirst(comptime W: type) type {
    return struct {
        fn body(ctx: Ctx) anyerror!void {
            try invalid_first_retries(W, ctx);
        }
    };
}

test "inline verify parent fetch invalid first retries" {
    // commonware `test_standard_verify_parent_fetch_invalid_first_retries` (Inline).
    try run_for(30, InvalidFirst(Networked.Inline).body);
}

test "deferred verify parent fetch invalid first retries" {
    // commonware `test_standard_verify_parent_fetch_invalid_first_retries` (Deferred).
    try run_for(30, InvalidFirst(Networked.Deferred).body);
}
