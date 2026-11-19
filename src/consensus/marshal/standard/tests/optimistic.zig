//! Deferred's optimistic validation on a live simplex engine (commonware `standard/mod.rs`
//! `optimistic_child` and `issue_5714_regression`).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const parallel = @import("parallel");
const codec = @import("codec");
const cryptography = @import("cryptography");
const types = @import("../../../types.zig");
const simplex = @import("../../../simplex/root.zig");
const simplex_types = @import("../../../simplex/types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks = @import("../../mocks/root.zig");
const mocks_block = @import("../../mocks/block.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const Validator = H.Validator(App);
const Ctx = runtime.deterministic.Context;
const Round = types.Round;
const View = types.View;
const D = harness.D;
const SimNet = harness.Network;
const Vote = simplex_types.Vote(harness.S, harness.D);
const Marshal = @FieldType(Validator, "mailbox");
const Stream = @import("../../ancestry.zig").AncestorStream(Marshal);
const Recording = mocks.verifying.RecordingVerifyingApp(harness.B, Ctx, harness.Ctx, Stream);
const Observed = mocks.verifying.Observed(D);
const Wrapper = @import("../deferred.zig").Deferred(
    Ctx,
    harness.S,
    Recording,
    harness.B,
    types.FixedEpocher,
);

const Params = struct {
    pub const Context = Ctx;
    pub const Scheme = harness.S;
    pub const Elector = simplex.elector.RoundRobinElector;
    pub const Blocker = SimNet.Control;
    pub const Digest = harness.D;
    pub const Automaton = *Wrapper;
    pub const Relay = *Wrapper;
    pub const Reporter = *Wrapper;
    pub const Strategy = parallel.Sequential;
    pub const Sender = SimNet.Sender;
    pub const Receiver = SimNet.Receiver;
};
const Engine = simplex.engine.Engine(Params);
const Channel = simplex.engine.Channel(Params);

const victim_index = 0;
const leader_index = 1;
const observer_index = 2;

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// Terms of two views elect participant 1 for views 1 and 2, and a lookahead of one view lets
/// a validator verify view 2 on its vote for view 1.
fn terms() simplex.elector.RoundRobin(cryptography.Sha256) {
    const length = types.TermLength.new(utils.NonZero(u32).init(2).?);
    return simplex.elector.RoundRobin(cryptography.Sha256).default()
        .with_term(length, .from_secs(60), .new(1));
}

fn register(control: SimNet.Control, channel: u64) !Channel {
    const registered = try control.register(channel, harness.test_quota);
    return .{ .sender = registered.sender, .receiver = registered.receiver };
}

/// The views of the victim's notarize votes, as the observer receives them.
const Notarized = struct {
    views: [8]u64 = undefined,
    len: usize = 0,

    fn slice(self: *const Notarized) []const u64 {
        return self.views[0..self.len];
    }
};

fn collect(receiver: *SimNet.Receiver, victim: harness.K, out: *Notarized) Io.Cancelable!void {
    while (true) {
        var message = receiver.recv() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        defer message.deinit();
        if (!message.peer.eql(victim)) continue;
        const vote = codec.decode(Vote, gpa, message.payload) catch continue;
        if (vote != .notarize) continue;
        if (out.len < out.views.len) {
            out.views[out.len] = vote.notarize.proposal.round.view.get();
            out.len += 1;
        }
    }
}

/// Everything one run borrows; `start` and `stop` pair.
const Run = struct {
    fixture: harness.Fixture,
    network: harness.TestNetwork,
    validator: *Validator,
    observed: Observed,
    application: Recording,
    wrapper: *Wrapper,
    elector: simplex.elector.RoundRobinElector,
    page_cache: runtime.buffer.paged.CacheRef,
    engine: Engine,
    handle: ?runtime.context.Handle(Engine.RunResult),
    leader_vote: Channel,
    leader_certificate: Channel,
    leader_resolver: Channel,
    observer_vote: Channel,

    fn key(self: *const Run, index: usize) harness.K {
        return self.fixture.participants[index];
    }

    fn start_validator(self: *Run, ctx: Ctx) !void {
        var rng = utils.rng.test_rng();
        self.fixture = try harness.fixture(gpa, &rng);
        errdefer self.fixture.deinit(gpa);
        const size = harness.max_message_size(H.Variant);
        const participants = self.fixture.participants;
        self.network = try .start(gpa, ctx.io(), 1, participants, size);
        errdefer self.network.stop();
        const app = try App.init(gpa, ctx.io());
        const provider: harness.Provider = .init(&self.fixture.schemes[victim_index]);
        const child = ctx.child("marshal").with_attribute("index", victim_index);
        const victim = self.key(victim_index);
        self.validator = try Validator.setup(child, self.network.network, victim, provider, 1, app);
        self.observed = .init(gpa);
        self.application = .{ .observed = &self.observed };
        const epoch_length = utils.NonZero(u64).init(harness.blocks_per_epoch).?;
        const epocher: types.FixedEpocher = .new(epoch_length);
        const marshal = self.validator.mailbox.clone();
        self.wrapper = try Wrapper.create(ctx.child("wrapper"), self.application, marshal, epocher);
    }

    /// Registers the victim's three simplex channels (marshal owns 1 and 2), the leader as the
    /// scripted sender, and a tap on the victim's votes, links everyone, and runs the engine.
    fn start_engine(self: *Run, ctx: Ctx, genesis: D) !void {
        const oracle = self.network.network.oracle();
        const victim_control = oracle.control(self.key(victim_index));
        const votes = try register(victim_control, 3);
        const certificates = try register(victim_control, 4);
        const backfill = try register(victim_control, 5);
        const leader_control = oracle.control(self.key(leader_index));
        self.leader_vote = try register(leader_control, 3);
        self.leader_certificate = try register(leader_control, 4);
        self.leader_resolver = try register(leader_control, 5);
        self.observer_vote = try register(oracle.control(self.key(observer_index)), 3);
        try self.network.link_all(self.fixture.participants, harness.link);
        self.elector = try terms().build(gpa, harness.num_validators);
        self.page_cache = try .init(gpa, harness.page_size, harness.page_cache_size);
        try self.engine.init(ctx.child("simplex"), .{
            .scheme = self.fixture.schemes[victim_index],
            .elector = self.elector,
            .blocker = victim_control,
            .automaton = self.wrapper,
            .relay = self.wrapper,
            .reporter = self.wrapper,
            .track_historical_votes = false,
            .strategy = parallel.sequential,
            .partition = "optimistic-child",
            .mailbox_size = 128,
            .epoch = .zero(),
            .floor = .{ .genesis = genesis },
            .replay_buffer = 1024,
            .write_buffer = 1024,
            .page_cache = &self.page_cache,
            .leader_timeout = .from_secs(2),
            .certification_timeout = .from_secs(4),
            .timeout_retry = .from_secs(3),
            .view_retention = .new(10),
            .skip = .{ .enabled = .{ .timeout = .from_secs(6) } },
            .fetch_timeout = .from_secs(1),
            .fetch_retry_delay = .from_millis(100),
            .forward = .disabled,
        });
        const args = .{ &self.engine, votes, certificates, backfill };
        self.handle = try ctx.child("engine").spawn(Engine.run, args);
    }

    fn stop(self: *Run, ctx: Ctx) void {
        if (self.handle) |handle| {
            // `Closed` means the abort ended the engine, as it should.
            if (handle.abort()) |result| {
                result catch |err| std.debug.panic("engine failed: {t}", .{err});
            } else |_| {}
        }
        self.engine.deinit();
        ctx.io().sleep(.fromMilliseconds(100), .awake) catch {};
        self.wrapper.destroy();
        const channels = [_]*Channel{
            &self.leader_vote,
            &self.leader_certificate,
            &self.leader_resolver,
            &self.observer_vote,
        };
        for (channels) |channel| {
            channel.sender.deinit();
            channel.receiver.deinit();
        }
        self.elector.deinit(gpa);
        self.page_cache.deinit();
        self.validator.crash();
        self.observed.deinit();
        self.network.stop();
        self.fixture.deinit(gpa);
    }

    /// Sends the leader's own notarize vote for `block` at `round` to the victim.
    fn notarize(self: *Run, round: Round, parent: u64, digest: D) !void {
        const Notarize = simplex_types.Notarize(harness.S, harness.D);
        const proposal = harness.Proposal.init(round, .new(parent), digest);
        const signed = (try Notarize.sign(gpa, &self.fixture.schemes[leader_index], proposal)).?;
        const bytes = try codec.encode(Vote, gpa, .{ .notarize = signed });
        defer gpa.free(bytes);
        const victim = self.key(victim_index);
        gpa.free(try self.leader_vote.sender.send(.{ .one = victim }, &.{bytes}, true));
    }
};

/// A block at `round` by the leader over `(parent_view, context_parent)` that names
/// `parent` as its own parent.
fn block_at(
    leader: harness.K,
    round: Round,
    parent_view: u64,
    context_parent: D,
    parent: D,
    height: u64,
    timestamp: u64,
) !harness.B {
    const context: harness.Ctx = .{
        .round = round,
        .leader = leader,
        .parent = .{ .new(parent_view), context_parent },
    };
    return harness.B.init(gpa, context, parent, .new(height), timestamp);
}

const Outcome = struct { notarized: Notarized, verified: [2]bool };

/// Runs the victim against a scripted leader proposing a first block in view 1 and its child
/// in view 2. With `linked` the first block names genesis as its parent; otherwise a digest no
/// block has. Returns the victim's notarized views and whether the application started
/// verifying each block (commonware `optimistic_child`).
fn optimistic_child(ctx: Ctx, linked: bool) !Outcome {
    const io = ctx.io();
    var elector = try terms().build(gpa, harness.num_validators);
    defer elector.deinit(gpa);
    for ([_]u64{ 1, 2 }) |view| {
        try testing.expectEqual(@as(u32, leader_index), elector.elect(round_at(view), {}).get());
    }
    var run: Run = undefined;
    run.handle = null;
    try run.start_validator(ctx);
    var genesis = try H.genesis_block(gpa, harness.num_validators);
    defer genesis.deinit();
    const leader = run.key(leader_index);
    const unlinked = harness.Sha256.hash(&.{"not the context parent"});
    const first_parent = if (linked) genesis.digest() else unlinked;
    const first = try block_at(leader, round_at(1), 0, genesis.digest(), first_parent, 1, 100);
    const child = try block_at(leader, round_at(2), 1, first.digest(), first.digest(), 2, 200);
    const digests = [2]D{ first.digest(), child.digest() };
    // Cache both blocks in the victim's buffer, as the leader's broadcast would.
    for ([_]harness.B{ first, child }) |raw| {
        const block = try mocks_block.ready(harness.B, gpa, raw);
        _ = try run.validator.extra.mailbox.broadcast(.{ .some = &.{} }, block);
    }
    try run.start_engine(ctx, genesis.digest());
    defer run.stop(ctx);
    var outcome: Outcome = .{ .notarized = .{}, .verified = .{ false, false } };
    var collector = try io.concurrent(collect, .{
        &run.observer_vote.receiver,
        run.key(victim_index),
        &outcome.notarized,
    });
    defer collector.cancel(io) catch {};
    // The leader's votes carry both proposals; the child arrives while the victim is in view 1.
    try run.notarize(round_at(1), 0, digests[0]);
    try ctx.sleep(.fromMilliseconds(250));
    try run.notarize(round_at(2), 1, digests[1]);
    try ctx.sleep(.fromMilliseconds(250));
    // By then view 1 has passed its certification timeout and the victim acted on both.
    try ctx.sleep(.fromSeconds(5));
    for (run.observed.items.items) |event| switch (event) {
        .started => |digest| for (digests, 0..) |candidate, index| {
            if (digest.eql(candidate)) outcome.verified[index] = true;
        },
        .cancelled => {},
    };
    return outcome;
}

fn Case(comptime linked: bool) type {
    return struct {
        var outcome: Outcome = undefined;

        fn body(ctx: Ctx) anyerror!void {
            outcome = try optimistic_child(ctx, linked);
        }

        fn run() !Outcome {
            const config: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };
            var runner = try runtime.deterministic.Runner.init(gpa, config);
            defer runner.deinit();
            try try runner.start_context(body, .{});
            return outcome;
        }
    };
}

test "issue 5714 regression: an unlinked block and its child get no vote" {
    // commonware `issue_5714_regression`. A first block naming its context's parent gets the
    // vote, and its child is verified on that vote alone.
    const linked = try Case(true).run();
    try testing.expectEqualSlices(u64, &.{ 1, 2 }, linked.notarized.slice());
    try testing.expectEqual([2]bool{ true, true }, linked.verified);
    // A first block naming any other parent gets no vote, so consensus never verifies the child.
    const unlinked = try Case(false).run();
    try testing.expectEqualSlices(u64, &.{}, unlinked.notarized.slice());
    try testing.expectEqual([2]bool{ false, false }, unlinked.verified);
}
