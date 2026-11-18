//! commonware `actors/resolver/actor.rs` tests that run the whole resolver actor, with its
//! p2p resolver engine, on the simulated network and the deterministic runtime.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const actor = @import("actor");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const actor_mod = @import("actor.zig");
const voter_ingress = @import("../voter/ingress.zig");

const TestDigest = cryptography.Sha256.Digest;
const TestScheme = ed25519.Scheme(TestDigest);
const Key = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Context = runtime.deterministic.Context;
const Certificate = types.Certificate(TestScheme, TestDigest);
const VoterMessage = voter_ingress.Message(TestScheme, TestDigest);
const VoterMailbox = voter_ingress.Mailbox(TestScheme, TestDigest);
const RecvError = std.Io.Cancelable || error{NetworkClosed};
const View = consensus_types.View;
const Epoch = consensus_types.Epoch;
const Duration = utils.Duration;
const gpa = testing.allocator;

const namespace = "resolver-actor";
const epoch: Epoch = .new(9);
const quota = p2p.Quota.per_second(1_000);
const resolver_channel = 2;

const Params = struct {
    pub const Scheme = TestScheme;
    pub const Digest = TestDigest;
    pub const Blocker = Net.Control;
    pub const Strategy = parallel.Sequential;
    pub const NetSender = Net.Sender;
    pub const NetReceiver = Net.Receiver;
};
const Actor = actor_mod.Actor(Params);
const RunResult = @typeInfo(@TypeOf(Actor.run)).@"fn".return_type.?;

fn link_ms(latency_ms: u64, jitter_ms: u64) p2p.simulated.Link {
    return .{
        .latency = .from_millis(latency_ms),
        .jitter = .from_millis(jitter_ms),
        .success_rate = 1.0,
    };
}

fn nullification(fixture: anytype, view: u64) !Certificate {
    const Nullify = types.Nullify(TestScheme);
    const round: consensus_types.Round = .new(epoch, .new(view));
    var votes: [4]Nullify = undefined;
    for (&votes, fixture.schemes) |*vote, *scheme| {
        vote.* = (try Nullify.sign(gpa, scheme, round)).?;
    }
    const sequential = parallel.sequential;
    return .{ .nullification = try .from_votes(gpa, &fixture.verifier, &votes, sequential) };
}

const Options = struct {
    term_length: u32 = 1,
    fetch_timeout: Duration = .from_millis(200),
    fetch_retry_delay: Duration = .from_millis(200),
    mailbox_size: u32 = 8,
};

/// One running resolver actor and the voter mailbox it reports to. Must not move once
/// started.
const Node = struct {
    actor: Actor,
    mailbox: Actor.Mailbox,
    voter: actor.mailbox.Receiver(VoterMessage),
    future: std.Io.Future(RunResult),
    /// Kept here: a scope is too large for a task's arguments.
    scope: runtime.telemetry.metrics.Scope,

    fn start(
        node: *Node,
        ctx: Context,
        scheme: *const TestScheme,
        blocker: Net.Control,
        channel: Net.Registered,
        options: Options,
    ) !void {
        const io = ctx.io();
        node.actor, node.mailbox = try Actor.init(gpa, io, .{
            .scheme = scheme,
            .blocker = blocker,
            .strategy = parallel.sequential,
            .epoch = epoch,
            .mailbox_size = options.mailbox_size,
            .fetch_timeout = options.fetch_timeout,
            .fetch_retry_delay = options.fetch_retry_delay,
            .term_length = .new(utils.NonZero(u32).init(options.term_length).?),
        });
        const voter = try actor.mailbox.new(VoterMessage, gpa, io, 8);
        node.voter = voter.receiver;
        const voter_mailbox: VoterMailbox = .{ .sender = voter.sender };
        try node.mailbox.replayed();
        node.scope = ctx.scope;
        node.future = try io.concurrent(run_node, .{
            node, voter_mailbox, channel.sender, channel.receiver,
        });
    }

    fn run_node(
        node: *Node,
        voter: VoterMailbox,
        sender: Net.Sender,
        receiver: Net.Receiver,
    ) RunResult {
        return node.actor.run(node.scope, voter, sender, receiver);
    }

    fn stop(node: *Node, io: std.Io) void {
        node.future.cancel(io) catch {};
        node.voter.deinit();
        node.mailbox.deinit();
        node.actor.deinit();
    }
};

/// The 4-participant network every case runs on, with each participant's resolver channel.
const Harness = struct {
    ctx: Context,
    fixture: cryptography.certificate.mocks.Fixture(TestScheme),
    network: *Net,
    network_task: std.Io.Future(@typeInfo(@TypeOf(Net.run)).@"fn".return_type.?),
    channels: [4]Net.Registered,

    fn start(harness: *Harness, ctx: Context) !void {
        return harness.start_with_quota(ctx, quota);
    }

    fn start_with_quota(harness: *Harness, ctx: Context, channel_quota: p2p.Quota) !void {
        const io = ctx.io();
        var rng = utils.rng.test_rng();
        harness.ctx = ctx;
        harness.fixture = try ed25519.fixture(TestDigest, gpa, &rng, namespace, 4);
        errdefer harness.fixture.deinit(gpa);
        harness.network = try Net.init(gpa, io, .{
            .max_size = 1024 * 1024,
            .max_peers_per_set = 4,
            .disconnect_on_block = true,
            .tracked_peer_sets = 1,
        });
        harness.network_task = try io.concurrent(Net.run, .{harness.network});
        const peers = harness.fixture.participants;
        _ = harness.oracle().manager().track(0, .init_primary(.init(peers)));
        for (&harness.channels, peers) |*channel, peer| {
            const control = harness.oracle().control(peer);
            channel.* = try control.register(resolver_channel, channel_quota);
        }
    }

    fn deinit(harness: *Harness) void {
        const io = harness.ctx.io();
        harness.network.close();
        harness.network_task.await(io) catch {};
        harness.network.deinit();
        harness.fixture.deinit(gpa);
        harness.* = undefined;
    }

    /// Releases the registered channels at `indices` that no actor took.
    fn close_channels(harness: *Harness, indices: []const usize) void {
        for (indices) |index| {
            harness.channels[index].sender.deinit();
            harness.channels[index].receiver.deinit();
        }
    }

    fn oracle(harness: *const Harness) Net.Oracle {
        return harness.network.oracle();
    }

    fn key(harness: *const Harness, index: usize) Key {
        return harness.fixture.participants[index];
    }

    fn link_both(harness: *const Harness, a: usize, b: usize) !void {
        const link = link_ms(10, 1);
        try harness.oracle().add_link(harness.key(a), harness.key(b), link);
        try harness.oracle().add_link(harness.key(b), harness.key(a), link);
    }
};

fn recv_silent(receiver: *Net.Receiver) !p2p.Message(Key) {
    return receiver.recv();
}

fn recv_voter(receiver: *actor.mailbox.Receiver(VoterMessage)) !?VoterMessage {
    return receiver.recv();
}

/// commonware `assert_targeted_fetch_does_not_restrict_existing_backfill`: a targeted ask
/// that joins an in-flight unrestricted fetch must not narrow it to the target.
fn targeted_fetch_keeps_backfill(ctx: Context, target_index: usize) !void {
    const io = ctx.io();
    var harness: Harness = undefined;
    try harness.start(ctx);
    defer harness.deinit();
    try harness.link_both(0, 1);
    const fixture = &harness.fixture;
    var requester: Node = undefined;
    const requester_control = harness.oracle().control(harness.key(0));
    try requester.start(ctx, &fixture.schemes[0], requester_control, harness.channels[0], .{});
    defer requester.stop(io);
    var responder: Node = undefined;
    const responder_control = harness.oracle().control(harness.key(2));
    try responder.start(ctx, &fixture.schemes[2], responder_control, harness.channels[2], .{});
    defer responder.stop(io);
    const requested: View = .new(1);
    try responder.mailbox.updated(gpa, try nullification(fixture, 1));
    try ctx.sleep(.fromMilliseconds(10));
    // Advancing to view 2 opens an unrestricted background ask for view 1. The only linked
    // peer is silent, so its request proves the background fetch is in flight.
    try requester.mailbox.updated(gpa, try nullification(fixture, 2));
    var silent = harness.channels[1].receiver;
    var request = try try ctx.timeout(.fromSeconds(2), recv_silent, .{&silent});
    defer request.deinit();
    try testing.expect(request.peer.eql(harness.key(0)));
    // A later targeted ancestry request (remote or self) attaches without narrowing it.
    const target = harness.key(target_index);
    try requester.mailbox.resolve(.new(3), requested, .nullification, target);
    try ctx.sleep(.fromMilliseconds(10));
    // Block the silent and unlinked peers, then link another responder: a narrowed fetch
    // could not finish.
    _ = requester_control.block(harness.key(1));
    _ = requester_control.block(harness.key(3));
    try harness.link_both(0, 2);
    const recovered = try try ctx.timeout(.fromSeconds(2), recv_voter, .{&requester.voter}) orelse
        return error.VoterClosed;
    defer VoterMessage.discard(recovered);
    try testing.expect(recovered == .verified);
    const certificate = recovered.verified.certificate;
    try testing.expect(certificate == .nullification);
    try testing.expectEqual(requested, certificate.view());
    silent.deinit();
    harness.channels[1].sender.deinit();
    harness.channels[3].sender.deinit();
    harness.channels[3].receiver.deinit();
}

fn notarization(fixture: anytype, view: u64) !types.Notarization(TestScheme, TestDigest) {
    const Notarize = types.Notarize(TestScheme, TestDigest);
    const proposal: types.Proposal(TestDigest) =
        .init(.new(epoch, .new(view)), .new(view - 1), .fill(@intCast(view)));
    var votes: [4]Notarize = undefined;
    for (&votes, fixture.schemes) |*vote, *scheme| {
        vote.* = (try Notarize.sign(gpa, scheme, proposal)).?;
    }
    return .from_votes(gpa, &fixture.verifier, &votes, parallel.sequential);
}

/// commonware `untargeted_parent_fetch_uses_available_holder`: certification recovery
/// fetches a missing mid-term parent from an available holder when the term's leader is
/// unavailable.
fn untargeted_parent_fetch(ctx: Context) !void {
    const io = ctx.io();
    const term_length = 5;
    const RoundRobin = @import("../../elector.zig").RoundRobin(cryptography.Sha256);
    const length = utils.NonZero(u32).init(term_length).?;
    const builder = RoundRobin.default().with_term(.new(length), .from_secs(1), .new(0));
    var elector = try builder.build(gpa, 4);
    defer elector.deinit(gpa);
    // The fixture must leave the stable leader unavailable.
    try testing.expectEqual(2, elector.elect(.new(epoch, .new(1)), {}).get());
    var harness: Harness = undefined;
    try harness.start(ctx);
    defer harness.deinit();
    try harness.link_both(0, 1);
    try harness.link_both(0, 3);
    const fixture = &harness.fixture;
    const options: Options = .{ .term_length = term_length };
    var requester: Node = undefined;
    const control = harness.oracle().control(harness.key(0));
    try requester.start(ctx, &fixture.schemes[0], control, harness.channels[0], options);
    defer requester.stop(io);
    var holders: [2]Node = undefined;
    for (&holders, [2]usize{ 1, 3 }) |*holder, index| {
        const holder_control = harness.oracle().control(harness.key(index));
        const channel = harness.channels[index];
        try holder.start(ctx, &fixture.schemes[index], holder_control, channel, options);
        try holder.mailbox.updated(gpa, .{ .notarization = try notarization(fixture, 2) });
        try holder.mailbox.certified(gpa, try notarization(fixture, 2), true);
    }
    defer for (&holders) |*holder| holder.stop(io);
    // Request the parent from any peer (the voter test covers the child that triggers it).
    try ctx.sleep(.fromMilliseconds(10));
    try requester.mailbox.resolve(.new(3), .new(2), .notarization, null);
    const recovered = try try ctx.timeout(.fromSeconds(5), recv_voter, .{&requester.voter}) orelse
        return error.VoterClosed;
    defer VoterMessage.discard(recovered);
    try testing.expect(recovered == .verified);
    const certificate = recovered.verified.certificate;
    try testing.expect(certificate == .notarization);
    var expected = try notarization(fixture, 2);
    defer expected.deinit(gpa);
    try testing.expect(certificate.notarization.eql(expected));
    harness.channels[2].sender.deinit();
    harness.channels[2].receiver.deinit();
}

test "resolver actor untargeted parent fetch uses an available holder" {
    try run(untargeted_parent_fetch, .{});
}

/// commonware `served_requests_hold_channel_capacity`: every request the network admits is
/// served even when every peer bursts at once and the holder's mailbox holds one message.
fn served_requests(ctx: Context) !void {
    const io = ctx.io();
    const burst = 2;
    var harness: Harness = undefined;
    try harness.start_with_quota(ctx, .per_second(burst));
    defer harness.deinit();
    const holder_index = 1;
    const requesters = [_]usize{ 0, 2, 3 };
    for (requesters) |index| try harness.link_both(index, holder_index);
    // Each requester sends its whole burst before the holder starts, so the holder's engine
    // forwards every request to the handler in one pass. A request is `id`, tag 0, key 1.
    for (requesters, 0..) |index, position| {
        for (0..burst) |id| {
            var request: [17]u8 = undefined;
            std.mem.writeInt(u64, request[0..8], position * burst + id, .big);
            request[8] = 0;
            std.mem.writeInt(u64, request[9..17], 1, .big);
            const sender = &harness.channels[index].sender;
            const sent = try sender.send(.{ .one = harness.key(holder_index) }, &.{&request}, true);
            gpa.free(sent);
        }
    }
    try ctx.sleep(.fromMilliseconds(50));
    const fixture = &harness.fixture;
    var holder: Node = undefined;
    const control = harness.oracle().control(harness.key(holder_index));
    const channel = harness.channels[holder_index];
    const options: Options = .{ .term_length = 5, .mailbox_size = 1 };
    try holder.start(ctx, &fixture.schemes[holder_index], control, channel, options);
    defer holder.stop(io);
    try holder.mailbox.updated(gpa, try nullification(fixture, 1));
    // Every request is answered with the certificate rather than an error.
    var answered: [requesters.len * burst]bool = @splat(false);
    for (requesters) |index| {
        for (0..burst) |_| {
            const receiver = &harness.channels[index].receiver;
            var reply = try try ctx.timeout(.fromSeconds(2), recv_silent, .{receiver});
            defer reply.deinit();
            const id = std.mem.readInt(u64, reply.payload[0..8], .big);
            try testing.expectEqual(1, reply.payload[8]); // Served.
            try testing.expect(!answered[id]);
            answered[id] = true;
        }
    }
    for (requesters) |index| {
        harness.channels[index].sender.deinit();
        harness.channels[index].receiver.deinit();
    }
}

test "resolver actor served requests hold channel capacity" {
    try run(served_requests, .{});
}

/// commonware `unresolved_delivery_does_not_block_nullification_fetch`: a valid
/// notarization that does not settle the ask does not keep another peer from supplying the
/// requested nullification.
fn unresolved_delivery(ctx: Context) !void {
    const io = ctx.io();
    var harness: Harness = undefined;
    try harness.start(ctx);
    defer harness.deinit();
    try harness.link_both(0, 1);
    const fixture = &harness.fixture;
    var nodes: [3]Node = undefined;
    const requester_control = harness.oracle().control(harness.key(0));
    for (&nodes, 0..) |*node, index| {
        const control = harness.oracle().control(harness.key(index));
        try node.start(ctx, &fixture.schemes[index], control, harness.channels[index], .{});
    }
    defer for (&nodes) |*node| node.stop(io);
    const requester, const first_responder, const holder = .{ &nodes[0], &nodes[1], &nodes[2] };
    const requested: View = .new(1);
    const notarized = requested.next();
    // Certifying the notarization makes it the responder's floor, so it answers a lower
    // view's request with it.
    try first_responder.mailbox.updated(gpa, .{ .notarization = try notarization(fixture, 2) });
    try first_responder.mailbox.certified(gpa, try notarization(fixture, 2), true);
    try holder.mailbox.updated(gpa, try nullification(fixture, 1));
    try ctx.sleep(.fromMilliseconds(10));
    // A later nullification exposes a gap and starts an unrestricted background fetch; the
    // only linked peer answers with a notarization that does not settle the ask.
    try requester.mailbox.updated(gpa, try nullification(fixture, notarized.get()));
    const first = try try ctx.timeout(.fromSeconds(2), recv_voter, .{&requester.voter}) orelse
        return error.VoterClosed;
    defer VoterMessage.discard(first);
    try testing.expect(first == .verified and first.verified.certificate == .notarization);
    try testing.expectEqual(notarized, first.verified.certificate.view());
    // Block the other peers and link the nullification holder, so retries reach only it.
    _ = requester_control.block(harness.key(1));
    _ = requester_control.block(harness.key(3));
    try harness.link_both(0, 2);
    try ctx.sleep(.fromMilliseconds(10));
    // The unresolved delivery released the slot: an ancestry ask for the same view fetches
    // the nullification from another peer.
    try requester.mailbox.resolve(.new(3), requested, .nullification, harness.key(2));
    const recovered = try try ctx.timeout(.fromSeconds(2), recv_voter, .{&requester.voter}) orelse
        return error.VoterClosed;
    defer VoterMessage.discard(recovered);
    try testing.expect(recovered == .verified);
    try testing.expect(recovered.verified.certificate == .nullification);
    try testing.expectEqual(requested, recovered.verified.certificate.view());
    harness.channels[3].sender.deinit();
    harness.channels[3].receiver.deinit();
}

test "resolver actor unresolved delivery does not block a nullification fetch" {
    try run(unresolved_delivery, .{});
}

/// A checked send the network always accepts (commonware `InertCheckedSender`).
const InertChecked = struct {
    pub fn send(_: InertChecked, parts: []const []const u8, _: bool) p2p.Unreliable(p2p.Feedback) {
        assert(parts.len > 0);
        return .{ .outcome = .ok };
    }

    pub fn deinit(_: InertChecked) void {}
};

/// A sender that accepts every request and never replies (commonware `inert_channel`), or,
/// with `ready_at`, reports every checked peer and rate-limits it until then (commonware
/// `RateLimitedSender`).
const TestSender = struct {
    checked: ?*std.ArrayList(Key) = null,
    ready_at: utils.SystemTime = undefined,

    pub fn check(self: *TestSender, recipients: p2p.Recipients(Key)) !p2p.Check(InertChecked) {
        assert(recipients == .one); // The resolver checks one recipient at a time.
        const checked = self.checked orelse return .{ .checked = .{} };
        try checked.append(gpa, recipients.one);
        return .{ .limited = self.ready_at };
    }

    pub fn send(_: *TestSender, _: p2p.Recipients(Key), _: []const []const u8, _: bool) ![]Key {
        return gpa.alloc(Key, 0);
    }
};

/// A receiver that never yields a message.
const SilentReceiver = struct {
    io: std.Io,

    pub fn recv(self: *SilentReceiver) RecvError!p2p.Message(Key) {
        // Each wake re-sleeps; only cancellation ends the wait.
        while (true) try self.io.sleep(.fromSeconds(3600), .awake);
    }

    pub fn capacity(_: *const SilentReceiver) usize {
        return 8;
    }
};

const InertParams = struct {
    pub const Scheme = TestScheme;
    pub const Digest = TestDigest;
    pub const Blocker = Net.Control;
    pub const Strategy = parallel.Sequential;
    pub const NetSender = TestSender;
    pub const NetReceiver = SilentReceiver;
};
const InertActor = actor_mod.Actor(InertParams);
const InertResult = @typeInfo(@TypeOf(InertActor.run)).@"fn".return_type.?;

/// A resolver actor on `TestSender` and `SilentReceiver`, with no peer ever replying.
const InertNode = struct {
    actor: InertActor,
    mailbox: InertActor.Mailbox,
    voter: actor.mailbox.Receiver(VoterMessage),
    future: std.Io.Future(InertResult),
    scope: runtime.telemetry.metrics.Scope,

    fn start(
        node: *InertNode,
        ctx: Context,
        scheme: *const TestScheme,
        blocker: Net.Control,
        sender: TestSender,
        options: Options,
    ) !void {
        const io = ctx.io();
        node.actor, node.mailbox = try InertActor.init(gpa, io, .{
            .scheme = scheme,
            .blocker = blocker,
            .strategy = parallel.sequential,
            .epoch = epoch,
            .mailbox_size = options.mailbox_size,
            .fetch_timeout = options.fetch_timeout,
            .fetch_retry_delay = options.fetch_retry_delay,
            .term_length = .new(utils.NonZero(u32).init(options.term_length).?),
        });
        const voter = try actor.mailbox.new(VoterMessage, gpa, io, 8);
        node.voter = voter.receiver;
        const voter_mailbox: VoterMailbox = .{ .sender = voter.sender };
        node.scope = ctx.scope;
        try node.mailbox.replayed();
        const receiver: SilentReceiver = .{ .io = io };
        node.future = try io.concurrent(run_inert, .{ node, voter_mailbox, sender, receiver });
    }

    fn run_inert(
        node: *InertNode,
        voter: VoterMailbox,
        sender: TestSender,
        receiver: SilentReceiver,
    ) InertResult {
        return node.actor.run(node.scope, voter, sender, receiver);
    }

    fn stop(node: *InertNode, io: std.Io) void {
        node.future.cancel(io) catch {};
        node.voter.deinit();
        node.mailbox.deinit();
        node.actor.deinit();
    }
};

/// Whether `ctx`'s registry shows `count` requests sent.
fn requests_sent(ctx: Context, count: u64) !bool {
    const text = try ctx.scope.encode(gpa);
    defer gpa.free(text);
    return runtime.telemetry.metrics.has_metric_value(text, "requests_sent_total", count);
}

/// commonware `retry_delay_is_independent_of_request_timeout`: request expiry and retry
/// backoff use their own configured durations.
fn retry_delay(ctx: Context) !void {
    const io = ctx.io();
    var harness: Harness = undefined;
    try harness.start(ctx);
    defer harness.deinit();
    const fetch_timeout: Duration = .from_secs(1);
    const fetch_retry_delay: Duration = .from_millis(100);
    const start = ctx.current();
    var node: InertNode = undefined;
    const control = harness.oracle().control(harness.key(0));
    const options: Options = .{
        .fetch_timeout = fetch_timeout,
        .fetch_retry_delay = fetch_retry_delay,
    };
    try node.start(ctx, &harness.fixture.schemes[0], control, .{}, options);
    defer node.stop(io);
    try node.mailbox.resolve(.new(2), .new(1), .notarization, harness.key(1));
    const timeout_ns: i96 = @intCast(fetch_timeout.as_nanos());
    const retry_ns: i96 = @intCast(fetch_retry_delay.as_nanos());
    try ctx.sleep_until(start.addDuration(.fromMilliseconds(50)));
    try testing.expect(try requests_sent(ctx, 1));
    // Expiry alone cannot dispatch the next request while its backoff is pending.
    try ctx.sleep_until(start.addDuration(.fromNanoseconds(timeout_ns + @divExact(retry_ns, 2))));
    try testing.expect(try requests_sent(ctx, 1));
    // The shorter retry delay releases the request before another timeout elapses.
    try ctx.sleep_until(start.addDuration(.fromNanoseconds(timeout_ns + 2 * retry_ns)));
    try testing.expect(try requests_sent(ctx, 2));
    harness.close_channels(&.{ 0, 1, 2, 3 });
}

test "resolver actor retry delay is independent of the request timeout" {
    try run(retry_delay, .{});
}

/// commonware `member_without_share_does_not_fetch_from_itself`: a committee member whose
/// scheme cannot sign never selects itself as a fetch target.
fn member_without_share(ctx: Context) !void {
    const io = ctx.io();
    var harness: Harness = undefined;
    try harness.start(ctx);
    defer harness.deinit();
    const fixture = &harness.fixture;
    const set = try fixture.verifier.participants().clone(gpa);
    var member = (try TestScheme.member(gpa, namespace, set, harness.key(0))).?;
    defer member.deinit(gpa);
    const fetch_timeout: Duration = .from_secs(5);
    var checked: std.ArrayList(Key) = .empty;
    defer checked.deinit(gpa);
    const ready_at = ctx.current().addDuration(.fromSeconds(5));
    const sender: TestSender = .{ .checked = &checked, .ready_at = .from_timestamp(ready_at) };
    var node: InertNode = undefined;
    const control = harness.oracle().control(harness.key(0));
    const options: Options = .{
        .fetch_timeout = fetch_timeout,
        .fetch_retry_delay = fetch_timeout,
    };
    try node.start(ctx, &member, control, sender, options);
    defer node.stop(io);
    // Advancing to view 2 opens a background fetch for view 1. Every peer is rate-limited,
    // so one pass inspects the whole candidate set, whatever the selection order.
    try node.mailbox.updated(gpa, try nullification(fixture, 2));
    try ctx.sleep(.fromMilliseconds(100));
    std.mem.sort(Key, checked.items, {}, key_less);
    try testing.expectEqual(3, checked.items.len);
    for (checked.items, fixture.participants[1..]) |peer, expected| {
        try testing.expect(peer.eql(expected));
    }
    harness.close_channels(&.{ 0, 1, 2, 3 });
}

fn key_less(_: void, a: Key, b: Key) bool {
    return a.order(b) == .lt;
}

test "resolver actor member without a share does not fetch from itself" {
    try run(member_without_share, .{});
}

fn run(comptime scenario: anytype, args: anytype) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = 0 });
    defer runner.deinit();
    try (try runner.start_context(scenario, args));
}

test "resolver actor targeted fetch does not restrict existing backfill" {
    try run(targeted_fetch_keeps_backfill, .{1});
}

test "resolver actor self-targeted fetch does not restrict existing backfill" {
    try run(targeted_fetch_keeps_backfill, .{0});
}

comptime {
    assert(resolver_channel == 2);
}
