//! Tests for the batcher actor on the deterministic runtime: network votes become a
//! certificate for the voter, and invalid traffic is blocked.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const lookahead = @import("../../lookahead.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const actor_mod = @import("actor.zig");
const voter_ingress = @import("../voter/ingress.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const Key = cryptography.ed25519.PublicKey;
const ActivityType = types.Activity(Scheme, Digest);
const NetMessage = p2p.Message(Key);
const VoterMessage = voter_ingress.Message(Scheme, Digest);
const gpa = testing.allocator;

const Log = struct {
    blocked: std.ArrayList(Key) = .empty,
    reported: u32 = 0,
    /// Each reported activity's kind and view, in order.
    activities: std.ArrayList(Seen) = .empty,

    const Seen = struct { tag: std.meta.Tag(ActivityType), view: u64 };

    fn deinit(self: *Log) void {
        self.blocked.deinit(gpa);
        self.activities.deinit(gpa);
    }

    fn count(self: *const Log, tag: std.meta.Tag(ActivityType), view: u64) usize {
        var total: usize = 0;
        for (self.activities.items) |seen| {
            total += @intFromBool(seen.tag == tag and seen.view == view);
        }
        return total;
    }
};

const Blocker = struct {
    log: *Log,
    pub const PublicKey = Key;
    pub fn block(self: Blocker, peer: Key) actor.Feedback {
        self.log.blocked.append(gpa, peer) catch @panic("out of memory");
        return .ok;
    }
};

const Reporter = struct {
    log: *Log,
    pub const Activity = ActivityType;
    pub fn report(self: Reporter, activity: ActivityType) actor.Feedback {
        self.log.reported += 1;
        const tag = std.meta.activeTag(activity);
        const seen: Log.Seen = .{ .tag = tag, .view = activity.view().get() };
        self.log.activities.append(gpa, seen) catch @panic("out of memory");
        return .ok;
    }
};

const Relay = struct {
    pub fn broadcast(_: Relay, _: Digest, _: lookahead.Plan(Key)) actor.Feedback {
        return .ok;
    }
};

/// A network receiver fed by the test.
const NetReceiver = struct {
    buffer: [16]NetMessage = undefined,
    queue: Io.Queue(NetMessage) = undefined,
    io: Io,

    fn init(self: *NetReceiver, io: Io) void {
        self.* = .{ .io = io };
        self.queue = .init(&self.buffer);
    }

    fn deliver(self: *NetReceiver, peer: Key, payload: []u8) !void {
        try self.queue.putOne(self.io, .{ .peer = peer, .payload = payload, .gpa = gpa });
    }

    pub fn recv(self: *NetReceiver) Io.Cancelable!?NetMessage {
        return self.queue.getOne(self.io) catch |err| switch (err) {
            error.Canceled => error.Canceled,
            error.Closed => null,
        };
    }
};

fn Params(
    comptime S: type,
    comptime D: type,
    comptime B: type,
    comptime Re: type,
    comptime Rl: type,
    comptime N: type,
) type {
    return struct {
        pub const Scheme = S;
        pub const Digest = D;
        pub const Blocker = B;
        pub const Reporter = Re;
        pub const Relay = Rl;
        pub const Strategy = parallel.Sequential;
        pub const Receiver = N;
    };
}
const P = Params(Scheme, Digest, Blocker, Reporter, Relay, NetReceiver);
const Batcher = actor_mod.Actor(P);

fn proposal(view: u64) types.Proposal(Digest) {
    return .init(.new(.new(0), .new(view)), .new(view - 1), .fill(@intCast(view)));
}

fn config(scheme: *const Scheme, log: *Log) actor_mod.Config(P) {
    return .{
        .scheme = scheme,
        .blocker = .{ .log = log },
        .reporter = .{ .log = log },
        .track_historical_votes = false,
        .relay = .{},
        .strategy = parallel.sequential,
        .view_retention = .new(10),
        .skip = .disabled,
        .epoch = .new(0),
        .mailbox_size = 16,
        .lookahead = .{
            .term_length = .new(utils.NonZero(u32).init(1).?),
            .optimistic_views = .new(0),
        },
        .forward = .disabled,
        .floor = .zero(),
    };
}

fn run_deterministic(comptime function: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
}

fn notarize_bytes(fixture: anytype, signer: usize, view: u64) ![]u8 {
    return notarize_proposal_bytes(fixture, signer, proposal(view));
}

fn notarize_proposal_bytes(
    fixture: anytype,
    signer: usize,
    value: types.Proposal(Digest),
) ![]u8 {
    const Notarize = types.Notarize(Scheme, Digest);
    const vote = (try Notarize.sign(gpa, &fixture.schemes[signer], value)).?;
    const Vote = types.Vote(Scheme, Digest);
    return codec.encode(Vote, gpa, .{ .notarize = vote });
}

/// Receives voter messages until a verified certificate arrives.
fn next_certificate(receiver: *actor.mailbox.Receiver(VoterMessage)) !VoterMessage {
    for (0..8) |_| {
        const message = (try receiver.recv()) orelse return error.Closed;
        if (message == .verified) return message;
    }
    return error.NoCertificate;
}

/// One batcher (participant 0 of 4) running against test channels. Must not move once
/// started: the receivers' queues point into themselves.
const Harness = struct {
    io: Io,
    fixture: cryptography.certificate.mocks.Fixture(Scheme),
    log: Log = .{},
    batcher: Batcher = undefined,
    mailbox: Batcher.Mailbox = undefined,
    voter: actor.mailbox.Receiver(VoterMessage) = undefined,
    votes: NetReceiver = undefined,
    certificates: NetReceiver = undefined,
    future: Io.Future(RunResult) = undefined,

    const RunResult = @typeInfo(@TypeOf(Batcher.run)).@"fn".return_type.?;

    fn start(self: *Harness, io: Io) !void {
        return self.start_scoped(io, null);
    }

    /// Starts with historical votes kept (commonware `track_historical_votes`).
    fn start_historical(self: *Harness, io: Io) !void {
        return self.start_with(io, null, .{ .track_historical_votes = true });
    }

    const Options = struct {
        track_historical_votes: bool = false,
        term_length: u32 = 1,
        optimistic_views: u64 = 0,
    };

    /// Starts with the batcher's metrics registered under `scope`, if any.
    fn start_scoped(self: *Harness, io: Io, scope: ?runtime.telemetry.metrics.Scope) !void {
        return self.start_with(io, scope, .{});
    }

    fn start_with(
        self: *Harness,
        io: Io,
        scope: ?runtime.telemetry.metrics.Scope,
        options: Options,
    ) !void {
        var rng = utils.rng.test_rng();
        const fixture = try ed25519.fixture(Digest, gpa, &rng, "batcher", 4);
        self.* = .{ .io = io, .fixture = fixture };
        var cfg = config(&fixture.schemes[0], &self.log);
        cfg.scope = scope;
        cfg.track_historical_votes = options.track_historical_votes;
        cfg.lookahead = .{
            .term_length = .new(utils.NonZero(u32).init(options.term_length).?),
            .optimistic_views = .new(options.optimistic_views),
        };
        self.batcher, self.mailbox = try Batcher.init(gpa, io, cfg);
        const voter = try actor.mailbox.new(VoterMessage, gpa, io, 16);
        self.voter = voter.receiver;
        self.votes.init(io);
        self.certificates.init(io);
        const voter_mailbox: voter_ingress.Mailbox(Scheme, Digest) = .{ .sender = voter.sender };
        self.future = try io.concurrent(Batcher.run, .{
            &self.batcher, voter_mailbox, &self.votes, &self.certificates,
        });
    }

    fn stop(self: *Harness) void {
        _ = self.future.cancel(self.io) catch {};
        self.voter.deinit();
        self.mailbox.deinit();
        self.batcher.deinit();
        self.log.deinit();
        self.fixture.deinit(gpa);
    }

    /// Receives voter messages until a verified certificate arrives.
    fn next_certificate(self: *Harness) !VoterMessage {
        for (0..8) |_| {
            const message = (try self.voter.recv()) orelse return error.Closed;
            if (message == .verified) return message;
        }
        return error.NoCertificate;
    }
};

test "batcher builds a notarization from network votes" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start(io);
            defer harness.stop();
            const fixture = &harness.fixture;
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            // A garbage payload is blocked; the sender is still a participant.
            try harness.votes.deliver(fixture.participants[3], try gpa.dupe(u8, "garbage"));
            for (1..4) |signer| {
                const bytes = try notarize_bytes(fixture, signer, 1);
                try harness.votes.deliver(fixture.participants[signer], bytes);
            }
            const message = try harness.next_certificate();
            defer VoterMessage.discard(message);
            const certificate = &message.verified.certificate;
            try testing.expect(certificate.* == .notarization);
            try testing.expect(certificate.notarization.proposal.eql(proposal(1)));
            try testing.expectEqual(1, harness.log.blocked.items.len);
            try testing.expect(harness.log.blocked.items[0].eql(fixture.participants[3]));
            try testing.expectEqual(3, harness.log.reported);
        }
    };
    try run_deterministic(Root.run);
}

fn nullification_bytes(fixture: anytype, epoch: u64, view: u64) ![]u8 {
    const Nullify = types.Nullify(Scheme);
    const round: consensus_types.Round = .new(.new(epoch), .new(view));
    var votes: [3]Nullify = undefined;
    for (&votes, 0..) |*vote, signer| {
        vote.* = (try Nullify.sign(gpa, &fixture.schemes[signer], round)).?;
    }
    const Nullification = types.Nullification(Scheme);
    const scheme = &fixture.schemes[0];
    var nullification = try Nullification.from_votes(gpa, scheme, &votes, parallel.sequential);
    const certificate: types.Certificate(Scheme, Digest) = .{ .nullification = nullification };
    defer nullification.deinit(gpa);
    return codec.encode(types.Certificate(Scheme, Digest), gpa, certificate);
}

test "batcher forwards verified certificates and blocks foreign epochs" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start(io);
            defer harness.stop();
            const fixture = &harness.fixture;
            try harness.mailbox.update(.new(2), .init(2), .zero(), null);
            const foreign = try nullification_bytes(fixture, 1, 2);
            try harness.certificates.deliver(fixture.participants[1], foreign);
            const bytes = try nullification_bytes(fixture, 0, 2);
            try harness.certificates.deliver(fixture.participants[2], bytes);
            const message = try harness.next_certificate();
            defer VoterMessage.discard(message);
            const certificate = &message.verified.certificate;
            try testing.expect(certificate.* == .nullification);
            try testing.expectEqual(2, certificate.view().get());
            try testing.expectEqual(1, harness.log.blocked.items.len);
            try testing.expect(harness.log.blocked.items[0].eql(fixture.participants[1]));
        }
    };
    try run_deterministic(Root.run);
}

/// Whether `registry`'s exposition has `latest_vote{peer="<participant>"} <view>`.
fn has_latest_vote(registry: *runtime.telemetry.metrics.Registry, peer: Key, view: u64) !bool {
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    var buffer: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "latest_vote{{peer=\"{f}\"}} {d}", .{ peer, view });
    return std.mem.indexOf(u8, text, line) != null;
}

// commonware `latest_vote_metric_tracking`: every participant's latest vote starts at 0,
// rises to the view of each accepted vote (also after the certificate formed), and never
// falls back on a vote for a lower view.
test "batcher tracks each peer's latest vote view" {
    const Root = struct {
        fn run(io: Io) !void {
            const metrics = runtime.telemetry.metrics;
            var registry = metrics.Registry.init(gpa);
            defer registry.deinit();
            var harness: Harness = undefined;
            try harness.start_scoped(io, metrics.Scope.init(&registry).child("batcher"));
            defer harness.stop();
            const fixture = &harness.fixture;
            for (fixture.participants) |participant| {
                try testing.expect(try has_latest_vote(&registry, participant, 0));
            }
            try harness.mailbox.update(.new(5), .init(1), .zero(), null);
            // The update lands before the votes, which view 0 would not admit.
            try io.sleep(.fromMilliseconds(50), .awake);
            const value: types.Proposal(Digest) = .init(.new(.new(0), .new(5)), .zero(), .fill(5));
            for (1..3) |signer| {
                const bytes = try notarize_proposal_bytes(fixture, signer, value);
                try harness.votes.deliver(fixture.participants[signer], bytes);
            }
            const Notarize = types.Notarize(Scheme, Digest);
            const own = (try Notarize.sign(gpa, &fixture.schemes[0], value)).?;
            try harness.mailbox.constructed(.{ .notarize = own });
            const message = try harness.next_certificate();
            VoterMessage.discard(message);
            try testing.expect(try has_latest_vote(&registry, fixture.participants[1], 5));
            try testing.expect(try has_latest_vote(&registry, fixture.participants[2], 5));
            try testing.expect(try has_latest_vote(&registry, fixture.participants[3], 0));
            // A vote after the quorum is still tracked.
            const late = try notarize_proposal_bytes(fixture, 3, value);
            try harness.votes.deliver(fixture.participants[3], late);
            try io.sleep(.fromMilliseconds(100), .awake);
            try testing.expect(try has_latest_vote(&registry, fixture.participants[3], 5));
            // A lower view does not lower the gauge.
            const lower: types.Proposal(Digest) = .init(.new(.new(0), .new(3)), .zero(), .fill(3));
            const stale = try notarize_proposal_bytes(fixture, 1, lower);
            try harness.votes.deliver(fixture.participants[1], stale);
            try io.sleep(.fromMilliseconds(100), .awake);
            try testing.expect(try has_latest_vote(&registry, fixture.participants[1], 5));
            try testing.expectEqual(0, harness.log.blocked.items.len);
        }
    };
    try run_deterministic(Root.run);
}

fn notarization_bytes(fixture: anytype, value: types.Proposal(Digest)) ![]u8 {
    return notarization_bytes_as(fixture, value, value);
}

/// A notarization signed over `value` but carrying `shown` (tampered when they differ).
fn notarization_bytes_as(
    fixture: anytype,
    value: types.Proposal(Digest),
    shown: types.Proposal(Digest),
) ![]u8 {
    const Notarize = types.Notarize(Scheme, Digest);
    var votes: [3]Notarize = undefined;
    for (&votes, 0..) |*vote, signer| {
        vote.* = (try Notarize.sign(gpa, &fixture.schemes[signer], value)).?;
    }
    const scheme = &fixture.schemes[0];
    const Notarization = types.Notarization(Scheme, Digest);
    var notarization = try Notarization.from_votes(gpa, scheme, &votes, parallel.sequential);
    defer notarization.deinit(gpa);
    notarization.proposal = shown;
    const certificate: types.Certificate(Scheme, Digest) = .{ .notarization = notarization };
    return codec.encode(types.Certificate(Scheme, Digest), gpa, certificate);
}

// commonware `test_future_notarization_without_leader_does_not_panic`: a valid notarization
// beyond the admission window makes a round with a proposal but no leader; the batcher
// forwards the certificate and its proposal, and keeps processing certificates.
test "batcher forwards a future notarization's proposal without a leader" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start(io);
            defer harness.stop();
            const fixture = &harness.fixture;
            try harness.mailbox.update(.new(1), .init(0), .zero(), null);
            const future: types.Proposal(Digest) = .init(.new(.new(0), .new(3)), .zero(), .fill(9));
            const bytes = try notarization_bytes(fixture, future);
            try harness.certificates.deliver(fixture.participants[1], bytes);
            const verified = (try harness.voter.recv()).?;
            defer VoterMessage.discard(verified);
            try testing.expect(verified == .verified);
            try testing.expectEqual(3, verified.verified.certificate.view().get());
            const forwarded = (try harness.voter.recv()).?;
            defer VoterMessage.discard(forwarded);
            try testing.expect(forwarded == .proposal);
            try testing.expect(forwarded.proposal.eql(future));
            const nullification = try nullification_bytes(fixture, 0, 1);
            try harness.certificates.deliver(fixture.participants[2], nullification);
            const message = try harness.next_certificate();
            defer VoterMessage.discard(message);
            try testing.expect(message.verified.certificate == .nullification);
            try testing.expectEqual(1, message.verified.certificate.view().get());
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_invalid_certificate_blocks_sender`: a valid certificate blocks no one; a
// notarization whose proposal was swapped no longer verifies, and its sender is blocked.
test "batcher blocks the sender of a tampered certificate" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start(io);
            defer harness.stop();
            const fixture = &harness.fixture;
            try harness.mailbox.update(.new(1), .init(0), .zero(), null);
            const valid = try nullification_bytes(fixture, 0, 1);
            try harness.certificates.deliver(fixture.participants[1], valid);
            const first = try harness.next_certificate();
            VoterMessage.discard(first);
            try testing.expectEqual(0, harness.log.blocked.items.len);
            // A notarization of one proposal that carries another.
            const signed = proposal(1);
            const swapped: types.Proposal(Digest) = .init(signed.round, .zero(), .fill(0xee));
            const tampered = try notarization_bytes_as(fixture, signed, swapped);
            try harness.certificates.deliver(fixture.participants[2], tampered);
            // Certificates are processed in order: once the next one arrives, the tampered
            // one was judged.
            const honest = try notarization_bytes(fixture, signed);
            try harness.certificates.deliver(fixture.participants[3], honest);
            const next = try harness.next_certificate();
            VoterMessage.discard(next);
            try testing.expectEqual(1, harness.log.blocked.items.len);
            try testing.expect(harness.log.blocked.items[0].eql(fixture.participants[2]));
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_votes_and_certificate_deduplication`: the leader's vote forwards its
// proposal, a network notarization is forwarded once, and the vote that would complete the
// quorum afterwards forms no second notarization.
test "batcher forwards one notarization when votes complete a certified quorum" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start(io);
            defer harness.stop();
            const fixture = &harness.fixture;
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            const value = proposal(1);
            try harness.votes.deliver(fixture.participants[1], try notarize_bytes(fixture, 1, 1));
            const Notarize = types.Notarize(Scheme, Digest);
            const ours = (try Notarize.sign(gpa, &fixture.schemes[0], value)).?;
            try harness.mailbox.constructed(.{ .notarize = ours });
            const forwarded = (try harness.voter.recv()).?;
            defer VoterMessage.discard(forwarded);
            try testing.expect(forwarded == .proposal);
            try testing.expect(forwarded.proposal.eql(value));
            const certificate = try notarization_bytes(fixture, value);
            try harness.certificates.deliver(fixture.participants[3], certificate);
            const verified = try harness.next_certificate();
            VoterMessage.discard(verified);
            try harness.votes.deliver(fixture.participants[2], try notarize_bytes(fixture, 2, 1));
            try io.sleep(.fromMilliseconds(150), .awake);
            try testing.expectError(error.Empty, harness.voter.try_recv());
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_votes_skipped_for_finalized_views`: votes above the finalized view
// assemble, and votes at the finalized view are skipped once it advances.
test "batcher skips votes for finalized views" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start(io);
            defer harness.stop();
            const fixture = &harness.fixture;
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            for (1..3) |signer| {
                const bytes = try notarize_bytes(fixture, signer, 1);
                try harness.votes.deliver(fixture.participants[signer], bytes);
            }
            const Notarize = types.Notarize(Scheme, Digest);
            const ours = (try Notarize.sign(gpa, &fixture.schemes[0], proposal(1))).?;
            try harness.mailbox.constructed(.{ .notarize = ours });
            const first = try harness.next_certificate();
            defer VoterMessage.discard(first);
            try testing.expectEqual(1, first.verified.certificate.view().get());
            // View 2 is finalized: its votes form nothing.
            try harness.mailbox.update(.new(3), .init(1), .new(2), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            for (1..3) |signer| {
                const bytes = try notarize_bytes(fixture, signer, 2);
                try harness.votes.deliver(fixture.participants[signer], bytes);
            }
            const late = (try Notarize.sign(gpa, &fixture.schemes[0], proposal(2))).?;
            try harness.mailbox.constructed(.{ .notarize = late });
            try io.sleep(.fromMilliseconds(150), .awake);
            while (harness.voter.try_recv()) |message| {
                defer VoterMessage.discard(message);
                try testing.expect(message != .verified);
            } else |err| try testing.expectEqual(error.Empty, err);
        }
    };
    try run_deterministic(Root.run);
}

fn vote_bytes(fixture: anytype, comptime kind: enum { notarize, finalize }, signer: usize) ![]u8 {
    const Vote = types.Vote(Scheme, Digest);
    const scheme = &fixture.schemes[signer];
    const value = proposal(1);
    const Notarize = types.Notarize(Scheme, Digest);
    const Finalize = types.Finalize(Scheme, Digest);
    const vote: Vote = switch (kind) {
        .notarize => .{ .notarize = (try Notarize.sign(gpa, scheme, value)).? },
        .finalize => .{ .finalize = (try Finalize.sign(gpa, scheme, value)).? },
    };
    return codec.encode(Vote, gpa, vote);
}

// commonware `test_duplicate_notarize_with_different_attestation_blocks_peer` and
// `test_duplicate_finalize_with_different_attestation_blocks_peer`: an exact duplicate is
// ignored, but the same vote with another signature blocks its sender.
test "batcher blocks a peer that resends a vote with another attestation" {
    const Root = struct {
        fn run(io: Io) !void {
            inline for (.{ .notarize, .finalize }) |kind| {
                var harness: Harness = undefined;
                try harness.start(io);
                defer harness.stop();
                const fixture = &harness.fixture;
                const peer = fixture.participants[1];
                try harness.mailbox.update(.new(1), .init(1), .zero(), null);
                try harness.votes.deliver(peer, try vote_bytes(fixture, kind, 1));
                try io.sleep(.fromMilliseconds(50), .awake);
                try harness.votes.deliver(peer, try vote_bytes(fixture, kind, 1));
                try io.sleep(.fromMilliseconds(50), .awake);
                try testing.expectEqual(0, harness.log.blocked.items.len);
                try harness.votes.deliver(peer, try vote_bytes(fixture, kind, 2));
                try io.sleep(.fromMilliseconds(50), .awake);
                try testing.expectEqual(1, harness.log.blocked.items.len);
                try testing.expect(harness.log.blocked.items[0].eql(peer));
            }
        }
    };
    try run_deterministic(Root.run);
}

fn nullify_bytes(fixture: anytype, signer: usize, view: u64) ![]u8 {
    const round: consensus_types.Round = .new(.new(0), .new(view));
    const vote = (try types.Nullify(Scheme).sign(gpa, &fixture.schemes[signer], round)).?;
    return codec.encode(types.Vote(Scheme, Digest), gpa, .{ .nullify = vote });
}

// commonware `test_network_votes_below_current_are_not_assembled`: votes for an untracked
// view below the current one are reported, but even a quorum that needs no proposal
// assembles nothing there.
test "batcher reports votes below the current view without assembling them" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start(io);
            defer harness.stop();
            const fixture = &harness.fixture;
            try harness.mailbox.update(.new(10), .init(0), .zero(), null);
            // The update and the votes arrive on different channels: let it land first.
            try io.sleep(.fromMilliseconds(10), .awake);
            for (1..4) |signer| {
                const bytes = try nullify_bytes(fixture, signer, 5);
                try harness.votes.deliver(fixture.participants[signer], bytes);
            }
            try io.sleep(.fromMilliseconds(50), .awake);
            try testing.expectEqual(3, harness.log.count(.nullify, 5));
            while (harness.voter.try_recv()) |message| {
                defer VoterMessage.discard(message);
                try testing.expect(message != .verified);
            } else |err| try testing.expectEqual(error.Empty, err);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_historical_votes_detect_conflicts_below_current`: with historical votes
// kept, conflicting votes below the current view still make evidence and block the sender.
test "batcher keeping historical votes detects conflicts below the current view" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_historical(io);
            defer harness.stop();
            const fixture = &harness.fixture;
            try harness.mailbox.update(.new(10), .init(0), .zero(), null);
            // The update and the votes arrive on different channels: let it land first.
            try io.sleep(.fromMilliseconds(10), .awake);
            const round: consensus_types.Round = .new(.new(0), .new(5));
            for ([_]u8{ 1, 2 }) |payload| {
                const value: types.Proposal(Digest) = .init(round, .new(4), .fill(payload));
                const bytes = try notarize_proposal_bytes(fixture, 1, value);
                try harness.votes.deliver(fixture.participants[1], bytes);
                try io.sleep(.fromMilliseconds(10), .awake);
            }
            try testing.expectEqual(1, harness.log.blocked.items.len);
            try testing.expect(harness.log.blocked.items[0].eql(fixture.participants[1]));
            try testing.expectEqual(1, harness.log.count(.conflicting_notarize, 5));
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_term_entry_assembles_buffered_lane_quorum`: with terms of 10 views and two
// optimistic views, votes for next-term lane view 14 buffered at view 9 assemble once the
// node enters the next term.
test "batcher assembles a buffered next-term lane quorum on term entry" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, .{ .term_length = 10, .optimistic_views = 2 });
            defer harness.stop();
            const fixture = &harness.fixture;
            try harness.mailbox.update(.new(9), .init(1), .zero(), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            const at: consensus_types.Round = .new(.new(0), .new(14));
            const lane: types.Proposal(Digest) = .init(at, .new(13), .fill(14));
            for (1..4) |signer| {
                const bytes = try notarize_proposal_bytes(fixture, signer, lane);
                try harness.votes.deliver(fixture.participants[signer], bytes);
            }
            try io.sleep(.fromMilliseconds(50), .awake);
            try testing.expectError(error.Empty, harness.voter.try_recv());
            try harness.mailbox.update(.new(11), .init(2), .zero(), null);
            try io.sleep(.fromMilliseconds(50), .awake);
            var proposed = false;
            var notarized = false;
            while (harness.voter.try_recv()) |message| {
                defer VoterMessage.discard(message);
                switch (message) {
                    .proposal => |forwarded| {
                        try testing.expect(forwarded.eql(lane));
                        proposed = true;
                    },
                    .verified => |verified| if (verified.certificate == .notarization) {
                        try testing.expect(verified.certificate.notarization.proposal.eql(lane));
                        notarized = true;
                    },
                    else => {},
                }
            } else |err| try testing.expectEqual(error.Empty, err);
            try testing.expect(proposed and notarized);
        }
    };
    try run_deterministic(Root.run);
}
