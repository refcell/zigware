//! Tests for the batcher actor on the deterministic runtime: network votes become a
//! certificate for the voter, and invalid traffic is blocked.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const assert = std.debug.assert;
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
const TimeoutReason = @import("../../metrics.zig").TimeoutReason;
const config_mod = @import("../../config.zig");

pub const Digest = cryptography.Sha256.Digest;
pub const Scheme = ed25519.Scheme(Digest);
pub const Key = cryptography.ed25519.PublicKey;
const ActivityType = types.Activity(Scheme, Digest);
const NetMessage = p2p.Message(Key);
pub const VoterMessage = voter_ingress.Message(Scheme, Digest);
const gpa = testing.allocator;

pub const Log = struct {
    blocked: std.ArrayList(Key) = .empty,
    reported: u32 = 0,
    /// Each reported activity's kind and view, in order.
    activities: std.ArrayList(Seen) = .empty,

    /// Each forward the relay was asked to send (commonware `MockRelay::broadcasts`).
    forwards: std.ArrayList(Forward) = .empty,

    const Seen = struct { tag: std.meta.Tag(ActivityType), view: u64 };
    pub const Forward = struct { digest: Digest, view: u64, peers: []Key };

    pub fn deinit(self: *Log) void {
        self.blocked.deinit(gpa);
        self.activities.deinit(gpa);
        for (self.forwards.items) |forward| gpa.free(forward.peers);
        self.forwards.deinit(gpa);
    }

    pub fn count(self: *const Log, tag: std.meta.Tag(ActivityType), view: u64) usize {
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
    log: *Log,
    pub fn broadcast(self: Relay, digest: Digest, plan: lookahead.Plan(Key)) actor.Feedback {
        const forward = switch (plan) {
            .forward => |forward| forward,
            .prepare, .propose => return .ok,
        };
        const peers = gpa.dupe(Key, forward.recipients.some) catch @panic("out of memory");
        const entry: Log.Forward = .{
            .digest = digest,
            .view = forward.round.view.get(),
            .peers = peers,
        };
        self.log.forwards.append(gpa, entry) catch @panic("out of memory");
        return .ok;
    }
};

/// A network receiver fed by the test.
pub const NetReceiver = struct {
    buffer: [16]NetMessage = undefined,
    queue: Io.Queue(NetMessage) = undefined,
    io: Io,

    pub fn init(self: *NetReceiver, io: Io) void {
        self.* = .{ .io = io };
        self.queue = .init(&self.buffer);
    }

    pub fn deliver(self: *NetReceiver, peer: Key, payload: []u8) !void {
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
pub const P = Params(Scheme, Digest, Blocker, Reporter, Relay, NetReceiver);
pub const Batcher = actor_mod.Actor(P);

pub fn proposal(view: u64) types.Proposal(Digest) {
    return .init(.new(.new(0), .new(view)), .new(view - 1), .fill(@intCast(view)));
}

pub fn config(scheme: *const Scheme, log: *Log) actor_mod.Config(P) {
    return .{
        .scheme = scheme,
        .blocker = .{ .log = log },
        .reporter = .{ .log = log },
        .track_historical_votes = false,
        .relay = .{ .log = log },
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

pub fn run_deterministic(comptime function: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
}

pub fn notarize_bytes(fixture: anytype, signer: usize, view: u64) ![]u8 {
    return notarize_proposal_bytes(fixture, signer, proposal(view));
}

pub fn notarize_proposal_bytes(
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
pub const Harness = struct {
    io: Io,
    fixture: cryptography.certificate.mocks.Fixture(Scheme),
    /// Participant 0's member-only scheme, when `Options.member_only` is set.
    local: ?Scheme = null,
    log: Log = .{},
    batcher: Batcher = undefined,
    mailbox: Batcher.Mailbox = undefined,
    voter: actor.mailbox.Receiver(VoterMessage) = undefined,
    votes: NetReceiver = undefined,
    certificates: NetReceiver = undefined,
    future: Io.Future(RunResult) = undefined,

    const RunResult = @typeInfo(@TypeOf(Batcher.run)).@"fn".return_type.?;

    pub fn start(self: *Harness, io: Io) !void {
        return self.start_scoped(io, null);
    }

    /// Starts with historical votes kept (commonware `track_historical_votes`).
    pub fn start_historical(self: *Harness, io: Io) !void {
        return self.start_with(io, null, .{ .track_historical_votes = true });
    }

    pub const Options = struct {
        track_historical_votes: bool = false,
        term_length: u32 = 1,
        optimistic_views: u64 = 0,
        participants: u32 = 4,
        /// Enables skipping with this timeout (commonware `SkipPolicy::Enabled`).
        skip_timeout_s: ?u64 = null,
        forward: config_mod.ForwardPolicy = .disabled,
        /// Participant 0 keeps its membership but cannot sign (commonware `Scheme::member`).
        member_only: bool = false,
        view_retention: u64 = 10,
        /// The view the batcher restores from (commonware `floor`).
        floor: u64 = 0,
    };

    /// Starts with the batcher's metrics registered under `scope`, if any.
    pub fn start_scoped(self: *Harness, io: Io, scope: ?runtime.telemetry.metrics.Scope) !void {
        return self.start_with(io, scope, .{});
    }

    pub fn start_with(
        self: *Harness,
        io: Io,
        scope: ?runtime.telemetry.metrics.Scope,
        options: Options,
    ) !void {
        var rng = utils.rng.test_rng();
        assert(options.participants >= 4);
        const n = options.participants;
        const fixture = try ed25519.fixture(Digest, gpa, &rng, "batcher", n);
        self.* = .{ .io = io, .fixture = fixture };
        if (options.member_only) {
            const set = try fixture.schemes[0].participants().clone(gpa);
            self.local = (try Scheme.member(gpa, "batcher", set, fixture.participants[0])).?;
        }
        const scheme = if (self.local) |*local| local else &fixture.schemes[0];
        var cfg = config(scheme, &self.log);
        cfg.scope = scope;
        if (options.skip_timeout_s) |seconds| {
            cfg.skip = .{ .enabled = .{ .timeout = .from_secs(seconds) } };
        }
        cfg.track_historical_votes = options.track_historical_votes;
        cfg.forward = options.forward;
        cfg.view_retention = .new(options.view_retention);
        cfg.floor = .new(options.floor);
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

    pub fn stop(self: *Harness) void {
        _ = self.future.cancel(self.io) catch {};
        self.voter.deinit();
        self.mailbox.deinit();
        self.batcher.deinit();
        self.log.deinit();
        if (self.local) |*local| local.deinit(gpa);
        self.fixture.deinit(gpa);
    }

    /// Receives voter messages until a verified certificate arrives.
    pub fn next_certificate(self: *Harness) !VoterMessage {
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

pub fn nullification_bytes(fixture: anytype, epoch: u64, view: u64) ![]u8 {
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
pub fn has_latest_vote(registry: *runtime.telemetry.metrics.Registry, peer: Key, view: u64) !bool {
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

pub fn notarization_bytes(fixture: anytype, value: types.Proposal(Digest)) ![]u8 {
    return notarization_bytes_as(fixture, value, value);
}

/// A notarization signed over `value` but carrying `shown` (tampered when they differ).
pub fn notarization_bytes_as(
    fixture: anytype,
    value: types.Proposal(Digest),
    shown: types.Proposal(Digest),
) ![]u8 {
    const Notarize = types.Notarize(Scheme, Digest);
    const n: u32 = @intCast(fixture.participants.len);
    const signers = n - (n - 1) / 3;
    var votes: [8]Notarize = undefined;
    assert(signers <= votes.len);
    for (votes[0..signers], 0..) |*vote, signer| {
        vote.* = (try Notarize.sign(gpa, &fixture.schemes[signer], value)).?;
    }
    const scheme = &fixture.schemes[0];
    const Notarization = types.Notarization(Scheme, Digest);
    const strategy = parallel.sequential;
    var notarization = try Notarization.from_votes(gpa, scheme, votes[0..signers], strategy);
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

pub fn vote_bytes(
    fixture: anytype,
    comptime kind: enum { notarize, finalize },
    signer: usize,
) ![]u8 {
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

pub fn nullify_bytes(fixture: anytype, signer: usize, view: u64) ![]u8 {
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

/// Fails if a voter timeout arrives within 50 ms (commonware `expect_no_timeout`).
pub fn expect_no_timeout(harness: *Harness) !void {
    try harness.io.sleep(.fromMilliseconds(50), .awake);
    while (harness.voter.try_recv()) |message| {
        defer VoterMessage.discard(message);
        try testing.expect(message != .timeout);
    } else |err| try testing.expectEqual(error.Empty, err);
}

/// Expects a voter timeout for `view` with `reason` within 100 ms (commonware
/// `expect_timeout`): the first timeout received must match.
pub fn expect_timeout(harness: *Harness, view: u64, reason: TimeoutReason) !void {
    try harness.io.sleep(.fromMilliseconds(100), .awake);
    while (harness.voter.try_recv()) |message| {
        defer VoterMessage.discard(message);
        if (message != .timeout) continue;
        try testing.expectEqual(view, message.timeout.round.view.get());
        try testing.expectEqual(reason, message.timeout.reason);
        return;
    } else |err| try testing.expectEqual(error.Empty, err);
    return error.NoTimeout;
}

/// Delivers a nullify for `view` from each signer in `signers`.
pub fn deliver_nullifies(harness: *Harness, signers: []const usize, view: u64) !void {
    assert(signers.len > 0);
    for (signers) |signer| {
        const bytes = try nullify_bytes(&harness.fixture, signer, view);
        try harness.votes.deliver(harness.fixture.participants[signer], bytes);
    }
}

/// Our own nullify for `view`, handed to the batcher as constructed.
pub fn construct_nullify(harness: *Harness, view: u64) !void {
    const round: consensus_types.Round = .new(.new(0), .new(view));
    const vote = (try types.Nullify(Scheme).sign(gpa, &harness.fixture.schemes[0], round)).?;
    try harness.mailbox.constructed(.{ .nullify = vote });
}

pub const skip_options: Harness.Options = .{ .participants = 5, .skip_timeout_s = 5 };

// commonware `test_leader_activity_detection`: leaders stay active while the network is
// quiet (fewer than a quorum recently active), and a local leader never gets an
// inactivity hint even once peers are active.
test "batcher fails open on leader activity until a quorum is active" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, skip_options);
            defer harness.stop();
            for (1..5) |view| try harness.mailbox.update(.new(view), .init(1), .zero(), null);
            try expect_no_timeout(&harness);
            try harness.mailbox.update(.new(5), .init(1), .zero(), null);
            try expect_no_timeout(&harness);
            try harness.mailbox.update(.new(100), .init(1), .zero(), null);
            try expect_no_timeout(&harness);
            try deliver_nullifies(&harness, &.{ 1, 2, 3, 4 }, 99);
            try io.sleep(.fromMilliseconds(50), .awake);
            try harness.mailbox.update(.new(101), .init(0), .zero(), null);
            try expect_no_timeout(&harness);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_leader_inactivity_reported_after_quorum_activity`: once we and three
// peers are active, a silent leader gets an inactivity hint on the next view.
test "batcher reports an inactive leader after quorum activity" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, skip_options);
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try expect_no_timeout(&harness);
            try construct_nullify(&harness, 1);
            try deliver_nullifies(&harness, &.{ 2, 3, 4 }, 1);
            try io.sleep(.fromMilliseconds(50), .awake);
            try harness.mailbox.update(.new(2), .init(1), .zero(), null);
            try expect_timeout(&harness, 2, .inactivity);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_leader_nullify_after_inactivity_still_fast_paths`: an inactivity hint
// does not suppress the leader's own nullify for the same view.
test "batcher fast-paths a leader nullify after an inactivity hint" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, skip_options);
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            try deliver_nullifies(&harness, &.{ 2, 3, 4 }, 1);
            try io.sleep(.fromMilliseconds(50), .awake);
            try harness.mailbox.update(.new(2), .init(1), .zero(), null);
            try expect_timeout(&harness, 2, .inactivity);
            try deliver_nullifies(&harness, &.{1}, 2);
            try expect_timeout(&harness, 2, .leader_nullify);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_leader_nullify_marks_active`: a leader's nullify for a prior view
// counts as activity, so no inactivity hint follows.
test "batcher counts a leader nullify as activity" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, skip_options);
            defer harness.stop();
            for (1..6) |view| try harness.mailbox.update(.new(view), .init(1), .zero(), null);
            try expect_no_timeout(&harness);
            try construct_nullify(&harness, 4);
            try deliver_nullifies(&harness, &.{ 2, 3, 4 }, 5);
            try io.sleep(.fromMilliseconds(50), .awake);
            try deliver_nullifies(&harness, &.{1}, 4);
            try io.sleep(.fromMilliseconds(50), .awake);
            try harness.mailbox.update(.new(6), .init(1), .zero(), null);
            try expect_no_timeout(&harness);
        }
    };
    try run_deterministic(Root.run);
}

/// A finalization of `value` signed by the first `signers` participants.
pub fn finalization_bytes(fixture: anytype, value: types.Proposal(Digest), signers: usize) ![]u8 {
    const Finalize = types.Finalize(Scheme, Digest);
    var votes: [8]Finalize = undefined;
    assert(signers <= votes.len);
    for (votes[0..signers], 0..) |*vote, signer| {
        vote.* = (try Finalize.sign(gpa, &fixture.schemes[signer], value)).?;
    }
    const scheme = &fixture.schemes[0];
    const Finalization = types.Finalization(Scheme, Digest);
    const strategy = parallel.sequential;
    var finalization = try Finalization.from_votes(gpa, scheme, votes[0..signers], strategy);
    defer finalization.deinit(gpa);
    const certificate: types.Certificate(Scheme, Digest) = .{ .finalization = finalization };
    return codec.encode(types.Certificate(Scheme, Digest), gpa, certificate);
}

// commonware `test_leader_certificate_marks_active`: a certificate relayed by the leader
// counts as activity, so no inactivity hint follows.
test "batcher counts a leader's relayed certificate as activity" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, skip_options);
            defer harness.stop();
            for (1..5) |view| try harness.mailbox.update(.new(view), .init(1), .zero(), null);
            try expect_no_timeout(&harness);
            try harness.mailbox.update(.new(5), .init(1), .zero(), null);
            try expect_no_timeout(&harness);
            try construct_nullify(&harness, 5);
            try deliver_nullifies(&harness, &.{ 2, 3, 4 }, 5);
            const at: consensus_types.Round = .new(.new(0), .new(5));
            const value: types.Proposal(Digest) = .init(at, .zero(), .fill(5));
            const bytes = try finalization_bytes(&harness.fixture, value, 4);
            try harness.certificates.deliver(harness.fixture.participants[1], bytes);
            const message = try harness.next_certificate();
            defer VoterMessage.discard(message);
            try testing.expect(message.verified.certificate == .finalization);
            try testing.expectEqual(5, message.verified.certificate.view().get());
            try harness.mailbox.update(.new(6), .init(1), .zero(), null);
            try expect_no_timeout(&harness);
        }
    };
    try run_deterministic(Root.run);
}

/// commonware `leader_nullify_on_view_entry`: a leader nullify buffered for view 2 while
/// at view 1 is hinted on entering view 2 only when skipping is enabled.
fn leader_nullify_on_view_entry(io: Io, skip_timeout_s: ?u64) !void {
    var harness: Harness = undefined;
    const options: Harness.Options = .{ .participants = 5, .skip_timeout_s = skip_timeout_s };
    try harness.start_with(io, null, options);
    defer harness.stop();
    try harness.mailbox.update(.new(1), .init(1), .zero(), null);
    try io.sleep(.fromMilliseconds(10), .awake);
    try deliver_nullifies(&harness, &.{2}, 2);
    try io.sleep(.fromMilliseconds(10), .awake);
    try harness.mailbox.update(.new(2), .init(2), .zero(), null);
    if (skip_timeout_s != null) {
        try expect_timeout(&harness, 2, .leader_nullify);
    } else {
        try expect_no_timeout(&harness);
    }
}

// commonware `test_leader_nullify_expire_on_view_entry`.
test "batcher hints a buffered leader nullify on view entry" {
    const Root = struct {
        fn run(io: Io) !void {
            try leader_nullify_on_view_entry(io, 5);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_disabled_skip_policy_ignores_leader_nullify_hint`.
test "batcher with skipping disabled ignores a buffered leader nullify" {
    const Root = struct {
        fn run(io: Io) !void {
            try leader_nullify_on_view_entry(io, null);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_leader_nullify_wrong_view_no_expire`: the current leader's nullify for
// another view is no fast-path hint.
test "batcher ignores a leader nullify for another view" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, skip_options);
            defer harness.stop();
            try harness.mailbox.update(.new(2), .init(2), .zero(), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            try deliver_nullifies(&harness, &.{2}, 3);
            try expect_no_timeout(&harness);
        }
    };
    try run_deterministic(Root.run);
}

/// A proposal at `view` with parent `parent` and payload byte `fill`.
fn proposal_at(view: u64, parent: u64, fill: u8) types.Proposal(Digest) {
    return .init(.new(.new(0), .new(view)), .new(parent), .fill(fill));
}

/// Delivers a notarize for `value` from each signer in `signers`.
fn deliver_notarizes(
    harness: *Harness,
    signers: []const usize,
    value: types.Proposal(Digest),
) !void {
    assert(signers.len > 0);
    for (signers) |signer| {
        const bytes = try notarize_proposal_bytes(&harness.fixture, signer, value);
        try harness.votes.deliver(harness.fixture.participants[signer], bytes);
    }
}

/// Our own notarize for `value`, handed to the batcher as constructed.
fn construct_notarize(harness: *Harness, value: types.Proposal(Digest)) !void {
    const Notarize = types.Notarize(Scheme, Digest);
    const vote = (try Notarize.sign(gpa, &harness.fixture.schemes[0], value)).?;
    try harness.mailbox.constructed(.{ .notarize = vote });
}

/// Waits for a notarization of `value`, then checks nothing was forwarded yet.
fn expect_notarization_unforwarded(harness: *Harness, value: types.Proposal(Digest)) !void {
    const message = try harness.next_certificate();
    defer VoterMessage.discard(message);
    try testing.expect(message.verified.certificate == .notarization);
    try testing.expect(message.verified.certificate.notarization.proposal.eql(value));
    try testing.expectEqual(0, harness.log.forwards.items.len);
}

/// Advances to `view` under `leader` with `value` forwardable, then expects one forward of
/// `value` to exactly `targets` (none when empty).
fn expect_forward_on_advance(
    harness: *Harness,
    view: u64,
    leader: u32,
    value: types.Proposal(Digest),
    targets: []const usize,
) !void {
    try harness.mailbox.update(.new(view), .init(leader), .zero(), value);
    try harness.io.sleep(.fromMilliseconds(50), .awake);
    const forwards = harness.log.forwards.items;
    if (targets.len == 0) return testing.expectEqual(0, forwards.len);
    try testing.expectEqual(1, forwards.len);
    try testing.expect(std.mem.eql(u8, &forwards[0].digest.bytes, &value.payload.bytes));
    try testing.expectEqual(value.view().get(), forwards[0].view);
    try testing.expectEqual(targets.len, forwards[0].peers.len);
    for (targets, forwards[0].peers) |target, peer| {
        try testing.expect(peer.eql(harness.fixture.participants[target]));
    }
}

const forward_voters: Harness.Options = .{ .participants = 5, .forward = .silent_voters };

// commonware `test_forward_emitted_on_view_advance_with_forwardable_proposal`: a
// notarization alone forwards nothing; advancing with its proposal forwardable sends it
// to the one participant that did not vote.
test "batcher forwards a proposal to silent voters on view advance" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, forward_voters);
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            const value = proposal_at(1, 0, 1);
            try deliver_notarizes(&harness, &.{ 1, 2, 3 }, value);
            try construct_notarize(&harness, value);
            try expect_notarization_unforwarded(&harness, value);
            try expect_forward_on_advance(&harness, 2, 2, value, &.{4});
        }
    };
    try run_deterministic(Root.run);
}

/// commonware `silent_leader_forwarding_respects_missing_vote`: `silent_leader` forwards
/// only to the next leader, and only when its matching vote was not observed.
fn silent_leader_forwarding(io: Io, leader_voted: bool) !void {
    var harness: Harness = undefined;
    try harness.start_with(io, null, .{ .participants = 5, .forward = .silent_leader });
    defer harness.stop();
    try harness.mailbox.update(.new(1), .init(1), .zero(), null);
    try io.sleep(.fromMilliseconds(10), .awake);
    const value = proposal_at(1, 0, 7);
    const voters: []const usize = if (leader_voted) &.{ 1, 2, 3 } else &.{ 1, 3, 4 };
    try deliver_notarizes(&harness, voters, value);
    try construct_notarize(&harness, value);
    try expect_notarization_unforwarded(&harness, value);
    const targets: []const usize = if (leader_voted) &.{} else &.{2};
    try expect_forward_on_advance(&harness, 2, 2, value, targets);
}

// commonware `test_silent_leader_forwarding_targets_missing_leader`.
test "batcher forwards to a silent next leader" {
    const Root = struct {
        fn run(io: Io) !void {
            try silent_leader_forwarding(io, false);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_silent_leader_forwarding_skips_observed_leader`.
test "batcher skips forwarding to a next leader that voted" {
    const Root = struct {
        fn run(io: Io) !void {
            try silent_leader_forwarding(io, true);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_forward_emitted_for_network_notarization_on_view_advance`: a network
// notarization completing sub-quorum votes forwards only on view advance, to the
// participants whose vote was not observed.
test "batcher forwards a network notarization's proposal on view advance" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, forward_voters);
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            const value = proposal_at(1, 0, 9);
            try deliver_notarizes(&harness, &.{ 1, 2 }, value);
            try construct_notarize(&harness, value);
            const bytes = try notarization_bytes(&harness.fixture, value);
            try harness.certificates.deliver(harness.fixture.participants[1], bytes);
            try expect_notarization_unforwarded(&harness, value);
            try expect_forward_on_advance(&harness, 2, 2, value, &.{ 3, 4 });
        }
    };
    try run_deterministic(Root.run);
}

/// commonware `self_excluded_from_forward_targets`: a certificate-only proposal forwards
/// to every remote participant but never to ourselves, signer or member-only.
fn self_excluded_from_forward_targets(io: Io, member_only: bool) !void {
    var harness: Harness = undefined;
    var options = forward_voters;
    options.member_only = member_only;
    try harness.start_with(io, null, options);
    defer harness.stop();
    try harness.mailbox.update(.new(1), .init(1), .zero(), null);
    try io.sleep(.fromMilliseconds(10), .awake);
    const value = proposal_at(1, 0, 3);
    const bytes = try notarization_bytes(&harness.fixture, value);
    try harness.certificates.deliver(harness.fixture.participants[1], bytes);
    try expect_notarization_unforwarded(&harness, value);
    try expect_forward_on_advance(&harness, 2, 2, value, &.{ 1, 2, 3, 4 });
}

// commonware `test_self_excluded_from_forward_targets`.
test "batcher never forwards to itself" {
    const Root = struct {
        fn run(io: Io) !void {
            try self_excluded_from_forward_targets(io, false);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_member_without_share_excluded_from_forward_targets`.
test "batcher as a member without a share never forwards to itself" {
    const Root = struct {
        fn run(io: Io) !void {
            try self_excluded_from_forward_targets(io, true);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_conflicting_notarize_voter_is_forwarded`: a peer that notarized a
// conflicting proposal, and one that only nullified, still get the winning proposal.
test "batcher forwards to conflicting and nullifying voters" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, .{ .participants = 7, .forward = .silent_voters });
            defer harness.stop();
            try harness.mailbox.update(.new(2), .init(1), .zero(), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            const winner = proposal_at(2, 1, 0xa);
            try deliver_notarizes(&harness, &.{1}, winner);
            try deliver_nullifies(&harness, &.{6}, 2);
            try deliver_notarizes(&harness, &.{2}, proposal_at(2, 1, 0xb));
            try deliver_notarizes(&harness, &.{ 3, 4, 5 }, winner);
            try construct_notarize(&harness, winner);
            try expect_notarization_unforwarded(&harness, winner);
            try expect_forward_on_advance(&harness, 3, 3, winner, &.{ 2, 6 });
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_finalize_voter_excluded_from_forwarding`: a peer that finalized the
// proposal already has the block and gets no forward.
test "batcher does not forward to finalize voters" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, .{ .participants = 7, .forward = .silent_voters });
            defer harness.stop();
            try harness.mailbox.update(.new(2), .init(1), .zero(), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            const value = proposal_at(2, 1, 0xc);
            const Finalize = types.Finalize(Scheme, Digest);
            const finalize = (try Finalize.sign(gpa, &harness.fixture.schemes[6], value)).?;
            const Vote = types.Vote(Scheme, Digest);
            const bytes = try codec.encode(Vote, gpa, .{ .finalize = finalize });
            try harness.votes.deliver(harness.fixture.participants[6], bytes);
            try io.sleep(.fromMilliseconds(10), .awake);
            try deliver_notarizes(&harness, &.{ 1, 2, 3, 4 }, value);
            try construct_notarize(&harness, value);
            try expect_notarization_unforwarded(&harness, value);
            try expect_forward_on_advance(&harness, 3, 3, value, &.{5});
        }
    };
    try run_deterministic(Root.run);
}

/// Expects the next voter message to be `value` forwarded as the leader's proposal.
fn expect_voter_proposal(harness: *Harness, value: types.Proposal(Digest)) !void {
    const message = try harness.voter.try_recv();
    defer VoterMessage.discard(message);
    try testing.expect(message == .proposal);
    try testing.expect(message.proposal.eql(value));
}

// commonware `test_proposal_forwarded_after_leader_set`: the leader's notarize forwards
// its proposal to the voter.
test "batcher forwards the leader's proposal to the voter" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, .{ .participants = 5 });
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            const value = proposal_at(1, 0, 1);
            try deliver_notarizes(&harness, &.{1}, value);
            try io.sleep(.fromMilliseconds(50), .awake);
            try expect_voter_proposal(&harness, value);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_proposal_forwarded_before_leader_set`: a leader notarize that arrives
// before the leader is known forwards its proposal once the leader is set.
test "batcher forwards a leader's early proposal once the leader is set" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, .{ .participants = 5 });
            defer harness.stop();
            const value = proposal_at(1, 0, 1);
            try deliver_notarizes(&harness, &.{1}, value);
            try io.sleep(.fromMilliseconds(50), .awake);
            try testing.expectError(error.Empty, harness.voter.try_recv());
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try io.sleep(.fromMilliseconds(50), .awake);
            try expect_voter_proposal(&harness, value);
        }
    };
    try run_deterministic(Root.run);
}

// commonware `test_optimistic_future_proposal_forwarded`: with terms of 5 and two
// optimistic views, the leader's notarize for in-window view 3 forwards its proposal
// while we are still at view 1.
test "batcher forwards an optimistic future proposal" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            const options: Harness.Options = .{
                .participants = 5,
                .term_length = 5,
                .optimistic_views = 2,
            };
            try harness.start_with(io, null, options);
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try io.sleep(.fromMilliseconds(10), .awake);
            const value = proposal_at(3, 2, 3);
            try deliver_notarizes(&harness, &.{1}, value);
            try io.sleep(.fromMilliseconds(250), .awake);
            try expect_voter_proposal(&harness, value);
        }
    };
    try run_deterministic(Root.run);
}
