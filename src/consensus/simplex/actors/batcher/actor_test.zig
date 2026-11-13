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

    fn deinit(self: *Log) void {
        self.blocked.deinit(gpa);
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
        _ = activity;
        self.log.reported += 1;
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
    const Notarize = types.Notarize(Scheme, Digest);
    const vote = (try Notarize.sign(gpa, &fixture.schemes[signer], proposal(view))).?;
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
        var rng = utils.rng.test_rng();
        const fixture = try ed25519.fixture(Digest, gpa, &rng, "batcher", 4);
        self.* = .{ .io = io, .fixture = fixture };
        const cfg = config(&fixture.schemes[0], &self.log);
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
