//! The probe actor's driver over in-memory channels: it solicits the committee, retries on
//! its deadline, delivers the floor, hands off to service once a source is attached, serves
//! requests from the source, blocks invalid tags, and stops when the network closes.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const utils = @import("utils");
const wire = @import("wire.zig");
const actor_mod = @import("actor.zig");

const gpa = testing.allocator;
const io = testing.io;
const mpsc = utils.channel.mpsc;
const Digest = cryptography.Sha256.Digest;
const ed25519 = consensus.simplex.scheme.ed25519;
const S = ed25519.Scheme(Digest);
const K = S.PublicKey;
const types = consensus.simplex.types;
const Proposal = types.Proposal(Digest);
const Finalization = types.Finalization(S, Digest);
const Fixture = cryptography.certificate.mocks.Fixture(S);
const Provider = cryptography.certificate.ConstantProvider(S);
const WireMessage = wire.Message(S, struct {
    pub const Commitment = Digest;
});
const NetMessage = p2p.Message(K);

/// Records every send; copies share one log.
const Sender = struct {
    const Sent = struct { to: ?K, bytes: []u8 };
    const Log = struct {
        mutex: Io.Mutex = .init,
        sent: std.ArrayList(Sent) = .empty,
    };
    log: *Log,

    pub fn send(
        self: Sender,
        recipients: p2p.Recipients(K),
        parts: []const []const u8,
        priority: bool,
    ) ![]K {
        _ = priority;
        const bytes = try std.mem.concat(gpa, u8, parts);
        errdefer gpa.free(bytes);
        const to: ?K = if (recipients == .one) recipients.one else null;
        self.log.mutex.lockUncancelable(io);
        defer self.log.mutex.unlock(io);
        try self.log.sent.append(gpa, .{ .to = to, .bytes = bytes });
        return gpa.alloc(K, 0);
    }

    fn count(self: Sender) usize {
        self.log.mutex.lockUncancelable(io);
        defer self.log.mutex.unlock(io);
        return self.log.sent.items.len;
    }

    fn at(self: Sender, index: usize) Sent {
        self.log.mutex.lockUncancelable(io);
        defer self.log.mutex.unlock(io);
        return self.log.sent.items[index];
    }

    fn free(log: *Log) void {
        for (log.sent.items) |sent| gpa.free(sent.bytes);
        log.sent.deinit(gpa);
    }
};

pub const Receiver = struct {
    receiver: mpsc.Receiver(NetMessage),

    pub fn recv(self: *Receiver) Io.Cancelable!?NetMessage {
        return self.receiver.recv();
    }

    pub fn deinit(self: *Receiver) void {
        self.receiver.deinit();
    }
};

pub const Blocker = struct {
    pub const Log = struct {
        mutex: Io.Mutex = .init,
        blocked: std.ArrayList(K) = .empty,
    };
    log: *Log,

    pub fn block(self: Blocker, peer: K) p2p.Feedback {
        self.log.mutex.lockUncancelable(io);
        defer self.log.mutex.unlock(io);
        self.log.blocked.append(gpa, peer) catch return .closed;
        return .ok;
    }

    pub fn count(self: Blocker) usize {
        self.log.mutex.lockUncancelable(io);
        defer self.log.mutex.unlock(io);
        return self.log.blocked.items.len;
    }
};

/// Serves a copy of one finalization.
const Source = struct {
    finalization: *const Finalization,

    pub fn latest_finalization(self: Source, allocator: Allocator) !?Finalization {
        return try self.finalization.clone(allocator);
    }
};

const Probe = actor_mod.Probe(struct {
    pub const Scheme = S;
    pub const Digest = Digest_;
    pub const Provider = Provider_;
    pub const Source = Source_;
    pub const Blocker = Blocker_;
    pub const NetSender = Sender;
    pub const NetReceiver = Receiver;
});
const Digest_ = Digest;
const Provider_ = Provider;
const Source_ = Source;
const Blocker_ = Blocker;

fn finalize_all(fixture: *const Fixture, view: u64) !Finalization {
    const round: consensus.Round = .new(.zero(), .new(view));
    const proposal = Proposal.init(round, .new(view - 1), .fill(@intCast(view)));
    const subject: types.Subject(Digest) = .{ .finalize = &proposal };
    const votes = try gpa.alloc(S.Attestation, fixture.schemes.len);
    defer gpa.free(votes);
    for (votes, fixture.schemes) |*vote, *scheme| vote.* = (try scheme.sign(gpa, subject)).?;
    const certificate = try fixture.schemes[0].assemble(gpa, votes, parallel.sequential);
    return .{ .proposal = proposal, .certificate = certificate };
}

pub fn deliver(network: mpsc.Sender(NetMessage), peer: K, bytes: []const u8) !void {
    const payload = try gpa.dupe(u8, bytes);
    errdefer gpa.free(payload);
    try network.send(.{ .peer = peer, .payload = payload, .gpa = gpa });
}

/// Waits (in real time) until `done(context)` holds.
pub fn wait_for(context: anytype, comptime done: fn (@TypeOf(context)) bool) !void {
    var waited: u32 = 0;
    while (!done(context)) : (waited += 1) {
        if (waited > 2_000) return error.TestTimedOut;
        try io.sleep(.fromMilliseconds(5), .awake);
    }
}

const Runner = struct {
    fn run(probe: *Probe, rng: *utils.rng.TestRng) anyerror!void {
        return probe.run(rng, parallel.sequential);
    }
};

test "stateful probe actor: discovers a floor, then serves peers" {
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "_COMMONWARE_GLUE_PROBE_TEST", 4);
    defer fixture.deinit(gpa);
    var low = try finalize_all(&fixture, 10);
    defer low.deinit(gpa);
    var high = try finalize_all(&fixture, 13);
    defer high.deinit(gpa);
    var latest = try finalize_all(&fixture, 20);
    defer latest.deinit(gpa);
    const low_bytes = try codec.encode(WireMessage, gpa, .{ .response = low });
    defer gpa.free(low_bytes);
    const high_bytes = try codec.encode(WireMessage, gpa, .{ .response = high });
    defer gpa.free(high_bytes);

    var sent_log: Sender.Log = .{};
    defer Sender.free(&sent_log);
    var block_log: Blocker.Log = .{};
    defer block_log.blocked.deinit(gpa);
    const sender: Sender = .{ .log = &sent_log };
    const blocker: Blocker = .{ .log = &block_log };
    var network = try mpsc.channel(NetMessage, gpa, io, 16);
    var network_open = true;
    defer if (network_open) network.sender.deinit();

    const created = try Probe.init(gpa, io, .{
        .provider = .init(&fixture.verifier),
        .blocker = blocker,
        .mailbox_size = 4,
        .minimum_epoch = .zero(),
        .retry_timeout_ns = 50 * std.time.ns_per_ms,
    }, sender, .{ .receiver = network.receiver });
    defer created.probe.deinit();
    var mailbox = created.mailbox;
    defer mailbox.deinit();
    var verify_rng = utils.rng.test_rng();
    var task = try io.concurrent(Runner.run, .{ created.probe, &verify_rng });
    var joined = false;
    defer if (!joined) {
        task.cancel(io) catch {};
    };

    // No subscriber, no request. A subscription solicits the committee, and the retry
    // deadline solicits it again while no sample completes.
    try testing.expectEqual(0, sender.count());
    var floor = try mailbox.subscribe();
    defer floor.deinit();
    try wait_for(sender, struct {
        fn done(s: Sender) bool {
            return s.count() >= 2;
        }
    }.done);
    for (0..2) |index| {
        const sent = sender.at(index);
        try testing.expectEqual(null, sent.to);
        try testing.expectEqualSlices(u8, &.{0}, sent.bytes);
    }

    // Two committee members reply; the floor is the higher reply.
    try deliver(network.sender, fixture.participants[0], low_bytes);
    try deliver(network.sender, fixture.participants[1], high_bytes);
    var received = try floor.recv();
    defer received.deinit();
    try testing.expectEqual(13, received.finalization.view().get());

    // Attached with no subscriber waiting, the probe serves the source's latest finalization.
    // The attachment and peer messages arrive on separate pumps, so a request may still reach
    // discovery (which ignores it): resend until one is served.
    try mailbox.attach(.{ .finalization = &latest });
    const before = sender.count();
    var attempts: u32 = 0;
    while (sender.count() == before) : (attempts += 1) {
        if (attempts > 2_000) return error.TestTimedOut;
        try deliver(network.sender, fixture.participants[2], &.{0});
        try io.sleep(.fromMilliseconds(5), .awake);
    }
    const served = sender.at(before);
    try testing.expect(served.to.?.eql(fixture.participants[2]));
    const cfg = fixture.verifier.certificate_codec_config();
    var decoded = try codec.decode_cfg(WireMessage, gpa, served.bytes, cfg);
    defer decoded.deinit(gpa);
    try testing.expectEqual(20, decoded.response.view().get());

    // In service, an invalid tag blocks its sender.
    try deliver(network.sender, fixture.participants[3], &.{7});
    try wait_for(blocker, struct {
        fn done(b: Blocker) bool {
            return b.count() == 1;
        }
    }.done);
    try testing.expect(block_log.blocked.items[0].eql(fixture.participants[3]));

    // A subscription in service gets the floor at once.
    var late = try mailbox.subscribe();
    defer late.deinit();
    var late_floor = try late.recv();
    defer late_floor.deinit();
    try testing.expectEqual(13, late_floor.finalization.view().get());

    // Closing the network stops the probe.
    network.sender.deinit();
    network_open = false;
    try task.await(io);
    joined = true;
}

test "stateful probe actor: a canceled probe returns error.Canceled" {
    // Swallowing the cancel would leave the caller's next wait unwakeable (AGENTS.md).
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "_COMMONWARE_GLUE_PROBE_TEST", 4);
    defer fixture.deinit(gpa);
    var sent_log: Sender.Log = .{};
    defer Sender.free(&sent_log);
    var block_log: Blocker.Log = .{};
    defer block_log.blocked.deinit(gpa);
    var network = try mpsc.channel(NetMessage, gpa, io, 16);
    defer network.sender.deinit();
    const created = try Probe.init(gpa, io, .{
        .provider = .init(&fixture.verifier),
        .blocker = .{ .log = &block_log },
        .mailbox_size = 4,
        .minimum_epoch = .zero(),
        .retry_timeout_ns = 50 * std.time.ns_per_ms,
    }, .{ .log = &sent_log }, .{ .receiver = network.receiver });
    defer created.probe.deinit();
    var mailbox = created.mailbox;
    defer mailbox.deinit();
    var verify_rng = utils.rng.test_rng();
    var task = try io.concurrent(Runner.run, .{ created.probe, &verify_rng });
    // Discovery waits for a subscriber; cancel it there.
    try io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectError(error.Canceled, task.cancel(io));
}
