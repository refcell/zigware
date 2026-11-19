//! commonware `glue/src/stateful/probe/mod.rs` tests on whom the probe solicits and judges:
//! current participants only, invalid duplicates, a rotated committee's finalization, and the
//! sample size under a participantless verifier. The first runs the actor's driver over
//! in-memory channels; the others run against the discovery state, as discovery_test.zig.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const utils = @import("utils");
const actor_mod = @import("actor.zig");
const discovery_mod = @import("discovery.zig");
const actor_test = @import("actor_test.zig");
const discovery_test = @import("discovery_test.zig");

const gpa = testing.allocator;
const io = testing.io;
const mpsc = utils.channel.mpsc;
const oneshot = utils.channel.oneshot;
const Digest = discovery_test.Digest;
const S = discovery_test.S;
const K = S.PublicKey;
const ed25519 = consensus.simplex.scheme.ed25519;
const Harness = discovery_test.Harness;
const Provider = discovery_test.Provider;
const Discovery = discovery_test.Discovery;
const namespace = discovery_test.namespace;
const Finalization = consensus.simplex.types.Finalization(S, Digest);
const Scoped = cryptography.certificate.Scoped;

/// Records each send's recipients; copies share one log.
const RecordingSender = struct {
    const Log = struct {
        mutex: std.Io.Mutex = .init,
        sends: std.ArrayList(p2p.Recipients(K)) = .empty,

        fn deinit(log: *Log) void {
            for (log.sends.items) |recipients| {
                if (recipients == .some) gpa.free(recipients.some);
            }
            log.sends.deinit(gpa);
        }
    };
    log: *Log,

    pub fn send(
        self: RecordingSender,
        recipients: p2p.Recipients(K),
        parts: []const []const u8,
        priority: bool,
    ) ![]K {
        _ = parts;
        _ = priority;
        var copy = recipients;
        if (recipients == .some) copy = .{ .some = try gpa.dupe(K, recipients.some) };
        errdefer if (copy == .some) gpa.free(copy.some);
        self.log.mutex.lockUncancelable(io);
        defer self.log.mutex.unlock(io);
        try self.log.sends.append(gpa, copy);
        return gpa.alloc(K, 0);
    }

    fn count(self: RecordingSender) usize {
        self.log.mutex.lockUncancelable(io);
        defer self.log.mutex.unlock(io);
        return self.log.sends.items.len;
    }
};

const NoSource = struct {
    pub fn latest_finalization(self: NoSource, allocator: std.mem.Allocator) !?Finalization {
        _ = self;
        _ = allocator;
        return null;
    }
};

const ConstantProvider = cryptography.certificate.ConstantProvider(S);
const Probe = actor_mod.Probe(struct {
    pub const Scheme = S;
    pub const Digest = Digest_;
    pub const Provider = ConstantProvider;
    pub const Source = NoSource;
    pub const Blocker = actor_test.Blocker;
    pub const NetSender = RecordingSender;
    pub const NetReceiver = actor_test.Receiver;
});
const Digest_ = Digest;

fn run_probe(probe: *Probe, rng: *utils.rng.TestRng) anyerror!void {
    return probe.run(rng, parallel.sequential);
}

test "stateful probe: requests finalizations only from current participants" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var sent: RecordingSender.Log = .{};
    defer sent.deinit();
    var blocked: actor_test.Blocker.Log = .{};
    defer blocked.blocked.deinit(gpa);
    const sender: RecordingSender = .{ .log = &sent };
    var network = try mpsc.channel(p2p.Message(K), gpa, io, 16);
    defer network.sender.deinit();
    const created = try Probe.init(gpa, io, .{
        .provider = .init(&harness.committee.verifier),
        .blocker = .{ .log = &blocked },
        .mailbox_size = 4,
        .minimum_epoch = .zero(),
        .retry_timeout_ns = 3_600 * std.time.ns_per_s,
    }, sender, .{ .receiver = network.receiver });
    defer created.probe.deinit();
    var mailbox = created.mailbox;
    defer mailbox.deinit();
    var rng = utils.rng.test_rng();
    var task = try io.concurrent(run_probe, .{ created.probe, &rng });
    defer task.cancel(io) catch {};

    var floor = try mailbox.subscribe();
    defer floor.deinit();
    try actor_test.wait_for(sender, struct {
        fn done(s: RecordingSender) bool {
            return s.count() >= 1;
        }
    }.done);
    // The request goes to the committee alone: no outsider on the network is solicited.
    const recipients = sent.sends.items[0];
    try testing.expect(recipients == .some);
    try testing.expectEqual(harness.committee.participants.len, recipients.some.len);
    for (harness.outsiders.participants) |outsider| {
        for (recipients.some) |peer| try testing.expect(!peer.eql(outsider));
    }
    for (harness.committee.participants) |member| {
        var found = false;
        for (recipients.some) |peer| found = found or peer.eql(member);
        try testing.expect(found);
    }
    try testing.expectEqual(0, blocked.blocked.items.len);
}

test "stateful probe: an invalid duplicate finalization is ignored" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var d = Discovery.init(gpa, harness.provider(), .new(0));
    defer d.deinit();
    var sub, _ = try discovery_test.subscribe(&d);
    defer sub.receiver.deinit();

    // Node 1 sends a valid finalization, then one signed by a foreign committee.
    const valid = try Harness.reply(&harness.committee, 0, 1);
    defer gpa.free(valid);
    const invalid = try Harness.reply(&harness.outsiders, 0, 2);
    defer gpa.free(invalid);
    try testing.expectEqual(.recorded, try harness.receive(&d, 1, valid));
    try testing.expectEqual(.ignore, try harness.receive(&d, 1, invalid));
    // From a peer not yet heard, the same bytes fail verification and block.
    try testing.expectEqual(.block, try harness.receive(&d, 2, invalid));
    try testing.expectError(error.Empty, sub.receiver.try_recv());
}

test "stateful probe: resolves a rotated committee's finalization from solicited peers" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    // Seven solicited at epoch 0; a disjoint committee of four signs epoch 1.
    var rng = utils.rng.TestRng.init(1);
    var seven = try ed25519.fixture(Digest, gpa, &rng, namespace, 7);
    defer seven.deinit(gpa);
    var rotated = try ed25519.fixture(Digest, gpa, &rng, namespace, 4);
    defer rotated.deinit(gpa);
    for (seven.participants[1..4]) |old| {
        for (rotated.participants) |new| assert(!old.eql(new));
    }
    const entries = [_]Provider.Entry{
        .{ .epoch = 0, .scheme = &seven.verifier },
        .{ .epoch = 1, .scheme = &rotated.verifier },
    };
    var d = Discovery.init(gpa, .{ .entries = &entries }, .new(0));
    defer d.deinit();
    var sub, _ = try discovery_test.subscribe(&d);
    defer sub.receiver.deinit();
    try testing.expectEqual(7, d.request_round().?.len);

    const finalization = try Harness.reply(&rotated, 1, 7);
    defer gpa.free(finalization);
    // Two replies do not satisfy a seven-node sample (f + 1 = 3), and none is blocked for
    // reporting a newer committee's finalization.
    for (seven.participants[1..3]) |peer| {
        const verdict = try d.receive(peer, finalization, &harness.rng, parallel.sequential);
        try testing.expectEqual(.recorded, verdict);
    }
    try testing.expectError(error.Empty, sub.receiver.try_recv());
    const third = seven.participants[3];
    const verdict = try d.receive(third, finalization, &harness.rng, parallel.sequential);
    try testing.expectEqual(.recorded, verdict);
    var floor = try sub.receiver.try_recv();
    defer floor.deinit();
    try testing.expectEqual(1, floor.finalization.epoch().get());
    try testing.expectEqual(7, floor.finalization.view().get());
}

/// An ed25519 scheme that may hide its participants (commonware's `MaybeEnumerableScheme`):
/// a participantless one still verifies but has no committee to size a sample by.
const Maybe = struct {
    pub const Subject = S.Subject;
    pub const Faults = S.Faults;
    pub const PublicKey = S.PublicKey;
    pub const Certificate = S.Certificate;

    inner: *const S,
    enumerable: bool,

    pub fn participants(self: *const Maybe) @TypeOf(self.inner.participants()) {
        assert(self.enumerable); // A verify-only scheme has no participant metadata.
        return self.inner.participants();
    }

    pub fn verify_certificate(
        self: *const Maybe,
        allocator: std.mem.Allocator,
        rng: anytype,
        subject: Subject,
        certificate: *const Certificate,
        strategy: anytype,
    ) std.mem.Allocator.Error!bool {
        return self.inner.verify_certificate(allocator, rng, subject, certificate, strategy);
    }

    pub fn certificate_codec_config(self: *const Maybe) usize {
        return self.inner.certificate_codec_config();
    }
};

/// Scoped verification through the participantless verifier; schemes enumerate.
const ParticipantlessAllProvider = struct {
    verifier: *const Maybe,
    scheme_: *const Maybe,

    pub fn scoped(self: @This(), epoch: consensus.Epoch) ?Scoped(Maybe) {
        _ = epoch;
        return .verifier(self.verifier);
    }

    pub fn scheme(self: @This(), epoch: consensus.Epoch) ?*const Maybe {
        _ = epoch;
        return self.scheme_;
    }
};

test "stateful probe: sample size uses the scoped scheme with a participantless verifier" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const participantless: Maybe = .{ .inner = &harness.committee.verifier, .enumerable = false };
    const enumerable: Maybe = .{ .inner = &harness.committee.verifier, .enumerable = true };
    const provider: ParticipantlessAllProvider = .{
        .verifier = &participantless,
        .scheme_ = &enumerable,
    };
    var d = discovery_mod.Discovery(Maybe, Digest, ParticipantlessAllProvider).init(
        gpa,
        provider,
        .new(0),
    );
    defer d.deinit();
    const Value = @TypeOf(d).FloorValue;
    var pair = try oneshot.channel(Value, gpa, io);
    defer pair.receiver.deinit();
    try testing.expect(try d.subscribe(pair.sender));
    try testing.expectEqual(4, d.request_round().?.len);

    // Two of four (f + 1 = 2) resolve the floor.
    const finalization = try Harness.reply(&harness.committee, 0, 1);
    defer gpa.free(finalization);
    for (harness.committee.participants[1..3]) |peer| {
        const verdict = try d.receive(peer, finalization, &harness.rng, parallel.sequential);
        try testing.expectEqual(.recorded, verdict);
    }
    var floor = try pair.receiver.try_recv();
    defer floor.deinit();
    try testing.expectEqual(1, floor.finalization.view().get());
}
