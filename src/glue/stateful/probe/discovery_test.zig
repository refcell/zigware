//! commonware `glue/src/stateful/probe/mod.rs` protocol tests, run against the probe's
//! discovery state without a network: solicit, collect and select, blocking, pausing, late
//! subscribers, duplicates, and epoch filtering.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const wire = @import("wire.zig");
const discovery_mod = @import("discovery.zig");

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
pub const Digest = cryptography.Sha256.Digest;
const ed25519 = consensus.simplex.scheme.ed25519;
pub const S = ed25519.Scheme(Digest);
const types = consensus.simplex.types;
const Proposal = types.Proposal(Digest);
const Finalization = types.Finalization(S, Digest);
const Round = consensus.Round;
const V = struct {
    pub const Commitment = Digest;
};
pub const Message = wire.Message(S, V);
pub const Fixture = cryptography.certificate.mocks.Fixture(S);
pub const namespace = "_COMMONWARE_GLUE_PROBE_TEST";

/// Schemes by epoch (commonware's `EpochProvider`).
pub const Provider = struct {
    pub const Entry = struct { epoch: u64, scheme: *const S };
    entries: []const Entry,

    pub fn scoped(self: Provider, epoch: consensus.Epoch) ?cryptography.certificate.Scoped(S) {
        const found = self.scheme(epoch) orelse return null;
        return .verifier(found);
    }

    pub fn scheme(self: Provider, epoch: consensus.Epoch) ?*const S {
        for (self.entries) |entry| if (entry.epoch == epoch.get()) return entry.scheme;
        return null;
    }
};

pub const Discovery = discovery_mod.Discovery(S, Digest, Provider);
pub const FloorValue = Discovery.FloorValue;

pub fn finalize_all(fixture: *const Fixture, proposal: Proposal) !Finalization {
    const subject: types.Subject(Digest) = .{ .finalize = &proposal };
    const votes = try gpa.alloc(S.Attestation, fixture.schemes.len);
    defer gpa.free(votes);
    for (votes, fixture.schemes) |*vote, *scheme| vote.* = (try scheme.sign(gpa, subject)).?;
    const certificate = try fixture.schemes[0].assemble(gpa, votes, parallel.sequential);
    return .{ .proposal = proposal, .certificate = certificate };
}

/// Two committees of four (the second signs nothing the first accepts), a provider, and
/// encoded replies.
pub const Harness = struct {
    committee: Fixture,
    outsiders: Fixture,
    entries_buffer: [2]Provider.Entry,
    entry_count: usize,
    rng: utils.rng.TestRng,

    pub fn init(harness: *Harness) !void {
        harness.rng = utils.rng.test_rng();
        harness.committee = try ed25519.fixture(Digest, gpa, &harness.rng, namespace, 4);
        harness.outsiders = try ed25519.fixture(Digest, gpa, &harness.rng, namespace, 4);
        harness.entries_buffer[0] = .{ .epoch = 0, .scheme = &harness.committee.verifier };
        harness.entry_count = 1;
    }

    pub fn deinit(harness: *Harness) void {
        harness.outsiders.deinit(gpa);
        harness.committee.deinit(gpa);
    }

    pub fn provider(harness: *const Harness) Provider {
        return .{ .entries = harness.entries_buffer[0..harness.entry_count] };
    }

    pub fn peer(harness: *const Harness, index: usize) S.PublicKey {
        return harness.committee.participants[index];
    }

    /// An encoded response at `(epoch, view)` signed by `fixture`.
    pub fn reply(fixture: *const Fixture, epoch: u64, view: u64) ![]u8 {
        const round: Round = .new(.new(epoch), .new(view));
        const proposal = Proposal.init(round, .new(view - 1), .fill(@intCast(view)));
        var finalization = try finalize_all(fixture, proposal);
        defer finalization.deinit(gpa);
        return codec.encode(Message, gpa, .{ .response = finalization });
    }

    pub fn receive(
        harness: *Harness,
        d: *Discovery,
        peer_index: usize,
        bytes: []const u8,
    ) !discovery_mod.Verdict {
        return d.receive(harness.peer(peer_index), bytes, &harness.rng, parallel.sequential);
    }
};

pub const Subscription = oneshot.Pair(FloorValue);

pub fn subscribe(d: *Discovery) !struct { Subscription, bool } {
    const pair = try oneshot.channel(FloorValue, gpa, io);
    return .{ pair, try d.subscribe(pair.sender) };
}

pub fn expect_floor_view(receiver: *oneshot.Receiver(FloorValue), view: u64) !void {
    var floor = try receiver.try_recv();
    defer floor.deinit();
    try testing.expectEqual(view, floor.finalization.view().get());
}

test "stateful probe discovery: resolves the highest floor from f + 1 replies" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var d = Discovery.init(gpa, harness.provider(), .new(0));
    defer d.deinit();

    var first, const solicit = try subscribe(&d);
    defer first.receiver.deinit();
    try testing.expect(solicit);
    try testing.expectEqual(4, d.request_round().?.len);
    try testing.expect(d.retrying());

    const low = try Harness.reply(&harness.committee, 0, 10);
    defer gpa.free(low);
    const high = try Harness.reply(&harness.committee, 0, 13);
    defer gpa.free(high);
    // One reply is not enough with f = 1, even a second copy from the same peer.
    try testing.expectEqual(.recorded, try harness.receive(&d, 0, low));
    try testing.expectEqual(.ignore, try harness.receive(&d, 0, high));
    try testing.expectError(error.Empty, first.receiver.try_recv());
    try testing.expectEqual(.recorded, try harness.receive(&d, 2, high));
    try expect_floor_view(&first.receiver, 13);
    try testing.expect(!d.retrying());

    // Replies after the floor are ignored, and a late subscriber gets the floor at once.
    try testing.expectEqual(.ignore, try harness.receive(&d, 3, high));
    var late, const late_solicit = try subscribe(&d);
    defer late.receiver.deinit();
    try testing.expect(!late_solicit);
    try expect_floor_view(&late.receiver, 13);
}

test "stateful probe discovery: a second subscriber joins the round in progress" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var d = Discovery.init(gpa, harness.provider(), .new(0));
    defer d.deinit();
    var a, const a_solicit = try subscribe(&d);
    defer a.receiver.deinit();
    var b, const b_solicit = try subscribe(&d);
    defer b.receiver.deinit();
    try testing.expect(a_solicit and !b_solicit);
    _ = d.request_round();
    const bytes = try Harness.reply(&harness.committee, 0, 11);
    defer gpa.free(bytes);
    _ = try harness.receive(&d, 1, bytes);
    _ = try harness.receive(&d, 3, bytes);
    try expect_floor_view(&a.receiver, 11);
    try expect_floor_view(&b.receiver, 11);
}

test "stateful probe discovery: replies without a subscriber are not recorded" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var d = Discovery.init(gpa, harness.provider(), .new(0));
    defer d.deinit();
    const bytes = try Harness.reply(&harness.committee, 0, 10);
    defer gpa.free(bytes);
    // Verified but dropped: the peer stays awaited.
    try testing.expectEqual(.ignore, try harness.receive(&d, 0, bytes));
    try testing.expect(d.sample.awaits(harness.peer(0)));
    try testing.expect(!d.retrying());

    // A subscriber that leaves pauses discovery the same way.
    var gone, _ = try subscribe(&d);
    gone.receiver.deinit();
    try testing.expectEqual(.ignore, try harness.receive(&d, 1, bytes));
    try testing.expect(!d.retrying());
    // Attaching with no subscriber ends discovery.
    try testing.expect(!d.finished());
    d.attach();
    try testing.expect(d.finished());
}

test "stateful probe discovery: blocks malformed, invalid, and non-participant replies" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var d = Discovery.init(gpa, harness.provider(), .new(0));
    defer d.deinit();
    var sub, _ = try subscribe(&d);
    defer sub.receiver.deinit();

    // An unknown tag, a truncated finalization, and trailing bytes are malformed.
    try testing.expectEqual(.block, try harness.receive(&d, 0, &.{2}));
    try testing.expectEqual(.block, try harness.receive(&d, 0, &.{1}));
    const valid = try Harness.reply(&harness.committee, 0, 10);
    defer gpa.free(valid);
    const trailing = try std.mem.concat(gpa, u8, &.{ valid, &.{0} });
    defer gpa.free(trailing);
    try testing.expectEqual(.block, try harness.receive(&d, 0, trailing));
    // A request is ignored.
    try testing.expectEqual(.ignore, try harness.receive(&d, 0, &.{0}));

    // A finalization signed by another committee fails verification.
    const forged = try Harness.reply(&harness.outsiders, 0, 10);
    defer gpa.free(forged);
    try testing.expectEqual(.block, try harness.receive(&d, 1, forged));

    // A valid finalization from a non-participant is blocked.
    const outsider = harness.outsiders.participants[0];
    const verdict = try d.receive(outsider, valid, &harness.rng, parallel.sequential);
    try testing.expectEqual(.block, verdict);

    // None of them counted: two valid replies are still needed.
    try testing.expectEqual(.recorded, try harness.receive(&d, 2, valid));
    try testing.expectError(error.Empty, sub.receiver.try_recv());
    try testing.expectEqual(.recorded, try harness.receive(&d, 3, valid));
    try expect_floor_view(&sub.receiver, 10);
}

test "stateful probe discovery: ignores replies below the minimum or in unknown epochs" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    // Epochs 0 and 1 have schemes, the minimum is 1, and epoch 5 is unknown.
    harness.entries_buffer[1] = .{ .epoch = 1, .scheme = &harness.committee.verifier };
    harness.entry_count = 2;
    var d = Discovery.init(gpa, harness.provider(), .new(1));
    defer d.deinit();
    var sub, _ = try subscribe(&d);
    defer sub.receiver.deinit();
    try testing.expectEqual(4, d.request_round().?.len);

    // Neither is decoded far enough to judge, so neither blocks, even forged ones.
    const below = try Harness.reply(&harness.outsiders, 0, 10);
    defer gpa.free(below);
    const unknown = try Harness.reply(&harness.outsiders, 5, 10);
    defer gpa.free(unknown);
    try testing.expectEqual(.ignore, try harness.receive(&d, 0, below));
    try testing.expectEqual(.ignore, try harness.receive(&d, 0, unknown));
    try testing.expect(d.sample.awaits(harness.peer(0)));

    const ok = try Harness.reply(&harness.committee, 1, 12);
    defer gpa.free(ok);
    _ = try harness.receive(&d, 0, ok);
    _ = try harness.receive(&d, 1, ok);
    try expect_floor_view(&sub.receiver, 12);
}

test "stateful probe discovery: no request without the minimum epoch's scheme" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var d = Discovery.init(gpa, harness.provider(), .new(3));
    defer d.deinit();
    var sub, _ = try subscribe(&d);
    defer sub.receiver.deinit();
    try testing.expectEqual(null, d.request_round());
}
