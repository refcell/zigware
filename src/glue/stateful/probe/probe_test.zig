//! Tests of the probe's wire limits (commonware `probe/limits.rs`) and its `Sample` (the
//! selection rules the probe actor's tests in `probe/mod.rs` exercise: highest of `f + 1`,
//! one reply per peer, unjudgeable replies not counted, a floor delivered once).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const wire = @import("wire.zig");
const sample_mod = @import("sample.zig");

const gpa = testing.allocator;
const Digest = cryptography.Sha256.Digest;
const ed25519 = consensus.simplex.scheme.ed25519;
const S = ed25519.Scheme(Digest);
const types = consensus.simplex.types;
const Proposal = types.Proposal(Digest);
const Finalization = types.Finalization(S, Digest);
const Round = consensus.Round;
/// The marshal variant: the probe uses only its commitment (commonware `Standard<TestBlock>`,
/// whose commitment is the block digest).
const V = struct {
    pub const Commitment = Digest;
};
const Message = wire.Message(S, V);
const Sample = sample_mod.Sample(S, Digest);
const namespace = "_COMMONWARE_GLUE_STATEFUL_PROBE_LIMITS";

const Fixture = cryptography.certificate.mocks.Fixture(S);

/// A finalization of `proposal` signed by every participant of `fixture`.
fn finalize_all(fixture: *const Fixture, proposal: Proposal) !Finalization {
    const subject: types.Subject(Digest) = .{ .finalize = &proposal };
    const votes = try gpa.alloc(S.Attestation, fixture.schemes.len);
    defer gpa.free(votes);
    for (votes, fixture.schemes) |*vote, *scheme| vote.* = (try scheme.sign(gpa, subject)).?;
    const certificate = try fixture.schemes[0].assemble(gpa, votes, parallel.sequential);
    return .{ .proposal = proposal, .certificate = certificate };
}

fn encoded_len(message: Message) !usize {
    const bytes = try codec.encode(Message, gpa, message);
    defer gpa.free(bytes);
    try testing.expectEqual(codec.encode_size(Message, message), bytes.len);
    return bytes.len;
}

test "stateful probe: payload bound matches the widest encodings" {
    // 127 and 128 sit on either side of the one-byte varint limit on a certificate's
    // signature count.
    for ([_]u32{ 1, 4, 127, 128 }) |participants| {
        var rng = utils.rng.test_rng();
        var fixture = try ed25519.fixture(Digest, gpa, &rng, namespace, participants);
        defer fixture.deinit(gpa);
        const bound = wire.max_payload_size(V, S, participants);

        // Every signer, and the widest round and parent view.
        const max = std.math.maxInt(u64);
        const round: Round = .new(.new(max), .new(max));
        const digest = cryptography.Sha256.hash(&.{"block"});
        const proposal = Proposal.init(round, .new(max - 1), digest);
        var finalization = try finalize_all(&fixture, proposal);
        defer finalization.deinit(gpa);
        const certificate_size = codec.encode_size(S.Certificate, finalization.certificate);
        const certificate_slack = S.max_certificate_size(participants) - certificate_size;

        // The request is narrower than the response, which falls short of the bound by the
        // unused width of its certificate's signature-list prefix.
        const request = try encoded_len(.request);
        const response = try encoded_len(.{ .response = finalization });
        try testing.expect(request < response);
        try testing.expectEqual(bound, response + certificate_slack);
    }
}

test "stateful probe: messages round trip and reject unknown tags" {
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, namespace, 4);
    defer fixture.deinit(gpa);
    const round: Round = .new(.new(3), .new(9));
    var finalization = try finalize_all(&fixture, Proposal.init(round, .new(8), .fill(7)));
    defer finalization.deinit(gpa);
    const cfg = fixture.verifier.certificate_codec_config();

    for ([_]Message{ .request, .{ .response = finalization } }) |message| {
        const bytes = try codec.encode(Message, gpa, message);
        defer gpa.free(bytes);
        var decoded = try codec.decode_cfg(Message, gpa, bytes, cfg);
        defer decoded.deinit(gpa);
        try testing.expectEqual(std.meta.activeTag(message), std.meta.activeTag(decoded));
        if (message == .response) try testing.expect(decoded.response.eql(finalization));
    }
    const request = try codec.encode(Message, gpa, .request);
    defer gpa.free(request);
    try testing.expectEqualSlices(u8, &.{0}, request);
    const bad = [_]u8{2};
    try testing.expectError(error.InvalidEnum, codec.decode_cfg(Message, gpa, &bad, cfg));
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(Message, gpa, &.{1}, cfg));
}

/// Judges every reply usable, or only those at or above `min_epoch`.
const Judge = struct {
    min_epoch: u64 = 0,

    pub fn judgeable(judge: Judge, finalization: *const Finalization) bool {
        return finalization.epoch().get() >= judge.min_epoch;
    }
};

const Replies = struct {
    fixture: Fixture,
    /// Finalizations at views 10..=13 of epoch 1 and view 20 of epoch 0.
    finalizations: [5]Finalization,

    fn init(replies: *Replies) !void {
        var rng = utils.rng.test_rng();
        replies.fixture = try ed25519.fixture(Digest, gpa, &rng, namespace, 4);
        const rounds = [_][2]u64{ .{ 1, 10 }, .{ 1, 11 }, .{ 1, 12 }, .{ 1, 13 }, .{ 0, 20 } };
        for (&replies.finalizations, rounds) |*finalization, r| {
            const round: Round = .new(.new(r[0]), .new(r[1]));
            const proposal = Proposal.init(round, .new(r[1] - 1), .fill(@intCast(r[1])));
            finalization.* = try finalize_all(&replies.fixture, proposal);
        }
    }

    fn deinit(replies: *Replies) void {
        for (&replies.finalizations) |*finalization| finalization.deinit(gpa);
        replies.fixture.deinit(gpa);
    }

    fn peer(replies: *const Replies, index: usize) S.PublicKey {
        return replies.fixture.participants[index];
    }

    fn record(replies: *const Replies, sample: *Sample, peer_index: usize, reply: usize) !void {
        const copy = try replies.finalizations[reply].clone(gpa);
        try sample.record(replies.peer(peer_index), copy);
    }
};

test "stateful probe: the sample waits for f + 1 replies and selects the highest" {
    var replies: Replies = undefined;
    try replies.init();
    defer replies.deinit();
    var sample = Sample.init(gpa, .new(0));
    defer sample.deinit();

    // With four peers (f = 1), one reply is not enough, even a matching one.
    try replies.record(&sample, 0, 0);
    try testing.expectEqual(null, try sample.select(4, Judge{}));
    try testing.expect(!sample.awaits(replies.peer(0)));
    try testing.expect(sample.awaits(replies.peer(1)));

    // A duplicate from the same peer is ignored and does not complete the sample.
    try replies.record(&sample, 0, 3);
    try testing.expectEqual(null, try sample.select(4, Judge{}));

    // A second peer completes it; the floor is the highest reply, not the first.
    try replies.record(&sample, 2, 3);
    const floor = (try sample.select(4, Judge{})).?;
    try testing.expectEqual(13, floor.view().get());

    // The floor is delivered once, and later replies are not awaited.
    try testing.expectEqual(null, try sample.select(4, Judge{}));
    try testing.expectEqual(13, sample.get_floor().?.view().get());
    try testing.expect(!sample.awaits(replies.peer(3)));
}

test "stateful probe: the sample selects the highest over stale agreement" {
    var replies: Replies = undefined;
    try replies.init();
    defer replies.deinit();
    var sample = Sample.init(gpa, .new(0));
    defer sample.deinit();
    // Two peers agree on an old finalization; a third reports a newer one.
    try replies.record(&sample, 0, 0);
    try replies.record(&sample, 1, 0);
    try replies.record(&sample, 3, 2);
    try testing.expectEqual(12, (try sample.select(4, Judge{})).?.view().get());
}

test "stateful probe: unjudgeable replies are neither counted nor selected" {
    var replies: Replies = undefined;
    try replies.init();
    defer replies.deinit();
    var sample = Sample.init(gpa, .new(0));
    defer sample.deinit();
    // The epoch-0 reply has the highest view but cannot be judged.
    try replies.record(&sample, 0, 4);
    try replies.record(&sample, 1, 1);
    const judge: Judge = .{ .min_epoch = 1 };
    try testing.expectEqual(null, try sample.select(4, judge));
    try replies.record(&sample, 2, 0);
    try testing.expectEqual(11, (try sample.select(4, judge)).?.view().get());
}

test "stateful probe: a reset starts a new request round" {
    var replies: Replies = undefined;
    try replies.init();
    defer replies.deinit();
    var sample = Sample.init(gpa, .new(0));
    defer sample.deinit();
    try replies.record(&sample, 0, 0);
    try replies.record(&sample, 1, 1);
    try testing.expect(try sample.select(4, Judge{}) != null);
    sample.reset();
    try testing.expectEqual(null, sample.get_floor());
    try testing.expect(sample.awaits(replies.peer(0)));
    try replies.record(&sample, 0, 2);
    try replies.record(&sample, 1, 3);
    try testing.expectEqual(13, (try sample.select(4, Judge{})).?.view().get());
}
