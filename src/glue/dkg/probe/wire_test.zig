//! Tests of the DKG probe's wire messages and payload bound (commonware
//! `glue/src/dkg/probe/limits.rs`).

const std = @import("std");
const testing = std.testing;
const broadcast = @import("broadcast");
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const wire = @import("wire.zig");
const mocks = @import("../tests/mocks.zig");

const gpa = testing.allocator;
const Digest = mocks.TestDigest;
const ed25519 = consensus.simplex.scheme.ed25519;
const S = ed25519.Scheme(Digest);
const V = consensus.marshal.standard.Standard(mocks.TestBlock);
const types = consensus.simplex.types;
const Proposal = types.Proposal(Digest);
const Finalization = types.Finalization(S, Digest);
const Message = wire.Message(S, V);
const Fixture = cryptography.certificate.mocks.Fixture(S);
const Epoch = consensus.Epoch;
const Round = consensus.Round;
/// Signing namespace for the certificates these tests assemble.
const namespace = "_COMMONWARE_GLUE_DKG_PROBE_LIMITS";

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
    const bytes = try message.encode(gpa);
    defer gpa.free(bytes);
    try testing.expectEqual(message.encode_size(), bytes.len);
    return bytes.len;
}

/// Checks every message against the payload bound; returns the finalization and block
/// response sizes (the finalization's with its certificate slack added).
fn check(participants: u32) !struct { usize, usize } {
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, namespace, participants);
    defer fixture.deinit(gpa);
    const max = std.math.maxInt(u64);
    const epoch: Epoch = .new(max);
    const round: Round = .new(epoch, .new(max));
    const digest = cryptography.Sha256.hash(&.{"block"});
    // Every signer, and the widest round and parent view.
    var finalization = try finalize_all(&fixture, Proposal.init(round, .new(max - 1), digest));
    defer finalization.deinit(gpa);
    const certificate_size = codec.encode_size(S.Certificate, finalization.certificate);
    const certificate_slack = S.max_certificate_size(participants) - certificate_size;

    // The bound is taken for the block the response carries.
    const context: mocks.TestContext = .{
        .round = round,
        .leader = fixture.participants[0],
        .parent = .{ .new(max - 1), digest },
    };
    const block = mocks.TestBlock.init(context, digest, .new(max), max);
    const bound = Message.max_encode_size(participants, codec.encode_size(mocks.TestBlock, block));
    var digested = try broadcast.Digested(mocks.TestBlock).precomputed(gpa, block, block.digest());
    defer digested.deinit();

    const messages = [_]Message{
        .{ .boundary_request = epoch },
        .{ .boundary_response = finalization },
        .{ .block_request = epoch },
        .{ .block_response = .{ .epoch = epoch, .block = digested } },
        .latest_request,
        .{ .latest_response = finalization },
    };
    var sizes: [messages.len]usize = undefined;
    for (&sizes, messages) |*size, message| {
        size.* = try encoded_len(message);
        try testing.expect(size.* <= bound);
    }
    // The finalization responses fall short of their bound by the unused width of the
    // certificate's signature-list prefix; with it added, the widest message reaches it.
    sizes[1] += certificate_slack;
    sizes[5] += certificate_slack;
    try testing.expectEqual(bound, std.mem.max(usize, &sizes));
    return .{ sizes[1], sizes[3] };
}

test "dkg probe: payload bound matches the widest encodings" {
    // commonware `widest_encodings`. Each response sets the bound for some committee: the
    // finalization response is narrower than the block response only for a committee of 1.
    // 127 and 128 sit on either side of the one-byte varint limit on a signature count.
    for ([_]u32{ 1, 4, 127, 128 }) |participants| {
        const finalization, const block = try check(participants);
        try testing.expectEqual(participants == 1, finalization < block);
    }
}

test "dkg probe: messages split into requests and responses" {
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, namespace, 4);
    defer fixture.deinit(gpa);
    const cfg = fixture.verifier.certificate_codec_config();
    const round: Round = .new(.new(3), .new(9));
    var finalization = try finalize_all(&fixture, Proposal.init(round, .new(8), .fill(7)));
    defer finalization.deinit(gpa);

    const requests = [_]Message{
        .{ .boundary_request = .new(5) },
        .{ .block_request = .new(6) },
        .latest_request,
    };
    for (requests) |message| {
        const bytes = try message.encode(gpa);
        defer gpa.free(bytes);
        const request = (try wire.read_request(gpa, bytes)).?;
        switch (message) {
            .boundary_request => |epoch| try testing.expectEqual(epoch, request.boundary),
            .block_request => |epoch| try testing.expectEqual(epoch, request.block),
            else => try testing.expect(request == .latest),
        }
        try testing.expectEqual(null, try wire.read_response(S, V, gpa, bytes, cfg));
    }
    const responses = [_]Message{
        .{ .boundary_response = finalization },
        .{ .latest_response = finalization },
    };
    for (responses) |message| {
        const bytes = try message.encode(gpa);
        defer gpa.free(bytes);
        try testing.expectEqual(null, try wire.read_request(gpa, bytes));
        var response = (try wire.read_response(S, V, gpa, bytes, cfg)).?;
        defer response.deinit(gpa);
        const decoded = switch (response) {
            .boundary, .latest => |value| value,
            .block => unreachable,
        };
        try testing.expectEqual(message == .boundary_response, response == .boundary);
        try testing.expect(decoded.proposal.eql(finalization.proposal));
    }
    // Unknown tags and trailing bytes are rejected.
    try testing.expectError(error.InvalidEnum, wire.read_request(gpa, &.{6}));
    try testing.expectError(error.InvalidEnum, wire.read_response(S, V, gpa, &.{6}, cfg));
    try testing.expectError(error.ExtraData, wire.read_request(gpa, &.{ 4, 0 }));
}

test "dkg probe: a block response body decodes against its commitment" {
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, namespace, 1);
    defer fixture.deinit(gpa);
    const context: mocks.TestContext = .{
        .round = .new(.new(2), .new(4)),
        .leader = fixture.participants[0],
        .parent = .{ .new(3), .fill(1) },
    };
    const block = mocks.TestBlock.init(context, .fill(1), .new(7), 11);
    var digested = try broadcast.Digested(mocks.TestBlock).precomputed(gpa, block, block.digest());
    defer digested.deinit();
    const message: Message = .{ .block_response = .{ .epoch = .new(2), .block = digested } };
    const bytes = try message.encode(gpa);
    defer gpa.free(bytes);
    const cfg = fixture.verifier.certificate_codec_config();
    const response = (try wire.read_response(S, V, gpa, bytes, cfg)).?;
    try testing.expectEqual(Epoch.new(2), response.block.epoch);
    const body = response.block.body;
    var decoded = try wire.read_block(V, gpa, body, block.digest(), {}, parallel.sequential);
    defer decoded.deinit();
    try testing.expect(decoded.digest().eql(block.digest()));
    // A body bound to another commitment is rejected.
    const other = cryptography.Sha256.hash(&.{"other"});
    if (wire.read_block(V, gpa, response.block.body, other, {}, parallel.sequential)) |value| {
        var wrong = value;
        wrong.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
}
