//! Size limits for the payloads simplex sends (commonware `simplex/limits.rs`).

const std = @import("std");
const assert = std.debug.assert;
const resolver = @import("resolver");
const utils = @import("utils");
const types = @import("types.zig");

/// An upper bound on the payloads simplex sends for committees of at most `participants`.
///
/// Votes and certificates go out without framing. The resolver requests a certificate by view
/// (a `U64` key) and returns one as a response value. The largest of the three bounds, with
/// every varint at its widest, is the payload bound.
pub fn max_payload_size(comptime S: type, comptime D: type, participants: u32) usize {
    const certificate = types.Certificate(S, D).max_encode_size_for(participants);
    const resolved = resolver.p2p.wire.max_message_size(utils.sequence.U64, certificate);
    const result = @max(types.Vote(S, D).max_encode_size, certificate, resolved);
    assert(result >= certificate);
    return result;
}

const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const vrf = @import("scheme/bls12381_threshold/vrf.zig");
const consensus_types = @import("../types.zig");

const MinSig = cryptography.bls12381.primitives.MinSig;
const Digest = cryptography.Sha256.Digest;

/// The wire types of `bls12381_threshold::vrf::Scheme<_, MinSig>`.
const Scheme = struct {
    pub const Signature = vrf.Signature(MinSig);
    pub const Certificate = vrf.Certificate(MinSig);

    pub fn max_certificate_size(_: u32) usize {
        return vrf.Certificate(MinSig).fixed_size;
    }
};

test "widest encodings meet the bounds (threshold vrf wire types)" {
    const max = std.math.maxInt(u64);
    const at = consensus_types.Round.new(.new(max), .new(max));
    const proposal = types.Proposal(Digest).init(at, .new(max - 1), .fill(7));
    const G1 = MinSig.Signature;
    const signature: Scheme.Signature = .{
        .vote_signature = G1.generator,
        .seed_signature = G1.generator,
    };
    const attestation = types.Attestation(Scheme).init(.init(std.math.maxInt(u32)), signature);
    const Vote = types.Vote(Scheme, Digest);
    const votes = [_]Vote{
        .{ .notarize = .{ .proposal = proposal, .attestation = attestation } },
        .{ .nullify = .{ .round = at, .attestation = attestation } },
        .{ .finalize = .{ .proposal = proposal, .attestation = attestation } },
    };
    var vote_max: usize = 0;
    for (votes) |vote| vote_max = @max(vote_max, codec.encode_size(Vote, vote));
    try testing.expectEqual(Vote.max_encode_size, vote_max);

    const Certificate = types.Certificate(Scheme, Digest);
    const certificate: Certificate = .{ .finalization = .{
        .proposal = proposal,
        .certificate = .init(signature),
    } };
    const encoded_certificate = codec.encode_size(Certificate, certificate);
    const bound = Certificate.max_encode_size_for(4);
    try testing.expectEqual(bound, encoded_certificate);
    try testing.expectEqual(1 + types.Proposal(Digest).max_encode_size + 2 * 48, bound);

    // A resolver response at the certificate bound outsizes the largest vote and a request for
    // the largest view, so it sets the payload bound.
    const wire = resolver.p2p.wire;
    const request = 8 + wire.request_overhead;
    const response = bound + wire.response_overhead_max;
    try testing.expect(vote_max < response and request < response);
    try testing.expectEqual(response, max_payload_size(Scheme, Digest, 4));
}
