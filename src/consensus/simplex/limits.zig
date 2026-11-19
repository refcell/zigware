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

const build_options = @import("build_options");
const builtin = @import("builtin");
const parallel = @import("parallel");
const ed25519 = @import("scheme/ed25519.zig");
const secp256r1 = @import("scheme/secp256r1.zig");
const multisig = @import("scheme/bls12381_multisig.zig");
const standard = @import("scheme/bls12381_threshold/standard.zig");
const MinPk = cryptography.bls12381.primitives.MinPk;
const Key = cryptography.ed25519.PublicKey;
const namespace = "_COMMONWARE_CONSENSUS_SIMPLEX_LIMITS";
/// BLS signing with the largest committees takes minutes in Debug; slow builds run them.
const large = builtin.mode != .debug or build_options.slow_tests;

/// commonware `check`: encoded messages from a real fixture against their bounds, and the
/// bounds against their field types.
fn check(comptime S: type, fixture: anytype) !void {
    const gpa = testing.allocator;
    const schemes = fixture.schemes;
    const participants: u32 = @intCast(schemes.len);
    const bound = max_payload_size(S, Digest, participants);
    // Use the widest round, parent view, and signer encodings.
    const max = std.math.maxInt(u64);
    const at = consensus_types.Round.new(.new(max), .new(max));
    var rng = utils.rng.test_rng();
    var digest: Digest = undefined;
    rng.fill_bytes(&digest.bytes);
    const proposal = types.Proposal(Digest).init(at, .new(max - 1), digest);
    const notarizes = try gpa.alloc(types.Notarize(S, Digest), schemes.len);
    defer gpa.free(notarizes);
    const nullifies = try gpa.alloc(types.Nullify(S), schemes.len);
    defer gpa.free(nullifies);
    const finalizes = try gpa.alloc(types.Finalize(S, Digest), schemes.len);
    defer gpa.free(finalizes);
    for (schemes, notarizes, nullifies, finalizes) |*scheme, *notarize, *nullify, *finalize| {
        notarize.* = (try types.Notarize(S, Digest).sign(gpa, scheme, proposal)).?;
        nullify.* = (try types.Nullify(S).sign(gpa, scheme, at)).?;
        finalize.* = (try types.Finalize(S, Digest).sign(gpa, scheme, proposal)).?;
    }
    // The largest vote has the widest signer.
    const widest: utils.Participant = .init(std.math.maxInt(u32));
    const Vote = types.Vote(S, Digest);
    var votes = [_]Vote{
        .{ .notarize = notarizes[0] },
        .{ .nullify = nullifies[0] },
        .{ .finalize = finalizes[0] },
    };
    votes[0].notarize.attestation.signer = widest;
    votes[1].nullify.attestation.signer = widest;
    votes[2].finalize.attestation.signer = widest;
    var vote_max: usize = 0;
    for (votes) |vote| vote_max = @max(vote_max, codec.encode_size(Vote, vote));
    try testing.expectEqual(Vote.max_encode_size, vote_max);
    try check_certificates(S, &schemes[0], notarizes, nullifies, finalizes, vote_max, bound);
}

/// The largest certificate has every signer.
fn check_certificates(
    comptime S: type,
    scheme: *const S,
    notarizes: []const types.Notarize(S, Digest),
    nullifies: []const types.Nullify(S),
    finalizes: []const types.Finalize(S, Digest),
    vote_max: usize,
    bound: usize,
) !void {
    const gpa = testing.allocator;
    const sequential = parallel.sequential;
    const Certificate = types.Certificate(S, Digest);
    var certificates = [_]Certificate{
        .{ .notarization = try .from_votes(gpa, scheme, notarizes, sequential) },
        .{ .nullification = try .from_votes(gpa, scheme, nullifies, sequential) },
        .{ .finalization = try .from_votes(gpa, scheme, finalizes, sequential) },
    };
    defer for (&certificates) |*certificate| certificate.deinit(gpa);
    var encoded: usize = 0;
    for (certificates) |certificate| {
        encoded = @max(encoded, codec.encode_size(Certificate, certificate));
    }
    const participants: u32 = @intCast(notarizes.len);
    const certificate = Certificate.max_encode_size_for(participants);
    try testing.expect(encoded <= certificate);
    const proposal_size = types.Proposal(Digest).max_encode_size;
    try testing.expectEqual(1 + proposal_size + S.max_certificate_size(participants), certificate);
    // A resolver response at the certificate bound outsizes both the largest vote and a
    // request for the largest view, so it sets the payload bound.
    const wire = resolver.p2p.wire;
    const request = codec.encode_size(utils.sequence.U64, .init(std.math.maxInt(u64))) +
        wire.request_overhead;
    const response = certificate + wire.response_overhead_max;
    try testing.expect(vote_max < response and request < response);
    try testing.expect(encoded + wire.response_overhead_max <= bound);
    try testing.expectEqual(response, bound);
}

/// Committees of 127 and 128 sit on either side of the one-byte varint limit on a signature
/// list's length.
const participants_all = [_]u32{ 1, 4, 127, 128 };

fn check_each(comptime S: type, comptime make: anytype) !void {
    const gpa = testing.allocator;
    for (participants_all) |n| {
        if (n > 4 and !large) continue;
        var rng = utils.rng.test_rng();
        var fixture = try make(S, gpa, &rng, namespace, n);
        defer fixture.deinit(gpa);
        try check(S, fixture);
    }
}

fn make_ed25519(
    comptime S: type,
    gpa: std.mem.Allocator,
    rng: anytype,
    ns: []const u8,
    n: u32,
) !cryptography.certificate.mocks.Fixture(S) {
    return ed25519.fixture(Digest, gpa, rng, ns, n);
}

test "widest encodings meet the bounds (ed25519)" {
    try check_each(ed25519.Scheme(Digest), make_ed25519);
}

test "widest encodings meet the bounds (secp256r1)" {
    try check_each(secp256r1.Scheme(Digest, Key), secp256r1.fixture);
}

test "widest encodings meet the bounds (bls12381 multisig)" {
    try check_each(multisig.Scheme(Digest, Key, MinPk), multisig.fixture);
    try check_each(multisig.Scheme(Digest, Key, MinSig), multisig.fixture);
}

test "widest encodings meet the bounds (bls12381 threshold)" {
    // A threshold certificate has one size for every committee.
    const gpa = testing.allocator;
    const sizes = [_]u32{ 4, 33 };
    inline for (.{ MinPk, MinSig }) |V| {
        inline for (.{
            .{ standard.Scheme(Digest, Key, V), standard.fixture },
            .{ vrf.Scheme(Digest, Key, V), vrf.fixture },
        }) |entry| {
            for (sizes) |n| {
                if (n > 4 and !large) continue;
                var rng = utils.rng.test_rng();
                var fixture = try entry[1](entry[0], gpa, &rng, namespace, n);
                defer fixture.deinit(gpa);
                try check(entry[0], fixture);
            }
        }
    }
}
