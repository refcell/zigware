//! Marshal's message size bounds (commonware `marshal/limits.rs`).
//!
//! `max_payload_size(V, S, participants, block_config)` bounds every payload marshal sends:
//! resolver requests and responses on the backfill network (a block, a notarization with its
//! backfill block, or a finalization with its application block) and its buffer's
//! broadcasts. Size each p2p channel with it.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const resolver = @import("resolver");
const simplex_types = @import("../simplex/types.zig");
const variant = @import("core/variant.zig");
const handler = @import("resolver/handler.zig");

/// The largest backfill message for an application block of at most `application` bytes.
pub fn max_backfill_size(
    comptime V: type,
    comptime S: type,
    participants: u32,
    application: usize,
) usize {
    comptime variant.assert_variant(V);
    const block = V.max_backfill_block_size(application);
    const Notarization = simplex_types.Notarization(S, V.Commitment);
    const Finalization = simplex_types.Finalization(S, V.Commitment);
    const notarized = Notarization.max_encode_size_for(participants) + block;
    const finalized = Finalization.max_encode_size_for(participants) + application;
    const value_size = @max(block, notarized, finalized);
    assert(value_size >= block);
    return resolver.p2p.wire.max_message_size(handler.Key(V.Commitment), value_size);
}

/// The largest encoded application block under `block_config`: a block declares
/// `max_encode_size_for(config)` when its bound depends on the configuration, or a constant
/// `max_encode_size` (commonware `BoundedBlock::max_encode_size`).
pub fn max_block_size(comptime B: type, block_config: codec.Cfg(B)) usize {
    if (comptime @hasDecl(B, "max_encode_size_for")) return B.max_encode_size_for(block_config);
    return comptime codec.max_encode_size(B).?;
}

/// The largest payload marshal sends for a committee of `participants`.
pub fn max_payload_size(
    comptime V: type,
    comptime S: type,
    participants: u32,
    block_config: codec.Cfg(V.ApplicationBlock),
) usize {
    const application = max_block_size(V.ApplicationBlock, block_config);
    const backfill = max_backfill_size(V, S, participants, application);
    return @max(backfill, V.max_buffer_payload_size(participants, application));
}

const testing = std.testing;
const builtin = @import("builtin");
const build_options = @import("build_options");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const simplex_scheme = @import("../simplex/root.zig").scheme;
const standard = @import("standard/variant.zig");
const mocks_block = @import("mocks/block.zig");

const Sha256 = cryptography.Sha256;
const PublicKey = cryptography.ed25519.PublicKey;
const MinPk = cryptography.bls12381.primitives.MinPk;
const MinSig = cryptography.bls12381.primitives.MinSig;
const StandardVariant = standard.Standard(mocks_block.EmptyBlock(Sha256));
const namespace = "_COMMONWARE_CONSENSUS_MARSHAL_LIMITS";

/// Checks that the backfill bound is exactly a proposal, the scheme's largest certificate, a
/// backfill block, and the response overhead, and that every request and every certificate
/// assembled from a quorum or the full committee fits it.
fn check_encoding(
    comptime V: type,
    comptime S: type,
    fixture: anytype,
    application: usize,
) !void {
    const gpa = testing.allocator;
    const schemes = fixture.schemes;
    const participants: u32 = @intCast(schemes.len);
    const D = V.Commitment;
    const Proposal = simplex_types.Proposal(D);
    const backfill = max_backfill_size(V, S, participants, application);
    const block = V.max_backfill_block_size(application);
    const max_certificate_size = S.max_certificate_size(participants);
    const wire = resolver.p2p.wire;
    try testing.expectEqual(
        Proposal.max_encode_size + max_certificate_size + block + wire.response_overhead_max,
        backfill,
    );
    const max = std.math.maxInt(u64);
    const keys = [_]handler.Key(D){
        .{ .block = D.fill(1) },
        .{ .finalized = .new(max) },
        .{ .notarized = .new(.new(max), .new(max)) },
    };
    for (keys) |key| try testing.expect(key.encode_size() + wire.request_overhead <= backfill);
    try testing.expect(block + wire.response_overhead_max <= backfill);

    const quorum = schemes[0].participants().quorum(utils.N3f1);
    for ([_]u64{ 1, 127, 128, max }) |view| {
        const round: consensus_types.Round = .new(.new(view), .new(view));
        const proposal = Proposal.init(round, .new(view - 1), D.fill(@truncate(view)));
        for ([_]u32{ quorum, participants }) |count| {
            const Notarize = simplex_types.Notarize(S, D);
            const votes = try gpa.alloc(Notarize, count);
            defer gpa.free(votes);
            for (votes, schemes[0..count]) |*vote, *scheme| {
                vote.* = (try Notarize.sign(gpa, scheme, proposal)).?;
            }
            defer for (votes) |*vote| free_attestation(S, gpa, &vote.attestation);
            const Notarization = simplex_types.Notarization(S, D);
            const strategy = parallel.sequential;
            var notarization = try Notarization.from_votes(gpa, &schemes[0], votes, strategy);
            defer free_certificate(S, gpa, &notarization.certificate);
            const certificate_size = codec.encode_size(S.Certificate, notarization.certificate);
            try testing.expect(certificate_size <= max_certificate_size);
            const encoded = try codec.encode(S.Certificate, gpa, notarization.certificate);
            defer gpa.free(encoded);
            const config = fixture.verifier.certificate_codec_config();
            var decoded = try codec.decode_cfg(S.Certificate, gpa, encoded, config);
            free_certificate(S, gpa, &decoded);
            const notarized = codec.encode_size(Notarization, notarization) + block;
            // A finalization has the same encoding as a notarization of the same proposal.
            const finalized = codec.encode_size(Notarization, notarization) + application;
            try testing.expect(notarized + wire.response_overhead_max <= backfill);
            try testing.expect(finalized + wire.response_overhead_max <= backfill);
        }
    }
}

fn free_attestation(comptime S: type, gpa: std.mem.Allocator, attestation: anytype) void {
    if (comptime @hasDecl(S.Signature, "deinit")) attestation.signature.deinit(gpa);
}

fn free_certificate(comptime S: type, gpa: std.mem.Allocator, certificate: *S.Certificate) void {
    if (comptime @hasDecl(S.Certificate, "deinit")) certificate.deinit(gpa);
}

fn check_fixture(
    comptime V: type,
    comptime S: type,
    comptime build: anytype,
    participants: u32,
    application: usize,
) !void {
    var rng = utils.rng.TestRng.init(0);
    var fixture = try build(S, testing.allocator, &rng, namespace, participants);
    defer fixture.deinit(testing.allocator);
    try check_encoding(V, S, fixture, application);
}

fn skip_slow() error{SkipZigTest}!void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
}

test "variable certificate overhead (ed25519)" {
    const S = simplex_scheme.ed25519.Scheme(Sha256.Digest);
    const fixture = cryptography.ed25519.certificate.fixture;
    try check_fixture(StandardVariant, S, fixture, 4, 1000);
    try check_fixture(StandardVariant, S, fixture, 128, 1000);
    // The standard buffer broadcasts whole blocks, which the backfill bound covers.
    const application = mocks_block.EmptyBlock(Sha256).max_encode_size;
    const backfill = max_backfill_size(StandardVariant, S, 4, application);
    try testing.expectEqual(backfill, max_payload_size(StandardVariant, S, 4, {}));
}

test "variable and fixed certificate overhead (secp256r1 and bls12381)" {
    try skip_slow();
    const D = Sha256.Digest;
    const secp = simplex_scheme.secp256r1;
    try check_fixture(StandardVariant, secp.Scheme(D, PublicKey), secp.fixture, 4, 0);
    const V = StandardVariant;
    const multisig = simplex_scheme.bls12381_multisig;
    try check_fixture(V, multisig.Scheme(D, PublicKey, MinSig), multisig.fixture, 4, 0);
    try check_fixture(V, multisig.Scheme(D, PublicKey, MinPk), multisig.fixture, 4, 1000);
    const threshold = simplex_scheme.bls12381_threshold.standard;
    try check_fixture(V, threshold.Scheme(D, PublicKey, MinSig), threshold.fixture, 4, 0);
    try check_fixture(V, threshold.Scheme(D, PublicKey, MinPk), threshold.fixture, 4, 1000);
    const vrf = simplex_scheme.bls12381_threshold.vrf;
    try check_fixture(V, vrf.Scheme(D, PublicKey, MinSig), vrf.fixture, 4, 0);
    try check_fixture(V, vrf.Scheme(D, PublicKey, MinPk), vrf.fixture, 4, 1000);
}
