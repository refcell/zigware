//! Tests of the DKG probe's boundary decoding (commonware
//! `glue/src/dkg/probe/actor/discovery.rs` `mod tests`): a boundary finalization authenticates
//! the commitment its block is decoded against, for the standard and coding marshal variants
//! and for the mock and BLS threshold schemes.
//!
//! commonware's `CodingBlock` wraps its `MockBlock` over a coding context; here marshal's
//! `mocks.Block(Sha256, CodingContext)` plays that role (the tests check decoding, not
//! digests).

const std = @import("std");
const testing = std.testing;
const coding = @import("coding");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const wire = @import("wire.zig");
const mocks = @import("../tests/mocks.zig");

const gpa = testing.allocator;
const seq = parallel.sequential;
const P = mocks.TestPublicKey;
const Digest = mocks.TestDigest;
const Sha256 = cryptography.sha256.Sha256;
const MinPk = cryptography.bls12381.primitives.MinPk;
const simplex = consensus.simplex.types;
const marshal = consensus.marshal;
const certificate_mocks = cryptography.certificate.mocks;
const Scoped = cryptography.certificate.Scoped;

const RS = coding.ReedSolomon(Sha256);
const Commitment = consensus.types.coding.Commitment(Digest, RS.Commitment, Digest);
const CodingContext = simplex.Context(Commitment, P);
const CodingBlock = marshal.mocks.Block(Sha256, CodingContext);
const CodingVariant = marshal.coding.Coding(CodingBlock, RS, Sha256, P);
const MockScheme = certificate_mocks.Scheme(simplex.Subject(Commitment), utils.N3f1, P, .{});
const ThresholdScheme = consensus.simplex.scheme.bls12381_threshold.vrf.Scheme(
    Commitment,
    P,
    MinPk,
);
const threshold_namespace = "_COMMONWARE_GLUE_DKG_PROBE_DISCOVERY_TEST";
const mock_namespace = "_COMMONWARE_GLUE_DKG_TEST";

/// commonware's `finalization`: every scheme in `schemes` finalizes `proposal`.
fn finalize(
    comptime S: type,
    comptime D: type,
    schemes: []const S,
    proposal: simplex.Proposal(D),
) !simplex.Finalization(S, D) {
    const Finalize = simplex.Finalize(S, D);
    var votes: [4]Finalize = undefined;
    for (schemes, votes[0..schemes.len]) |*scheme, *vote| {
        vote.* = (try Finalize.sign(gpa, scheme, proposal)).?;
    }
    const Finalization = simplex.Finalization(S, D);
    return Finalization.from_votes(gpa, &schemes[0], votes[0..schemes.len], seq);
}

fn proposal_at(comptime D: type, payload: D) simplex.Proposal(D) {
    return .init(.new(.zero(), .new(1)), .zero(), payload);
}

/// commonware's `coding_block`: a height-1 block coded for `participants` participants.
fn coding_block(leader: P, participants: u16) !CodingVariant.Block {
    const config = marshal.coding.coding_config_for_participants(participants);
    const context: CodingContext = .{
        .round = .new(.zero(), .new(1)),
        .leader = leader,
        .parent = .{ .zero(), .init(.empty, .empty, .empty, config) },
    };
    const parent = Sha256.hash(&.{"parent"});
    const block = try CodingBlock.init(gpa, context, parent, .new(1), 0);
    const Inner = @FieldType(CodingVariant.Block, "inner_value");
    return CodingVariant.Block.encode(gpa, try Inner.compute(gpa, block), config, seq);
}

/// Encodes `message`, then decodes its boundary finalization (owned by the caller).
fn decode_finalization(
    comptime S: type,
    comptime V: type,
    message: wire.Message(S, V),
    verifier: *const S,
) !simplex.Finalization(S, V.Commitment) {
    const bytes = try message.encode(gpa);
    defer gpa.free(bytes);
    const cfg = Scoped(S).verifier(verifier).certificate_codec_config();
    var response = (try wire.read_response(S, V, gpa, bytes, cfg)).?;
    errdefer response.deinit(gpa);
    if (response != .boundary) return error.ExpectedFinalizationResponse;
    return response.boundary;
}

fn verify(comptime S: type, finalization: anytype, verifier: *const S) !bool {
    var rng = utils.rng.TestRng.init(7);
    return finalization.verify(gpa, &rng, Scoped(S).verifier(verifier), seq);
}

/// Encodes a block response for `block`, splits off its epoch, and decodes the body against
/// `commitment` (the decoded block is owned by the caller).
fn decode_block(
    comptime S: type,
    comptime V: type,
    block: V.Block,
    commitment: V.Commitment,
    verifier: *const S,
) !V.Block {
    const response_value: wire.Message(S, V).BlockResponse = .{ .epoch = .zero(), .block = block };
    const message: wire.Message(S, V) = .{ .block_response = response_value };
    const bytes = try message.encode(gpa);
    defer gpa.free(bytes);
    const cfg = Scoped(S).verifier(verifier).certificate_codec_config();
    var response = (try wire.read_response(S, V, gpa, bytes, cfg)).?;
    defer response.deinit(gpa);
    if (response != .block) return error.ExpectedBlockResponse;
    try testing.expectEqual(0, response.block.epoch.get());
    return wire.read_block(V, gpa, response.block.body, commitment, {}, seq);
}

fn threshold_fixture() !certificate_mocks.Fixture(ThresholdScheme) {
    var rng = utils.rng.TestRng.init(0);
    const vrf = consensus.simplex.scheme.bls12381_threshold.vrf;
    return vrf.fixture(ThresholdScheme, gpa, &rng, threshold_namespace, 4);
}

fn mock_fixture(comptime S: type) !certificate_mocks.Fixture(S) {
    var rng = utils.rng.TestRng.init(0);
    return certificate_mocks.fixture(S, gpa, &rng, mock_namespace, 4);
}

/// Decodes a valid coding block after authenticating its finalization under `verifier`.
fn expect_coding_block_decodes(
    comptime S: type,
    fixture: *const certificate_mocks.Fixture(S),
    verifier: *const S,
) !void {
    var block = try coding_block(fixture.participants[0], 4);
    defer block.deinit(gpa);
    const payload = CodingVariant.commitment(&block);
    var signed = try finalize(S, Commitment, fixture.schemes, proposal_at(Commitment, payload));
    defer signed.deinit(gpa);
    const message: wire.Message(S, CodingVariant) = .{ .boundary_response = signed };
    var finalization = try decode_finalization(S, CodingVariant, message, verifier);
    defer finalization.deinit(gpa);
    try testing.expect(try verify(S, &finalization, verifier));
    const commitment = finalization.proposal.payload;
    var decoded = try decode_block(S, CodingVariant, block, commitment, verifier);
    defer decoded.deinit(gpa);
    try testing.expectEqual(1, decoded.height().get());
    try testing.expect(CodingVariant.commitment(&decoded).eql(payload));
    // The finalized payload fixes the root, so the probe decodes without re-encoding.
    try testing.expect(try decoded.shard(gpa, 0) == null);
}

test "dkg probe discovery: an invalid coding finalization fails before a block request" {
    var fixture = try threshold_fixture();
    defer fixture.deinit(gpa);
    const identity = fixture.verifier.identity();
    var verifier = try ThresholdScheme.certificate_verifier(gpa, threshold_namespace, identity);
    defer verifier.deinit(gpa);
    var block = try coding_block(fixture.participants[0], 4);
    defer block.deinit(gpa);
    const payload = CodingVariant.commitment(&block);
    const proposal = proposal_at(Commitment, payload);
    var signed = try finalize(ThresholdScheme, Commitment, fixture.schemes, proposal);
    defer signed.deinit(gpa);
    signed.proposal.payload = .init(
        Sha256.hash(&.{"tampered block"}),
        Sha256.hash(&.{"tampered root"}),
        Sha256.hash(&.{"tampered context"}),
        marshal.coding.coding_config_for_participants(4),
    );
    const message: wire.Message(ThresholdScheme, CodingVariant) = .{ .boundary_response = signed };
    var finalization = try decode_finalization(ThresholdScheme, CodingVariant, message, &verifier);
    defer finalization.deinit(gpa);
    try testing.expect(!try verify(ThresholdScheme, &finalization, &verifier));
}

test "dkg probe discovery: a valid standard block decodes after authentication" {
    const S = mocks_scheme;
    const V = marshal.standard.Standard(mocks.TestBlock);
    var fixture = try mock_fixture(S);
    defer fixture.deinit(gpa);
    const verifier = &fixture.schemes[0];
    const block = mocks.genesis_block(fixture.participants[0]);
    const proposal = proposal_at(Digest, block.digest());
    var signed = try finalize(S, Digest, fixture.schemes, proposal);
    defer signed.deinit(gpa);
    const message: wire.Message(S, V) = .{ .boundary_response = signed };
    var finalization = try decode_finalization(S, V, message, verifier);
    defer finalization.deinit(gpa);
    try testing.expect(try verify(S, &finalization, verifier));
    var digested = try V.Block.precomputed(gpa, block, block.digest());
    defer digested.deinit();
    const commitment = finalization.proposal.payload;
    var decoded = try decode_block(S, V, digested, commitment, verifier);
    defer decoded.deinit();
    try testing.expect(decoded.inner().eql(block));
}

test "dkg probe discovery: a valid coding block decodes after authentication" {
    var fixture = try mock_fixture(MockScheme);
    defer fixture.deinit(gpa);
    try expect_coding_block_decodes(MockScheme, &fixture, &fixture.schemes[0]);
}

test "dkg probe discovery: a valid coding block decodes with a certificate verifier" {
    var fixture = try threshold_fixture();
    defer fixture.deinit(gpa);
    const identity = fixture.verifier.identity();
    var verifier = try ThresholdScheme.certificate_verifier(gpa, threshold_namespace, identity);
    defer verifier.deinit(gpa);
    try expect_coding_block_decodes(ThresholdScheme, &fixture, &verifier);
}

/// commonware's `simplex::mocks::scheme`, the `TestScheme` of glue's DKG tests.
const mocks_scheme = @import("../state_sync_test.zig").Scheme;
