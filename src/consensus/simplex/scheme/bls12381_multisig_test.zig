//! The multisig scheme over simplex subjects: a quorum of finalize votes aggregates into a
//! finalization that verifies only for its own subject and survives the message codec.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const types = @import("../types.zig");
const multisig = @import("bls12381_multisig.zig");

const Digest = cryptography.Sha256.Digest;
const MinSig = cryptography.bls12381.primitives.MinSig;
const Scheme = multisig.Scheme(Digest, cryptography.ed25519.PublicKey, MinSig);
const Subject = types.Subject(Digest);
const Finalization = types.Finalization(Scheme, Digest);
const sequential = parallel.sequential;

test "a quorum of finalize votes aggregates into a finalization" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try multisig.fixture(Scheme, gpa, &rng, "simplex", 4);
    defer fixture.deinit(gpa);
    const proposal: types.Proposal(Digest) = .init(.new(.new(2), .new(5)), .new(4), .fill(5));
    const subject: Subject = .{ .finalize = &proposal };
    var votes: [3]Scheme.Attestation = undefined;
    for (&votes, fixture.schemes[0..3]) |*vote, *scheme| {
        vote.* = (try scheme.sign(gpa, subject)).?;
    }
    const verifier = &fixture.verifier;
    var finalization: Finalization = .{
        .proposal = proposal,
        .certificate = try verifier.assemble(gpa, &votes, sequential),
    };
    defer finalization.deinit(gpa);
    const certificate = &finalization.certificate;
    const verify = Scheme.verify_certificate;
    try testing.expect(try verify(verifier, gpa, &rng, subject, certificate, sequential));
    const notarize: Subject = .{ .notarize = &proposal };
    try testing.expect(!try verify(verifier, gpa, &rng, notarize, certificate, sequential));
    const bytes = try codec.encode(Finalization, gpa, finalization);
    defer gpa.free(bytes);
    try testing.expect(bytes.len <= Finalization.max_encode_size_for(4));
    const cfg = verifier.certificate_codec_config();
    var decoded = try codec.decode_cfg(Finalization, gpa, bytes, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(finalization));
}
