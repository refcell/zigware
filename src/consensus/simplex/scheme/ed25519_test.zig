//! The ed25519 scheme over simplex subjects: votes sign under per-kind namespaces, and a
//! quorum of votes assembles into a certificate that carries through the message codecs.
//! The scheme itself is tested by the crypto lane.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const types = @import("../types.zig");
const Round = @import("../../types.zig").Round;
const ed25519 = @import("ed25519.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const Subject = types.Subject(Digest);
const Proposal = types.Proposal(Digest);
const Notarization = types.Notarization(Scheme, Digest);
const Notarize = types.Notarize(Scheme, Digest);
const sequential = parallel.sequential;

fn proposal(view: u64) Proposal {
    const round: Round = .new(.new(1), .new(view));
    return .init(round, .new(view - 1), .fill(@intCast(view)));
}

test "simplex subjects sign under their own namespaces" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "simplex", 4);
    defer fixture.deinit(gpa);
    const p = proposal(3);
    const notarize: Subject = .{ .notarize = &p };
    const finalize: Subject = .{ .finalize = &p };
    const verifier = &fixture.verifier;
    for (fixture.schemes, 0..) |*scheme, index| {
        try testing.expectEqual(index, scheme.me().?.signer.get());
        const attestation = (try scheme.sign(gpa, notarize)).?;
        try testing.expect(try verifier.verify_attestation(gpa, &rng, notarize, &attestation, {}));
        // The same proposal signed for notarize does not verify as finalize.
        try testing.expect(!try verifier.verify_attestation(gpa, &rng, finalize, &attestation, {}));
    }
    try testing.expectEqual(null, try verifier.sign(gpa, notarize));
}

test "a quorum of notarize votes makes a notarization that survives the codec" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "simplex", 4);
    defer fixture.deinit(gpa);
    const p = proposal(7);
    const subject: Subject = .{ .notarize = &p };
    var votes: [3]Scheme.Attestation = undefined;
    for (&votes, fixture.schemes[1..]) |*vote, *scheme| vote.* = (try scheme.sign(gpa, subject)).?;

    // A vote round-trips through the wire format.
    const vote: Notarize = .{ .proposal = p, .attestation = votes[0] };
    const vote_bytes = try codec.encode(Notarize, gpa, vote);
    defer gpa.free(vote_bytes);
    try testing.expect((try codec.decode(Notarize, gpa, vote_bytes)).eql(vote));

    const scheme = &fixture.schemes[0];
    var notarization: Notarization = .{
        .proposal = p,
        .certificate = try scheme.assemble(gpa, &votes, sequential),
    };
    defer notarization.deinit(gpa);
    const certificate = &notarization.certificate;
    try testing.expect(try scheme.verify_certificate(gpa, &rng, subject, certificate, sequential));
    const bytes = try codec.encode(Notarization, gpa, notarization);
    defer gpa.free(bytes);
    try testing.expect(bytes.len <= Notarization.max_encode_size_for(4));
    var decoded = try codec.decode_cfg(Notarization, gpa, bytes, scheme.certificate_codec_config());
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(notarization));
    // The certificate does not verify for the finalize subject or another proposal.
    const other = proposal(8);
    const wrong = [_]Subject{ .{ .finalize = &p }, .{ .notarize = &other } };
    for (wrong) |bad| {
        try testing.expect(!try scheme.verify_certificate(gpa, &rng, bad, certificate, sequential));
    }
}
