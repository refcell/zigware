//! Tests of the simplex wire types (commonware `simplex/types.rs` tests that need no signing
//! scheme), and every simplex `CodecConformance` hash in commonware's
//! `consensus/conformance.toml`.
//!
//! Commonware's conformance values use `bls12381_threshold::vrf::Scheme<ed25519::PublicKey,
//! MinSig>`; the messages only need its wire types, `vrf.Signature(MinSig)` and
//! `vrf.Certificate(MinSig)`. The encode/decode tests that sign with each scheme follow with
//! the schemes.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");
const codec = @import("codec");
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const types = @import("types.zig");
const vrf = @import("scheme/bls12381_threshold/vrf.zig");

const Round = consensus_types.Round;
const View = consensus_types.View;
const Participant = consensus_types.Participant;
const MinSig = cryptography.bls12381.primitives.MinSig;
const Sha256 = cryptography.Sha256;
const ed25519 = cryptography.ed25519;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;

/// A SHA-256 digest with commonware's `Arbitrary` (hash of up to 256 drawn bytes).
const Digest = struct {
    inner: Sha256.Digest,

    pub const fixed_size: usize = 32;

    fn fill(byte: u8) Digest {
        return .{ .inner = .fill(byte) };
    }

    pub fn order(a: Digest, b: Digest) std.math.Order {
        return a.inner.order(b.inner);
    }

    pub fn write(self: Digest, writer: *codec.Writer) void {
        self.inner.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Digest {
        return .{ .inner = try Sha256.Digest.read(gpa, reader, {}) };
    }

    pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Digest {
        const len = u.int_in_range(u64, 0, 256);
        const data = try gpa.alloc(u8, len);
        try u.bytes(data);
        return .{ .inner = Sha256.hash(&.{data}) };
    }
};

/// The wire types of `bls12381_threshold::vrf::Scheme<_, MinSig>`.
const Scheme = struct {
    pub const Signature = vrf.Signature(MinSig);
    pub const Certificate = vrf.Certificate(MinSig);

    pub fn max_certificate_size(_: u32) usize {
        return vrf.Certificate(MinSig).fixed_size;
    }
};

const Proposal = types.Proposal(Digest);
const Notarize = types.Notarize(Scheme, Digest);
const Nullify = types.Nullify(Scheme);
const Finalize = types.Finalize(Scheme, Digest);
const Notarization = types.Notarization(Scheme, Digest);
const Nullification = types.Nullification(Scheme);
const Finalization = types.Finalization(Scheme, Digest);
const ConflictingNotarize = types.ConflictingNotarize(Scheme, Digest);
const ConflictingFinalize = types.ConflictingFinalize(Scheme, Digest);
const NullifyFinalize = types.NullifyFinalize(Scheme, Digest);
const Vote = types.Vote(Scheme, Digest);
const Certificate = types.Certificate(Scheme, Digest);
const Artifact = types.Artifact(Scheme, Digest);
const Activity = types.Activity(Scheme, Digest);
const Context = types.Context(Digest, ed25519.PublicKey);

fn round(epoch: u64, view: u64) Round {
    return .new(.new(epoch), .new(view));
}

fn signature(seed: u8) Scheme.Signature {
    const G1 = MinSig.Signature;
    const scalar = cryptography.bls12381.primitives.group.Scalar.from_ikm(&@splat(seed));
    return .{ .vote_signature = G1.generator.mul(scalar), .seed_signature = G1.generator };
}

fn notarize(signer: u32, proposal: Proposal) Notarize {
    return .{ .proposal = proposal, .attestation = .init(.init(signer), signature(1)) };
}

fn finalize(signer: u32, proposal: Proposal) Finalize {
    return .{ .proposal = proposal, .attestation = .init(.init(signer), signature(2)) };
}

fn nullify(signer: u32, at: Round) Nullify {
    return .{ .round = at, .attestation = .init(.init(signer), signature(3)) };
}

fn expect_roundtrip(comptime T: type, value: T) !void {
    const encoded = try codec.encode(T, testing.allocator, value);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(codec.encode_size(T, value), encoded.len);
    const decoded = try codec.decode(T, testing.allocator, encoded);
    try testing.expect(decoded.eql(value));
}

test "proposal encode decode" {
    const proposal = Proposal.init(round(0, 10), .new(5), .fill(1));
    try expect_roundtrip(Proposal, proposal);
    // Round (epoch 0, view 10), parent view 5, then the 32-byte payload.
    const encoded = try codec.encode(Proposal, testing.allocator, proposal);
    defer testing.allocator.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 0, 10, 5 }, encoded[0..3]);
    try testing.expectEqual(3 + 32, encoded.len);
    try testing.expectEqual(.lt, Proposal.order(proposal, .init(round(0, 10), .new(6), .fill(0))));
}

test "votes, certificates, and unions roundtrip" {
    const proposal = Proposal.init(round(1, 10), .new(9), .fill(7));
    const other = Proposal.init(round(1, 10), .new(9), .fill(8));
    const certificate = Scheme.Certificate.init(signature(4));
    const notarization: Notarization = .{ .proposal = proposal, .certificate = certificate };
    const nullification: Nullification = .{ .round = round(1, 10), .certificate = certificate };
    try expect_roundtrip(Notarize, notarize(3, proposal));
    try expect_roundtrip(Nullify, nullify(3, round(1, 10)));
    try expect_roundtrip(Finalize, finalize(3, proposal));
    try expect_roundtrip(Notarization, notarization);
    try expect_roundtrip(Nullification, nullification);
    try expect_roundtrip(ConflictingNotarize, .init(notarize(2, proposal), notarize(2, other)));
    try expect_roundtrip(ConflictingFinalize, .init(finalize(2, proposal), finalize(2, other)));
    try expect_roundtrip(NullifyFinalize, .init(nullify(2, round(1, 10)), finalize(2, proposal)));
    try expect_roundtrip(Vote, .{ .nullify = nullify(4, round(1, 11)) });
    const finalization: Finalization = .{ .proposal = proposal, .certificate = certificate };
    try expect_roundtrip(Finalization, finalization);
    try expect_roundtrip(Certificate, .{ .finalization = finalization });
    const certification: types.Certification = .{ .round = round(2, 3), .certified = true };
    try expect_roundtrip(Artifact, .{ .certification = certification });
    try expect_roundtrip(Activity, .{ .certification = notarization });
    try testing.expect(!Vote.eql(.{ .notarize = notarize(1, proposal) }, .{
        .finalize = finalize(1, proposal),
    }));
    const activity: Activity = .{ .notarize = notarize(1, proposal) };
    try testing.expect(!activity.verified());
    try testing.expect((Activity{ .nullification = nullification }).verified());
    try testing.expectEqual(View.new(10), activity.view());
}

test "unions reject unknown tags" {
    try testing.expectError(error.Invalid, codec.decode(Vote, testing.allocator, &.{3}));
    try testing.expectError(error.Invalid, codec.decode(Certificate, testing.allocator, &.{3}));
    try testing.expectError(error.Invalid, codec.decode(Artifact, testing.allocator, &.{7}));
    try testing.expectError(error.Invalid, codec.decode(Activity, testing.allocator, &.{10}));
    // A known tag with no payload runs out of input instead.
    try testing.expectError(error.EndOfBuffer, codec.decode(Activity, testing.allocator, &.{9}));
}

test "deferred signatures decode lazily" {
    const proposal = Proposal.init(round(0, 1), .zero(), .fill(1));
    var bytes = try codec.encode(Notarize, testing.allocator, notarize(0, proposal));
    defer testing.allocator.free(bytes);
    // Corrupt the vote signature: the vote still decodes (and re-encodes unchanged), but its
    // signature does not.
    bytes[bytes.len - 96] ^= 0xff;
    const vote = try codec.decode(Notarize, testing.allocator, bytes);
    try testing.expectEqual(null, vote.attestation.signature.get());
    const again = try codec.encode(Notarize, testing.allocator, vote);
    defer testing.allocator.free(again);
    try testing.expectEqualSlices(u8, bytes, again);
}

// commonware issue 2944: conflicting evidence must name two different proposals from one
// signer in one round, and decoding rejects anything else.
test "issue 2944 regression: conflicting evidence decode" {
    const proposal = Proposal.init(round(0, 5), .new(4), .fill(1));
    const other = Proposal.init(round(0, 5), .new(4), .fill(2));
    const later = Proposal.init(round(0, 6), .new(4), .fill(2));
    const bad_notarize = [_][2]Notarize{
        .{ notarize(1, proposal), notarize(1, proposal) },
        .{ notarize(1, proposal), notarize(2, other) },
        .{ notarize(1, proposal), notarize(1, later) },
    };
    for (bad_notarize) |pair| {
        try expect_invalid(ConflictingNotarize, .{ .first = pair[0], .second = pair[1] });
    }
    try expect_invalid(ConflictingFinalize, .{
        .first = finalize(1, proposal),
        .second = finalize(1, proposal),
    });
    try expect_invalid(NullifyFinalize, .{
        .nullify = nullify(1, round(0, 6)),
        .finalize = finalize(1, proposal),
    });
}

// commonware issue_2944_regression_conflicting_notarize_new (should_panic "proposals must
// differ"): conflicting evidence over one proposal twice is refused at construction.
test "issue 2944 regression: conflicting notarize init" {
    try utils.death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            const vote = notarize(0, Proposal.init(round(0, 10), .new(5), .fill(1)));
            _ = ConflictingNotarize.init(vote, vote);
        }
    }.body);
}

// commonware issue_2944_regression_conflicting_finalize_new: the same for finalize votes.
test "issue 2944 regression: conflicting finalize init" {
    try utils.death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            const vote = finalize(0, Proposal.init(round(0, 10), .new(5), .fill(1)));
            _ = ConflictingFinalize.init(vote, vote);
        }
    }.body);
}

/// Encodes `value` (built without `init`'s checks) and expects decoding to reject it.
fn expect_invalid(comptime T: type, value: T) !void {
    const bytes = try codec.encode(T, testing.allocator, value);
    defer testing.allocator.free(bytes);
    try testing.expectError(error.Invalid, codec.decode(T, testing.allocator, bytes));
}

const MockAttributable = struct {
    participant: Participant,
    pub fn signer(self: MockAttributable) Participant {
        return self.participant;
    }
};

test "attributable map" {
    const gpa = testing.allocator;
    var map = types.AttributableMap(MockAttributable).init(5);
    defer map.deinit(gpa);
    try testing.expect(map.is_empty() and map.data.len == 0);
    for (0..5) |i| try testing.expectEqual(null, map.get(.init(@intCast(i))));
    try testing.expect(try map.insert(gpa, .{ .participant = .init(3) }));
    try testing.expectEqual(5, map.data.len);
    try testing.expect(try map.insert(gpa, .{ .participant = .init(1) }));
    try testing.expectEqual(2, map.len());
    var iterator = map.iterator();
    try testing.expectEqual(1, iterator.next().?.participant.get());
    try testing.expectEqual(3, iterator.next().?.participant.get());
    try testing.expectEqual(null, iterator.next());
    try testing.expectEqual(3, map.get(.init(3)).?.participant.get());
    // Duplicates and out-of-range signers are rejected.
    try testing.expect(!try map.insert(gpa, .{ .participant = .init(3) }));
    try testing.expect(!try map.insert(gpa, .{ .participant = .init(5) }));
    try testing.expectEqual(2, map.len());
    map.clear(gpa);
    try testing.expect(map.is_empty() and map.data.len == 0);
    try testing.expectEqual(null, map.get(.init(1)));
    try testing.expect(try map.insert(gpa, .{ .participant = .init(1) }));
}

// Conformance.

const conformance_file = @embedFile("../conformance.toml");
const prefix = "commonware_consensus::simplex::";

fn skip_slow() error{SkipZigTest}!void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
}

fn CodecConformance(comptime T: type, comptime gen: codec.arbitrary.Generator(T)) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const value = try codec.arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

fn verify(
    comptime path: []const u8,
    comptime T: type,
    comptime gen: codec.arbitrary.Generator(T),
) !void {
    try conformance.verify(
        CodecConformance(T, gen),
        std.heap.smp_allocator,
        prefix ++ path,
        conformance.default_cases,
        conformance_file,
    );
}

fn default(comptime T: type) codec.arbitrary.Generator(T) {
    return codec.arbitrary.default_generator(T);
}

/// `PrivateKey::random(StdRng::from_seed(u.arbitrary::<[u8; 32]>())).public_key()`.
fn gen_public_key(u: *Unstructured) ed25519.PublicKey {
    var key: [32]u8 = undefined;
    u.fill(&key);
    var rng = utils.rng.TestRng.init_key(key);
    const private_key = ed25519.PrivateKey.random(&rng);
    return private_key.public_key();
}

fn gen_context(gpa: Allocator, u: *Unstructured) ArbitraryError!Context {
    const at = try Round.arbitrary(gpa, u);
    const leader = gen_public_key(u);
    const parent_view = try View.arbitrary(gpa, u);
    const parent_digest = try Digest.arbitrary(gpa, u);
    return .{ .round = at, .leader = leader, .parent = .{ parent_view, parent_digest } };
}

test "simplex proposal conformance hash matches commonware" {
    const path = "types::tests::conformance::CodecConformance<Proposal<Sha256Digest>>";
    try verify(path, Proposal, default(Proposal));
}

test "simplex context conformance hash matches commonware" {
    try skip_slow();
    const path = "types::tests::conformance::CodecConformance<Context<Sha256Digest,PublicKey>>";
    try verify(path, Context, gen_context);
}

// commonware records one hash over all `default_cases` vectors, so no smaller per-push count
// can be checked; slow builds (nightly) run it, and the roundtrip tests above run per push.
test "simplex message conformance hashes match commonware" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const t = "types::tests::conformance::CodecConformance<";
    const entries = .{
        .{ "Vote<Scheme,Sha256Digest>>", Vote },
        .{ "Certificate<Scheme,Sha256Digest>>", Certificate },
        .{ "Artifact<Scheme,Sha256Digest>>", Artifact },
        .{ "Notarize<Scheme,Sha256Digest>>", Notarize },
        .{ "Notarization<Scheme,Sha256Digest>>", Notarization },
        .{ "Nullify<Scheme>>", Nullify },
        .{ "Nullification<Scheme>>", Nullification },
        .{ "Finalize<Scheme,Sha256Digest>>", Finalize },
        .{ "Finalization<Scheme,Sha256Digest>>", Finalization },
        .{ "Activity<Scheme,Sha256Digest>>", Activity },
        .{ "ConflictingNotarize<Scheme,Sha256Digest>>", ConflictingNotarize },
        .{ "ConflictingFinalize<Scheme,Sha256Digest>>", ConflictingFinalize },
        .{ "NullifyFinalize<Scheme,Sha256Digest>>", NullifyFinalize },
    };
    inline for (entries) |entry| try verify(t ++ entry[0], entry[1], default(entry[1]));
}

test "threshold vrf conformance hashes match commonware" {
    try skip_slow();
    const v = "scheme::bls12381_threshold::vrf::tests::conformance::CodecConformance<";
    const entries = .{
        .{ "Signature<MinSig>>", vrf.Signature(MinSig) },
        .{ "Certificate<MinSig>>", vrf.Certificate(MinSig) },
        .{ "Seed<MinSig>>", vrf.Seed(MinSig) },
    };
    inline for (entries) |entry| try verify(v ++ entry[0], entry[1], default(entry[1]));
}
