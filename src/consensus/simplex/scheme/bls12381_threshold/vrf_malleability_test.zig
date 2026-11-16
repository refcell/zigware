//! commonware `bls12381_threshold::vrf` malleability tests: shifting signature mass between
//! the vote and seed components, or between two attestations or certificates, keeps a naive
//! aggregate check passing, so each component must be verified on its own.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const vrf = @import("vrf.zig");

const primitives = cryptography.bls12381.primitives;
const Scalar = primitives.group.Scalar;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Round = consensus_types.Round;
const Participant = utils.Participant;
const N3f1 = utils.N3f1;
const sequential = parallel.sequential;
/// Debug runs without `-Dslow-tests` cover MinPk only, to keep the suite fast; ReleaseSafe
/// covers both variants.
const variants = if (builtin.mode == .debug and !build_options.slow_tests)
    .{primitives.MinPk}
else
    .{ primitives.MinPk, primitives.MinSig };
const namespace = "bls-threshold-signing-scheme";
const gpa = testing.allocator;

fn SchemeOf(comptime V: type) type {
    return vrf.Scheme(Digest, cryptography.ed25519.PublicKey, V);
}

const Fixture = cryptography.certificate.mocks.Fixture;

fn setup(comptime V: type, n: u32, seed: u64) !Fixture(SchemeOf(V)) {
    var rng = utils.rng.TestRng.init(seed);
    return vrf.fixture(SchemeOf(V), gpa, &rng, namespace, n);
}

fn sample_proposal(view: u64, tag: u8) types.Proposal(Digest) {
    const round: Round = .new(.new(0), .new(view));
    return .init(round, round.view.previous().?, Sha256.hash(&.{&.{tag}}));
}

/// A random multiple of the signature group's generator.
fn random_delta(comptime V: type, rng: anytype) V.Signature {
    return V.Signature.generator.mul(Scalar.random(rng));
}

/// A certificate over `subject` from the first quorum of `schemes`.
fn quorum_certificate(comptime S: type, schemes: []const S, subject: S.Subject) !S.Certificate {
    const quorum = N3f1.quorum(schemes.len);
    var votes: [16]S.Attestation = undefined;
    for (schemes[0..quorum], votes[0..quorum]) |*scheme, *vote| {
        vote.* = (try scheme.sign(gpa, subject)).?;
    }
    return schemes[0].assemble(gpa, votes[0..quorum], sequential);
}

test "vrf: verify_attestations rejects vote mass moved between signers" {
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 71);
        defer fixture.deinit(gpa);
        var rng = utils.rng.test_rng();
        const proposal = sample_proposal(29, 15);
        const subject: S.Subject = .{ .notarize = &proposal };
        const scheme = &fixture.schemes[0];
        const votes = [2]S.Attestation{
            (try fixture.schemes[0].sign(gpa, subject)).?,
            (try fixture.schemes[1].sign(gpa, subject)).?,
        };
        var valid = try scheme.verify_attestations(gpa, &rng, subject, &votes, sequential);
        defer valid.deinit(gpa);
        try testing.expectEqual(0, valid.invalid.len);
        try testing.expectEqual(2, valid.verified.len);

        const delta = random_delta(V, &rng);
        const first = votes[0].signature.get().?;
        const second = votes[1].signature.get().?;
        const forged = [2]S.Attestation{
            .init(votes[0].signer, .{
                .vote_signature = first.vote_signature.sub(delta),
                .seed_signature = first.seed_signature,
            }),
            .init(votes[1].signer, .{
                .vote_signature = second.vote_signature.add(delta),
                .seed_signature = second.seed_signature,
            }),
        };
        // The vote signatures still sum to the valid sum.
        const forged_sum = forged[0].signature.get().?.vote_signature
            .add(forged[1].signature.get().?.vote_signature);
        try testing.expect(forged_sum.eql(first.vote_signature.add(second.vote_signature)));
        const verify = S.verify_attestations;
        var verification = try verify(scheme, gpa, &rng, subject, &forged, sequential);
        defer verification.deinit(gpa);
        try testing.expect(verification.invalid.len > 0);
    }
}

/// commonware's `optimistic_assemble_verifies_both_components`, run under every strategy
/// shape: votes whose vote or seed component belongs to another round are rejected by
/// signer, whether alone or one in each fallback half, and a valid batch certifies.
fn OptimisticAssemble(comptime V: type) type {
    return struct {
        const S = SchemeOf(V);
        const Output = [2][S.Certificate.fixed_size]u8;

        pub fn run(_: @This(), strategy: parallel.mocks.Explorer) !Output {
            var fixture = try setup(V, 7, 72);
            defer fixture.deinit(gpa);
            var rng = utils.rng.test_rng();
            const quorum = N3f1.quorum(fixture.schemes.len);
            const subject: S.Subject = .{ .nullify = .new(.new(0), .new(30)) };
            const other: S.Subject = .{ .nullify = .new(.new(0), .new(31)) };
            var votes: [7]S.Attestation = undefined;
            for (fixture.schemes[0..quorum], votes[0..quorum]) |*scheme, *vote| {
                vote.* = (try scheme.sign(gpa, subject)).?;
            }
            var outputs: Output = undefined;
            for ([_]usize{ 1, quorum }, &outputs) |pending_len, *output| {
                const ctx: Context = .{
                    .fixture = &fixture,
                    .votes = votes[0..quorum],
                    .subject = subject,
                    .other = other,
                    .pending_len = pending_len,
                };
                output.* = try ctx.check(&rng, strategy);
            }
            return outputs;
        }

        const Context = struct {
            fixture: *const Fixture(S),
            votes: []const S.Attestation,
            subject: S.Subject,
            other: S.Subject,
            pending_len: usize,

            fn check(
                ctx: Context,
                rng: anytype,
                strategy: anytype,
            ) ![S.Certificate.fixed_size]u8 {
                const verifier = &ctx.fixture.verifier;
                // Retained votes authenticate both components before a replacement arrives.
                const prior_len = ctx.votes.len - ctx.pending_len;
                const retained = ctx.votes[0..prior_len];
                const subject = ctx.subject;
                var prior = try verifier.verify_attestations(gpa, rng, subject, retained, strategy);
                defer prior.deinit(gpa);
                try testing.expectEqual(0, prior.invalid.len);
                for ([_]bool{ false, true }) |corrupt_vote| {
                    try ctx.reject_mixed(rng, prior.verified, corrupt_vote, strategy);
                }
                // A valid replacement or complete batch still certifies the intended round.
                const pending = ctx.votes[prior_len..];
                var result = try verifier.optimistic_assemble(
                    gpa,
                    rng,
                    ctx.subject,
                    pending,
                    prior.verified,
                    strategy,
                );
                defer result.deinit(gpa);
                const certificate = &result.certificate;
                const verify = S.verify_certificate;
                const cert = certificate;
                try testing.expect(try verify(verifier, gpa, rng, subject, cert, strategy));
                try testing.expect(!try verify(verifier, gpa, rng, ctx.other, cert, strategy));
                return codec.encode_fixed(S.Certificate, certificate.*);
            }

            /// Replaces one component of the corrupted votes with the other round's, and
            /// returns how many signers it wrote to `invalid`.
            fn corrupt(
                ctx: Context,
                pending: []S.Attestation,
                corrupt_vote: bool,
                invalid: *[2]Participant,
            ) !usize {
                const prior_len = ctx.votes.len - ctx.pending_len;
                var invalid_len: usize = 0;
                // Proof: the divisor is non-zero.
                const second = std.math.divCeil(usize, ctx.pending_len, 2) catch unreachable;
                const positions: []const struct { usize, bool } = if (ctx.pending_len == 1)
                    &.{.{ 0, corrupt_vote }}
                else
                    &.{ .{ 0, corrupt_vote }, .{ second, !corrupt_vote } };
                for (positions) |item| {
                    const position, const vote_side = item;
                    const scheme = &ctx.fixture.schemes[prior_len + position];
                    const replaced = (try scheme.sign(gpa, ctx.other)).?.signature.get().?;
                    const original = pending[position].signature.get().?;
                    pending[position] = .init(pending[position].signer, .{
                        .vote_signature = if (vote_side)
                            replaced.vote_signature
                        else
                            original.vote_signature,
                        .seed_signature = if (vote_side)
                            original.seed_signature
                        else
                            replaced.seed_signature,
                    });
                    invalid[invalid_len] = pending[position].signer;
                    invalid_len += 1;
                }
                return invalid_len;
            }

            /// Corrupts one component of the first pending vote (and, in a larger batch, the
            /// other component of the vote opening the second fallback half) and checks that
            /// exactly those signers are rejected.
            fn reject_mixed(
                ctx: Context,
                rng: anytype,
                prior: []const S.Attestation,
                corrupt_vote: bool,
                strategy: anytype,
            ) !void {
                const prior_len = ctx.votes.len - ctx.pending_len;
                var pending: [7]S.Attestation = undefined;
                @memcpy(pending[0..ctx.pending_len], ctx.votes[prior_len..]);
                var invalid: [2]Participant = undefined;
                const corrupted = pending[0..ctx.pending_len];
                const invalid_len = try ctx.corrupt(corrupted, corrupt_vote, &invalid);
                std.mem.sort(Participant, invalid[0..invalid_len], {}, less);
                // Network inputs keep encoded points until the helper decodes them.
                for (pending[0..ctx.pending_len]) |*vote| {
                    const bytes = try codec.encode(S.Attestation, gpa, vote.*);
                    defer gpa.free(bytes);
                    vote.* = try codec.decode(S.Attestation, gpa, bytes);
                }
                const verifier = &ctx.fixture.verifier;
                var result = try verifier.optimistic_assemble(
                    gpa,
                    rng,
                    ctx.subject,
                    pending[0..ctx.pending_len],
                    prior,
                    strategy,
                );
                defer result.deinit(gpa);
                const verification = switch (result) {
                    .certificate => return error.ForgedVotesCertified,
                    .verification => |value| value,
                };
                var accepted: [7]S.Attestation = undefined;
                var accepted_len: usize = 0;
                for (ctx.votes[prior_len..]) |vote| {
                    if (contains(invalid[0..invalid_len], vote.signer)) continue;
                    accepted[accepted_len] = vote;
                    accepted_len += 1;
                }
                try testing.expectEqual(accepted_len, verification.verified.len);
                for (accepted[0..accepted_len], verification.verified) |expected, actual| {
                    try testing.expect(expected.eql(actual));
                }
                const rejected = try gpa.dupe(Participant, verification.invalid);
                defer gpa.free(rejected);
                std.mem.sort(Participant, rejected, {}, less);
                try testing.expectEqual(invalid_len, rejected.len);
                for (invalid[0..invalid_len], rejected) |a, b| {
                    try testing.expectEqual(a.get(), b.get());
                }
            }
        };
    };
}

fn less(_: void, a: Participant, b: Participant) bool {
    return a.get() < b.get();
}

fn contains(items: []const Participant, item: Participant) bool {
    for (items) |value| if (value.get() == item.get()) return true;
    return false;
}

test "vrf: optimistic assembly verifies both components" {
    // Exploring every schedule takes over a minute in Debug; ReleaseSafe runs it.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    inline for (variants) |V| {
        const explored = try parallel.mocks.explore(gpa, testing.io, OptimisticAssemble(V){});
        // A threshold signature is unique, so both paths recover the same certificate.
        try testing.expectEqualSlices(u8, &explored[0], &explored[1]);
    }
}

test "vrf: verify_certificate rejects mass moved from vote to seed" {
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 73);
        defer fixture.deinit(gpa);
        var rng = utils.rng.test_rng();
        const proposal = sample_proposal(31, 16);
        const subject: S.Subject = .{ .notarize = &proposal };
        const certificate = try quorum_certificate(S, fixture.schemes, subject);
        const verifier = &fixture.verifier;
        const verify = S.verify_certificate;
        try testing.expect(try verify(verifier, gpa, &rng, subject, &certificate, sequential));
        const pair = certificate.get().?;
        const delta = random_delta(V, &rng);
        const forged: S.Certificate = .init(.{
            .vote_signature = pair.vote_signature.sub(delta),
            .seed_signature = pair.seed_signature.add(delta),
        });
        const forged_pair = forged.get().?;
        const forged_sum = forged_pair.vote_signature.add(forged_pair.seed_signature);
        try testing.expect(forged_sum.eql(pair.vote_signature.add(pair.seed_signature)));
        try testing.expect(!try verify(verifier, gpa, &rng, subject, &forged, sequential));
    }
}

test "vrf: verify_certificates rejects vote mass moved between certificates" {
    inline for (variants) |V| {
        const S = SchemeOf(V);
        var fixture = try setup(V, 4, 79);
        defer fixture.deinit(gpa);
        var rng = utils.rng.test_rng();
        const first_proposal = sample_proposal(33, 17);
        const second_proposal = sample_proposal(34, 18);
        const first_subject: S.Subject = .{ .notarize = &first_proposal };
        const second_subject: S.Subject = .{ .notarize = &second_proposal };
        const first = try quorum_certificate(S, fixture.schemes, first_subject);
        const second = try quorum_certificate(S, fixture.schemes, second_subject);
        const verifier = &fixture.verifier;
        const valid = [_]S.Item{
            .{ .subject = first_subject, .certificate = &first },
            .{ .subject = second_subject, .certificate = &second },
        };
        try testing.expect(try verifier.verify_certificates(gpa, &rng, &valid, sequential));
        const delta = random_delta(V, &rng);
        const first_pair = first.get().?;
        const second_pair = second.get().?;
        const forged_first: S.Certificate = .init(.{
            .vote_signature = first_pair.vote_signature.sub(delta),
            .seed_signature = first_pair.seed_signature,
        });
        const forged_second: S.Certificate = .init(.{
            .vote_signature = second_pair.vote_signature.add(delta),
            .seed_signature = second_pair.seed_signature,
        });
        const forged_sum = forged_first.get().?.vote_signature
            .add(forged_second.get().?.vote_signature);
        const valid_sum = first_pair.vote_signature.add(second_pair.vote_signature);
        try testing.expect(forged_sum.eql(valid_sum));
        const forged = [_]S.Item{
            .{ .subject = first_subject, .certificate = &forged_first },
            .{ .subject = second_subject, .certificate = &forged_second },
        };
        try testing.expect(!try verifier.verify_certificates(gpa, &rng, &forged, sequential));
    }
}
