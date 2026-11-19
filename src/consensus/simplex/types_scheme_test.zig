//! commonware `simplex/types.rs` tests that sign and verify on every scheme: votes and
//! certificates fail under another namespace or another committee, a sub-quorum assembles
//! nothing, and fault evidence verifies only under its own scheme.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const types = @import("types.zig");
const consensus_types = @import("../types.zig");
const ed25519 = @import("scheme/ed25519.zig");
const secp256r1 = @import("scheme/secp256r1.zig");
const multisig = @import("scheme/bls12381_multisig.zig");
const standard = @import("scheme/bls12381_threshold/standard.zig");
const vrf = @import("scheme/bls12381_threshold/vrf.zig");

const gpa = testing.allocator;
const Digest = cryptography.Sha256.Digest;
const Key = cryptography.ed25519.PublicKey;
const MinPk = cryptography.bls12381.primitives.MinPk;
const MinSig = cryptography.bls12381.primitives.MinSig;
const Fixture = cryptography.certificate.mocks.Fixture;
const sequential = parallel.sequential;
const namespace = "ns";
const n = 5;

fn make_ed25519(
    comptime S: type,
    allocator: std.mem.Allocator,
    rng: anytype,
    ns: []const u8,
    count: u32,
) !Fixture(S) {
    return ed25519.fixture(Digest, allocator, rng, ns, count);
}

/// commonware's scheme list for these tests, in its order.
const schemes = .{
    .{ ed25519.Scheme(Digest), make_ed25519 },
    .{ secp256r1.Scheme(Digest, Key), secp256r1.fixture },
    .{ multisig.Scheme(Digest, Key, MinPk), multisig.fixture },
    .{ multisig.Scheme(Digest, Key, MinSig), multisig.fixture },
    .{ vrf.Scheme(Digest, Key, MinPk), vrf.fixture },
    .{ vrf.Scheme(Digest, Key, MinSig), vrf.fixture },
    .{ standard.Scheme(Digest, Key, MinPk), standard.fixture },
    .{ standard.Scheme(Digest, Key, MinSig), standard.fixture },
};

/// commonware `setup_seeded_ns`: five participants from a seeded rng.
fn setup(comptime entry: anytype, seed: u64, ns: []const u8) !Fixture(entry[0]) {
    var rng = utils.rng.TestRng.init(seed);
    return entry[1](entry[0], gpa, &rng, ns, n);
}

fn proposal(digest: u8) types.Proposal(Digest) {
    const round = consensus_types.Round.new(.new(0), .new(10));
    return .init(round, .new(5), .fill(digest));
}

/// Runs `body` on every scheme. BLS signing is slow in Debug, so Debug without
/// `-Dslow-tests` runs the ed25519 and secp256r1 schemes only.
fn for_each_scheme(comptime body: anytype) !void {
    const all = builtin.mode != .debug or build_options.slow_tests;
    inline for (schemes, 0..) |entry, index| {
        if (all or index < 2) try body(entry);
    }
}

fn notarize_wrong_namespace_and_scheme(comptime entry: anytype) !void {
    const S = entry[0];
    var fixture = try setup(entry, 0, namespace);
    defer fixture.deinit(gpa);
    var wrong_namespace = try setup(entry, 0, "wrong_namespace");
    defer wrong_namespace.deinit(gpa);
    var wrong_scheme = try setup(entry, 1, namespace);
    defer wrong_scheme.deinit(gpa);
    var rng = utils.rng.test_rng();
    const notarize = (try types.Notarize(S, Digest).sign(gpa, &fixture.schemes[0], proposal(2))).?;
    try testing.expect(try notarize.verify(gpa, &rng, &fixture.schemes[0], sequential));
    try testing.expect(!try notarize.verify(gpa, &rng, &wrong_namespace.schemes[0], sequential));
    try testing.expect(!try notarize.verify(gpa, &rng, &wrong_scheme.verifier, sequential));
}

// commonware `test_notarize_verify_wrong_namespace` and `test_notarize_verify_wrong_scheme`.
test "a notarize verifies only under its own namespace and committee" {
    try for_each_scheme(notarize_wrong_namespace_and_scheme);
}

/// A quorum of `kind` votes from `fixture`, assembled.
fn certificate(
    comptime S: type,
    comptime kind: enum { notarization, finalization },
    fixture: *const Fixture(S),
    digest: u8,
) !switch (kind) {
    .notarization => types.Notarization(S, Digest),
    .finalization => types.Finalization(S, Digest),
} {
    const Vote = switch (kind) {
        .notarization => types.Notarize(S, Digest),
        .finalization => types.Finalize(S, Digest),
    };
    const Certificate = switch (kind) {
        .notarization => types.Notarization(S, Digest),
        .finalization => types.Finalization(S, Digest),
    };
    const quorum = utils.N3f1.quorum(n);
    var votes: [n]Vote = undefined;
    for (votes[0..quorum], fixture.schemes[0..quorum]) |*vote, *scheme| {
        vote.* = (try Vote.sign(gpa, scheme, proposal(digest))).?;
    }
    return Certificate.from_votes(gpa, &fixture.schemes[0], votes[0..quorum], sequential);
}

fn certificates_wrong_namespace_and_scheme(comptime entry: anytype) !void {
    const S = entry[0];
    var fixture = try setup(entry, 0, namespace);
    defer fixture.deinit(gpa);
    var wrong_namespace = try setup(entry, 0, "wrong_namespace");
    defer wrong_namespace.deinit(gpa);
    var wrong_scheme = try setup(entry, 1, namespace);
    defer wrong_scheme.deinit(gpa);
    var rng = utils.rng.test_rng();
    var notarization = try certificate(S, .notarization, &fixture, 3);
    defer notarization.deinit(gpa);
    try testing.expect(try notarization.verify(gpa, &rng, &fixture.schemes[0], sequential));
    try testing.expect(!try notarization.verify(gpa, &rng, &wrong_scheme.verifier, sequential));
    const other = &wrong_namespace.schemes[0];
    try testing.expect(!try notarization.verify(gpa, &rng, other, sequential));
    var finalization = try certificate(S, .finalization, &fixture, 9);
    defer finalization.deinit(gpa);
    try testing.expect(try finalization.verify(gpa, &rng, &fixture.schemes[0], sequential));
    try testing.expect(!try finalization.verify(gpa, &rng, &wrong_scheme.verifier, sequential));
}

// commonware `test_notarization_verify_wrong_scheme`, `test_notarization_verify_wrong_namespace`,
// and `test_finalization_wrong_scheme`.
test "certificates verify only under their own namespace and committee" {
    try for_each_scheme(certificates_wrong_namespace_and_scheme);
}

fn insufficient_signatures(comptime entry: anytype) !void {
    const S = entry[0];
    var fixture = try setup(entry, 0, namespace);
    defer fixture.deinit(gpa);
    const quorum = utils.N3f1.quorum(n);
    try testing.expect(quorum > 1);
    var votes: [n]types.Notarize(S, Digest) = undefined;
    for (votes[0 .. quorum - 1], fixture.schemes[0 .. quorum - 1]) |*vote, *scheme| {
        vote.* = (try types.Notarize(S, Digest).sign(gpa, scheme, proposal(5))).?;
    }
    const Notarization = types.Notarization(S, Digest);
    const few = votes[0 .. quorum - 1];
    const result = Notarization.from_votes(gpa, &fixture.schemes[0], few, sequential);
    try testing.expectError(error.InsufficientAttestations, result);
}

// commonware `test_notarization_recover_insufficient_signatures`.
test "a sub-quorum of notarizes assembles no notarization" {
    try for_each_scheme(insufficient_signatures);
}

fn conflict_detection(comptime entry: anytype) !void {
    const S = entry[0];
    var fixture = try setup(entry, 0, namespace);
    defer fixture.deinit(gpa);
    var wrong_namespace = try setup(entry, 0, "wrong_namespace");
    defer wrong_namespace.deinit(gpa);
    var wrong_scheme = try setup(entry, 1, namespace);
    defer wrong_scheme.deinit(gpa);
    var rng = utils.rng.test_rng();
    const scheme = &fixture.schemes[0];
    const Notarize = types.Notarize(S, Digest);
    const conflicting: types.ConflictingNotarize(S, Digest) = .init(
        (try Notarize.sign(gpa, scheme, proposal(6))).?,
        (try Notarize.sign(gpa, scheme, proposal(7))).?,
    );
    try testing.expect(try conflicting.verify(gpa, &rng, scheme, sequential));
    const other = &wrong_namespace.schemes[0];
    try testing.expect(!try conflicting.verify(gpa, &rng, other, sequential));
    try testing.expect(!try conflicting.verify(gpa, &rng, &wrong_scheme.verifier, sequential));
    const round = proposal(8).round;
    const nullify_finalize: types.NullifyFinalize(S, Digest) = .init(
        (try types.Nullify(S).sign(gpa, scheme, round)).?,
        (try types.Finalize(S, Digest).sign(gpa, scheme, proposal(8))).?,
    );
    try testing.expect(try nullify_finalize.verify(gpa, &rng, scheme, sequential));
    try testing.expect(!try nullify_finalize.verify(gpa, &rng, other, sequential));
    const wrong = &wrong_scheme.verifier;
    try testing.expect(!try nullify_finalize.verify(gpa, &rng, wrong, sequential));
}

// commonware `test_conflicting_notarize_detection` and `test_nullify_finalize_detection`.
test "fault evidence verifies only under its own namespace and committee" {
    try for_each_scheme(conflict_detection);
}
