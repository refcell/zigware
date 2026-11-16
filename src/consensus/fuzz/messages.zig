//! The `simplex_messages` fuzz target (commonware
//! `consensus/fuzz/fuzz_targets/simplex_messages.rs`): a vote or certificate that decodes
//! for a scheme re-encodes to exactly the decoded bytes. The schemes are ed25519, BLS12-381
//! multisig (MinPk and MinSig), and the BLS12-381 threshold VRF scheme (MinPk and MinSig),
//! all over SHA-256 payloads.
//!
//! An input is one of commonware's ten `FuzzInput` arms; certificate arms of the schemes
//! with a participant-bounded codec also draw `participants` (clamped to 4..=255). The data
//! is the drawn bytes, as in commonware, or, so that the seeded run reaches decodable
//! messages without coverage guidance, a valid encoding for the arm with up to three drawn
//! edits. The threshold VRF scheme needs only its wire types to decode, so it is a
//! wire-only stand-in until consensus-simplex ports its signing.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const math = @import("math");
const parallel = @import("parallel");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const simplex = @import("../simplex/root.zig");

const types = simplex.types;
const vrf = simplex.scheme.bls12381_threshold.vrf;
const multisig = simplex.scheme.bls12381_multisig;
const Unstructured = minifuzz.Unstructured;
const Digest = cryptography.Sha256.Digest;
const PublicKey = cryptography.ed25519.PublicKey;
const MinPk = cryptography.bls12381.primitives.MinPk;
const MinSig = cryptography.bls12381.primitives.MinSig;

const Ed25519 = simplex.scheme.ed25519.Scheme(Digest);
const MultisigMinPk = multisig.Scheme(Digest, PublicKey, MinPk);
const MultisigMinSig = multisig.Scheme(Digest, PublicKey, MinSig);
const ThresholdMinPk = Threshold(MinPk);
const ThresholdMinSig = Threshold(MinSig);

/// The wire types of `bls12381_threshold::vrf::Scheme<_, V>`.
fn Threshold(comptime V: type) type {
    return struct {
        pub const Signature = vrf.Signature(V);
        pub const Certificate = vrf.Certificate(V);

        pub fn max_certificate_size(_: u32) usize {
            return vrf.Certificate(V).fixed_size;
        }
    };
}

/// commonware's `FuzzInput` arms, in declaration order.
pub const Target = enum {
    ed25519_vote,
    ed25519_certificate,
    multisig_min_pk_vote,
    multisig_min_pk_certificate,
    multisig_min_sig_vote,
    multisig_min_sig_certificate,
    threshold_min_pk_vote,
    threshold_min_pk_certificate,
    threshold_min_sig_vote,
    threshold_min_sig_certificate,

    /// The certificate arms whose codec is bounded by a drawn participant count.
    fn has_participants(target: Target) bool {
        return switch (target) {
            .ed25519_certificate,
            .multisig_min_pk_certificate,
            .multisig_min_sig_certificate,
            => true,
            else => false,
        };
    }
};

const target_count = @typeInfo(Target).@"enum".field_names.len;

/// The largest input the target decodes; every seed encoding fits.
const input_size_max = 1024;

/// A valid encoding per target, in `Target` order, for the edited inputs.
pub const Seeds = struct {
    encodings: [target_count][]u8,

    pub fn init(gpa: Allocator) !Seeds {
        var seeds: Seeds = .{ .encodings = @splat(&.{}) };
        errdefer seeds.deinit(gpa);
        var rng = utils.rng.test_rng();
        var ed25519_fixture = try simplex.scheme.ed25519.fixture(Digest, gpa, &rng, "fuzz", 4);
        defer ed25519_fixture.deinit(gpa);
        try signed_seeds(Ed25519, gpa, &ed25519_fixture, seeds.encodings[0..2]);
        var min_pk_fixture = try multisig.fixture(MultisigMinPk, gpa, &rng, "fuzz", 4);
        defer min_pk_fixture.deinit(gpa);
        try signed_seeds(MultisigMinPk, gpa, &min_pk_fixture, seeds.encodings[2..4]);
        var min_sig_fixture = try multisig.fixture(MultisigMinSig, gpa, &rng, "fuzz", 4);
        defer min_sig_fixture.deinit(gpa);
        try signed_seeds(MultisigMinSig, gpa, &min_sig_fixture, seeds.encodings[4..6]);
        try threshold_seeds(MinPk, gpa, seeds.encodings[6..8]);
        try threshold_seeds(MinSig, gpa, seeds.encodings[8..10]);
        for (seeds.encodings) |encoding| {
            assert(encoding.len > 0 and encoding.len <= input_size_max);
        }
        return seeds;
    }

    pub fn deinit(self: *Seeds, gpa: Allocator) void {
        for (self.encodings) |encoding| gpa.free(encoding);
        self.* = undefined;
    }
};

fn seed_proposal() types.Proposal(Digest) {
    return .init(.new(.new(3), .new(9)), .new(8), .fill(0x5a));
}

/// A notarize vote and a notarization assembled from three signed votes.
fn signed_seeds(comptime S: type, gpa: Allocator, fixture: anytype, out: *[2][]u8) !void {
    const Notarize = types.Notarize(S, Digest);
    const Notarization = types.Notarization(S, Digest);
    assert(fixture.schemes.len == 4);
    const proposal = seed_proposal();
    var notarizes: [3]Notarize = undefined;
    for (&notarizes, fixture.schemes[0..3]) |*notarize, *scheme| {
        notarize.* = (try Notarize.sign(gpa, scheme, proposal)).?;
    }
    const verifier = &fixture.verifier;
    var notarization = try Notarization.from_votes(gpa, verifier, &notarizes, parallel.sequential);
    defer notarization.deinit(gpa);
    out[0] = try codec.encode(types.Vote(S, Digest), gpa, .{ .notarize = notarizes[1] });
    const certificate: types.Certificate(S, Digest) = .{ .notarization = notarization };
    out[1] = try codec.encode(types.Certificate(S, Digest), gpa, certificate);
    assert(out[0].len > 0 and out[1].len > 0);
}

/// A notarize vote and a notarization of the wire-only threshold VRF scheme.
fn threshold_seeds(comptime V: type, gpa: Allocator, out: *[2][]u8) !void {
    const S = Threshold(V);
    const Point = V.Signature;
    const Scalar = cryptography.bls12381.primitives.group.Scalar;
    const signature: S.Signature = .{
        .vote_signature = Point.generator.mul(Scalar.from_ikm(&@splat(1))),
        .seed_signature = Point.generator.mul(Scalar.from_ikm(&@splat(2))),
    };
    const proposal = seed_proposal();
    const vote: types.Vote(S, Digest) = .{ .notarize = .{
        .proposal = proposal,
        .attestation = .init(.init(2), signature),
    } };
    out[0] = try codec.encode(types.Vote(S, Digest), gpa, vote);
    const certificate: types.Certificate(S, Digest) = .{ .notarization = .{
        .proposal = proposal,
        .certificate = S.Certificate.init(signature),
    } };
    out[1] = try codec.encode(types.Certificate(S, Digest), gpa, certificate);
    assert(out[0].len > 0 and out[1].len > 0);
}

/// commonware's `participant_cfg`: `participants.clamp(4, 255)`.
fn participant_cfg(participants: u8) usize {
    const result = std.math.clamp(participants, 4, 255);
    assert(result >= 4);
    return result;
}

const Edit = enum { overwrite, flip, truncate, append };

/// The input bytes: drawn, or `seed` with up to three drawn edits.
fn draw_data(seed: []const u8, u: *Unstructured, buffer: *[input_size_max]u8) ![]const u8 {
    assert(seed.len <= buffer.len);
    if (try u.arbitrary(bool)) {
        const size = @min(u.arbitrary_len(u8), buffer.len);
        @memcpy(buffer[0..size], try u.bytes(size));
        return buffer[0..size];
    }
    var size = seed.len;
    @memcpy(buffer[0..size], seed);
    for (0..u.int_in_range(u8, 0, 3)) |_| {
        switch (try u.arbitrary(Edit)) {
            .overwrite => if (size > 0) {
                buffer[u.int_in_range(usize, 0, size - 1)] = try u.arbitrary(u8);
            },
            .flip => if (size > 0) {
                const bit: u3 = @intCast(u.int_in_range(u8, 0, 7));
                buffer[u.int_in_range(usize, 0, size - 1)] ^= @as(u8, 1) << bit;
            },
            .truncate => size = u.int_in_range(usize, 0, size),
            .append => if (size < buffer.len) {
                buffer[size] = try u.arbitrary(u8);
                size += 1;
            },
        }
    }
    assert(size <= buffer.len);
    return buffer[0..size];
}

/// Returns whether `data` decoded (and so re-encoded to itself).
fn roundtrip_vote(comptime S: type, gpa: Allocator, data: []const u8) !bool {
    const Vote = types.Vote(S, Digest);
    const vote = codec.decode(Vote, gpa, data) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return false,
    };
    const encoded = try codec.encode(Vote, gpa, vote);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, data, encoded);
    return true;
}

fn roundtrip_certificate(
    comptime S: type,
    gpa: Allocator,
    data: []const u8,
    cfg: codec.Cfg(S.Certificate),
) !bool {
    const Certificate = types.Certificate(S, Digest);
    var certificate = codec.decode_cfg(Certificate, gpa, data, cfg) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return false,
    };
    defer certificate.deinit(gpa);
    const encoded = try codec.encode(Certificate, gpa, certificate);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, data, encoded);
    return true;
}

/// Decodes `data` for `target` and checks that it re-encodes to itself. Returns whether it
/// decoded.
fn roundtrip(target: Target, gpa: Allocator, data: []const u8, participants: u8) !bool {
    assert(data.len <= input_size_max);
    const cfg = participant_cfg(participants);
    return switch (target) {
        .ed25519_vote => roundtrip_vote(Ed25519, gpa, data),
        .ed25519_certificate => roundtrip_certificate(Ed25519, gpa, data, cfg),
        .multisig_min_pk_vote => roundtrip_vote(MultisigMinPk, gpa, data),
        .multisig_min_pk_certificate => roundtrip_certificate(MultisigMinPk, gpa, data, cfg),
        .multisig_min_sig_vote => roundtrip_vote(MultisigMinSig, gpa, data),
        .multisig_min_sig_certificate => roundtrip_certificate(MultisigMinSig, gpa, data, cfg),
        .threshold_min_pk_vote => roundtrip_vote(ThresholdMinPk, gpa, data),
        .threshold_min_pk_certificate => roundtrip_certificate(ThresholdMinPk, gpa, data, {}),
        .threshold_min_sig_vote => roundtrip_vote(ThresholdMinSig, gpa, data),
        .threshold_min_sig_certificate => roundtrip_certificate(ThresholdMinSig, gpa, data, {}),
    };
}

/// One input: commonware's `fuzz(input)`.
pub fn body(seeds: *const Seeds, u: *Unstructured) anyerror!void {
    const target = try u.arbitrary(Target);
    const participants: u8 = if (target.has_participants()) try u.arbitrary(u8) else 0;
    var buffer: [input_size_max]u8 = undefined;
    const data = try draw_data(seeds.encodings[@backingInt(target)], u, &buffer);
    assert(data.len <= buffer.len);
    _ = try roundtrip(target, testing.allocator, data, participants);
}

fn with_seeds(comptime run: fn (*const Seeds) anyerror!void) !void {
    var seeds = try Seeds.init(testing.allocator);
    defer seeds.deinit(testing.allocator);
    try run(&seeds);
}

test "simplex_messages: every seed decodes under its arm and roundtrips" {
    try with_seeds(struct {
        fn run(seeds: *const Seeds) anyerror!void {
            for (seeds.encodings, 0..) |encoding, index| {
                const target: Target = @fromBackingInt(@intCast(index));
                try testing.expect(try roundtrip(target, testing.allocator, encoding, 4));
                // One byte short never decodes.
                const short = encoding[0 .. encoding.len - 1];
                try testing.expect(!try roundtrip(target, testing.allocator, short, 4));
            }
        }
    }.run);
}

test "simplex_messages fuzz target (minifuzz)" {
    try with_seeds(struct {
        fn run(seeds: *const Seeds) anyerror!void {
            try minifuzz.run(testing.allocator, seeds, body);
        }
    }.run);
}

test "simplex_messages fuzz target (std fuzz)" {
    try with_seeds(struct {
        fn run(seeds: *const Seeds) anyerror!void {
            try testing.fuzz(seeds, math.testing.smith_body(*const Seeds, body), .{});
        }
    }.run);
}
