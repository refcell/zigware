//! The `simplex_elector` fuzz target (commonware
//! `consensus/fuzz/fuzz_targets/simplex_elector.rs`): every elector elects a participant
//! in range for any round. The electors are round-robin (in index order or shuffled by a
//! drawn seed, with a drawn term length) and random over a drawn threshold VRF certificate
//! (MinPk and MinSig, each in versions 0 and 1). As in commonware, view 1 elects without a
//! certificate.
//!
//! commonware derives the committee from one ed25519 key per participant
//! (`TestRng::new(i)` for i in 1..=count); electors see only the committee size, so this
//! port draws the size alone. commonware draws each certificate signature as the generator
//! times `Scalar::from_ikm` of 64 drawn bytes; a scalar multiplication per input is too slow
//! for a debug-mode seeded run, so this port draws each from a table of such points.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const build_options = @import("build_options");
const cryptography = @import("cryptography");
const math = @import("math");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const consensus_types = @import("../types.zig");
const simplex = @import("../simplex/root.zig");

const elector = simplex.elector;
const vrf = simplex.scheme.bls12381_threshold.vrf;
const Unstructured = minifuzz.Unstructured;
const Round = consensus_types.Round;
const View = consensus_types.View;
const TermLength = consensus_types.TermLength;
const Sha256 = cryptography.Sha256;
const MinPk = cryptography.bls12381.primitives.MinPk;
const MinSig = cryptography.bls12381.primitives.MinSig;
const Scalar = cryptography.bls12381.primitives.group.Scalar;
const RoundRobin = elector.RoundRobin(Sha256);

/// commonware's `FuzzElector` arms, in declaration order.
const Kind = enum { round_robin, round_robin_shuffled, random_min_pk, random_min_sig };

/// commonware's `TermLength` `Arbitrary`: `int_in_range(1..=u32::MAX)`.
fn draw_term(u: *Unstructured) TermLength {
    const length = u.int_in_range(u32, 1, std.math.maxInt(u32));
    assert(length >= 1);
    return .{ .length = length };
}

/// The points certificates draw from, per variant: the generator times
/// `Scalar::from_ikm([i; 64])`.
pub const Points = struct {
    min_pk: [point_count]MinPk.Signature,
    min_sig: [point_count]MinSig.Signature,

    const point_count = 8;

    pub fn init() Points {
        var points: Points = undefined;
        inline for (.{ &points.min_pk, &points.min_sig }) |points_of| {
            const Point = @TypeOf(points_of[0]);
            for (points_of, 0..) |*point, index| {
                point.* = Point.generator.mul(Scalar.from_ikm(&@splat(@intCast(index))));
                assert(!point.is_zero());
            }
        }
        return points;
    }

    fn of(self: *const Points, comptime V: type) *const [point_count]V.Signature {
        return if (V == MinPk) &self.min_pk else &self.min_sig;
    }
};

/// A threshold VRF certificate: a vote and a seed signature drawn from `points`.
fn draw_certificate(comptime V: type, points: *const Points, u: *Unstructured) vrf.Certificate(V) {
    const table = points.of(V);
    const vote_signature = table[u.int_in_range(usize, 0, table.len - 1)];
    const seed_signature = table[u.int_in_range(usize, 0, table.len - 1)];
    assert(!vote_signature.is_zero() and !seed_signature.is_zero());
    return .init(.{ .vote_signature = vote_signature, .seed_signature = seed_signature });
}

/// A term length of one keeps the rotating default, as commonware's target does.
fn with_term(config: RoundRobin, term: TermLength) RoundRobin {
    if (term.length == 1) return config;
    return config.with_term(term, utils.Duration.from_secs(12), .new(0));
}

fn check_round_robin(config: RoundRobin, participants: u8, round: Round) !void {
    if (participants == 0) return;
    const gpa = testing.allocator;
    var built = try config.build(gpa, participants);
    defer built.deinit(gpa);
    assert(built.permutation.len == participants);
    const leader = built.elect(round, {});
    try testing.expect(leader.get() < participants);
}

fn check_random(
    comptime V: type,
    points: *const Points,
    u: *Unstructured,
    participants: u8,
    round: Round,
) !void {
    const certificate = draw_certificate(V, points, u);
    if (participants == 0) return;
    // View 1 has no previous certificate.
    const input: ?*const vrf.Certificate(V) =
        if (round.view == View.new(1)) null else &certificate;
    for ([_]elector.RandomVersion{ .v0, .v1 }) |version| {
        const built = elector.Random(Sha256).init(version).build(V, participants);
        assert(built.n == participants);
        const leader = built.elect(round, input);
        try testing.expect(leader.get() < participants);
    }
}

/// One input: commonware's `FuzzInput { participants_count, round, elector }`.
pub fn body(points: *const Points, u: *Unstructured) anyerror!void {
    try elect(points, u, true);
}

/// The round-robin arms only (a random arm drawn folds onto its round-robin peer).
pub fn body_round_robin(points: *const Points, u: *Unstructured) anyerror!void {
    try elect(points, u, false);
}

fn elect(points: *const Points, u: *Unstructured, random: bool) !void {
    const participants = try u.arbitrary(u8);
    const epoch = try u.arbitrary(u64);
    const round: Round = .new(.new(epoch), .new(try u.arbitrary(u64)));
    var kind = try u.arbitrary(Kind);
    if (!random) kind = @fromBackingInt(@intCast(@backingInt(kind) % 2));
    assert(random or kind == .round_robin or kind == .round_robin_shuffled);
    switch (kind) {
        .round_robin => {
            const config = with_term(RoundRobin.default(), draw_term(u));
            try check_round_robin(config, participants, round);
        },
        .round_robin_shuffled => {
            const seed = try u.arbitrary([32]u8);
            const config = with_term(RoundRobin.shuffled(&seed), draw_term(u));
            try check_round_robin(config, participants, round);
        },
        .random_min_pk => try check_random(MinPk, points, u, participants, round),
        .random_min_sig => try check_random(MinSig, points, u, participants, round),
    }
}

/// Cases in the seeded run over every arm, before `-Dfuzz-soak`: a random elector decodes
/// its certificate's points on every election, which takes tens of milliseconds per case in
/// debug builds. The cheap round-robin arms also run alone at minifuzz's default bound.
const search_limit = 256;

test "simplex_elector fuzz target (minifuzz)" {
    const points: Points = .init();
    const builder = (minifuzz.Builder{}).with_search_limit(search_limit * build_options.fuzz_soak);
    try builder.run(testing.allocator, &points, body);
}

test "simplex_elector fuzz target, round-robin arms (minifuzz)" {
    const points: Points = .init();
    try minifuzz.run(testing.allocator, &points, body_round_robin);
}

test "simplex_elector fuzz target (std fuzz)" {
    const points: Points = .init();
    try testing.fuzz(&points, math.testing.smith_body(*const Points, body), .{});
}
