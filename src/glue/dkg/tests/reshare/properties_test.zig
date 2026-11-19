//! Tests for the reshare properties on hand-built validator states: each property accepts a
//! plan's expected outcome and rejects the outcome a plausible bug would produce.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../../types.zig");
const properties = @import("properties.zig");

const gpa = testing.allocator;
const ed25519 = cryptography.ed25519;
const Key = ed25519.PublicKey;
const Set = utils.ordered.Set(Key);
const Unit = utils.sequence.Unit;
const MinPk = cryptography.bls12381.primitives.MinPk;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Info = types.EpochInfo(MinPk, Key, Unit);
const Boundary = properties.Boundary(Info);
const Tracker = properties.Tracker;

/// A validator whose final blocks carry `outcomes[epoch]`'s info (null: no block).
const FakeState = struct {
    pub const Info = types.EpochInfo(MinPk, Key, Unit);

    key: Key,
    processed: u64 = 0,
    synced: ?u64 = null,
    registered: []const properties.Registration = &.{},
    outcomes: []const ?types.EpochOutcome,
    mode: cryptography.bls12381.primitives.sharing.Mode = .non_zero_counter,

    pub fn public_key(self: *const FakeState) Key {
        return self.key;
    }

    pub fn processed_height(self: *const FakeState) u64 {
        return self.processed;
    }

    pub fn registrations(self: *const FakeState) []const properties.Registration {
        return self.registered;
    }

    pub fn state_sync_height(self: *const FakeState) ?u64 {
        return self.synced;
    }

    pub fn boundary(self: *const FakeState, allocator: Allocator, height: u64) !Boundary {
        const epoch = (height + 1) / properties.epoch_length - 1;
        std.debug.assert(properties.final_height(epoch) == height);
        if (epoch >= self.outcomes.len) return .missing;
        const outcome = self.outcomes[epoch] orelse return .missing;
        return .{ .info = try info_for(allocator, self.key, epoch + 1, outcome, self.mode) };
    }
};

fn info_for(
    allocator: Allocator,
    key: Key,
    epoch: u64,
    outcome: types.EpochOutcome,
    mode: cryptography.bls12381.primitives.sharing.Mode,
) !Info {
    var rng = utils.rng.TestRng.init(epoch);
    // `deal` takes the players.
    const participants = try Set.from_dedup(allocator, &.{key});
    var dealt = try fd.deal(MinPk, Key, utils.N3f1, allocator, &rng, mode, participants);
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(allocator);
    return .{
        .outcome = outcome,
        .epoch = .new(epoch),
        .output = dealt.output,
        .players = try dealt.output.players.clone(allocator),
        .next_players = try dealt.output.players.clone(allocator),
        .directory = .{},
    };
}

fn key_of(seed: u64) Key {
    return ed25519.PrivateKey.from_seed(seed).public_key();
}

test "reshare properties: boundary epoch infos" {
    const Property = properties.BoundaryEpochInfos(FakeState);
    var tracker: Tracker = .init(gpa);
    defer tracker.deinit();
    const good = FakeState{ .key = key_of(0), .outcomes = &.{ .success, .success, .success } };
    try Property.init(gpa, 3).check(&tracker, &.{&good});
    // A failed boundary fails a plan that requires every epoch to succeed.
    const failed = FakeState{ .key = key_of(0), .outcomes = &.{ .success, .failure, .success } };
    const strict = Property.init(gpa, 3);
    try testing.expectError(error.UnexpectedFailure, strict.check(&tracker, &.{&failed}));
    // Unless it is an expected failure.
    var expecting = Property.init(gpa, 3);
    expecting.expected_failures = &.{1};
    try expecting.check(&tracker, &.{&failed});
    try testing.expectError(error.UnexpectedSuccess, expecting.check(&tracker, &.{&good}));
    // A missing boundary fails, unless the validator state-synced past it.
    const missing = FakeState{ .key = key_of(0), .outcomes = &.{ null, .success, .success } };
    try testing.expectError(error.MissingBoundary, strict.check(&tracker, &.{&missing}));
    var synced = missing;
    synced.synced = properties.final_height(0) + 1;
    try Property.init(gpa, 3).check(&tracker, &.{&synced});
    // min_successes counts successes among the checked epochs.
    var lenient = Property.init(gpa, 3);
    lenient.min_successes = 2;
    try lenient.check(&tracker, &.{&failed});
    lenient.min_successes = 3 - 1;
    const two_failed = FakeState{
        .key = key_of(0),
        .outcomes = &.{ .failure, .failure, .success },
    };
    try testing.expectError(error.TooFewSuccesses, lenient.check(&tracker, &.{&two_failed}));
}

test "reshare properties: signer registered, output mode, and recovery" {
    var tracker: Tracker = .init(gpa);
    defer tracker.deinit();
    const Membership = cryptography.certificate.Membership;
    const member: []const properties.Registration = &.{
        .{ .epoch = .new(1), .membership = Membership{ .member = .from_usize(0) } },
        .{ .epoch = .new(2), .membership = null },
    };
    const signer: []const properties.Registration = &.{
        .{ .epoch = .new(1), .membership = Membership{ .signer = .from_usize(0) } },
    };
    const a = FakeState{ .key = key_of(0), .registered = member, .outcomes = &.{.success} };
    const b = FakeState{ .key = key_of(1), .registered = signer, .outcomes = &.{.success} };
    const Signer = properties.SignerRegistered(FakeState);
    try (Signer{}).check(&tracker, &.{ &a, &b });
    try testing.expectError(error.NoSigner, (Signer{}).check(&tracker, &.{&a}));

    const Mode = properties.BoundaryOutputMode(FakeState);
    var roots = a;
    roots.mode = .roots_of_unity;
    try (Mode{ .gpa = gpa, .epoch = 0, .mode = 1 }).check(&tracker, &.{&roots});
    const want_roots: Mode = .{ .gpa = gpa, .epoch = 0, .mode = 1 };
    try testing.expectError(error.WrongMode, want_roots.check(&tracker, &.{&a}));

    const Recovered = properties.AllNodesRecovered(FakeState);
    const keys = [_]Key{ key_of(0), key_of(1) };
    const recovered: Recovered = .{ .public_keys = &keys };
    // The tracker has seen nobody, so even the full set fails on the tracked count.
    try testing.expectError(error.TrackedCount, recovered.check(&tracker, &.{ &a, &b }));
    try testing.expectError(error.StateCount, recovered.check(&tracker, &.{&a}));
}

test "reshare properties: committee schedule rotates and wraps" {
    const keys = [_]Key{ key_of(0), key_of(1), key_of(2), key_of(3) };
    const schedule: properties.CommitteeSchedule = .{
        .participants = &keys,
        .committee_sizes = &.{ 3, 2 },
        .rotation_stride = 1,
    };
    var epoch3 = try schedule.players(gpa, 3);
    defer epoch3.deinit(gpa);
    // Epoch 3: offset 3, size 2 → participants 3 and 0 (wrapping).
    var expected = try Set.from_dedup(gpa, &.{ keys[3], keys[0] });
    defer expected.deinit(gpa);
    try testing.expect(epoch3.eql(expected));
    var epoch0 = try schedule.players(gpa, 0);
    defer epoch0.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), epoch0.len());
}

test "reshare properties: all active processed height" {
    const exit: properties.AllActiveProcessedHeight = .{ .required = 31, .participants = 2 };
    var a = FakeState{ .key = key_of(0), .processed = 31, .outcomes = &.{} };
    const b = FakeState{ .key = key_of(1), .processed = 40, .outcomes = &.{} };
    try testing.expect(try exit.reached({}, @as([]const *const FakeState, &.{ &a, &b }), 2));
    // A missing validator or one below the height keeps waiting.
    try testing.expect(!try exit.reached({}, @as([]const *const FakeState, &.{&b}), 2));
    a.processed = 30;
    try testing.expect(!try exit.reached({}, @as([]const *const FakeState, &.{ &a, &b }), 2));
}
