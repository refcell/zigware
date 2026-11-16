//! commonware `simplex/scheme/reporter.rs` tests: peer activity is verified and, for
//! non-attributable schemes, suppressed; certificates always pass.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const types = @import("../types.zig");
const Round = @import("../../types.zig").Round;
const ed25519 = @import("ed25519.zig");
const standard = @import("bls12381_threshold/standard.zig");
const reporter_mod = @import("reporter.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Ed25519 = ed25519.Scheme(Digest);
const MinPk = cryptography.bls12381.primitives.MinPk;
const Threshold = standard.Scheme(Digest, cryptography.ed25519.PublicKey, MinPk);
const Rng = utils.rng.TestRng;
const sequential = parallel.sequential;
const namespace = "test-reporter";

/// Records the tags of the activities it receives.
fn Mock(comptime S: type) type {
    return struct {
        const Activity = types.Activity(S, Digest);
        reported: [8]std.meta.Tag(Activity) = undefined,
        count: usize = 0,

        pub fn report(self: *@This(), activity: Activity) actor.Feedback {
            self.reported[self.count] = activity;
            self.count += 1;
            return .ok;
        }
    };
}

fn Wrapper(comptime S: type) type {
    return reporter_mod.AttributableReporter(S, Digest, Rng, parallel.Sequential, *Mock(S));
}

/// A four-validator fixture of `S` over `fixture_namespace`.
fn fixture_of(
    comptime S: type,
    rng: *Rng,
    fixture_namespace: []const u8,
) !cryptography.certificate.mocks.Fixture(S) {
    if (S == Ed25519) return ed25519.fixture(Digest, gpa, rng, fixture_namespace, 4);
    return standard.fixture(S, gpa, rng, fixture_namespace, 4);
}

fn create_proposal(epoch: u64, view: u64) types.Proposal(Digest) {
    var buffer: [64]u8 = undefined;
    const data = std.fmt.bufPrint(&buffer, "proposal-{d}-{d}", .{ epoch, view }) catch
        unreachable; // Proof: two u64s fit in 64 bytes with the prefix.
    return .init(.new(.new(epoch), .new(view)), .new(view), Sha256.hash(&.{data}));
}

/// A notarize vote from validator 1, signed by a fixture over "wrong-namespace" when
/// `wrong` (so it fails verification), reported to a wrapper over the first fixture's
/// verifier; returns how many activities passed through.
fn report_peer_notarize(comptime S: type, wrong: bool, verify: bool) !usize {
    var rng = utils.rng.test_rng();
    var fixture = try fixture_of(S, &rng, namespace);
    defer fixture.deinit(gpa);
    var other = try fixture_of(S, &rng, "wrong-namespace");
    defer other.deinit(gpa);
    const signer = if (wrong) &other.schemes[1] else &fixture.schemes[1];
    var mock: Mock(S) = .{};
    const verifier = fixture.verifier;
    var wrapper = Wrapper(S).init(gpa, testing.io, rng, verifier, &mock, sequential, verify);
    const Notarize = types.Notarize(S, Digest);
    const notarize = (try Notarize.sign(gpa, signer, create_proposal(0, 1))).?;
    try testing.expectEqual(actor.Feedback.ok, wrapper.report(.{ .notarize = notarize }));
    if (mock.count > 0) try testing.expectEqual(.notarize, mock.reported[0]);
    return mock.count;
}

test "invalid peer activity is ignored" {
    try testing.expect(Ed25519.is_attributable());
    try testing.expectEqual(0, try report_peer_notarize(Ed25519, true, true));
}

test "without verification, invalid peer activity passes" {
    try testing.expectEqual(1, try report_peer_notarize(Ed25519, true, false));
}

test "an attributable scheme reports peer activity" {
    try testing.expectEqual(1, try report_peer_notarize(Ed25519, false, true));
}

test "a non-attributable scheme filters peer activity" {
    try testing.expect(!Threshold.is_attributable());
    try testing.expectEqual(0, try report_peer_notarize(Threshold, false, true));
}

/// A notarization of `proposal` assembled by every scheme in `fixture`.
fn notarization_of(comptime S: type, fixture: anytype) !types.Notarization(S, Digest) {
    const Notarize = types.Notarize(S, Digest);
    const proposal = create_proposal(0, 1);
    var votes: [4]Notarize = undefined;
    for (&votes, fixture.schemes) |*vote, *scheme| {
        vote.* = (try Notarize.sign(gpa, scheme, proposal)).?;
    }
    const Notarization = types.Notarization(S, Digest);
    return Notarization.from_votes(gpa, &fixture.schemes[0], &votes, sequential);
}

test "certificates are always reported" {
    var rng = utils.rng.test_rng();
    var fixture = try standard.fixture(Threshold, gpa, &rng, namespace, 4);
    defer fixture.deinit(gpa);
    var notarization = try notarization_of(Threshold, &fixture);
    defer notarization.deinit(gpa);
    var mock: Mock(Threshold) = .{};
    const verifier = fixture.verifier;
    var wrapper = Wrapper(Threshold).init(gpa, testing.io, rng, verifier, &mock, sequential, true);
    try testing.expectEqual(actor.Feedback.ok, wrapper.report(.{ .notarization = notarization }));
    try testing.expectEqual(1, mock.count);
    try testing.expectEqual(.notarization, mock.reported[0]);
}

test "a certification is reported without verification" {
    var rng = utils.rng.test_rng();
    var fixture = try fixture_of(Ed25519, &rng, namespace);
    defer fixture.deinit(gpa);
    var wrong = try fixture_of(Ed25519, &rng, "wrong-namespace");
    defer wrong.deinit(gpa);
    // A notarization that does not verify under the reporter's scheme.
    var notarization = try notarization_of(Ed25519, &wrong);
    defer notarization.deinit(gpa);
    try testing.expect(!try notarization.verify(gpa, &rng, &fixture.verifier, sequential));
    var mock: Mock(Ed25519) = .{};
    const verifier = fixture.verifier;
    var wrapper = Wrapper(Ed25519).init(gpa, testing.io, rng, verifier, &mock, sequential, true);
    const activity: types.Activity(Ed25519, Digest) = .{ .certification = notarization };
    try testing.expect(activity.verified());
    try testing.expectEqual(actor.Feedback.ok, wrapper.report(activity));
    try testing.expectEqual(1, mock.count);
    try testing.expectEqual(.certification, mock.reported[0]);
}
