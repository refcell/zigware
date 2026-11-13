//! commonware `actors/batcher/votes.rs` tests.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const votes_mod = @import("votes.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const Tracker = votes_mod.VoteTracker(Scheme, Digest);
const Vote = types.Vote(Scheme, Digest);
const Participant = consensus_types.Participant;

fn expect_outcome(expected: votes_mod.Outcome, actual: votes_mod.Outcome) !void {
    try testing.expectEqualDeep(expected, actual);
}

const added_retained: votes_mod.Outcome = .{ .added = .{ .retained = true } };
const added_compact: votes_mod.Outcome = .{ .added = .{ .retained = false } };
const duplicate_compact: votes_mod.Outcome = .{ .duplicate = .{ .retained = false } };

test "vote tracker records and releases" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "test", 2);
    defer fixture.deinit(gpa);
    const round: consensus_types.Round = .new(.new(0), .new(1));
    const proposal: types.Proposal(Digest) = .init(round, .zero(), .fill(1));
    const scheme = &fixture.schemes[0];
    const signer = Participant.init(0);
    const votes = [_]Vote{
        .{ .notarize = (try types.Notarize(Scheme, Digest).sign(gpa, scheme, proposal)).? },
        .{ .nullify = (try types.Nullify(Scheme).sign(gpa, scheme, round)).? },
        .{ .finalize = (try types.Finalize(Scheme, Digest).sign(gpa, scheme, proposal)).? },
    };
    var tracker = Tracker.init(2, false);
    defer tracker.deinit(gpa);
    for (votes) |vote| try expect_outcome(added_retained, try tracker.record(gpa, vote, &proposal));
    try testing.expect(tracker.notarize(signer) != null);
    try testing.expect(tracker.has_nullify(signer));
    try testing.expect(tracker.finalize(signer) != null);

    try tracker.release_notarizes(gpa, &proposal);
    try tracker.release_nullifies(gpa);
    try tracker.release_finalizes(gpa, &proposal);
    try testing.expectEqual(null, tracker.notarize(signer));
    try testing.expect(!tracker.has_nullify(signer));
    try testing.expectEqual(null, tracker.finalize(signer));
    var finalizes = tracker.iter_finalizes();
    try testing.expectEqual(null, finalizes.next());
    try testing.expect(tracker.has_notarize_for(signer, &proposal));
    try testing.expect(tracker.has_finalize_for(signer, &proposal));
    try testing.expect(tracker.saw_nullify(signer).? == .compacted);
    try testing.expect(tracker.saw_finalize(signer).? == .compacted);
    for (votes) |vote| {
        try expect_outcome(duplicate_compact, try tracker.record(gpa, vote, &proposal));
    }
    // Releasing a compacted phase is idempotent.
    try tracker.release_notarizes(gpa, &proposal);
    try testing.expect(tracker.has_notarize_for(signer, &proposal));
}

test "vote tracker retention policy" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "test", 2);
    defer fixture.deinit(gpa);
    const proposal: types.Proposal(Digest) = .init(.new(.new(0), .new(1)), .zero(), .fill(1));
    const scheme = &fixture.schemes[0];
    const notarize = (try types.Notarize(Scheme, Digest).sign(gpa, scheme, proposal)).?;
    const signer = notarize.signer();
    const vote: Vote = .{ .notarize = notarize };

    var releasing = Tracker.init(2, false);
    defer releasing.deinit(gpa);
    try expect_outcome(added_retained, try releasing.record(gpa, vote, &proposal));
    try releasing.release_notarizes(gpa, &proposal);
    try testing.expect(releasing.notarizes == .compacted);
    try expect_outcome(duplicate_compact, try releasing.record(gpa, vote, &proposal));

    // A certificate can arrive before any vote: later votes use compact storage.
    const finalize: Vote = .{
        .finalize = (try types.Finalize(Scheme, Digest).sign(gpa, scheme, proposal)).?,
    };
    var certificate_first = Tracker.init(2, false);
    defer certificate_first.deinit(gpa);
    try certificate_first.release_notarizes(gpa, &proposal);
    try certificate_first.release_finalizes(gpa, &proposal);
    for ([_]Vote{ vote, finalize }) |each| {
        try expect_outcome(added_compact, try certificate_first.record(gpa, each, &proposal));
    }
    try testing.expect(certificate_first.notarizes == .compacted);
    try testing.expect(certificate_first.finalizes == .compacted);
    try testing.expect(certificate_first.has_notarize_for(signer, &proposal));
    try testing.expect(certificate_first.has_finalize_for(signer, &proposal));
    for ([_]Vote{ vote, finalize }) |each| {
        const outcome = try certificate_first.record(gpa, each, &proposal);
        try expect_outcome(duplicate_compact, outcome);
    }

    var retaining = Tracker.init(2, true);
    defer retaining.deinit(gpa);
    try expect_outcome(added_retained, try retaining.record(gpa, vote, &proposal));
    try retaining.release_notarizes(gpa, &proposal);
    try testing.expect(retaining.notarizes == .full);
    try testing.expect(retaining.notarize(signer) != null);
}

test "compacted votes detect a conflicting proposal" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "test", 2);
    defer fixture.deinit(gpa);
    const round: consensus_types.Round = .new(.new(0), .new(1));
    const certified: types.Proposal(Digest) = .init(round, .zero(), .fill(1));
    const other: types.Proposal(Digest) = .init(round, .zero(), .fill(2));
    const Notarize = types.Notarize(Scheme, Digest);
    const scheme = &fixture.schemes[1];
    var tracker = Tracker.skipped(2);
    defer tracker.deinit(gpa);
    const first: Vote = .{ .notarize = (try Notarize.sign(gpa, scheme, other)).? };
    try expect_outcome(added_compact, try tracker.record(gpa, first, &certified));
    const second: Vote = .{ .notarize = (try Notarize.sign(gpa, scheme, certified)).? };
    try expect_outcome(.conflicting, try tracker.record(gpa, second, &certified));
    // As in commonware, the conflicting vote still marks the signer as having the proposal.
    try testing.expect(tracker.has_notarize_for(.init(1), &certified));
    // An out-of-range signer counts as a duplicate rather than growing the flags.
    var outsider = first;
    outsider.notarize.attestation.signer = .init(7);
    try expect_outcome(duplicate_compact, try tracker.record(gpa, outsider, &certified));
}
