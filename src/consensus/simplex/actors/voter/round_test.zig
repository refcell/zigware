//! commonware `actors/voter/round.rs` tests (the two `should_panic` replay conflicts are
//! asserts here and are not exercised).

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const round_mod = @import("round.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const Round = round_mod.Round(Scheme, Digest);
const Proposal = types.Proposal(Digest);
const Notarize = types.Notarize(Scheme, Digest);
const Finalize = types.Finalize(Scheme, Digest);
const Nullify = types.Nullify(Scheme);
const Notarization = types.Notarization(Scheme, Digest);
const Finalization = types.Finalization(Scheme, Digest);
const Nullification = types.Nullification(Scheme);
const Artifact = types.Artifact(Scheme, Digest);
const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
const Rnd = consensus_types.Round;
const gpa = testing.allocator;
const sequential = parallel.sequential;
const second_ns: i96 = std.time.ns_per_s;

fn fixture() !Fixture {
    var rng = utils.rng.test_rng();
    return ed25519.fixture(Digest, gpa, &rng, "ns", 4);
}

fn rnd(epoch: u64, view: u64) Rnd {
    return .new(.new(epoch), .new(view));
}

fn proposal(round: Rnd, parent: u64, payload: u8) Proposal {
    return .init(round, .new(parent), .fill(payload));
}

fn notarization(f: *const Fixture, value: Proposal, signers: []const usize) !Notarization {
    var votes: [4]Notarize = undefined;
    for (signers, 0..) |signer, i| votes[i] = (try Notarize.sign(gpa, &f.schemes[signer], value)).?;
    return Notarization.from_votes(gpa, &f.verifier, votes[0..signers.len], sequential);
}

fn finalization(f: *const Fixture, value: Proposal, signers: []const usize) !Finalization {
    var votes: [4]Finalize = undefined;
    for (signers, 0..) |signer, i| votes[i] = (try Finalize.sign(gpa, &f.schemes[signer], value)).?;
    return Finalization.from_votes(gpa, &f.verifier, votes[0..signers.len], sequential);
}

fn nullification(f: *const Fixture, round: Rnd) !Nullification {
    var votes: [4]Nullify = undefined;
    for (&votes, 0..) |*vote, signer| vote.* = (try Nullify.sign(gpa, &f.schemes[signer], round)).?;
    return Nullification.from_votes(gpa, &f.verifier, &votes, sequential);
}

const all = [_]usize{ 0, 1, 2, 3 };
const others = [_]usize{ 1, 2, 3 };

/// A round led by `leader` holding a notarization of `value` signed by everyone but us.
fn notarized_round(f: *const Fixture, value: Proposal, leader: u32) !Round {
    var round = Round.init(&f.schemes[0], value.round);
    round.set_leader(.init(leader));
    const added = round.add_notarization(try notarization(f, value, &others));
    try testing.expect(added.added and added.equivocator == null);
    return round;
}

fn expect_proposal(actual: ?*const Proposal, expected: Proposal) !void {
    const value = actual orelse return error.TestExpectedProposal;
    try testing.expect(value.eql(expected));
}

test "voter round ancestry request deduplicates view" {
    var f = try fixture();
    defer f.deinit(gpa);
    var round = Round.init(&f.schemes[0], rnd(1, 10));
    defer round.deinit(gpa);
    const requested: consensus_types.View = .new(3);
    try testing.expect(round.request(requested));
    try testing.expect(!round.request(requested));
    try testing.expect(round.request(requested.next()));
    try testing.expect(!round.request(requested.next()));
}

test "voter round elapsed since start anchors at proposal then entry" {
    var f = try fixture();
    defer f.deinit(gpa);
    const info = rnd(1, 10);
    const s = second_ns;
    var round = Round.init(&f.schemes[0], info);
    try testing.expectEqual(null, round.elapsed_since_start(5 * s));
    try testing.expectEqual(null, round.elapsed_since_entry(5 * s));
    // Follower: anchored at view entry; the first entry wins.
    round.mark_entered(1 * s);
    round.mark_entered(3 * s);
    try testing.expectEqual(4 * s, round.elapsed_since_start(5 * s).?);
    try testing.expectEqual(4 * s, round.elapsed_since_entry(5 * s).?);
    // Optimistic leader: proposing before entering anchors at the proposal.
    const value = proposal(info, 9, 1);
    round = Round.init(&f.schemes[0], info);
    try testing.expect(round.proposed(2 * s, value));
    try testing.expectEqual(null, round.elapsed_since_entry(3 * s));
    round.mark_entered(4 * s);
    try testing.expectEqual(4 * s, round.elapsed_since_start(6 * s).?);
    try testing.expectEqual(2 * s, round.elapsed_since_entry(6 * s).?);
    // Normal leader: the proposal anchors the sample even after entry.
    round = Round.init(&f.schemes[0], info);
    round.mark_entered(1 * s);
    try testing.expect(round.proposed(3 * s, value));
    try testing.expectEqual(3 * s, round.elapsed_since_start(6 * s).?);
    try testing.expectEqual(5 * s, round.elapsed_since_entry(6 * s).?);
}

test "voter round equivocation detected on notarization conflict" {
    var f = try fixture();
    defer f.deinit(gpa);
    const a = proposal(rnd(1, 1), 0, 1);
    const b = proposal(rnd(1, 1), 0, 2);
    var round = Round.init(&f.schemes[0], a.round);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    try testing.expect(round.set_proposal(&a));
    try testing.expect(round.verified());
    try expect_proposal(round.construct_notarize(), a);
    try testing.expectEqual(null, round.construct_finalize());

    const added = round.add_notarization(try notarization(&f, b, &others));
    try testing.expect(added.added);
    try testing.expect(added.equivocator.?.eql(f.participants[0]));
    try expect_proposal(&round.broadcast_notarization().?.proposal, b);
    try testing.expectEqual(null, round.construct_notarize());
    try testing.expectEqual(null, round.construct_finalize());
}

test "voter round equivocation detected on finalization conflict" {
    var f = try fixture();
    defer f.deinit(gpa);
    const a = proposal(rnd(1, 1), 0, 1);
    const b = proposal(rnd(1, 1), 0, 2);
    var round = Round.init(&f.schemes[0], a.round);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    try testing.expect(round.set_proposal(&a));
    try testing.expect(round.verified());
    try expect_proposal(round.construct_notarize(), a);
    try testing.expectEqual(null, round.construct_finalize());

    const finalized = round.add_finalization(try finalization(&f, b, &others));
    try testing.expect(finalized.added);
    try testing.expect(finalized.equivocator.?.eql(f.participants[0]));
    try expect_proposal(&round.broadcast_finalization().?.proposal, b);
    // Equivocation was already detected.
    const notarized = round.add_notarization(try notarization(&f, b, &others));
    try testing.expect(notarized.added);
    try testing.expectEqual(null, notarized.equivocator);
    try expect_proposal(&round.broadcast_notarization().?.proposal, b);
    try testing.expectEqual(null, round.construct_notarize());
    try testing.expectEqual(null, round.construct_finalize());
}

/// Our replayed notarize for the leader's first proposal, then the leader's conflicting
/// proposal re-forwarded by a restarted batcher, then the network's certificate for it.
fn restart_equivocation(f: *const Fixture, x: Proposal, y: Proposal) !Round {
    var round = Round.init(&f.schemes[1], x.round);
    round.set_leader(.init(0));
    const notarize = (try Notarize.sign(gpa, &f.schemes[1], x)).?;
    round.replay(&.{ .notarize = notarize });
    try testing.expect(!round.set_proposal(&y));
    return round;
}

test "voter round restart equivocation: finalization overrides local vote" {
    var f = try fixture();
    defer f.deinit(gpa);
    const x = proposal(rnd(1, 1), 0, 1);
    const y = proposal(rnd(1, 1), 0, 2);
    var round = try restart_equivocation(&f, x, y);
    defer round.deinit(gpa);
    const added = round.add_finalization(try finalization(&f, y, &.{ 0, 2, 3 }));
    try testing.expect(added.added);
    try testing.expect(added.equivocator.?.eql(f.participants[0]));
    try expect_proposal(round.certified_proposal(), y);
}

test "voter round restart equivocation: notarization overrides local vote" {
    var f = try fixture();
    defer f.deinit(gpa);
    const x = proposal(rnd(1, 1), 0, 1);
    const y = proposal(rnd(1, 1), 0, 2);
    var round = try restart_equivocation(&f, x, y);
    defer round.deinit(gpa);
    const added = round.add_notarization(try notarization(&f, y, &.{ 0, 2, 3 }));
    try testing.expect(added.added);
    try testing.expect(added.equivocator.?.eql(f.participants[0]));
    try testing.expect(round.pending_certification().?.eql(y));
    // Even certified, an equivocated round emits no finalize vote.
    round.certified(true);
    try testing.expectEqual(null, round.construct_finalize());
}

test "voter round no equivocation on matching certificate" {
    var f = try fixture();
    defer f.deinit(gpa);
    const value = proposal(rnd(1, 1), 0, 1);
    var round = Round.init(&f.schemes[0], value.round);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    try testing.expect(round.set_proposal(&value));
    const added = round.add_notarization(try notarization(&f, value, &all));
    try testing.expect(added.added and added.equivocator == null);
}

test "voter round broadcasts recovered certificates without local votes" {
    var f = try fixture();
    defer f.deinit(gpa);
    const value = proposal(rnd(1, 1), 0, 9);
    var round = Round.init(&f.schemes[0], value.round);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    const notarized = round.add_notarization(try notarization(&f, value, &others));
    try testing.expect(notarized.added and notarized.equivocator == null);
    try testing.expect(!round.broadcast_notarize());
    try testing.expectEqual(null, round.construct_notarize());
    try testing.expect(round.broadcast_notarization() != null);
    try testing.expect(!round.broadcast_notarize());
    try testing.expectEqual(null, round.broadcast_notarization());

    const finalized = round.add_finalization(try finalization(&f, value, &others));
    try testing.expect(finalized.added and finalized.equivocator == null);
    try testing.expect(round.decision != .finalize);
    try testing.expectEqual(null, round.construct_finalize());
    try testing.expect(round.broadcast_finalization() != null);
    try testing.expect(round.decision != .finalize);
    try testing.expectEqual(null, round.broadcast_finalization());
}

test "voter round replay sets broadcast flags" {
    var f = try fixture();
    defer f.deinit(gpa);
    const info = rnd(5, 2);
    const value = proposal(info, 0, 40);
    var notarized = try notarization(&f, value, &all);
    defer notarized.deinit(gpa);
    var nullified = try nullification(&f, info);
    defer nullified.deinit(gpa);
    var finalized = try finalization(&f, value, &all);
    defer finalized.deinit(gpa);
    var round = Round.init(&f.schemes[0], info);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    round.replay(&.{ .notarize = (try Notarize.sign(gpa, &f.schemes[0], value)).? });
    try testing.expect(round.broadcast_notarize_);
    // Replaying each certificate (twice) keeps its flag set.
    for (0..2) |_| {
        round.replay(&.{ .notarization = notarized });
        try testing.expect(round.broadcast_notarization_);
        round.replay(&.{ .nullification = nullified });
        try testing.expect(round.broadcast_nullification_);
        round.replay(&.{ .finalization = finalized });
        try testing.expect(round.broadcast_finalization_);
    }
}

test "voter round replayed local notarize restores verified proposal" {
    var f = try fixture();
    defer f.deinit(gpa);
    const info = rnd(5, 2);
    const value = proposal(info, 1, 41);
    var round = Round.init(&f.schemes[0], info);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    round.replay(&.{ .notarize = (try Notarize.sign(gpa, &f.schemes[0], value)).? });
    try expect_proposal(round.proposal(), value);
    try testing.expectEqual(.verified, round.slot.status());
    try testing.expect(round.broadcast_notarize());
    // A leader-owned replay requests no verification.
    try testing.expectEqual(.skip, round.request_verify());
    const added = round.add_notarization(try notarization(&f, value, &all));
    try testing.expect(added.added and added.equivocator == null);
    try testing.expect(round.pending_certification().?.eql(value));
}

test "voter round nullify and finalize block each other" {
    var f = try fixture();
    defer f.deinit(gpa);
    const info = rnd(5, 2);
    const value = proposal(info, 0, 40);
    var round = Round.init(&f.schemes[0], info);
    round.set_leader(.init(0));
    round.replay(&.{ .finalize = (try Finalize.sign(gpa, &f.schemes[0], value)).? });
    try testing.expectEqual(null, round.construct_nullify());
    round.deinit(gpa);

    // Our nullify blocks a later finalize, even once notarized and certified.
    const other = proposal(rnd(1, 1), 0, 2);
    round = Round.init(&f.schemes[0], other.round);
    defer round.deinit(gpa);
    round.set_leader(.init(1));
    try testing.expectEqual(false, round.construct_nullify().?);
    const added = round.add_notarization(try notarization(&f, other, &others));
    try testing.expect(added.added and added.equivocator == null);
    round.certified(true);
    try testing.expectEqual(null, round.construct_finalize());
}

test "voter round latch before deadlines remains first timeout" {
    var f = try fixture();
    defer f.deinit(gpa);
    var round = Round.init(&f.schemes[0], rnd(5, 2));
    const s = second_ns;
    round.latch_timeout(1 * s, .inactivity);
    round.set_deadlines(10 * s, 20 * s, null);
    const latched = round.next_timeout(0, 5 * s, true).?;
    try testing.expectEqual(1 * s, latched.deadline);
    try testing.expectEqual(.inactivity, latched.reason);
    const leader = round.next_timeout(0, 5 * s, false).?;
    try testing.expectEqual(10 * s, leader.deadline);
    try testing.expectEqual(.leader_timeout, leader.reason);
}

test "voter round nullify retry is stable and resets on retry" {
    var f = try fixture();
    defer f.deinit(gpa);
    var round = Round.init(&f.schemes[0], rnd(5, 2));
    const s = second_ns;
    const retry = 5 * s;
    round.set_deadlines(1 * s, 2 * s, null);
    round.latch_timeout(0, .inactivity);
    try testing.expectEqual(false, round.construct_nullify().?);
    try testing.expectEqual(null, round.construct_finalize());
    // Later deadlines and latches are ignored; the retry is scheduled on the first poll.
    round.set_deadlines(10 * s, 20 * s, null);
    round.latch_timeout(3 * s, .leader_nullify);
    const first = round.next_timeout(4 * s, retry, true).?;
    try testing.expectEqual(9 * s, first.deadline);
    try testing.expectEqual(.retry, first.reason);
    try testing.expectEqual(first, round.next_timeout(30 * s, retry, true).?);
    // A retry nullify reschedules from the next poll.
    try testing.expectEqual(true, round.construct_nullify().?);
    try testing.expectEqual(35 * s, round.next_timeout(30 * s, retry, true).?.deadline);
}

test "voter round pending certification lifecycle" {
    var f = try fixture();
    defer f.deinit(gpa);
    const value = proposal(rnd(1, 1), 0, 1);
    var round = Round.init(&f.schemes[0], value.round);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    try testing.expect(round.set_proposal(&value));
    try testing.expect(round.verified());
    // Not pending until notarized.
    try testing.expectEqual(null, round.pending_certification());
    const added = round.add_notarization(try notarization(&f, value, &all));
    try testing.expect(added.added);
    try testing.expect(round.pending_certification().?.eql(value));
    // Nothing is pending while a request is in flight, after an abort, or once certified.
    round.set_certify_outstanding();
    try testing.expectEqual(null, round.pending_certification());
    round.abort_certify();
    try testing.expectEqual(null, round.pending_certification());
    // A result arriving after the abort must not panic.
    round.certified(true);
    try testing.expectEqual(null, round.pending_certification());
}

test "voter round pending certification returns local or certificate proposal" {
    var f = try fixture();
    defer f.deinit(gpa);
    const value = proposal(rnd(1, 1), 0, 7);
    var round = Round.init(&f.schemes[0], value.round);
    round.set_leader(.init(0));
    try testing.expect(round.proposed(0, value));
    _ = round.add_notarization(try notarization(&f, value, &all));
    try testing.expect(round.pending_certification().?.eql(value));
    round.deinit(gpa);
    // A notarization for a proposal the round never saw fills the slot.
    round = Round.init(&f.schemes[0], value.round);
    defer round.deinit(gpa);
    round.set_leader(.init(1));
    _ = round.add_notarization(try notarization(&f, value, &all));
    try testing.expect(round.pending_certification().?.eql(value));
}

test "voter round construct finalize requires notarization" {
    var f = try fixture();
    defer f.deinit(gpa);
    const value = proposal(rnd(1, 1), 0, 1);
    var round = Round.init(&f.schemes[0], value.round);
    defer round.deinit(gpa);
    round.set_leader(.init(0));
    try testing.expect(round.set_proposal(&value));
    try testing.expect(round.verified());
    try testing.expect(round.construct_notarize() != null);
    round.certified(true);
    try testing.expectEqual(null, round.construct_finalize());
    _ = round.add_notarization(try notarization(&f, value, &all));
    try testing.expect(round.construct_finalize() != null);
    try testing.expectEqual(null, round.construct_nullify());
}

test "voter round certified recovered proposal allows finalize then notarize" {
    var f = try fixture();
    defer f.deinit(gpa);
    const value = proposal(rnd(1, 1), 0, 3);
    var round = try notarized_round(&f, value, 1);
    defer round.deinit(gpa);
    try testing.expectEqual(null, round.construct_notarize());
    try testing.expectEqual(.send, round.request_verify());
    round.certified(true);
    try testing.expect(round.construct_finalize() != null);
    try testing.expect(round.verified());
    try expect_proposal(round.construct_notarize(), value);
}

test "voter round request verify withholds once certification requested" {
    var f = try fixture();
    defer f.deinit(gpa);
    const value = proposal(rnd(1, 1), 0, 4);
    for (0..4) |outcome| {
        var round = try notarized_round(&f, value, 1);
        defer round.deinit(gpa);
        round.set_certify_outstanding();
        switch (outcome) {
            0 => {},
            1 => round.certified(true),
            2 => round.certified(false),
            else => round.abort_certify(),
        }
        try testing.expect(round.pending_verification() != null);
        try testing.expectEqual(.withhold, round.request_verify());
        try testing.expectEqual(null, round.pending_verification());
        try testing.expectEqual(.skip, round.request_verify());
    }
}

test "voter round proposed rejects populated slot, confirms held proposal" {
    var f = try fixture();
    defer f.deinit(gpa);
    const certified = proposal(rnd(1, 1), 0, 5);
    const built = proposal(rnd(1, 1), 0, 6);
    var round = try notarized_round(&f, certified, 0);
    try testing.expect(!round.proposed(0, built));
    try expect_proposal(round.proposal(), certified);
    try testing.expectEqual(.unverified, round.slot.status());
    try testing.expectEqual(null, round.elapsed_since_start(0));
    // The same proposal, rebuilt while a certificate for it arrived, is confirmed.
    try testing.expect(round.proposed(0, certified));
    try testing.expectEqual(.verified, round.slot.status());
    try testing.expect(round.elapsed_since_start(0) != null);
    try testing.expectEqual(.skip, round.request_verify());
    round.deinit(gpa);
}

test "voter round replay notarize after certificate" {
    var f = try fixture();
    defer f.deinit(gpa);
    const value = proposal(rnd(1, 1), 0, 7);
    var round = try notarized_round(&f, value, 1);
    try testing.expectEqual(.unverified, round.slot.status());
    round.replay(&.{ .notarize = (try Notarize.sign(gpa, &f.schemes[0], value)).? });
    try testing.expectEqual(.verified, round.slot.status());
    try testing.expect(round.broadcast_notarize());
    try testing.expectEqual(.skip, round.request_verify());
    round.deinit(gpa);
    // A notarize for a different proposal does not verify the certified one.
    const certified = proposal(rnd(1, 1), 0, 8);
    const voted = proposal(rnd(1, 1), 0, 9);
    round = try notarized_round(&f, certified, 1);
    defer round.deinit(gpa);
    round.replay(&.{ .notarize = (try Notarize.sign(gpa, &f.schemes[0], voted)).? });
    try expect_proposal(round.proposal(), certified);
    try testing.expectEqual(.unverified, round.slot.status());
    try testing.expect(round.broadcast_notarize());
    try testing.expectEqual(.send, round.request_verify());
}
