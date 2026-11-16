//! commonware `actors/voter/slot.rs` tests.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const types = @import("../../types.zig");
const slot_mod = @import("slot.zig");

const Digest = cryptography.Sha256.Digest;
const Slot = slot_mod.Slot(Digest);
const Proposal = types.Proposal(Digest);

fn proposal(epoch: u64, view: u64, parent: u64, payload: u8) Proposal {
    return .init(.new(.new(epoch), .new(view)), .new(parent), .fill(payload));
}

fn expect_proposal(slot: *const Slot, expected: Proposal) !void {
    const held = slot.proposal() orelse return error.TestExpectedProposal;
    try testing.expect(held.eql(expected));
}

fn expect_equivocated(change: anytype, dropped: Proposal, retained: Proposal) !void {
    try testing.expect(change == .equivocated);
    try testing.expect(change.equivocated.dropped.eql(dropped));
    try testing.expect(change.equivocated.retained.eql(retained));
}

test "slot request build behavior" {
    var slot: Slot = .empty;
    try testing.expect(slot.should_build());
    try testing.expect(slot.should_build());
    slot.set_building();
    try testing.expect(!slot.should_build());
    slot.clear_request();
    try testing.expect(slot.should_build());

    slot = .empty;
    _ = slot.record_verified(proposal(7, 3, 2, 1));
    slot.clear_request();
    try testing.expect(!slot.should_build());
}

test "slot records proposal with flags" {
    var slot: Slot = .empty;
    try testing.expect(slot.proposal() == null);
    const value = proposal(9, 1, 0, 2);
    try testing.expect(slot.record_verified(value));
    try expect_proposal(&slot, value);
    try testing.expectEqual(.verified, slot.status());
    try testing.expect(!slot.should_build());
    try testing.expect(!slot.request_verify());
}

test "slot replay allows existing proposal" {
    var slot: Slot = .empty;
    const value = proposal(17, 6, 5, 11);
    const other = proposal(17, 6, 5, 12);
    try testing.expect(slot.record_verified(value));
    try testing.expect(slot.record_verified(value));
    try testing.expect(!slot.record_verified(other));
    try testing.expect(!slot.should_build());
    try testing.expectEqual(.verified, slot.status());
    try expect_proposal(&slot, value);
}

test "slot update preserves status when equal" {
    var slot: Slot = .empty;
    const value = proposal(13, 2, 1, 12);
    try testing.expect(slot.update_vote(&value).? == .new);
    try testing.expect(slot.update_certificate(&value) == .unchanged);
    try testing.expectEqual(.unverified, slot.status());
    try testing.expect(slot.mark_verified());
    try testing.expect(slot.update_certificate(&value) == .unchanged);
    try testing.expectEqual(.verified, slot.status());
}

test "slot certificate then vote detects equivocation" {
    var slot: Slot = .empty;
    const a = proposal(21, 4, 2, 13);
    const b = proposal(21, 4, 2, 14);
    try testing.expect(slot.update_certificate(&a) == .new);
    try expect_equivocated(slot.update_vote(&b).?, b, a);
    try testing.expectEqual(.equivocated, slot.status());
    try expect_proposal(&slot, a);
}

test "slot certificate during pending propose detects equivocation" {
    var slot: Slot = .empty;
    const compromised = proposal(25, 8, 2, 42);
    const honest = proposal(25, 8, 2, 15);
    try testing.expect(slot.should_build());
    slot.set_building();
    try testing.expect(!slot.should_build());
    // A compromised node's certificate arrives before our local propose returns.
    try testing.expect(slot.update_certificate(&compromised) == .new);
    try testing.expectEqual(.unverified, slot.status());
    try expect_proposal(&slot, compromised);
    // Our honest payload, finished late, is ignored.
    _ = slot.record_verified(honest);
    try testing.expectEqual(.unverified, slot.status());
    try expect_proposal(&slot, compromised);
}

test "slot certificate during pending verify detects equivocation" {
    var slot: Slot = .empty;
    const leader = proposal(26, 9, 4, 16);
    const conflicting = proposal(26, 9, 4, 99);
    try testing.expect(slot.update_vote(&leader).? == .new);
    try testing.expectEqual(.unverified, slot.status());
    try testing.expect(slot.request_verify());
    try testing.expect(!slot.request_verify());
    try expect_equivocated(slot.update_certificate(&conflicting), leader, conflicting);
    try testing.expectEqual(.equivocated, slot.status());
    // A verifier completion arriving afterwards is ignored.
    try testing.expect(!slot.mark_verified());
    try testing.expect(slot.update_certificate(&conflicting) == .unchanged);
}

test "slot certificates override votes" {
    var slot: Slot = .empty;
    const a = proposal(21, 4, 2, 15);
    const b = proposal(21, 4, 2, 16);
    try testing.expect(slot.update_vote(&a).? == .new);
    try expect_equivocated(slot.update_certificate(&b), a, b);
    try testing.expectEqual(.equivocated, slot.status());
    try expect_proposal(&slot, b);
    try testing.expect(!slot.should_build());
}

test "slot recovered certificate overrides equivocated vote" {
    var slot: Slot = .empty;
    const ours = proposal(27, 5, 4, 19);
    const winner = proposal(27, 5, 4, 20);
    try testing.expect(slot.update_vote(&ours).? == .new);
    try testing.expect(slot.update_vote(&winner).? == .equivocated);
    try expect_proposal(&slot, ours);
    // The certificate is authoritative even after equivocation was recorded.
    try expect_equivocated(slot.update_certificate(&winner), ours, winner);
    try expect_proposal(&slot, winner);
    try testing.expectEqual(.equivocated, slot.status());
}

test "slot certificate does not clear equivocated" {
    var slot: Slot = .empty;
    const a = proposal(25, 7, 3, 17);
    const b = proposal(25, 7, 3, 18);
    try testing.expect(slot.update_vote(&a).? == .new);
    try testing.expect(slot.update_certificate(&b) == .equivocated);
    try testing.expect(slot.update_certificate(&b) == .unchanged);
    try testing.expectEqual(.equivocated, slot.status());
    // Votes stay suppressed once equivocation is recorded.
    try testing.expect(slot.update_vote(&a) == null);
    try expect_proposal(&slot, b);
}

test "slot unequivocated proposal allows recovered unverified, blocks equivocation" {
    const a = proposal(30, 10, 9, 21);
    const b = proposal(30, 10, 9, 22);
    var slot: Slot = .empty;
    try testing.expect(!slot.has_unequivocated_proposal());
    try testing.expect(slot.update_certificate(&a) == .new);
    try testing.expect(slot.has_unequivocated_proposal());
    try testing.expect(slot.update_vote(&b).? == .equivocated);
    try testing.expect(!slot.has_unequivocated_proposal());
}

test "slot record verified keeps equivocated" {
    var slot: Slot = .empty;
    const a = proposal(31, 8, 7, 23);
    const b = proposal(31, 8, 7, 24);
    try testing.expect(slot.update_vote(&a).? == .new);
    try testing.expect(slot.update_vote(&b).? == .equivocated);
    try testing.expect(slot.record_verified(a));
    try expect_proposal(&slot, a);
    try testing.expectEqual(.equivocated, slot.status());
    try testing.expect(!slot.should_build());
    try testing.expect(!slot.should_verify());
}
