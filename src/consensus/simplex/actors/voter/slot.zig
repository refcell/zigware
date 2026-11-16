//! A round's proposal slot (commonware `actors/voter/slot.rs`): the proposal, its
//! verification status, the build and verify requests, and detected equivocation.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../../types.zig");

/// Proposal verification status within a round.
pub const Status = enum {
    /// No proposal recorded.
    none,
    /// Proposal recorded, verification pending.
    unverified,
    /// Built locally, restored from our own vote, or verified by the automaton.
    verified,
    /// Conflicting proposals were observed; our notarize and finalize votes are suppressed.
    equivocated,
};

/// How a slot changed after an update.
pub fn Change(comptime D: type) type {
    return union(enum) {
        /// First proposal recorded for the round.
        new,
        /// The proposal matches the recorded one.
        unchanged,
        /// The proposal conflicts: `retained` is what the slot holds now.
        equivocated: struct { dropped: types.Proposal(D), retained: types.Proposal(D) },
    };
}

pub fn Slot(comptime D: type) type {
    return struct {
        const Self = @This();
        const Proposal = types.Proposal(D);

        proposal_: ?Proposal = null,
        status_: Status = .none,
        requested_build: bool = false,
        requested_verify: bool = false,

        pub const empty: Self = .{};

        pub fn proposal(self: *const Self) ?*const Proposal {
            if (self.proposal_) |*held| return held;
            return null;
        }

        pub fn status(self: *const Self) Status {
            assert((self.status_ == .none) == (self.proposal_ == null));
            return self.status_;
        }

        /// Whether the slot holds a proposal and saw no equivocation.
        pub fn has_unequivocated_proposal(self: *const Self) bool {
            return self.proposal_ != null and self.status_ != .equivocated;
        }

        pub fn should_build(self: *const Self) bool {
            return !self.requested_build and self.proposal_ == null;
        }

        pub fn set_building(self: *Self) void {
            self.requested_build = true;
        }

        /// Clears the build request.
        pub fn clear_request(self: *Self) void {
            self.requested_build = false;
        }

        /// Whether verification has yet to be requested (regardless of a proposal: the caller
        /// holds the one to verify).
        pub fn should_verify(self: *const Self) bool {
            return !self.requested_verify;
        }

        /// Records an already-verified proposal. Returns whether the slot holds it afterwards;
        /// a different held proposal is left unchanged (Twins can cause this), and recorded
        /// equivocation is kept.
        pub fn record_verified(self: *Self, value: Proposal) bool {
            if (self.proposal_) |existing| {
                if (!existing.eql(value)) return false;
            } else {
                self.proposal_ = value;
            }
            if (self.status_ != .equivocated) self.status_ = .verified;
            self.requested_build = true;
            self.requested_verify = true;
            assert(self.proposal_ != null);
            return true;
        }

        pub fn request_verify(self: *Self) bool {
            if (self.requested_verify) return false;
            self.requested_verify = true;
            return true;
        }

        pub fn mark_verified(self: *Self) bool {
            if (self.status_ != .unverified) return false;
            assert(self.proposal_ != null);
            self.status_ = .verified;
            return true;
        }

        /// Records a proposal seen in a vote. A conflicting vote never replaces the recorded
        /// proposal but marks the slot equivocated; after that, votes return null.
        pub fn update_vote(self: *Self, value: *const Proposal) ?Change(D) {
            if (self.status_ == .equivocated) return null;
            const existing = self.proposal_ orelse {
                self.proposal_ = value.*;
                self.status_ = .unverified;
                return .new;
            };
            if (existing.eql(value.*)) return .unchanged;
            self.status_ = .equivocated;
            return .{ .equivocated = .{ .dropped = value.*, .retained = existing } };
        }

        /// Records a proposal recovered from a certificate. Certificates are authoritative:
        /// a conflicting one replaces the recorded proposal (even after equivocation) and
        /// marks the slot equivocated. A certificate confers no verification status.
        pub fn update_certificate(self: *Self, value: *const Proposal) Change(D) {
            const existing = self.proposal_ orelse {
                self.proposal_ = value.*;
                self.status_ = .unverified;
                return .new;
            };
            if (existing.eql(value.*)) return .unchanged;
            self.proposal_ = value.*;
            self.requested_build = true;
            self.requested_verify = true;
            self.status_ = .equivocated;
            assert(!self.has_unequivocated_proposal());
            return .{ .equivocated = .{ .dropped = existing, .retained = value.* } };
        }
    };
}

test {
    _ = @import("slot_test.zig");
}
