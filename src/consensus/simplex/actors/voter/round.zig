//! The voter's state for one round (commonware `actors/voter/round.rs`): the leader, the
//! proposal slot, our nullify-or-finalize decision and its deadlines, the certificates, and
//! certification.
//!
//! Times are runtime nanoseconds (`context.now_ns`). Tracing spans are not ported. An
//! outstanding certification holds no handle: the voter cancels the task itself and ignores
//! results for rounds that are no longer `outstanding`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const metrics = @import("../../metrics.zig");
const slot_mod = @import("slot.zig");

const Participant = consensus_types.Participant;
const View = consensus_types.View;
const TimeoutReason = metrics.TimeoutReason;

/// Runtime nanoseconds.
pub const Instant = i96;

/// A deadline and why it fires.
pub const Timeout = struct { deadline: Instant, reason: TimeoutReason };

/// Our nullify or finalize vote for the round, and the round-local timeouts that can still
/// fire. Neither vote is retracted, so a round never returns to `pending`.
const Decision = union(enum) {
    /// Neither vote broadcast. `latch` holds the first explicit timeout and never moves.
    pending: struct {
        leader: ?Instant = null,
        certification: ?Instant = null,
        latch: ?Timeout = null,
    },
    /// Nullify broadcast; only the retry deadline can fire (scheduled on the next poll).
    nullify: struct { retry: ?Instant = null },
    /// Finalize broadcast; no round-local timeout can fire.
    finalize,
};

pub fn Leader(comptime P: type) type {
    return struct { index: Participant, key: P };
}

const CertifyState = union(enum) {
    ready,
    outstanding,
    /// True if certification succeeded, false if the automaton declined.
    certified: bool,
    /// Canceled by a finalization.
    aborted,
};

/// Outcome of `request_verify`.
pub const VerifyRequest = enum {
    /// Claimed; send it to the automaton.
    send,
    /// Claimed but not sent: certification of the round was already requested.
    withhold,
    /// The round is not pending verification.
    skip,
};

pub fn Round(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const Proposal = types.Proposal(D);
        const Notarization = types.Notarization(S, D);
        const Nullification = types.Nullification(S);
        const Finalization = types.Finalization(S, D);
        pub const LeaderInfo = Leader(S.PublicKey);
        pub const Verifying = struct { proposal: Proposal, parent_payload: D };

        entered_at: ?Instant = null,
        proposed_at: ?Instant = null,
        scheme: *const S,
        round: consensus_types.Round,
        leader_: ?LeaderInfo = null,
        slot: slot_mod.Slot(D) = .empty,
        decision: Decision = .{ .pending = .{} },
        stall_deadline_: ?Instant = null,
        notarization_: ?Notarization = null,
        broadcast_notarize_: bool = false,
        broadcast_notarization_: bool = false,
        nullification_: ?Nullification = null,
        broadcast_nullification_: bool = false,
        finalization_: ?Finalization = null,
        broadcast_finalization_: bool = false,
        certify: CertifyState = .ready,
        last_ancestry_request: ?View = null,
        verifying_: ?Verifying = null,

        pub fn init(scheme: *const S, round: consensus_types.Round) Self {
            return .{ .scheme = scheme, .round = round };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.notarization_) |*certificate| certificate.deinit(gpa);
            if (self.nullification_) |*certificate| certificate.deinit(gpa);
            if (self.finalization_) |*certificate| certificate.deinit(gpa);
            self.* = undefined;
        }

        fn propose_ready(self: *const Self) ?LeaderInfo {
            const elected = self.leader_ orelse return null;
            if (!self.is_signer(elected.index)) return null;
            if (self.decision == .nullify or !self.slot.should_build()) return null;
            return elected;
        }

        pub fn should_propose(self: *const Self) bool {
            return self.propose_ready() != null;
        }

        /// The leader, when we should start building a proposal locally.
        pub fn try_propose(self: *Self) ?LeaderInfo {
            const elected = self.propose_ready() orelse return null;
            self.slot.set_building();
            assert(!self.slot.should_build());
            return elected;
        }

        /// Clears the local proposal request; a new build may follow only while the slot is
        /// empty.
        pub fn clear_proposal_request(self: *Self) void {
            self.slot.clear_request();
        }

        fn verify_ready(self: *const Self) ?LeaderInfo {
            const elected = self.leader_ orelse return null;
            if (self.is_signer(elected.index)) return null;
            if (self.decision == .nullify or !self.slot.should_verify()) return null;
            return elected;
        }

        /// The leader and proposal if the verification request can be claimed, without
        /// claiming it.
        pub fn pending_verification(self: *const Self) ?struct { LeaderInfo, Proposal } {
            const elected = self.verify_ready() orelse return null;
            const proposal_ = self.slot.proposal() orelse return null;
            return .{ elected, proposal_.* };
        }

        /// Claims the round's single verification request.
        pub fn request_verify(self: *Self) VerifyRequest {
            if (self.verify_ready() == null or !self.slot.request_verify()) return .skip;
            assert(!self.slot.should_verify());
            return switch (self.certify) {
                .ready => .send,
                .outstanding, .certified, .aborted => .withhold,
            };
        }

        /// Records the ancestry view verification requested; false for a repeat.
        pub fn request(self: *Self, view: View) bool {
            if (self.last_ancestry_request) |last| if (last == view) return false;
            self.last_ancestry_request = view;
            return true;
        }

        pub fn set_verifying(self: *Self, proposal_: Proposal, parent_payload: D) void {
            self.verifying_ = .{ .proposal = proposal_, .parent_payload = parent_payload };
        }

        pub fn verifying(self: *const Self) ?*const Verifying {
            if (self.verifying_) |*value| return value;
            return null;
        }

        pub fn clear_verifying(self: *Self) void {
            self.verifying_ = null;
        }

        /// The notarized proposal ready for certification, without recording the request.
        pub fn pending_certification(self: *const Self) ?Proposal {
            const notarization_ = &(self.notarization_ orelse return null);
            if (self.certify != .ready) return null;
            const held = self.slot.proposal() orelse
                @panic("proposal must be set if notarization is set");
            assert(held.eql(notarization_.proposal)); // Slot matches the notarization.
            return held.*;
        }

        /// Records that a certification request is in flight.
        pub fn set_certify_outstanding(self: *Self) void {
            assert(self.certify == .ready);
            self.certify = .outstanding;
        }

        pub fn is_certify_outstanding(self: *const Self) bool {
            return self.certify == .outstanding;
        }

        /// Aborts the in-flight certification request.
        pub fn abort_certify(self: *Self) void {
            if (self.certify == .certified) return;
            self.certify = .aborted;
        }

        pub fn is_certify_aborted(self: *const Self) bool {
            return self.certify == .aborted;
        }

        pub fn leader(self: *const Self) ?*const LeaderInfo {
            if (self.leader_) |*value| return value;
            return null;
        }

        /// Whether the local participant controls `signer`.
        pub fn is_signer(self: *const Self, signer: Participant) bool {
            const membership = self.scheme.me() orelse return false;
            const index = membership.signer_index() orelse return false;
            return index.get() == signer.get();
        }

        pub fn set_leader(self: *Self, index: Participant) void {
            const key = self.scheme.participants().key(index) orelse
                @panic("leader index comes from elector, must be within bounds");
            self.leader_ = .{ .index = index, .key = key.* };
        }

        pub fn notarization(self: *const Self) ?*const Notarization {
            if (self.notarization_) |*value| return value;
            return null;
        }

        pub fn nullification(self: *const Self) ?*const Nullification {
            if (self.nullification_) |*value| return value;
            return null;
        }

        pub fn finalization(self: *const Self) ?*const Finalization {
            if (self.finalization_) |*value| return value;
            return null;
        }

        pub fn is_certified(self: *const Self) bool {
            return self.certify == .certified and self.certify.certified;
        }

        fn is_failed_certification(self: *const Self) bool {
            return self.certify == .certified and !self.certify.certified;
        }

        /// Whether we saw a notarization or finalization for this round itself.
        pub fn is_directly_notarized(self: *const Self) bool {
            return self.notarization_ != null or self.finalization_ != null;
        }

        /// Finalized, or notarized unless our own certification rejected it.
        fn has_usable_certificate(self: *const Self) bool {
            if (self.finalization_ != null) return true;
            return self.notarization_ != null and !self.is_failed_certification();
        }

        /// The payload of ancestry this round's certificate supports, read from the
        /// certificate.
        pub fn certificate_ancestry_payload(self: *const Self) ?D {
            if (!self.has_usable_certificate()) return null;
            if (self.finalization_) |*value| return value.proposal.payload;
            return self.notarization_.?.proposal.payload;
        }

        /// The certified proposal (a finalized round is implicitly certified).
        pub fn certified_proposal(self: *const Self) ?*const Proposal {
            if (self.finalization_ == null and !self.is_certified()) return null;
            return self.slot.proposal() orelse @panic("proposal must exist");
        }

        pub fn certified_payload(self: *const Self) ?D {
            const value = self.certified_proposal() orelse return null;
            return value.payload;
        }

        /// The proposal, if it may be forwarded (see `has_usable_certificate`).
        pub fn forwardable_proposal(self: *const Self) ?*const Proposal {
            if (!self.has_usable_certificate()) return null;
            return self.slot.proposal();
        }

        /// Whether we verified the proposal (built it, or verified a peer's).
        pub fn is_verified(self: *const Self) bool {
            return self.slot.status() == .verified;
        }

        pub fn broadcast_notarize(self: *const Self) bool {
            return self.broadcast_notarize_;
        }

        /// Records when we entered this view; the first entry wins.
        pub fn mark_entered(self: *Self, now: Instant) void {
            if (self.entered_at == null) self.entered_at = now;
        }

        /// Time since we built our proposal (when leading) or entered the view.
        pub fn elapsed_since_start(self: *const Self, now: Instant) ?u64 {
            const start = self.proposed_at orelse self.entered_at orelse return null;
            return @intCast(@max(now - start, 0));
        }

        pub fn elapsed_since_entry(self: *const Self, now: Instant) ?u64 {
            const start = self.entered_at orelse return null;
            return @intCast(@max(now - start, 0));
        }

        /// Completes the local proposal flow. False when we already nullified or the slot
        /// holds a different proposal.
        pub fn proposed(self: *Self, now: Instant, value: Proposal) bool {
            if (self.decision == .nullify) return false;
            if (!self.slot.record_verified(value)) return false;
            self.proposed_at = now;
            return true;
        }

        /// Completes peer verification. False when we already nullified or a certificate
        /// replaced the proposal.
        pub fn verified(self: *Self) bool {
            if (self.decision == .nullify) return false;
            return self.slot.mark_verified();
        }

        /// Sets the leader's proposal from the batcher. Returns whether to verify it.
        pub fn set_proposal(self: *Self, value: *const Proposal) bool {
            if (self.decision == .nullify) return false;
            const change = self.slot.update_vote(value) orelse return false;
            return change == .new;
        }

        /// Marks certification as complete.
        pub fn certified(self: *Self, is_success: bool) void {
            if (self.certify == .certified) {
                assert(self.certify.certified == is_success); // Certification never conflicts.
                return;
            }
            self.certify = .{ .certified = is_success };
        }

        pub fn proposal(self: *const Self) ?*const Proposal {
            return self.slot.proposal();
        }

        pub fn has_unequivocated_proposal(self: *const Self) bool {
            return self.slot.has_unequivocated_proposal();
        }

        /// Arms the deadlines on view entry; once either vote is cast only the stall deadline
        /// is armed.
        pub fn set_deadlines(
            self: *Self,
            leader_deadline: Instant,
            certification_deadline: Instant,
            stall: ?Instant,
        ) void {
            switch (self.decision) {
                .pending => |*pending| {
                    pending.leader = leader_deadline;
                    pending.certification = certification_deadline;
                },
                .nullify, .finalize => {},
            }
            self.stall_deadline_ = stall;
        }

        /// Latches the first explicit timeout; ignored after either vote.
        pub fn latch_timeout(self: *Self, now: Instant, reason: TimeoutReason) void {
            switch (self.decision) {
                .pending => |*pending| {
                    if (pending.latch != null) return;
                    pending.latch = .{ .deadline = now, .reason = reason };
                },
                .nullify, .finalize => {},
            }
        }

        /// Records a nullify vote: true for a retry, false for the first, null once we
        /// finalized.
        pub fn construct_nullify(self: *Self) ?bool {
            if (self.decision == .finalize) return null;
            const retry = self.decision == .nullify;
            self.decision = .{ .nullify = .{} };
            return retry;
        }

        /// The next round-local timeout.
        pub fn next_timeout(
            self: *Self,
            now: Instant,
            retry_interval_ns: u64,
            allow_latched_timeout: bool,
        ) ?Timeout {
            if (self.finalization_ != null) return null;
            const proposed_ = self.slot.proposal() != null;
            switch (self.decision) {
                .finalize => return null,
                .nullify => |*nullify| {
                    if (nullify.retry == null) nullify.retry = now + retry_interval_ns;
                    return .{ .deadline = nullify.retry.?, .reason = .retry };
                },
                .pending => |pending| {
                    if (allow_latched_timeout) if (pending.latch) |latch| return latch;
                    if (!proposed_) if (pending.leader) |deadline| {
                        return .{ .deadline = deadline, .reason = .leader_timeout };
                    };
                    if (!self.is_certified()) if (pending.certification) |deadline| {
                        return .{ .deadline = deadline, .reason = .certification_timeout };
                    };
                    return null;
                },
            }
        }

        /// The same-term stall deadline while the round is unfinalized.
        pub fn stall_deadline(self: *const Self) ?Instant {
            if (self.finalization_ != null) return null;
            return self.stall_deadline_;
        }

        /// Adds a proposal recovered from a certificate. Returns the leader's key when it
        /// equivocated.
        pub fn add_recovered_proposal(self: *Self, value: *const Proposal) ?S.PublicKey {
            return switch (self.slot.update_certificate(value)) {
                .new, .unchanged => null,
                .equivocated => if (self.leader_) |leader_| leader_.key else null,
            };
        }

        pub const Added = struct { added: bool, equivocator: ?S.PublicKey };

        /// Takes ownership of `certificate` when added; otherwise the caller keeps it.
        pub fn add_notarization(self: *Self, certificate: Notarization) Added {
            if (self.notarization_ != null) return .{ .added = false, .equivocator = null };
            const equivocator = self.add_recovered_proposal(&certificate.proposal);
            self.notarization_ = certificate;
            return .{ .added = true, .equivocator = equivocator };
        }

        /// Takes ownership of `certificate` when added; otherwise the caller keeps it.
        pub fn add_nullification(self: *Self, certificate: Nullification) bool {
            if (self.nullification_ != null) return false;
            self.nullification_ = certificate;
            return true;
        }

        /// Takes ownership of `certificate` when added; otherwise the caller keeps it.
        pub fn add_finalization(self: *Self, certificate: Finalization) Added {
            if (self.finalization_ != null) return .{ .added = false, .equivocator = null };
            const equivocator = self.add_recovered_proposal(&certificate.proposal);
            self.finalization_ = certificate;
            return .{ .added = true, .equivocator = equivocator };
        }

        /// The notarization to broadcast, once.
        pub fn broadcast_notarization(self: *Self) ?*const Notarization {
            if (self.broadcast_notarization_) return null;
            const value = self.notarization() orelse return null;
            self.broadcast_notarization_ = true;
            return value;
        }

        /// The nullification to broadcast, once.
        pub fn broadcast_nullification(self: *Self) ?*const Nullification {
            if (self.broadcast_nullification_) return null;
            const value = self.nullification() orelse return null;
            self.broadcast_nullification_ = true;
            return value;
        }

        /// The finalization to broadcast, once.
        pub fn broadcast_finalization(self: *Self) ?*const Finalization {
            if (self.broadcast_finalization_) return null;
            const value = self.finalization() orelse return null;
            self.broadcast_finalization_ = true;
            return value;
        }

        /// Whether `construct_notarize` would yield a proposal: not yet voted notarize or
        /// nullify, and the proposal is verified (so not equivocated).
        pub fn can_construct_notarize(self: *const Self) bool {
            if (self.broadcast_notarize_ or self.decision == .nullify) return false;
            return self.slot.status() == .verified;
        }

        /// The proposal to notarize, marking the vote as broadcast.
        pub fn construct_notarize(self: *Self) ?*const Proposal {
            if (!self.can_construct_notarize()) return null;
            self.broadcast_notarize_ = true;
            return self.slot.proposal();
        }

        /// The proposal to finalize: no vote cast yet, an unequivocated notarized proposal,
        /// and our certification succeeded.
        pub fn construct_finalize(self: *Self) ?*const Proposal {
            if (self.decision != .pending) return null;
            if (!self.slot.has_unequivocated_proposal()) return null;
            if (self.notarization_ == null or !self.is_certified()) return null;
            self.decision = .finalize;
            return self.slot.proposal();
        }

        /// Restores state from a journaled artifact.
        pub fn replay(self: *Self, artifact: *const types.Artifact(S, D)) void {
            switch (artifact.*) {
                .notarize => |*notarize| {
                    assert(self.is_signer(notarize.attestation.signer)); // Our own vote.
                    _ = self.slot.record_verified(notarize.proposal);
                    self.broadcast_notarize_ = true;
                },
                .nullify => |*nullify| {
                    assert(self.is_signer(nullify.attestation.signer)); // Our own vote.
                    assert(self.decision != .finalize); // Conflicts with a local finalize.
                    self.decision = .{ .nullify = .{} };
                },
                .finalize => |*finalize| {
                    assert(self.is_signer(finalize.attestation.signer)); // Our own vote.
                    assert(self.decision != .nullify); // Conflicts with a local nullify.
                    self.decision = .finalize;
                },
                .notarization => self.broadcast_notarization_ = true,
                .nullification => self.broadcast_nullification_ = true,
                .finalization => self.broadcast_finalization_ = true,
                .certification => |certification| self.certified(certification.certified),
            }
        }
    };
}

test {
    _ = @import("round_test.zig");
}
