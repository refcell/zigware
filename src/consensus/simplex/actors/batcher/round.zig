//! The batcher's state for one round (commonware `actors/batcher/round.rs`): checks each
//! network vote against the sender, detects conflicts, reports activity, and feeds the
//! verifier that builds certificates.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const verifier_mod = @import("verifier.zig");
const votes_mod = @import("votes.zig");

const Participant = consensus_types.Participant;
const Outcome = votes_mod.Outcome;

pub fn Round(comptime S: type, comptime B: type, comptime D: type, comptime R: type) type {
    return struct {
        const Self = @This();
        const Verifier = verifier_mod.Verifier(S, D);
        const Tracker = votes_mod.VoteTracker(S, D);
        const Vote = types.Vote(S, D);
        const Proposal = types.Proposal(D);
        const Activity = types.Activity(S, D);
        pub const Certificate = types.Certificate(S, D);
        pub const Kind = Verifier.Kind;
        pub const Batch = verifier_mod.Batch(Certificate);

        blocker: B,
        reporter: R,
        verifier: Verifier,
        votes: Tracker,
        proposal_sent: bool = false,

        pub fn init(
            round: consensus_types.Round,
            scheme: *const S,
            blocker: B,
            reporter: R,
            track_historical_votes: bool,
        ) Self {
            const participants: u32 = @intCast(scheme.participants().len());
            const votes = Tracker.init(participants, track_historical_votes);
            return with_votes(round, scheme, blocker, reporter, votes);
        }

        /// A round below the current view: votes are only remembered, never kept.
        pub fn skipped(
            round: consensus_types.Round,
            scheme: *const S,
            blocker: B,
            reporter: R,
        ) Self {
            const participants: u32 = @intCast(scheme.participants().len());
            return with_votes(round, scheme, blocker, reporter, Tracker.skipped(participants));
        }

        fn with_votes(
            round: consensus_types.Round,
            scheme: *const S,
            blocker: B,
            reporter: R,
            votes: Tracker,
        ) Self {
            const quorum = scheme.participants().quorum(S.Faults);
            assert(quorum > 0);
            return .{
                .blocker = blocker,
                .reporter = reporter,
                .verifier = Verifier.init(round, scheme, quorum),
                .votes = votes,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.verifier.deinit(gpa);
            self.votes.deinit(gpa);
            self.* = undefined;
        }

        pub fn has_certificate(self: *const Self, kind: Kind) bool {
            return self.verifier.has_certificate(kind);
        }

        /// Records a certificate for this round. Returns whether buffered votes for a newly
        /// learned proposal should be processed.
        pub fn record_certificate(
            self: *Self,
            gpa: Allocator,
            certificate: *const Certificate,
        ) !bool {
            const process_votes = switch (certificate.*) {
                .notarization => |*notarization| try self.set_authoritative_proposal(
                    gpa,
                    &notarization.proposal,
                ),
                .finalization => |*finalization| finalization: {
                    _ = self.verifier.set_proposal(.{ .certificate = finalization.proposal });
                    break :finalization false;
                },
                .nullification => false,
            };
            const kind = std.meta.activeTag(certificate.*);
            self.verifier.record_certificate(gpa, kind);
            try self.release_votes(gpa, kind);
            assert(self.has_certificate(kind));
            return process_votes;
        }

        fn release_votes(self: *Self, gpa: Allocator, kind: Kind) !void {
            switch (kind) {
                .notarization => {
                    const proposal = self.verifier.proposal() orelse unreachable; // Proof:
                    // a notarization sets the authoritative proposal first.
                    try self.votes.release_notarizes(gpa, proposal);
                },
                .nullification => try self.votes.release_nullifies(gpa),
                .finalization => {
                    const proposal = self.verifier.proposal() orelse unreachable; // Proof:
                    // a finalization sets the authoritative proposal first.
                    try self.votes.release_finalizes(gpa, proposal);
                },
            }
        }

        /// Records a vote and reports it. `constructed` votes are our own (already verified).
        pub fn accept_vote(self: *Self, gpa: Allocator, vote: Vote, constructed: bool) !Outcome {
            if (constructed and vote == .finalize) {
                _ = try self.set_authoritative_proposal(gpa, &vote.finalize.proposal);
            }
            const outcome = try self.votes.record(gpa, vote, self.verifier.proposal());
            const retained = switch (outcome) {
                .added => |added| added.retained,
                .duplicate => |duplicate| {
                    if (constructed and duplicate.retained and vote != .nullify) {
                        @panic("duplicate constructed vote");
                    }
                    return outcome;
                },
                .conflicting => {
                    assert(!constructed); // Conflicting constructed vote.
                    return outcome;
                },
            };
            const activity: Activity = switch (vote) {
                .notarize => |notarize| .{ .notarize = notarize },
                .nullify => |nullify| .{ .nullify = nullify },
                .finalize => |finalize| .{ .finalize = finalize },
            };
            _ = self.reporter.report(activity);
            if (retained) try self.verifier.add(gpa, vote, constructed);
            return outcome;
        }

        fn set_authoritative_proposal(
            self: *Self,
            gpa: Allocator,
            proposal: *const Proposal,
        ) !bool {
            const update = self.verifier.set_proposal(.{ .certificate = proposal.* });
            if (update.replaced) {
                var finalizes = self.votes.iter_finalizes();
                while (finalizes.next()) |finalize| {
                    if (!finalize.proposal.eql(proposal.*)) continue;
                    try self.verifier.add(gpa, .{ .finalize = finalize.* }, false);
                }
            }
            return update.changed;
        }

        fn block(self: *Self, sender: S.PublicKey) void {
            _ = self.blocker.block(sender);
        }

        /// Handles a vote from `sender`. Returns whether it was newly added.
        pub fn add_network(self: *Self, gpa: Allocator, sender: S.PublicKey, vote: Vote) !bool {
            const index = self.verifier.participants().index(sender) orelse {
                self.block(sender); // Unknown participant.
                return false;
            };
            if (index.get() != vote.signer().get()) {
                self.block(sender); // Signer mismatch.
                return false;
            }
            return switch (vote) {
                .notarize => |notarize| self.add_notarize(gpa, sender, index, notarize),
                .nullify => |nullify| self.add_nullify(gpa, sender, index, nullify),
                .finalize => |finalize| self.add_finalize(gpa, sender, index, finalize),
            };
        }

        fn add_notarize(
            self: *Self,
            gpa: Allocator,
            sender: S.PublicKey,
            index: Participant,
            notarize: types.Notarize(S, D),
        ) !bool {
            if (self.votes.notarize(index)) |previous| {
                if (!previous.proposal.eql(notarize.proposal)) {
                    const fault = types.ConflictingNotarize(S, D).init(previous.*, notarize);
                    _ = self.reporter.report(.{ .conflicting_notarize = fault });
                    self.block(sender);
                } else if (!previous.eql(notarize)) {
                    self.block(sender); // Invalid signature.
                }
                return false;
            }
            return self.accept_from_network(gpa, sender, .{ .notarize = notarize });
        }

        fn add_nullify(
            self: *Self,
            gpa: Allocator,
            sender: S.PublicKey,
            index: Participant,
            nullify: types.Nullify(S),
        ) !bool {
            if (self.votes.saw_finalize(index)) |previous| {
                switch (previous) {
                    .retained => |finalize| {
                        const fault = types.NullifyFinalize(S, D).init(nullify, finalize.*);
                        _ = self.reporter.report(.{ .nullify_finalize = fault });
                    },
                    .compacted => {},
                }
                self.block(sender); // Nullify after finalize.
                return false;
            }
            if (self.votes.nullify(index)) |previous| {
                if (!previous.eql(nullify)) self.block(sender); // Conflicting nullify.
                return false;
            }
            return self.accept_from_network(gpa, sender, .{ .nullify = nullify });
        }

        fn add_finalize(
            self: *Self,
            gpa: Allocator,
            sender: S.PublicKey,
            index: Participant,
            finalize: types.Finalize(S, D),
        ) !bool {
            if (self.votes.saw_nullify(index)) |previous| {
                switch (previous) {
                    .retained => |nullify| {
                        const fault = types.NullifyFinalize(S, D).init(nullify.*, finalize);
                        _ = self.reporter.report(.{ .nullify_finalize = fault });
                    },
                    .compacted => {},
                }
                self.block(sender); // Finalize after nullify.
                return false;
            }
            if (self.votes.finalize(index)) |previous| {
                if (!previous.proposal.eql(finalize.proposal)) {
                    const fault = types.ConflictingFinalize(S, D).init(previous.*, finalize);
                    _ = self.reporter.report(.{ .conflicting_finalize = fault });
                    self.block(sender);
                } else if (!previous.eql(finalize)) {
                    self.block(sender); // Invalid signature.
                }
                return false;
            }
            return self.accept_from_network(gpa, sender, .{ .finalize = finalize });
        }

        fn accept_from_network(
            self: *Self,
            gpa: Allocator,
            sender: S.PublicKey,
            vote: Vote,
        ) !bool {
            return switch (try self.accept_vote(gpa, vote, false)) {
                .added => true,
                .duplicate => false,
                .conflicting => conflicting: {
                    assert(vote != .nullify); // Nullify votes carry no proposal.
                    self.block(sender);
                    break :conflicting false;
                },
            };
        }

        pub fn set_leader(self: *Self, leader: Participant) void {
            self.verifier.set_leader(leader, self.votes.notarize(leader));
        }

        /// The proposal to forward to peers, once per round, unless we are the leader.
        pub fn try_forward_proposal(self: *Self, me: Participant) ?Proposal {
            if (self.proposal_sent) return null;
            const proposal = self.verifier.proposal() orelse return null;
            if (self.verifier.leader()) |leader| if (leader.get() == me.get()) return null;
            self.proposal_sent = true;
            return proposal.*;
        }

        /// Constructs the next certificate this round can form, if any.
        pub fn try_construct(
            self: *Self,
            gpa: Allocator,
            rng: anytype,
            strategy: anytype,
        ) !?Batch {
            const result = try self.verifier.try_construct_notarization(gpa, rng, strategy) orelse
                try self.verifier.try_construct_nullification(gpa, rng, strategy) orelse
                try self.verifier.try_construct_finalization(gpa, rng, strategy) orelse
                return null;
            if (result.certificate) |*certificate| {
                _ = try self.record_certificate(gpa, certificate);
            }
            return result;
        }

        pub fn has_nullify(self: *const Self, signer: Participant) bool {
            return self.votes.has_nullify(signer);
        }

        pub fn is_missing_voter(
            self: *const Self,
            proposal: *const Proposal,
            participant: Participant,
        ) bool {
            if (self.votes.has_notarize_for(participant, proposal)) return false;
            return !self.votes.has_finalize_for(participant, proposal);
        }

        /// Participants with neither a notarize nor a finalize vote for `proposal`.
        pub fn missing_voters(
            self: *const Self,
            gpa: Allocator,
            proposal: *const Proposal,
        ) ![]Participant {
            var missing: std.ArrayList(Participant) = .empty;
            errdefer missing.deinit(gpa);
            const count = self.verifier.participants().len();
            for (0..count) |index| {
                const participant = Participant.from_usize(index);
                if (self.is_missing_voter(proposal, participant)) {
                    try missing.append(gpa, participant);
                }
            }
            assert(missing.items.len <= count);
            return missing.toOwnedSlice(gpa);
        }
    };
}

test {
    _ = @import("round_test.zig");
}
