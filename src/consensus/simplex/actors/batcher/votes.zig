//! Votes the batcher has seen in one round (commonware `actors/batcher/votes.rs`).
//!
//! Each phase (notarize, nullify, finalize) keeps every vote until its certificate forms.
//! Then, unless historical votes are retained, the votes are released and only a few bits
//! per signer remain: whether it voted, whether its vote carried the certified proposal, and
//! whether that relation is known. The bits keep duplicates and conflicts detectable after
//! the evidence is gone.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");

const Participant = consensus_types.Participant;

/// What recording a vote did.
pub const Outcome = union(enum) {
    added: struct { retained: bool },
    duplicate: struct { retained: bool },
    conflicting,
};

/// A vote seen earlier: kept in full, or only remembered after compaction.
pub fn ObservedVote(comptime T: type) type {
    return union(enum) {
        retained: *const T,
        compacted,
    };
}

const PhaseBits = struct {
    seen: u8,
    has_proposal: u8,
    relation: u8,
};

const notarize_bits: PhaseBits = .{ .seen = 1 << 0, .has_proposal = 1 << 1, .relation = 1 << 2 };
const nullify_bits: PhaseBits = .{ .seen = 1 << 3, .has_proposal = 0, .relation = 0 };
const finalize_bits: PhaseBits = .{ .seen = 1 << 4, .has_proposal = 1 << 5, .relation = 1 << 6 };

/// The votes of one phase, or nothing once compacted.
fn Phase(comptime T: type) type {
    return union(enum) {
        const Self = @This();

        full: types.AttributableMap(T),
        compacted,

        fn init(participants: u32) Self {
            return .{ .full = .init(participants) };
        }

        fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .full => |*votes| votes.deinit(gpa),
                .compacted => {},
            }
            self.* = undefined;
        }

        fn get(self: *const Self, signer: Participant) ?*const T {
            return switch (self.*) {
                .full => |*votes| votes.get(signer),
                .compacted => null,
            };
        }
    };
}

pub fn VoteTracker(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const Notarize = types.Notarize(S, D);
        const Nullify = types.Nullify(S);
        const Finalize = types.Finalize(S, D);
        const Vote = types.Vote(S, D);
        const Proposal = types.Proposal(D);

        participants: u32,
        retain_votes_after_certification: bool,
        /// Per-signer `PhaseBits` flags, allocated on first compaction.
        compacted: []u8 = &.{},
        notarizes: Phase(Notarize),
        nullifies: Phase(Nullify),
        finalizes: Phase(Finalize),

        pub fn init(participants: u32, retain_votes_after_certification: bool) Self {
            assert(participants > 0);
            return .{
                .participants = participants,
                .retain_votes_after_certification = retain_votes_after_certification,
                .notarizes = .init(participants),
                .nullifies = .init(participants),
                .finalizes = .init(participants),
            };
        }

        /// A tracker for a view below the current one: it only remembers who voted.
        pub fn skipped(participants: u32) Self {
            assert(participants > 0);
            return .{
                .participants = participants,
                .retain_votes_after_certification = false,
                .notarizes = .compacted,
                .nullifies = .compacted,
                .finalizes = .compacted,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            assert(self.compacted.len == 0 or self.compacted.len == self.participants);
            gpa.free(self.compacted);
            self.notarizes.deinit(gpa);
            self.nullifies.deinit(gpa);
            self.finalizes.deinit(gpa);
            self.* = undefined;
        }

        fn flags(self: *Self, gpa: Allocator) Allocator.Error![]u8 {
            if (self.compacted.len == 0) {
                self.compacted = try gpa.alloc(u8, self.participants);
                @memset(self.compacted, 0);
            }
            assert(self.compacted.len == self.participants);
            return self.compacted;
        }

        fn remember(
            self: *Self,
            gpa: Allocator,
            signer: Participant,
            bits: PhaseBits,
            matches: ?bool,
        ) Allocator.Error!Outcome {
            const index = signer.get();
            if (index >= self.participants) return .{ .duplicate = .{ .retained = false } };
            const flag = &(try self.flags(gpa))[index];
            const previously_seen = flag.* & bits.seen != 0;
            const proposal_conflict = if (matches) |same| previously_seen and
                flag.* & bits.relation != 0 and
                (flag.* & bits.has_proposal != 0) != same else false;
            flag.* |= bits.seen;
            if (matches) |same| {
                flag.* |= bits.relation;
                if (same) flag.* |= bits.has_proposal;
            }
            assert(flag.* & bits.seen != 0);
            if (!previously_seen) return .{ .added = .{ .retained = false } };
            if (proposal_conflict) return .conflicting;
            return .{ .duplicate = .{ .retained = false } };
        }

        fn record_phase(
            self: *Self,
            gpa: Allocator,
            comptime T: type,
            phase: *Phase(T),
            vote: T,
            bits: PhaseBits,
            matches: ?bool,
        ) Allocator.Error!Outcome {
            switch (phase.*) {
                .full => |*votes| {
                    if (try votes.insert(gpa, vote)) return .{ .added = .{ .retained = true } };
                    return .{ .duplicate = .{ .retained = true } };
                },
                .compacted => return self.remember(gpa, vote.signer(), bits, matches),
            }
        }

        fn remembered(self: *const Self, signer: Participant, flag: u8) bool {
            if (signer.get() >= self.compacted.len) return false;
            return self.compacted[signer.get()] & flag != 0;
        }

        /// Records `vote`; `proposal` is the round's known proposal, if any.
        pub fn record(
            self: *Self,
            gpa: Allocator,
            vote: Vote,
            proposal: ?*const Proposal,
        ) Allocator.Error!Outcome {
            return switch (vote) {
                .notarize => |cast| self.record_phase(
                    gpa,
                    Notarize,
                    &self.notarizes,
                    cast,
                    notarize_bits,
                    if (proposal) |known| known.eql(cast.proposal) else null,
                ),
                .nullify => |cast| self.record_phase(
                    gpa,
                    Nullify,
                    &self.nullifies,
                    cast,
                    nullify_bits,
                    null,
                ),
                .finalize => |cast| self.record_phase(
                    gpa,
                    Finalize,
                    &self.finalizes,
                    cast,
                    finalize_bits,
                    if (proposal) |known| known.eql(cast.proposal) else null,
                ),
            };
        }

        fn release(
            self: *Self,
            gpa: Allocator,
            comptime T: type,
            phase: *Phase(T),
            bits: PhaseBits,
            proposal: ?*const Proposal,
        ) Allocator.Error!void {
            if (self.retain_votes_after_certification) return;
            var votes = switch (phase.*) {
                .full => |votes| votes,
                .compacted => return,
            };
            defer votes.deinit(gpa);
            if (!votes.is_empty()) {
                const flag = try self.flags(gpa);
                var iterator = votes.iterator();
                while (iterator.next()) |vote| {
                    const entry = &flag[vote.signer().get()];
                    entry.* |= bits.seen | bits.relation;
                    const carries = if (proposal) |known| known.eql(vote.proposal) else false;
                    if (carries) entry.* |= bits.has_proposal;
                }
            }
            phase.* = .compacted;
            assert(phase.* == .compacted);
        }

        pub fn release_notarizes(self: *Self, gpa: Allocator, proposal: *const Proposal) !void {
            try self.release(gpa, Notarize, &self.notarizes, notarize_bits, proposal);
        }

        pub fn release_nullifies(self: *Self, gpa: Allocator) Allocator.Error!void {
            if (self.retain_votes_after_certification) return;
            // Nullify votes carry no proposal, so only `seen` survives.
            var votes = switch (self.nullifies) {
                .full => |votes| votes,
                .compacted => return,
            };
            defer votes.deinit(gpa);
            if (!votes.is_empty()) {
                const flag = try self.flags(gpa);
                var iterator = votes.iterator();
                while (iterator.next()) |vote| flag[vote.signer().get()] |= nullify_bits.seen;
            }
            self.nullifies = .compacted;
        }

        pub fn release_finalizes(self: *Self, gpa: Allocator, proposal: *const Proposal) !void {
            try self.release(gpa, Finalize, &self.finalizes, finalize_bits, proposal);
        }

        pub fn saw_nullify(self: *const Self, signer: Participant) ?ObservedVote(Nullify) {
            if (self.nullify(signer)) |vote| return .{ .retained = vote };
            if (self.remembered(signer, nullify_bits.seen)) return .compacted;
            return null;
        }

        pub fn saw_finalize(self: *const Self, signer: Participant) ?ObservedVote(Finalize) {
            if (self.finalize(signer)) |vote| return .{ .retained = vote };
            if (self.remembered(signer, finalize_bits.seen)) return .compacted;
            return null;
        }

        pub fn has_notarize_for(
            self: *const Self,
            signer: Participant,
            proposal: *const Proposal,
        ) bool {
            if (self.remembered(signer, notarize_bits.has_proposal)) return true;
            const vote = self.notarize(signer) orelse return false;
            return vote.proposal.eql(proposal.*);
        }

        pub fn has_finalize_for(
            self: *const Self,
            signer: Participant,
            proposal: *const Proposal,
        ) bool {
            if (self.remembered(signer, finalize_bits.has_proposal)) return true;
            const vote = self.finalize(signer) orelse return false;
            return vote.proposal.eql(proposal.*);
        }

        pub fn notarize(self: *const Self, signer: Participant) ?*const Notarize {
            return self.notarizes.get(signer);
        }

        pub fn nullify(self: *const Self, signer: Participant) ?*const Nullify {
            return self.nullifies.get(signer);
        }

        pub fn finalize(self: *const Self, signer: Participant) ?*const Finalize {
            return self.finalizes.get(signer);
        }

        /// Retained finalize votes in signer order (none once compacted).
        pub fn iter_finalizes(self: *const Self) types.AttributableMap(Finalize).Iterator {
            return switch (self.finalizes) {
                .full => |*votes| votes.iterator(),
                .compacted => .{ .data = &.{} },
            };
        }

        pub fn has_nullify(self: *const Self, signer: Participant) bool {
            return self.nullify(signer) != null;
        }
    };
}

test {
    _ = @import("votes_test.zig");
}
