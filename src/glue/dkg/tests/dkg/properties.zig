//! The one-shot DKG end-to-end property (commonware `glue::dkg::tests::dkg::properties`).
//!
//! `DkgOutcome(S, expected)` checks every active participant's state after a plan. On
//! success, each completed with an epoch-zero artifact over exactly the participants, with no
//! next players or reveals, the same output everywhere, and a stored epoch-zero share. On
//! failure, each completed without an artifact and without persisting a share. Rust picks the
//! property's name from `expected` at run time; here `expected` is comptime, so `name` is a
//! constant as `simulate.property.Property` requires.
//!
//! `S` provides `completed(state) bool`, `info(state) ?*const Info` (borrowed), and
//! `has_share(state, Epoch) bool`.

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../../types.zig");
const simulate_tracker = @import("../../../simulate/tracker.zig");

const Epoch = consensus.Epoch;
const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const PublicKey = cryptography.ed25519.PublicKey;
const MinPk = cryptography.bls12381.primitives.MinPk;

/// The epoch-zero artifact a one-shot DKG reports.
pub const Info = types.EpochInfo(MinPk, PublicKey, Unit);

/// Whether the plan expects the ceremony to succeed.
pub const ExpectedOutcome = enum { success, failure };

/// Why `DkgOutcome` rejects the final states.
pub const Error = error{
    /// The number of active states differs from the participant count.
    StateCount,
    /// A state did not report a completion.
    NotCompleted,
    /// A successful ceremony left a state without an artifact.
    MissingInfo,
    /// A failed ceremony produced an artifact.
    FailedWithInfo,
    /// A failed ceremony persisted an epoch-zero share.
    FailedWithShare,
    /// The artifact's outcome is not `success`.
    UnexpectedOutcome,
    /// The artifact is not for epoch zero.
    UnexpectedEpoch,
    /// The output's players are not the participants.
    OutputPlayers,
    /// The artifact's players are not the participants.
    InfoPlayers,
    /// A one-shot DKG announced next players.
    NextPlayers,
    /// The output revealed shares.
    Revealed,
    /// Participants produced different outputs.
    OutputsDiffer,
    /// The secret store lacks the epoch-zero share.
    MissingShare,
};

pub fn DkgOutcome(comptime S: type, comptime expected: ExpectedOutcome) type {
    return struct {
        const Self = @This();
        pub const name = switch (expected) {
            .success => "dkg_success",
            .failure => "dkg_failure",
        };
        pub const Tracker = simulate_tracker.ProgressTracker(PublicKey);

        /// The participants, borrowed; they outlive the property.
        participants: Set(PublicKey),

        pub fn check(
            self: *const Self,
            tracker: *const Tracker,
            states: []const *const S,
        ) Error!void {
            _ = tracker;
            assert(self.participants.len() > 0);
            if (states.len != self.participants.len()) return error.StateCount;
            var first: ?*const Info = null;
            for (states) |state| {
                if (!state.completed()) return error.NotCompleted;
                const info = state.info() orelse {
                    if (expected == .success) return error.MissingInfo;
                    if (state.has_share(Epoch.zero())) return error.FailedWithShare;
                    continue;
                };
                if (expected == .failure) return error.FailedWithInfo;
                try self.check_info(info);
                if (first) |output| {
                    if (!info.output.eql(output.output)) return error.OutputsDiffer;
                } else first = info;
                if (!state.has_share(Epoch.zero())) return error.MissingShare;
            }
        }

        fn check_info(self: *const Self, info: *const Info) Error!void {
            assert(expected == .success);
            if (info.outcome != .success) return error.UnexpectedOutcome;
            if (info.epoch.get() != 0) return error.UnexpectedEpoch;
            if (!info.output.players.eql(self.participants)) return error.OutputPlayers;
            if (!info.players.eql(self.participants)) return error.InfoPlayers;
            if (info.next_players.len() != 0) return error.NextPlayers;
            if (info.output.revealed.len() != 0) return error.Revealed;
        }
    };
}
