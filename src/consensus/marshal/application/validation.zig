//! Invariant checks shared by marshal's verification and certification flows (commonware
//! `marshal/application/validation.rs`).

const std = @import("std");
const types = @import("../../types.zig");

const Epoch = types.Epoch;
const Height = types.Height;
const Round = types.Round;

/// Which marshal cache holds a structurally valid candidate. This selects where candidate
/// bytes are stored; it is not, by itself, an application-validity claim. Callers that start
/// the store before application verification completes must still combine the verdict with
/// store durability before allowing a finalize vote.
pub const Stage = enum {
    /// Store in `verified_blocks`.
    verified,
    /// Store in `notarized_blocks`.
    certified,

    /// Stores `block` through `marshal` (a core mailbox) for this stage, returning once it is
    /// durably persisted (false if marshal could not accept it).
    pub fn store(self: Stage, marshal: anytype, round: Round, block: anytype) !bool {
        return switch (self) {
            .verified => marshal.verified(round, block),
            .certified => marshal.certified(round, block),
        };
    }
};

/// Whether `height` is the last block of `epoch`.
fn is_at_epoch_boundary(epocher: anytype, height: Height, epoch: Epoch) bool {
    comptime types.assert_epocher(@TypeOf(epocher));
    const last = epocher.last(epoch) orelse return false;
    return last.get() == height.get();
}

/// Whether a verify-time re-proposal is valid: only the last block of the epoch may be
/// re-proposed.
pub fn is_valid_reproposal_at_verify(epocher: anytype, height: Height, epoch: Epoch) bool {
    return is_at_epoch_boundary(epocher, height, epoch);
}

/// Whether a certify-time block should be treated as a re-proposal. Certification may only
/// have the block's embedded round, so a block counts as one when it is an epoch-boundary
/// block, the certify view is later than the embedded view, and both rounds share an epoch.
pub fn is_inferred_reproposal_at_certify(
    epocher: anytype,
    height: Height,
    embedded_round: Round,
    certify_round: Round,
) bool {
    return is_at_epoch_boundary(epocher, height, embedded_round.epoch) and
        certify_round.view.get() > embedded_round.view.get() and
        certify_round.epoch.get() == embedded_round.epoch.get();
}

/// Whether `epocher` places `height` in `expected_epoch` (false for heights it cannot place).
pub fn is_block_in_expected_epoch(epocher: anytype, height: Height, expected_epoch: Epoch) bool {
    comptime types.assert_epocher(@TypeOf(epocher));
    const bounds = epocher.containing(height) orelse return false;
    return bounds.epoch.get() == expected_epoch.get();
}

const testing = std.testing;
const utils = @import("utils");

fn epocher_of(length: u64) types.FixedEpocher {
    return .new(utils.NonZero(u64).init(length).?);
}

test "is valid reproposal at verify" {
    const epocher = epocher_of(10);
    try testing.expect(is_valid_reproposal_at_verify(epocher, .new(9), .new(0)));
    try testing.expect(!is_valid_reproposal_at_verify(epocher, .new(8), .new(0)));
    const max = std.math.maxInt(u64);
    try testing.expect(!is_valid_reproposal_at_verify(epocher, .new(0), .new(max)));
}

test "is inferred reproposal at certify" {
    const epocher = epocher_of(10);
    const embedded: Round = .new(.new(0), .new(9));
    try testing.expect(is_inferred_reproposal_at_certify(epocher, .new(9), embedded, .new(
        .new(0),
        .new(10),
    )));
    try testing.expect(!is_inferred_reproposal_at_certify(epocher, .new(9), embedded, .new(
        .new(0),
        .new(9),
    )));
    try testing.expect(!is_inferred_reproposal_at_certify(epocher, .new(9), embedded, .new(
        .new(1),
        .new(10),
    )));
    try testing.expect(!is_inferred_reproposal_at_certify(epocher, .new(8), .new(
        .new(0),
        .new(8),
    ), .new(.new(0), .new(9))));
}

test "is block in expected epoch" {
    const epocher = epocher_of(10);
    try testing.expect(is_block_in_expected_epoch(epocher, .new(7), .new(0)));
    try testing.expect(!is_block_in_expected_epoch(epocher, .new(7), .new(1)));
    const max = std.math.maxInt(u64);
    try testing.expect(!is_block_in_expected_epoch(epocher, .new(max), .new(0)));
}
