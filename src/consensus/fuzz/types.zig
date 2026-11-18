//! Shared types of the engine fuzzers (commonware `consensus/fuzz/src/types.rs` and the
//! `Configuration` of `lib.rs`).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const consensus_types = @import("../types.zig");
const bounds = @import("bounds.zig");

pub const Digest = cryptography.Sha256.Digest;

/// The epoch every fuzzed engine runs in (commonware `EPOCH`).
pub const epoch: consensus_types.Epoch = .new(333);

/// The network's size and how many of its nodes are Byzantine.
pub const Configuration = struct {
    /// Total number of nodes.
    n: u32,
    /// Number of faulty (Byzantine) nodes.
    faults: u32,
    /// Number of correct (honest) nodes.
    correct: u32,

    pub fn init(n: u32, faults: u32, correct: u32) Configuration {
        assert(faults + correct == n);
        return .{ .n = n, .faults = faults, .correct = correct };
    }

    /// Whether this configuration can make progress (liveness).
    pub fn can_finalize(self: Configuration) bool {
        return self.faults <= bounds.max_faults(self.n);
    }
};

/// 4 nodes, 1 faulty, 3 correct (the standard BFT configuration).
pub const n4f1c3: Configuration = .{ .n = 4, .faults = 1, .correct = 3 };
/// 4 nodes, 3 faulty, 1 correct (an adversarial majority, without liveness).
pub const n4f3c1: Configuration = .{ .n = 4, .faults = 3, .correct = 1 };

/// Message kinds the disrupter can send.
pub const Message = enum { notarize, nullify, finalize, random };

/// A notarization or finalization a replica reported: its proposal and signer count (null
/// for threshold schemes, which do not expose it).
pub const Certified = struct {
    view: u64,
    payload: Digest,
    /// View of the proposal's parent.
    parent: u64,
    signature_count: ?u32,
};

pub const Nullification = struct {
    view: u64,
    signature_count: ?u32,
};

/// A vote a replica signed itself: its view and, for a notarize, its proposal's parent view.
pub const Voted = struct {
    view: u64,
    parent: u64 = 0,
};

/// One replica's certificates and own votes, each sorted by view with at most one per view.
/// The own votes go beyond commonware, whose `ReplicaState` holds certificates only.
pub const Replica = struct {
    notarizations: []const Certified = &.{},
    nullifications: []const Nullification = &.{},
    finalizations: []const Certified = &.{},
    notarize_votes: []const Voted = &.{},
    nullify_votes: []const Voted = &.{},
    finalize_votes: []const Voted = &.{},
};

test "can finalize" {
    try testing.expect(n4f1c3.can_finalize());
    try testing.expect(!n4f3c1.can_finalize());
    try testing.expect(Configuration.init(4, 0, 4).can_finalize());
    try testing.expect(Configuration.init(4, 1, 3).can_finalize());
    try testing.expect(!Configuration.init(4, 2, 2).can_finalize());
}
