//! Post-run properties of the stateful e2e plans (commonware
//! `glue/src/stateful/tests/properties.rs`), over `single_db.NodeState`.

const std = @import("std");
const assert = std.debug.assert;

const log = std.log.scoped(.stateful_e2e);

/// Every active validator serves the same finalized block at `height`.
pub const BlockAgreementAtHeight = struct {
    pub const name = "block_agreement_at_height";
    height: u64,

    pub fn check(self: *const BlockAgreementAtHeight, _: anytype, states: anytype) !void {
        assert(states.len > 0);
        var expected: ?[32]u8 = null;
        for (states, 0..) |state, index| {
            const digest = try state.digest_at_height(self.height) orelse {
                log.err("validator {d} has no finalized digest at height {d}", .{
                    index,
                    self.height,
                });
                return error.MissingFinalizedDigest;
            };
            if (expected) |previous| {
                if (!std.mem.eql(u8, &previous, &digest.bytes)) {
                    log.err("digest disagreement at finalized height {d}", .{self.height});
                    return error.DigestDisagreement;
                }
            } else expected = digest.bytes;
        }
        assert(expected != null);
    }
};

/// Every active validator pruned the block at `pruned_height` from marshal and still serves the
/// one at `retained_height`.
pub const MarshalPrunedBelow = struct {
    pub const name = "marshal_pruned_below";
    pruned_height: u64,
    retained_height: u64,

    pub fn check(self: *const MarshalPrunedBelow, _: anytype, states: anytype) !void {
        assert(self.pruned_height < self.retained_height);
        for (states, 0..) |state, index| {
            if (try state.digest_at_height(self.retained_height) == null) {
                log.err("validator {d} pruned the retained block at height {d}", .{
                    index,
                    self.retained_height,
                });
                return error.RetainedBlockPruned;
            }
            if (try state.digest_at_height(self.pruned_height) != null) {
                log.err("validator {d} still serves height {d}; marshal did not prune", .{
                    index,
                    self.pruned_height,
                });
                return error.MarshalNotPruned;
            }
        }
    }
};

/// Every active validator's database discarded operations below `min_oldest_retained`.
pub const QmdbPruned = struct {
    pub const name = "qmdb_pruned";
    min_oldest_retained: u64,

    pub fn check(self: *const QmdbPruned, _: anytype, states: anytype) !void {
        assert(self.min_oldest_retained > 0);
        for (states, 0..) |state, index| {
            const oldest = try state.oldest_retained();
            if (oldest < self.min_oldest_retained) {
                log.err("validator {d} retains operations from {d}; expected past {d}", .{
                    index,
                    oldest,
                    self.min_oldest_retained,
                });
                return error.QmdbNotPruned;
            }
        }
    }
};

/// At least one validator used state sync and then processed past the synced height.
///
/// Beyond commonware, the validator's plan must also have recorded completion: syncing
/// acknowledges retained blocks to marshal, so marshal's processed height advances past the
/// synced height even while a sync that never finishes is still fetching.
pub const LateJoinerStateSyncHandoff = struct {
    pub const name = "late_joiner_state_sync_handoff";

    pub fn check(_: *const LateJoinerStateSyncHandoff, _: anytype, states: anytype) !void {
        assert(states.len > 0);
        for (states) |state| {
            const synced = state.state_sync_height() orelse continue;
            if (!state.state_sync_completed()) continue;
            if (state.processed_height() > synced) return;
        }
        log.err("no validator both used state sync and advanced beyond the synced height", .{});
        return error.NoStateSyncHandoff;
    }
};

/// A validator crashed during state sync, restarted into it from its persisted floor, and
/// then processed past the synced height.
/// Like `LateJoinerStateSyncHandoff`, its plan must also have recorded completion.
pub const CrashDuringStateSyncRecovery = struct {
    pub const name = "crash_during_state_sync_recovery";

    pub fn check(_: *const CrashDuringStateSyncRecovery, _: anytype, states: anytype) !void {
        assert(states.len > 0);
        for (states, 0..) |state, index| {
            const processed = state.processed_height();
            log.info("validator {d}: resumed={} sync_height={?d} processed_height={d}", .{
                index,
                state.state_sync_resumed(),
                state.state_sync_height(),
                processed,
            });
            const synced = state.state_sync_height() orelse continue;
            if (!state.state_sync_completed()) continue;
            if (state.state_sync_resumed() and processed > synced) return;
        }
        log.err("no validator re-entered state sync after a crash and then advanced", .{});
        return error.NoStateSyncRecovery;
    }
};
