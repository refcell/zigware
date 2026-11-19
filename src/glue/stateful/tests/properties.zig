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
