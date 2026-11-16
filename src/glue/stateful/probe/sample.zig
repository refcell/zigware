//! Floor sampling shared by the stateful and DKG probes (commonware
//! `glue/src/stateful/probe/sample.rs`).
//!
//! Both probes discover a floor by soliciting a committee's latest finalizations and selecting
//! the highest from `f + 1` distinct replies. `Sample` owns that bookkeeping: one reply per
//! peer, the fault-budget threshold, and selection of the highest reply. Each probe keeps its own
//! wire format, committee source, minimum-epoch filter, verification, and peer blocking.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const utils = @import("utils");

const Epoch = consensus.Epoch;

/// An `f + 1` sample of a committee's latest finalizations (`consensus.simplex.types
/// .Finalization(S, D)`), keyed by `S.PublicKey`.
///
/// The sample counts at most one reply per peer and resolves to the highest reply once `f + 1`
/// distinct peers have contributed, where `f` is the solicited committee's maximum fault count
/// under `3f + 1`. If at most `f` members are faulty, `f + 1` replies include an honest one, so
/// the floor is at least as recent as that member's reply.
///
/// Callers verify replies and enforce committee membership before recording them, and judge at
/// selection time which recorded replies are usable (a reply becomes unjudgeable if its epoch's
/// scheme is forgotten). The sample owns recorded replies and the floor.
pub fn Sample(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = S.PublicKey;
        pub const Finalization = consensus.simplex.types.Finalization(S, D);
        const Reply = struct { peer: PublicKey, finalization: Finalization };

        gpa: Allocator,
        minimum_epoch: Epoch,
        /// One reply per peer, sorted by peer (commonware's `BTreeMap`, whose order breaks
        /// ties between replies of equal rounds).
        replies: std.ArrayList(Reply) = .empty,
        floor: ?Finalization = null,

        /// An empty sample that ignores replies below `minimum_epoch`.
        pub fn init(gpa: Allocator, minimum_epoch: Epoch) Self {
            return .{ .gpa = gpa, .minimum_epoch = minimum_epoch };
        }

        pub fn deinit(self: *Self) void {
            self.reset();
            self.replies.deinit(self.gpa);
            self.* = undefined;
        }

        /// The selected floor, if the sample has resolved.
        pub fn get_floor(self: *const Self) ?*const Finalization {
            return if (self.floor) |*floor| floor else null;
        }

        /// Whether a reply from `peer` is still awaited: false once the floor is selected or
        /// after `peer` contributed to the current round. Check before decoding or verifying,
        /// so a duplicate costs nothing and is never treated as a fault.
        pub fn awaits(self: *const Self, peer: PublicKey) bool {
            return self.floor == null and self.find(peer) == null;
        }

        /// Records `finalization` (taking ownership) as `peer`'s reply, keeping only the first
        /// reply from each peer in a round. The caller verified it and checked membership, and
        /// discards replies below `minimum_epoch` without treating them as faults.
        pub fn record(
            self: *Self,
            peer: PublicKey,
            finalization: Finalization,
        ) Allocator.Error!void {
            var owned = finalization;
            const index = self.insertion_index(peer);
            if (index < self.replies.items.len and self.replies.items[index].peer.eql(peer)) {
                owned.deinit(self.gpa);
                return;
            }
            errdefer owned.deinit(self.gpa);
            try self.replies.insert(self.gpa, index, .{ .peer = peer, .finalization = owned });
            assert(self.find(peer) == index);
        }

        /// Discards the floor and every reply, starting a new request round.
        pub fn reset(self: *Self) void {
            for (self.replies.items) |*reply| reply.finalization.deinit(self.gpa);
            self.replies.clearRetainingCapacity();
            if (self.floor) |*floor| floor.deinit(self.gpa);
            self.floor = null;
        }

        /// Selects the highest judgeable reply once `f + 1` replies are judgeable, with `f` from
        /// `committee_size`. Only replies for which `judge.judgeable(*const Finalization)` holds
        /// count. Returns the floor (borrowed from the sample) exactly once, when first
        /// selected.
        pub fn select(
            self: *Self,
            committee_size: usize,
            judge: anytype,
        ) Allocator.Error!?*const Finalization {
            if (self.floor != null) return null;
            var best: ?*const Finalization = null;
            var count: usize = 0;
            for (self.replies.items) |*reply| {
                const finalization = &reply.finalization;
                if (!judge.judgeable(finalization)) continue;
                count += 1;
                const higher = if (best) |candidate|
                    finalization.round().order(candidate.round()) == .gt
                else
                    true;
                if (higher) best = finalization;
            }
            const floor = best orelse return null;
            if (count < @as(usize, utils.N3f1.max_faults(committee_size)) + 1) return null;
            self.floor = try floor.clone(self.gpa);
            return &self.floor.?;
        }

        fn find(self: *const Self, peer: PublicKey) ?usize {
            const index = self.insertion_index(peer);
            if (index == self.replies.items.len) return null;
            if (!self.replies.items[index].peer.eql(peer)) return null;
            return index;
        }

        /// The first position whose peer is not below `peer`.
        fn insertion_index(self: *const Self, peer: PublicKey) usize {
            var low: usize = 0;
            var high: usize = self.replies.items.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                if (self.replies.items[middle].peer.order(peer) == .lt) {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            assert(low <= self.replies.items.len);
            return low;
        }
    };
}
