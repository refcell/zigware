//! Finalization progress tracking and agreement checking (commonware
//! `glue/src/simulate/tracker.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus = @import("consensus");

const Round = consensus.Round;
const Height = consensus.Height;
const View = consensus.View;
const Epoch = consensus.Epoch;

/// A finalization event from a validator (commonware `FinalizationUpdate<P>`).
pub fn FinalizationUpdate(comptime P: type) type {
    return struct {
        /// Which validator reported this finalization.
        pk: P,
        /// The finalized round.
        round: Round,
        /// The finalized application height.
        height: Height,
        /// The digest of the finalized block, as bytes; borrowed, the tracker copies it.
        block_digest: []const u8,
    };
}

/// Why the tracker refuses a finalization.
pub const ObserveError = error{
    /// A different block digest was already seen at the same application height.
    ForkAtHeight,
    /// A different block digest was already seen at the same round.
    ForkAtRound,
} || Allocator.Error;

/// Tracks finalization progress across all validators (commonware `ProgressTracker<P>`).
///
/// Validates safety invariants (agreement, no forks) and tracks liveness (progress toward a
/// finalization target). Owns copies of every digest it has seen.
pub fn ProgressTracker(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Update = FinalizationUpdate(P);

        const KeyContext = struct {
            pub fn hash(_: KeyContext, key: P) u32 {
                const encoded = codec.encode_fixed(P, key);
                return @truncate(std.hash.Wyhash.hash(0, &encoded));
            }

            pub fn eql(_: KeyContext, a: P, b: P, _: usize) bool {
                return a.eql(b);
            }
        };

        gpa: Allocator,
        /// Latest finalized round per validator.
        status: std.ArrayHashMapUnmanaged(P, Round, KeyContext, true) = .empty,
        /// Distinct block digests seen at each round (for fork detection).
        digests_by_round: std.AutoHashMapUnmanaged(Round, std.ArrayList([]u8)) = .empty,
        /// Block digest seen at each application height.
        digests_by_height: std.AutoHashMapUnmanaged(u64, []u8) = .empty,

        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa };
        }

        pub fn deinit(self: *Self) void {
            var rounds = self.digests_by_round.valueIterator();
            while (rounds.next()) |digests| {
                for (digests.items) |digest| self.gpa.free(digest);
                digests.deinit(self.gpa);
            }
            self.digests_by_round.deinit(self.gpa);
            var heights = self.digests_by_height.valueIterator();
            while (heights.next()) |digest| self.gpa.free(digest.*);
            self.digests_by_height.deinit(self.gpa);
            self.status.deinit(self.gpa);
            self.* = undefined;
        }

        /// Records a finalization update from a validator.
        ///
        /// Fails if a different block digest was already seen at the same round or
        /// application height. Replayed tips are checked for agreement without regressing
        /// the validator's latest finalized round.
        pub fn observe(self: *Self, update: Update) ObserveError!void {
            const by_height = try self.digests_by_height.getOrPut(self.gpa, update.height.get());
            if (!by_height.found_existing) {
                by_height.value_ptr.* = self.gpa.dupe(u8, update.block_digest) catch |err| {
                    self.digests_by_height.removeByPtr(by_height.key_ptr);
                    return err;
                };
            }
            if (!std.mem.eql(u8, by_height.value_ptr.*, update.block_digest)) {
                return error.ForkAtHeight;
            }

            const by_round = try self.digests_by_round.getOrPut(self.gpa, update.round);
            if (!by_round.found_existing) by_round.value_ptr.* = .empty;
            const digests = by_round.value_ptr;
            if (!contains(digests.items, update.block_digest)) {
                try digests.ensureUnusedCapacity(self.gpa, 1);
                digests.appendAssumeCapacity(try self.gpa.dupe(u8, update.block_digest));
            }
            assert(digests.items.len >= 1);
            if (digests.items.len > 1) return error.ForkAtRound;

            const status = try self.status.getOrPut(self.gpa, update.pk);
            if (!status.found_existing or status.value_ptr.order(update.round) == .lt) {
                status.value_ptr.* = update.round;
            }
        }

        fn contains(digests: []const []u8, digest: []const u8) bool {
            for (digests) |seen| if (std.mem.eql(u8, seen, digest)) return true;
            return false;
        }

        /// Whether at least `total` validators have finalized at or past view `required`.
        pub fn all_reached(self: *const Self, total: usize, required: u64) bool {
            var reached: usize = 0;
            for (self.status.values()) |round| {
                if (round.view.get() >= required) reached += 1;
            }
            assert(reached <= self.status.count());
            return reached >= total;
        }

        /// The minimum finalized view across all tracked validators, zero if none.
        pub fn min_view(self: *const Self) u64 {
            const rounds = self.status.values();
            if (rounds.len == 0) return 0;
            var result: u64 = std.math.maxInt(u64);
            for (rounds) |round| result = @min(result, round.view.get());
            return result;
        }

        /// The highest finalized round observed from any validator.
        pub fn max_round(self: *const Self) ?Round {
            var result: ?Round = null;
            for (self.status.values()) |round| {
                if (result == null or result.?.order(round) == .lt) result = round;
            }
            return result;
        }

        /// The number of validators currently tracked.
        pub fn tracked_count(self: *const Self) usize {
            return self.status.count();
        }

        /// The number of distinct finalized block digests observed at `view` of epoch zero.
        pub fn unique_digests_at(self: *const Self, view: u64) usize {
            const round = Round.new(.zero(), View.new(view));
            const digests = self.digests_by_round.get(round) orelse return 0;
            return digests.items.len;
        }
    };
}
