//! The processor's prune schedule and its finalization boundary (commonware
//! `glue/src/stateful/actor/processor/mod.rs`: `Pruning`, `Prune`, `FinalizationBoundary`,
//! `Disposition`, `ExecutionStep`; `PruneConfig` from `actor/core/mod.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");

const Height = consensus.types.Height;
const Round = consensus.Round;

/// How `Stateful` prunes databases and marshal.
pub const PruneConfig = struct {
    /// Finalized blocks between pruning attempts. `Stateful` picks a random phase within it at
    /// startup; it controls how often pruning runs, not how much history is retained.
    maintenance_interval: u64,
    /// Finalized blocks to retain in marshal beyond its acknowledgement window plus one; enough
    /// for a rebooted node to catch up from peers.
    retained_marshal_blocks: u64,
    /// Finalized blocks' worth of operations to retain in QMDB beyond marshal's
    /// acknowledgement window plus one, to serve state sync to lagging peers. Usually 0.
    retained_qmdb_blocks: u64,

    /// Marshal must retain at least as many blocks as QMDB (commonware panics).
    pub fn validate(config: PruneConfig) error{InvalidPruneConfig}!void {
        if (config.maintenance_interval == 0) return error.InvalidPruneConfig;
        if (config.retained_marshal_blocks < config.retained_qmdb_blocks) {
            return error.InvalidPruneConfig;
        }
    }
};

/// Marshal and database prune targets selected from finalized history.
pub fn Prune(comptime T: type) type {
    return struct {
        marshal_height: Height,
        /// The finalized height whose sync targets are the database prune target.
        barrier_height: Height,
        qmdb_target: T,
    };
}

/// The prune schedule and the finalized sync targets `T` it retains: a prune is due at
/// heights congruent to `offset` modulo the interval, once a full marshal retention window
/// has been recorded since startup.
pub fn Pruning(comptime T: type) type {
    return struct {
        const Self = @This();

        interval: u64,
        offset: u64,
        marshal_window: usize,
        qmdb_window: usize,
        /// A ring of the last `marshal_window` (height, targets), oldest at `head`.
        heights: []Height,
        targets: []T,
        head: usize = 0,
        count: usize = 0,

        /// A schedule whose phase is random within the interval.
        pub fn random(
            gpa: Allocator,
            config: PruneConfig,
            max_pending_acks: u64,
            random_source: std.Random,
        ) !Self {
            try config.validate();
            const offset = random_source.int(u64) % config.maintenance_interval;
            return init(gpa, config, max_pending_acks, offset);
        }

        /// A schedule that prunes at heights congruent to `offset` modulo the interval.
        pub fn init(
            gpa: Allocator,
            config: PruneConfig,
            max_pending_acks: u64,
            offset: u64,
        ) !Self {
            try config.validate();
            if (offset >= config.maintenance_interval) return error.InvalidPruneConfig;
            const base = std.math.add(u64, max_pending_acks, 1) catch
                return error.InvalidPruneConfig;
            const marshal_window = std.math.add(u64, base, config.retained_marshal_blocks) catch
                return error.InvalidPruneConfig;
            const qmdb_window = base + config.retained_qmdb_blocks; // At most marshal_window.
            assert(qmdb_window <= marshal_window);
            const heights = try gpa.alloc(Height, @intCast(marshal_window));
            errdefer gpa.free(heights);
            const targets = try gpa.alloc(T, @intCast(marshal_window));
            return .{
                .interval = config.maintenance_interval,
                .offset = offset,
                .marshal_window = @intCast(marshal_window),
                .qmdb_window = @intCast(qmdb_window),
                .heights = heights,
                .targets = targets,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.heights);
            gpa.free(self.targets);
            self.* = undefined;
        }

        /// Records the sync targets of the finalized block at `height` and returns a prune if
        /// one is due: marshal to the oldest retained height, the databases to the oldest
        /// targets in the database retention window.
        pub fn observe(self: *Self, height: Height, targets: T) ?Prune(T) {
            const window = self.marshal_window;
            if (self.count == window) {
                self.head = (self.head + 1) % window;
                self.count -= 1;
            }
            const slot = (self.head + self.count) % window;
            self.heights[slot] = height;
            self.targets[slot] = targets;
            self.count += 1;
            assert(self.count <= window);

            if (height.get() % self.interval != self.offset) return null;
            if (self.count < window) return null;
            const qmdb_slot = (self.head + self.count - self.qmdb_window) % window;
            return .{
                .marshal_height = self.heights[self.head],
                .barrier_height = self.heights[qmdb_slot],
                .qmdb_target = self.targets[qmdb_slot],
            };
        }
    };
}

/// One block's processing, which requests share.
pub fn ExecutionStep(comptime D: type) type {
    return struct {
        digest: D,
        parent: D,
        round: Round,
    };
}

/// How an execution step crosses a maintenance boundary.
pub const Disposition = enum {
    /// Continue work proven to descend from the finalized block.
    retain,
    /// Finish this step before maintenance proceeds.
    join,
    /// Reject work whose parent or round is incompatible with the finalized branch.
    reject,
};

/// The cached state that stays valid once one finalized block (`digest` at `round`) is applied:
/// its compatible descendants.
pub fn FinalizationBoundary(comptime D: type) type {
    return struct {
        const Self = @This();

        digest: D,
        round: Round,
        compatible: std.AutoHashMapUnmanaged(D, void) = .empty,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.compatible.deinit(gpa);
            self.* = undefined;
        }

        /// Classifies `step` against the incoming finalized branch.
        pub fn disposition(self: *const Self, step: *const ExecutionStep(D)) Disposition {
            if (std.meta.eql(step.digest, self.digest)) return .join;
            if (step.round.order(self.round) == .gt and self.compatible.contains(step.parent)) {
                return .retain;
            }
            return .reject;
        }

        /// Lets a completed retained descendant parent later retained steps.
        pub fn completed(self: *Self, gpa: Allocator, step: *const ExecutionStep(D)) !void {
            assert(self.disposition(step) == .retain);
            try self.compatible.put(gpa, step.digest, {});
        }
    };
}
