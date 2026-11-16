//! State sync's anchors, tip updates, and the generation coordinator of tuple sets (commonware
//! `glue/src/stateful/db/mod.rs`: `Anchor`, `TipUpdate`, `dispatch_queued_tips`,
//! `DbSyncState`, `CoordinatorAction`, `CoordinatorState`).
//!
//! # Anchors
//!
//! A sync starts from the sync targets of one finalized block, its anchor. Finalized tips
//! that arrive while it runs replace the targets when they are higher; a tip at or below the
//! current anchor is ignored, and a higher tip with unchanged targets only moves the anchor.
//!
//! # Convergence (tuple sets)
//!
//! Each tip dispatched to a tuple set's databases is a generation. A database seeks the
//! targets of its assigned generation and reports when it reaches them. The set finishes once
//! every database reached the same generation with no tip pending. When every database has
//! reached but at different generations, the ones behind regroup on the highest.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const consensus = @import("consensus");
const utils = @import("utils");
const db = @import("mod.zig");

const Height = consensus.types.Height;
const Round = consensus.Round;
const oneshot = utils.channel.oneshot;
const ring = utils.channel.ring;

/// The most databases a set holds (`db.Tuple`'s bound).
pub const max_databases = 8;

/// The finalized block that carries a set of sync targets.
pub fn Anchor(comptime D: type) type {
    return struct {
        const Self = @This();

        height: Height,
        round: Round,
        digest: D,

        pub fn eql(a: Self, b: Self) bool {
            return a.height.get() == b.height.get() and a.round.order(b.round) == .eq and
                std.meta.eql(a.digest, b.digest);
        }
    };
}

/// A finalized tip delivered to a running sync, optionally observed: its observer resolves
/// once a sync handled it, adopted or not, and fails with `error.Closed` if it is dropped
/// unhandled.
pub fn TipUpdate(comptime D: type, comptime T: type) type {
    return struct {
        const Self = @This();

        anchor: Anchor(D),
        targets: T,
        observed: ?oneshot.Sender(void) = null,

        pub fn init(anchor: Anchor(D), targets: T) Self {
            return .{ .anchor = anchor, .targets = targets };
        }

        pub const Observed = struct { update: Self, observed: oneshot.Receiver(void) };

        /// An update and the receiver that resolves once a sync handled it.
        pub fn with_observation(gpa: Allocator, io: Io, anchor: Anchor(D), targets: T) !Observed {
            const pair = try oneshot.channel(void, gpa, io);
            return .{
                .update = .{ .anchor = anchor, .targets = targets, .observed = pair.sender },
                .observed = pair.receiver,
            };
        }

        /// Passes the anchor and targets to `context.record`, then resolves the observer.
        /// Consumes the update.
        pub fn record(self: *Self, context: anytype) void {
            context.record(self.anchor, self.targets);
            if (self.observed) |*observed| {
                // `send` releases the sender. A dropped observer asked for nothing.
                observed.send({}) catch {};
            }
            self.* = undefined;
        }

        /// Drops the update unhandled (a channel's discard hook): its observer fails.
        pub fn discard(self: Self) void {
            var update = self;
            if (update.observed) |*observed| observed.deinit();
        }
    };
}

/// Drains queued tip updates, keeping the highest above `current_anchor`, and moves the anchor
/// to it. Sends its targets on `target_tx` only when they differ from `current_target`.
/// Returns false when the target receiver is gone. A disconnected update channel is closed
/// and set to null.
pub fn dispatch_queued_tips(
    comptime D: type,
    comptime T: type,
    tip_updates: *?ring.Receiver(TipUpdate(D, T)),
    target_tx: ring.Sender(T),
    current_anchor: *Anchor(D),
    current_target: *T,
) bool {
    const Latest = struct {
        anchor: Anchor(D),
        targets: T,
        found: bool = false,

        pub fn record(latest: *@This(), anchor: Anchor(D), targets: T) void {
            if (anchor.height.get() <= latest.anchor.height.get()) return;
            latest.* = .{ .anchor = anchor, .targets = targets, .found = true };
        }
    };
    var latest: Latest = .{ .anchor = current_anchor.*, .targets = current_target.* };
    while (tip_updates.*) |*receiver| {
        var update = receiver.try_recv() catch |err| switch (err) {
            error.Empty => break,
            error.Disconnected => {
                receiver.deinit();
                tip_updates.* = null;
                break;
            },
        };
        update.record(&latest);
    }
    if (!latest.found) return true;
    assert(latest.anchor.height.get() > current_anchor.height.get());
    current_anchor.* = latest.anchor;
    if (db.targets_eql(T, &latest.targets, current_target)) return true;
    current_target.* = latest.targets;
    return target_tx.send_lossy(latest.targets);
}

/// One database's progress toward its assigned generation.
pub const DbSyncState = union(enum) {
    /// Still syncing toward the generation's targets.
    seeking: u64,
    /// Reported reaching the generation's targets.
    reached: u64,

    pub fn generation(state: DbSyncState) u64 {
        return switch (state) {
            .seeking, .reached => |value| value,
        };
    }

    pub fn is_reached(state: DbSyncState) bool {
        return state == .reached;
    }
};

/// What the coordinator does after processing events.
pub fn CoordinatorAction(comptime D: type, comptime T: type) type {
    return union(enum) {
        /// Nothing until the next event.
        wait,
        /// Dispatch `targets` as `generation` to the databases still seeking.
        dispatch: struct { generation: u64, targets: T },
        /// Every database reached the targets of one generation, carried by `anchor`.
        converged: struct { anchor: Anchor(D), targets: T },
    };
}

/// The convergence state machine of a tuple set's sync: each database's assigned generation
/// and whether it reached it, and the anchor and targets of every assigned generation.
pub fn CoordinatorState(comptime D: type, comptime T: type) type {
    return struct {
        const Self = @This();
        const Action = CoordinatorAction(D, T);
        const Generation = struct { generation: u64, anchor: Anchor(D), targets: T };
        const Tip = struct { anchor: Anchor(D), targets: T };

        dbs_buffer: [max_databases]DbSyncState,
        db_count: usize,
        /// Assigned generations: at most one per database, plus one being inserted.
        generations_buffer: [max_databases + 1]Generation,
        generation_count: usize,
        current_generation: u64,
        latest_tip: ?Tip,
        last_dispatched_anchor: Anchor(D),

        pub fn init(db_count: usize, anchor: Anchor(D), targets: T) Self {
            assert(db_count > 0);
            assert(db_count <= max_databases);
            var self: Self = .{
                .dbs_buffer = undefined,
                .db_count = db_count,
                .generations_buffer = undefined,
                .generation_count = 1,
                .current_generation = 0,
                .latest_tip = null,
                .last_dispatched_anchor = anchor,
            };
            @memset(self.dbs(), .{ .seeking = 0 });
            self.generations_buffer[0] = .{ .generation = 0, .anchor = anchor, .targets = targets };
            return self;
        }

        fn dbs(self: *Self) []DbSyncState {
            return self.dbs_buffer[0..self.db_count];
        }

        fn generations(self: *Self) []Generation {
            return self.generations_buffer[0..self.generation_count];
        }

        /// Records that database `index` reached `generation`. Late events for a generation the
        /// database is no longer assigned are ignored.
        pub fn record_reached(self: *Self, index: usize, generation: u64) void {
            assert(index < self.db_count);
            const state = &self.dbs()[index];
            if (state.generation() != generation) return;
            state.* = .{ .reached = generation };
        }

        /// Records a tip as the pending dispatch, replacing an earlier pending tip. A tip at or
        /// below the pending or last dispatched anchor's height is ignored; targets are not
        /// compared.
        pub fn record_tip_update(self: *Self, anchor: Anchor(D), targets: T) void {
            const current = if (self.latest_tip) |tip| tip.anchor else self.last_dispatched_anchor;
            if (anchor.height.get() <= current.height.get()) return;
            self.latest_tip = .{ .anchor = anchor, .targets = targets };
        }

        /// The next action, updating assignments for a dispatch. Converges when every database
        /// reached the same generation and no tip is pending. Dispatches a pending tip as a
        /// new generation, or regroups when every database reached different generations.
        /// After a dispatch, `should_dispatch` names the databases that receive the targets.
        pub fn next_action(self: *Self) Action {
            var all_reached = true;
            var min_generation: u64 = std.math.maxInt(u64);
            var max_generation: u64 = 0;
            for (self.dbs()) |state| {
                all_reached = all_reached and state.is_reached();
                min_generation = @min(min_generation, state.generation());
                max_generation = @max(max_generation, state.generation());
            }
            if (all_reached and min_generation != max_generation) {
                return self.regroup(max_generation);
            }
            const tip = self.latest_tip orelse {
                if (!all_reached) return .wait;
                const entry = self.find(min_generation);
                return .{ .converged = .{ .anchor = entry.anchor, .targets = entry.targets } };
            };
            // A pending tip starts a new generation for the databases not at their target
            // (every database, when all reached the same generation).
            self.latest_tip = null;
            const generation = self.current_generation + 1;
            self.current_generation = generation;
            for (self.dbs()) |*state| {
                if (all_reached or !state.is_reached()) state.* = .{ .seeking = generation };
            }
            assert(self.generation_count < self.generations_buffer.len);
            self.generations_buffer[self.generation_count] = .{
                .generation = generation,
                .anchor = tip.anchor,
                .targets = tip.targets,
            };
            self.generation_count += 1;
            self.last_dispatched_anchor = tip.anchor;
            self.prune_generations();
            return .{ .dispatch = .{ .generation = generation, .targets = tip.targets } };
        }

        /// Resets the databases behind `max_generation` to seek it.
        fn regroup(self: *Self, max_generation: u64) Action {
            const targets = self.find(max_generation).targets;
            for (self.dbs()) |*state| {
                if (state.generation() != max_generation) {
                    state.* = .{ .seeking = max_generation };
                }
            }
            self.prune_generations();
            return .{ .dispatch = .{ .generation = max_generation, .targets = targets } };
        }

        fn find(self: *Self, generation: u64) *const Generation {
            for (self.generations()) |*entry| {
                if (entry.generation == generation) return entry;
            }
            unreachable; // Every assigned generation keeps its state until unassigned.
        }

        /// Drops the state of generations no database is assigned.
        fn prune_generations(self: *Self) void {
            var kept: usize = 0;
            for (self.generations()) |entry| {
                const assigned = for (self.dbs()) |state| {
                    if (state.generation() == entry.generation) break true;
                } else false;
                if (!assigned) continue;
                self.generations_buffer[kept] = entry;
                kept += 1;
            }
            self.generation_count = kept;
            assert(kept > 0);
            assert(kept <= self.db_count);
        }

        /// Whether database `index` receives a dispatch's targets (it has not reached its
        /// generation).
        pub fn should_dispatch(self: *Self, index: usize) bool {
            assert(index < self.db_count);
            return !self.dbs()[index].is_reached();
        }

        /// Marks a reached database as reached for `generation`; no effect on a seeking one.
        /// Only for a database whose target is unchanged in `generation`.
        pub fn mark_reached_same_target(self: *Self, index: usize, generation: u64) void {
            assert(index < self.db_count);
            const state = &self.dbs()[index];
            if (!state.is_reached()) return;
            state.* = .{ .reached = generation };
        }
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("sync_test.zig");
}
