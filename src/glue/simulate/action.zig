//! Simulation action types (commonware `glue/src/simulate/action.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");

const Duration = utils.time.Duration;
const Link = p2p.simulated.Link;

/// Storage fault injection for the deterministic runtime (commonware `FaultConfig`).
pub const FaultConfig = runtime.storage.faulty.Config;

/// A single simulation action to apply at a specific time (commonware `Action<P>`).
pub fn Action(comptime P: type) type {
    return union(enum) {
        /// Update deterministic storage fault injection.
        set_storage_fault: FaultConfig,
        /// Reset all directed links, restoring full connectivity with the given link.
        heal: Link,
        /// Update a specific directed link by removing and re-adding it.
        update_link: struct { from: P, to: P, link: Link },
        /// Crash a specific validator.
        crash: P,
        /// Restart a previously crashed validator.
        restart: P,
    };
}

/// A time-ordered sequence of simulation actions (commonware `Schedule<P>`). Owns its events.
pub fn Schedule(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Event = struct { at: Duration, action: Action(P) };

        /// Time-indexed actions, in nondecreasing time order.
        events: std.ArrayList(Event) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.events.deinit(gpa);
            self.* = undefined;
        }

        /// Adds `action` at simulation time `at`, which must not be earlier than the most
        /// recently added event (commonware panics; this fails with `error.OutOfOrder`).
        pub fn add(
            self: *Self,
            gpa: Allocator,
            at: Duration,
            action: Action(P),
        ) (error{OutOfOrder} || Allocator.Error)!void {
            if (self.events.items.len > 0) {
                const last = self.events.items[self.events.items.len - 1].at;
                if (at.order(last) == .lt) return error.OutOfOrder;
            }
            try self.events.append(gpa, .{ .at = at, .action = action });
            assert(self.events.items.len > 0);
        }
    };
}

/// An inclusive range of processed heights.
pub const HeightRange = struct {
    min: u64,
    max: u64,

    pub fn contains(self: HeightRange, height: u64) bool {
        assert(self.min <= self.max);
        return height >= self.min and height <= self.max;
    }
};

/// Crash strategy for a simulation run (commonware `Crash<P>`).
pub fn Crash(comptime P: type) type {
    return union(enum) {
        /// Periodically crash random validators and restart them after a downtime.
        random: struct {
            /// How often to trigger crashes.
            frequency: Duration,
            /// How long crashed validators stay offline.
            downtime: Duration,
            /// Number of validators to crash each time.
            count: usize,
        },
        /// Delay specific validators until the given round is observed.
        delay_round: struct {
            /// Validators to delay; borrowed.
            participants: []const P,
            /// Round to wait for before starting delayed validators.
            round: consensus.Round,
        },
        /// Crash a validator when its application enters a processed-height window, then
        /// restart it after the downtime.
        processed_height: struct {
            /// Validator to crash.
            participant: P,
            /// Processed-height window in which the crash must occur.
            heights: HeightRange,
            /// How long the validator remains offline.
            downtime: Duration,
        },
        /// Time-indexed action schedule for precise control; borrowed.
        schedule: *const Schedule(P),
    };
}
