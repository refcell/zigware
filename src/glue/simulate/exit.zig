//! Exit conditions for simulation completion (commonware `glue/src/simulate/exit.rs`).

const std = @import("std");
const assert = std.debug.assert;
const tracker = @import("tracker.zig");
const processed = @import("processed.zig");

/// A simulation termination condition over validators with public keys `P` and states `S`
/// (commonware `ExitCondition<P, S>`): a type-erased pointer to a condition value.
///
/// A condition value has `pub const name: []const u8`, optionally `pub const requires_polling`
/// (default false: checked only on finalization reports), and
/// `pub fn reached(self, tracker, states, target_count) !bool`, where `target_count` is the
/// number of validators that must satisfy it in the current run state.
pub fn ExitCondition(comptime P: type, comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Tracker = tracker.ProgressTracker(P);
        const Reached = fn (
            *const anyopaque,
            *const Tracker,
            []const *const S,
            usize,
        ) anyerror!bool;

        context: *const anyopaque,
        name: []const u8,
        requires_polling: bool,
        reached_fn: *const Reached,

        /// Wraps `condition`, a pointer to a condition value that outlives the plan.
        pub fn from(condition: anytype) Self {
            const C = @typeInfo(@TypeOf(condition)).pointer.child;
            const Erased = struct {
                fn reached(
                    context: *const anyopaque,
                    progress: *const Tracker,
                    states: []const *const S,
                    target_count: usize,
                ) anyerror!bool {
                    const typed: *const C = @ptrCast(@alignCast(context));
                    return typed.reached(progress, states, target_count);
                }
            };
            return .{
                .context = condition,
                .name = C.name,
                .requires_polling = @hasDecl(C, "requires_polling") and C.requires_polling,
                .reached_fn = Erased.reached,
            };
        }

        pub fn reached(
            self: Self,
            progress: *const Tracker,
            states: []const *const S,
            target_count: usize,
        ) anyerror!bool {
            return self.reached_fn(self.context, progress, states, target_count);
        }
    };
}

/// Exit once at least `target_count` validators have finalized view `required`.
pub const MinimumFinalizations = struct {
    pub const name = "minimum_finalizations";

    required: u64,

    pub fn reached(
        self: *const MinimumFinalizations,
        progress: anytype,
        _: anytype,
        target: usize,
    ) !bool {
        return progress.all_reached(target, self.required);
    }
};

/// Exit once at least `target_count` validators have processed application height `required`.
pub const ProcessedHeightAtLeast = struct {
    pub const name = "processed_height_at_least";
    pub const requires_polling = true;

    required: u64,

    pub fn reached(
        self: *const ProcessedHeightAtLeast,
        _: anytype,
        states: anytype,
        target: usize,
    ) !bool {
        const S = @typeInfo(@typeInfo(@TypeOf(states)).pointer.child).pointer.child;
        var count: usize = 0;
        for (states) |state| {
            if (processed.processed_height(S, state) >= self.required) count += 1;
        }
        assert(count <= states.len);
        return count >= target;
    }
};
