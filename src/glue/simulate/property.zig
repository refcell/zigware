//! Properties checked during and after a simulation (commonware
//! `glue/src/simulate/property.rs`). A property fails by returning an error; the plan logs its
//! name and fails the run.

const std = @import("std");
const tracker = @import("tracker.zig");

/// A property checked after each finalization against the states of the active validators
/// (commonware `FinalizationProperty<S>`). A property value has `pub const name` and
/// `pub fn check(self, states) !void`.
pub fn FinalizationProperty(comptime S: type) type {
    return struct {
        const Self = @This();
        const Check = fn (*const anyopaque, []const *const S) anyerror!void;

        context: *const anyopaque,
        name: []const u8,
        check_fn: *const Check,

        /// Wraps `property`, a pointer to a property value that outlives the plan.
        pub fn from(property: anytype) Self {
            const T = @typeInfo(@TypeOf(property)).pointer.child;
            const Erased = struct {
                fn check(context: *const anyopaque, states: []const *const S) anyerror!void {
                    const typed: *const T = @ptrCast(@alignCast(context));
                    return typed.check(states);
                }
            };
            return .{ .context = property, .name = T.name, .check_fn = Erased.check };
        }

        pub fn check(self: Self, states: []const *const S) anyerror!void {
            return self.check_fn(self.context, states);
        }
    };
}

/// A property checked once at the end of a simulation, inside the runtime, with the progress
/// tracker and the states of the active validators (commonware `Property<P, S>`). A property
/// value has `pub const name` and `pub fn check(self, tracker, states) !void`.
pub fn Property(comptime P: type, comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Tracker = tracker.ProgressTracker(P);
        const Check = fn (*const anyopaque, *const Tracker, []const *const S) anyerror!void;

        context: *const anyopaque,
        name: []const u8,
        check_fn: *const Check,

        /// Wraps `property`, a pointer to a property value that outlives the plan.
        pub fn from(property: anytype) Self {
            const T = @typeInfo(@TypeOf(property)).pointer.child;
            const Erased = struct {
                fn check(
                    context: *const anyopaque,
                    progress: *const Tracker,
                    states: []const *const S,
                ) anyerror!void {
                    const typed: *const T = @ptrCast(@alignCast(context));
                    return typed.check(progress, states);
                }
            };
            return .{ .context = property, .name = T.name, .check_fn = Erased.check };
        }

        pub fn check(self: Self, progress: *const Tracker, states: []const *const S) anyerror!void {
            return self.check_fn(self.context, progress, states);
        }
    };
}
