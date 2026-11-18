//! A reporter that forwards finalizations to the simulation harness (commonware
//! `glue/src/simulate/reporter.rs`).
//!
//! An engine definition (`engine.zig`) puts a `MonitorReporter` in marshal's reporter chain so
//! the harness tracks finalization progress: each `Update.tip` is sent to the plan's
//! `Monitor`, then every update, tip or block, goes on to the wrapped reporter.

const std = @import("std");
const assert = std.debug.assert;
const actor = @import("actor");
const events = @import("events.zig");

/// Wraps reporter `R` (a value or a pointer whose `report` takes marshal's `Update`) for the
/// validator with public key of type `P`.
pub fn MonitorReporter(comptime P: type, comptime R: type) type {
    const Inner = switch (@typeInfo(R)) {
        .pointer => |pointer| pointer.child,
        else => R,
    };
    comptime assert(@hasDecl(Inner, "Activity") and @hasDecl(Inner, "report"));
    return struct {
        const Self = @This();
        pub const Activity = Inner.Activity;

        inner: R,
        monitor: events.Monitor(P),
        pk: P,

        /// `pk` is the validator this reporter belongs to; `monitor` reaches the harness;
        /// `inner` receives every update after interception.
        pub fn init(pk: P, monitor: events.Monitor(P), inner: R) Self {
            return .{ .inner = inner, .monitor = monitor, .pk = pk };
        }

        pub fn report(self: *Self, activity: Activity) actor.Feedback {
            switch (activity) {
                .tip => |tip| {
                    const digest = tip.digest.as_slice();
                    assert(digest.len > 0);
                    // commonware ignores a closed monitor (`let _ = send(..)`).
                    _ = self.monitor.send(.{
                        .pk = self.pk,
                        .round = tip.round,
                        .height = tip.height,
                        .block_digest = digest,
                    });
                },
                .block => {},
            }
            return self.inner.report(activity);
        }

        comptime {
            @import("consensus").traits.assert_reporter(Self);
        }
    };
}
