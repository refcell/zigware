//! Simulation harness for testing compositions of the primitives (commonware
//! `glue/src/simulate`): a declarative plan composes a validator stack (p2p, consensus,
//! application) with injected actions, progress tracking, and property checks.
//!
//! - `ProgressTracker` monitors finalization progress and agreement.
//! - `Schedule`, `Action`, and `Crash` describe the faults a plan injects.

const std = @import("std");

pub const action = @import("action.zig");
pub const tracker = @import("tracker.zig");

pub const Action = action.Action;
pub const Schedule = action.Schedule;
pub const Crash = action.Crash;
pub const HeightRange = action.HeightRange;
pub const FaultConfig = action.FaultConfig;
pub const FinalizationUpdate = tracker.FinalizationUpdate;
pub const ProgressTracker = tracker.ProgressTracker;
pub const ObserveError = tracker.ObserveError;

test {
    std.testing.refAllDecls(@This());
    _ = @import("simulate_test.zig");
}
