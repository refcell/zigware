//! Simulation harness for testing compositions of the primitives (commonware
//! `glue/src/simulate`): a declarative plan composes a validator stack (p2p, consensus,
//! application) with injected actions, progress tracking, and property checks.
//!
//! - `ProgressTracker` monitors finalization progress and agreement.
//! - `Schedule`, `Action`, and `Crash` describe the faults a plan injects.
//! - `Plan` runs an engine definition (`engine.zig`) on every validator, injecting its faults
//!   and checking its exit condition and properties.

const std = @import("std");

pub const action = @import("action.zig");
pub const tracker = @import("tracker.zig");
pub const engine = @import("engine.zig");
pub const events = @import("events.zig");
pub const exit = @import("exit.zig");
pub const plan = @import("plan.zig");
pub const processed = @import("processed.zig");
pub const property = @import("property.zig");
pub const team = @import("team.zig");

pub const Action = action.Action;
pub const Schedule = action.Schedule;
pub const Crash = action.Crash;
pub const HeightRange = action.HeightRange;
pub const FaultConfig = action.FaultConfig;
pub const FinalizationUpdate = tracker.FinalizationUpdate;
pub const ProgressTracker = tracker.ProgressTracker;
pub const ObserveError = tracker.ObserveError;
pub const ChannelSpec = engine.ChannelSpec;
pub const InitContext = engine.InitContext;
pub const Monitor = events.Monitor;
pub const ExitCondition = exit.ExitCondition;
pub const MinimumFinalizations = exit.MinimumFinalizations;
pub const ProcessedHeightAtLeast = exit.ProcessedHeightAtLeast;
pub const FinalizationProperty = property.FinalizationProperty;
pub const Property = property.Property;
pub const Plan = plan.Plan;
pub const PlanError = plan.Error;
pub const Team = team.Team;

test {
    std.testing.refAllDecls(@This());
    _ = @import("simulate_test.zig");
    _ = @import("plan_test.zig");
}
