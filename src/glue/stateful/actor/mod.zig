//! The `Stateful` actor's parts (commonware `glue/src/stateful/actor`). So far: the syncer's
//! `SyncPlan`, the durable startup decision between peer state sync and recovery from marshal,
//! and the processor's prune schedule and finalization boundary.

const std = @import("std");

pub const plan = @import("syncer/plan.zig");
pub const SyncPlan = plan.SyncPlan;
pub const SyncState = plan.SyncState;

pub const pruning = @import("processor/pruning.zig");
pub const PruneConfig = pruning.PruneConfig;
pub const Pruning = pruning.Pruning;
pub const Prune = pruning.Prune;
pub const FinalizationBoundary = pruning.FinalizationBoundary;

test {
    std.testing.refAllDecls(@This());
    _ = @import("syncer/plan_test.zig");
    _ = @import("processor/pruning_test.zig");
}
