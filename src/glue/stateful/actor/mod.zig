//! The `Stateful` actor's parts (commonware `glue/src/stateful/actor`). So far: the syncer's
//! `SyncPlan`, the durable startup decision between peer state sync and recovery from marshal.

const std = @import("std");

pub const plan = @import("syncer/plan.zig");
pub const SyncPlan = plan.SyncPlan;
pub const SyncState = plan.SyncState;

test {
    std.testing.refAllDecls(@This());
    _ = @import("syncer/plan_test.zig");
}
