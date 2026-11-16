//! Speculative and finalized QMDB state for applications built on consensus (commonware
//! `glue/src/stateful`).
//!
//! An application executes blocks against database batches. `Stateful` keeps speculative state
//! in memory, persists finalized state, and bootstraps through peer state sync. This port
//! proceeds module by module (see docs/lanes/glue.md, section stateful):
//!
//! - `db`: the database batch lifecycle (`Shared`, the ManagedDb contract, database sets,
//!   `Barrier`) and its QMDB implementations (`db.any`).
//! - `probe`: the floor sample and wire messages of peer-sampled floor discovery.
//! - `actor`: `SyncPlan`, the persisted startup floor (see its docs for the startup steps).

const std = @import("std");

pub const db = @import("db/mod.zig");
pub const probe = @import("probe/mod.zig");
pub const actor = @import("actor/mod.zig");
pub const SyncPlan = actor.SyncPlan;

/// Whether `Application.process` may rely on the block's finalization.
pub const Finality = enum {
    /// The block is not known to be finalized, so it must pass every validity check.
    candidate,
    /// The network finalized the block, so honest voters already accepted it as a candidate.
    finalized,
};

test {
    std.testing.refAllDecls(@This());
}
