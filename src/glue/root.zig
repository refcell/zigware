//! glue: Default constructions that span multiple primitives.
//!
//! Zig port of commonware's `commonware-glue` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/glue). Lane: glue (see
//! docs/lanes/glue.md).
//!
//! - `simulate`: a harness for deterministic simulations of validator stacks.
//! - `stateful`: speculative and finalized QMDB state for applications built on consensus.
//! - `dkg`: threshold key generation and continuous resharing (the `dkg` section of
//!   docs/lanes/glue.md).
//! - `transfers`: settling and selecting batches of balance transfers.

const std = @import("std");

pub const simulate = @import("simulate/mod.zig");
pub const stateful = @import("stateful/mod.zig");
pub const dkg = @import("dkg/root.zig");
pub const transfers = @import("transfers/mod.zig");

test {
    std.testing.refAllDecls(@This());
}
