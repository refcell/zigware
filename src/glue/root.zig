//! glue: Default constructions that span multiple primitives.
//!
//! Zig port of commonware's `commonware-glue` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/glue). Lane: glue (see
//! docs/lanes/glue.md).
//!
//! - `simulate`: a harness for deterministic simulations of validator stacks.

const std = @import("std");

pub const simulate = @import("simulate/mod.zig");

test {
    std.testing.refAllDecls(@This());
}
