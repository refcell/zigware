//! glue: Default constructions that span multiple primitives.
//!
//! Zig port of commonware's `commonware-glue` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/glue). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
