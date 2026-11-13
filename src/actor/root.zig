//! actor: Safely coordinate concurrent components.
//!
//! Zig port of commonware's `commonware-actor` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/actor). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
