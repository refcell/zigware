//! parallel: Parallelize fold operations with pluggable execution strategies.
//!
//! Zig port of commonware's `commonware-parallel` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/parallel). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
