//! bench: Abstract benchmark workloads.
//!
//! Zig port of commonware's `commonware-bench` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/bench). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
