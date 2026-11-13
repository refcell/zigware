//! clearing: Settle actions at scale.
//!
//! Zig port of commonware's `commonware-clearing` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/clearing). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
