//! consensus: Order opaque messages in a Byzantine environment.
//!
//! Zig port of commonware's `commonware-consensus` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/consensus). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
