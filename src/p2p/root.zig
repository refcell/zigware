//! p2p: Communicate with authenticated peers.
//!
//! Zig port of commonware's `commonware-p2p` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/p2p). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
