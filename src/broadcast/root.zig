//! broadcast: Disseminate data over a wide-area network.
//!
//! Zig port of commonware's `commonware-broadcast` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/broadcast). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
