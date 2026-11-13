//! stream: Exchange messages over arbitrary transport.
//!
//! Zig port of commonware's `commonware-stream` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/stream). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
