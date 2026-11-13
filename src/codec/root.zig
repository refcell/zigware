//! codec: Serialize structured data.
//!
//! Zig port of commonware's `commonware-codec` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/codec). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
