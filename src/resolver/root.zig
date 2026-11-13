//! resolver: Resolve data identified by a fixed-length key.
//!
//! Zig port of commonware's `commonware-resolver` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/resolver). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
