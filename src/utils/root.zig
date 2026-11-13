//! utils: Leverage common functionality across multiple primitives.
//!
//! Zig port of commonware's `commonware-utils` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/utils). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
