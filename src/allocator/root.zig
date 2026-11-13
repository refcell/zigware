//! allocator: Allocate and manage memory.
//!
//! Zig port of commonware's `commonware-allocator` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/allocator). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
