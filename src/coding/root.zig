//! coding: Encode data to enable recovery from a subset of fragments.
//!
//! Zig port of commonware's `commonware-coding` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/coding). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
