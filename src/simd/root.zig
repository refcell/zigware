//! simd: Abstract over SIMD operations.
//!
//! Zig port of commonware's `commonware-simd` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/simd). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
