//! math: Create and manipulate mathematical objects.
//!
//! Zig port of commonware's `commonware-math` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/math). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
