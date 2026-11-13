//! formatting: Format and parse encoded data.
//!
//! Zig port of commonware's `commonware-formatting` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/formatting). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
