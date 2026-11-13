//! collector: Collect responses to committable requests.
//!
//! Zig port of commonware's `commonware-collector` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/collector). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
