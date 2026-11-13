//! conformance: Automatically assert the stability of encoding and mechanisms over time.
//!
//! Zig port of commonware's `commonware-conformance` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/conformance). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
