//! invariants: Define and exercise invariants.
//!
//! Zig port of commonware's `commonware-invariants` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/invariants). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
