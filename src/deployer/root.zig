//! deployer: Deploy infrastructure across cloud providers.
//!
//! Zig port of commonware's `commonware-deployer` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/deployer). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
