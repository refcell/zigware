//! runtime: Execute asynchronous tasks with a configurable scheduler.
//!
//! Zig port of commonware's `commonware-runtime` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/runtime). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
