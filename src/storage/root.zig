//! storage: Persist and retrieve data from an abstract store.
//!
//! Zig port of commonware's `commonware-storage` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/storage). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
