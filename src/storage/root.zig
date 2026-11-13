//! storage: Persist and retrieve data from an abstract store.
//!
//! Zig port of commonware's `commonware-storage` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/storage). Lanes: storage-merkle owns
//! merkle, bmt, bitmap, index, rmap, and translator (docs/lanes/storage-merkle.md); other
//! storage lanes add their modules here.

const std = @import("std");

pub const translator = @import("translator.zig");
pub const rmap = @import("rmap/mod.zig");
pub const RMap = rmap.RMap;

test {
    std.testing.refAllDecls(@This());
}
