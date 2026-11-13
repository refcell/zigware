//! consensus: Order opaque messages in a Byzantine environment.
//!
//! Zig port of commonware's `commonware-consensus` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/consensus). docs/lanes/
//! consensus-simplex.md tracks what is ported.

const std = @import("std");

pub const types = @import("types.zig");
pub const Epoch = types.Epoch;
pub const Height = types.Height;
pub const View = types.View;
pub const Round = types.Round;

test {
    std.testing.refAllDecls(@This());
}
