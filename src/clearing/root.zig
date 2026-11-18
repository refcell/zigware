//! clearing: Settle actions at scale.
//!
//! Zig port of commonware's `commonware-clearing` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/clearing). Lane: clearing (see
//! docs/lanes/clearing.md).
//!
//! - `bajillion`: an operator settles payments between accounts in epochs, validators check and
//!   certify each close, and a ledger posts the certified summaries and pays out withdrawals.

const std = @import("std");

pub const bajillion = @import("bajillion/mod.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("fuzz/decode.zig");
    _ = @import("fuzz/verify.zig");
    _ = @import("tests/bajillion/main.zig");
}
