//! cryptography: Generate keys, sign arbitrary messages, and deterministically verify signatures.
//!
//! Zig port of commonware's `commonware-cryptography` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/cryptography). Not yet ported; see
//! docs/lanes/ for the lane that owns this package.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
