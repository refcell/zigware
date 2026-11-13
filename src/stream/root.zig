//! stream: Exchange messages over arbitrary transport.
//!
//! Zig port of commonware's `commonware-stream` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/stream). Landed: `utils.codec`
//! (length-prefixed framing) and `mocks` (an in-memory sink/stream pair that also documents
//! the transport contract). The sake handshake and cups protocol follow.

const std = @import("std");

pub const utils = @import("utils.zig");
pub const mocks = @import("mocks.zig");

test {
    std.testing.refAllDecls(@This());
}
