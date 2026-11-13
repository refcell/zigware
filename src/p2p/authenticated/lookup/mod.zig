//! Authenticated networking with peer addresses known in advance (commonware
//! `p2p/src/authenticated/lookup`).

pub const types = @import("types.zig");
pub const Message = types.Message;

test {
    @import("std").testing.refAllDecls(@This());
}
