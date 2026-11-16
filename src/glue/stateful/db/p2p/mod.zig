//! The p2p resolver for QMDB state sync (commonware `glue/src/stateful/db/p2p`). So far: the
//! payload bound, `max_payload_size`.

const std = @import("std");

pub const limits = @import("limits.zig");
pub const max_payload_size = limits.max_payload_size;

test {
    std.testing.refAllDecls(@This());
}
