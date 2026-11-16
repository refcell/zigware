//! The p2p resolver for QMDB state sync (commonware `glue/src/stateful/db/p2p`). So far: the
//! payload bound, `max_payload_size`, and the resolver engine's `Handler`.

const std = @import("std");

pub const limits = @import("limits.zig");
pub const max_payload_size = limits.max_payload_size;
pub const handler = @import("handler.zig");
pub const Handler = handler.Handler;
pub const EngineMessage = handler.EngineMessage;
pub const Subscriber = handler.Subscriber;

test {
    std.testing.refAllDecls(@This());
}
