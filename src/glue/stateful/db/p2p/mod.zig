//! The p2p resolver for QMDB state sync (commonware `glue/src/stateful/db/p2p`). So far: the
//! payload bound, `max_payload_size`, the resolver engine's `Handler`, and the `Mailbox`
//! sync source.

const std = @import("std");

pub const limits = @import("limits.zig");
pub const max_payload_size = limits.max_payload_size;
pub const handler = @import("handler.zig");
pub const Handler = handler.Handler;
pub const EngineMessage = handler.EngineMessage;
pub const Subscriber = handler.Subscriber;
pub const mailbox = @import("mailbox.zig");
pub const Mailbox = mailbox.Mailbox;
pub const Message = mailbox.Message;

test {
    std.testing.refAllDecls(@This());
    _ = @import("mailbox_test.zig");
}
