//! Epoch-scoped Simplex engines driven by finalized epoch artifacts (commonware
//! `glue::dkg::orchestrator`). Ported so far: limits, mailbox.

pub const limits = @import("limits.zig");
pub const max_payload_size = limits.max_payload_size;
pub const mailbox = @import("mailbox.zig");
pub const Mailbox = mailbox.Mailbox;
pub const Message = mailbox.Message;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("mailbox_test.zig");
}
