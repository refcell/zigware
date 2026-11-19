//! Epoch-scoped Simplex engines driven by finalized epoch artifacts (commonware
//! `glue::dkg::orchestrator`). Ported so far: limits, mailbox, actor.

pub const limits = @import("limits.zig");
pub const max_payload_size = limits.max_payload_size;
pub const mailbox = @import("mailbox.zig");
pub const Mailbox = mailbox.Mailbox;
pub const Message = mailbox.Message;
pub const actor = @import("actor.zig");
pub const Actor = actor.Actor;
pub const Config = actor.Config;
pub const SimplexConfig = actor.SimplexConfig;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("mailbox_test.zig");
    _ = @import("actor_test.zig");
    _ = @import("cluster_test.zig");
}
