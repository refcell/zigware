//! What marshal's standard and erasure-coded variants share (commonware `marshal/core`).

const std = @import("std");

pub const acks = @import("acks.zig");
pub const actor = @import("actor.zig");
pub const Actor = actor.Actor;
pub const cache = @import("cache.zig");
pub const certified = @import("certified.zig");
pub const delivery = @import("delivery.zig");
pub const durability = @import("durability.zig");
pub const floor = @import("floor.zig");
pub const Cutoff = floor.Cutoff;
pub const Floor = floor.Floor;
pub const Processed = floor.Processed;
pub const mailbox = @import("mailbox.zig");
pub const Mailbox = mailbox.Mailbox;
pub const Message = mailbox.Message;
pub const Identifier = mailbox.Identifier;
pub const DigestFallback = mailbox.DigestFallback;
pub const CommitmentFallback = mailbox.CommitmentFallback;
pub const staged = @import("staged.zig");
pub const stream = @import("stream.zig");
pub const subscriptions = @import("subscriptions.zig");
pub const variant = @import("variant.zig");
pub const ExpectedCommitment = variant.ExpectedCommitment;
pub const assert_variant = variant.assert_variant;
pub const assert_buffer = variant.assert_buffer;
pub const NoBuffer = variant.NoBuffer;

test {
    std.testing.refAllDecls(@This());
}
