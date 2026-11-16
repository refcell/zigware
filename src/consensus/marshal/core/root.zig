//! What marshal's standard and erasure-coded variants share (commonware `marshal/core`).

const std = @import("std");

pub const acks = @import("acks.zig");
pub const certified = @import("certified.zig");
pub const durability = @import("durability.zig");
pub const floor = @import("floor.zig");
pub const Cutoff = floor.Cutoff;
pub const Floor = floor.Floor;
pub const Processed = floor.Processed;
pub const staged = @import("staged.zig");
pub const stream = @import("stream.zig");
pub const subscriptions = @import("subscriptions.zig");
pub const variant = @import("variant.zig");
pub const ExpectedCommitment = variant.ExpectedCommitment;
pub const assert_variant = variant.assert_variant;
pub const assert_buffer = variant.assert_buffer;

test {
    std.testing.refAllDecls(@This());
}
