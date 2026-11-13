//! Utilities for exchanging messages with many peers (commonware `p2p/src/utils/mod.rs`).

pub const limited = @import("limited.zig");
pub const watch = @import("watch.zig");
pub const LimitedSender = limited.LimitedSender;
pub const CheckedSender = limited.CheckedSender;
pub const Watch = watch.Watch;

test {
    @import("std").testing.refAllDecls(@This());
}
