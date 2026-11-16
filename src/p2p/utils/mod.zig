//! Utilities for exchanging messages with many peers (commonware `p2p/src/utils/mod.rs`).

pub const limited = @import("limited.zig");
pub const watch = @import("watch.zig");
pub const io_rng = @import("io_rng.zig");
pub const IoRng = io_rng.IoRng;
pub const shuffle = @import("shuffle.zig");
pub const LimitedSender = limited.LimitedSender;
pub const CheckedSender = limited.CheckedSender;
pub const Watch = watch.Watch;

test {
    @import("std").testing.refAllDecls(@This());
}
