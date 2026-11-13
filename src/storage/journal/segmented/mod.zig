//! Segmented journals: one blob per section (commonware's `journal/segmented`).

const std = @import("std");

pub const manager = @import("manager.zig");
pub const fixed = @import("fixed.zig");

test {
    std.testing.refAllDecls(@This());
}
