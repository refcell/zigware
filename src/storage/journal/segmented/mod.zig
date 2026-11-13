//! Segmented journals: one blob per section (commonware's `journal/segmented`).

const std = @import("std");

pub const manager = @import("manager.zig");
pub const fixed = @import("fixed.zig");
pub const variable = @import("variable.zig");
pub const glob = @import("glob.zig");
pub const oversized = @import("oversized.zig");

test {
    std.testing.refAllDecls(@This());
}
