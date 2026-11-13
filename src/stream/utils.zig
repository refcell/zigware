//! Utilities for stream implementations (commonware `stream/src/utils`).

const std = @import("std");

pub const codec = @import("utils/codec.zig");

test {
    std.testing.refAllDecls(@This());
}
