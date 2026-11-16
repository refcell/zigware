//! Marshal's application wrappers' shared plumbing (commonware `marshal/application`).

const std = @import("std");

pub const gates = @import("gates.zig");
pub const relay = @import("relay.zig");
pub const validation = @import("validation.zig");

test {
    std.testing.refAllDecls(@This());
}
