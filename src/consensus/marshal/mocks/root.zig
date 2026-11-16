//! Test doubles for marshal (commonware `marshal/mocks`).

const std = @import("std");

pub const block = @import("block.zig");
pub const EmptyBlock = block.EmptyBlock;
pub const Block = block.Block;
pub const ready = block.ready;
pub const verifying = @import("verifying.zig");
pub const store = @import("store.zig");
pub const resolver = @import("resolver.zig");

test {
    std.testing.refAllDecls(@This());
}
