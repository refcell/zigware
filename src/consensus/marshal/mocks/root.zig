//! Test doubles for marshal (commonware `marshal/mocks`).

const std = @import("std");

pub const block = @import("block.zig");
pub const EmptyBlock = block.EmptyBlock;
pub const Block = block.Block;
pub const ready = block.ready;
pub const verifying = @import("verifying.zig");
pub const store = @import("store.zig");
pub const resolver = @import("resolver.zig");
pub const application = @import("application.zig");
pub const Application = application.Application;
pub const harness = @import("harness.zig");
pub const scenarios = @import("scenarios.zig");
pub const scenarios_queries = @import("scenarios_queries.zig");
pub const scenarios_recoverable = @import("scenarios_recoverable.zig");

test {
    std.testing.refAllDecls(@This());
}
