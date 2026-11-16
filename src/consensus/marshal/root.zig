//! Ordered delivery of finalized blocks (commonware `consensus/src/marshal`).
//!
//! The marshal actor turns simplex's notarizations and finalizations, blocks from a
//! broadcast buffer, and blocks backfilled over a resolver into an in-order stream of
//! finalized blocks for the application. `core` holds what the standard and erasure-coded
//! variants share; `coding` is the erasure-coded variant. docs/lanes/consensus-marshal.md
//! tracks what is ported.

const std = @import("std");

pub const config = @import("config.zig");
pub const Config = config.Config;
pub const Start = config.Start;
pub const core = @import("core/root.zig");
pub const limits = @import("limits.zig");
pub const max_payload_size = limits.max_payload_size;
pub const mocks = @import("mocks/root.zig");
pub const resolver = @import("resolver/root.zig");
pub const standard = @import("standard/root.zig");
pub const store = @import("store.zig");

test {
    std.testing.refAllDecls(@This());
}
