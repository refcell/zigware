//! A p2p-optimized collector (commonware `collector/src/p2p`).
//!
//! # Message sizes
//!
//! Requests travel on the requests channel and responses on the responses channel, each as
//! the encoding of one request from the `Mailbox` or one response from the `Handler`. The
//! engine adds no framing, so each must fit the network's configured maximum message size.

pub const engine = @import("engine.zig");
pub const Engine = engine.Engine;
pub const Config = engine.Config;
pub const ingress = @import("ingress.zig");
pub const Mailbox = ingress.Mailbox;
pub const Message = ingress.Message;
pub const mocks = @import("mocks.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("policy_test.zig");
    _ = @import("engine_test.zig");
}
