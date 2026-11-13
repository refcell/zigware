//! Resolve data identified by a fixed-length key by using the P2P network
//! (commonware `resolver/src/p2p`).

const std = @import("std");

pub const wire = @import("wire.zig");
pub const Message = wire.Message;
pub const Payload = wire.Payload;

/// Mock implementations for testing.
pub const mocks = struct {
    pub const Key = @import("mocks/key.zig").Key;
    pub const Consumer = @import("mocks/consumer.zig").Consumer;
};

test {
    std.testing.refAllDecls(@This());
    _ = wire;
}
