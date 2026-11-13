//! Resolve data identified by a fixed-length key by using the P2P network
//! (commonware `resolver/src/p2p`).

const std = @import("std");

pub const wire = @import("wire.zig");
pub const Message = wire.Message;
pub const Payload = wire.Payload;
pub const score = @import("score.zig");
pub const fetcher = @import("fetcher.zig");
pub const Fetcher = fetcher.Fetcher;
pub const inflight = @import("inflight.zig");
pub const config = @import("config.zig");
pub const Config = config.Config;
pub const metrics = @import("metrics.zig");
pub const ingress = @import("ingress.zig");
pub const Mailbox = ingress.Mailbox;
pub const Produced = @import("produced.zig").Produced;
pub const engine = @import("engine.zig");
pub const Engine = engine.Engine;

/// Serves data requested by the network: `P.Key` and
/// `produce(self, key) !utils.channel.oneshot.Receiver(Produced)`; a receiver closed without a
/// value answers the requester with an error response.
pub fn assert_producer(comptime P: type) void {
    comptime {
        std.debug.assert(@hasDecl(P, "Key"));
        std.debug.assert(@hasDecl(P, "produce"));
    }
}

/// Mock implementations for testing.
pub const mocks = struct {
    pub const Key = @import("mocks/key.zig").Key;
    pub const Consumer = @import("mocks/consumer.zig").Consumer;
    pub const Producer = @import("mocks/producer.zig").Producer;
};

test {
    std.testing.refAllDecls(@This());
    _ = wire;
    _ = score;
    _ = fetcher;
    _ = inflight;
    _ = ingress;
}
