//! Metric labels of the simulated network (commonware `p2p/src/simulated/metrics.rs`).

const p2p = @import("../root.zig");

/// A message from `origin` to `recipient` on `channel`.
pub fn Message(comptime P: type) type {
    return struct {
        origin: P,
        recipient: P,
        channel: p2p.Channel,

        pub fn new(origin: P, recipient: P, channel: p2p.Channel) @This() {
            return .{ .origin = origin, .recipient = recipient, .channel = channel };
        }
    };
}
