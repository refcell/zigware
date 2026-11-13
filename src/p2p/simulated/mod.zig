//! Simulate networking between peers with configurable link behavior: latency, jitter, drops,
//! bandwidth limits, partitions, and blocking (commonware `p2p/src/simulated`).
//!
//! Runs deterministically on `runtime.deterministic`: the same seed reproduces the same order
//! of delivered and dropped messages.

pub const rational = @import("rational.zig");
pub const bandwidth = @import("bandwidth.zig");
pub const sorted_map = @import("sorted_map.zig");
pub const transmitter = @import("transmitter.zig");
pub const channel = @import("channel.zig");
pub const tracker = @import("tracker.zig");
pub const normal = @import("normal.zig");
pub const Normal = normal.Normal;
pub const network = @import("network.zig");
pub const Network = network.Network;
pub const Config = network.Config;
pub const Link = network.Link;
pub const Error = network.Error;
pub const Rational = rational.Rational;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("network_test.zig");
    _ = @import("network_peers_test.zig");
    _ = @import("network_bandwidth_test.zig");
}
