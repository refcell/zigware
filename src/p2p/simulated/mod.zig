//! Simulate networking between peers with configurable link behavior: latency, jitter, drops,
//! bandwidth limits, partitions, and blocking (commonware `p2p/src/simulated`).
//!
//! Runs deterministically on `runtime.deterministic`: the same seed reproduces the same order
//! of delivered and dropped messages.

pub const rational = @import("rational.zig");
pub const bandwidth = @import("bandwidth.zig");
pub const sorted_map = @import("sorted_map.zig");
pub const transmitter = @import("transmitter.zig");
pub const Rational = rational.Rational;

test {
    @import("std").testing.refAllDecls(@This());
}
