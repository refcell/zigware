//! Communicate with a fixed set of authenticated peers (commonware
//! `p2p/src/authenticated`). `lookup` dials peers at known addresses; `discovery` finds
//! addresses from bootstrappers.

pub const data = @import("data.zig");
pub const Data = data.Data;
pub const max_payload_overhead = data.max_payload_overhead;
pub const max_size = data.max_size;
pub const dialing = @import("dialing.zig");
pub const lookup = @import("lookup/mod.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
