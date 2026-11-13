//! Authenticated networking that discovers peer addresses through gossip (commonware
//! `p2p/src/authenticated/discovery`).

pub const types = @import("types.zig");
pub const BitVec = types.BitVec;
pub const Info = types.Info;
pub const InfoVerifier = types.InfoVerifier;
pub const Payload = types.Payload;
pub const PayloadConfig = types.PayloadConfig;
pub const max_gossip_size = types.max_gossip_size;

test {
    @import("std").testing.refAllDecls(@This());
}
