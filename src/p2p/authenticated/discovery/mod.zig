//! Authenticated networking that discovers peer addresses through gossip (commonware
//! `p2p/src/authenticated/discovery`).

pub const types = @import("types.zig");
pub const BitVec = types.BitVec;
pub const Info = types.Info;
pub const InfoVerifier = types.InfoVerifier;
pub const Payload = types.Payload;
pub const PayloadConfig = types.PayloadConfig;
pub const max_gossip_size = types.max_gossip_size;
pub const record = @import("record.zig");
pub const bit_set = @import("bit_set.zig");
pub const directory = @import("directory.zig");
pub const tracker = @import("tracker.zig");
pub const peer = @import("peer.zig");
pub const config = @import("config.zig");
pub const Config = config.Config;
pub const Bootstrapper = config.Bootstrapper;
pub const network = @import("network.zig");
pub const Network = network.Network;

test {
    @import("std").testing.refAllDecls(@This());
}
