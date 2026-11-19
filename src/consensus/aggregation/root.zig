//! Recover quorum certificates over an externally synchronized sequence of items (commonware
//! `consensus::aggregation`). docs/lanes/consensus-marshal.md tracks what is ported.
//!
//! A dynamic set of participants signs each item (a height and a digest) the application
//! supplies, gossips `TipAck`s (an ack and the sender's tip), and assembles a certificate
//! once a quorum of acks for the same item arrives. Certificates are never gossiped: each
//! participant recovers them locally, and its tip fast-forwards to the highest tip at least
//! one honest participant reported.
//!
//! Acks sign only the item, never the epoch: the epoch selects the verifying scheme, and the
//! engine only accepts an ack from the signer it names, so relabeling one gains nothing.

const std = @import("std");

pub const types = @import("types.zig");
pub const scheme = @import("scheme.zig");
pub const limits = @import("limits.zig");
pub const max_payload_size = limits.max_payload_size;
pub const safe_tip = @import("safe_tip.zig");
pub const SafeTip = safe_tip.SafeTip;
pub const config = @import("config.zig");
pub const Config = config.Config;
pub const metrics = @import("metrics.zig");
pub const engine = @import("engine.zig");
pub const Engine = engine.Engine;
pub const mocks = @import("mocks/root.zig");

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = scheme;
    _ = limits;
    _ = safe_tip;
    _ = metrics;
    _ = mocks;
    _ = @import("height_map.zig");
    _ = @import("mod_test.zig");
    _ = @import("fuzz.zig");
}
