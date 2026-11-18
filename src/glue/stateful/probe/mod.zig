//! Peer-sampled discovery of a recent finalization from which to begin state sync (commonware
//! `glue/src/stateful/probe`).
//!
//! A node starting fresh, or far behind, needs a recent and trustworthy finalization (the
//! floor). It cannot trust one peer to name it, so the probe solicits the minimum epoch's
//! committee and adopts the highest verified finalization among `f + 1` distinct replies: under
//! `3f + 1`, such a sample includes an honest reply, so the floor is no older than it.
//!
//! This module has `Sample` (the `f + 1` bookkeeping shared with the DKG probe), the wire
//! `Message`, `max_payload_size`, and `Discovery`, the actor's I/O-free state (subscriptions,
//! request rounds, judging replies, and floor delivery). The actor's driver (network, mailbox,
//! retry deadline, and serving marshal's latest finalization) runs on top of it.

const std = @import("std");

pub const sample = @import("sample.zig");
pub const Sample = sample.Sample;
pub const wire = @import("wire.zig");
pub const Tag = wire.Tag;
pub const Message = wire.Message;
pub const max_payload_size = wire.max_payload_size;
pub const discovery = @import("discovery.zig");
pub const Discovery = discovery.Discovery;
pub const Floor = discovery.Floor;
pub const Verdict = discovery.Verdict;
pub const actor = @import("actor.zig");
pub const Probe = actor.Probe;
pub const Mailbox = actor.Mailbox;
pub const Config = actor.Config;
pub const MarshalSource = actor.MarshalSource;

test {
    std.testing.refAllDecls(@This());
    _ = @import("probe_test.zig");
    _ = @import("discovery_test.zig");
    _ = @import("actor_test.zig");
}
