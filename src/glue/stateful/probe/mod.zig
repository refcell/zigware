//! Peer-sampled discovery of a recent finalization from which to begin state sync (commonware
//! `glue/src/stateful/probe`).
//!
//! A node starting fresh, or far behind, needs a recent and trustworthy finalization (the
//! floor). It cannot trust one peer to name it, so the probe solicits the minimum epoch's
//! committee and adopts the highest verified finalization among `f + 1` distinct replies: under
//! `3f + 1`, such a sample includes an honest reply, so the floor is no older than it.
//!
//! This module has the probe's pure parts: `Sample` (the `f + 1` bookkeeping shared with the
//! DKG probe), the wire `Message`, and `max_payload_size`. The actor (solicit, collect, retry,
//! and serving marshal's latest finalization) follows once marshal's mailbox lands.

const std = @import("std");

pub const sample = @import("sample.zig");
pub const Sample = sample.Sample;
pub const wire = @import("wire.zig");
pub const Tag = wire.Tag;
pub const Message = wire.Message;
pub const max_payload_size = wire.max_payload_size;

test {
    std.testing.refAllDecls(@This());
    _ = @import("probe_test.zig");
}
