//! Discovery of the public epoch material a joining node needs before consensus starts
//! (commonware `glue/src/dkg/probe`).
//!
//! The probe extends `glue.stateful.probe`'s solicit-and-sample floor discovery with
//! requests for the floor epoch's boundary finalization and block, which carry that epoch's
//! public `EpochInfo`. This module has the wire messages and the payload bound; the actor
//! follows.

pub const wire = @import("wire.zig");
pub const Message = wire.Message;
pub const Tag = wire.Tag;
pub const max_payload_size = wire.max_payload_size;

test {
    _ = wire;
    _ = @import("wire_test.zig");
}
