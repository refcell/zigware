//! The reshare actor (commonware `glue::dkg::reshare::actor`): a per-epoch driver for the
//! reshare ceremony. Ported so far: setup's helpers.

pub const setup = @import("setup.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
