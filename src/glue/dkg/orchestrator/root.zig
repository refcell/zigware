//! Epoch-scoped Simplex engines driven by finalized epoch artifacts (commonware
//! `glue::dkg::orchestrator`). Ported so far: limits.

pub const limits = @import("limits.zig");
pub const max_payload_size = limits.max_payload_size;

test {
    @import("std").testing.refAllDecls(@This());
}
