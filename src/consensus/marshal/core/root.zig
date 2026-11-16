//! What marshal's standard and erasure-coded variants share (commonware `marshal/core`).

const std = @import("std");

pub const variant = @import("variant.zig");
pub const ExpectedCommitment = variant.ExpectedCommitment;
pub const assert_variant = variant.assert_variant;
pub const assert_buffer = variant.assert_buffer;

test {
    std.testing.refAllDecls(@This());
}
