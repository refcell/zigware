//! BLS12-381 primitives (commonware `bls12381::primitives`).

const std = @import("std");

pub const arithmetic = @import("arithmetic/root.zig");
pub const group = @import("group.zig");

test {
    std.testing.refAllDecls(@This());
}
