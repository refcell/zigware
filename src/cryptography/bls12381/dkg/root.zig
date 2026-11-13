//! Distributed key generation for BLS12-381 threshold keys (commonware `bls12381::dkg`).

const std = @import("std");

pub const feldman_desmedt = @import("feldman_desmedt.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("conformance_test.zig");
}
