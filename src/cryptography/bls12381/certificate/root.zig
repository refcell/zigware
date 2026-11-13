//! BLS12-381 certificate schemes (commonware `bls12381::certificate`): `multisig`
//! aggregates attributable individual signatures, and `threshold` recovers one threshold
//! signature from partial signatures.

const std = @import("std");

pub const multisig = @import("multisig.zig");

test {
    std.testing.refAllDecls(@This());
}
