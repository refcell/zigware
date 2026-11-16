//! BLS12-381: signatures, threshold signatures, DKG, and timelock encryption (commonware
//! `cryptography::bls12381`). Lane: bls-math (docs/lanes/bls-math.md).

const std = @import("std");

pub const primitives = @import("primitives/root.zig");
pub const certificate = @import("certificate/root.zig");
pub const dkg = @import("dkg/root.zig");
pub const tle = @import("tle.zig");
pub const scheme = @import("scheme.zig");
pub const PrivateKey = scheme.PrivateKey;
pub const PublicKey = scheme.PublicKey;
pub const Signature = scheme.Signature;

test {
    std.testing.refAllDecls(@This());
    _ = @import("conformance_test.zig");
    _ = @import("scheme_tests.zig");
    _ = @import("fuzz_tests.zig");
}
