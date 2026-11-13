//! BLS12-381 arithmetic: Montgomery prime fields, the Fp2/Fp6/Fp12 tower, G1 and G2 in
//! Jacobian coordinates with compressed (ZCash) encodings, the optimal ate pairing, RFC 9380
//! hash-to-curve, and Pippenger MSM. Adapted from needlefish (same author, MIT), which has no
//! dependencies either. `primitives/group.zig` wraps it in commonware's types.

const std = @import("std");

pub const montgomery = @import("montgomery.zig");
pub const fields = @import("fields.zig");
pub const Fp = fields.Fp;
pub const Fr = fields.Fr;
pub const Fp2 = fields.Fp2;
pub const Fp6 = fields.Fp6;
pub const Fp12 = fields.Fp12;
pub const curve = @import("curve.zig");
pub const g1 = @import("g1.zig");
pub const g2 = @import("g2.zig");
pub const pairing = @import("pairing.zig");
pub const map = @import("map.zig");
pub const msm = @import("msm.zig");

test {
    std.testing.refAllDecls(@This());
}
