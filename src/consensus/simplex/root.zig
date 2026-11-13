//! Simplex-like BFT agreement with an embedded VRF and succinct certificates (commonware
//! `consensus::simplex`). docs/lanes/consensus-simplex.md tracks what is ported.

const std = @import("std");

pub const types = @import("types.zig");
pub const attestation = @import("attestation.zig");
pub const Attestation = attestation.Attestation;
pub const Deferred = attestation.Deferred;
pub const elector = @import("elector.zig");
pub const limits = @import("limits.zig");

pub const scheme = struct {
    pub const bls12381_threshold = struct {
        pub const vrf = @import("scheme/bls12381_threshold/vrf.zig");
    };
};

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = attestation;
    _ = elector;
    _ = limits;
    _ = scheme.bls12381_threshold.vrf;
}
