//! Simplex-like BFT agreement with an embedded VRF and succinct certificates (commonware
//! `consensus::simplex`). docs/lanes/consensus-simplex.md tracks what is ported.

const std = @import("std");

pub const types = @import("types.zig");
pub const Attestation = @import("cryptography").certificate.Attestation;
pub const Deferred = @import("cryptography").certificate.Deferred;
pub const elector = @import("elector.zig");
pub const limits = @import("limits.zig");
pub const config = @import("config.zig");
pub const metrics = @import("metrics.zig");

pub const scheme = struct {
    pub const namespace = @import("scheme/namespace.zig");
    pub const Namespace = namespace.Namespace;
    pub const ed25519 = @import("scheme/ed25519.zig");
    pub const bls12381_multisig = @import("scheme/bls12381_multisig.zig");
    pub const secp256r1 = @import("scheme/secp256r1.zig");
    pub const bls12381_threshold = struct {
        pub const vrf = @import("scheme/bls12381_threshold/vrf.zig");
    };
};

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = elector;
    _ = limits;
    _ = config;
    _ = metrics;
    _ = scheme.bls12381_threshold.vrf;
    _ = scheme.namespace;
    _ = scheme.ed25519;
    _ = scheme.bls12381_multisig;
    _ = scheme.secp256r1;
}
