//! Ed25519 implementation of the signer traits (commonware `cryptography/src/ed25519`).
//!
//! Validation follows ZIP-215 (https://zips.z.cash/zip-0215), as commonware does with its
//! vendored `ed25519-consensus`: see `ed25519/core.zig`.

const scheme = @import("ed25519/scheme.zig");

pub const core = @import("ed25519/core.zig");
pub const msm = @import("ed25519/msm.zig");
pub const PrivateKey = scheme.PrivateKey;
pub const PublicKey = scheme.PublicKey;
pub const Signature = scheme.Signature;
pub const certificate = @import("ed25519/certificate.zig");

test {
    _ = @import("ed25519/tests.zig");
    _ = @import("ed25519/msm_test.zig");
    _ = @import("ed25519/certificate.zig");
    _ = @import("ed25519/verify_msm.zig");
    _ = @import("ed25519/verify_ifma.zig");
    _ = @import("ed25519/base_mul.zig");
}
