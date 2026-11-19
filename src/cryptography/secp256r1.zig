//! secp256r1 (NIST P-256) implementation of the signer traits (commonware
//! `cryptography/src/secp256r1`).
//!
//! Public keys are compressed SEC 1 points (33 bytes), signatures are deterministic
//! (RFC 6979) and normalized to low `s` (BIP 62). `standard` signatures are `r || s`
//! (64 bytes); `recoverable` signatures prefix a recovery id (65 bytes) so the signer's key can
//! be recovered from the message.

pub const common = @import("secp256r1/common.zig");
pub const standard = @import("secp256r1/standard.zig");
pub const recoverable = @import("secp256r1/recoverable.zig");
pub const certificate = @import("secp256r1/certificate.zig");

pub const curve_name = common.curve_name;
pub const private_key_length = common.private_key_length;
pub const public_key_length = common.public_key_length;

test {
    _ = @import("secp256r1/tests.zig");
    _ = @import("secp256r1/fuzz_test.zig");
    _ = @import("secp256r1/certificate.zig");
    _ = @import("secp256r1/verify.zig");
    _ = @import("secp256r1/field.zig");
}
