//! curve25519: Perform Curve25519 field/group arithmetic, Ed25519 signing and verification, and
//! X25519 key exchange.
//!
//! Zig port of commonware's `commonware-cryptography-curve25519` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/cryptography/curve25519). Lane:
//! curve25519 (see docs/lanes/curve25519.md).
//!
//! Ed25519 verification follows ZIP-215 exactly as the crate does (see `signing`), so every node
//! accepts the same signatures. The crate's test vectors (RFC 8032, RFC 7748, ZIP 215, and
//! Project Wycheproof) run against this package in `vectors_test.zig`.

pub const signing = @import("signing.zig");
pub const SigningKey = signing.SigningKey;
pub const VerifyingKey = signing.VerifyingKey;
pub const Signature = signing.Signature;

pub const key_exchange = @import("key_exchange.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("vectors_test.zig");
    _ = @import("conformance_test.zig");
    _ = @import("signing_test.zig");
}
