//! A mock certificate scheme over aggregation items (commonware `aggregation/mocks/scheme.rs`):
//! a shared ledger records what each participant signed, so signing and verifying cost no
//! cryptography. The 1k-height test runs on it.

const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../types.zig");

const certificate_mocks = cryptography.certificate.mocks;

/// The mock scheme over items with digest `D`, for ed25519 identities.
pub fn Scheme(comptime D: type) type {
    return certificate_mocks.Scheme(types.Item(D), utils.N3f1, cryptography.ed25519.PublicKey, .{});
}

/// ed25519 identities and one mock signer per identity sharing one ledger.
pub const fixture = certificate_mocks.fixture;
