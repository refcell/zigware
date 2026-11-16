//! The mock certificate scheme for simplex tests (commonware `simplex::mocks::scheme`,
//! `impl_certificate_mock!(Subject<'a, D>, Namespace, N3f1)`): synthetic signatures and
//! certificates in a shared ledger, so DSTs spend no time on real cryptography.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../types.zig");

const mocks = cryptography.certificate.mocks;

/// The mock scheme over simplex subjects with payload digest `D` and ed25519 identities.
pub fn Scheme(comptime D: type) type {
    return mocks.Scheme(types.Subject(D), utils.N3f1, cryptography.ed25519.PublicKey, .{});
}

/// ed25519 identities and one mock signer each over a shared ledger (commonware
/// `mocks::scheme::fixture`).
pub fn fixture(
    comptime D: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!mocks.Fixture(Scheme(D)) {
    std.debug.assert(n > 0);
    return mocks.fixture(Scheme(D), gpa, rng, namespace, n);
}
