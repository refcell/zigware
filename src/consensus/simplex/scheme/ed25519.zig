//! The ed25519 simplex scheme (commonware `simplex::scheme::ed25519`):
//! `impl_certificate_ed25519!(Subject<'a, D>, Namespace, N3f1)`, which here is the crypto
//! lane's `ed25519.certificate.Scheme` over simplex subjects with the `N3f1` fault model.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../types.zig");

const certificate = cryptography.ed25519.certificate;

/// The ed25519 scheme for proposals with payload digest `D`.
pub fn Scheme(comptime D: type) type {
    return certificate.Scheme(types.Subject(D), utils.N3f1);
}

/// Ed25519 identities and a signing scheme for each, in participant order (commonware
/// `simplex::scheme::ed25519::fixture`).
pub fn fixture(
    comptime D: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!cryptography.certificate.mocks.Fixture(Scheme(D)) {
    return certificate.fixture(Scheme(D), gpa, rng, namespace, n);
}

test {
    _ = @import("ed25519_test.zig");
}
