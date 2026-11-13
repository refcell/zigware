//! The secp256r1 simplex scheme (commonware `simplex::scheme::secp256r1`):
//! `impl_certificate_secp256r1!(Subject<'a, D>, Namespace, N3f1)`, which here is the crypto
//! lane's `secp256r1.certificate.Scheme` over simplex subjects.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../types.zig");

const certificate = cryptography.secp256r1.certificate;

/// The secp256r1 scheme for proposals with payload digest `D` and identities `P`.
pub fn Scheme(comptime D: type, comptime P: type) type {
    return certificate.Scheme(types.Subject(D), utils.N3f1, P);
}

/// ed25519 identities paired with secp256r1 keys, and a signing scheme for each.
pub fn fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!cryptography.certificate.mocks.Fixture(S) {
    return certificate.fixture(S, gpa, rng, namespace, n);
}

test {
    _ = @import("secp256r1_test.zig");
}
