//! The BLS12-381 multisig simplex scheme (commonware `simplex::scheme::bls12381_multisig`):
//! `impl_certificate_bls12381_multisig!(Subject<'a, D>, Namespace, N3f1)`, which here is the
//! crypto lane's `bls12381.certificate.multisig.Scheme` over simplex subjects.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../types.zig");

const multisig = cryptography.bls12381.certificate.multisig;

/// The multisig scheme for proposals with payload digest `D`, identities `P`, and BLS
/// variant `V` (`MinPk` or `MinSig`).
pub fn Scheme(comptime D: type, comptime P: type, comptime V: type) type {
    return multisig.Scheme(types.Subject(D), utils.N3f1, P, V);
}

/// ed25519 identities with BLS keys, and a signing scheme for each (commonware
/// `simplex::scheme::bls12381_multisig::fixture`).
pub fn fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!cryptography.certificate.mocks.Fixture(S) {
    return multisig.fixture(S, gpa, rng, namespace, n);
}

test {
    _ = @import("bls12381_multisig_test.zig");
}
