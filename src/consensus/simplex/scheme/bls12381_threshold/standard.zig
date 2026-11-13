//! The BLS12-381 threshold simplex scheme without a VRF (commonware
//! `simplex::scheme::bls12381_threshold::standard`):
//! `impl_certificate_bls12381_threshold!(Subject<'a, D>, Namespace, N3f1)`, which here is the
//! crypto lane's `bls12381.certificate.threshold.Scheme` over simplex subjects.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../../types.zig");

const threshold = cryptography.bls12381.certificate.threshold;

/// The threshold scheme for proposals with payload digest `D`, identities `P`, and BLS
/// variant `V` (`MinPk` or `MinSig`).
pub fn Scheme(comptime D: type, comptime P: type, comptime V: type) type {
    return threshold.Scheme(types.Subject(D), utils.N3f1, P, V);
}

/// ed25519 identities and a dealt sharing, with a signing scheme per share (commonware
/// `simplex::scheme::bls12381_threshold::standard::fixture`).
pub fn fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!cryptography.certificate.mocks.Fixture(S) {
    return threshold.fixture(S, gpa, rng, namespace, n);
}

test {
    _ = @import("standard_test.zig");
}
