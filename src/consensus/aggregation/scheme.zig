//! Signing schemes for aggregation (commonware `aggregation/scheme.rs`).
//!
//! Each wraps one of cryptography's certificate schemes with `Item(D)` as the subject and
//! the `N3f1` fault model (commonware's `impl_certificate_*!(&'a Item<D>, Namespace, N3f1)`):
//!
//! - `ed25519`, `secp256r1`: attributable individual signatures; HSM-friendly, no setup.
//! - `bls12381_multisig`: attributable signatures aggregated into compact certificates.
//! - `bls12381_threshold`: non-attributable threshold signatures; constant-size certificates
//!   from a trusted setup (DKG).
//!
//! `assert_scheme(S, D)` is commonware's `Scheme<D>` marker trait.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("types.zig");

const certificate = cryptography.certificate;
const Fixture = certificate.mocks.Fixture;

/// Asserts that `S` is a certificate scheme over `Item(D)` with the `N3f1` fault model.
pub fn assert_scheme(comptime S: type, comptime D: type) void {
    comptime {
        certificate.assert_scheme(S);
        if (S.Subject != types.Item(D)) @compileError("aggregation schemes sign Item(D)");
        if (S.Faults != utils.N3f1) @compileError("aggregation schemes use N3f1");
    }
}

pub const ed25519 = struct {
    /// The ed25519 scheme over items with digest `D`.
    pub fn Scheme(comptime D: type) type {
        return cryptography.ed25519.certificate.Scheme(types.Item(D), utils.N3f1);
    }

    /// ed25519 identities and a signing scheme for each, in participant order.
    pub fn fixture(
        comptime S: type,
        gpa: Allocator,
        rng: anytype,
        namespace: []const u8,
        n: u32,
    ) Allocator.Error!Fixture(S) {
        return cryptography.ed25519.certificate.fixture(S, gpa, rng, namespace, n);
    }
};

pub const secp256r1 = struct {
    /// The secp256r1 scheme over items with digest `D` and identities `P`.
    pub fn Scheme(comptime D: type, comptime P: type) type {
        return cryptography.secp256r1.certificate.Scheme(types.Item(D), utils.N3f1, P);
    }

    /// ed25519 identities paired with secp256r1 keys, and a signing scheme for each.
    pub fn fixture(
        comptime S: type,
        gpa: Allocator,
        rng: anytype,
        namespace: []const u8,
        n: u32,
    ) Allocator.Error!Fixture(S) {
        return cryptography.secp256r1.certificate.fixture(S, gpa, rng, namespace, n);
    }
};

pub const bls12381_multisig = struct {
    const multisig = cryptography.bls12381.certificate.multisig;

    /// The multisig scheme over items with digest `D`, identities `P`, and variant `V`.
    pub fn Scheme(comptime D: type, comptime P: type, comptime V: type) type {
        return multisig.Scheme(types.Item(D), utils.N3f1, P, V);
    }

    /// ed25519 identities with BLS keys, and a signing scheme for each.
    pub fn fixture(
        comptime S: type,
        gpa: Allocator,
        rng: anytype,
        namespace: []const u8,
        n: u32,
    ) Allocator.Error!Fixture(S) {
        return multisig.fixture(S, gpa, rng, namespace, n);
    }
};

pub const bls12381_threshold = struct {
    const threshold = cryptography.bls12381.certificate.threshold;

    /// The threshold scheme over items with digest `D`, identities `P`, and variant `V`.
    pub fn Scheme(comptime D: type, comptime P: type, comptime V: type) type {
        return threshold.Scheme(types.Item(D), utils.N3f1, P, V);
    }

    /// ed25519 identities with dealt threshold shares, and a signing scheme for each.
    pub fn fixture(
        comptime S: type,
        gpa: Allocator,
        rng: anytype,
        namespace: []const u8,
        n: u32,
    ) Allocator.Error!Fixture(S) {
        return threshold.fixture(S, gpa, rng, namespace, n);
    }
};

comptime {
    const D = cryptography.Sha256.Digest;
    const P = cryptography.ed25519.PublicKey;
    const MinSig = cryptography.bls12381.primitives.MinSig;
    assert_scheme(ed25519.Scheme(D), D);
    assert_scheme(secp256r1.Scheme(D, P), D);
    assert_scheme(bls12381_multisig.Scheme(D, P, MinSig), D);
    assert_scheme(bls12381_threshold.Scheme(D, P, MinSig), D);
}
