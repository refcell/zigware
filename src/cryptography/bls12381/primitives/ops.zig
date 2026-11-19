//! BLS12-381 signatures (commonware `bls12381::primitives::ops`): key generation, signing,
//! verification, and proofs of possession, generic over a variant (`MinPk` or `MinSig`).
//!
//! Signatures use the proof-of-possession scheme: messages hash with `V.message`, proofs of
//! possession with `V.proof_of_possession`. A namespaced message is framed as
//! `union_unique(namespace, message)`, so a signature never verifies under another namespace.
//!
//! - `aggregate`: aggregation of public keys and signatures.
//! - `batch`: batch verification of many signatures.
//! - `threshold`: threshold signatures over a `Sharing`.

const std = @import("std");
const assert = std.debug.assert;
const group = @import("group.zig");
const variant = @import("variant.zig");

pub const aggregate = @import("ops/aggregate.zig");
pub const batch = @import("ops/batch.zig");
pub const threshold = @import("ops/threshold.zig");

const Private = group.Private;
const Error = variant.Error;

/// The public key `generator * private`.
pub fn compute_public(comptime V: type, private: Private) V.Public {
    return V.Public.generator.mul(private.scalar.value);
}

pub fn Keypair(comptime V: type) type {
    return struct { private: Private, public: V.Public };
}

/// A new keypair from `rng`.
pub fn keypair(comptime V: type, rng: anytype) Keypair(V) {
    const private = Private.random(rng);
    return .{ .private = private, .public = compute_public(V, private) };
}

/// Hashes `message` to the signature group with `dst`.
pub fn hash(comptime V: type, dst: []const u8, message: []const u8) V.Signature {
    return V.Signature.hash_to_group(dst, message);
}

/// Hashes `union_unique(namespace, message)` to the signature group with `dst`.
pub fn hash_with_namespace(
    comptime V: type,
    dst: []const u8,
    namespace: []const u8,
    message: []const u8,
) V.Signature {
    var prefix: [5]u8 = undefined;
    const parts = group.union_unique_parts(&prefix, namespace, message);
    return V.Signature.hash_to_group_parts(dst, &parts);
}

/// Signs `message` hashed with `dst`.
pub fn sign(comptime V: type, private: Private, dst: []const u8, message: []const u8) V.Signature {
    return hash(V, dst, message).mul(private.scalar.value);
}

/// Verifies a signature over `message` hashed with `dst`.
pub fn verify(
    comptime V: type,
    public: V.Public,
    dst: []const u8,
    message: []const u8,
    signature: V.Signature,
) Error!void {
    return V.verify(public, hash(V, dst, message), signature);
}

/// Signs `message` in `namespace` (deterministic; safe for consensus).
pub fn sign_message(
    comptime V: type,
    private: Private,
    namespace: []const u8,
    message: []const u8,
) V.Signature {
    return hash_with_namespace(V, V.message, namespace, message).mul(private.scalar.value);
}

/// Verifies a signature over `message` in `namespace`. Assumes `public` and `signature`
/// passed their group checks (decoding performs them).
pub fn verify_message(
    comptime V: type,
    public: V.Public,
    namespace: []const u8,
    message: []const u8,
    signature: V.Signature,
) Error!void {
    return V.verify(public, hash_with_namespace(V, V.message, namespace, message), signature);
}

/// A proof of possession: a signature over the encoded public key in `namespace`.
pub fn sign_proof_of_possession(
    comptime V: type,
    private: Private,
    namespace: []const u8,
) V.Signature {
    const public = compute_public(V, private);
    const encoded = public.to_bytes();
    const hm = hash_with_namespace(V, V.proof_of_possession, namespace, &encoded);
    return hm.mul(private.scalar.value);
}

/// Verifies a proof of possession for `public`.
pub fn verify_proof_of_possession(
    comptime V: type,
    public: V.Public,
    namespace: []const u8,
    signature: V.Signature,
) Error!void {
    const encoded = public.to_bytes();
    const hm = hash_with_namespace(V, V.proof_of_possession, namespace, &encoded);
    return V.verify(public, hm, signature);
}

test {
    _ = @import("ops/tests.zig");
    _ = threshold;
}
