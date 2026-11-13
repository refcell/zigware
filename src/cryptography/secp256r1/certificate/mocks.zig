//! Test fixtures for secp256r1 certificate schemes (commonware
//! `secp256r1/certificate/mocks.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const standard = @import("../standard.zig");
const ed25519_mocks = @import("../../ed25519/certificate/mocks.zig");
const certificate_mocks = @import("../../certificate/mocks.zig");

/// Builds `n` ed25519 identities, each paired with a fresh secp256r1 signing key, one signing
/// scheme `S` per identity, and a verifier (commonware `fixture`). `S` is a secp256r1
/// certificate scheme over ed25519 identities, such as
/// `secp256r1.certificate.Scheme(Subject, Faults, ed25519.PublicKey)`.
pub fn fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!certificate_mocks.Fixture(S) {
    assert(n > 0);
    const identities, const identity_keys = try ed25519_mocks.participants(gpa, rng, n);
    errdefer gpa.free(identities);
    errdefer gpa.free(identity_keys);
    const signing_keys = try gpa.alloc(standard.PrivateKey, n);
    defer gpa.free(signing_keys);
    const pairs = try gpa.alloc(S.Participants.Pair, n);
    defer gpa.free(pairs);
    for (signing_keys, pairs, identities) |*key, *pair, identity| {
        key.* = standard.PrivateKey.random(rng);
        pair.* = .{ identity, key.public_key() };
    }
    const schemes = try gpa.alloc(S, n);
    errdefer gpa.free(schemes);
    var built: usize = 0;
    errdefer for (schemes[0..built]) |*scheme| scheme.deinit(gpa);
    for (signing_keys, schemes) |key, *scheme| {
        const signer = try S.signer(gpa, namespace, try participants(S, gpa, pairs), key);
        scheme.* = signer orelse unreachable; // Proof: every signing key is paired.
        built += 1;
    }
    assert(built == n);
    return .{
        .participants = identities,
        .private_keys = identity_keys,
        .schemes = schemes,
        .verifier = try S.verifier(gpa, namespace, try participants(S, gpa, pairs)),
    };
}

fn participants(
    comptime S: type,
    gpa: Allocator,
    pairs: []const S.Participants.Pair,
) Allocator.Error!S.Participants {
    return S.Participants.init(gpa, pairs) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Proof: identities are sorted and unique, and independent random signing keys
        // collide with negligible probability.
        else => unreachable,
    };
}
