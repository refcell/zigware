//! Test fixtures for ed25519 certificate schemes (commonware `ed25519/certificate/mocks.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const scheme_module = @import("../scheme.zig");
const certificate_mocks = @import("../../certificate/mocks.zig");

const PrivateKey = scheme_module.PrivateKey;
const PublicKey = scheme_module.PublicKey;

const Identity = struct {
    public_key: PublicKey,
    private_key: PrivateKey,

    fn less(_: void, a: Identity, b: Identity) bool {
        return a.public_key.order(b.public_key) == .lt;
    }
};

/// `n` ed25519 identities from `rng`, sorted by public key (commonware `participants`).
/// The caller frees both slices.
pub fn participants(
    gpa: Allocator,
    rng: anytype,
    n: u32,
) Allocator.Error!struct { []PublicKey, []PrivateKey } {
    const identities = try gpa.alloc(Identity, n);
    defer gpa.free(identities);
    for (identities) |*identity| {
        const private_key = PrivateKey.random(rng);
        identity.* = .{ .public_key = private_key.public_key(), .private_key = private_key };
    }
    std.mem.sort(Identity, identities, {}, Identity.less);
    const public_keys = try gpa.alloc(PublicKey, n);
    errdefer gpa.free(public_keys);
    const private_keys = try gpa.alloc(PrivateKey, n);
    for (identities, public_keys, private_keys, 0..) |identity, *public_key, *private_key, i| {
        // ed25519 public keys from distinct random seeds are unique.
        if (i > 0) assert(identities[i - 1].public_key.order(identity.public_key) == .lt);
        public_key.* = identity.public_key;
        private_key.* = identity.private_key;
    }
    return .{ public_keys, private_keys };
}

/// Builds `n` ed25519 identities, one signing scheme `S` per identity, and a verifier
/// (commonware `fixture`). `S` is an ed25519 certificate scheme, such as
/// `ed25519.certificate.Scheme(Subject, Faults)`.
pub fn fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!certificate_mocks.Fixture(S) {
    assert(n > 0);
    const public_keys, const private_keys = try participants(gpa, rng, n);
    errdefer gpa.free(public_keys);
    errdefer gpa.free(private_keys);
    var set = S.Participants.init(gpa, public_keys) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Proof: `participants` returns strictly increasing keys.
        else => unreachable,
    };
    defer set.deinit(gpa);
    const schemes = try gpa.alloc(S, n);
    errdefer gpa.free(schemes);
    var built: usize = 0;
    errdefer for (schemes[0..built]) |*scheme| scheme.deinit(gpa);
    for (private_keys, schemes) |private_key, *scheme| {
        const signer = try S.signer(gpa, namespace, try set.clone(gpa), private_key);
        scheme.* = signer orelse unreachable; // Proof: every key is in `set`.
        built += 1;
    }
    assert(built == n);
    return .{
        .participants = public_keys,
        .private_keys = private_keys,
        .schemes = schemes,
        .verifier = try S.verifier(gpa, namespace, try set.clone(gpa)),
    };
}
