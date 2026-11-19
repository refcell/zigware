//! Tests for provider.zig: schemes register per epoch, read back by epoch, and keep the role
//! (signer, member, verifier) of the registered `SchemeInfo`.

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const types = @import("types.zig");
const provider = @import("provider.zig");

const ed25519 = zigware.cryptography.ed25519;
const fd = zigware.cryptography.bls12381.dkg.feldman_desmedt;
const utils = zigware.utils;

const gpa = testing.allocator;
const Set = types.Set(types.PublicKey);
const Epoch = types.Epoch;

test "dkg: provider registers each epoch's scheme with its role" {
    var keys: [4]types.PublicKey = undefined;
    for (&keys, 0..) |*key, seed| key.* = ed25519.PrivateKey.from_seed(seed).public_key();
    const players = try Set.from_dedup(gpa, &keys);
    var rng = utils.rng.TestRng.init(0);
    const mode = types.sharing_mode;
    var dealt = try fd.deal(types.MinSig, types.PublicKey, utils.N3f1, gpa, &rng, mode, players);
    defer dealt.shares.deinit(gpa);
    defer dealt.output.deinit(gpa);

    var dynamic = provider.DynamicProvider.init(gpa, testing.io);
    defer dynamic.deinit();
    var registrar: provider.Registrar = .{ .provider = &dynamic };
    const outsider = ed25519.PrivateKey.from_seed(99).public_key();
    const roles = [_]struct { key: types.PublicKey, share: bool }{
        .{ .key = keys[0], .share = true },
        .{ .key = keys[1], .share = false },
        .{ .key = outsider, .share = false },
    };
    for (roles, 0..) |role, epoch| {
        const set = try dealt.output.players.clone(gpa);
        const sharing = try dealt.output.public.clone(gpa);
        const share = if (role.share) dealt.shares.values[0] else null;
        const info = provider.SchemeInfo.init(role.key, set, sharing, share);
        try registrar.register(testing.io, .new(epoch), info);
    }
    try testing.expect(dynamic.scheme(.new(3)) == null);
    try testing.expect(dynamic.scoped(.new(3)) == null);

    // Epoch 0 signs with share 0, epoch 1 is `keys[1]`'s seat without a share, and epoch 2
    // only verifies.
    const signer = dynamic.scheme(.new(0)).?;
    const share_index = dealt.shares.values[0].index.get();
    try testing.expectEqual(share_index, signer.me().?.signer.get());
    const member = dynamic.scheme(.new(1)).?;
    const seat = dealt.output.players.index(keys[1]).?.get();
    try testing.expectEqual(seat, member.me().?.member.get());
    try testing.expect(member.signing_share == null);
    try testing.expect(dynamic.scheme(.new(2)).?.me() == null);
    try testing.expect(dynamic.scoped(.new(2)).?.into_scheme().? == dynamic.scheme(.new(2)).?);

    // A second registration for an epoch keeps the first scheme where readers hold it.
    const set = try dealt.output.players.clone(gpa);
    const sharing = try dealt.output.public.clone(gpa);
    try registrar.register(testing.io, .new(0), .init(outsider, set, sharing, null));
    try testing.expect(dynamic.scheme(.new(0)).? == signer);
    try testing.expect(signer.me() != null);
}
