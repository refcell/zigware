//! Tests for the golden DKG's `Info` and `Output` (commonware `dkg/golden/mod.rs` tests that
//! do not need dealings), plus an `Info` summary from a Rust run.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const hex = @import("formatting").hex_literal;
const golden = @import("../golden.zig");
const feldman_desmedt = @import("../feldman_desmedt.zig");
const primitives = @import("../../primitives/root.zig");

const Info = golden.Info;
const PrivateKey = golden.PrivateKey;
const PublicKey = golden.PublicKey;
const Output = golden.Output(PublicKey);
const Set = utils.ordered.Set;
const N3f1 = utils.N3f1;
const MinPk = primitives.MinPk;
const gpa = testing.allocator;

/// Public keys of the first `count` `PrivateKey::random(test_rng())` draws.
fn test_keys(comptime count: usize) [count]PublicKey {
    var rng = utils.test_rng();
    var keys: [count]PublicKey = undefined;
    for (&keys) |*key| key.* = PrivateKey.random(&rng).public_key();
    return keys;
}

fn set_of(keys: []const PublicKey) !Set(PublicKey) {
    return Set(PublicKey).init(gpa, keys);
}

test "golden: info summary matches commonware" {
    const keys = test_keys(5);
    const info_result = Info.init(
        N3f1,
        gpa,
        "test",
        7,
        null,
        try set_of(keys[0..3]),
        try set_of(keys[1..]),
    );
    var info = try info_result;
    defer info.deinit(gpa);
    const expected = hex("bd28937891ef96bebb49180d6235b97deb7c0fd7674ba8384be559ca5d2137f1");
    try testing.expectEqualSlices(u8, &expected, &info.summary.bytes);
    try testing.expectEqual(3, info.player_quorum);
    try testing.expectEqual(3, info.required_commitments);
    try testing.expectEqual(2, info.degree());
}

test "golden: info rejects empty participants" {
    const keys = test_keys(1);
    const empty: Set(PublicKey) = try set_of(&.{});
    try testing.expectError(
        error.NumDealers,
        Info.init(N3f1, gpa, "test", 0, null, empty, try set_of(&keys)),
    );
    const empty_players: Set(PublicKey) = try set_of(&.{});
    try testing.expectError(
        error.NumPlayers,
        Info.init(N3f1, gpa, "test", 0, null, try set_of(&keys), empty_players),
    );
}

/// A previous-round output over `players`, with a fresh sharing.
fn previous_output(players: []const PublicKey) !Output {
    var rng = utils.test_rng();
    const n: u32 = @intCast(players.len);
    const mode: primitives.sharing.Mode = .non_zero_counter;
    const dealing = try feldman_desmedt.deal_anonymous(MinPk, N3f1, gpa, &rng, mode, n);
    for (dealing.shares) |*share| share.private.zeroize();
    gpa.free(dealing.shares);
    var player_set = try set_of(players);
    errdefer player_set.deinit(gpa);
    return .{
        .summary = .{ .bytes = @splat(7) },
        .public = dealing.sharing,
        .quorum_value = .{ .value = player_set.quorum(N3f1) },
        .dealers = try set_of(players[0..1]),
        .players = player_set,
    };
}

test "golden: info rejects reshare dealers outside the previous players" {
    const keys = test_keys(6);
    const previous = try previous_output(keys[0..4]);
    // keys[4] was not a previous player.
    const dealers = try set_of(&.{ keys[0], keys[1], keys[4] });
    try testing.expectError(
        error.UnknownDealer,
        Info.init(N3f1, gpa, "test", 1, previous, dealers, try set_of(keys[0..4])),
    );
}

test "golden: info rejects reshares with too few dealers" {
    const keys = test_keys(4);
    const previous = try previous_output(&keys);
    // The previous quorum is 3.
    try testing.expectError(
        error.NumDealers,
        Info.init(N3f1, gpa, "test", 1, previous, try set_of(keys[0..2]), try set_of(&keys)),
    );
    var reshare = try Info.init(
        N3f1,
        gpa,
        "test",
        1,
        try previous_output(&keys),
        try set_of(keys[0..3]),
        try set_of(&keys),
    );
    defer reshare.deinit(gpa);
    try testing.expectEqual(3, reshare.required_commitments);
    var rng = utils.test_rng();
    try testing.expectError(error.MissingDealerShare, reshare.unwrap_or_random_share(&rng, null));
}

test "golden: output round trips and rejects inconsistent encodings" {
    const keys = test_keys(4);
    var output = try previous_output(&keys);
    defer output.deinit(gpa);
    const cfg: Output.Cfg = .{ .max_participants = 4, .max_supported_mode = .v0 };
    const bytes = try codec.encode(Output, gpa, output);
    defer gpa.free(bytes);
    var decoded = try codec.decode_cfg(Output, gpa, bytes, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(output));

    var bad_quorum = try output.clone(gpa);
    defer bad_quorum.deinit(gpa);
    bad_quorum.quorum_value = .{ .value = 5 };
    const bad_quorum_bytes = try codec.encode(Output, gpa, bad_quorum);
    defer gpa.free(bad_quorum_bytes);
    try testing.expectError(error.Invalid, codec.decode_cfg(Output, gpa, bad_quorum_bytes, cfg));

    var short_players = try output.clone(gpa);
    defer short_players.deinit(gpa);
    short_players.players.deinit(gpa);
    short_players.players = try set_of(keys[0..3]);
    short_players.quorum_value = .{ .value = 2 };
    const short_bytes = try codec.encode(Output, gpa, short_players);
    defer gpa.free(short_bytes);
    try testing.expectError(error.Invalid, codec.decode_cfg(Output, gpa, short_bytes, cfg));
}
