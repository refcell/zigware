//! Tests of commonware's `glue::dkg::types` (`mod tests`).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const cryptography = @import("cryptography");
const types = @import("types.zig");
const network = @import("network.zig");

const ed25519 = cryptography.ed25519;
const P = ed25519.PublicKey;
const Set = utils.ordered.Set;
const MinPk = cryptography.bls12381.primitives.MinPk;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Addresses = network.Addresses(P);
const Info = types.EpochInfo(MinPk, P, Addresses);
const cfg = struct {
    fn of(max: u32) types.InfoCfg {
        return .{ .max_participants = max, .max_supported_mode = .v1 };
    }
}.of;

fn key(seed: u64) P {
    return ed25519.PrivateKey.from_seed(seed).public_key();
}

fn keys_in(gpa: Allocator, start: u64, end: u64) !Set(P) {
    var list: std.ArrayList(P) = .empty;
    defer list.deinit(gpa);
    for (start..end) |seed| try list.append(gpa, key(seed));
    return Set(P).from_dedup(gpa, list.items);
}

/// Each key at `127.0.0.1:index + 1`.
fn addresses(gpa: Allocator, keys: Set(P)) !Addresses {
    const pairs = try gpa.alloc(Addresses.Inner.Pair, keys.items.len);
    defer gpa.free(pairs);
    for (keys.items, pairs, 0..) |item, *pair, index| {
        const port: u16 = @intCast(index + 1);
        pair.* = .{ item, .{ .symmetric = .{ .ip = .{ .v4 = .localhost }, .port = port } } };
    }
    return Addresses.init(gpa, pairs);
}

fn trusted_output(gpa: Allocator, dealers: Set(P)) !fd.Output(MinPk, P) {
    var rng = utils.rng.TestRng.init(1);
    var dealt = try fd.deal(MinPk, P, utils.N3f1, gpa, &rng, .non_zero_counter, dealers);
    const output = dealt.output;
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    return output;
}

fn addressed_info(gpa: Allocator, participants: u64) !Info {
    var keys = try keys_in(gpa, 0, participants);
    defer keys.deinit(gpa);
    return .{
        .outcome = .success,
        .epoch = .new(2),
        .output = try trusted_output(gpa, try keys.clone(gpa)),
        .players = try keys.clone(gpa),
        .next_players = try keys.clone(gpa),
        .directory = try addresses(gpa, keys),
    };
}

fn expect_roundtrip(gpa: Allocator, info: Info, max: u32) !void {
    const bytes = try codec.encode(Info, gpa, info);
    defer gpa.free(bytes);
    try testing.expectEqual(info.encode_size(), bytes.len);
    try testing.expect(bytes.len <= Info.max_encode_size_with(max));
    var decoded = try codec.decode_cfg(Info, gpa, bytes, cfg(max));
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(info));
}

/// Decoding `info` fails (commonware asserts only `is_err`).
fn expect_rejected(gpa: Allocator, info: Info, max: u32) !void {
    const bytes = try codec.encode(Info, gpa, info);
    defer gpa.free(bytes);
    var decoded = codec.decode_cfg(Info, gpa, bytes, cfg(max)) catch return;
    decoded.deinit(gpa);
    return error.TestUnexpectedResult;
}

test "types: addressed epoch info roundtrips" {
    const gpa = testing.allocator;
    var info = try addressed_info(gpa, 4);
    defer info.deinit(gpa);
    try expect_roundtrip(gpa, info, 4);
}

// A node's role follows its share and its place among the players: a player with a share
// signs, a player without one is a member, and any other node is a verifier.
test "types: scheme info names the node role" {
    const gpa = testing.allocator;
    const Scheme = types.SchemeInfo(MinPk, P);
    var keys = try keys_in(gpa, 0, 4);
    defer keys.deinit(gpa);
    var rng = utils.rng.TestRng.init(1);
    const owned = try keys.clone(gpa);
    var dealt = try fd.deal(MinPk, P, utils.N3f1, gpa, &rng, .non_zero_counter, owned);
    defer dealt.deinit(gpa);
    const player = keys.items[1];
    const share = dealt.shares.get_value(player).?.*;
    const outsider = key(99);

    const public = dealt.output.public;
    var signer = Scheme.init(player, try keys.clone(gpa), try public.clone(gpa), share);
    defer signer.deinit(gpa);
    try testing.expect(signer == .signer);
    try testing.expect(signer.signer.share.eql(share));
    var member = Scheme.init(player, try keys.clone(gpa), try public.clone(gpa), null);
    defer member.deinit(gpa);
    try testing.expect(member == .member);
    try testing.expect(member.member.public_key.eql(player));
    var verifier = Scheme.init(outsider, try keys.clone(gpa), try public.clone(gpa), null);
    defer verifier.deinit(gpa);
    try testing.expect(verifier == .verifier);
    for ([_]*const Scheme{ &signer, &member, &verifier }) |info| {
        try testing.expect(info.participants().eql(keys));
        try testing.expect(info.sharing().eql(dealt.output.public));
    }
    try testing.expect(!signer.eql(member));
    try testing.expect(!member.eql(verifier));
    var copy = try member.clone(gpa);
    defer copy.deinit(gpa);
    try testing.expect(copy.eql(member));
}

test "types: addressed epoch info roundtrips disjoint participant sets" {
    const gpa = testing.allocator;
    const dealers = try keys_in(gpa, 0, 4);
    var peers = try keys_in(gpa, 0, 12);
    defer peers.deinit(gpa);
    var info: Info = .{
        .outcome = .success,
        .epoch = .new(2),
        .output = try trusted_output(gpa, dealers),
        .players = try keys_in(gpa, 4, 8),
        .next_players = try keys_in(gpa, 8, 12),
        .directory = try addresses(gpa, peers),
    };
    defer info.deinit(gpa);
    try expect_roundtrip(gpa, info, 4);
    var participants = try info.participants(gpa);
    defer participants.deinit(gpa);
    try testing.expect(participants.dealers.eql(info.output.players));
}

test "types: addressed epoch info rejects extra directory peer" {
    const gpa = testing.allocator;
    var info = try addressed_info(gpa, 1);
    defer info.deinit(gpa);
    var two = try keys_in(gpa, 0, 2);
    defer two.deinit(gpa);
    info.directory.deinit(gpa);
    info.directory = try addresses(gpa, two);
    try expect_rejected(gpa, info, 1);
}

test "types: addressed epoch info rejects missing directory peer" {
    const gpa = testing.allocator;
    var info = try addressed_info(gpa, 1);
    defer info.deinit(gpa);
    info.directory.deinit(gpa);
    info.directory = try addresses(gpa, .empty);
    try expect_rejected(gpa, info, 1);
}

test "types: addressed epoch info rejects wrong directory peer" {
    const gpa = testing.allocator;
    var info = try addressed_info(gpa, 1);
    defer info.deinit(gpa);
    var wrong = try keys_in(gpa, 1, 2);
    defer wrong.deinit(gpa);
    info.directory.deinit(gpa);
    info.directory = try addresses(gpa, wrong);
    // The lengths agree, so the directory fails the match check itself.
    const bytes = try codec.encode(Info, gpa, info);
    defer gpa.free(bytes);
    try testing.expectError(error.Invalid, codec.decode_cfg(Info, gpa, bytes, cfg(1)));
}

test "types: participants validate empty, oversized, and reshare dealers" {
    const gpa = testing.allocator;
    const Participants = types.Participants(P);
    var four = try keys_in(gpa, 0, 4);
    defer four.deinit(gpa);
    var later = try keys_in(gpa, 2, 6);
    defer later.deinit(gpa);
    var output = try trusted_output(gpa, try four.clone(gpa));
    defer output.deinit(gpa);
    const ok: Participants = .{ .dealers = four, .players = later, .next_players = .empty };
    try ok.validate(MinPk, 4, null, 0);
    try ok.validate(MinPk, 4, &output, 0);
    try testing.expectError(error.TooManyParticipants, ok.validate(MinPk, 3, null, 0));
    const no_dealers: Participants = .{ .dealers = .empty, .players = four, .next_players = .{} };
    try testing.expectError(error.EmptyDealers, no_dealers.validate(MinPk, 4, null, 0));
    const no_players: Participants = .{ .dealers = four, .players = .{}, .next_players = .{} };
    try testing.expectError(error.EmptyPlayers, no_players.validate(MinPk, 4, null, 0));
    const shifted: Participants = .{ .dealers = later, .players = four, .next_players = .empty };
    try testing.expectError(error.InitialReshareDealers, shifted.validate(MinPk, 4, &output, 0));
    try testing.expectError(error.UnknownReshareDealer, shifted.validate(MinPk, 4, &output, 1));
    // A later round accepts any subset of the previous players.
    const subset: Participants = .{
        .dealers = .{ .items = four.items[1..3] },
        .players = four,
        .next_players = .empty,
    };
    try subset.validate(MinPk, 4, &output, 1);
    var tracked = try shifted.tracked_peers(gpa);
    defer tracked.deinit(gpa);
    try testing.expect(tracked.primary.eql(later));
    try testing.expect(tracked.secondary.eql(four));
}

test "types: payload and message roundtrip with their size bounds" {
    const gpa = testing.allocator;
    const Payload = types.Payload(MinPk, P, Addresses);
    var payload: Payload = .{ .epoch_info = try addressed_info(gpa, 4) };
    defer payload.deinit(gpa);
    const bytes = try codec.encode(Payload, gpa, payload);
    defer gpa.free(bytes);
    try testing.expectEqual(@as(u8, 1), bytes[0]);
    try testing.expect(bytes.len <= Payload.max_encode_size_with(4));
    var decoded = try codec.decode_cfg(Payload, gpa, bytes, cfg(4));
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(payload));
    var bad = try gpa.dupe(u8, bytes);
    defer gpa.free(bad);
    bad[0] = 2;
    try testing.expectError(error.InvalidEnum, codec.decode_cfg(Payload, gpa, bad, cfg(4)));

    const Message = types.Message(MinPk, P);
    const signer = ed25519.PrivateKey.from_seed(3);
    const ack: Message = .{ .ack = .{ .sig = signer.sign("", "ack") } };
    const ack_bytes = try codec.encode(Message, gpa, ack);
    defer gpa.free(ack_bytes);
    try testing.expectEqual(1 + 64, ack_bytes.len);
    try testing.expect(ack_bytes.len <= Message.max_encode_size_with(1));
    var decoded_ack = try codec.decode_cfg(Message, gpa, ack_bytes, 1);
    defer decoded_ack.deinit(gpa);
    try testing.expect(decoded_ack.eql(ack));
}

test "types: epoch outcome encodes as a tag" {
    const gpa = testing.allocator;
    for ([_]types.EpochOutcome{ .success, .failure }, 0..) |outcome, tag| {
        const bytes = try codec.encode(types.EpochOutcome, gpa, outcome);
        defer gpa.free(bytes);
        try testing.expectEqualSlices(u8, &.{@intCast(tag)}, bytes);
    }
    try testing.expectError(error.InvalidEnum, codec.decode(types.EpochOutcome, gpa, &.{2}));
}

test "types: max participants accepts the u32 range" {
    try testing.expectEqual(@as(u32, 1), types.max_participants(1));
    try testing.expectEqual(std.math.maxInt(u32), types.max_participants(std.math.maxInt(u32)));
}
