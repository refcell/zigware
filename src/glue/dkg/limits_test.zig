//! commonware's `glue::dkg::limits` test `widest_encodings`: every size bound equals the widest
//! encoding it covers plus the unused width of its length prefixes.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const math = @import("math");
const p2p = @import("p2p");
const cryptography = @import("cryptography");
const Epoch = @import("consensus").Epoch;
const types = @import("types.zig");
const network = @import("network.zig");
const limits = @import("limits.zig");

const ed25519 = cryptography.ed25519;
const P = ed25519.PublicKey;
const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const primitives = cryptography.bls12381.primitives;
const Scalar = primitives.group.Scalar;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Addresses = network.Addresses(P);
const Bytes = std.ArrayList(u8);

/// Namespace for the signatures these tests build.
const namespace = "_COMMONWARE_GLUE_DKG_LIMITS";
const u32_varint_max = codec.varint.max_size(u32);

fn participants(gpa: Allocator, count: u64) !Set(P) {
    const keys = try gpa.alloc(P, count);
    for (keys, 0..) |*item, seed| item.* = ed25519.PrivateKey.from_seed(seed).public_key();
    return Set(P).from_owned_dedup(gpa, keys);
}

fn append_encoded(gpa: Allocator, out: *Bytes, comptime T: type, value: T) !void {
    const bytes = try codec.encode(T, gpa, value);
    defer gpa.free(bytes);
    try out.appendSlice(gpa, bytes);
}

/// An encoded commitment with `count` coefficients.
fn commitment(comptime V: type, gpa: Allocator, out: *Bytes, count: u32) !void {
    var rng = utils.rng.TestRng.init(0);
    var scalars = try math.poly.Poly(Scalar).random(gpa, &rng, count - 1);
    defer scalars.deinit(gpa);
    var committed = try math.poly.commit(gpa, V.Public, scalars);
    defer committed.deinit(gpa);
    try append_encoded(gpa, out, @TypeOf(committed), committed);
}

fn signature(gpa: Allocator, out: *Bytes) !void {
    const sig = ed25519.PrivateKey.from_seed(0).sign(namespace, "message");
    try out.appendSlice(gpa, &sig.raw);
}

/// The widest dealing for `count` participants.
fn dealer(comptime V: type, gpa: Allocator, count: u32) !Bytes {
    var out: Bytes = .empty;
    try out.append(gpa, 0);
    try commitment(V, gpa, &out, count);
    var rng = utils.rng.TestRng.init(0);
    try append_encoded(gpa, &out, Scalar, Scalar.random(&rng));
    return out;
}

fn ack(gpa: Allocator) !Bytes {
    var out: Bytes = .empty;
    try out.append(gpa, 1);
    try signature(gpa, &out);
    return out;
}

/// The widest dealer log payload: every player is acknowledged, since a signature is wider
/// than a revealed share.
fn log(comptime V: type, gpa: Allocator, count: u32) !Bytes {
    comptime std.debug.assert(codec.fixed_size(ed25519.Signature).? > Scalar.fixed_size);
    var out: Bytes = .empty;
    try out.append(gpa, 0);
    try append_encoded(gpa, &out, P, ed25519.PrivateKey.from_seed(0).public_key());
    try commitment(V, gpa, &out, count);
    try out.append(gpa, 0);
    var players = try participants(gpa, count);
    defer players.deinit(gpa);
    try append_encoded(gpa, &out, Set(P), players);
    try append_encoded(gpa, &out, usize, count);
    for (0..count) |_| {
        try out.append(gpa, 0);
        try signature(gpa, &out);
    }
    try signature(gpa, &out);
    return out;
}

/// The widest epoch artifact payload, ending with `directory`. Its output names `sets[0]`, its
/// players are `sets[1]`, and its next players are `sets[2]`.
fn info(
    comptime V: type,
    gpa: Allocator,
    count: u32,
    sets: [3]Set(P),
    directory: []const u8,
) !Bytes {
    var out: Bytes = .empty;
    try out.appendSlice(gpa, &.{ 1, 1 });
    try append_encoded(gpa, &out, Epoch, .new(std.math.maxInt(u64)));
    try out.appendSlice(gpa, &@as([32]u8, @splat(0xab))); // The summary.
    try out.append(gpa, 0);
    try append_encoded(gpa, &out, u32, count);
    try commitment(V, gpa, &out, count);
    for ([_]Set(P){ sets[0], sets[0], sets[0], sets[1], sets[2] }) |set| {
        try append_encoded(gpa, &out, Set(P), set);
    }
    try out.appendSlice(gpa, directory);
    return out;
}

fn reencoded_len(comptime T: type, gpa: Allocator, bytes: []const u8, cfg: codec.Cfg(T)) !usize {
    var decoded = try codec.decode_cfg(T, gpa, bytes, cfg);
    defer decoded.deinit(gpa);
    const again = try codec.encode(T, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, bytes, again);
    return again.len;
}

/// Four labels of 63, 63, 63, and 61 letters: the longest valid hostname.
fn widest_host() [253]u8 {
    var host: [253]u8 = undefined;
    var index: usize = 0;
    for ("abcd", [_]usize{ 63, 63, 63, 61 }) |letter, len| {
        if (index > 0) {
            host[index] = '.';
            index += 1;
        }
        @memset(host[index..][0..len], letter);
        index += len;
    }
    std.debug.assert(index == host.len);
    return host;
}

/// Each peer behind the widest address: a 253-byte DNS name and an IPv6 egress.
fn widest_addresses(gpa: Allocator, peers: Set(P)) !Addresses {
    const host = comptime widest_host();
    const address: p2p.Address = .{ .asymmetric = .{
        .ingress = .{ .dns = .{ .host = try utils.Hostname.init(&host), .port = 65535 } },
        .egress = .{ .ip = .{ .v6 = .localhost }, .port = 65535 },
    } };
    const pairs = try gpa.alloc(Addresses.Inner.Pair, peers.items.len);
    defer gpa.free(pairs);
    for (pairs, peers.items) |*pair, peer| pair.* = .{ peer, address };
    return Addresses.init(gpa, pairs);
}

fn check_messages(comptime V: type, gpa: Allocator, count: u32, slack: usize) !void {
    const Message = types.Message(V, P);
    var dealing_bytes = try dealer(V, gpa, count);
    defer dealing_bytes.deinit(gpa);
    var ack_bytes = try ack(gpa);
    defer ack_bytes.deinit(gpa);
    const dealing = try reencoded_len(Message, gpa, dealing_bytes.items, count);
    const acknowledgement = try reencoded_len(Message, gpa, ack_bytes.items, count);
    const message = Message.max_encode_size_with(count);
    try testing.expect(acknowledgement < dealing);
    try testing.expectEqual(message, dealing + slack);
    try testing.expectEqual(limits.max_payload_size(V, P, count), message + 10);
    // One more coefficient than configured fails to decode.
    var wider = try dealer(V, gpa, count + 1);
    defer wider.deinit(gpa);
    try testing.expect(std.meta.isError(codec.decode_cfg(Message, gpa, wider.items, count)));
}

fn check_payloads(comptime V: type, gpa: Allocator, count: u32, slack: usize) !void {
    const Payload = types.Payload(V, P, Unit);
    const cfg: types.InfoCfg = .{ .max_participants = count, .max_supported_mode = .v0 };
    var set = try participants(gpa, count);
    defer set.deinit(gpa);
    var log_bytes = try log(V, gpa, count);
    defer log_bytes.deinit(gpa);
    var info_bytes = try info(V, gpa, count, .{ set, set, set }, &.{});
    defer info_bytes.deinit(gpa);
    const log_size = try reencoded_len(Payload, gpa, log_bytes.items, cfg) + 3 * slack;
    const info_size = try reencoded_len(Payload, gpa, info_bytes.items, cfg) + 6 * slack;
    try testing.expectEqual(fd.SignedDealerLog(V, P).max_encode_size_with(count) + 1, log_size);
    try testing.expectEqual(types.EpochInfo(V, P, Unit).max_encode_size_with(count) + 1, info_size);
    try testing.expectEqual(Payload.max_encode_size_with(count), @max(log_size, info_size));
    // One more participant than configured fails to decode.
    var wider = try participants(gpa, count + 1);
    defer wider.deinit(gpa);
    var wide_log = try log(V, gpa, count + 1);
    defer wide_log.deinit(gpa);
    var wide_info = try info(V, gpa, count + 1, .{ wider, wider, wider }, &.{});
    defer wide_info.deinit(gpa);
    for ([_][]const u8{ wide_log.items, wide_info.items }) |bytes| {
        try testing.expect(std.meta.isError(codec.decode_cfg(Payload, gpa, bytes, cfg)));
    }
}

/// The widest addressed artifact names disjoint output players, players, and next players, so
/// its directory holds three times `count` peers, each behind the widest address.
fn check_addressed(comptime V: type, gpa: Allocator, count: u32, slack: usize) !void {
    const Payload = types.Payload(V, P, Addresses);
    const cfg: types.InfoCfg = .{ .max_participants = count, .max_supported_mode = .v0 };
    var peers = try participants(gpa, 3 * @as(u64, count));
    defer peers.deinit(gpa);
    var directory = try widest_addresses(gpa, peers);
    defer directory.deinit(gpa);
    const directory_bytes = try codec.encode(Addresses, gpa, directory);
    defer gpa.free(directory_bytes);
    var sets: [3]Set(P) = undefined;
    for (&sets, 0..) |*set, index| set.* = .{ .items = peers.items[index * count ..][0..count] };
    var encoded = try info(V, gpa, count, sets, directory_bytes);
    defer encoded.deinit(gpa);
    // The bound adds the unused width of the directory's key-set and address-list prefixes
    // and of each address's hostname prefix.
    const entries: usize = 3 * @as(usize, count);
    const address_slack = p2p.Address.max_encode_size - directory.map.values[0].encode_size();
    const prefix_slack = u32_varint_max - codec.varint.size(u32, @intCast(entries));
    const directory_slack = 2 * prefix_slack + entries * address_slack;
    const len = try reencoded_len(Payload, gpa, encoded.items, cfg);
    try testing.expectEqual(Payload.max_encode_size_with(count), len + 6 * slack + directory_slack);
}

fn check(comptime V: type, count: u32) !void {
    const gpa = testing.allocator;
    const slack = u32_varint_max - codec.varint.size(u32, count);
    try check_messages(V, gpa, count, slack);
    try check_payloads(V, gpa, count, slack);
    try check_addressed(V, gpa, count, slack);
}

test "limits: widest encodings (widest_encodings)" {
    const counts = [_]u32{ 1, 4, 127, 128 };
    // The wide commitments take minutes in Debug; run them in optimized builds or with
    // `-Dslow-tests`.
    const slow = builtin.mode == .debug and !build_options.slow_tests;
    const run = if (slow) counts[0..2] else counts[0..];
    for (run) |count| {
        try check(primitives.MinPk, count);
        try check(primitives.MinSig, count);
    }
}
