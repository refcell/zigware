//! Decode fuzz for the golden DKG `Dealing`: random bytes or a valid dealing (a committed
//! polynomial and masked shares) mutated by flips, truncation, or extension. Every decode
//! fails cleanly or yields a dealing that encodes back to exactly the input, with between one
//! and `max_players` coefficients and at most `max_players` shares under sorted, distinct keys.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const math = @import("math");
const utils = @import("utils");
const dealing = @import("dealing.zig");
const evrf = @import("evrf.zig");
const primitives = @import("../../primitives/root.zig");

const rng = utils.rng;
const FuzzRng = rng.FuzzRng;
const Dealing = dealing.Dealing;
const PublicKey = evrf.PublicKey;
const PrivateKey = evrf.PrivateKey;
const Scalar = primitives.group.Scalar;
const G1 = primitives.group.G1;
const Map = utils.ordered.Map(PublicKey, Scalar);
const gpa = testing.allocator;

const players_max = 6;

/// A valid encoding of a dealing with `degree + 1` coefficients and `shares` players.
fn valid_encoding(r: *FuzzRng, degree: usize, shares: usize, out: *std.ArrayList(u8)) !void {
    assert(shares <= players_max + 1);
    var coeffs: [players_max + 1]Scalar = undefined;
    for (coeffs[0 .. degree + 1]) |*coeff| coeff.* = .from_u64(r.next_u64());
    var poly = try math.poly.Poly(Scalar).from_slice(gpa, coeffs[0 .. degree + 1]);
    defer poly.deinit(gpa);
    const commitment = try math.poly.commit(gpa, G1, poly);
    var pairs: [players_max + 1]Map.Pair = undefined;
    for (pairs[0..shares], 0..) |*pair, index| {
        const key = PrivateKey.from_seed(index + (r.next_u64() & 0xff) * 16);
        pair.* = .{ key.public_key(), .from_u64(r.next_u64()) };
    }
    var value: Dealing = .{
        .nonce = undefined,
        .poly = commitment,
        .masked_shares = Map.init(gpa, pairs[0..shares]) catch |err| {
            var owned = commitment;
            owned.deinit(gpa);
            return err;
        },
    };
    defer value.deinit(gpa);
    r.fill_bytes(&value.nonce.bytes);
    const encoded = try codec.encode(Dealing, gpa, value);
    defer gpa.free(encoded);
    if (shares >= 2 and rng.range_at_most(r, u8, 0, 2) == 0) disorder_keys(r, encoded, shares);
    try out.appendSlice(gpa, encoded);
}

/// Duplicate or swap two adjacent share keys in place: the keys are a block of 32-byte
/// encodings ending before the values' one-byte count and `shares` 32-byte values.
fn disorder_keys(r: *FuzzRng, encoded: []u8, shares: usize) void {
    assert(shares >= 2);
    const key_size = PublicKey.fixed_size;
    comptime assert(key_size == Scalar.fixed_size);
    const keys_end = encoded.len - 1 - shares * key_size;
    const keys = encoded[keys_end - shares * key_size .. keys_end];
    const first = rng.range_less_than(r, usize, 0, shares - 1) * key_size;
    const left = keys[first..][0..key_size];
    const right = keys[first + key_size ..][0..key_size];
    if (rng.boolean(r)) {
        @memcpy(right, left);
    } else {
        var saved: [key_size]u8 = left.*;
        @memcpy(left, right);
        @memcpy(right, &saved);
    }
}

/// Flip, truncate, or extend `bytes` a few times.
fn mutate(r: *FuzzRng, bytes: *std.ArrayList(u8)) !void {
    const mutations = rng.range_at_most(r, u8, 0, 3);
    for (0..mutations) |_| {
        switch (rng.range_at_most(r, u8, 0, 2)) {
            0 => if (bytes.items.len > 0) {
                const index = rng.range_less_than(r, usize, 0, bytes.items.len);
                bytes.items[index] ^= rng.range_at_most(r, u8, 1, 255);
            },
            1 => bytes.shrinkRetainingCapacity(rng.range_at_most(r, usize, 0, bytes.items.len)),
            2 => {
                var extra: [8]u8 = undefined;
                r.fill_bytes(&extra);
                try bytes.appendSlice(gpa, extra[0..rng.range_at_most(r, usize, 1, extra.len)]);
            },
            else => unreachable,
        }
    }
}

fn check_decode(bytes: []const u8, max_players: u32) !void {
    assert(max_players > 0);
    const cfg: dealing.ReadCfg = .{ .max_players = max_players, .max_supported_mode = .v0 };
    var value = codec.decode_cfg(Dealing, gpa, bytes, cfg) catch return;
    defer value.deinit(gpa);
    try testing.expect(value.poly.coeffs.len >= 1);
    try testing.expect(value.poly.coeffs.len <= max_players);
    const keys = value.masked_shares.keys.items;
    try testing.expect(keys.len <= max_players);
    var index: usize = 1;
    while (index < keys.len) : (index += 1) {
        try testing.expectEqual(std.math.Order.lt, keys[index - 1].order(keys[index]));
    }
    const encoded = try codec.encode(Dealing, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, bytes, encoded);
}

fn fuzz_dealing(_: void, r: *FuzzRng) !void {
    const max_players = rng.range_at_most(r, u32, 1, players_max);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    if (rng.range_at_most(r, u8, 0, 3) == 0) {
        try bytes.resize(gpa, rng.range_at_most(r, usize, 0, 256));
        r.fill_bytes(bytes.items);
    } else {
        // Sizes one past the bound exercise both range checks.
        const degree = rng.range_at_most(r, usize, 0, max_players);
        const shares = rng.range_at_most(r, usize, 0, max_players + 1);
        try valid_encoding(r, degree, shares, &bytes);
        try mutate(r, &bytes);
    }
    try check_decode(bytes.items, max_players);
}

test "fuzz golden dealing decoder" {
    try utils.fuzz.run({}, fuzz_dealing, 0x6465_616c, 150);
}
