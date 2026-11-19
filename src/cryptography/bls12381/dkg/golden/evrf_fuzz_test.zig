//! Decode fuzz for the golden DKG's proof-carrying types: `SignedDealerLog`, `DealerLog`,
//! `VrfCommitments`, and the eVRF `Proof`. Building a valid proof takes bulletproofs, so the
//! seeds come from one embedded `SignedDealerLog` (2 dealers, 3 players, `utils.test_rng`; see
//! `testdata/signed_dealer_log.hex`) and its re-encoded parts. Each input is a seed mutated by
//! flips, truncation, extension, or a duplicated or swapped commitment key, decoded under a
//! drawn player bound without verifying. A decode fails cleanly or yields a value within the
//! bound that encodes back to exactly the input.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const dealing = @import("dealing.zig");
const evrf = @import("evrf.zig");
const primitives = @import("../../primitives/root.zig");

const rng = utils.rng;
const FuzzRng = rng.FuzzRng;
const SignedDealerLog = dealing.SignedDealerLog;
const DealerLog = dealing.DealerLog;
const VrfCommitments = evrf.VrfCommitments;
const Proof = evrf.Proof;
const PublicKey = evrf.PublicKey;
const G1 = primitives.group.G1;
const Map = utils.ordered.Map(PublicKey, G1);
const gpa = testing.allocator;

const seed_hex = @embedFile("testdata/signed_dealer_log.hex");
const seed_len = 3063;
/// Players in the seed round: every commitment map and proof vector holds this many.
const seed_players = 3;

/// `vrf_commitments_overfull` is the seed's commitments with a fourth commitment beside the
/// three-player proof, so only the commitment map's own bound rejects it at three players.
const Kind = enum {
    signed_dealer_log,
    dealer_log,
    vrf_commitments,
    proof,
    vrf_commitments_overfull,
};
const kinds = std.enums.values(Kind).len;

/// The seed encodings, one per kind, owned by the caller.
const Seeds = struct {
    bytes: [kinds][]u8,

    fn init() !Seeds {
        var raw: [seed_len]u8 = undefined;
        var hex: [2 * seed_len]u8 = undefined;
        var hex_len: usize = 0;
        for (seed_hex) |char| {
            if (char == '\n') continue;
            hex[hex_len] = char;
            hex_len += 1;
        }
        assert(hex_len == hex.len);
        _ = try std.fmt.hexToBytes(&raw, &hex);
        const cfg: dealing.ReadCfg = .{ .max_players = seed_players, .max_supported_mode = .v0 };
        var signed = try codec.decode_cfg(SignedDealerLog, gpa, &raw, cfg);
        defer signed.deinit(gpa);
        var seeds: Seeds = undefined;
        seeds.bytes[0] = try gpa.dupe(u8, &raw);
        errdefer gpa.free(seeds.bytes[0]);
        seeds.bytes[1] = try codec.encode(DealerLog, gpa, signed.log);
        errdefer gpa.free(seeds.bytes[1]);
        seeds.bytes[2] = try codec.encode(VrfCommitments, gpa, signed.log.commitments);
        errdefer gpa.free(seeds.bytes[2]);
        seeds.bytes[3] = try codec.encode(Proof, gpa, signed.log.commitments.proof);
        errdefer gpa.free(seeds.bytes[3]);
        seeds.bytes[4] = try overfull(&signed.log.commitments);
        assert(signed.log.commitments.commitments.keys.items.len == seed_players);
        return seeds;
    }

    fn deinit(seeds: *Seeds) void {
        for (seeds.bytes) |bytes| gpa.free(bytes);
        seeds.* = undefined;
    }
};

/// `commitments` with one more (key, generator) commitment, encoded.
fn overfull(commitments: *const VrfCommitments) ![]u8 {
    const map = &commitments.commitments;
    var pairs: [seed_players + 1]Map.Pair = undefined;
    for (pairs[0..seed_players], map.keys.items, map.values) |*pair, key, value| {
        pair.* = .{ key, value };
    }
    pairs[seed_players] = .{ evrf.PrivateKey.from_seed(7).public_key(), G1.generator };
    var extended: VrfCommitments = .{
        .proof = commitments.proof,
        .commitments = try Map.init(gpa, &pairs),
    };
    defer extended.commitments.deinit(gpa);
    return codec.encode(VrfCommitments, gpa, extended);
}

/// Duplicate or swap two adjacent commitment keys. The commitment map ends every encoding
/// but the proof's: a one-byte key count, 32-byte keys, a one-byte value count, then the
/// 48-byte G1 commitments.
fn disorder_keys(r: *FuzzRng, encoded: []u8) void {
    const key_size = PublicKey.fixed_size;
    comptime assert(key_size == 32);
    comptime assert(G1.fixed_size == 48);
    const keys_end = encoded.len - 1 - seed_players * G1.fixed_size;
    const keys = encoded[keys_end - seed_players * key_size .. keys_end];
    assert(encoded[keys_end] == seed_players);
    const first = rng.range_less_than(r, usize, 0, seed_players - 1) * key_size;
    const left = keys[first..][0..key_size];
    const right = keys[first + key_size ..][0..key_size];
    if (rng.boolean(r)) {
        @memcpy(right, left);
    } else {
        const saved: [key_size]u8 = left.*;
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

fn expect_canonical(comptime T: type, value: T, bytes: []const u8) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, bytes, encoded);
}

fn expect_commitments(value: *const VrfCommitments, max_players: u32) !void {
    const keys = value.commitments.keys.items;
    try testing.expect(keys.len <= max_players);
    var index: usize = 1;
    while (index < keys.len) : (index += 1) {
        try testing.expectEqual(std.math.Order.lt, keys[index - 1].order(keys[index]));
    }
    try testing.expect(value.proof.pedersen_to_plain.len <= max_players);
}

/// Whether `bytes` decoded; a decoded value passed every check.
fn check_decode(kind: Kind, bytes: []const u8, max_players: u32) !bool {
    assert(max_players > 0);
    const cfg: dealing.ReadCfg = .{ .max_players = max_players, .max_supported_mode = .v0 };
    switch (kind) {
        .signed_dealer_log => {
            var value = codec.decode_cfg(SignedDealerLog, gpa, bytes, cfg) catch return false;
            defer value.deinit(gpa);
            try expect_commitments(&value.log.commitments, max_players);
            try expect_canonical(SignedDealerLog, value, bytes);
        },
        .dealer_log => {
            var value = codec.decode_cfg(DealerLog, gpa, bytes, cfg) catch return false;
            defer value.deinit(gpa);
            try expect_commitments(&value.commitments, max_players);
            try expect_canonical(DealerLog, value, bytes);
        },
        .vrf_commitments, .vrf_commitments_overfull => {
            const decoded = codec.decode_cfg(VrfCommitments, gpa, bytes, max_players);
            var value = decoded catch return false;
            defer value.deinit(gpa);
            try expect_commitments(&value, max_players);
            try expect_canonical(VrfCommitments, value, bytes);
        },
        .proof => {
            var reader: codec.Reader = .init(bytes);
            var value = Proof.read(gpa, &reader, max_players) catch return false;
            defer value.deinit(gpa);
            // Trailing bytes fail a whole decode.
            if (reader.remaining() != 0) return false;
            try testing.expect(value.pedersen_to_plain.len <= max_players);
            try expect_canonical(Proof, value, bytes);
        },
    }
    return true;
}

fn fuzz_evrf(seeds: *Seeds, r: *FuzzRng) !void {
    const kind: Kind = @fromBackingInt(@intCast(rng.range_less_than(r, u8, 0, kinds)));
    // Bounds below the seed's three players exercise every length check.
    const max_players = rng.range_at_most(r, u32, 1, seed_players + 1);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try bytes.appendSlice(gpa, seeds.bytes[@backingInt(kind)]);
    const ordered = kind != .proof and kind != .vrf_commitments_overfull;
    if (ordered and rng.range_at_most(r, u8, 0, 3) == 0) disorder_keys(r, bytes.items);
    try mutate(r, &bytes);
    _ = try check_decode(kind, bytes.items, max_players);
}

test "fuzz golden eVRF decoders from an embedded dealer log" {
    var seeds = try Seeds.init();
    defer seeds.deinit();
    // The unmutated seeds decode and re-encode exactly at the seed's bound.
    for (std.enums.values(Kind)) |kind| {
        const seed = seeds.bytes[@backingInt(kind)];
        const fits = kind != .vrf_commitments_overfull;
        try testing.expectEqual(fits, try check_decode(kind, seed, seed_players));
    }
    try utils.fuzz.run(&seeds, fuzz_evrf, 0x6576_7266, 200);
}
