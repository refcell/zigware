//! The `secp256r1_standard_decode` and `secp256r1_recoverable_decode` fuzz targets.
//!
//! commonware checks its decoders against the `p256` crate. zigware checks them against
//! independent statements of the same rules: a private key is a big-endian integer in
//! `[1, n)`, a public key a compressed point whose x is below p and on the curve, and a
//! signature has `r` and `s` in `[1, n)` with `s <= (n - 1) / 2`. Signatures must also verify
//! under `std.crypto.sign.ecdsa`, and derived public keys must match std's.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const fuzz = @import("../fuzz.zig");
const common = @import("common.zig");
const standard = @import("standard.zig");
const recoverable = @import("recoverable.zig");
const P256 = std.crypto.ecc.P256;
const StdEcdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const order = P256.scalar.field_order;
const variable_lengths = [_]usize{ 0, 31, 32, 33, 34, 63, 64, 65, 128, 256 };

fn decode(comptime T: type, bytes: []const u8) codec.Error!T {
    return codec.decode(T, testing.allocator, bytes);
}

fn scalar_in_range(bytes: *const [32]u8) bool {
    const value = std.mem.readInt(u256, bytes, .big);
    return value != 0 and value < order;
}

/// SEC 1 compressed point validity, from the curve equation y^2 = x^3 - 3x + b.
fn public_key_valid(bytes: []const u8) bool {
    if (bytes.len != common.public_key_length) return false;
    if (bytes[0] != 0x02 and bytes[0] != 0x03) return false;
    const x = P256.Fe.fromBytes(bytes[1..33].*, .big) catch return false;
    const rhs = x.sq().mul(x).sub(x).sub(x).sub(x).add(P256.B);
    return rhs.isSquare();
}

fn test_private_key(comptime M: type, bytes: []const u8) !void {
    const ours = decode(M.PrivateKey, bytes);
    if (bytes.len != common.private_key_length) {
        try testing.expect(std.meta.isError(ours));
        return;
    }
    const valid = scalar_in_range(bytes[0..32]);
    try testing.expectEqual(valid, !std.meta.isError(ours));
    if (ours) |key| {
        try testing.expectEqualSlices(u8, bytes, &codec.encode_fixed(M.PrivateKey, key));
    } else |_| {}
}

fn test_public_key(comptime M: type, bytes: []const u8) !void {
    const ours = decode(M.PublicKey, bytes);
    try testing.expectEqual(public_key_valid(bytes), !std.meta.isError(ours));
    if (ours) |key| {
        // Decoding keeps the encoding: the round trip is exact.
        try testing.expectEqualSlices(u8, bytes, &codec.encode_fixed(M.PublicKey, key));
        const std_key = try StdEcdsa.PublicKey.fromSec1(bytes);
        try testing.expectEqualSlices(u8, bytes, &std_key.toCompressedSec1());
    } else |_| {}
}

fn test_signature(comptime M: type, comptime offset: usize, bytes: []const u8) !void {
    const ours = decode(M.Signature, bytes);
    if (bytes.len != 64 + offset) {
        try testing.expect(std.meta.isError(ours));
        return;
    }
    const rs = bytes[offset..];
    const valid = (offset == 0 or bytes[0] < 4) and scalar_in_range(rs[0..32]) and
        scalar_in_range(rs[32..64]) and !common.is_high(rs[32..64].*);
    try testing.expectEqual(valid, !std.meta.isError(ours));
    if (ours) |signature| {
        try testing.expectEqualSlices(u8, bytes, &codec.encode_fixed(M.Signature, signature));
    } else |_| {}
}

fn test_sign_verify(
    comptime M: type,
    comptime offset: usize,
    key_bytes: *const [32]u8,
    message: []const u8,
) !void {
    const key = decode(M.PrivateKey, key_bytes) catch return;
    const public = key.public_key();
    const signature = key.sign("", message);
    try testing.expect(public.verify("", message, &signature));
    const with_namespace = key.sign("test_namespace", message);
    try testing.expect(public.verify("test_namespace", message, &with_namespace));
    try testing.expect(!public.verify("", message, &with_namespace));
    try testing.expect(!public.verify("test_namespace", message, &signature));

    const encoded = codec.encode_fixed(M.Signature, signature);
    const decoded = try decode(M.Signature, &encoded);
    try testing.expect(public.verify("", message, &decoded));

    // std's ECDSA verifier accepts the same signature over the framed payload.
    const payload = try utils.union_unique(testing.allocator, "", message);
    defer testing.allocator.free(payload);
    const std_key = try StdEcdsa.PublicKey.fromSec1(public.as_slice());
    const std_signature = StdEcdsa.Signature.fromBytes(encoded[offset..][0..64].*);
    try std_signature.verify(payload, std_key);
}

fn test_public_key_derivation(comptime M: type, bytes: []const u8) !void {
    const key = decode(M.PrivateKey, bytes) catch return;
    const std_secret = try StdEcdsa.SecretKey.fromBytes(bytes[0..32].*);
    const std_pair = try StdEcdsa.KeyPair.fromSecretKey(std_secret);
    const expected = std_pair.public_key.toCompressedSec1();
    try testing.expectEqualSlices(u8, &expected, key.public_key().as_slice());
}

/// One fuzz case for the scheme `M`, whose signatures carry `offset` prefix bytes.
fn fuzz_decode(comptime M: type, comptime offset: usize, bytes: []const u8) !void {
    var input = fuzz.Input.init(bytes);
    const selector = input.int_in_range(0, 9);
    var private_key: [32]u8 = undefined;
    input.fill(&private_key);
    var public_key: [33]u8 = undefined;
    input.fill(&public_key);
    var signature: [64 + offset]u8 = undefined;
    input.fill(&signature);
    const length = variable_lengths[input.int_in_range(0, variable_lengths.len - 1)];
    const variable = input.take(length);
    const message = input.bytes;
    switch (selector) {
        0 => try test_private_key(M, &private_key),
        1 => try test_public_key(M, &public_key),
        2 => try test_signature(M, offset, &signature),
        3 => try test_private_key(M, variable),
        4 => try test_public_key(M, variable),
        5 => try test_signature(M, offset, variable),
        6 => try test_public_key_derivation(M, variable),
        7 => try test_sign_verify(M, offset, &private_key, message),
        8 => try test_public_key(M, &public_key),
        else => try test_public_key(M, variable),
    }
}

fn fuzz_both(bytes: []const u8) !void {
    try fuzz_decode(standard, 0, bytes);
    try fuzz_decode(recoverable, 1, bytes);
}

test "secp256r1 fuzz decode (seeded)" {
    var random = fuzz.prng(0x5ec9256);
    var bytes: [512]u8 = undefined;
    for (0..fuzz.iterations(128)) |_| {
        random.random().bytes(&bytes);
        try fuzz_both(bytes[0..random.random().uintAtMost(usize, bytes.len)]);
    }
    // Valid keys and points: a random 32-byte string is a valid scalar, and half of all x
    // coordinates are on the curve, so steer some inputs to those cases.
    for (0..fuzz.iterations(32)) |index| {
        random.random().bytes(&bytes);
        bytes[0] = @intCast(index % 10);
        bytes[33] = 0x02 + @as(u8, @intCast(index % 2));
        try fuzz_both(&bytes);
    }
}

test "secp256r1 fuzz decode (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [512]u8 = undefined;
            const length = smith.slice(&bytes);
            try fuzz_both(bytes[0..length]);
        }
    }.run, .{});
}
