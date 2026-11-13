//! secp256r1 tests (commonware `secp256r1/{common,standard,recoverable}.rs` tests). Tests
//! the two schemes share run for both; `offset` is where `r || s` starts in a signature.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const common = @import("common.zig");
const standard = @import("standard.zig");
const recoverable = @import("recoverable.zig");
const vectors = @import("vectors.zig");
const P256 = std.crypto.ecc.P256;
const Scalar = P256.scalar.Scalar;

const namespace = "test-namespace";
const schemes = .{
    .{ .module = standard, .offset = 0 },
    .{ .module = recoverable, .offset = 1 },
};

/// The key from commonware's `create_private_key`.
const test_key = "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464";
const rfc6979_key = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const scheme_sign_message = "5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf" ++
    "416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b5" ++
    "3cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9" ++
    "b0d0debd97d79ce8";

fn hex_alloc(hex: []const u8) ![]u8 {
    const bytes = try testing.allocator.alloc(u8, hex.len / 2);
    errdefer testing.allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);
    return bytes;
}

fn hex_array(comptime len: usize, hex: []const u8) ![len]u8 {
    var bytes: [len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex);
    return bytes;
}

fn private_key(comptime M: type, hex: []const u8) !M.PrivateKey {
    return try codec.decode(M.PrivateKey, testing.allocator, &try hex_array(32, hex));
}

/// `parse_public_key_as_compressed_vector`: odd-length hex is left-padded with a zero.
fn compressed_vector(qx: []const u8, qy: []const u8) ![]u8 {
    var padded: [80]u8 = undefined;
    const x_hex = if (qx.len % 2 == 1) try std.fmt.bufPrint(&padded, "0{s}", .{qx}) else qx;
    const y = try hex_alloc(qy);
    defer testing.allocator.free(y);
    const out = try testing.allocator.alloc(u8, 1 + x_hex.len / 2);
    errdefer testing.allocator.free(out);
    out[0] = if (y[y.len - 1] % 2 == 0) 0x02 else 0x03;
    _ = try std.fmt.hexToBytes(out[1..], x_hex);
    return out;
}

fn public_key(comptime M: type, qx: []const u8, qy: []const u8) !M.PublicKey {
    const bytes = try compressed_vector(qx, qy);
    defer testing.allocator.free(bytes);
    return try codec.decode(M.PublicKey, testing.allocator, bytes);
}

/// `normalize_s`: `r || (n - s)` when `s` is high.
fn normalize(raw: [64]u8) [64]u8 {
    if (!common.is_high(raw[32..64].*)) return raw;
    const s = Scalar.fromBytes(raw[32..64].*, .big) catch unreachable;
    return raw[0..32].* ++ s.neg().toBytes(.big);
}

fn decode_fails(comptime T: type, bytes: []const u8) !void {
    try testing.expect(std.meta.isError(codec.decode(T, testing.allocator, bytes)));
}

test "secp256r1 private key is redacted" {
    var buffer: [64]u8 = undefined;
    inline for (schemes) |scheme| {
        const key = try private_key(scheme.module, test_key);
        const text = try std.fmt.bufPrint(&buffer, "{f}", .{key});
        try testing.expect(std.mem.indexOf(u8, text, "REDACTED") != null);
    }
}

test "secp256r1 codec round trips" {
    inline for (schemes) |scheme| {
        const M = scheme.module;
        const key = try private_key(M, test_key);
        const encoded_key = codec.encode_fixed(M.PrivateKey, key);
        try testing.expectEqual(common.private_key_length, encoded_key.len);
        const decoded_key = try codec.decode(M.PrivateKey, testing.allocator, &encoded_key);
        try testing.expect(decoded_key.eql(&key));

        const public = key.public_key();
        const encoded_public = codec.encode_fixed(M.PublicKey, public);
        try testing.expectEqual(common.public_key_length, encoded_public.len);
        const decoded_public = try codec.decode(M.PublicKey, testing.allocator, &encoded_public);
        try testing.expect(decoded_public.eql(public));

        const signature = key.sign(namespace, "Hello World");
        const encoded = codec.encode_fixed(M.Signature, signature);
        try testing.expectEqual(64 + scheme.offset, encoded.len);
        const decoded = try codec.decode(M.Signature, testing.allocator, &encoded);
        try testing.expect(decoded.eql(signature));
    }
}

test "secp256r1 scheme sign" {
    const message = try hex_alloc(scheme_sign_message);
    defer testing.allocator.free(message);
    inline for (schemes) |scheme| {
        const key = try private_key(scheme.module, test_key);
        const signature = key.sign(namespace, message);
        try testing.expectEqual(64 + scheme.offset, signature.as_slice().len);
        try testing.expect(key.public_key().verify(namespace, message, &signature));
        try testing.expect(!key.public_key().verify("other", message, &signature));
    }
}

test "secp256r1 decode rejects zero, high-s, zero-r, zero-s signatures" {
    inline for (schemes) |scheme| {
        const M = scheme.module;
        const offset = scheme.offset;
        try decode_fails(M.Signature, &@as([64 + offset]u8, @splat(0)));

        const key = try private_key(M, vectors.keypairs[0].private_key);
        const signature = codec.encode_fixed(M.Signature, key.sign(namespace, "edge"));
        var bad = signature;
        bad[offset + 32] |= 0x80;
        try decode_fails(M.Signature, &bad);

        bad = signature;
        @memset(bad[offset..][0..32], 0);
        bad[offset + 32] = 1;
        try decode_fails(M.Signature, &bad);

        bad = codec.encode_fixed(M.Signature, key.sign_raw("sample"));
        @memset(bad[offset..][0..32], 0);
        try decode_fails(M.Signature, &bad);
        bad = codec.encode_fixed(M.Signature, key.sign_raw("sample"));
        @memset(bad[offset + 32 ..], 0);
        try decode_fails(M.Signature, &bad);
    }
    var bad_recovery_id = codec.encode_fixed(
        recoverable.Signature,
        (try private_key(recoverable, test_key)).sign(namespace, "edge"),
    );
    bad_recovery_id[0] = 4;
    try decode_fails(recoverable.Signature, &bad_recovery_id);
}

test "secp256r1 rfc6979" {
    const expected_sample = try hex_array(
        64,
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" ++
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    );
    const expected_test = try hex_array(
        64,
        "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" ++
            "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
    );
    inline for (schemes) |scheme| {
        const key = try private_key(scheme.module, rfc6979_key);
        const sample = key.sign_raw("sample");
        try testing.expectEqualSlices(
            u8,
            &normalize(expected_sample),
            sample.as_slice()[scheme.offset..],
        );
        const signature = key.sign_raw("test");
        try testing.expectEqualSlices(u8, &expected_test, signature.as_slice()[scheme.offset..]);
    }
}

test "secp256r1 public key length is enforced" {
    const coordinate = "d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f";
    const uncompressed = try hex_array(65, "04" ++ coordinate ++ coordinate);
    inline for (schemes) |scheme| {
        const M = scheme.module;
        try testing.expectError(
            error.Invalid,
            codec.decode(M.PublicKey, testing.allocator, &uncompressed),
        );
        const compressed = try compressed_vector(coordinate, coordinate);
        defer testing.allocator.free(compressed);
        _ = try codec.decode(M.PublicKey, testing.allocator, compressed);
        const too_long = try std.mem.concat(testing.allocator, u8, &.{ compressed, &.{0} });
        defer testing.allocator.free(too_long);
        try testing.expectError(
            error.ExtraData,
            codec.decode(M.PublicKey, testing.allocator, too_long),
        );
    }
}

test "secp256r1 keypair vectors" {
    inline for (schemes) |scheme| {
        for (vectors.keypairs) |vector| {
            const key = try private_key(scheme.module, vector.private_key);
            const expected = try public_key(scheme.module, vector.qx, vector.qy);
            try testing.expect(key.public_key().eql(expected));
        }
    }
}

test "secp256r1 public key validation vectors" {
    inline for (schemes) |scheme| {
        for (vectors.public_key_validations) |vector| {
            const bytes = try compressed_vector(vector.qx, vector.qy);
            defer testing.allocator.free(bytes);
            const result = codec.decode(scheme.module.PublicKey, testing.allocator, bytes);
            try testing.expectEqual(vector.valid, !std.meta.isError(result));
        }
    }
}

const SignatureVector = struct {
    public_key: [common.public_key_length]u8,
    rs: [64]u8,
    message: []u8,
    valid: bool,

    fn init(vector: vectors.SignatureVerification) !SignatureVector {
        const public = try public_key(standard, vector.qx, vector.qy);
        return .{
            .public_key = public.inner.raw,
            .rs = (try hex_array(32, vector.r)) ++ (try hex_array(32, vector.s)),
            .message = try hex_alloc(vector.message),
            .valid = vector.valid,
        };
    }

    fn deinit(self: *SignatureVector) void {
        testing.allocator.free(self.message);
    }
};

test "secp256r1 standard signature verification vectors" {
    for (vectors.signature_verifications) |raw_vector| {
        var vector = try SignatureVector.init(raw_vector);
        defer vector.deinit();
        const public = standard.PublicKey.from_bytes(vector.public_key).?;
        if (vector.valid) {
            if (common.is_high(vector.rs[32..64].*)) {
                try decode_fails(standard.Signature, &vector.rs);
            }
            const normalized = normalize(vector.rs);
            const signature = try codec.decode(standard.Signature, testing.allocator, &normalized);
            try testing.expect(public.verify_raw(vector.message, &signature));
        } else if (codec.decode(standard.Signature, testing.allocator, &vector.rs)) |signature| {
            try testing.expect(!public.verify_raw(vector.message, &signature));
        } else |_| {}
    }
}

/// `RecoveryId::trial_recovery_from_msg`: the id that recovers `public`, if any. Takes `s`
/// as is, even when high.
fn trial_recovery(
    public: *const common.PublicKeyInner,
    message: []const u8,
    rs: [64]u8,
) ?common.RecoveryId {
    const scalars: common.Scalars = .{
        .r = Scalar.fromBytes(rs[0..32].*, .big) catch return null,
        .s = Scalar.fromBytes(rs[32..64].*, .big) catch return null,
    };
    const hash = common.payload_hash(null, message);
    for (0..4) |id| {
        const recovered = common.recover(hash, scalars, @intCast(id)) orelse continue;
        if (recovered.eql(public)) return @intCast(id);
    }
    return null;
}

test "secp256r1 recoverable signature verification vectors" {
    for (vectors.signature_verifications) |raw_vector| {
        var vector = try SignatureVector.init(raw_vector);
        defer vector.deinit();
        const public = recoverable.PublicKey.from_bytes(vector.public_key).?;
        const id = trial_recovery(&public.inner, vector.message, vector.rs) orelse 0;
        const encoded = [1]u8{id} ++ vector.rs;
        if (vector.valid) {
            if (common.is_high(vector.rs[32..64].*)) {
                try decode_fails(recoverable.Signature, &encoded);
            }
            const normalized = normalize(vector.rs);
            const recovery_id = trial_recovery(&public.inner, vector.message, normalized).?;
            const signature = recoverable.Signature.init(recovery_id, normalized);
            try testing.expect(public.verify_raw(vector.message, &signature));
        } else if (codec.decode(recoverable.Signature, testing.allocator, &encoded)) |signature| {
            try testing.expect(!public.verify_raw(vector.message, &signature));
        } else |_| {}
    }
}

test "secp256r1 codec rejects the high-s vector signature" {
    var vector = try SignatureVector.init(vectors.signature_verifications[4]);
    defer vector.deinit();
    try testing.expect(common.is_high(vector.rs[32..64].*));
    try decode_fails(standard.Signature, &vector.rs);
    const public = recoverable.PublicKey.from_bytes(vector.public_key).?;
    const id = trial_recovery(&public.inner, vector.message, vector.rs) orelse 0;
    try decode_fails(recoverable.Signature, &([1]u8{id} ++ vector.rs));
}

test "secp256r1 recover signer" {
    const key = try private_key(recoverable, test_key);
    const expected = key.public_key();

    const signature = key.sign(namespace, "recover with namespace");
    const recovered = signature.recover_signer(namespace, "recover with namespace").?;
    try testing.expect(recovered.eql(expected));

    // A different message recovers some other key (or none).
    if (signature.recover_signer(namespace, "different message")) |other| {
        try testing.expect(!other.eql(expected));
    }

    // Flipping the y parity must not recover the signer, so verification fails.
    var flipped = key.sign(namespace, "recover with no namespace");
    flipped.raw[0] ^= 1;
    if (flipped.recover_signer(namespace, "recover with no namespace")) |other| {
        try testing.expect(!other.eql(expected));
    }
    try testing.expect(!expected.verify(namespace, "recover with no namespace", &flipped));
}
