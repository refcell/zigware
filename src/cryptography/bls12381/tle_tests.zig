//! Tests for `tle.zig` (commonware `bls12381::tle` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const primitives = @import("primitives/root.zig");
const tle = @import("tle.zig");

const ops = primitives.ops;
const Scalar = primitives.group.Scalar;
const MinPk = primitives.MinPk;
const MinSig = primitives.MinSig;
const Block = tle.Block;
const gpa = testing.allocator;

fn target_bytes(target: u64) [8]u8 {
    var out: [8]u8 = undefined;
    std.mem.writeInt(u64, &out, target, .big);
    return out;
}

test "tle: an identity signature cannot decrypt" {
    inline for (.{ MinPk, MinSig }) |V| {
        const sigma: Block = @splat(1);
        const message: Block = @splat(2);
        const r = tle.h3(&sigma, &message);
        const identity = V.pairing(V.Public.zero, V.Signature.generator);
        const ciphertext: tle.Ciphertext(V) = .{
            .u = V.Public.generator.mul(r),
            .v = tle.xor(sigma, tle.h2(identity)),
            .w = tle.xor(message, tle.h4(&sigma)),
        };
        try testing.expect(tle.decrypt(V, V.Signature.zero, ciphertext) == null);
    }
}

test "tle: an identity public key cannot encrypt" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        const message: Block = @splat(0);
        try testing.expectError(
            error.InvalidPublicKey,
            tle.encrypt(V, &rng, V.Public.zero, "test", "target", &message),
        );
    }
}

fn round_trip(comptime V: type, target: u64, message: *const [32]u8) !void {
    var rng = utils.test_rng();
    const pair = ops.keypair(V, &rng);
    const t = target_bytes(target);
    const signature = ops.sign_message(V, pair.private, "_TLE_", &t);
    const ciphertext = try tle.encrypt(V, &rng, pair.public, "_TLE_", &t, message);
    const decrypted = tle.decrypt(V, signature, ciphertext).?;
    try testing.expectEqualSlices(u8, message, &decrypted);
}

test "tle: encrypt and decrypt" {
    try round_trip(MinPk, 10, "Hello, IBE! This is exactly 32b!");
    try round_trip(MinSig, 20, "Testing MinSig variant - 32 byte");
}

test "tle: a wrong key cannot decrypt" {
    var rng = utils.test_rng();
    const first = ops.keypair(MinPk, &rng);
    const second = ops.keypair(MinPk, &rng);
    const t = target_bytes(30);
    const message = "Secret message padded to 32bytes";
    const ciphertext = try tle.encrypt(MinPk, &rng, first.public, "_TLE_", &t, message);
    const wrong = ops.sign_message(MinPk, second.private, "_TLE_", &t);
    try testing.expect(tle.decrypt(MinPk, wrong, ciphertext) == null);
}

const Fixture = struct {
    signature: MinPk.Signature,
    ciphertext: tle.Ciphertext(MinPk),
    rng: utils.rng.TestRng,
};

fn encrypt_fixture(target: u64, message: *const [32]u8) !Fixture {
    var rng = utils.test_rng();
    const pair = ops.keypair(MinPk, &rng);
    const t = target_bytes(target);
    const signature = ops.sign_message(MinPk, pair.private, "_TLE_", &t);
    const ciphertext = try tle.encrypt(MinPk, &rng, pair.public, "_TLE_", &t, message);
    return .{ .signature = signature, .ciphertext = ciphertext, .rng = rng };
}

test "tle: tampering with W, V, or U is detected" {
    var fixture = try encrypt_fixture(40, "Tamper test padded to 32 bytes..");
    var tampered = fixture.ciphertext;
    tampered.w[0] ^= 0xFF;
    try testing.expect(tle.decrypt(MinPk, fixture.signature, tampered) == null);

    fixture = try encrypt_fixture(110, "Another CCA test message 32bytes");
    tampered = fixture.ciphertext;
    tampered.v[0] ^= 0x01;
    try testing.expect(tle.decrypt(MinPk, fixture.signature, tampered) == null);

    fixture = try encrypt_fixture(70, "CCA security test message 32 byt");
    tampered = fixture.ciphertext;
    tampered.u = tampered.u.mul(Scalar.random(&fixture.rng));
    try testing.expect(tle.decrypt(MinPk, fixture.signature, tampered) == null);
    try testing.expect(tle.decrypt(MinPk, fixture.signature, fixture.ciphertext) != null);
}

test "tle: namespaces separate targets" {
    var rng = utils.test_rng();
    const pair = ops.keypair(MinPk, &rng);
    const t = target_bytes(100);
    const message = "Namespace vs no namespace - 32by";
    const signature_1 = ops.sign_message(MinPk, pair.private, "example.org", &t);
    const signature_2 = ops.sign_message(MinPk, pair.private, "other.org", &t);
    const ciphertext_1 = try tle.encrypt(MinPk, &rng, pair.public, "example.org", &t, message);
    const ciphertext_2 = try tle.encrypt(MinPk, &rng, pair.public, "other.org", &t, message);
    try testing.expect(tle.decrypt(MinPk, signature_2, ciphertext_1) == null);
    try testing.expect(tle.decrypt(MinPk, signature_1, ciphertext_2) == null);
    try testing.expectEqualSlices(u8, message, &tle.decrypt(MinPk, signature_1, ciphertext_1).?);
    try testing.expectEqualSlices(u8, message, &tle.decrypt(MinPk, signature_2, ciphertext_2).?);
}

test "tle: ciphertext codec round trip" {
    const fixture = try encrypt_fixture(80, "Message with namespace - 32 byte");
    const bytes = try codec.encode(tle.Ciphertext(MinPk), gpa, fixture.ciphertext);
    defer gpa.free(bytes);
    try testing.expectEqual(tle.Ciphertext(MinPk).fixed_size, bytes.len);
    const decoded = try codec.decode(tle.Ciphertext(MinPk), gpa, bytes);
    try testing.expect(decoded.eql(fixture.ciphertext));
    const short = bytes[0 .. bytes.len - 1];
    try testing.expectError(error.EndOfBuffer, codec.decode(tle.Ciphertext(MinPk), gpa, short));
}

fn expect_vector(
    comptime V: type,
    target: u64,
    message: *const [32]u8,
    comptime expected_hex: []const u8,
) !void {
    var rng = utils.test_rng();
    const pair = ops.keypair(V, &rng);
    const t = target_bytes(target);
    const ciphertext = try tle.encrypt(V, &rng, pair.public, "_TLE_", &t, message);
    const bytes = try codec.encode(tle.Ciphertext(V), gpa, ciphertext);
    defer gpa.free(bytes);
    var expected: [expected_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, bytes);
}

test "tle: ciphertexts match commonware" {
    // commonware: `keypair` then `encrypt` with one `test_rng()`.
    try expect_vector(MinPk, 10, "Hello, IBE! This is exactly 32b!", "ac6b1f47f2f9489f181fef77" ++
        "2e0b3005618bc8a8cf07cb1f10e27af10fc83f55b9516e01e0ba6dbe2ef62286be65368f91085970" ++
        "645459058b4118dac31df4f47110163486a0862b2df4ba69e4b6d3f4deee6d4a5a0c5134db0beeec" ++
        "d93c10e15eaa123b1c144568c3c82154fc8ac3f8");
    try expect_vector(MinSig, 20, "Testing MinSig variant - 32 byte", "ae5dcce7bc9e0b11d0b65fbc" ++
        "e75d7abef1e66c4a5c5f6627b13131d10361b0d44af577bcee7ae37e1e5b18ef411d99a6101623167f" ++
        "95abb524d41b43d262424b6504c0f8b58c77a808c3e07043aaa05b5b04d110202f49cf97bbd48b2293" ++
        "3e0964953290f3ec86c4e8c46e5ec3a08f0b1b8c7685dc4c573f6af345c401ae173bc2ee72525c4e16" ++
        "5dd427a19fe43359e41fb1087a1718042697976a54adc1d5bc");
}
