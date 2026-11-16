//! commonware-cryptography-curve25519's vector tests (`src/test.rs`, module `tests`), run against
//! zigware's Ed25519 (`cryptography.ed25519`) and X25519 (`key_exchange`).

const std = @import("std");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const vectors = @import("vectors.zig");
const signing = @import("signing.zig");
const key_exchange = @import("key_exchange.zig");
const testing = std.testing;
const sequential = parallel.sequential;

fn bytes(comptime N: usize, hex: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&out, hex) catch unreachable; // Fixture hex is valid.
    std.debug.assert(decoded.len == N);
    return out;
}

/// Decodes a variable-length hex field into `buffer`.
fn slice(buffer: []u8, hex: []const u8) []u8 {
    return std.fmt.hexToBytes(buffer, hex) catch unreachable; // Fixture hex is valid.
}

fn verify_single(
    key: signing.VerifyingKey,
    message: []const u8,
    signature: signing.Signature,
) !bool {
    var rng = utils.test_rng();
    const items = [_]signing.VerifyingKey.RawEntry{
        .{ .key = &key, .signature = &signature, .message = message },
    };
    const batch = signing.VerifyingKey.verify_batch_raw(&rng, &items, sequential);
    const single = key.verify_raw(message, &signature);
    try testing.expectEqual(single, batch);
    return single;
}

test "curve25519: RFC 8032 Ed25519 vectors" {
    var buffer: [1024]u8 = undefined;
    for (vectors.rfc8032_ed25519) |vector| {
        const signing_key = signing.SigningKey.from_seed(bytes(32, vector.secret_key));
        const public_key = bytes(32, vector.public_key);
        const expected = bytes(64, vector.signature);
        const message = slice(&buffer, vector.message);
        try testing.expectEqualSlices(u8, &public_key, &signing_key.verifying_key().bytes);
        try testing.expectEqualSlices(u8, &expected, &signing_key.sign_raw(message).bytes);
        const signature: signing.Signature = .{ .bytes = expected };
        try testing.expect(signing_key.verifying_key().verify_raw(message, &signature));
        const key = signing.VerifyingKey.from_bytes(public_key);
        try testing.expect(try verify_single(key, message, signature));
    }
}

test "curve25519: Wycheproof Ed25519 vectors match ZIP-215" {
    var buffer: [1024]u8 = undefined;
    var signature_buffer: [128]u8 = undefined;
    for (vectors.wycheproof_ed25519) |vector| {
        const key = signing.VerifyingKey.from_bytes(bytes(32, vector.public_key));
        const message = slice(&buffer, vector.message);
        const raw = slice(&signature_buffer, vector.signature);
        // A signature that is not 64 bytes does not decode.
        const valid = raw.len == 64 and try verify_single(key, message, .{ .bytes = raw[0..64].* });
        testing.expectEqual(vector.valid_zip215, valid) catch |err| {
            std.debug.print("Wycheproof Ed25519 test {d}\n", .{vector.tc_id});
            return err;
        };
    }
}

test "curve25519: RFC 7748 X25519 vectors" {
    for (vectors.rfc7748_x25519) |vector| {
        const secret = key_exchange.SecretKey.from_raw(bytes(32, vector.scalar));
        const shared = secret.exchange(.{ .bytes = bytes(32, vector.u_coordinate) }).?;
        try testing.expectEqualSlices(u8, &bytes(32, vector.output), &shared.bytes);
    }
    const vector = vectors.rfc7748_x25519_diffie_hellman;
    const alice = key_exchange.SecretKey.from_raw(bytes(32, vector.alice_secret));
    const bob = key_exchange.SecretKey.from_raw(bytes(32, vector.bob_secret));
    try testing.expectEqualSlices(u8, &bytes(32, vector.alice_public), &alice.public_key().bytes);
    try testing.expectEqualSlices(u8, &bytes(32, vector.bob_public), &bob.public_key().bytes);
    const expected = bytes(32, vector.shared_secret);
    try testing.expectEqualSlices(u8, &expected, &alice.exchange(bob.public_key()).?.bytes);
    try testing.expectEqualSlices(u8, &expected, &bob.exchange(alice.public_key()).?.bytes);
}

test "curve25519: Wycheproof X25519 vectors" {
    for (vectors.wycheproof_x25519) |vector| {
        const secret = key_exchange.SecretKey.from_raw(bytes(32, vector.private_key));
        const shared = secret.exchange(.{ .bytes = bytes(32, vector.public_key) });
        const expected: ?[32]u8 = if (vector.shared_secret) |hex| bytes(32, hex) else null;
        const actual: ?[32]u8 = if (shared) |value| value.bytes else null;
        testing.expectEqual(expected, actual) catch |err| {
            std.debug.print("Wycheproof X25519 test {d}\n", .{vector.tc_id});
            return err;
        };
    }
}

test "curve25519: ZIP-215 vectors verify singly and in every batch" {
    const namespace = "_COMMONWARE_CRYPTOGRAPHY_CURVE25519_ZIP215_VECTORS";
    const message = "Zcash";
    var keys: [196]signing.VerifyingKey = undefined;
    var signatures: [196]signing.Signature = undefined;
    var count: usize = 0;
    // Every pairing of the eight canonical low-order encodings and their six non-canonical
    // aliases; with s = 0 each satisfies the cofactored equation for every message.
    for (vectors.zip215_points) |a_hex| {
        for (vectors.zip215_points) |r_hex| {
            keys[count] = signing.VerifyingKey.from_bytes(bytes(32, a_hex));
            signatures[count] = .{ .bytes = bytes(32, r_hex) ++ @as([32]u8, @splat(0)) };
            try testing.expect(keys[count].verify(namespace, message, &signatures[count]));
            count += 1;
            var rng = utils.test_rng();
            const last = count - 1;
            const one = [_]signing.VerifyingKey.Entry{.{
                .public_key = &keys[last],
                .signature = &signatures[last],
                .namespace = namespace,
                .message = message,
            }};
            const entries = cryptography.entries;
            try testing.expect(signing.VerifyingKey.verify_batch(&rng, &one, entries, sequential));
        }
    }
    var items: [196]signing.VerifyingKey.Entry = undefined;
    for (&items, &keys, &signatures) |*item, *key, *signature| {
        item.* = .{
            .public_key = key,
            .signature = signature,
            .namespace = namespace,
            .message = message,
        };
    }
    var rng = utils.test_rng();
    const entries = cryptography.entries;
    try testing.expect(signing.VerifyingKey.verify_batch(&rng, &items, entries, sequential));
}
