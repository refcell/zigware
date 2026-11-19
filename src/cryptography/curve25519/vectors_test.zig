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

test "curve25519: RFC 7748 iterated X25519" {
    var k: [32]u8 = @splat(0);
    k[0] = 9;
    var u = k;
    for (1..1001) |i| {
        const next = key_exchange.SecretKey.from_raw(k).exchange(.{ .bytes = u }).?.bytes;
        u = k;
        k = next;
        if (i == 1) {
            const after_one = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079";
            try testing.expectEqualSlices(u8, &bytes(32, after_one), &k);
        }
    }
    const after_thousand = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51";
    try testing.expectEqualSlices(u8, &bytes(32, after_thousand), &k);
}

test "curve25519: ZIP-215 full batch verifies under every strategy shape" {
    const namespace = "_COMMONWARE_CRYPTOGRAPHY_CURVE25519_ZIP215_VECTORS";
    const count = vectors.zip215_points.len * vectors.zip215_points.len;
    var keys: [count]signing.VerifyingKey = undefined;
    var signatures: [count]signing.Signature = undefined;
    var items: [count]signing.VerifyingKey.Entry = undefined;
    var index: usize = 0;
    for (vectors.zip215_points) |a_hex| {
        for (vectors.zip215_points) |r_hex| {
            keys[index] = signing.VerifyingKey.from_bytes(bytes(32, a_hex));
            signatures[index] = .{ .bytes = bytes(32, r_hex) ++ @as([32]u8, @splat(0)) };
            items[index] = .{
                .public_key = &keys[index],
                .signature = &signatures[index],
                .namespace = namespace,
                .message = "Zcash",
            };
            index += 1;
        }
    }
    // Shards below 44 signatures take Straus, larger ones the buckets.
    const Op = struct {
        items: []const signing.VerifyingKey.Entry,
        pub fn run(op: @This(), explorer: parallel.mocks.Explorer) bool {
            var rng = utils.test_rng();
            const entries = cryptography.entries;
            return signing.VerifyingKey.verify_batch(&rng, op.items, entries, explorer);
        }
    };
    const op: Op = .{ .items = &items };
    try testing.expect(try parallel.mocks.explore(testing.allocator, testing.io, op));
}
