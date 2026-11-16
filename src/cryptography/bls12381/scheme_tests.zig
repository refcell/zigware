//! Tests of the BLS12-381 `Signer` and `Verifier` keys (commonware `bls12381::scheme::tests`),
//! including their `CodecConformance` hashes.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const formatting = @import("formatting");
const utils = @import("utils");
const parallel = @import("parallel");
const signer = @import("../signer.zig");
const primitives = @import("primitives/root.zig");
const scheme = @import("scheme.zig");
const shared = @import("conformance_test.zig");

const arbitrary = codec.arbitrary;
const Unstructured = arbitrary.Unstructured;
const PrivateKey = scheme.PrivateKey;
const PublicKey = scheme.PublicKey;
const Signature = scheme.Signature;

fn expect_roundtrip(comptime T: type, bytes: []const u8) !void {
    const value = try codec.decode(T, testing.allocator, bytes);
    const encoded = try codec.encode(T, testing.allocator, value);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(codec.fixed_size(T).?, encoded.len);
    try testing.expectEqualSlices(u8, bytes, encoded);
    const decoded = try codec.decode(T, testing.allocator, encoded);
    try testing.expect(decoded.eql(value));
}

test "bls12381 scheme: codec private key" {
    const bytes = formatting.hex_literal(
        "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
    );
    const original = try codec.decode(PrivateKey, testing.allocator, &bytes);
    const encoded = try codec.encode(PrivateKey, testing.allocator, original);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(PrivateKey.fixed_size, encoded.len);
    const decoded = try codec.decode(PrivateKey, testing.allocator, encoded);
    try testing.expect(original.eql(&decoded));
}

test "bls12381 scheme: codec public key" {
    const bytes = formatting.hex_literal("0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f" ++
        "368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a");
    try expect_roundtrip(PublicKey, &bytes);
}

test "bls12381 scheme: codec signature" {
    const bytes = formatting.hex_literal("0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b90" ++
        "0a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e" ++
        "7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb");
    try expect_roundtrip(Signature, &bytes);
}

test "bls12381 scheme: from private" {
    var rng = utils.test_rng();
    const private_key = PrivateKey.from_private(primitives.group.Private.random(&rng));
    const signature = private_key.sign("ns", "test message");
    try testing.expect(private_key.public_key().verify("ns", "test message", &signature));
    try testing.expect(!private_key.public_key().verify("other", "test message", &signature));
}

test "bls12381 scheme: private key redacted" {
    var rng = utils.test_rng();
    const private_key = PrivateKey.random(&rng);
    var buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{private_key});
    try testing.expect(std.mem.indexOf(u8, text, "REDACTED") != null);
}

test "bls12381 scheme: batch verify empty" {
    var rng = utils.test_rng();
    const entries: []const PublicKey.Entry = &.{};
    try testing.expect(!PublicKey.verify_batch(&rng, entries, signer.entries, parallel.sequential));
}

test "bls12381 scheme: batch verify invalid message" {
    var rng = utils.test_rng();
    const private_key = PrivateKey.random(&rng);
    const public_key = private_key.public_key();
    const signature = private_key.sign("ns", "message");
    var entries = [_]PublicKey.Entry{.{
        .namespace = "ns",
        .message = "message",
        .public_key = &public_key,
        .signature = &signature,
    }};
    const sequential = parallel.sequential;
    try testing.expect(PublicKey.verify_batch(&rng, &entries, signer.entries, sequential));
    // Changing the message must invalidate the signature.
    entries[0].message = "invalid";
    try testing.expect(!PublicKey.verify_batch(&rng, &entries, signer.entries, sequential));
}

/// Nine unit items whose namespace, message, signer, and signature are found by index.
const Batch = struct {
    namespaces: [9][]const u8,
    messages: [9][]const u8,
    signers: [9]usize,
    public_keys: [3]PublicKey,
    signatures: [9]Signature,

    pub fn project(self: *const Batch, index: usize, _: *const void) PublicKey.Entry {
        return .{
            .namespace = self.namespaces[index],
            .message = self.messages[index],
            .public_key = &self.public_keys[self.signers[index]],
            .signature = &self.signatures[index],
        };
    }

    fn verify(self: *const Batch) bool {
        var rng = utils.test_rng();
        const items: [9]void = @splat({});
        return PublicKey.verify_batch(&rng, &items, self, parallel.sequential);
    }
};

test "bls12381 scheme: projected batch indexes zero-sized items" {
    var rng = utils.test_rng();
    var keys: [3]PrivateKey = undefined;
    for (&keys) |*key| key.* = PrivateKey.random(&rng);
    var storage: [9][63]u8 = undefined;
    var batch: Batch = undefined;
    for (0..9) |i| {
        const names = [_][]const u8{ "", "alpha", "beta" };
        @memset(&storage[i], @intCast(i));
        batch.namespaces[i] = names[(i / 3) % 3];
        batch.messages[i] = storage[i][0 .. i * 7];
        batch.signers[i] = i % keys.len;
        batch.signatures[i] = keys[i % keys.len].sign(batch.namespaces[i], batch.messages[i]);
    }
    for (&batch.public_keys, keys) |*public_key, key| public_key.* = key.public_key();
    try testing.expect(batch.verify());
    // Changing the message, namespace, or signer at any index fails the whole batch.
    for (0..9) |i| {
        const message = batch.messages[i];
        batch.messages[i] = storage[i][0 .. i * 7 + 1];
        storage[i][i * 7] = 0;
        try testing.expect(!batch.verify());
        batch.messages[i] = message;
        const namespace = batch.namespaces[i];
        batch.namespaces[i] = "other";
        try testing.expect(!batch.verify());
        batch.namespaces[i] = namespace;
        const signer_index = batch.signers[i];
        batch.signers[i] = (signer_index + 1) % keys.len;
        try testing.expect(!batch.verify());
        batch.signers[i] = signer_index;
    }
    try testing.expect(batch.verify());
}

/// `PrivateKey::random(StdRng::from_seed(u.arbitrary::<[u8; 32]>()))`.
fn gen_private_key(gpa: Allocator, u: *Unstructured) arbitrary.Error!PrivateKey {
    var rng = utils.rng.TestRng.init_key(try arbitrary.value([32]u8, gpa, u));
    return PrivateKey.random(&rng);
}

fn gen_public_key(gpa: Allocator, u: *Unstructured) arbitrary.Error!PublicKey {
    const private_key = try gen_private_key(gpa, u);
    return private_key.public_key();
}

/// A random key signs up to 255 arbitrary bytes under the test namespace.
fn gen_signature(gpa: Allocator, u: *Unstructured) arbitrary.Error!Signature {
    const private_key = try gen_private_key(gpa, u);
    const len = try arbitrary.value(usize, gpa, u) % 256;
    // `arbitrary_iter().take(len)`: a continuation byte before each element.
    var message: std.ArrayList(u8) = .empty;
    while (message.items.len < len and u.keep_going()) try message.append(gpa, u.int(u8));
    assert(message.items.len <= len);
    return private_key.sign("_COMMONWARE_CRYPTOGRAPHY_BLS12381_TEST", message.items);
}

test "conformance: bls12381 scheme keys and signatures" {
    try shared.skip_slow();
    const name = "scheme::tests::conformance::CodecConformance<";
    try shared.verify(name ++ "PrivateKey>", PrivateKey, gen_private_key);
    try shared.verify(name ++ "PublicKey>", PublicKey, gen_public_key);
    try shared.verify(name ++ "Signature>", Signature, gen_signature);
}
