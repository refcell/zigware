//! Ports of commonware's BLS12-381 fuzz targets (`cryptography/fuzz/fuzz_targets/bls12381_*`)
//! as deterministic minifuzz tests plus coverage-guided `std.testing.fuzz` hooks.
//!
//! `bls12381_decode` compares against blst in commonware; with no reference library here it
//! checks that every accepted encoding round-trips byte for byte and that the key and
//! signature decoders agree with the group decoders they wrap.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const math = @import("math");
const invariants = @import("invariants");
const build_options = @import("build_options");
const primitives = @import("primitives/root.zig");
const scheme = @import("scheme.zig");
const builtin = @import("builtin");
const utils = @import("utils");
const parallel = @import("parallel");

const minifuzz = invariants.minifuzz;
const Unstructured = minifuzz.Unstructured;
const MinPk = primitives.MinPk;
const Allocator = std.mem.Allocator;

/// Search limits for the slower targets: small in Debug, larger in release builds.
fn search_limit(debug: u64, release: u64) u64 {
    const base = if (builtin.mode == .debug) debug else release;
    return base * build_options.fuzz_soak;
}

/// commonware `common::arbitrary_bytes`: a length in `min..=max`, then that many bytes.
fn arbitrary_bytes(u: *Unstructured, min: usize, max: usize) ![]const u8 {
    return u.bytes(u.int_in_range(usize, min, max));
}

/// Decodes `data` as `T` and, on success, checks that it encodes back to `data` and that
/// the wrapped point `G` decodes the same bytes.
fn check_decode(comptime T: type, comptime G: type, data: []const u8) !void {
    const gpa = testing.allocator;
    const decoded = codec.decode(T, gpa, data);
    const point = codec.decode(G, gpa, data);
    try testing.expectEqual(std.meta.isError(point), std.meta.isError(decoded));
    const value = decoded catch return;
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, data, encoded);
}

/// commonware's `bls12381_decode` input: fixed-size key and signature bytes, variable data
/// of a chosen length, and a case selector.
fn decode_body(_: void, u: *Unstructured) !void {
    const pubkey_48 = try u.arbitrary([48]u8);
    const signature_96 = try u.arbitrary([96]u8);
    const lengths = [_]usize{ 0, 47, 48, 49, 95, 96, 97, 128, 256, 1024 };
    const variable_data = try u.bytes(try u.choose(usize, &lengths));
    const case_selector = try u.arbitrary(u8);
    switch (case_selector % 6) {
        0 => try check_decode(scheme.PublicKey, MinPk.Public, &pubkey_48),
        1 => try check_decode(scheme.Signature, MinPk.Signature, &signature_96),
        2, 4 => try check_decode(scheme.PublicKey, MinPk.Public, variable_data),
        3, 5 => try check_decode(scheme.Signature, MinPk.Signature, variable_data),
        else => unreachable,
    }
}

test "bls12381 fuzz: decode" {
    try (minifuzz.Builder{}).with_search_limit(256 * build_options.fuzz_soak)
        .run(testing.allocator, {}, decode_body);
}

test "bls12381 fuzz: decode (coverage-guided)" {
    try testing.fuzz({}, math.testing.smith_body(void, decode_body), .{});
}

test "bls12381 fuzz: decode accepts generator encodings" {
    const public = MinPk.Public.generator.to_bytes();
    try check_decode(scheme.PublicKey, MinPk.Public, &public);
    const signature = MinPk.Signature.generator.to_bytes();
    try check_decode(scheme.Signature, MinPk.Signature, &signature);
    const decoded = codec.decode(scheme.PublicKey, testing.allocator, &public);
    try testing.expect(!std.meta.isError(decoded));
}

/// One `bls12381_batch_operations` entry: a namespace, a message, a key, and a signature.
const BatchItem = struct {
    namespace: []const u8,
    message: []const u8,
    public_key: scheme.PublicKey,
    signature: scheme.Signature,
};

/// Views a `BatchItem` as a batch entry.
const BatchProjector = struct {
    pub fn project(_: BatchProjector, _: usize, item: *const BatchItem) scheme.PublicKey.Entry {
        return .{
            .namespace = item.namespace,
            .message = item.message,
            .public_key = &item.public_key,
            .signature = &item.signature,
        };
    }
};

/// Draws one `FuzzOperation` and appends its entry; whether the batch can stay valid.
fn batch_operation(gpa: Allocator, u: *Unstructured, batch: *std.ArrayList(BatchItem)) !?bool {
    const valid = try u.arbitrary(bool);
    const seed = try u.arbitrary(u64);
    const wrong_seed = if (valid) seed else try u.arbitrary(u64);
    const namespace = try arbitrary_bytes(u, 0, 50);
    const message = try arbitrary_bytes(u, 0, 100);
    const private_key = scheme.PrivateKey.from_seed(seed);
    const signature = private_key.sign(namespace, message);
    if (!valid and seed == wrong_seed) return null;
    const public_key = scheme.PrivateKey.from_seed(wrong_seed).public_key();
    try testing.expectEqual(valid, public_key.verify(namespace, message, &signature));
    try batch.append(gpa, .{
        .namespace = namespace,
        .message = message,
        .public_key = public_key,
        .signature = signature,
    });
    return valid;
}

fn batch_body(_: void, u: *Unstructured) !void {
    const gpa = testing.allocator;
    var rng = utils.rng.TestRng.init(u.arbitrary(u64) catch 0);
    const num_ops = u.int_in_range(u32, 1, 32);
    var batch: std.ArrayList(BatchItem) = .empty;
    defer batch.deinit(gpa);
    var expected: ?bool = null;
    for (0..num_ops) |_| {
        const valid = batch_operation(gpa, u, &batch) catch |err| switch (err) {
            error.NotEnoughData, error.IncorrectFormat, error.EmptyChoose => break,
            else => return err,
        } orelse continue;
        expected = (expected orelse true) and valid;
    }
    const projector: BatchProjector = .{};
    const result = scheme.PublicKey.verify_batch(&rng, batch.items, projector, parallel.sequential);
    try testing.expectEqual(expected orelse false, result);
}

test "bls12381 fuzz: batch operations" {
    try (minifuzz.Builder{}).with_search_limit(search_limit(2, 32))
        .run(testing.allocator, {}, batch_body);
}

test "bls12381 fuzz: batch operations (coverage-guided)" {
    try testing.fuzz({}, math.testing.smith_body(void, batch_body), .{});
}

const aggregate = primitives.ops.aggregate;
const MinSig = primitives.MinSig;

/// commonware `common::arbitrary_g1`/`arbitrary_g2`: an encoding, else zero or the generator.
fn arbitrary_point(comptime G: type, u: *Unstructured) !G {
    const bytes = try u.arbitrary([G.fixed_size]u8);
    var reader = codec.Reader.init(&bytes);
    return G.read(testing.allocator, &reader, {}) catch
        if (try u.arbitrary(bool)) G.zero else G.generator;
}

fn arbitrary_points(comptime G: type, gpa: Allocator, u: *Unstructured, max: usize) ![]G {
    const points = try gpa.alloc(G, u.int_in_range(usize, 0, max));
    errdefer gpa.free(points);
    for (points) |*point| point.* = try arbitrary_point(G, u);
    return points;
}

/// commonware `common::arbitrary_messages`.
fn arbitrary_messages(
    gpa: Allocator,
    u: *Unstructured,
    min: usize,
    max: usize,
) ![]aggregate.NamespacedMessage {
    const messages = try gpa.alloc(aggregate.NamespacedMessage, u.int_in_range(usize, min, max));
    errdefer gpa.free(messages);
    for (messages) |*item| {
        const namespace = try arbitrary_bytes(u, 0, 50);
        item.* = .{ .namespace = namespace, .message = try arbitrary_bytes(u, 0, 100) };
    }
    return messages;
}

const AggregateKind = enum { combine_public_keys, combine_signatures, same_message, same_signer };

/// One `bls12381_aggregate_operations` operation in variant `V`. Like commonware's target it
/// checks only that the operations run; results are discarded.
fn aggregate_operation(comptime V: type, kind: AggregateKind, u: *Unstructured) !void {
    const gpa = testing.allocator;
    switch (kind) {
        .combine_public_keys, .same_message => {
            const public_keys = try arbitrary_points(V.Public, gpa, u, 20);
            defer gpa.free(public_keys);
            if (kind == .combine_public_keys) {
                if (public_keys.len > 0) _ = aggregate.combine_public_keys(V, public_keys);
                return;
            }
            const namespace = try arbitrary_bytes(u, 0, 50);
            const message = try arbitrary_bytes(u, 0, 100);
            const signature = try arbitrary_point(V.Signature, u);
            if (public_keys.len == 0) return;
            const public = aggregate.combine_public_keys(V, public_keys);
            const combined = aggregate.combine_signatures(V, &.{signature});
            aggregate.verify_same_message(V, public, namespace, message, combined) catch {};
        },
        .combine_signatures => {
            const signatures = try arbitrary_points(V.Signature, gpa, u, 20);
            defer gpa.free(signatures);
            if (signatures.len > 0) _ = aggregate.combine_signatures(V, signatures);
        },
        .same_signer => {
            const public_key = try arbitrary_point(V.Public, u);
            const messages = try arbitrary_messages(gpa, u, 1, 20);
            defer gpa.free(messages);
            const signature = try arbitrary_point(V.Signature, u);
            // The concurrency; results do not depend on it, so this runs sequentially.
            _ = u.int_in_range(usize, 1, 8);
            const combined_message = aggregate.combine_messages(V, messages);
            const combined = aggregate.combine_signatures(V, &.{signature});
            aggregate.verify_same_signer(V, public_key, combined_message, combined) catch {};
        },
    }
}

fn aggregate_body(_: void, u: *Unstructured) !void {
    // `Vec<FuzzOperation>`: a continuation bit before each operation.
    while (u.arbitrary(bool) catch false) {
        const choice = u.int_in_range(u32, 0, 7);
        // Choices alternate MinPk and MinSig through the four kinds.
        const kind: AggregateKind = switch (choice / 2) {
            0 => .combine_public_keys,
            1 => .combine_signatures,
            2 => .same_message,
            else => .same_signer,
        };
        if (choice % 2 == 0) {
            try aggregate_operation(MinPk, kind, u);
        } else {
            try aggregate_operation(MinSig, kind, u);
        }
    }
}

test "bls12381 fuzz: aggregate operations" {
    try (minifuzz.Builder{}).with_search_limit(search_limit(4, 64))
        .run(testing.allocator, {}, aggregate_body);
}

test "bls12381 fuzz: aggregate operations (coverage-guided)" {
    try testing.fuzz({}, math.testing.smith_body(void, aggregate_body), .{});
}

const tle = @import("tle.zig");
const Private = primitives.group.Private;

const TleKind = enum { encrypt_decrypt, wrong_key, tampered, decrypt_arbitrary };

/// Encrypts `message` to `secret`'s key with `TestRng(rng_seed)`.
fn tle_encrypt(
    comptime V: type,
    secret: Private,
    namespace: []const u8,
    target: []const u8,
    message: *const tle.Block,
    rng_seed: u64,
) !tle.Ciphertext(V) {
    var rng = utils.rng.TestRng.init(rng_seed);
    const public = primitives.ops.compute_public(V, secret);
    return tle.encrypt(V, &rng, public, namespace, target, message);
}

/// One `bls12381_tle` operation in variant `V`: a round trip must decrypt, and decrypting
/// with a wrong key, a tampered ciphertext, or arbitrary inputs must not crash. A different
/// key must also fail to decrypt (commonware does not check that).
fn tle_operation(comptime V: type, kind: TleKind, u: *Unstructured) !void {
    if (kind == .decrypt_arbitrary) {
        const signature = try arbitrary_point(V.Signature, u);
        const point = try arbitrary_point(V.Public, u);
        const ciphertext: tle.Ciphertext(V) = .{
            .u = point,
            .v = try u.arbitrary(tle.Block),
            .w = try u.arbitrary(tle.Block),
        };
        _ = tle.decrypt(V, signature, ciphertext);
        return;
    }
    const secret = try u.arbitrary(Private);
    const wrong = if (kind == .wrong_key) try u.arbitrary(Private) else secret;
    const namespace = try arbitrary_bytes(u, 0, 50);
    const target = try arbitrary_bytes(u, 0, 100);
    const message = try u.arbitrary(tle.Block);
    const tamper_index = if (kind == .tampered) u.int_in_range(usize, 0, 95) else 0;
    const tamper_value = if (kind == .tampered) try u.arbitrary(u8) else 0;
    const rng_seed = try u.arbitrary(u64);
    var ciphertext = try tle_encrypt(V, secret, namespace, target, &message, rng_seed);
    if (kind == .tampered) {
        var encoded: [tle.Ciphertext(V).fixed_size]u8 = undefined;
        var writer = codec.Writer.init(&encoded);
        ciphertext.write(&writer);
        if (tamper_index < encoded.len) encoded[tamper_index] ^= tamper_value;
        var reader = codec.Reader.init(&encoded);
        ciphertext = tle.Ciphertext(V).read(testing.allocator, &reader, {}) catch return;
    }
    const signature = primitives.ops.sign_message(V, wrong, namespace, target);
    const decrypted = tle.decrypt(V, signature, ciphertext);
    switch (kind) {
        .encrypt_decrypt => try testing.expectEqualSlices(u8, &message, &decrypted.?),
        .wrong_key => if (!wrong.eql(secret)) try testing.expect(decrypted == null),
        else => {},
    }
}

fn tle_body(_: void, u: *Unstructured) !void {
    // `Vec<FuzzOperation>`: a continuation bit before each operation.
    while (u.arbitrary(bool) catch false) {
        const choice = u.int_in_range(u32, 0, 7);
        const kind: TleKind = @fromBackingInt(@intCast(choice / 2));
        if (choice % 2 == 0) {
            try tle_operation(MinPk, kind, u);
        } else {
            try tle_operation(MinSig, kind, u);
        }
    }
}

test "bls12381 fuzz: tle" {
    try (minifuzz.Builder{}).with_search_limit(search_limit(2, 32))
        .run(testing.allocator, {}, tle_body);
}

test "bls12381 fuzz: tle (coverage-guided)" {
    try testing.fuzz({}, math.testing.smith_body(void, tle_body), .{});
}
