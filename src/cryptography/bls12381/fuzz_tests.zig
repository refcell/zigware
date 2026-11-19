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

const threshold = primitives.ops.threshold;
const sharing_mod = primitives.sharing;
const Share = primitives.group.Share;
const Participant = utils.Participant;

/// commonware `Sharing::arbitrary`: a total in `1..=100`, a mode, and a seed for a random
/// polynomial of degree `quorum(total) - 1`.
fn arbitrary_sharing(comptime V: type, gpa: Allocator, u: *Unstructured) !sharing_mod.Sharing(V) {
    const total = u.int_in_range(u32, 1, 100);
    const mode = try u.arbitrary(sharing_mod.Mode);
    var rng = utils.rng.TestRng.init(try u.arbitrary(u64));
    var private = try sharing_mod.Poly(primitives.group.Scalar).random(
        gpa,
        &rng,
        utils.N3f1.quorum(total) - 1,
    );
    defer private.deinit(gpa);
    var committed = try math.poly.commit(gpa, V.Public, private);
    errdefer committed.deinit(gpa);
    return sharing_mod.Sharing(V).init(gpa, mode, total, committed);
}

/// commonware `common::arbitrary_share`: an index in `1..=100` and an arbitrary key.
fn arbitrary_share(u: *Unstructured) !Share {
    const index = Participant.init(u.int_in_range(u32, 1, 100));
    return Share.init(index, try u.arbitrary(Private));
}

fn arbitrary_partials(
    comptime V: type,
    gpa: Allocator,
    u: *Unstructured,
    max: usize,
    random_index: bool,
) ![]primitives.variant.PartialSignature(V) {
    const count = u.int_in_range(usize, 0, max);
    const partials = try gpa.alloc(primitives.variant.PartialSignature(V), count);
    errdefer gpa.free(partials);
    for (partials) |*partial| {
        const index = if (random_index)
            Participant.init(u.int_in_range(u32, 1, 100))
        else
            try u.arbitrary(Participant);
        partial.* = .{ .index = index, .value = try arbitrary_point(V.Signature, u) };
    }
    return partials;
}

const ThresholdKind = enum {
    sign_pop,
    verify_pop,
    same_signer,
    same_message,
    recover,
    recover_multiple,
    recover_pair,
    sign_message,
};

/// One `bls12381_threshold_operations` operation in variant `V`; like commonware's target,
/// it checks only that the operations run.
fn threshold_operation(comptime V: type, kind: ThresholdKind, u: *Unstructured) !void {
    const gpa = testing.allocator;
    switch (kind) {
        .sign_pop, .verify_pop => {
            var public = try arbitrary_sharing(V, gpa, u);
            defer public.deinit(gpa);
            if (kind == .sign_pop) {
                const share = try arbitrary_share(u);
                const namespace = try arbitrary_bytes(u, 0, 50);
                if (share.index.get() > public.required()) return;
                _ = threshold.sign_proof_of_possession(V, public, share, namespace);
            } else {
                const namespace = try arbitrary_bytes(u, 0, 50);
                const partial: primitives.variant.PartialSignature(V) = .{
                    .index = try u.arbitrary(Participant),
                    .value = try arbitrary_point(V.Signature, u),
                };
                if (partial.index.get() > public.required()) return;
                threshold.verify_proof_of_possession(V, public, namespace, partial) catch {};
            }
        },
        .same_signer => try threshold_same_signer(V, gpa, u),
        .same_message => try threshold_same_message(V, gpa, u),
        .recover, .recover_multiple, .recover_pair => try threshold_recover(V, kind, gpa, u),
        .sign_message => {
            const share = try arbitrary_share(u);
            const namespace = try arbitrary_bytes(u, 0, 50);
            _ = threshold.sign_message(V, share, namespace, try arbitrary_bytes(u, 0, 100));
        },
    }
}

fn threshold_same_signer(comptime V: type, gpa: Allocator, u: *Unstructured) !void {
    const messages = try arbitrary_messages(gpa, u, 0, 10);
    defer gpa.free(messages);
    const entries = try gpa.alloc(threshold.SignerEntry(V), messages.len);
    defer gpa.free(entries);
    for (entries, messages) |*entry, item| {
        entry.* = .{
            .namespace = item.namespace,
            .message = item.message,
            .partial = .{ .index = undefined, .value = try arbitrary_point(V.Signature, u) },
        };
    }
    var public = try arbitrary_sharing(V, gpa, u);
    defer public.deinit(gpa);
    const index = Participant.init(u.int_in_range(u32, 1, 100));
    if (index.get() > public.required() or entries.len == 0) return;
    // As in commonware, entry `i` claims index `index + i`.
    for (entries, 0..) |*entry, i| entry.partial.index = .from_usize(index.get() + i);
    var rng = utils.test_rng();
    threshold.batch_verify_same_signer(
        V,
        gpa,
        &rng,
        public,
        index,
        entries,
        parallel.sequential,
    ) catch |err|
        switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };
}

fn threshold_same_message(comptime V: type, gpa: Allocator, u: *Unstructured) !void {
    var public = try arbitrary_sharing(V, gpa, u);
    defer public.deinit(gpa);
    const namespace = try arbitrary_bytes(u, 0, 50);
    const message = try arbitrary_bytes(u, 0, 100);
    const partials = try arbitrary_partials(V, gpa, u, 10, true);
    defer gpa.free(partials);
    if (public.required() != partials.len) return;
    var rng = utils.test_rng();
    const invalid = try threshold.batch_verify_same_message(
        V,
        gpa,
        &rng,
        public,
        namespace,
        message,
        partials,
        parallel.sequential,
    );
    defer gpa.free(invalid);
    try testing.expect(invalid.len <= partials.len);
}

fn threshold_recover(
    comptime V: type,
    kind: ThresholdKind,
    gpa: Allocator,
    u: *Unstructured,
) !void {
    var sharing = try arbitrary_sharing(V, gpa, u);
    defer sharing.deinit(gpa);
    switch (kind) {
        .recover => {
            const partials = try arbitrary_partials(V, gpa, u, 20, false);
            defer gpa.free(partials);
            _ = threshold.recover(V, gpa, sharing, partials) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {},
            };
        },
        .recover_multiple => {
            const Group = []const primitives.variant.PartialSignature(V);
            const groups = try gpa.alloc(Group, u.int_in_range(usize, 0, 5));
            defer gpa.free(groups);
            var built: usize = 0;
            defer for (groups[0..built]) |group| gpa.free(group);
            while (built < groups.len) : (built += 1) {
                groups[built] = try arbitrary_partials(V, gpa, u, 10, false);
            }
            _ = u.int_in_range(usize, 1, 4); // The concurrency; results do not depend on it.
            const out = try gpa.alloc(V.Signature, groups.len);
            defer gpa.free(out);
            threshold.recover_multiple(
                V,
                gpa,
                sharing,
                groups,
                out,
                parallel.sequential,
            ) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {},
            };
        },
        else => {
            const first = try arbitrary_partials(V, gpa, u, 10, false);
            defer gpa.free(first);
            const second = try arbitrary_partials(V, gpa, u, 10, false);
            defer gpa.free(second);
            _ = threshold.recover_pair(
                V,
                gpa,
                sharing,
                first,
                second,
                parallel.sequential,
            ) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {},
            };
        },
    }
}

/// A share survives an encode and decode unchanged.
fn serialize_share(u: *Unstructured) !void {
    const share = try arbitrary_share(u);
    var buffer: [64]u8 = undefined;
    var writer = codec.Writer.init(&buffer);
    share.write(&writer);
    const decoded = codec.decode(Share, testing.allocator, writer.written()) catch return;
    try testing.expect(decoded.eql(share));
}

fn threshold_body(_: void, u: *Unstructured) !void {
    const num_ops = u.int_in_range(u32, 1, 100);
    for (0..num_ops) |_| {
        const choice = u.int_in_range(u32, 0, 16);
        const result = switch (choice) {
            16 => serialize_share(u),
            // commonware lists Recover as MinSig first, then MinPk.
            8 => threshold_operation(MinSig, .recover, u),
            9 => threshold_operation(MinPk, .recover, u),
            else => if (choice % 2 == 0)
                threshold_operation(MinPk, @fromBackingInt(@intCast(choice / 2)), u)
            else
                threshold_operation(MinSig, @fromBackingInt(@intCast(choice / 2)), u),
        };
        // A failed draw ends the input, as commonware breaks out of its loop.
        result catch |err| switch (err) {
            error.NotEnoughData, error.IncorrectFormat, error.EmptyChoose => break,
            else => return err,
        };
    }
}

test "bls12381 fuzz: threshold operations" {
    // Minutes in Debug, so it runs in optimized builds (CI's ReleaseSafe job) or -Dslow-tests.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    try (minifuzz.Builder{}).with_search_limit(search_limit(2, 32))
        .run(testing.allocator, {}, threshold_body);
}

test "bls12381 fuzz: threshold operations (coverage-guided)" {
    try testing.fuzz({}, math.testing.smith_body(void, threshold_body), .{});
}

const Scalar = primitives.group.Scalar;
const G1 = primitives.group.G1;
const G2 = primitives.group.G2;
const ops = primitives.ops;

fn arbitrary_scalars(gpa: Allocator, u: *Unstructured, max: usize) ![]Scalar {
    const scalars = try gpa.alloc(Scalar, u.int_in_range(usize, 0, max));
    errdefer gpa.free(scalars);
    for (scalars) |*scalar| scalar.* = try u.arbitrary(Scalar);
    return scalars;
}

/// commonware `arbitrary_poly_scalar`: a degree in `0..=10`, an RNG seed, and the constant.
fn arbitrary_poly_scalar(gpa: Allocator, u: *Unstructured) !sharing_mod.Poly(Scalar) {
    const degree = u.int_in_range(u32, 0, 10);
    var rng = utils.rng.TestRng.init_key(try u.arbitrary([32]u8));
    const constant = try u.arbitrary(Scalar);
    return sharing_mod.Poly(Scalar).random_with_constant(gpa, &rng, degree, constant);
}

/// Encodes `value` and expects it to decode (with `cfg`) to the same value when it decodes.
fn expect_serialize(comptime T: type, value: T, cfg: anytype) !void {
    var buffer: [T.fixed_size]u8 = undefined;
    var writer = codec.Writer.init(&buffer);
    value.write(&writer);
    var reader = codec.Reader.init(writer.written());
    const decoded = T.read(testing.allocator, &reader, cfg) catch return;
    try testing.expect(decoded.eql(value));
}

/// Scalar operations: choices 0 to 2 and 30.
fn scalar_operation(choice: u32, u: *Unstructured) !void {
    const a = try u.arbitrary(Scalar);
    switch (choice) {
        0 => {
            const b = try u.arbitrary(Scalar);
            _ = a.add(b);
            _ = a.mul(b);
        },
        1 => _ = a.sub(try u.arbitrary(Scalar)),
        2 => {
            const inverse = a.inv();
            if (a.eql(Scalar.zero)) {
                try testing.expect(inverse.eql(Scalar.zero));
            } else {
                try testing.expect(a.mul(inverse).eql(Scalar.one));
            }
        },
        else => try expect_serialize(Scalar, a, .reject_zero),
    }
}

/// Point operations in `G`: arithmetic, scalar multiplication, MSM, hash to point, and
/// serialization.
fn point_operation(comptime G: type, kind: u32, gpa: Allocator, u: *Unstructured) !void {
    switch (kind) {
        0 => _ = (try arbitrary_point(G, u)).add(try arbitrary_point(G, u)),
        1 => _ = (try arbitrary_point(G, u)).mul(try u.arbitrary(Scalar)),
        2 => {
            const points = try arbitrary_points(G, gpa, u, 10);
            defer gpa.free(points);
            const scalars = try arbitrary_scalars(gpa, u, 10);
            defer gpa.free(scalars);
            const len = @min(points.len, scalars.len);
            if (len > 0) _ = G.msm(points[0..len], scalars[0..len]);
        },
        3 => _ = G.hash_to_group(G.message_dst, try arbitrary_bytes(u, 0, 100)),
        else => try expect_serialize(G, try arbitrary_point(G, u), {}),
    }
}

/// Keys and hashes: choices 11 to 15.
fn key_operation(choice: u32, u: *Unstructured) !void {
    switch (choice) {
        11 => {}, // Key generation draws from an RNG; commonware skips it here too.
        12 => {
            const private = try u.arbitrary(Private);
            _ = ops.compute_public(MinPk, private);
            _ = ops.compute_public(MinSig, private);
        },
        13 => {
            const share = try arbitrary_share(u);
            if (try u.arbitrary(bool)) _ = share.public(MinPk) else _ = share.public(MinSig);
        },
        14 => {
            const message = try arbitrary_bytes(u, 0, 100);
            if (try u.arbitrary(bool)) {
                _ = ops.hash(MinPk, MinPk.message, message);
            } else {
                _ = ops.hash(MinSig, MinSig.message, message);
            }
        },
        else => {
            const namespace = try arbitrary_bytes(u, 0, 50);
            const message = try arbitrary_bytes(u, 0, 100);
            if (try u.arbitrary(bool)) {
                _ = ops.hash_with_namespace(MinPk, MinPk.message, namespace, message);
            } else {
                _ = ops.hash_with_namespace(MinSig, MinSig.message, namespace, message);
            }
        },
    }
}

/// Signatures in `V`: sign, sign low-level, verify, verify low-level. A fresh signature
/// must verify (commonware ignores the result).
fn signature_operation(comptime V: type, kind: u32, u: *Unstructured) !void {
    switch (kind) {
        0, 1 => {
            const private = try u.arbitrary(Private);
            const namespace = if (kind == 0) try arbitrary_bytes(u, 0, 50) else "";
            const message = try arbitrary_bytes(u, 0, 100);
            const public = ops.compute_public(V, private);
            if (kind == 0) {
                const signature = ops.sign_message(V, private, namespace, message);
                try ops.verify_message(V, public, namespace, message, signature);
            } else {
                const signature = ops.sign(V, private, V.message, message);
                try ops.verify(V, public, V.message, message, signature);
            }
        },
        else => {
            const public = try arbitrary_point(V.Public, u);
            const namespace = if (kind == 2) try arbitrary_bytes(u, 0, 50) else "";
            const message = try arbitrary_bytes(u, 0, 100);
            const signature = try arbitrary_point(V.Signature, u);
            if (kind == 2) {
                ops.verify_message(V, public, namespace, message, signature) catch {};
            } else {
                ops.verify(V, public, V.message, message, signature) catch {};
            }
        },
    }
}

/// Proofs of possession in `V`: sign (which must verify) or verify arbitrary inputs.
fn proof_of_possession_operation(comptime V: type, sign: bool, u: *Unstructured) !void {
    if (sign) {
        const private = try u.arbitrary(Private);
        const namespace = try arbitrary_bytes(u, 0, 50);
        const signature = ops.sign_proof_of_possession(V, private, namespace);
        const public = ops.compute_public(V, private);
        try ops.verify_proof_of_possession(V, public, namespace, signature);
    } else {
        const public = try arbitrary_point(V.Public, u);
        const namespace = try arbitrary_bytes(u, 0, 50);
        const signature = try arbitrary_point(V.Signature, u);
        ops.verify_proof_of_possession(V, public, namespace, signature) catch {};
    }
}

/// Polynomials: addition (choice 28) and commitment (29).
fn poly_operation(choice: u32, gpa: Allocator, u: *Unstructured) !void {
    var a = try arbitrary_poly_scalar(gpa, u);
    defer a.deinit(gpa);
    if (choice == 28) {
        var b = try arbitrary_poly_scalar(gpa, u);
        defer b.deinit(gpa);
        try a.add_assign(gpa, b);
    } else if (try u.arbitrary(bool)) {
        var committed = try math.poly.commit(gpa, G1, a);
        committed.deinit(gpa);
    } else {
        var committed = try math.poly.commit(gpa, G2, a);
        committed.deinit(gpa);
    }
}

fn primitive_operation(choice: u32, gpa: Allocator, u: *Unstructured) !void {
    switch (choice) {
        0...2, 30 => try scalar_operation(choice, u),
        3...6 => try point_operation(G1, choice - 3, gpa, u),
        7...10 => try point_operation(G2, choice - 7, gpa, u),
        31 => try point_operation(G1, 4, gpa, u),
        32 => try point_operation(G2, 4, gpa, u),
        11...15 => try key_operation(choice, u),
        16...19 => try signature_operation(MinPk, choice - 16, u),
        20...23 => try signature_operation(MinSig, choice - 20, u),
        24, 25 => try proof_of_possession_operation(MinPk, choice == 24, u),
        26, 27 => try proof_of_possession_operation(MinSig, choice == 26, u),
        28, 29 => try poly_operation(choice, gpa, u),
        else => unreachable,
    }
}

fn primitive_body(_: void, u: *Unstructured) !void {
    // `Vec<FuzzOperation>`: a continuation bit before each operation.
    while (u.arbitrary(bool) catch false) {
        try primitive_operation(u.int_in_range(u32, 0, 32), testing.allocator, u);
    }
}

test "bls12381 fuzz: primitive operations" {
    try (minifuzz.Builder{}).with_search_limit(search_limit(4, 64))
        .run(testing.allocator, {}, primitive_body);
}

test "bls12381 fuzz: primitive operations (coverage-guided)" {
    try testing.fuzz({}, math.testing.smith_body(void, primitive_body), .{});
}
