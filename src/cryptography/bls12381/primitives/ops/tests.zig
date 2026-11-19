//! Tests for `ops.zig`, `variant.zig`, `ops/aggregate.zig`, and `ops/batch.zig` (commonware
//! `ops`, `variant`, `aggregate`, and `batch` tests), including the noble-curves vectors
//! (`test_vectors/min_pk.txt`, `min_sig.txt`) and the Ethereum bls12-381-tests vectors.

const std = @import("std");
const parallel = @import("parallel");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const group = @import("../group.zig");
const variant = @import("../variant.zig");
const ops = @import("../ops.zig");
const eth_vectors = @import("eth_vectors.zig");

const aggregate = ops.aggregate;
const batch = ops.batch;
const MinPk = variant.MinPk;
const MinSig = variant.MinSig;
const Private = group.Private;
const Scalar = group.Scalar;
const gpa = testing.allocator;

fn from_hex(comptime length: usize, text: []const u8) ![length]u8 {
    var out: [length]u8 = undefined;
    if (text.len != 2 * length) return error.BadVectorLength;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}

fn decode(comptime T: type, bytes: []const u8) codec.Error!T {
    return codec.decode(T, gpa, bytes);
}

test "ops: codec round trip of keys" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        const pair = ops.keypair(V, &rng);
        const private_bytes = try codec.encode(Private, gpa, pair.private);
        defer gpa.free(private_bytes);
        const public_bytes = try codec.encode(V.Public, gpa, pair.public);
        defer gpa.free(public_bytes);
        try testing.expect((try decode(Private, private_bytes)).eql(pair.private));
        try testing.expect((try decode(V.Public, public_bytes)).eql(pair.public));
    }
}

test "ops: proof of possession, namespaces, and single messages" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        const pair = ops.keypair(V, &rng);
        const pop = ops.sign_proof_of_possession(V, pair.private, "test");
        try ops.verify_proof_of_possession(V, pair.public, "test", pop);
        try testing.expectError(
            error.InvalidSignature,
            ops.verify_proof_of_possession(V, pair.public, "other", pop),
        );
        const message = [_]u8{ 1, 9, 6, 9 };
        const signature = ops.sign_message(V, pair.private, "good", &message);
        try ops.verify_message(V, pair.public, "good", &message, signature);
        try testing.expectError(
            error.InvalidSignature,
            ops.verify_message(V, pair.public, "bad", &message, signature),
        );
        // A namespaced signature is a plain signature over union_unique(namespace, message).
        const payload = try utils.union_unique(gpa, "good", &message);
        defer gpa.free(payload);
        try ops.verify(V, pair.public, V.message, payload, signature);
    }
}

/// Optimized builds and `-Dslow-tests` run the full sets; a Debug run (where they take
/// minutes) checks every 16th vector and the smaller bisection shapes.
const slow = builtin.mode != .debug or build_options.slow_tests;
const vector_stride: usize = if (slow) 1 else 16;

/// Runs the noble-curves vectors for one variant: each signs, verifies, and fails once
/// tampered; the whole set batch-verifies, and fails once one signature is tampered.
fn check_noble(comptime V: type, comptime dst: []const u8, comptime text: []const u8) !void {
    var publics: std.ArrayList(V.Public) = .empty;
    defer publics.deinit(gpa);
    var hms: std.ArrayList(V.Signature) = .empty;
    defer hms.deinit(gpa);
    var signatures: std.ArrayList(V.Signature) = .empty;
    defer signatures.deinit(gpa);
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    var line_index: usize = 0;
    while (lines.next()) |line| : (line_index += 1) {
        if (line_index % vector_stride != 0) continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        const private_hex = fields.next() orelse return error.BadVector;
        const message_hex = fields.next() orelse return error.BadVector;
        const signature_hex = fields.next() orelse return error.BadVector;
        const private = try decode(Private, &try from_hex(32, private_hex));
        var message_buffer: [128]u8 = undefined;
        const message = try std.fmt.hexToBytes(&message_buffer, message_hex);
        const signature_bytes = try from_hex(V.Signature.fixed_size, signature_hex);
        var signature = try decode(V.Signature, &signature_bytes);
        try testing.expect(ops.sign(V, private, dst, message).eql(signature));
        const public = ops.compute_public(V, private);
        try ops.verify(V, public, dst, message, signature);
        try publics.append(gpa, public);
        try hms.append(gpa, ops.hash(V, dst, message));
        try signatures.append(gpa, signature);
        signature = signature.add(V.Signature.generator);
        const tampered = ops.verify(V, public, dst, message, signature);
        try testing.expectError(error.InvalidSignature, tampered);
    }
    var rng = utils.test_rng();
    try V.batch_verify(&rng, publics.items, hms.items, signatures.items);
    signatures.items[0] = signatures.items[0].add(V.Signature.generator);
    rng = utils.test_rng();
    try testing.expectError(
        error.InvalidSignature,
        V.batch_verify(&rng, publics.items, hms.items, signatures.items),
    );
}

test "ops: noble min_sig vectors" {
    try check_noble(
        MinSig,
        "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_",
        @embedFile("test_vectors/min_sig.txt"),
    );
}

test "ops: noble min_pk vectors" {
    try check_noble(
        MinPk,
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
        @embedFile("test_vectors/min_pk.txt"),
    );
}

test "ops: zero private key is rejected" {
    const zero: [32]u8 = @splat(0);
    try testing.expectError(error.Invalid, decode(Private, &zero));
}

test "ops: ethereum sign vectors" {
    inline for (eth_vectors.sign) |vector| {
        const private = try decode(Private, &try from_hex(32, vector.private));
        const message = try from_hex(vector.message.len / 2, vector.message);
        const expected = try decode(MinPk.Signature, &try from_hex(96, vector.signature));
        try testing.expect(ops.sign(MinPk, private, MinPk.message, &message).eql(expected));
    }
}

const ParsedVerify = struct {
    public: codec.Error!MinPk.Public,
    message: [32]u8,
    signature: codec.Error!MinPk.Signature,
    valid: bool,
};

fn parse_verify(comptime vector: eth_vectors.VerifyVector) !ParsedVerify {
    return .{
        .public = decode(MinPk.Public, &try from_hex(48, vector.public)),
        .message = try from_hex(32, vector.message),
        .signature = decode(MinPk.Signature, &try from_hex(96, vector.signature)),
        .valid = vector.valid,
    };
}

fn check_eth_verify(comptime vector: eth_vectors.VerifyVector) !void {
    const parsed = try parse_verify(vector);
    if (!parsed.valid) {
        const public = parsed.public catch return;
        const signature = parsed.signature catch return;
        try testing.expectError(
            error.InvalidSignature,
            ops.verify(MinPk, public, MinPk.message, &parsed.message, signature),
        );
        return;
    }
    const public = try parsed.public;
    const signature = try parsed.signature;
    try ops.verify(MinPk, public, MinPk.message, &parsed.message, signature);
    var rng = utils.test_rng();
    const hm = ops.hash(MinPk, MinPk.message, &parsed.message);
    try MinPk.batch_verify(&rng, &.{public}, &.{hm}, &.{signature});
}

test "ops: ethereum verify vectors" {
    inline for (eth_vectors.verify) |vector| try check_eth_verify(vector);
}

test "ops: ethereum batch verify" {
    var valid_publics: std.ArrayList(MinPk.Public) = .empty;
    defer valid_publics.deinit(gpa);
    var valid_hms: std.ArrayList(MinPk.Signature) = .empty;
    defer valid_hms.deinit(gpa);
    var valid_signatures: std.ArrayList(MinPk.Signature) = .empty;
    defer valid_signatures.deinit(gpa);
    var all_publics: std.ArrayList(MinPk.Public) = .empty;
    defer all_publics.deinit(gpa);
    var all_hms: std.ArrayList(MinPk.Signature) = .empty;
    defer all_hms.deinit(gpa);
    var all_signatures: std.ArrayList(MinPk.Signature) = .empty;
    defer all_signatures.deinit(gpa);
    inline for (eth_vectors.verify) |vector| {
        const parsed = try parse_verify(vector);
        if (parsed.public) |public| {
            if (parsed.signature) |signature| {
                const hm = ops.hash(MinPk, MinPk.message, &parsed.message);
                if (parsed.valid) {
                    try valid_publics.append(gpa, public);
                    try valid_hms.append(gpa, hm);
                    try valid_signatures.append(gpa, signature);
                }
                try all_publics.append(gpa, public);
                try all_hms.append(gpa, hm);
                try all_signatures.append(gpa, signature);
            } else |_| {}
        } else |_| {}
    }
    var rng = utils.test_rng();
    try MinPk.batch_verify(&rng, valid_publics.items, valid_hms.items, valid_signatures.items);
    rng = utils.test_rng();
    try testing.expectError(
        error.InvalidSignature,
        MinPk.batch_verify(&rng, all_publics.items, all_hms.items, all_signatures.items),
    );
}

test "variant: batch verify accepts valid and rejects empty, identity, and forgeries" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        const one = ops.keypair(V, &rng);
        const two = ops.keypair(V, &rng);
        const sig1 = ops.sign_message(V, one.private, "test", "message 1");
        const sig2 = ops.sign_message(V, two.private, "test", "message 2");
        const hm1 = ops.hash_with_namespace(V, V.message, "test", "message 1");
        const hm2 = ops.hash_with_namespace(V, V.message, "test", "message 2");
        try V.batch_verify(&rng, &.{ one.public, two.public }, &.{ hm1, hm2 }, &.{ sig1, sig2 });
        try testing.expectError(error.InvalidSignature, V.batch_verify(&rng, &.{}, &.{}, &.{}));
        try testing.expectError(
            error.InvalidSignature,
            V.batch_verify(&rng, &.{ one.public, V.Public.zero }, &.{ hm1, hm2 }, &.{
                sig1,
                V.Signature.zero,
            }),
        );
        try testing.expectError(
            error.InvalidSignature,
            V.batch_verify(&rng, &.{one.public}, &.{hm1}, &.{V.Signature.zero}),
        );
        // Offsets that cancel in an unweighted sum are caught by the random weights.
        const delta = V.Signature.generator.mul(Scalar.random(&rng));
        const forged1 = sig1.sub(delta);
        const forged2 = sig2.add(delta);
        try testing.expectError(error.InvalidSignature, V.verify(one.public, hm1, forged1));
        try testing.expectError(error.InvalidSignature, V.verify(two.public, hm2, forged2));
        try testing.expect(forged1.add(forged2).eql(sig1.add(sig2)));
        try testing.expectError(
            error.InvalidSignature,
            V.batch_verify(&rng, &.{ one.public, two.public }, &.{ hm1, hm2 }, &.{
                forged1,
                forged2,
            }),
        );
    }
}

test "variant: partial signature codec" {
    inline for (.{ MinPk, MinSig }) |V| {
        const Partial = variant.PartialSignature(V);
        var rng = utils.test_rng();
        const partial: Partial = .{
            .index = utils.Participant.init(300),
            .value = V.Signature.generator.mul(Scalar.random(&rng)),
        };
        const encoded = try codec.encode(Partial, gpa, partial);
        defer gpa.free(encoded);
        try testing.expectEqual(2 + V.Signature.fixed_size, encoded.len);
        try testing.expect((try decode(Partial, encoded)).eql(partial));
    }
}

test "aggregate: same message from many keys" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var publics: [4]V.Public = undefined;
        var signatures: [3]V.Signature = undefined;
        for (&publics, 0..) |*public, index| {
            const pair = ops.keypair(V, &rng);
            public.* = pair.public;
            if (index < 3) signatures[index] = ops.sign_message(V, pair.private, "test", "message");
        }
        const sum = aggregate.combine_signatures(V, &signatures);
        const keys = aggregate.combine_public_keys(V, publics[0..3]);
        try aggregate.verify_same_message(V, keys, "test", "message", sum);
        // A wrong key set or a missing key fails.
        const wrong = aggregate.combine_public_keys(V, &.{ publics[0], publics[1], publics[3] });
        try testing.expectError(
            error.InvalidSignature,
            aggregate.verify_same_message(V, wrong, "test", "message", sum),
        );
        const short = aggregate.combine_public_keys(V, publics[0..2]);
        try testing.expectError(
            error.InvalidSignature,
            aggregate.verify_same_message(V, short, "test", "message", sum),
        );
    }
}

test "aggregate: same signer over many messages" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        const pair = ops.keypair(V, &rng);
        const messages = [_]aggregate.NamespacedMessage{
            .{ .namespace = "test", .message = "Message 1" },
            .{ .namespace = "test", .message = "Message 2" },
            .{ .namespace = "test", .message = "Message 3" },
        };
        var signatures: [3]V.Signature = undefined;
        for (&signatures, messages) |*signature, item| {
            signature.* = ops.sign_message(V, pair.private, item.namespace, item.message);
        }
        const sum = aggregate.combine_signatures(V, &signatures);
        const combined = aggregate.combine_messages(V, &messages, parallel.sequential);
        try aggregate.verify_same_signer(V, pair.public, combined, sum);
        try testing.expectError(
            error.InvalidSignature,
            aggregate.verify_same_signer(V, pair.public, .zero, .zero),
        );
    }
}

/// Whether `entries` verify, under every strategy shape (commonware `explore`).
fn same_signer_explored(
    comptime V: type,
    rng: *utils.TestRng,
    public: V.Public,
    entries: []const batch.SignerEntry(V),
) !bool {
    const Op = struct {
        rng: utils.TestRng,
        public: V.Public,
        entries: []const batch.SignerEntry(V),

        pub fn run(op: @This(), explorer: parallel.mocks.Explorer) bool {
            var run_rng = op.rng;
            batch.verify_same_signer(V, &run_rng, op.public, op.entries, explorer) catch
                return false;
            return true;
        }
    };
    const op: Op = .{ .rng = rng.*, .public = public, .entries = entries };
    const verdict = try parallel.mocks.explore(gpa, testing.io, op);
    var serial_rng = rng.*;
    const serial = batch.verify_same_signer(V, &serial_rng, public, entries, parallel.sequential);
    try testing.expectEqual(std.meta.isError(serial), !verdict);
    rng.* = serial_rng;
    return verdict;
}

test "aggregate: combine_messages across pools equals the sequential sum" {
    var rng = utils.test_rng();
    var bytes: [200][16]u8 = undefined;
    var messages: [200]aggregate.NamespacedMessage = undefined;
    for (&bytes, &messages) |*message, *item| {
        rng.fill_bytes(message);
        item.* = .{ .namespace = "test", .message = message };
    }
    inline for (.{ MinPk, MinSig }) |V| {
        for ([_]usize{ 1, 2, 7, 200 }) |count| {
            const serial = aggregate.combine_messages(V, messages[0..count], parallel.sequential);
            for ([_]u32{ 0, 1, 3, 8 }) |workers| {
                const strategy = try parallel.mocks.pooled(gpa, testing.io, workers, 8);
                defer strategy.pool.destroy();
                const pooled = aggregate.combine_messages(V, messages[0..count], strategy);
                try testing.expect(serial.eql(pooled));
            }
        }
    }
}

test "batch: same signer accepts valid and rejects identity and wrong signatures" {
    inline for (.{ MinPk, MinSig }) |V| {
        const Entry = batch.SignerEntry(V);
        var rng = utils.test_rng();
        const pair = ops.keypair(V, &rng);
        var entries: [3]Entry = undefined;
        for (&entries, [_][]const u8{ "Message 1", "Message 2", "Message 3" }) |*entry, m| {
            entry.* = .{
                .namespace = "test",
                .message = m,
                .signature = ops.sign_message(V, pair.private, "test", m),
            };
        }
        try testing.expect(try same_signer_explored(V, &rng, pair.public, &entries));
        entries[1].signature = entries[0].signature;
        try testing.expect(!try same_signer_explored(V, &rng, pair.public, &entries));
        const identity = [_]Entry{.{
            .namespace = "test",
            .message = "message",
            .signature = V.Signature.zero,
        }};
        try testing.expectError(
            error.InvalidSignature,
            batch.verify_same_signer(V, &rng, pair.public, &identity, parallel.sequential),
        );
    }
}

/// Bisection reports exactly the corrupted entries, alone and in cancelling pairs.
fn check_bisection(comptime V: type) !void {
    const Entry = batch.Entry(V);
    var rng = utils.test_rng();
    var valid: [9]Entry = undefined;
    for (&valid) |*entry| {
        const pair = ops.keypair(V, &rng);
        entry.* = .{
            .public = pair.public,
            .signature = ops.sign_message(V, pair.private, "test", "message"),
        };
    }
    const totals_slow = [_]usize{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const totals = if (slow) &totals_slow else totals_slow[0..3];
    for (totals) |total| {
        for (0..total) |first| {
            for (first..total) |second| {
                var entries = valid;
                const offset = V.Signature.generator.mul(Scalar.random(&rng));
                entries[first].signature = entries[first].signature.add(offset);
                if (second != first) {
                    entries[second].signature = entries[second].signature.sub(offset);
                }
                const found = try find_explored(V, &rng, entries[0..total]);
                defer gpa.free(found);
                if (second == first) {
                    try testing.expectEqualSlices(usize, &.{first}, found);
                } else {
                    try testing.expectEqualSlices(usize, &.{ first, second }, found);
                }
            }
        }
        const clean =
            try batch.verify_same_message(
                V,
                gpa,
                &rng,
                "test",
                "message",
                valid[0..total],
                parallel.sequential,
            );
        defer gpa.free(clean);
        try testing.expectEqual(@as(usize, 0), clean.len);
    }
}

/// commonware's `explore(|strategy| find(..))`: the invalid indices, which every strategy shape
/// (whole input, split batches, seeded schedules) must agree on. Each run draws from a copy
/// of `rng`, which then advances as one run did.
fn find_explored(comptime V: type, rng: *utils.TestRng, entries: []const batch.Entry(V)) ![]usize {
    const Op = struct {
        rng: utils.TestRng,
        entries: []const batch.Entry(V),

        pub fn run(op: @This(), explorer: parallel.mocks.Explorer) std.mem.Allocator.Error![]usize {
            var run_rng = op.rng;
            const message = "message";
            return batch.verify_same_message(
                V,
                gpa,
                &run_rng,
                "test",
                message,
                op.entries,
                explorer,
            );
        }

        pub fn eql(_: @This(), a: []usize, b: []usize) bool {
            return std.mem.eql(usize, a, b);
        }

        pub fn discard(_: @This(), found: []usize) void {
            gpa.free(found);
        }
    };
    const found = try parallel.mocks.explore(
        gpa,
        testing.io,
        Op{ .rng = rng.*, .entries = entries },
    );
    errdefer gpa.free(found);
    const serial = try batch.verify_same_message(
        V,
        gpa,
        rng,
        "test",
        "message",
        entries,
        parallel.sequential,
    );
    defer gpa.free(serial);
    try testing.expectEqualSlices(usize, serial, found);
    return found;
}

test "batch: same message bisection finds corrupted entries" {
    try check_bisection(MinPk);
    try check_bisection(MinSig);
}

test "batch: same message detects an identity signature" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        const pair = ops.keypair(V, &rng);
        const entry: batch.Entry(V) = .{ .public = pair.public, .signature = V.Signature.zero };
        const entries = [_]batch.Entry(V){entry};
        const found = try batch.verify_same_message(
            V,
            gpa,
            &rng,
            "test",
            "message",
            &entries,
            parallel.sequential,
        );
        defer gpa.free(found);
        try testing.expectEqualSlices(usize, &.{0}, found);
    }
}

test "ops: verify_same_signer rejects offsets that cancel in the aggregate" {
    // commonware batch.rs `test_rejects_malleability`.
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        const keys = ops.keypair(V, &rng);
        const sig1 = ops.sign_message(V, keys.private, "test", "message 1");
        const sig2 = ops.sign_message(V, keys.private, "test", "message 2");
        try ops.verify_message(V, keys.public, "test", "message 1", sig1);
        try ops.verify_message(V, keys.public, "test", "message 2", sig2);
        const delta = V.Signature.generator.mul(Scalar.random(&rng));
        const forged1 = sig1.sub(delta);
        const forged2 = sig2.add(delta);
        const failure = error.InvalidSignature;
        const forged1_alone = ops.verify_message(V, keys.public, "test", "message 1", forged1);
        try testing.expectError(failure, forged1_alone);
        const forged2_alone = ops.verify_message(V, keys.public, "test", "message 2", forged2);
        try testing.expectError(failure, forged2_alone);
        // The aggregates are equal, so naive aggregate verification accepts the forgeries.
        const forged_aggregate = aggregate.combine_signatures(V, &.{ forged1, forged2 });
        const valid_aggregate = aggregate.combine_signatures(V, &.{ sig1, sig2 });
        try testing.expect(forged_aggregate.eql(valid_aggregate));
        const hm1 = ops.hash_with_namespace(V, V.message, "test", "message 1");
        const hm2 = ops.hash_with_namespace(V, V.message, "test", "message 2");
        try V.verify(keys.public, hm1.add(hm2), forged_aggregate.value);
        // Randomly weighted batch verification does not.
        const Entry = batch.SignerEntry(V);
        const forged = [_]Entry{
            .{ .namespace = "test", .message = "message 1", .signature = forged1 },
            .{ .namespace = "test", .message = "message 2", .signature = forged2 },
        };
        const strategy = parallel.sequential;
        const forged_result = batch.verify_same_signer(V, &rng, keys.public, &forged, strategy);
        try testing.expectError(failure, forged_result);
        const valid = [_]Entry{
            .{ .namespace = "test", .message = "message 1", .signature = sig1 },
            .{ .namespace = "test", .message = "message 2", .signature = sig2 },
        };
        try batch.verify_same_signer(V, &rng, keys.public, &valid, strategy);
    }
}
