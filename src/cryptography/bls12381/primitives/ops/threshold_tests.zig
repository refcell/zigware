//! Tests for `threshold.zig` (commonware `ops::threshold` tests). Sharings come from the
//! trusted dealer `dkg.feldman_desmedt.deal_anonymous`, which draws from the test RNG
//! exactly as commonware's does.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const group = @import("../group.zig");
const variant = @import("../variant.zig");
const ops = @import("../ops.zig");
const threshold = @import("threshold.zig");
const sharing_mod = @import("../sharing.zig");
const dkg = @import("../../dkg/root.zig").feldman_desmedt;

const Participant = utils.Participant;
const Private = group.Private;
const Scalar = group.Scalar;
const MinPk = variant.MinPk;
const MinSig = variant.MinSig;
const PartialSignature = variant.PartialSignature;
const gpa = testing.allocator;

fn deal(comptime V: type, rng: anytype, n: u32) !dkg.Dealing(V) {
    return dkg.deal_anonymous(V, utils.N3f1, gpa, rng, .non_zero_counter, n);
}

fn sign_all(
    comptime V: type,
    shares: []const group.Share,
    namespace: []const u8,
    message: []const u8,
) ![]PartialSignature(V) {
    const partials = try gpa.alloc(PartialSignature(V), shares.len);
    for (partials, shares) |*partial, share| {
        partial.* = threshold.sign_message(V, share, namespace, message);
    }
    return partials;
}

test "threshold: proof of possession" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 5);
        defer dealing.deinit(gpa);
        var partials: [5]PartialSignature(V) = undefined;
        for (&partials, dealing.shares) |*partial, share| {
            partial.* = threshold.sign_proof_of_possession(V, dealing.sharing, share, "test");
            try threshold.verify_proof_of_possession(V, dealing.sharing, "test", partial.*);
        }
        const signature = try threshold.recover(V, gpa, dealing.sharing, &partials);
        try ops.verify_proof_of_possession(V, dealing.sharing.public(), "test", signature);
    }
}

test "threshold: message" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 5);
        defer dealing.deinit(gpa);
        const message = [_]u8{ 1, 9, 6, 9 };
        const partials = try sign_all(V, dealing.shares, "test", &message);
        defer gpa.free(partials);
        for (partials) |partial| {
            try threshold.verify_message(V, dealing.sharing, "test", &message, partial);
        }
        const signature = try threshold.recover(V, gpa, dealing.sharing, partials);
        try ops.verify_message(V, dealing.sharing.public(), "test", &message, signature);
    }
}

test "threshold: recover from exactly a quorum" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 6);
        defer dealing.deinit(gpa);
        const t = utils.N3f1.quorum(@as(u32, 6));
        const partials = try sign_all(V, dealing.shares[0..t], "test", "payload");
        defer gpa.free(partials);
        const signature = try threshold.recover(V, gpa, dealing.sharing, partials);
        try ops.verify_message(V, dealing.sharing.public(), "test", "payload", signature);
    }
}

test "threshold: recover multiple" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 6);
        defer dealing.deinit(gpa);
        const t = utils.N3f1.quorum(@as(u32, 6));
        const first = try sign_all(V, dealing.shares[0..t], "test", "payload1");
        defer gpa.free(first);
        const second = try sign_all(V, dealing.shares[0..t], "test", "payload2");
        defer gpa.free(second);
        const pair = try threshold.recover_pair(V, gpa, dealing.sharing, first, second);
        const public = dealing.sharing.public();
        try ops.verify_message(V, public, "test", "payload1", pair[0]);
        try ops.verify_message(V, public, "test", "payload2", pair[1]);

        // Sets selecting different indices cannot share an interpolator.
        const shifted = try sign_all(V, dealing.shares[1 .. t + 1], "test", "payload2");
        defer gpa.free(shifted);
        try testing.expectError(
            error.InvalidIndex,
            threshold.recover_pair(V, gpa, dealing.sharing, first, shifted),
        );
    }
}

test "threshold: recover rejects a bad namespace" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 5);
        defer dealing.deinit(gpa);
        const partials = try sign_all(V, dealing.shares, "test", "hello");
        defer gpa.free(partials);
        for (partials) |partial| {
            try testing.expectError(
                error.InvalidSignature,
                threshold.verify_message(V, dealing.sharing, "bad", "hello", partial),
            );
        }
        const signature = try threshold.recover(V, gpa, dealing.sharing, partials);
        try testing.expectError(
            error.InvalidSignature,
            ops.verify_message(V, dealing.sharing.public(), "bad", "hello", signature),
        );
    }
}

test "threshold: recover needs a quorum of distinct indices" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 5);
        defer dealing.deinit(gpa);
        try testing.expectEqual(@as(u32, 4), dealing.sharing.required());
        const partials = try sign_all(V, dealing.shares[0..3], "test", "hello");
        defer gpa.free(partials);
        for (partials) |partial| {
            try threshold.verify_message(V, dealing.sharing, "test", "hello", partial);
        }
        try testing.expectError(
            error.NotEnoughPartialSignatures,
            threshold.recover(V, gpa, dealing.sharing, partials),
        );
        // A repeated index does not count twice.
        const repeated = [_]PartialSignature(V){
            partials[0], partials[1], partials[2], partials[2],
        };
        try testing.expectError(
            error.NotEnoughPartialSignatures,
            threshold.recover(V, gpa, dealing.sharing, &repeated),
        );
    }
}

test "threshold: a bad share fails verification" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 5);
        defer dealing.deinit(gpa);
        dealing.shares[3].private = Private.random(&rng);
        const partials = try sign_all(V, dealing.shares, "test", "hello");
        defer gpa.free(partials);
        for (partials, 0..) |partial, i| {
            const result = threshold.verify_message(V, dealing.sharing, "test", "hello", partial);
            if (i == 3) {
                try testing.expectError(error.InvalidSignature, result);
            } else try result;
        }
        // Recovery uses the lowest four indices, including the bad share.
        const signature = try threshold.recover(V, gpa, dealing.sharing, partials);
        try testing.expectError(
            error.InvalidSignature,
            ops.verify_message(V, dealing.sharing.public(), "test", "hello", signature),
        );
    }
}

fn expect_invalid(
    comptime V: type,
    rng: anytype,
    sharing: anytype,
    partials: []const PartialSignature(V),
    expected: []const u32,
) !void {
    const invalid = try threshold.batch_verify_same_message(
        V,
        gpa,
        rng,
        sharing,
        "test",
        "hello",
        partials,
    );
    defer gpa.free(invalid);
    try testing.expectEqual(expected.len, invalid.len);
    for (invalid, expected) |position, index| {
        try testing.expectEqual(index, partials[position].index.get());
    }
}

test "threshold: batch verify same message" {
    var rng = utils.test_rng();
    var dealing = try deal(MinSig, &rng, 5);
    defer dealing.deinit(gpa);
    const partials = try sign_all(MinSig, dealing.shares, "test", "hello");
    defer gpa.free(partials);
    dealing.sharing.precompute_partial_publics();
    try expect_invalid(MinSig, &rng, dealing.sharing, partials, &.{});
}

test "threshold: batch verify same message finds one invalid" {
    var rng = utils.test_rng();
    var dealing = try deal(MinSig, &rng, 5);
    defer dealing.deinit(gpa);
    dealing.shares[1].private = Private.random(&rng);
    const partials = try sign_all(MinSig, dealing.shares, "test", "hello");
    defer gpa.free(partials);
    dealing.sharing.precompute_partial_publics();
    try expect_invalid(MinSig, &rng, dealing.sharing, partials, &.{1});
}

test "threshold: batch verify same message finds many invalid" {
    var rng = utils.test_rng();
    var dealing = try deal(MinSig, &rng, 6);
    defer dealing.deinit(gpa);
    for ([_]usize{ 1, 3 }) |i| dealing.shares[i].private = Private.random(&rng);
    const partials = try sign_all(MinSig, dealing.shares, "test", "hello");
    defer gpa.free(partials);
    dealing.sharing.precompute_partial_publics();
    try expect_invalid(MinSig, &rng, dealing.sharing, partials, &.{ 1, 3 });
}

test "threshold: batch verify same message rejects an out-of-range index" {
    var rng = utils.test_rng();
    var dealing = try deal(MinSig, &rng, 5);
    defer dealing.deinit(gpa);
    const partials = try sign_all(MinSig, dealing.shares, "test", "hello");
    defer gpa.free(partials);
    partials[0].index = Participant.init(100);
    dealing.sharing.precompute_partial_publics();
    try expect_invalid(MinSig, &rng, dealing.sharing, partials, &.{100});
}

test "threshold: batch verify same message with one signer" {
    var rng = utils.test_rng();
    var dealing = try deal(MinSig, &rng, 1);
    defer dealing.deinit(gpa);
    const partials = try sign_all(MinSig, dealing.shares, "test", "hello");
    defer gpa.free(partials);
    try expect_invalid(MinSig, &rng, dealing.sharing, partials, &.{});
    dealing.shares[0].private = Private.random(&rng);
    const bad = try sign_all(MinSig, dealing.shares, "test", "hello");
    defer gpa.free(bad);
    try expect_invalid(MinSig, &rng, dealing.sharing, bad, &.{0});
}

test "threshold: batch verify same message finds the last invalid" {
    var rng = utils.test_rng();
    var dealing = try deal(MinSig, &rng, 5);
    defer dealing.deinit(gpa);
    dealing.shares[4].private = Private.random(&rng);
    const partials = try sign_all(MinSig, dealing.shares, "test", "hello");
    defer gpa.free(partials);
    try expect_invalid(MinSig, &rng, dealing.sharing, partials, &.{4});
}

fn signer_entries(
    comptime V: type,
    share: group.Share,
    pairs: []const [2][]const u8,
    out: []threshold.SignerEntry(V),
) void {
    for (out, pairs) |*entry, pair| {
        entry.* = .{
            .namespace = pair[0],
            .message = pair[1],
            .partial = threshold.sign_message(V, share, pair[0], pair[1]),
        };
    }
}

const same_namespace = [_][2][]const u8{ .{ "ns", "msg1" }, .{ "ns", "msg2" }, .{ "ns", "msg3" } };
const alt_namespace = [_][2][]const u8{
    .{ "alt", "msg1" },
    .{ "alt", "msg2" },
    .{ "alt", "msg3" },
};
const mixed_namespaces = [_][2][]const u8{
    .{ "ns1", "msg1" },
    .{ "ns2", "msg2" },
    .{ "ns3", "msg3" },
};

test "threshold: batch verify same signer" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 5);
        defer dealing.deinit(gpa);
        const sharing = dealing.sharing;
        const signer = dealing.shares[0];
        var entries: [3]threshold.SignerEntry(V) = undefined;
        signer_entries(V, signer, &same_namespace, &entries);
        try threshold.batch_verify_same_signer(V, gpa, &rng, sharing, signer.index, &entries);

        var alt: [3]threshold.SignerEntry(V) = undefined;
        signer_entries(V, signer, &alt_namespace, &alt);
        try threshold.batch_verify_same_signer(V, gpa, &rng, sharing, signer.index, &alt);

        var mixed: [3]threshold.SignerEntry(V) = undefined;
        signer_entries(V, signer, &mixed_namespaces, &mixed);
        try threshold.batch_verify_same_signer(V, gpa, &rng, sharing, signer.index, &mixed);

        try testing.expectError(
            error.InvalidSignature,
            threshold.batch_verify_same_signer(V, gpa, &rng, sharing, .init(1), &entries),
        );

        var swapped = entries;
        std.mem.swap(PartialSignature(V), &swapped[0].partial, &swapped[1].partial);
        try testing.expectError(
            error.InvalidSignature,
            threshold.batch_verify_same_signer(V, gpa, &rng, sharing, signer.index, &swapped),
        );

        var other_signer = entries;
        other_signer[0].partial = threshold.sign_message(V, dealing.shares[1], "ns", "msg1");
        try testing.expectError(
            error.InvalidSignature,
            threshold.batch_verify_same_signer(V, gpa, &rng, sharing, signer.index, &other_signer),
        );
    }
}

/// The Lagrange coefficient of `i` among `indices`, evaluated at `target`.
fn lagrange_coefficient(
    scalars: []const Scalar,
    target: Participant,
    i: Participant,
    indices: []const Participant,
) Scalar {
    var numerator = Scalar.one;
    var denominator = Scalar.one;
    const x = scalars[target.get()];
    const x_i = scalars[i.get()];
    for (indices) |j| {
        if (j.get() == i.get()) continue;
        const x_j = scalars[j.get()];
        numerator = numerator.mul(x.sub(x_j));
        denominator = denominator.mul(x_i.sub(x_j));
    }
    return numerator.mul(denominator.inv());
}

test "threshold: derive missing partials" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 5);
        defer dealing.deinit(gpa);
        const t = utils.N3f1.quorum(@as(u32, 5));
        const scalars = try dealing.sharing.mode.all_scalars(gpa, 5);
        defer gpa.free(scalars);
        const partials = try sign_all(V, dealing.shares, "test", "hello");
        defer gpa.free(partials);

        var indices: [5]Participant = undefined;
        var points: [5]V.Signature = undefined;
        for (indices[0..t], points[0..t], partials[0..t]) |*index, *point, partial| {
            index.* = partial.index;
            point.* = partial.value;
        }
        for (dealing.shares, partials) |target, original| {
            var weights: [5]Scalar = undefined;
            for (weights[0..t], indices[0..t]) |*weight, index| {
                weight.* = lagrange_coefficient(scalars, target.index, index, indices[0..t]);
            }
            const derived: PartialSignature(V) = .{
                .index = target.index,
                .value = V.Signature.msm(points[0..t], weights[0..t]),
            };
            try threshold.verify_message(V, dealing.sharing, "test", "hello", derived);
            try testing.expect(derived.value.eql(original.value));
        }
    }
}

test "threshold: batch verify same message rejects malleability" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 5);
        defer dealing.deinit(gpa);
        const sharing = dealing.sharing;
        const valid = [_]PartialSignature(V){
            threshold.sign_message(V, dealing.shares[0], "test", "message"),
            threshold.sign_message(V, dealing.shares[1], "test", "message"),
        };
        for (valid) |partial| try threshold.verify_message(V, sharing, "test", "message", partial);

        const delta = V.Signature.generator.mul(Scalar.random(&rng));
        const forged = [_]PartialSignature(V){
            .{ .index = valid[0].index, .value = valid[0].value.sub(delta) },
            .{ .index = valid[1].index, .value = valid[1].value.add(delta) },
        };
        for (forged) |partial| {
            try testing.expectError(
                error.InvalidSignature,
                threshold.verify_message(V, sharing, "test", "message", partial),
            );
        }
        const forged_sum = forged[0].value.add(forged[1].value);
        try testing.expect(forged_sum.eql(valid[0].value.add(valid[1].value)));
        // Naive aggregate verification accepts the forgery.
        const public_sum = (try sharing.partial_public(valid[0].index))
            .add(try sharing.partial_public(valid[1].index));
        const hm = ops.hash_with_namespace(V, V.message, "test", "message");
        try V.verify(public_sum, hm, forged_sum);

        const bad = try threshold.batch_verify_same_message(
            V,
            gpa,
            &rng,
            sharing,
            "test",
            "message",
            &forged,
        );
        defer gpa.free(bad);
        try testing.expect(bad.len > 0);
        const good = try threshold.batch_verify_same_message(
            V,
            gpa,
            &rng,
            sharing,
            "test",
            "message",
            &valid,
        );
        defer gpa.free(good);
        try testing.expectEqual(@as(usize, 0), good.len);
    }
}

test "threshold: batch verify same signer rejects malleability" {
    inline for (.{ MinPk, MinSig }) |V| {
        var rng = utils.test_rng();
        var dealing = try deal(V, &rng, 5);
        defer dealing.deinit(gpa);
        const sharing = dealing.sharing;
        const signer = dealing.shares[0];
        var valid: [2]threshold.SignerEntry(V) = undefined;
        signer_entries(V, signer, &.{ .{ "test", "message 1" }, .{ "test", "message 2" } }, &valid);
        for (valid) |entry| {
            try threshold.verify_message(V, sharing, "test", entry.message, entry.partial);
        }

        const delta = V.Signature.generator.mul(Scalar.random(&rng));
        var forged = valid;
        forged[0].partial.value = valid[0].partial.value.sub(delta);
        forged[1].partial.value = valid[1].partial.value.add(delta);
        for (forged) |entry| {
            try testing.expectError(
                error.InvalidSignature,
                threshold.verify_message(V, sharing, "test", entry.message, entry.partial),
            );
        }
        const forged_sum = forged[0].partial.value.add(forged[1].partial.value);
        try testing.expect(forged_sum.eql(valid[0].partial.value.add(valid[1].partial.value)));
        // Naive aggregate verification accepts the forgery.
        const public = try sharing.partial_public(signer.index);
        const hm = ops.hash_with_namespace(V, V.message, "test", "message 1")
            .add(ops.hash_with_namespace(V, V.message, "test", "message 2"));
        try V.verify(public, hm, forged_sum);

        try testing.expectError(
            error.InvalidSignature,
            threshold.batch_verify_same_signer(V, gpa, &rng, sharing, signer.index, &forged),
        );
        try threshold.batch_verify_same_signer(V, gpa, &rng, sharing, signer.index, &valid);
    }
}

fn expect_hex(expected: []const u8, actual: []const u8) !void {
    var buffer: [256]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&buffer, expected);
    try testing.expectEqualSlices(u8, bytes, actual);
}

/// Vectors from commonware: `deal_anonymous` with `test_rng()`, share 0, and the signature
/// recovered from every share's partial over ("test", "hello"). The sharing is compared by
/// the SHA-256 of its encoding.
fn expect_dealing_vector(
    comptime V: type,
    mode: sharing_mod.Mode,
    n: u32,
    sharing_length: usize,
    sharing_sha256: []const u8,
    share0: []const u8,
    signature: []const u8,
) !void {
    var rng = utils.test_rng();
    var dealing = try dkg.deal_anonymous(V, utils.N3f1, gpa, &rng, mode, n);
    defer dealing.deinit(gpa);
    const encoded = try codec.encode(sharing_mod.Sharing(V), gpa, dealing.sharing);
    defer gpa.free(encoded);
    try testing.expectEqual(sharing_length, encoded.len);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    try expect_hex(sharing_sha256, &digest);
    const share_bytes = try codec.encode(group.Share, gpa, dealing.shares[0]);
    defer gpa.free(share_bytes);
    try expect_hex(share0, share_bytes);
    const partials = try sign_all(V, dealing.shares, "test", "hello");
    defer gpa.free(partials);
    const recovered = try threshold.recover(V, gpa, dealing.sharing, partials);
    try expect_hex(signature, &recovered.to_bytes());
}

test "threshold: dealing and recovery match commonware" {
    try expect_dealing_vector(
        MinSig,
        .non_zero_counter,
        5,
        390,
        "b52c50cfd9d37de5fb5fb4fabe2eb6156a9674c1d492776915945b20fc387f6c",
        "006990f62c96eff9989eb29ce25d36c823efb0c08a9437847e1969f9f5235a990e",
        "a0fdbe29d957577074d42f8171cef536cfa5360b0a053ef8a8efbf5c76b78c22" ++
            "28ea17d6b378a133838906f82a3944ae",
    );
    try expect_dealing_vector(
        MinPk,
        .roots_of_unity,
        7,
        246,
        "1b939a8fb08f64d7c44ef889226a9a475894533b04f214bd747e8a70287a36e1",
        "006febc3b098a51e107c8b47259e1c9d191c7d97bff8cf0f3593ebac6e6d578f29",
        "b1e3b1a01e4b6fce02b40f77b43f87ce02f7a54c766f4dc160ae29fc25669c8d" ++
            "9feef1d6ad55dcdaca6f2bcb2161d928135389b60ed16bd1df50abde6a96cef5" ++
            "a7b9829ee5a61e9610d665da22d2f2ad72468aa3f52a54d6cf6b5f4fd49e2b42",
    );
}
