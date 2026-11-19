//! Tests of `batch`: commonware's `batch_coefficients_*`, `group_ranges_*`, and the MSM's
//! `canonical_edge_terms_match_bitwise_multiplication` and `matches_naive_double_and_add`, plus
//! batch verdicts across chunk boundaries and offsetting forgeries, which only colliding
//! coefficients would accept.

const std = @import("std");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const batch = @import("batch.zig");
const signing = @import("signing.zig");
const core = cryptography.ed25519.core;
const testing = std.testing;
const gpa = testing.allocator;
const Point = core.Point;
const scalar = Point.scalar;
const SigningKey = signing.SigningKey;
const VerifyingKey = signing.VerifyingKey;

test "curve25519 batch: coefficients are deterministic and block dependent" {
    const seed: [32]u8 = @splat(7);
    const again = batch.batch_coefficients(&seed, 0);
    try testing.expectEqualDeep(again, batch.batch_coefficients(&seed, 0));
    const first = batch.batch_coefficients(&seed, 0)[0];
    try testing.expect(!std.mem.eql(u8, &first, &batch.batch_coefficients(&seed, 1)[0]));
    const other: [32]u8 = @splat(8);
    try testing.expect(!std.mem.eql(u8, &first, &batch.batch_coefficients(&other, 0)[0]));
}

test "curve25519 batch: coefficients are SHA-512(seed || u64_le(block)) in 16-byte lanes" {
    const seed: [32]u8 = @splat(0x5a);
    for ([_]u64{ 0, 1, 2, 0x0102_0304_0506_0708, std.math.maxInt(u64) - 1 }) |block| {
        var input: [40]u8 = undefined;
        input[0..32].* = seed;
        std.mem.writeInt(u64, input[32..40], block, .little);
        var digest: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(&input, &digest, .{});
        const coefficients = batch.batch_coefficients(&seed, block);
        for (coefficients, 0..) |coefficient, lane| {
            try testing.expectEqualSlices(u8, digest[lane * 16 ..][0..16], coefficient[0..16]);
            try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), coefficient[16..32]);
        }
    }
}

test "curve25519 batch: group_end groups adjacent equal keys" {
    // commonware's group_ranges cases, as (key byte) in sorted order.
    const keys = [_][32]u8{ @splat(1), @splat(1), @splat(2), @splat(3), @splat(3), @splat(3) };
    const order = [_]u8{ 0, 1, 2, 3, 4, 5 };
    try testing.expectEqual(2, batch.group_end(&keys, &order, 0));
    try testing.expectEqual(3, batch.group_end(&keys, &order, 2));
    try testing.expectEqual(6, batch.group_end(&keys, &order, 3));
    const distinct = [_][32]u8{ @splat(1), @splat(2) };
    try testing.expectEqual(1, batch.group_end(&distinct, order[0..2], 0));
    try testing.expectEqual(2, batch.group_end(&distinct, order[0..2], 1));
}

/// Bitwise double-and-add, independent of every MSM.
fn naive_mul(point: Point, s: [32]u8) Point {
    var result = Point.identityElement;
    var bit: usize = 256;
    while (bit > 0) {
        bit -= 1;
        result = result.dbl();
        if ((s[bit / 8] >> @intCast(bit % 8)) & 1 == 1) result = result.add(point);
    }
    return result;
}

/// `point` with Z = 1, as the MSM takes it: re-decoded from its encoding.
fn affine(point: Point) Point {
    return core.decompress(point.toBytes()).?;
}

fn expect_point(expected: Point, actual: Point) !void {
    try testing.expectEqualSlices(u8, &expected.toBytes(), &actual.toBytes());
}

/// Zero, one, the largest 128-bit value, `2^252` and its neighbors, and `L - 1`.
fn edge_scalars() [7][32]u8 {
    var top = scalar.zero;
    top[31] = 0x10;
    var one = scalar.zero;
    one[0] = 1;
    var max128 = scalar.zero;
    @memset(max128[0..16], 0xff);
    return .{
        scalar.zero,
        one,
        max128,
        scalar.sub(top, one),
        top,
        scalar.add(top, one),
        scalar.neg(one),
    };
}

test "curve25519 batch: signed digits recompose every edge scalar" {
    for (edge_scalars()) |s| {
        const digits = batch.signed_digits(&s);
        var value: i512 = 0;
        var window: usize = batch.windows;
        while (window > 0) {
            window -= 1;
            value = value * (1 << batch.width) + digits[window];
        }
        try testing.expectEqual(@as(i512, std.mem.readInt(u256, &s, .little)), value);
    }
}

test "curve25519 batch: edge terms match bitwise multiplication" {
    const torsion = core.decompress(@splat(0)).?;
    const points = [_]Point{ Point.basePoint, torsion, affine(Point.basePoint.add(torsion)) };
    for (edge_scalars()) |s| {
        for (points) |point| {
            var terms: batch.Terms = .init();
            terms.add(point, &s);
            try expect_point(naive_mul(point, s), terms.sum());
        }
    }
}

test "curve25519 batch: a full chunk of terms matches naive double-and-add" {
    var rng = utils.TestRng.init(3);
    const terms = try gpa.create(batch.Terms);
    defer gpa.destroy(terms);
    terms.* = .init();
    var expected = Point.identityElement;
    for (0..2 * batch.chunk_signatures + 1) |index| {
        var seed: [64]u8 = undefined;
        rng.fill_bytes(&seed);
        var point = affine(Point.basePoint.mulPublic(scalar.reduce64(seed)) catch unreachable);
        // Every eighth point carries a torsion component, as an adversary's keys may.
        if (index % 8 == 0) point = affine(point.add(core.decompress(@splat(0)).?));
        rng.fill_bytes(&seed);
        // Short scalars leave the high windows empty, as the `z` terms do.
        const s = if (index % 3 == 0) scalar.reduce64(seed) else blk: {
            var short = scalar.zero;
            short[0..16].* = seed[0..16].*;
            break :blk short;
        };
        terms.add(point, &s);
        expected = expected.add(naive_mul(point, s));
    }
    try expect_point(expected, terms.sum());
}

/// Raw signatures over 8-byte messages, every third by one repeated signer.
const Signatures = struct {
    const capacity = 300;
    keys: [capacity]VerifyingKey,
    signatures: [capacity]signing.Signature,
    messages: [capacity][8]u8,
    count: usize,

    fn create(count: usize) !*Signatures {
        std.debug.assert(count <= capacity);
        const set = try gpa.create(Signatures);
        var rng = utils.TestRng.init(count);
        const repeated = SigningKey.random(&rng);
        set.count = count;
        for (0..count) |i| {
            std.mem.writeInt(u64, &set.messages[i], i, .little);
            const signer = if (i % 3 == 0) repeated else SigningKey.random(&rng);
            set.keys[i] = signer.verifying_key();
            set.signatures[i] = signer.sign_raw(&set.messages[i]);
        }
        return set;
    }

    fn verify(set: *const Signatures, strategy: anytype) bool {
        var entries: [capacity]VerifyingKey.RawEntry = undefined;
        for (0..set.count) |i| {
            entries[i] = .{
                .key = &set.keys[i],
                .signature = &set.signatures[i],
                .message = &set.messages[i],
            };
        }
        var rng = utils.test_rng();
        return VerifyingKey.verify_batch_raw(&rng, entries[0..set.count], strategy);
    }

    /// The verdict under every strategy shape, which must agree with the sequential one.
    fn verify_explored(set: *const Signatures) !bool {
        const Op = struct {
            set: *const Signatures,
            pub fn run(op: @This(), explorer: parallel.mocks.Explorer) bool {
                return op.set.verify(explorer);
            }
        };
        const verdict = try parallel.mocks.explore(gpa, testing.io, Op{ .set = set });
        try testing.expectEqual(set.verify(parallel.sequential), verdict);
        return verdict;
    }
};

test "curve25519 batch: verdicts across chunk boundaries" {
    const set = try Signatures.create(300);
    defer gpa.destroy(set);
    try testing.expect(try set.verify_explored());
    // 300 signatures split into chunks of 100 on one thread; 127 and 128 straddle a full
    // chunk's edge on shards of 150.
    for ([_]usize{ 0, 99, 100, 127, 128, 149, 150, 299 }) |position| {
        set.messages[position][7] ^= 1;
        defer set.messages[position][7] ^= 1;
        try testing.expect(!set.verify(parallel.sequential));
    }
    set.messages[128][7] ^= 1;
    defer set.messages[128][7] ^= 1;
    try testing.expect(!try set.verify_explored());
}

/// Moves `delta B` from signature `left`'s `s` to signature `right`'s: each signature is now
/// invalid, but the batch equation still holds whenever `z_left == z_right`.
fn offset(set: *Signatures, left: usize, right: usize) void {
    var delta = scalar.zero;
    delta[0] = 1;
    const left_s = set.signatures[left].bytes[32..64];
    const right_s = set.signatures[right].bytes[32..64];
    left_s.* = scalar.add(left_s.*, delta);
    right_s.* = scalar.sub(right_s.*, delta);
}

test "curve25519 batch: offsetting forgeries reject on both MSM paths" {
    // 20 signatures take Straus and 150 the buckets. Every pair of the first eight shares a
    // coefficient block or straddles one; the last pair sits in different chunks.
    for ([_]usize{ 20, 150 }) |count| {
        const set = try Signatures.create(count);
        defer gpa.destroy(set);
        try testing.expect(set.verify(parallel.sequential));
        const original = set.signatures;
        for (0..8) |left| {
            for (left + 1..8) |right| {
                defer set.signatures = original;
                offset(set, left, right);
                testing.expect(!set.verify(parallel.sequential)) catch |err| {
                    std.debug.print("count {d}, pair {d} {d}\n", .{ count, left, right });
                    return err;
                };
            }
        }
        offset(set, 5, count - 1);
        try testing.expect(!set.verify(parallel.sequential));
    }
}
