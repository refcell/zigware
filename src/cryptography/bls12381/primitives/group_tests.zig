//! Tests for `group.zig` (commonware `group.rs` tests). Fixed vectors come from
//! commonware's `group` module (blst) with `test_rng()`: three `Scalar::random` draws and
//! their G1/G2 multiples, then one `SmallScalar::random` draw.

const std = @import("std");
const build_options = @import("build_options");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const math = @import("math");
const group = @import("group.zig");

const Scalar = group.Scalar;
const SmallScalar = group.SmallScalar;
const G1 = group.G1;
const G2 = group.G2;
const Private = group.Private;
const Share = group.Share;
const minifuzz = @import("invariants").minifuzz;
const test_suites = math.algebra.test_suites;
const hex = @import("formatting").hex_literal;

const random_vectors = [3]struct { scalar: []const u8, g1: []const u8, g2: []const u8 }{
    .{
        .scalar = "2d55f3211a910b5f94f364129a1febef26c143284cfeee8a8d36a2e2468e9a96",
        .g1 = "976ab7efaef8a73690b9067690ac7541bc34f74b2543e8db16b5bf63aec48775" ++
            "8ca98efdf5c9fcf1154941d8a8a1ec3d",
        .g2 = "92b050b6fbe80695b5d56835e978918e37c8707a7fad09a01ae782d4c3170c9b" ++
            "aa4c2c196b36eac6b78ceb210b287aeb0727ef1c60e48042142f7bcc8b638230" ++
            "5cd50c5a4542c44ec72a4de6640c194f8ef36bea1dbed168ab6fd8681d910d55",
    },
    .{
        .scalar = "4b6c6d7834416e2a93b5a5cba71c9f0cb1c39c9ddd5fc9c36278ab00e5c9f8f0",
        .g1 = "a5ed658fa332b6447dc79c38e93bfb71af9d5b34d86e5db516c212fc4c55a06a" ++
            "840bcaa90beb063cf874405e869eb3fc",
        .g2 = "849792f18a43831c6a7716111804696e343c28d61e77c1efc4c80e703aee30ad" ++
            "7b0b81bcea55f26fa995e525a220d88d0e94d704f5775bf41486524f9dcb9401" ++
            "0b835678243c67fabe6497f2477915c6e526d07f299902d6d0e818e20e1e82f0",
    },
    .{
        .scalar = "2dbb6b50586cf49bb1b9ef0a52c7ea7fc1c51578ece1acff4cf2f5826680161e",
        .g1 = "a82ebac606db6fcc5e413f886cdf7b19e3cef4adb47c574cbc9e08a8cd600320" ++
            "019641293cdde9271fd44db6e20e069b",
        .g2 = "98c6e82fdf8990fa8b78df3788c45d4a36d83dd6c4e619b7b746abe12891427d" ++
            "d93ccd2d00596b8a87a5b084578fd2cf0a1f3a02672f4b370b2601e6425f873e" ++
            "afeb10a62adaa093b503a8630b89994c5f1401e62001896d2bd4f858be2cb941",
    },
};

fn expect_hex(comptime expected: []const u8, actual: []const u8) !void {
    try testing.expectEqualSlices(u8, &hex(expected), actual);
}

test "group: random scalars and generator multiples match commonware" {
    var rng = utils.test_rng();
    inline for (random_vectors) |vector| {
        const scalar = Scalar.random(&rng);
        try expect_hex(vector.scalar, &scalar.to_bytes());
        try expect_hex(vector.g1, &G1.generator.mul(scalar).to_bytes());
        try expect_hex(vector.g2, &G2.generator.mul(scalar).to_bytes());
    }
    // commonware's `as_bytes` is blst's little-endian scalar.
    const small = SmallScalar.random(&rng);
    var little = small.to_bytes();
    std.mem.reverse(u8, &little);
    try expect_hex(
        "7a95e009bf5704d8a3438bd0e15e4e8d00000000000000000000000000000000",
        &little,
    );
}

test "group: KeyGen matches EIP-2333 derive_master_SK" {
    // blst_keygen is EIP-2333's master key derivation (test case 0).
    const seed = hex("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553" ++
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
    const expected: u256 =
        6083874454709270928345386274498605044986640685124978867557563392430687146096;
    try testing.expectEqual(expected, Scalar.from_ikm(&seed).fr.to_int());
}

test "group: pairing of generators matches blst GT encoding" {
    const gt = group.pairing(G1.generator, G2.generator);
    const bytes = gt.to_bytes();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &digest, .{});
    try expect_hex(
        "1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7" ++
            "b6d194f60839c508a84305aaca1789b6",
        bytes[0..48],
    );
    try expect_hex(
        "4bb3f049849e856bd6879346f3978c28b031a407701c01ebb19d74a35c645520",
        &digest,
    );
}

test "group: scalar map and hash to group match commonware" {
    const scalar = Scalar.map("TEST_DST", "test message");
    try expect_hex(
        "2c474eb62605ad7021386b90f520a765568b9f2d8a651da3247088afab5dcb05",
        &scalar.to_bytes(),
    );
    try expect_hex(
        "aa3e260a3827d39c2c4e0a39015f1528ea78e9b63a27cf687d6fcc811b5a738c" ++
            "723a3d8dcddef2b0a9b615484c8a100a",
        &G1.hash_to_group(group.g1_message, "msg").to_bytes(),
    );
    try expect_hex(
        "b0bd37e06aa96922ebed9335ed3b530f701abf5b3ae39673e23bd72558bcded0" ++
            "8c27284d4b992258d41ce58f3c45657c0c592ec57ea12349370aa65aa6f8d1a8" ++
            "60dc081daa1a0cd2d26fda9aef364911750dd9c8aa290b0bad454854b95929aa",
        &G2.hash_to_group(group.g2_message, "msg").to_bytes(),
    );
}

fn field_body(_: void, u: *minifuzz.Unstructured) anyerror!void {
    try test_suites.fuzz_field_ntt(Scalar, u);
}

fn g1_space_body(_: void, u: *minifuzz.Unstructured) anyerror!void {
    try test_suites.fuzz_space_ring(Scalar, G1, u);
}

fn g2_space_body(_: void, u: *minifuzz.Unstructured) anyerror!void {
    try test_suites.fuzz_space_ring(Scalar, G2, u);
}

fn hash_body(_: void, u: *minifuzz.Unstructured) anyerror!void {
    try test_suites.fuzz_hash_to_group(G1, u);
    try test_suites.fuzz_hash_to_group(G2, u);
}

/// Runs a minifuzz body over `cases` inputs (times `-Dfuzz-soak`). Point arithmetic is slow
/// in Debug builds, so these use fewer cases than commonware's time-bounded default.
fn fuzz_cases(cases: u64, body: fn (void, *minifuzz.Unstructured) anyerror!void) !void {
    try (minifuzz.Builder{}).with_search_limit(cases * build_options.fuzz_soak)
        .run(testing.allocator, {}, body);
}

test "group: scalar is a field with an NTT domain" {
    try fuzz_cases(200, field_body);
}

test "group: G1 and G2 are spaces over the scalars" {
    try fuzz_cases(8, g1_space_body);
    try fuzz_cases(4, g2_space_body);
}

test "group: hash to group is deterministic and separating" {
    try fuzz_cases(8, hash_body);
}

test "group: basic group doubling" {
    var rng = utils.test_rng();
    const s = Scalar.random(&rng);
    const p1 = G1.generator.mul(s.double());
    const p2 = G1.generator.mul(s).double();
    try testing.expect(p1.eql(p2));
}

test "group: scalar codec round trip and zero handling" {
    var rng = utils.test_rng();
    const original = Scalar.random(&rng);
    const encoded = try codec.encode(Scalar, testing.allocator, original);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(@as(usize, 32), encoded.len);
    const decoded = try codec.decode_cfg(Scalar, testing.allocator, encoded, .reject_zero);
    try testing.expect(original.eql(decoded));

    const zero_bytes: [32]u8 = @splat(0);
    const zero = try codec.decode_cfg(Scalar, testing.allocator, &zero_bytes, .allow_zero);
    try testing.expect(zero.eql(Scalar.zero));
    try testing.expectError(
        error.Invalid,
        codec.decode_cfg(Scalar, testing.allocator, &zero_bytes, .reject_zero),
    );
    try testing.expectError(error.Invalid, codec.decode(Private, testing.allocator, &zero_bytes));
    const high: [32]u8 = @splat(0xff);
    try testing.expectError(
        error.Invalid,
        codec.decode_cfg(Scalar, testing.allocator, &high, .allow_zero),
    );
    // r itself is the smallest non-canonical encoding.
    var modulus: [32]u8 = undefined;
    std.mem.writeInt(u256, &modulus, r_value, .big);
    try testing.expectError(
        error.Invalid,
        codec.decode_cfg(Scalar, testing.allocator, &modulus, .allow_zero),
    );
}

const r_value = @import("arithmetic/root.zig").fields.r;

test "group: scalar sqrt, squares, and sign" {
    var rng = utils.test_rng();
    for (0..16) |_| {
        const square = Scalar.random(&rng).square();
        try testing.expect(square.is_square());
        const root = square.sqrt() orelse return error.MissingRoot;
        try testing.expect(root.square().eql(square));
        const s = Scalar.random(&rng);
        try testing.expect(s.is_positive() != s.neg().is_positive());
    }
    var found = false;
    var value: u64 = 2;
    while (value < 100) : (value += 1) {
        const s = Scalar.from_u64(value);
        if (!s.is_square()) {
            try testing.expect(s.sqrt() == null);
            found = true;
            break;
        }
    }
    try testing.expect(found);
    try testing.expect(Scalar.one.is_square());
    try testing.expect(!Scalar.zero.is_square());
    try testing.expect(Scalar.zero.sqrt().?.eql(Scalar.zero));
    try testing.expect(!Scalar.one.is_positive());
    try testing.expect(Scalar.one.neg().is_positive());
}

test "group: NTT constants" {
    const root = Scalar.root_of_unity(32).?;
    try testing.expect(math.algebra.exp(Scalar, root, &.{@as(u64, 1) << 32}).eql(Scalar.one));
    try testing.expect(!math.algebra.exp(Scalar, root, &.{@as(u64, 1) << 31}).eql(Scalar.one));
    try testing.expect(Scalar.root_of_unity(33) == null);
    try testing.expect(Scalar.coset_shift().eql(Scalar.from_u64(7)));
    try testing.expect(Scalar.coset_shift().mul(Scalar.coset_shift_inv()).eql(Scalar.one));
    try testing.expect(Scalar.from_u64(2).mul(Scalar.one.div_2()).eql(Scalar.one));
    try testing.expect(Scalar.from_limbs(.{ 7, 0, 0, 0 }).eql(Scalar.from_u64(7)));
}

fn expect_point_round_trip(comptime P: type, point: P) !void {
    const encoded = try codec.encode(P, testing.allocator, point);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(P.fixed_size, encoded.len);
    const decoded = try codec.decode(P, testing.allocator, encoded);
    try testing.expect(point.eql(decoded));
}

test "group: point codecs round trip and reject identity" {
    var rng = utils.test_rng();
    const s = Scalar.random(&rng);
    try expect_point_round_trip(G1, G1.generator.mul(s));
    try expect_point_round_trip(G2, G2.generator.mul(s));
    var g1_zero: [48]u8 = G1.zero.to_bytes();
    try testing.expectEqual(@as(u8, 0xc0), g1_zero[0]);
    try testing.expectError(error.Invalid, codec.decode(G1, testing.allocator, &g1_zero));
    const g2_zero = G2.zero.to_bytes();
    try testing.expectError(error.Invalid, codec.decode(G2, testing.allocator, &g2_zero));
    // Missing compression bit, and infinity with the sign bit set.
    g1_zero[0] = 0x40;
    try testing.expectError(error.Invalid, codec.decode(G1, testing.allocator, &g1_zero));
    g1_zero[0] = 0xe0;
    try testing.expectError(error.Invalid, codec.decode(G1, testing.allocator, &g1_zero));
}

test "group: points outside the subgroup are rejected" {
    const arithmetic = @import("arithmetic/root.zig");
    const off_g1 = arithmetic.g1.compress(arithmetic.g1.test_point_off_subgroup(1));
    try testing.expectError(error.Invalid, codec.decode(G1, testing.allocator, &off_g1));
    const off_g2 = arithmetic.g2.compress(arithmetic.g2.test_point_off_subgroup(1));
    try testing.expectError(error.Invalid, codec.decode(G2, testing.allocator, &off_g2));
}

fn naive_msm(comptime P: type, points: []const P, scalars: []const Scalar) P {
    var total = P.zero;
    for (points, scalars) |point, scalar| total = total.add(point.mul(scalar));
    return total;
}

fn check_msm(comptime P: type, count: usize) !void {
    var rng = utils.test_rng();
    const points = try testing.allocator.alloc(P, count);
    defer testing.allocator.free(points);
    const scalars = try testing.allocator.alloc(Scalar, count);
    defer testing.allocator.free(scalars);
    for (points, scalars) |*point, *scalar| {
        point.* = P.generator.mul(Scalar.random(&rng));
        scalar.* = Scalar.random(&rng);
    }
    try testing.expect(P.msm(points, scalars).eql(naive_msm(P, points, scalars)));
    if (count < 2) return;
    // An identity point and a zero scalar contribute nothing.
    points[count / 2] = P.zero;
    scalars[0] = Scalar.zero;
    try testing.expect(P.msm(points, scalars).eql(naive_msm(P, points, scalars)));
    @memset(scalars, Scalar.zero);
    try testing.expect(P.msm(points, scalars).eql(P.zero));
    @memset(points, P.zero);
    try testing.expect(P.msm(points, scalars).eql(P.zero));
}

test "group: msm matches the naive sum" {
    try testing.expect(G1.msm(&.{}, @as([]const Scalar, &.{})).eql(G1.zero));
    for ([_]usize{ 1, 10, 300 }) |count| try check_msm(G1, count);
    for ([_]usize{ 1, 10 }) |count| try check_msm(G2, count);
}

test "group: msm over small scalars" {
    var rng = utils.test_rng();
    var points: [6]G1 = undefined;
    var smalls: [6]SmallScalar = undefined;
    var expected = G1.zero;
    for (&points, &smalls) |*point, *small| {
        point.* = G1.generator.mul(Scalar.random(&rng));
        small.* = SmallScalar.random(&rng);
        expected = expected.add(point.mul(small.to_scalar()));
    }
    try testing.expect(G1.msm(&points, &smalls).eql(expected));
    try testing.expect(points[0].mul(smalls[0]).eql(points[0].mul(smalls[0].to_scalar())));
}

test "group: small scalar zero and conversion" {
    var zero_rng = utils.rng.ScriptedRng.init(&.{ 0, 0 });
    const small = SmallScalar.random(&zero_rng);
    try testing.expect(small.eql(SmallScalar.zero));
    try testing.expect(small.to_scalar().eql(Scalar.zero));
    var rng = utils.test_rng();
    const other = SmallScalar.random(&rng);
    try testing.expectEqualSlices(u8, &other.to_bytes(), &other.to_scalar().to_bytes());
}

test "group: ordering follows the encoding" {
    var rng = utils.test_rng();
    var scalars: [10]Scalar = undefined;
    var points: [10]G1 = undefined;
    for (&scalars, &points) |*scalar, *point| {
        scalar.* = Scalar.random(&rng);
        point.* = G1.generator.mul(scalar.*);
    }
    std.mem.sort(Scalar, &scalars, {}, Scalar.less_than);
    std.mem.sort(G1, &points, {}, G1.less_than);
    for (scalars[0..9], scalars[1..], points[0..9], points[1..]) |a, b, p, q| {
        try testing.expect(std.mem.order(u8, &a.to_bytes(), &b.to_bytes()) == .lt);
        try testing.expect(std.mem.order(u8, &p.to_bytes(), &q.to_bytes()) == .lt);
    }
}

test "group: share codec and redaction" {
    var rng = utils.test_rng();
    const share = Share.init(utils.Participant.init(1), Private.random(&rng));
    const encoded = try codec.encode(Share, testing.allocator, share);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(@as(usize, 33), encoded.len);
    const decoded = try codec.decode(Share, testing.allocator, encoded);
    try testing.expect(share.eql(decoded));
    var buffer: [128]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{share});
    try testing.expect(std.mem.indexOf(u8, text, "REDACTED") != null);
    const scalar_text = try std.fmt.bufPrint(&buffer, "{f}", .{share.private.scalar.value});
    try testing.expectEqualStrings("[REDACTED]", scalar_text);
}

test "group: scalar map separates messages and tags" {
    const a = Scalar.map("TEST_DST", "test message");
    try testing.expect(a.eql(Scalar.map("TEST_DST", "test message")));
    try testing.expect(!a.eql(Scalar.map("TEST_DST", "different message")));
    try testing.expect(!a.eql(Scalar.map("DIFFERENT_DST", "test message")));
    try testing.expect(!Scalar.map("TEST_DST", "").eql(Scalar.zero));
    const large: [1000]u8 = @splat(0x42);
    try testing.expect(!Scalar.map("TEST_DST", &large).eql(Scalar.zero));
}
