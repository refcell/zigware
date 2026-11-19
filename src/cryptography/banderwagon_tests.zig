//! Tests for `banderwagon.zig` (commonware `banderwagon.rs` tests), including the official
//! go-ipa / rust-verkle serialization vectors for successive doublings of the generator.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const math = @import("math");
const minifuzz = @import("invariants").minifuzz;
const hex = @import("formatting").hex_literal;
const banderwagon = @import("banderwagon.zig");
const circuit = @import("zk/circuit.zig");
const shared = @import("bls12381/conformance_test.zig");

const F = banderwagon.F;
const G = banderwagon.G;
const GVar = banderwagon.GVar;
const Base = banderwagon.Base;
const Var = banderwagon.Var;
const BoolVar = banderwagon.BoolVar;
const Context = banderwagon.Context;
const Unstructured = minifuzz.Unstructured;
const test_suites = math.algebra.test_suites;
const gpa = testing.allocator;

const test_dst = "COMMONWARE_BANDERWAGON_HASH_TO_CURVE_TEST";

/// Runs a minifuzz body over `cases` inputs (times `-Dfuzz-soak`). Point arithmetic is slow
/// in Debug builds, so these use fewer cases than commonware's time-bounded default.
fn fuzz_cases(cases: u64, body: fn (void, *Unstructured) anyerror!void) !void {
    try (minifuzz.Builder{}).with_search_limit(cases * build_options.fuzz_soak)
        .run(gpa, {}, body);
}

fn arbitrary_point(u: *Unstructured) !G {
    return G.generator.mul(F.from_u64(try u.arbitrary(u64)));
}

/// commonware's `u.arbitrary::<Scalar>()` with zero replaced by one.
fn arbitrary_lambda(u: *Unstructured) !Base {
    const lambda = try u.arbitrary(Base);
    return if (lambda.eql(Base.zero)) Base.one else lambda;
}

fn scaled(p: G, lambda: Base) G {
    return .{
        .x = p.x.mul(lambda),
        .y = p.y.mul(lambda),
        .t = p.t.mul(lambda),
        .z = p.z.mul(lambda),
    };
}

fn twin(p: G) G {
    return .{ .x = p.x.neg(), .y = p.y.neg(), .t = p.t, .z = p.z };
}

fn encode(p: G) [32]u8 {
    return codec.encode_fixed(G, p);
}

fn expect_round_trip(p: G) !void {
    const encoded = encode(p);
    try testing.expect((try codec.decode(G, gpa, &encoded)).eql(p));
}

test "banderwagon: constants match their canonical values" {
    const expect_int = struct {
        fn run(value: Base, expected: u256) !void {
            try testing.expectEqual(expected, value.to_int());
        }
    }.run;
    try expect_int(banderwagon.curve_a, Base.one.neg().to_int() - 4);
    const generator_x: u256 = 0x29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18;
    const generator_y: u256 = 0x2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166;
    try expect_int(G.generator.x, generator_x);
    try expect_int(G.generator.y, generator_y);
    try testing.expect(G.generator.t.eql(G.generator.x.mul(G.generator.y)));
    // The generator is on the curve: a x^2 + y^2 == 1 + d x^2 y^2.
    const x_sq = G.generator.x.square();
    const y_sq = G.generator.y.square();
    const left = banderwagon.curve_a.mul(x_sq).add(y_sq);
    try testing.expect(left.eql(Base.one.add(banderwagon.curve_d.mul(x_sq).mul(y_sq))));
}

fn field_body(_: void, u: *Unstructured) anyerror!void {
    try test_suites.fuzz_field(F, u);
}

test "banderwagon: field laws" {
    try fuzz_cases(200, field_body);
}

test "banderwagon: random is canonical and covers the full range" {
    var rng = utils.test_rng();
    var saw_top_bit = false;
    for (0..1000) |_| {
        const f = F.random(&rng);
        try testing.expect(f.value < F.r);
        saw_top_bit = saw_top_bit or f.bits()[F.bit_count - 1];
    }
    try testing.expect(saw_top_bit);
}

fn f_round_trip_body(_: void, u: *Unstructured) anyerror!void {
    const f = try u.arbitrary(F);
    const encoded = codec.encode_fixed(F, f);
    try testing.expect((try codec.decode(F, gpa, &encoded)).eql(f));
}

test "banderwagon: F codec round trip" {
    try fuzz_cases(200, f_round_trip_body);
}

test "banderwagon: F codec rejects non-canonical" {
    var modulus: [32]u8 = undefined;
    std.mem.writeInt(u256, &modulus, F.r, .little);
    try testing.expectError(error.Invalid, codec.decode(F, gpa, &modulus));
    const high: [32]u8 = @splat(0xff);
    try testing.expectError(error.Invalid, codec.decode(F, gpa, &high));
}

fn modulus_body(_: void, u: *Unstructured) anyerror!void {
    const a = try u.arbitrary(F);
    const b = try u.arbitrary(F);
    try testing.expect(G.generator.mul(a).mul(b).eql(G.generator.mul(a.mul(b))));
}

test "banderwagon: field modulus matches the group order" {
    try fuzz_cases(8, modulus_body);
}

test "banderwagon: eq identity" {
    try testing.expect(G.zero.eql(G.zero));
}

fn reflexive_body(_: void, u: *Unstructured) anyerror!void {
    const p = try arbitrary_point(u);
    try testing.expect(p.eql(p));
}

fn projective_body(_: void, u: *Unstructured) anyerror!void {
    const p = try arbitrary_point(u);
    const lambda = try arbitrary_lambda(u);
    try testing.expect(p.eql(scaled(p, lambda)));
}

fn two_torsion_body(_: void, u: *Unstructured) anyerror!void {
    const p = try arbitrary_point(u);
    try testing.expect(p.eql(twin(p)));
}

fn distinct_body(_: void, u: *Unstructured) anyerror!void {
    const p = try arbitrary_point(u);
    try testing.expect(!p.eql(p.add(G.generator)));
}

test "banderwagon: eq is reflexive" {
    try fuzz_cases(32, reflexive_body);
}

test "banderwagon: eq is invariant under projective scaling" {
    try fuzz_cases(32, projective_body);
}

test "banderwagon: eq is invariant under two-torsion" {
    try fuzz_cases(32, two_torsion_body);
}

test "banderwagon: distinct points are not equal" {
    try fuzz_cases(32, distinct_body);
}

test "banderwagon: codec fixed size" {
    try testing.expectEqual(32, codec.fixed_size(G).?);
}

test "banderwagon: identity round trips as zero bytes" {
    const encoded = encode(G.zero);
    try testing.expectEqualSlices(u8, &@as([32]u8, @splat(0)), &encoded);
    try expect_round_trip(G.zero);
}

test "banderwagon: generator round trips" {
    try expect_round_trip(G.generator);
}

test "banderwagon: hash_to_group is deterministic and in the subgroup" {
    const p = G.hash_to_group(test_dst, "hello");
    const q = G.hash_to_group(test_dst, "hello");
    try testing.expect(p.eql(q));
    try expect_round_trip(p);
}

// Vectors from commonware (a Rust run): hash_to_group outputs, and the first two
// `F::random(test_rng())` draws with the sender key `[x_send] G`.
test "banderwagon: hash_to_group and random match commonware" {
    @setEvalBranchQuota(20_000);
    const cases = [_]struct { []const u8, [32]u8 }{
        .{ "hello", hex("296f61c4ac671ee68eda33fd61420c4ff2fc89a972e30fb9bb97b66df649e095") },
        .{ "", hex("03d733379aecb1baa7d414eb61ebe3cd7c1b1630d98f8552afe9a1e41dddedee") },
        .{ "message-a", hex("712a9fe3720b8a68db018e00376202eeb411afb0dd2440bc500ea892c27e1e78") },
    };
    for (cases) |case| {
        try testing.expectEqualSlices(u8, &case[1], &encode(G.hash_to_group(test_dst, case[0])));
    }
    const parts = G.hash_to_group_parts(test_dst, &.{ "mess", "", "age-a" });
    try testing.expectEqualSlices(u8, &cases[2][1], &encode(parts));

    var rng = utils.test_rng();
    const x_send = F.random(&rng);
    const x_recv = F.random(&rng);
    const want_send = hex("7f6f2ccdb23f2abb7b69278e947c01c6160a31cf02c19d06d0f6e5ab1d768b15");
    const want_recv = hex("117be1de549d1d4322c4711f11efa0c5137903124f85fc37c761ffc91ace300b");
    try testing.expectEqualSlices(u8, &want_send, &codec.encode_fixed(F, x_send));
    try testing.expectEqualSlices(u8, &want_recv, &codec.encode_fixed(F, x_recv));
    const sender = hex("6bfb93450486a31bdb7ca55a2da315523894f55dea49210377d93610b216479b");
    try testing.expectEqualSlices(u8, &sender, &encode(G.generator.mul(x_send)));
}

test "banderwagon: hash_to_group separates messages" {
    const p = G.hash_to_group(test_dst, "message-a");
    const q = G.hash_to_group(test_dst, "message-b");
    try testing.expect(!p.eql(q));
}

/// arbitrary 1.4's `Vec<u8>`: each byte is preceded by a continuation bool.
fn arbitrary_vec(u: *Unstructured, list: *std.ArrayList(u8)) !void {
    while (try u.arbitrary(bool)) {
        try list.append(gpa, try u.arbitrary(u8));
    }
}

fn hash_subgroup_body(_: void, u: *Unstructured) anyerror!void {
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(gpa);
    try arbitrary_vec(u, &message);
    try expect_round_trip(G.hash_to_group(test_dst, message.items));
}

fn hash_laws_body(_: void, u: *Unstructured) anyerror!void {
    try test_suites.fuzz_hash_to_group(G, u);
}

test "banderwagon: hash_to_group output is in the subgroup" {
    try fuzz_cases(32, hash_subgroup_body);
}

test "banderwagon: hash_to_group laws" {
    try fuzz_cases(32, hash_laws_body);
}

test "banderwagon: codec fixed vectors" {
    // Serializations of G, 2G, 4G, ... (crate-crypto/rust-verkle
    // `banderwagon::element::fixed_test_vectors`), matching go-ipa / Ethereum Verkle.
    @setEvalBranchQuota(100_000);
    const expected = [_][32]u8{
        hex("4a2c7486fd924882bf02c6908de395122843e3e05264d7991e18e7985dad51e9"),
        hex("43aa74ef706605705989e8fd38df46873b7eae5921fbed115ac9d937399ce4d5"),
        hex("5e5f550494159f38aa54d2ed7f11a7e93e4968617990445cc93ac8e59808c126"),
        hex("0e7e3748db7c5c999a7bcd93d71d671f1f40090423792266f94cb27ca43fce5c"),
        hex("14ddaa48820cb6523b9ae5fe9fe257cbbd1f3d598a28e670a40da5d1159d864a"),
        hex("6989d1c82b2d05c74b62fb0fbdf8843adae62ff720d370e209a7b84e14548a7d"),
        hex("26b8df6fa414bf348a3dc780ea53b70303ce49f3369212dec6fbe4b349b832bf"),
        hex("37e46072db18f038f2cc7d3d5b5d1374c0eb86ca46f869d6a95fc2fb092c0d35"),
        hex("2c1ce64f26e1c772282a6633fac7ca73067ae820637ce348bb2c8477d228dc7d"),
        hex("297ab0f5a8336a7a4e2657ad7a33a66e360fb6e50812d4be3326fab73d6cee07"),
        hex("5b285811efa7a965bd6ef5632151ebf399115fcc8f5b9b8083415ce533cc39ce"),
        hex("1f939fa2fd457b3effb82b25d3fe8ab965f54015f108f8c09d67e696294ab626"),
        hex("3088dcb4d3f4bacd706487648b239e0be3072ed2059d981fe04ce6525af6f1b8"),
        hex("35fbc386a16d0227ff8673bc3760ad6b11009f749bb82d4facaea67f58fc60ed"),
        hex("00f29b4f3255e318438f0a31e058e4c081085426adb0479f14c64985d0b956e0"),
        hex("3fa4384b2fa0ecc3c0582223602921daaa893a97b64bdf94dcaa504e8b7b9e5f"),
    };
    var point = G.generator;
    for (expected) |want| {
        try testing.expectEqualSlices(u8, &want, &encode(point));
        try testing.expect((try codec.decode(G, gpa, &want)).eql(point));
        point = point.double();
    }
}

fn round_trip_body(_: void, u: *Unstructured) anyerror!void {
    try expect_round_trip(try arbitrary_point(u));
}

fn twin_encoding_body(_: void, u: *Unstructured) anyerror!void {
    const p = try arbitrary_point(u);
    try testing.expectEqualSlices(u8, &encode(p), &encode(twin(p)));
}

fn scaled_encoding_body(_: void, u: *Unstructured) anyerror!void {
    const p = try arbitrary_point(u);
    const lambda = try arbitrary_lambda(u);
    try testing.expectEqualSlices(u8, &encode(p), &encode(scaled(p, lambda)));
}

test "banderwagon: codec round trip" {
    try fuzz_cases(32, round_trip_body);
}

test "banderwagon: codec is canonical for the twin" {
    try fuzz_cases(32, twin_encoding_body);
}

test "banderwagon: codec is canonical under projective scaling" {
    try fuzz_cases(32, scaled_encoding_body);
}

test "banderwagon: read boundaries" {
    const encoded = encode(G.generator);
    for (0..32) |len| {
        var reader: codec.Reader = .init(encoded[0..len]);
        try testing.expectError(error.EndOfBuffer, codec.read(G, gpa, &reader));
        try testing.expectEqual(len, reader.remaining());
    }

    const extended = encoded ++ [1]u8{42};
    var reader: codec.Reader = .init(&extended);
    try testing.expect((try codec.read(G, gpa, &reader)).eql(G.generator));
    try testing.expectEqualSlices(u8, &.{42}, reader.rest());

    const high: [33]u8 = @splat(0xff);
    reader = .init(&high);
    try testing.expectError(error.Invalid, codec.read(G, gpa, &reader));
    try testing.expectEqualStrings("Banderwagon", reader.diagnostic.context);
    try testing.expectEqualStrings("x not a canonical field element", reader.diagnostic.message);
    try testing.expectEqualSlices(u8, &.{0xff}, reader.rest());
}

test "banderwagon: decode rejects a non-canonical field element" {
    // The big-endian bytes of the BLS12-381 scalar modulus.
    const modulus = hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    try testing.expectError(error.Invalid, codec.decode(G, gpa, &modulus));
    const high: [32]u8 = @splat(0xff);
    try testing.expectError(error.Invalid, codec.decode(G, gpa, &high));
}

fn off_subgroup_body(_: void, u: *Unstructured) anyerror!void {
    const x = try u.arbitrary(Base);
    const numerator = Base.one.sub(x.square().mul(banderwagon.curve_a));
    if (!numerator.eql(Base.zero) and !numerator.is_square()) {
        const bytes = codec.encode_fixed(Base, x);
        try testing.expectError(error.Invalid, codec.decode(G, gpa, &bytes));
    }
}

test "banderwagon: decode rejects points off the subgroup" {
    try fuzz_cases(64, off_subgroup_body);
}

/// Builds `[scalar] base` in circuit, asserts it equals `expected` with the quotient-aware
/// `GVar.assert_eq`, and reports whether the circuit is satisfied. `witness` chooses
/// whether the scalar is a witness (exercising `scalar_bits_le`) or a constant.
fn run_scalar_mul(base: G, scalar: Base, expected: G, witness: bool) !bool {
    var ctx: Context = try .init(gpa, .uniform(1 << 15), .prover);
    errdefer ctx.deinit(gpa);
    const s = if (witness) Var.witness_value(&ctx, scalar) else Var.constant(&ctx, scalar);
    base.scalar_mul(&ctx, s).assert_eq(GVar.constant(expected));
    var valued, const indices = try ctx.finish_valued(gpa, &.{});
    defer valued.deinit(gpa);
    defer gpa.free(indices);
    return valued.is_satisfied();
}

test "banderwagon: scalar_mul for small scalars" {
    try shared.skip_slow();
    const scalars = [_]u64{ 0, 1, 2, 3, 4, 7, 8, 15, 16, 1_000_000, std.math.maxInt(u64) };
    for (scalars) |k| {
        const expected = math.algebra.scale(G, G.generator, &.{k});
        try testing.expect(try run_scalar_mul(G.generator, Base.from_u64(k), expected, false));
        try testing.expect(try run_scalar_mul(G.generator, Base.from_u64(k), expected, true));
    }
}

test "banderwagon: scalar_mul rejects a wrong result" {
    const correct = math.algebra.scale(G, G.generator, &.{5});
    const wrong = correct.add(G.generator);
    try testing.expect(try run_scalar_mul(G.generator, Base.from_u64(5), correct, true));
    try testing.expect(!try run_scalar_mul(G.generator, Base.from_u64(5), wrong, true));
}

fn scalar_mul_random_body(_: void, u: *Unstructured) anyerror!void {
    const base = try arbitrary_point(u);
    const scalar = try u.arbitrary(Base);
    // Scale by the scalar's canonical integer, the one `scalar_mul` decomposes in circuit.
    const value = scalar.to_int();
    var words: [4]u64 = undefined;
    for (&words, 0..) |*word, index| word.* = @truncate(value >> @intCast(64 * index));
    const expected = math.algebra.scale(G, base, &words);
    try testing.expect(try run_scalar_mul(base, scalar, expected, true));
}

test "banderwagon: scalar_mul for random bases and scalars" {
    try fuzz_cases(if (builtin.mode == .debug) 2 else 8, scalar_mul_random_body);
}

// Not in commonware's banderwagon tests (golden exercises them): the windowed and squared
// gadgets agree with their native counterparts.
test "banderwagon: windowed and squared gadgets agree with native" {
    const bases = [_]G{ G.generator, G.hash_to_group(test_dst, "second") };
    const k: u64 = 0b1011_0110_1101;
    var ctx: Context = try .init(gpa, .uniform(1 << 15), .prover);
    errdefer ctx.deinit(gpa);
    var bits: [12]BoolVar = undefined;
    for (&bits, 0..) |*bit, index| {
        bit.* = BoolVar.witness_value(&ctx, (k >> @intCast(index)) & 1 == 1);
    }
    var out: [bases.len]GVar = undefined;
    try banderwagon.scalar_mul_many_in_circuit(gpa, 5, &bases, &bits, &out);
    for (bases, out) |base, result| result.assert_eq(GVar.constant(base.mul(F.from_u64(k))));
    const scalar = Var.witness_value(&ctx, Base.from_u64(k));
    const squared = G.generator.scalar_mul_x_squared(&ctx, scalar);
    squared.assert_eq(Var.native(G.generator.scalar_mul_x_squared_base(Base.from_u64(k))));
    try testing.expect(G.generator.scalar_mul_x_squared_f(F.from_u64(k))
        .eql(G.generator.scalar_mul_x_squared_base(Base.from_u64(k))));
    var valued, const indices = try ctx.finish_valued(gpa, &.{});
    defer valued.deinit(gpa);
    defer gpa.free(indices);
    try testing.expect(valued.is_satisfied());
    try testing.expect(valued.circuit.assertions.len > 0);
}

/// Decoder fuzz (not a commonware target): every accepted `G` or `F` encoding is canonical,
/// so it re-encodes to the same bytes, and a decoded point is a subgroup element.
fn decode_body(_: void, u: *Unstructured) anyerror!void {
    const bytes = try u.arbitrary([32]u8);
    if (codec.decode(G, gpa, &bytes)) |point| {
        try testing.expectEqualSlices(u8, &bytes, &encode(point));
        try testing.expect(point.eql(point.canonicalize()));
    } else |err| try testing.expectEqual(error.Invalid, err);
    if (codec.decode(F, gpa, &bytes)) |scalar| {
        try testing.expectEqualSlices(u8, &bytes, &codec.encode_fixed(F, scalar));
    } else |err| try testing.expectEqual(error.Invalid, err);
}

test "banderwagon fuzz: decode" {
    try fuzz_cases(256, decode_body);
}

test "banderwagon fuzz: decode (coverage-guided)" {
    try testing.fuzz({}, math.testing.smith_body(void, decode_body), .{});
}

fn index_of(v: Var) circuit.CircuitIdx {
    return v.inner.circuit.idx;
}

/// Probes the circuit's sizes: a fresh witness and a fresh constant report how many of each
/// were allocated before them.
fn expect_shape(ctx: *Context, outputs: []const Var, expected: []const circuit.CircuitIdx) !void {
    var indices: [8]circuit.CircuitIdx = undefined;
    for (outputs, 0..) |output, position| indices[position] = index_of(output);
    indices[outputs.len] = index_of(Var.witness_value(ctx, Base.one));
    indices[outputs.len + 1] = index_of(Var.constant(ctx, Base.from_u64(2)));
    const count = outputs.len + 2;
    try testing.expectEqual(expected.len, count);
    for (expected, indices[0..count]) |want, got| try testing.expect(want.eql(got));
}

fn finish_satisfied(ctx: *Context) !bool {
    var valued, const indices = try ctx.finish_valued(gpa, &.{});
    defer valued.deinit(gpa);
    defer gpa.free(indices);
    return valued.is_satisfied();
}

// The output indices commonware's `build_with_values` returns for the same gadget calls
// (from a Rust run), so the circuits match node for node.
test "banderwagon: scalar_mul_x_squared builds commonware's circuit" {
    var ctx: Context = try .init(gpa, .uniform(1 << 14), .prover);
    errdefer ctx.deinit(gpa);
    const s = Var.witness_value(&ctx, Base.from_u64(12345));
    const out = G.generator.scalar_mul_x_squared(&ctx, s);
    try expect_shape(&ctx, &.{out}, &.{
        .{ .node = 7628 }, .{ .witness = 764 }, .{ .constant = 3685 },
    });
    try testing.expect(try finish_satisfied(&ctx));
}

test "banderwagon: scalar_mul_many_in_circuit builds commonware's circuit" {
    var ctx: Context = try .init(gpa, .uniform(1 << 12), .prover);
    errdefer ctx.deinit(gpa);
    const k: u64 = 0b10_1101_0110;
    var bits: [10]BoolVar = undefined;
    for (&bits, 0..) |*bit, index| {
        bit.* = BoolVar.witness_value(&ctx, (k >> @intCast(index)) & 1 == 1);
    }
    const bases = [_]G{ G.generator, G.hash_to_group(test_dst, "second") };
    var out: [bases.len]GVar = undefined;
    try banderwagon.scalar_mul_many_in_circuit(gpa, 4, &bases, &bits, &out);
    const outputs = [_]Var{ out[0].x_squared(), out[1].x_squared() };
    try expect_shape(&ctx, &outputs, &.{
        .{ .node = 409 }, .{ .node = 410 }, .{ .witness = 22 }, .{ .constant = 198 },
    });
    try testing.expect(try finish_satisfied(&ctx));
}

test "banderwagon: scalar_mul_bits and scalar_bits_le build commonware's circuit" {
    var ctx: Context = try .init(gpa, .uniform(1 << 12), .prover);
    errdefer ctx.deinit(gpa);
    var bits: [6]BoolVar = undefined;
    for (&bits, 0..) |*bit, index| bit.* = BoolVar.witness_value(&ctx, index % 2 == 0);
    const out = G.hash_to_group(test_dst, "third").scalar_mul_bits(&bits).x_squared();
    const s = Var.witness_value(&ctx, Base.from_u64(3).neg());
    const decomposed = banderwagon.scalar_bits_le(&ctx, s);
    const last = decomposed[254].var_value().mul(decomposed[0].var_value());
    try expect_shape(&ctx, &.{ out, last }, &.{
        .{ .node = 140 }, .{ .node = 1161 }, .{ .witness = 272 }, .{ .constant = 448 },
    });
    try testing.expect(try finish_satisfied(&ctx));
}

test "banderwagon canonical affine batch matches canonicalize per point" {
    var rng = utils.test_rng();
    const base = G.generator.mul(F.random(&rng));
    var points: [33]G = undefined;
    points[0] = G.zero;
    for (points[1..], 0..) |*point, previous| point.* = points[previous].add(base);
    // A negated twin has the other sign of `y`, so both branches run.
    points[7] = points[7].neg();
    var xs: [points.len]Base = undefined;
    var ys: [points.len]Base = undefined;
    G.canonical_affine_batch(&points, &xs, &ys);
    var negated: usize = 0;
    for (points, xs, ys) |point, x, y| {
        const expected_x, const expected_y = point.canonicalize().affine();
        try testing.expect(x.eql(expected_x) and y.eql(expected_y));
        _, const raw_y = point.affine();
        if (!raw_y.eql(y)) negated += 1;
    }
    try testing.expect(negated > 0 and negated < points.len);
}
