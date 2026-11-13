//! `CodecConformance` hashes of the BLS12-381 types, checked against commonware's
//! cryptography `conformance.toml` (shared with the rest of the crate). Each generator ports
//! the type's Rust `Arbitrary` impl, so the 65536 encoded values match commonware's.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const primitives = @import("primitives/root.zig");
const tle = @import("tle.zig");

const arbitrary = codec.arbitrary;
const Unstructured = arbitrary.Unstructured;
const Error = arbitrary.Error;
const group = primitives.group;
const aggregate = primitives.ops.aggregate;
const Scalar = group.Scalar;
const MinPk = primitives.MinPk;
const MinSig = primitives.MinSig;

const conformance_file = @embedFile("../conformance.toml");
const prefix = "commonware_cryptography::bls12381::";

/// Every case multiplies a point by a scalar; Debug builds take minutes, so they run only in
/// optimized builds or with `-Dslow-tests`.
fn skip_slow() error{SkipZigTest}!void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
}

fn CodecConformance(comptime T: type, comptime gen: arbitrary.Generator(T)) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const value = try arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

fn verify(comptime name: []const u8, comptime T: type, comptime gen: arbitrary.Generator(T)) !void {
    try conformance.verify(
        CodecConformance(T, gen),
        std.heap.smp_allocator,
        prefix ++ name,
        conformance.default_cases,
        conformance_file,
    );
}

/// `Scalar::from_ikm(&u.arbitrary::<[u8; 64]>()?)`.
fn gen_scalar(gpa: Allocator, u: *Unstructured) Error!Scalar {
    const ikm = try arbitrary.value([64]u8, gpa, u);
    return Scalar.from_ikm(&ikm);
}

fn gen_private(gpa: Allocator, u: *Unstructured) Error!group.Private {
    return group.Private.init(try gen_scalar(gpa, u));
}

/// The derived `Participant(u32)`, then the private key.
fn gen_share(gpa: Allocator, u: *Unstructured) Error!group.Share {
    const index = utils.Participant.init(u.int(u32));
    return group.Share.init(index, try gen_private(gpa, u));
}

/// `G::generator() * &u.arbitrary::<Scalar>()?`.
fn gen_point(comptime G: type) arbitrary.Generator(G) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!G {
            return G.generator.mul(try gen_scalar(gpa, u));
        }
    }.generate;
}

fn gen_partial(comptime V: type) arbitrary.Generator(primitives.variant.PartialSignature(V)) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!primitives.variant.PartialSignature(V) {
            const index = utils.Participant.init(u.int(u32));
            return .{ .index = index, .value = try gen_point(V.Signature)(gpa, u) };
        }
    }.generate;
}

/// The aggregate wrappers hold one arbitrary point.
fn gen_wrapper(comptime W: type) arbitrary.Generator(W) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!W {
            const Element = @FieldType(W, "value");
            return .{ .value = try gen_point(Element)(gpa, u) };
        }
    }.generate;
}

/// A point, then two arbitrary 32-byte blocks.
fn gen_ciphertext(gpa: Allocator, u: *Unstructured) Error!tle.Ciphertext(MinPk) {
    const point = try gen_point(MinPk.Public)(gpa, u);
    const v = try arbitrary.value(tle.Block, gpa, u);
    const w = try arbitrary.value(tle.Block, gpa, u);
    return .{ .u = point, .v = v, .w = w };
}

test "conformance: bls12381 group scalars, keys, and shares" {
    try skip_slow();
    const module = "primitives::group::tests::conformance::";
    try verify(module ++ "CodecConformance<Scalar>", Scalar, gen_scalar);
    try verify(module ++ "CodecConformance<Private>", group.Private, gen_private);
    try verify(module ++ "CodecConformance<Share>", group.Share, gen_share);
}

test "conformance: bls12381 group points" {
    try skip_slow();
    const module = "primitives::group::tests::conformance::";
    try verify(module ++ "CodecConformance<G1>", group.G1, gen_point(group.G1));
    try verify(module ++ "CodecConformance<G2>", group.G2, gen_point(group.G2));
}

test "conformance: bls12381 partial signatures" {
    try skip_slow();
    const module = "primitives::variant::tests::conformance::";
    const PartialSignature = primitives.variant.PartialSignature;
    try verify(
        module ++ "CodecConformance<PartialSignature<MinPk>>",
        PartialSignature(MinPk),
        gen_partial(MinPk),
    );
    try verify(
        module ++ "CodecConformance<PartialSignature<MinSig>>",
        PartialSignature(MinSig),
        gen_partial(MinSig),
    );
}

test "conformance: bls12381 aggregates" {
    try skip_slow();
    const module = "primitives::ops::aggregate::tests::conformance::";
    const Public = aggregate.PublicKey(MinSig);
    const Signature = aggregate.Signature(MinSig);
    const Message = aggregate.Message(MinSig);
    try verify(module ++ "CodecConformance<PublicKey<MinSig>>", Public, gen_wrapper(Public));
    try verify(module ++ "CodecConformance<Signature<MinSig>>", Signature, gen_wrapper(Signature));
    try verify(module ++ "CodecConformance<Message<MinSig>>", Message, gen_wrapper(Message));
}

test "conformance: bls12381 tle ciphertext" {
    try skip_slow();
    try verify(
        "tle::tests::conformance::CodecConformance<Ciphertext<MinPk>>",
        tle.Ciphertext(MinPk),
        gen_ciphertext,
    );
}
