//! `CodecConformance` hashes of the math types (every `conformance_tests!` in commonware's math
//! crate: the test field and group, goldilocks, `Poly`, and the NTT `Matrix`).
//!
//! Each entry regenerates commonware's 65536 values with the same `arbitrary` + ChaCha8 inputs,
//! using a port of the type's Rust `Arbitrary` impl, encodes them with zigware, and checks the
//! SHA-256 against `conformance.toml` (copied unchanged from commonware).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const arbitrary = codec.arbitrary;
const Unstructured = arbitrary.Unstructured;
const Error = arbitrary.Error;
const testing = @import("testing.zig");
const Goldilocks = @import("fields/goldilocks.zig").F;
const Poly = @import("poly.zig").Poly;
const Matrix = @import("ntt.zig").Matrix;

const conformance_file = @embedFile("conformance.toml");
const prefix = "commonware_math::";

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
    comptime assert(name.len > 0);
    try conformance.verify(
        CodecConformance(T, gen),
        std.heap.smp_allocator,
        prefix ++ name,
        conformance.default_cases,
        conformance_file,
    );
}

/// The test field `F`: `u64::arbitrary % P`.
fn gen_test_f(_: Allocator, u: *Unstructured) Error!testing.F {
    return testing.F.from_u64(u.int(u64));
}

/// The test group `G`: the generator times an arbitrary `F`.
fn gen_test_g(gpa: Allocator, u: *Unstructured) Error!testing.G {
    return testing.G.generator.mul(try gen_test_f(gpa, u));
}

/// Goldilocks `F`: `reduce_64(u64::arbitrary)`.
fn gen_goldilocks(_: Allocator, u: *Unstructured) Error!Goldilocks {
    return Goldilocks.from_u64(u.int(u64));
}

/// `Poly<F>` over the test field: one coefficient, then arbitrary's `Vec<F>` (a continuation
/// bit before each further coefficient).
fn gen_poly(gpa: Allocator, u: *Unstructured) Error!Poly(testing.F) {
    var coeffs: std.ArrayList(testing.F) = .empty;
    try coeffs.append(gpa, try gen_test_f(gpa, u));
    // Each continuation consumes a byte until the data runs out, then reads zero: bounded.
    while (u.keep_going()) try coeffs.append(gpa, try gen_test_f(gpa, u));
    assert(coeffs.items.len >= 1);
    return .from_owned(coeffs.items);
}

/// `Matrix<F>` over goldilocks: rows and cols each in `1..=16`, then `rows * cols` elements.
fn gen_matrix(gpa: Allocator, u: *Unstructured) Error!Matrix(Goldilocks) {
    const rows = u.int_in_range(usize, 1, 16);
    const cols = u.int_in_range(usize, 1, 16);
    assert(rows >= 1 and cols >= 1);
    const data = try gpa.alloc(Goldilocks, rows * cols);
    for (data) |*element| element.* = try gen_goldilocks(gpa, u);
    return .{ .rows = rows, .cols = cols, .data = data };
}

test "conformance: test field and group" {
    try verify("test::test::conformance::CodecConformance<F>", testing.F, gen_test_f);
    try verify("test::test::conformance::CodecConformance<G>", testing.G, gen_test_g);
}

test "conformance: goldilocks" {
    const name = "fields::goldilocks::test::conformance::CodecConformance<F>";
    try verify(name, Goldilocks, gen_goldilocks);
}

test "conformance: poly" {
    const name = "poly::test::conformance::CodecConformance<Poly<F>>";
    try verify(name, Poly(testing.F), gen_poly);
}

test "conformance: ntt matrix" {
    const name = "ntt::test::conformance::CodecConformance<Matrix<F>>";
    try verify(name, Matrix(Goldilocks), gen_matrix);
}
