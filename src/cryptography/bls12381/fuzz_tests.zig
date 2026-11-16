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

const minifuzz = invariants.minifuzz;
const Unstructured = minifuzz.Unstructured;
const MinPk = primitives.MinPk;

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
