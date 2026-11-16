//! Codec conformance (every `conformance_tests!` in commonware's clearing crate).
//!
//! Each entry regenerates commonware's 65536 values per type with the same `arbitrary` +
//! ChaCha8 inputs, encodes them with zigware, and checks the SHA-256 against the hash committed
//! in commonware's `clearing/conformance.toml` (copied unchanged to `src/clearing`). A match
//! proves the encodings are byte-identical to commonware's. Types that draw ed25519 keys or
//! signatures run thousands of scalar multiplications, so they skip in Debug unless
//! `-Dslow-tests`; CI's ReleaseSafe run checks them.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");
const codec = @import("codec");
const conformance = @import("conformance");
const arb = @import("arbitrary.zig");
const mod = @import("mod.zig");
const t = @import("testing.zig");

const conformance_file = @embedFile("../conformance.toml");
const prefix = "commonware_clearing::bajillion::";

const PublicKey = t.PublicKey;
const Digest = t.Digest;

fn skip_slow() error{SkipZigTest}!void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
}

fn CodecConformance(comptime T: type) type {
    return struct {
        fn gen(gpa: Allocator, u: *arb.Unstructured) arb.Error!T {
            return arb.value(T, gpa, u);
        }

        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const value = try codec.arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

fn verify(comptime name: []const u8, comptime T: type) !void {
    const entry = (try conformance.find(conformance_file, prefix ++ name)).?;
    try conformance.verify(
        CodecConformance(T),
        std.heap.smp_allocator,
        prefix ++ name,
        entry.n_cases,
        conformance_file,
    );
}

test "conformance: lookup" {
    try verify(
        "lookup::tests::conformance::CodecConformance<Lookup<u64,u64,Digest>>",
        mod.Lookup(u64, u64, Digest),
    );
}

test "conformance: amounts" {
    try skip_slow();
    try verify(
        "amounts::tests::conformance::CodecConformance<Amounts<PublicKey,u64>>",
        mod.Amounts(PublicKey, u64),
    );
}

test "conformance: matrix opening" {
    try skip_slow();
    try verify(
        "matrix::tests::conformance::CodecConformance<Opening<PublicKey,Digest,u64>>",
        mod.Opening(PublicKey, Digest, u64),
    );
}
