//! curve25519 conformance (every `conformance_tests!` in commonware-cryptography-curve25519).
//!
//! Each entry regenerates commonware's values with the shared `arbitrary` + ChaCha8 inputs,
//! encodes them with zigware, and checks the SHA-256 against the hash in the crate's
//! `conformance.toml` (copied here unchanged).

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const arbitrary = codec.arbitrary;

const signing = @import("signing.zig");
const key_exchange = @import("key_exchange.zig");

const conformance_file = @embedFile("conformance.toml");
const prefix = "commonware_cryptography_curve25519::";

fn Codec(comptime name: []const u8, comptime T: type, comptime cases: u64) type {
    return struct {
        const type_name = prefix ++ name;
        const n_cases = cases;
        const Conformance = struct {
            pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
                const generator = arbitrary.default_generator(T);
                const value = try arbitrary.generate(T, generator, gpa, seed);
                return codec.encode(T, gpa, value);
            }
        };
    };
}

const signing_path = "signing::tests::conformance::CodecConformance<";
const exchange_path = "key_exchange::tests::conformance::CodecConformance<";

const entries = .{
    Codec(exchange_path ++ "PublicKey>", key_exchange.PublicKey, conformance.default_cases),
    Codec(signing_path ++ "Signature>", signing.Signature, conformance.default_cases),
    Codec(signing_path ++ "SigningKey>", signing.SigningKey, 1024),
    Codec(signing_path ++ "VerifyingKey>", signing.VerifyingKey, conformance.default_cases),
};

test "curve25519 conformance hashes match commonware" {
    // About 13 s in Debug (65536 point decodings); CI runs ReleaseSafe, as cryptography does.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    inline for (entries) |entry| {
        try conformance.verify(
            entry.Conformance,
            std.heap.smp_allocator,
            entry.type_name,
            entry.n_cases,
            conformance_file,
        );
    }
}
