//! Shared helpers for QMDB tests: codec conformance against commonware's
//! `storage/conformance.toml`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");

pub const conformance_file = @embedFile("../conformance.toml");

/// commonware's `CodecConformance<T>`: encodes `T::arbitrary` for seeds `0..65536`. `T`
/// declares `arbitrary(gpa, *Unstructured)`.
pub fn CodecConformance(comptime T: type) type {
    return struct {
        fn generate(gpa: Allocator, u: *codec.arbitrary.Unstructured) codec.arbitrary.Error!T {
            return T.arbitrary(gpa, u);
        }

        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const value = try codec.arbitrary.generate(T, generate, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

/// Checks `CodecConformance(T)` against the hash recorded for `type_name`.
pub fn verify_codec(comptime T: type, type_name: []const u8) !void {
    try conformance.verify(
        CodecConformance(T),
        std.heap.smp_allocator,
        type_name,
        conformance.default_cases,
        conformance_file,
    );
}
