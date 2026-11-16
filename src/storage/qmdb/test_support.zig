//! Shared helpers for QMDB tests: codec conformance against commonware's
//! `storage/conformance.toml`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const runtime = @import("runtime");

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

/// Commonware's conformance log configuration for the database log type `LogCfg`: the fixed
/// journal with 7 items per blob, or the variable journal with 7 items per section, no
/// compression, and a unit codec configuration, both under the partition `cf-log`.
pub fn log_config(comptime LogCfg: type, cache_ref: *runtime.buffer.paged.CacheRef) LogCfg {
    if (comptime @hasField(LogCfg, "items_per_section")) {
        const CodecCfg = @FieldType(LogCfg, "codec_config");
        return .{
            .partition = "cf-log",
            .items_per_section = 7,
            .codec_config = codec.unit_cfg(CodecCfg),
            .cache_ref = cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
    }
    return .{
        .partition = "cf-log",
        .items_per_blob = 7,
        .cache_ref = cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
}
