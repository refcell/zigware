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
/// compression, and a codec configuration bounding byte values to 10000 bytes (commonware's
/// `(0..=10000).into()`), both under the partition `cf-log`.
pub fn log_config(comptime LogCfg: type, cache_ref: *runtime.buffer.paged.CacheRef) LogCfg {
    if (comptime @hasField(LogCfg, "items_per_section")) {
        const CodecCfg = @FieldType(LogCfg, "codec_config");
        return .{
            .partition = "cf-log",
            .items_per_section = 7,
            .codec_config = codec_config(CodecCfg),
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

/// The codec configuration of a test operation: units stay units, and slices (a field
/// `range`) are bounded to 10000 items. Operation configurations nest at most one tuple deep.
pub fn codec_config(comptime C: type) C {
    if (comptime is_slice_cfg(C) or C == void) return leaf_config(C);
    var result: C = undefined;
    inline for (@typeInfo(C).@"struct".field_types, 0..) |field_type, index| {
        result[index] = leaf_config(field_type);
    }
    return result;
}

fn is_slice_cfg(comptime C: type) bool {
    return @typeInfo(C) == .@"struct" and @hasField(C, "range");
}

fn leaf_config(comptime C: type) C {
    if (comptime is_slice_cfg(C)) return .{ .range = .inclusive(0, 10000) };
    return codec.unit_cfg(C);
}

/// Expects each `{name, value}` sample in `registry`'s encoding (commonware's
/// `metrics.contains("name value")` checks), printing the encoding on a miss.
pub fn expect_metric_values(
    gpa: Allocator,
    registry: *runtime.telemetry.metrics.Registry,
    expected: []const [2][]const u8,
) !void {
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    for (expected) |sample| {
        if (runtime.telemetry.metrics.has_metric_value(text, sample[0], sample[1])) continue;
        std.debug.print("missing {s} {s}\n{s}\n", .{ sample[0], sample[1], text });
        return error.TestExpectedEqual;
    }
}
