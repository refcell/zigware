//! utils conformance (every `conformance_tests!` in commonware's utils crate).
//!
//! Each entry regenerates commonware's values with the shared `arbitrary` + ChaCha8 inputs
//! (`codec.arbitrary`), encodes them with zigware, and checks the SHA-256 against the hash in
//! commonware's `utils/conformance.toml` (copied here unchanged), through the shared
//! `conformance` harness.

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const arbitrary = codec.arbitrary;
const Unstructured = arbitrary.Unstructured;
const Error = arbitrary.Error;

const root = @import("root.zig");
const rng = @import("rng.zig");
const range = @import("range.zig");
const sequence = @import("sequence.zig");
const bitmap = @import("bitmap.zig");
const hostname = @import("hostname.zig");
const ordered = @import("ordered.zig");

const conformance_file = @embedFile("conformance.toml");
const prefix = "commonware_utils::";

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

fn Entry(comptime name: []const u8, comptime C: type, comptime cases: u64) type {
    return struct {
        const type_name = prefix ++ name;
        const Conformance = C;
        const n_cases = cases;
    };
}

fn Codec(comptime name: []const u8, comptime T: type, comptime gen: arbitrary.Generator(T)) type {
    return Entry(name, CodecConformance(T, gen), conformance.default_cases);
}

/// `#[derive(Arbitrary)]` on a newtype over a byte array: one byte per element.
fn gen_bytes(comptime T: type) arbitrary.Generator(T) {
    return struct {
        fn generate(_: Allocator, u: *Unstructured) Error!T {
            var result: T = undefined;
            u.fill(&result.bytes);
            return result;
        }
    }.generate;
}

fn gen_participant(_: Allocator, u: *Unstructured) Error!root.Participant {
    return .init(u.int(u32));
}

fn gen_vec_u64(_: Allocator, u: *Unstructured) Error!sequence.VecU64 {
    return .init(u.int(u64));
}

fn gen_unit(_: Allocator, _: *Unstructured) Error!sequence.Unit {
    return .{};
}

/// `NonEmptyRange::arbitrary`: two values, ordered; equal values are `IncorrectFormat`.
fn gen_range(comptime T: type) arbitrary.Generator(range.NonEmptyRange(T)) {
    return struct {
        fn generate(_: Allocator, u: *Unstructured) Error!range.NonEmptyRange(T) {
            const a = u.int(T);
            const b = u.int(T);
            return range.NonEmptyRange(T).init(@min(a, b), @max(a, b)) catch
                error.IncorrectFormat;
        }
    }.generate;
}

/// commonware's `FuzzRngConformance`: a seeded input of 1..=64 bytes, then 32 big-endian
/// `u64` output blocks.
const FuzzRngConformance = struct {
    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var seed_rng = rng.TestRng.init(seed);
        const len = rng.range_at_most(&seed_rng, usize, 1, 64);
        var input: [64]u8 = undefined;
        seed_rng.fill_bytes(input[0..len]);
        var generator = rng.FuzzRng.init(input[0..len]);
        const output = try gpa.alloc(u8, 32 * 8);
        for (0..32) |i| {
            std.mem.writeInt(u64, output[i * 8 ..][0..8], generator.next_u64(), .big);
        }
        return output;
    }
};

const sequence_path = "sequence::";
const conformance_suffix = "::tests::conformance::CodecConformance<";

const entries = .{
    Codec("tests::conformance::CodecConformance<Participant>", root.Participant, gen_participant),
    Codec(
        "range" ++ conformance_suffix ++ "NonEmptyRange<u32>>",
        range.NonEmptyRange(u32),
        gen_range(u32),
    ),
    Codec(
        "range" ++ conformance_suffix ++ "NonEmptyRange<u64>>",
        range.NonEmptyRange(u64),
        gen_range(u64),
    ),
    Codec(
        sequence_path ++ "fixed_bytes" ++ conformance_suffix ++ "FixedBytes<16>>",
        sequence.FixedBytes(16),
        gen_bytes(sequence.FixedBytes(16)),
    ),
    Codec(
        sequence_path ++ "u32" ++ conformance_suffix ++ "U32>",
        sequence.U32,
        gen_bytes(sequence.U32),
    ),
    Codec(
        sequence_path ++ "u64" ++ conformance_suffix ++ "U64>",
        sequence.U64,
        gen_bytes(sequence.U64),
    ),
    Codec(
        sequence_path ++ "prefixed_u64" ++ conformance_suffix ++ "U64>",
        sequence.PrefixedU64,
        gen_bytes(sequence.PrefixedU64),
    ),
    Codec(
        sequence_path ++ "vec_u64" ++ conformance_suffix ++ "VecU64>",
        sequence.VecU64,
        gen_vec_u64,
    ),
    Codec(
        sequence_path ++ "unit::test::conformance::CodecConformance<Unit>",
        sequence.Unit,
        gen_unit,
    ),
    Entry("rng::tests::conformance::FuzzRngConformance", FuzzRngConformance, 1024),
    Codec(
        "hostname" ++ conformance_suffix ++ "Hostname>",
        hostname.Hostname,
        arbitrary.default_generator(hostname.Hostname),
    ),
    Codec(
        "bitmap" ++ conformance_suffix ++ "BitMap>",
        bitmap.DefaultBitMap,
        arbitrary.default_generator(bitmap.DefaultBitMap),
    ),
    Codec(
        "ordered::test::conformance::CodecConformance<Set<u32>>",
        ordered.Set(u32),
        arbitrary.default_generator(ordered.Set(u32)),
    ),
    Codec(
        "ordered::test::conformance::CodecConformance<Map<u32,u32>>",
        ordered.Map(u32, u32),
        arbitrary.default_generator(ordered.Map(u32, u32)),
    ),
    Codec(
        "ordered::test::conformance::CodecConformance<BiMap<u32,u32>>",
        ordered.BiMap(u32, u32),
        arbitrary.default_generator(ordered.BiMap(u32, u32)),
    ),
    Codec(
        "bitmap::prunable" ++ conformance_suffix ++ "Prunable<16>>",
        bitmap.Prunable(16),
        arbitrary.default_generator(bitmap.Prunable(16)),
    ),
    Codec(
        "bitmap::roaring::container::array" ++ conformance_suffix ++ "super::Array>",
        bitmap.roaring.Array,
        arbitrary.default_generator(bitmap.roaring.Array),
    ),
    Codec(
        "bitmap::roaring::container::bitmap" ++ conformance_suffix ++ "super::Bitmap>",
        bitmap.roaring.Bitmap,
        arbitrary.default_generator(bitmap.roaring.Bitmap),
    ),
    Codec(
        "bitmap::roaring::container::run" ++ conformance_suffix ++ "super::Run>",
        bitmap.roaring.Run,
        arbitrary.default_generator(bitmap.roaring.Run),
    ),
    Codec(
        "bitmap::roaring::container" ++ conformance_suffix ++ "super::Container>",
        bitmap.roaring.Container,
        arbitrary.default_generator(bitmap.roaring.Container),
    ),
    Entry(
        "bitmap::roaring::container::tests::conformance::ContainerTransitionsConformance",
        @import("bitmap/roaring/container_test.zig").TransitionsConformance,
        1024,
    ),
};

test "utils conformance hashes match commonware" {
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
