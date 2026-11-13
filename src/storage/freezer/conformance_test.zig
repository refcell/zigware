//! Freezer codec conformance (commonware's `freezer/storage.rs` `CodecConformance` hashes).

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const freezer = @import("mod.zig");

const conformance_file = @embedFile("../conformance.toml");
const prefix = "commonware_storage::freezer::storage::conformance::CodecConformance<";

fn CodecConformance(comptime T: type) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const gen = codec.arbitrary.default_generator(T);
            const value = try codec.arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

fn verify(comptime T: type, comptime name: []const u8) !void {
    try conformance.verify(
        CodecConformance(T),
        std.heap.smp_allocator,
        prefix ++ name ++ ">",
        conformance.default_cases,
        conformance_file,
    );
}

test "conformance CodecConformance<Checkpoint>" {
    try verify(freezer.Checkpoint, "Checkpoint");
}

test "conformance CodecConformance<Cursor>" {
    try verify(freezer.Cursor, "Cursor");
}

test "conformance CodecConformance<Entry>" {
    try verify(freezer.Entry, "Entry");
}

test "conformance CodecConformance<Record<U64>>" {
    try verify(freezer.Record(utils.sequence.U64), "Record<U64>");
}
