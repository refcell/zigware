//! Prunable archive codec conformance (`CodecConformance<Record<U64>>`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const prunable = @import("mod.zig");

const conformance_file = @embedFile("../../conformance.toml");

const RecordConformance = struct {
    const Record = prunable.Record(utils.sequence.U64);

    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const gen = codec.arbitrary.default_generator(Record);
        const record = try codec.arbitrary.generate(Record, gen, arena.allocator(), seed);
        return codec.encode(Record, gpa, record);
    }
};

test "conformance CodecConformance<Record<U64>>" {
    try conformance.verify(
        RecordConformance,
        std.heap.smp_allocator,
        "commonware_storage::archive::prunable::storage::conformance::" ++
            "CodecConformance<Record<U64>>",
        conformance.default_cases,
        conformance_file,
    );
}
