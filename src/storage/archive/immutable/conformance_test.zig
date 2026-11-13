//! Immutable archive codec conformance (`CodecConformance<Record>`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const immutable = @import("mod.zig");

const conformance_file = @embedFile("../../conformance.toml");

const RecordConformance = struct {
    const Record = immutable.Record;

    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const arena_gpa = arena.allocator();
        const record = try codec.arbitrary.generate(Record, Record.arbitrary, arena_gpa, seed);
        return codec.encode(Record, gpa, record);
    }
};

test "conformance CodecConformance<Record>" {
    try conformance.verify(
        RecordConformance,
        std.heap.smp_allocator,
        "commonware_storage::archive::immutable::storage::conformance::CodecConformance<Record>",
        conformance.default_cases,
        conformance_file,
    );
}
