//! Prunable archive codec conformance (`CodecConformance<Record<U64>>`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const prunable = @import("mod.zig");
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const storage_mod = struct {
    const translator = @import("../../translator.zig");
};

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

/// `StorageConformance<ArchivePrunableWorkload>`: 100 to 499 random 64-byte keys with random
/// `i32` values at consecutive indices, then a sync. Commits the storage audit.
const ArchivePrunableWorkload = struct {
    const A = prunable.Archive(storage_mod.translator.TwoCap, [64]u8, i32);

    fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var rng = utils.rng.TestRng.init(seed);
        var registry = metrics.Registry.init(gpa);
        defer registry.deinit();
        var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10);
        defer cache_ref.deinit();
        var names: [3][64]u8 = undefined;
        const kinds = [_][]const u8{ "metadata", "key", "value" };
        var partitions: [3][]const u8 = undefined;
        for (kinds, &names, &partitions) |kind, *buffer, *partition| {
            const format = "archive-prunable-{s}-{d}";
            partition.* = try std.fmt.bufPrint(buffer, format, .{ kind, seed });
        }
        var store = try A.init(gpa, storage, metrics.Scope.init(&registry).child("archive"), .{
            .translator = .{},
            .metadata_partition = partitions[0],
            .key_partition = partitions[1],
            .key_cache_ref = &cache_ref,
            .value_partition = partitions[2],
            .codec_config = {},
            .items_per_section = 1024,
            .key_write_buffer = 1024,
            .value_write_buffer = 1024,
            .replay_buffer = 1024,
        });
        defer store.deinit();
        const items_count = utils.rng.range_less_than(&rng, u32, 100, 500);
        for (0..items_count) |i| {
            var key: [64]u8 = undefined;
            rng.fill_bytes(&key);
            const value: i32 = @bitCast(rng.next_u32());
            try store.put(i, key, value);
        }
        try store.sync();
    }

    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var memory = runtime.storage.memory.Storage.init(gpa);
        defer memory.deinit();
        try run(gpa, memory.storage(), seed);
        const audit = memory.audit();
        return gpa.dupe(u8, &audit);
    }
};

test "conformance StorageConformance<ArchivePrunableWorkload>" {
    try conformance.verify(
        ArchivePrunableWorkload,
        std.testing.allocator,
        "commonware_storage::archive::conformance::StorageConformance<ArchivePrunableWorkload>",
        128,
        conformance_file,
    );
}
