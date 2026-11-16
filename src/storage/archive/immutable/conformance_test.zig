//! Immutable archive codec conformance (`CodecConformance<Record>`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const immutable = @import("mod.zig");
const utils = @import("utils");
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;

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

/// `StorageConformance<ArchiveImmutableWorkload>`: 100 to 499 random 64-byte keys with random
/// `i32` values at consecutive indices, then a sync. Commits the storage audit.
const ArchiveImmutableWorkload = struct {
    const A = immutable.Archive([64]u8, i32);

    fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var rng = utils.rng.TestRng.init(seed);
        var registry = metrics.Registry.init(gpa);
        defer registry.deinit();
        var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10);
        defer cache_ref.deinit();
        var names: [6][64]u8 = undefined;
        const kinds = [_][]const u8{
            "metadata", "freezer-table", "freezer-key", "freezer-value", "ordinal",
        };
        var partitions: [6][]const u8 = undefined;
        for (kinds, names[0..kinds.len], partitions[0..kinds.len]) |kind, *buffer, *partition| {
            const format = "archive-immutable-{s}-{d}";
            partition.* = try std.fmt.bufPrint(buffer, format, .{ kind, seed });
        }
        const scope = metrics.Scope.init(&registry).child("archive");
        var store = try A.init(gpa, storage, scope, .{
            .metadata_partition = partitions[0],
            .freezer_table_partition = partitions[1],
            .freezer_table_initial_size = 64,
            .freezer_table_resize_frequency = 2,
            .freezer_table_resize_chunk_size = 32,
            .freezer_key_partition = partitions[2],
            .freezer_key_cache_ref = &cache_ref,
            .freezer_value_partition = partitions[3],
            .freezer_value_target_size = 1024 * 1024,
            .ordinal_partition = partitions[4],
            .items_per_section = 1024,
            .freezer_key_write_buffer = 1024,
            .freezer_value_write_buffer = 1024,
            .ordinal_write_buffer = 1024,
            .replay_buffer = 1024,
            .codec_config = {},
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

test "conformance StorageConformance<ArchiveImmutableWorkload>" {
    try conformance.verify(
        ArchiveImmutableWorkload,
        std.testing.allocator,
        "commonware_storage::archive::conformance::StorageConformance<ArchiveImmutableWorkload>",
        128,
        conformance_file,
    );
}
