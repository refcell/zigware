//! Freezer codec conformance (commonware's `freezer/storage.rs` `CodecConformance` hashes).

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const freezer = @import("mod.zig");

const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;

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

/// `StorageConformance<FreezerWorkload>`: 64 random 64-byte keys with periodic syncs that
/// drive resizes, then a close that finishes them. Commits the storage audit.
const FreezerWorkload = struct {
    fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var rng = utils.rng.TestRng.init(seed);
        var registry = metrics.Registry.init(gpa);
        defer registry.deinit();
        var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10);
        defer cache_ref.deinit();
        var names: [3][64]u8 = undefined;
        const kinds = [_][]const u8{ "key", "value", "table" };
        var partitions: [3][]const u8 = undefined;
        for (kinds, &names, &partitions) |kind, *buffer, *partition| {
            const format = "freezer-{s}-conformance-{d}";
            partition.* = try std.fmt.bufPrint(buffer, format, .{ kind, seed });
        }
        const F = freezer.Freezer([64]u8, i32);
        var store = try F.init(gpa, storage, metrics.Scope.init(&registry).child("freezer"), .{
            .key_partition = partitions[0],
            .key_write_buffer = 1024,
            .key_cache_ref = &cache_ref,
            .value_partition = partitions[1],
            .value_write_buffer = 1024,
            .value_target_size = 128,
            .table_partition = partitions[2],
            .table_initial_size = 4,
            .table_resize_frequency = 1,
            .table_resize_chunk_size = 4,
            .table_replay_buffer = 1024,
            .codec_config = {},
        }, null);
        var open = true;
        defer if (open) store.deinit();
        for (0..64) |i| {
            var key: [64]u8 = undefined;
            rng.fill_bytes(&key);
            _ = try store.put(key, @intCast(i));
            if (i % 8 == 0) _ = try store.sync();
        }
        open = false;
        _ = store.close() catch |err| {
            store.deinit();
            return err;
        };
    }

    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var memory = runtime.storage.memory.Storage.init(gpa);
        defer memory.deinit();
        try run(gpa, memory.storage(), seed);
        const audit = memory.audit();
        return gpa.dupe(u8, &audit);
    }
};

test "conformance StorageConformance<FreezerWorkload>" {
    try conformance.verify(
        FreezerWorkload,
        std.testing.allocator,
        "commonware_storage::freezer::conformance::StorageConformance<FreezerWorkload>",
        512,
        conformance_file,
    );
}
