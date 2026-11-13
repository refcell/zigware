//! Cache conformance (commonware's `cache/conformance.rs` and the `Record<u64>` codec hash).
//!
//! `StorageConformance<CacheWorkload>` runs commonware's workload on in-memory storage with
//! the runtime RNG seeded by the case seed and commits the storage audit (CRC32C of every
//! durable blob), so a match means the cache writes byte-identical blobs.

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const cache_mod = @import("mod.zig");

const conformance_file = @embedFile("../conformance.toml");
const Bytes = []const u8;

const CacheWorkload = struct {
    fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var rng = utils.rng.TestRng.init(seed);
        var registry = metrics.Registry.init(gpa);
        defer registry.deinit();
        var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10);
        defer cache_ref.deinit();
        var partition_buffer: [64]u8 = undefined;
        const partition = try std.fmt.bufPrint(&partition_buffer, "cache-conformance-{d}", .{seed});
        const config: cache_mod.Config(Bytes) = .{
            .partition = partition,
            .codec_config = .{ .range = .range(0, 256), .item = {} },
            .items_per_blob = 16,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &cache_ref,
        };
        const scope = metrics.Scope.init(&registry).child("cache");
        var cache = try cache_mod.Cache(Bytes).init(gpa, storage, scope, config);
        defer cache.deinit();
        const items = utils.rng.range_less_than(&rng, usize, 16, 80);
        var value: [256]u8 = undefined;
        for (0..items) |i| {
            const index = @as(u64, i) * 2 + seed % 2;
            const len = utils.rng.range_less_than(&rng, usize, 0, 256);
            rng.fill_bytes(value[0..len]);
            try cache.put(index, value[0..len]);
        }
        try cache.sync();
        if (items > 32) {
            try cache.prune(32);
            try cache.sync();
        }
    }

    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var memory = runtime.storage.memory.Storage.init(gpa);
        defer memory.deinit();
        try run(gpa, memory.storage(), seed);
        const audit = memory.audit();
        return gpa.dupe(u8, &audit);
    }
};

/// `#[derive(Arbitrary)]`-equivalent of `Record::arbitrary`: the index, then the value.
fn gen_record(
    _: Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error!cache_mod.Record(u64) {
    const index = u.int(u64);
    const value = u.int(u64);
    return .{ .index = index, .value = value };
}

const RecordConformance = struct {
    const Record = cache_mod.Record(u64);

    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const record = try codec.arbitrary.generate(Record, gen_record, arena.allocator(), seed);
        return codec.encode(Record, gpa, record);
    }
};

test "conformance StorageConformance<CacheWorkload>" {
    try conformance.verify(
        CacheWorkload,
        std.testing.allocator,
        "commonware_storage::cache::conformance::StorageConformance<CacheWorkload>",
        256,
        conformance_file,
    );
}

test "conformance CodecConformance<Record<u64>>" {
    try conformance.verify(
        RecordConformance,
        std.heap.smp_allocator,
        "commonware_storage::cache::storage::conformance::CodecConformance<Record<u64>>",
        conformance.default_cases,
        conformance_file,
    );
}
