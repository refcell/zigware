//! Storage conformance of the keyless database (commonware's `qmdb/conformance.rs`
//! `StorageConformance<Keyless{Mmr,Mmb}{Fixed,Variable}Storage>`): the storage audit after the
//! three-batch append workload and a sync, with partitions named for the workload and seed,
//! over 64 seeds.

const std = @import("std");
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const test_support = @import("../test_support.zig");
const roots = @import("conformance_test.zig");

const metrics = runtime.telemetry.metrics;

fn Workload(comptime F: type, comptime V: bool, comptime name: []const u8) type {
    const Db = roots.Db(F, V);
    return struct {
        pub fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
            var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 101, 11);
            defer cache_ref.deinit();
            var registry = metrics.Registry.init(gpa);
            defer registry.deinit();
            var partitions: test_support.AuditPartitions = .{};
            try partitions.init(name, seed);
            const cfg: Db.Cfg = .{
                .merkle = .{
                    .journal_partition = partitions.journal,
                    .metadata_partition = partitions.metadata,
                    .items_per_blob = 11,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                    .cache_ref = &cache_ref,
                },
                .log = if (V) .{
                    .partition = partitions.log,
                    .items_per_section = 7,
                    .codec_config = .{ .range = .inclusive(0, 10000) },
                    .cache_ref = &cache_ref,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                } else .{
                    .partition = partitions.log,
                    .items_per_blob = 7,
                    .cache_ref = &cache_ref,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                },
            };
            const scope = metrics.Scope.init(&registry).child("db");
            var db = try Db.init(gpa, storage, scope, cfg, null);
            defer db.deinit();
            try roots.workload(F, V, &db, seed);
            try db.sync();
        }
    };
}

fn verify(comptime F: type, comptime V: bool, comptime name: []const u8) !void {
    try test_support.verify_storage(Workload(F, V, name), name, 64);
}

const mmr = merkle.mmr.Family;
const mmb = merkle.mmb.Family;

test "keyless storage conformance (MMR fixed)" {
    try verify(mmr, false, "KeylessMmrFixedStorage");
}

test "keyless storage conformance (MMB fixed)" {
    try verify(mmb, false, "KeylessMmbFixedStorage");
}

test "keyless storage conformance (MMR variable)" {
    try verify(mmr, true, "KeylessMmrVariableStorage");
}

test "keyless storage conformance (MMB variable)" {
    try verify(mmb, true, "KeylessMmbVariableStorage");
}
