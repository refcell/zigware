//! Storage conformance of the immutable database (commonware's `qmdb/conformance.rs`
//! `StorageConformance<Immutable{Mmr,Mmb}{Fixed,Variable}Storage>`): the storage audit after the
//! three-batch set workload and a sync, with partitions named for the workload and seed, over
//! 64 seeds.

const std = @import("std");
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const test_support = @import("../test_support.zig");
const support = @import("test_support.zig");
const roots = @import("conformance_test.zig");

const metrics = runtime.telemetry.metrics;

fn Workload(comptime Db: type, comptime name: []const u8) type {
    return struct {
        pub fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
            var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 101, 11);
            defer cache_ref.deinit();
            var registry = metrics.Registry.init(gpa);
            defer registry.deinit();
            var partitions: test_support.AuditPartitions = .{};
            try partitions.init(name, seed);
            var log = test_support.log_config(@FieldType(Db.Cfg, "log"), &cache_ref);
            log.partition = partitions.log;
            const cfg: Db.Cfg = .{
                .merkle = .{
                    .journal_partition = partitions.journal,
                    .metadata_partition = partitions.metadata,
                    .items_per_blob = 11,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                    .cache_ref = &cache_ref,
                },
                .log = log,
                .translator = .{},
            };
            const scope = metrics.Scope.init(&registry).child("db");
            var db = try Db.init(gpa, storage, scope, cfg, null);
            defer db.deinit();
            try roots.workload(gpa, &db, seed);
            try db.sync();
        }
    };
}

fn verify(comptime Db: type, comptime name: []const u8) !void {
    try test_support.verify_storage(Workload(Db, name), name, 64);
}

const mmr = merkle.mmr.Family;
const mmb = merkle.mmb.Family;

test "immutable storage conformance (MMR fixed)" {
    try verify(support.Fixed(mmr), "ImmutableMmrFixedStorage");
}

test "immutable storage conformance (MMB fixed)" {
    try verify(support.Fixed(mmb), "ImmutableMmbFixedStorage");
}

test "immutable storage conformance (MMR variable)" {
    try verify(support.Variable(mmr), "ImmutableMmrVariableStorage");
}

test "immutable storage conformance (MMB variable)" {
    try verify(support.Variable(mmb), "ImmutableMmbVariableStorage");
}
