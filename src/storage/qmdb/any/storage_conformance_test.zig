//! Storage conformance of the `any` database (commonware's `qmdb/conformance.rs`
//! `StorageConformance<Any{Mmr,Mmb}{Unordered,Ordered}{Fixed,Variable}Storage>`): the storage
//! audit after the four-batch keyed workload and a sync, with partitions named for the workload
//! and seed, over 64 seeds.

const std = @import("std");
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const test_support = @import("../test_support.zig");
const support = @import("test_support.zig");
const keyed = @import("conformance_test.zig");

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
                .init_cache = 1024,
            };
            const scope = metrics.Scope.init(&registry).child("db");
            var db = try Db.init(gpa, storage, scope, cfg, null);
            defer db.deinit();
            const batches = try keyed.keyed_batches(gpa, seed);
            defer for (batches) |list| gpa.free(list);
            for (batches) |writes| try support.apply_writes(Db, &db, writes);
            try db.sync();
        }
    };
}

fn verify(comptime Db: type, comptime name: []const u8) !void {
    try test_support.verify_storage(Workload(Db, name), name, 64);
}

const mmr = merkle.mmr.Family;
const mmb = merkle.mmb.Family;

test "any storage conformance (MMR unordered fixed)" {
    try verify(support.UnorderedFixed(mmr), "AnyMmrUnorderedFixedStorage");
}

test "any storage conformance (MMR unordered variable)" {
    try verify(support.UnorderedVariable(mmr), "AnyMmrUnorderedVariableStorage");
}

test "any storage conformance (MMR ordered fixed)" {
    try verify(support.OrderedFixed(mmr), "AnyMmrOrderedFixedStorage");
}

test "any storage conformance (MMR ordered variable)" {
    try verify(support.OrderedVariable(mmr), "AnyMmrOrderedVariableStorage");
}

test "any storage conformance (MMB unordered fixed)" {
    try verify(support.UnorderedFixed(mmb), "AnyMmbUnorderedFixedStorage");
}

test "any storage conformance (MMB unordered variable)" {
    try verify(support.UnorderedVariable(mmb), "AnyMmbUnorderedVariableStorage");
}

test "any storage conformance (MMB ordered fixed)" {
    try verify(support.OrderedFixed(mmb), "AnyMmbOrderedFixedStorage");
}

test "any storage conformance (MMB ordered variable)" {
    try verify(support.OrderedVariable(mmb), "AnyMmbOrderedVariableStorage");
}
