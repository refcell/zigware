//! Storage conformance of the `current` database (commonware's `qmdb/conformance.rs`
//! `StorageConformance<Current{Mmr,Mmb}{Unordered,Ordered}{Fixed,Variable}Storage>`): the
//! storage audit after the four-batch keyed workload and a sync, with partitions named for the
//! workload and seed (the grafted metadata under `-graft`), over 64 seeds.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const test_support = @import("../test_support.zig");
const keyed = @import("../any/conformance_test.zig");
const support = @import("test_support.zig");

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
            var graft_buffer: [96]u8 = undefined;
            const graft = try std.fmt.bufPrint(&graft_buffer, "{s}-{d}-graft", .{ name, seed });
            assert(graft.len > name.len);
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
                .grafted_metadata_partition = graft,
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

test "current storage conformance (MMR unordered fixed)" {
    try verify(support.UnorderedFixed(mmr), "CurrentMmrUnorderedFixedStorage");
}

test "current storage conformance (MMR unordered variable)" {
    try verify(support.UnorderedVariable(mmr), "CurrentMmrUnorderedVariableStorage");
}

test "current storage conformance (MMR ordered fixed)" {
    try verify(support.OrderedFixed(mmr), "CurrentMmrOrderedFixedStorage");
}

test "current storage conformance (MMR ordered variable)" {
    try verify(support.OrderedVariable(mmr), "CurrentMmrOrderedVariableStorage");
}

test "current storage conformance (MMB unordered fixed)" {
    try verify(support.UnorderedFixed(mmb), "CurrentMmbUnorderedFixedStorage");
}

test "current storage conformance (MMB unordered variable)" {
    try verify(support.UnorderedVariable(mmb), "CurrentMmbUnorderedVariableStorage");
}

test "current storage conformance (MMB ordered fixed)" {
    try verify(support.OrderedFixed(mmb), "CurrentMmbOrderedFixedStorage");
}

test "current storage conformance (MMB ordered variable)" {
    try verify(support.OrderedVariable(mmb), "CurrentMmbOrderedVariableStorage");
}
