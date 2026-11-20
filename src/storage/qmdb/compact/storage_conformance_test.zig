//! Storage conformance of the compact databases (commonware's `qmdb/conformance.rs`
//! `StorageConformance<{Immutable,Keyless}{Mmr,Mmb}Compact{Fixed,Variable}Storage>`): the storage
//! audit after the immutable or keyless root workload and a sync, with the witness journal
//! under `{name}-{seed}-compact-witness`, over 64 seeds.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const test_support = @import("../test_support.zig");
const roots = @import("conformance_test.zig");
const support = @import("test_support.zig");

fn Workload(comptime Db: type, comptime name: []const u8) type {
    return struct {
        pub fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
            var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 101, 11);
            defer cache_ref.deinit();
            var buffer: [96]u8 = undefined;
            const partition = try std.fmt.bufPrint(&buffer, "{s}-{d}-compact-witness", .{
                name, seed,
            });
            assert(partition.len > name.len);
            const cfg: Db.Cfg = .{
                .witness = .{
                    .partition = partition,
                    .items_per_section = 64,
                    .codec_config = {},
                    .cache_ref = &cache_ref,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                },
                .codec_config = support.codec_config(Db),
            };
            var db = try Db.init(gpa, storage, cfg, null);
            defer db.deinit();
            try roots.workload(Db, &db, seed);
            try db.sync();
        }
    };
}

fn verify(comptime Db: type, comptime name: []const u8) !void {
    try test_support.verify_storage(Workload(Db, name), name, 64);
}

const mmr = merkle.mmr.Family;
const mmb = merkle.mmb.Family;

test "compact immutable storage conformance (MMR fixed)" {
    try verify(support.ImmutableFixed(mmr), "ImmutableMmrCompactFixedStorage");
}

test "compact immutable storage conformance (MMB fixed)" {
    try verify(support.ImmutableFixed(mmb), "ImmutableMmbCompactFixedStorage");
}

test "compact immutable storage conformance (MMR variable)" {
    try verify(support.ImmutableVariable(mmr), "ImmutableMmrCompactVariableStorage");
}

test "compact immutable storage conformance (MMB variable)" {
    try verify(support.ImmutableVariable(mmb), "ImmutableMmbCompactVariableStorage");
}

test "compact keyless storage conformance (MMR fixed)" {
    try verify(support.KeylessFixed(mmr), "KeylessMmrCompactFixedStorage");
}

test "compact keyless storage conformance (MMB fixed)" {
    try verify(support.KeylessFixed(mmb), "KeylessMmbCompactFixedStorage");
}

test "compact keyless storage conformance (MMR variable)" {
    try verify(support.KeylessVariable(mmr), "KeylessMmrCompactVariableStorage");
}

test "compact keyless storage conformance (MMB variable)" {
    try verify(support.KeylessVariable(mmb), "KeylessMmbCompactVariableStorage");
}
