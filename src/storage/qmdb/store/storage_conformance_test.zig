//! Storage conformance of the store (commonware's `qmdb/conformance.rs`
//! `StorageConformance<StoreStorage>`): the storage audit after the four-batch keyed workload,
//! each batch applied under `Proportional`, and a sync, over 64 seeds.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const runtime = @import("runtime");
const translator = @import("../../translator.zig");
const value = @import("../value.zig");
const test_support = @import("../test_support.zig");
const keyed = @import("../any/conformance_test.zig");
const keyed_support = @import("../any/test_support.zig");
const store = @import("mod.zig");

const Digest = cryptography.Sha256.Digest;
const Db = store.Db(Digest, value.Variable(Digest), translator.OneCap, parallel.Sequential);

const StoreStorage = struct {
    pub fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 101, 11);
        defer cache_ref.deinit();
        var log = test_support.log_config(Db.Journal.Cfg, &cache_ref);
        // Commonware's `store_config("store")`: one partition for every seed.
        log.partition = "store-log";
        const cfg: Db.Cfg = .{ .log = log, .translator = .{}, .init_cache = 1024, .strategy = .{} };
        var db = try Db.init(gpa, storage, cfg, null);
        defer db.deinit();
        const batches = try keyed.keyed_batches(gpa, seed);
        defer for (batches) |list| gpa.free(list);
        for (batches) |writes| try apply(gpa, &db, writes);
        try db.sync();
    }

    fn apply(gpa: Allocator, db: *Db, writes: []const keyed_support.Write) !void {
        const converted = try gpa.alloc(Db.Write, writes.len);
        defer gpa.free(converted);
        for (writes, converted) |w, *out| out.* = .{ .key = w.key, .value = w.value };
        var changeset = try Db.Changeset.init(gpa, converted);
        try db.apply_batch(&changeset); // Consumes the changeset, also on error.
    }
};

test "store storage conformance" {
    try test_support.verify_storage(StoreStorage, "StoreStorage", 64);
}
