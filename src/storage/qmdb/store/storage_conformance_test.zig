//! Storage conformance of the store (commonware's `qmdb/conformance.rs`): the storage audit
//! after a workload and a sync. `StoreStorage` applies the four-batch keyed workload under
//! `Proportional` over 64 seeds; `StoreFloorStorage` applies `floor_batches`, each batch under
//! its own rule, over 200.

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
const floor = @import("../any/floor_conformance_test.zig");
const store = @import("mod.zig");

const Digest = cryptography.Sha256.Digest;
const Db = store.Db(Digest, value.Variable(Digest), translator.OneCap, parallel.Sequential);

const StoreStorage = struct {
    pub fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 101, 11);
        defer cache_ref.deinit();
        var db = try Db.init(gpa, storage, store_cfg(&cache_ref), null);
        defer db.deinit();
        const batches = try keyed.keyed_batches(gpa, seed);
        defer for (batches) |list| gpa.free(list);
        for (batches) |writes| try apply(gpa, &db, writes);
        try db.sync();
    }

    fn apply(gpa: Allocator, db: *Db, writes: []const keyed_support.Write) !void {
        var changeset = try changeset_of(gpa, writes);
        try db.apply_batch(&changeset); // Consumes the changeset, also on error.
    }
};

const StoreFloorStorage = struct {
    pub fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 101, 11);
        defer cache_ref.deinit();
        var db = try Db.init(gpa, storage, store_cfg(&cache_ref), null);
        defer db.deinit();
        var plan = try floor.floor_batches(gpa, seed);
        defer plan.deinit();
        for (plan.batches.items) |*batch| {
            var changeset = try changeset_of(gpa, batch.writes);
            try db.apply_batch_with(&changeset, &batch.rule); // Consumes the changeset.
        }
        try db.sync();
    }
};

/// Commonware's `store_config("store")`: one partition for every seed.
fn store_cfg(cache_ref: *runtime.buffer.paged.CacheRef) Db.Cfg {
    var log = test_support.log_config(Db.Journal.Cfg, cache_ref);
    log.partition = "store-log";
    return .{ .log = log, .translator = .{}, .init_cache = 1024, .strategy = .{} };
}

/// `writes` as a store changeset, which the caller applies (consuming it).
fn changeset_of(gpa: Allocator, writes: []const keyed_support.Write) !Db.Changeset {
    const converted = try gpa.alloc(Db.Write, writes.len);
    defer gpa.free(converted);
    for (writes, converted) |w, *out| out.* = .{ .key = w.key, .value = w.value };
    return Db.Changeset.init(gpa, converted);
}

test "store storage conformance" {
    try test_support.verify_storage(StoreStorage, "StoreStorage", 64);
}

test "store floor storage conformance" {
    try test_support.verify_storage(StoreFloorStorage, "StoreFloorStorage", 200);
}
