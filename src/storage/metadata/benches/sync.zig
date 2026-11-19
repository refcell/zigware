//! `metadata::sync`: syncing `modified` new values into a store of `keys` random values whose
//! two blobs are both populated. Each iteration builds a fresh store (untimed).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const common = @import("common.zig");

pub fn run(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    for ([_]usize{ 100, 1_000, 10_000 }) |keys| {
        var initial: ?[]common.KV = null;
        defer if (initial) |kvs| gpa.free(kvs);
        for ([_]usize{ 0, 1, 5, 25, 50, 75, 100 }) |modified| {
            const benchmark = bench.Benchmark.init("metadata::sync")
                .with_param("keys", keys)
                .with_param("modified", modified);
            if (!runner.matches(benchmark.name())) continue;
            if (initial == null) initial = try common.random_kvs(gpa, keys);
            const changes = try common.modified_kvs(gpa, initial.?, modified);
            defer gpa.free(changes);
            var workload: Sync = .{
                .gpa = gpa,
                .io = runner.io,
                .inputs = runner.inputs,
                .initial = initial.?,
                .changes = changes,
            };
            try runner.run(benchmark, &workload);
        }
    }
}

const Sync = struct {
    gpa: Allocator,
    io: std.Io,
    inputs: bench.Inputs,
    initial: []const common.KV,
    changes: []const common.KV,
    disk: common.Disk = undefined,
    store: ?common.Store = null,

    pub fn setup(self: *Sync) !void {
        assert(self.store == null);
        try self.disk.init(self.io, self.gpa, "metadata-sync", self.inputs);
    }

    /// Destroy the previous store, fill a fresh one, sync twice, then stage the changes.
    pub fn before_iter(self: *Sync) !void {
        try self.destroy();
        self.store = try common.open(self.gpa, &self.disk);
        const store = &self.store.?;
        for (self.initial) |*kv| try common.put(self.gpa, store, kv.key, &kv.value);
        try store.sync();
        try store.sync();
        for (self.changes) |*kv| try common.put(self.gpa, store, kv.key, &kv.value);
        assert(store.count() == self.initial.len);
    }

    pub fn iter(self: *Sync) !usize {
        const store = &self.store.?;
        try store.sync();
        return store.count();
    }

    pub fn teardown(self: *Sync) !void {
        defer self.disk.deinit();
        try self.destroy();
    }

    fn destroy(self: *Sync) !void {
        var store = self.store orelse return;
        self.store = null;
        try store.destroy();
    }
};
