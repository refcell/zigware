//! `metadata::restart`: reopening a store whose two blobs both hold `keys` random values.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const common = @import("common.zig");

pub fn run(runner: *bench.Runner) !void {
    const counts_all = [_]usize{ 100, 1_000, 10_000, 100_000 };
    // commonware smoke-tests every count; unoptimized builds take seconds on the largest.
    const counts = runner.inputs.pick([]const usize, counts_all[0..3], &counts_all, &counts_all);
    for (counts) |keys| {
        const benchmark = bench.Benchmark.init("metadata::restart").with_param("keys", keys);
        var workload: Restart = .{
            .gpa = runner.allocator,
            .io = runner.io,
            .inputs = runner.inputs,
            .keys = keys,
        };
        try runner.run(benchmark, &workload);
    }
}

const Restart = struct {
    gpa: Allocator,
    io: std.Io,
    inputs: bench.Inputs,
    keys: usize,
    disk: common.Disk = undefined,

    /// Fill the store and sync twice so both blobs are populated.
    pub fn setup(self: *Restart) !void {
        try self.disk.init(self.io, self.gpa, "metadata-restart", self.inputs);
        errdefer self.disk.deinit();
        const kvs = try common.random_kvs(self.gpa, self.keys);
        defer self.gpa.free(kvs);
        var store = try common.open(self.gpa, &self.disk);
        defer store.deinit();
        for (kvs) |*kv| try common.put(self.gpa, &store, kv.key, &kv.value);
        try store.sync();
        try store.sync();
        assert(store.count() == self.keys);
    }

    pub fn iter(self: *Restart) !usize {
        var store = try common.open(self.gpa, &self.disk);
        defer store.deinit();
        assert(store.count() == self.keys);
        return store.count();
    }

    pub fn teardown(self: *Restart) !void {
        defer self.disk.deinit();
        var store = try common.open(self.gpa, &self.disk);
        try store.destroy();
    }
};
