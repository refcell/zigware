//! `journal::fixed_read_sequential`: reading every item of a journal holding exactly that
//! many, in order from position zero.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const common = @import("common.zig");

const item_size = 32;
const items_per_blob: u64 = 100_000;

pub fn run(runner: *bench.Runner) !void {
    const counts_all = [_]u64{ 1_000, 10_000, 100_000, 500_000 };
    // commonware smoke-tests every count; unoptimized builds take seconds on the larger ones.
    const counts = runner.inputs.pick([]const u64, counts_all[0..1], &counts_all, &counts_all);
    for (counts) |items| {
        const benchmark = bench.Benchmark.init("journal::fixed_read_sequential")
            .with_param("items", items)
            .with_param("size", item_size);
        var workload: Sequential = .{
            .gpa = runner.allocator,
            .io = runner.io,
            .inputs = runner.inputs,
            .items = items,
        };
        try runner.run(benchmark, &workload);
    }
}

const Sequential = struct {
    gpa: Allocator,
    io: std.Io,
    inputs: bench.Inputs,
    items: u64,
    disk: common.Disk = undefined,
    cache_ref: common.CacheRef = undefined,
    journal: common.FixedJournal(item_size) = undefined,

    pub fn setup(self: *Sequential) !void {
        try self.disk.init(self.io, self.gpa, "fixed-read-sequential", self.inputs);
        errdefer self.disk.deinit();
        self.cache_ref = try .init(self.gpa, common.page_size, common.page_cache_size);
        errdefer self.cache_ref.deinit();
        self.journal = try common.open_fixed(
            item_size,
            self.gpa,
            &self.disk,
            &self.cache_ref,
            "test-partition",
            items_per_blob,
        );
        errdefer self.journal.deinit();
        try common.append_random(&self.journal, item_size, self.items);
        assert(self.journal.size() == self.items);
    }

    pub fn iter(self: *Sequential) !u64 {
        for (0..self.items) |position| {
            // A pointer sink: by value, a small array item gets one barrier per byte.
            const item = try self.journal.read(position);
            std.mem.doNotOptimizeAway(&item);
        }
        return self.items;
    }

    pub fn teardown(self: *Sequential) !void {
        defer self.disk.deinit();
        defer self.cache_ref.deinit();
        try self.journal.destroy();
    }
};
