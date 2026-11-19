//! `journal::read_cached`: random reads of every item once each is served from memory (the
//! page cache or the write buffer), across item sizes on both sides of page boundaries.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const utils = @import("utils");
const common = @import("common.zig");

const partition = "read-cached";
const items_per_blob: u64 = 10_000;
/// Small enough that every page fits in the page cache.
const items: u64 = 20_000;

const Kind = enum { fixed, variable };

pub fn run(runner: *bench.Runner) !void {
    inline for (.{ 8, 32, 64, 128, 129, 256 }) |size| try run_size(runner, .fixed, size);
    try run_size(runner, .variable, 32);
}

fn run_size(runner: *bench.Runner, comptime kind: Kind, comptime size: usize) !void {
    const benchmark = bench.Benchmark.init("journal::read_cached")
        .with_param("journal", kind)
        .with_param("size", size);
    var workload: Cached(kind, size) = .{
        .gpa = runner.allocator,
        .io = runner.io,
        .inputs = runner.inputs,
    };
    try runner.run(benchmark, &workload);
}

fn Cached(comptime kind: Kind, comptime size: usize) type {
    const J = switch (kind) {
        .fixed => common.FixedJournal(size),
        .variable => common.VariableJournal(size),
    };
    return struct {
        const Self = @This();

        gpa: Allocator,
        io: std.Io,
        inputs: bench.Inputs,
        disk: common.Disk = undefined,
        cache_ref: common.CacheRef = undefined,
        journal: J = undefined,
        positions: []u64 = &.{},

        pub fn setup(self: *Self) !void {
            try self.disk.init(self.io, self.gpa, "read-cached", self.inputs);
            errdefer self.disk.deinit();
            self.cache_ref = try .init(self.gpa, common.page_size, common.page_cache_size);
            errdefer self.cache_ref.deinit();
            const open = switch (kind) {
                .fixed => common.open_fixed,
                .variable => common.open_variable,
            };
            const cache_ref = &self.cache_ref;
            const disk = &self.disk;
            self.journal = try open(size, self.gpa, disk, cache_ref, partition, items_per_blob);
            errdefer self.journal.deinit();
            try common.append_random(&self.journal, size, items);
            // Every position in a fixed random order.
            self.positions = try self.gpa.alloc(u64, items);
            errdefer self.gpa.free(self.positions);
            for (self.positions, 0..) |*position, index| position.* = index;
            var rng = utils.rng.test_rng();
            common.shuffle(u64, &rng, self.positions);
            _ = try self.iter();
            for (self.positions) |position| {
                if (self.journal.try_read_sync(position) == null) return error.NotInMemory;
            }
        }

        pub fn iter(self: *Self) !u64 {
            for (self.positions) |position| {
                // A pointer sink: by value, a small array gets one barrier per byte.
                const item = try self.journal.read(position);
                std.mem.doNotOptimizeAway(&item);
            }
            assert(self.positions.len == items);
            return self.positions.len;
        }

        pub fn teardown(self: *Self) !void {
            defer self.disk.deinit();
            defer self.cache_ref.deinit();
            self.gpa.free(self.positions);
            self.positions = &.{};
            try self.journal.destroy();
        }
    };
}

comptime {
    assert(items_per_blob < items);
}
