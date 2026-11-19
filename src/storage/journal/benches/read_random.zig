//! `journal::fixed_read_random` and `journal::variable_read_random`: random reads of one
//! populated journal, populated once for every benchmark of its kind as commonware does.
//!
//! Modes: `serial` awaits each read; `read_many` batch-reads the sorted, deduplicated
//! positions. commonware's `concurrent` mode joins one future per read; these journals take
//! reads through one handle, so it issues the same reads back to back (docs/lanes).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const utils = @import("utils");
const common = @import("common.zig");

const item_size = 32;
const Item = [item_size]u8;

const Kind = enum { fixed, variable };
const Mode = enum { serial, concurrent, read_many };

pub fn run(runner: *bench.Runner) !void {
    try run_kind(runner, .fixed);
    try run_kind(runner, .variable);
}

fn prefix(kind: Kind) []const u8 {
    return switch (kind) {
        .fixed => "journal::fixed_read_random",
        .variable => "journal::variable_read_random",
    };
}

fn benchmark_of(kind: Kind, mode: Mode, reads: u64) bench.Benchmark {
    return bench.Benchmark.init(prefix(kind))
        .with_param("mode", mode)
        .with_param("items", reads)
        .with_param("size", item_size);
}

fn run_kind(runner: *bench.Runner, comptime kind: Kind) !void {
    const reads_all = runner.inputs.pick(
        []const u64,
        &.{100},
        &.{ 100, 1_000, 10_000, 100_000 },
        &.{ 100, 1_000, 10_000, 100_000 },
    );
    const items = runner.inputs.pick(u64, 10_000, 5_000_000, 5_000_000);
    var any = false;
    for ([_]Mode{ .serial, .concurrent, .read_many }) |mode| {
        for (reads_all) |reads| any = any or runner.matches(benchmark_of(kind, mode, reads).name());
    }
    if (!any) return;

    const gpa = runner.allocator;
    var disk: common.Disk = undefined;
    try disk.init(runner.io, gpa, "read-random", runner.inputs);
    defer disk.deinit();
    var cache_ref = try common.CacheRef.init(gpa, common.page_size, common.page_cache_size);
    defer cache_ref.deinit();
    var journal = switch (kind) {
        .fixed => try common.open_fixed(
            item_size,
            gpa,
            &disk,
            &cache_ref,
            "test-partition",
            10_000,
        ),
        .variable => try common.open_variable(
            item_size,
            gpa,
            &disk,
            &cache_ref,
            "variable-random-test-partition",
            10_000,
        ),
    };
    var destroyed = false;
    defer if (!destroyed) journal.deinit();
    try common.append_random(&journal, item_size, items);

    for ([_]Mode{ .serial, .concurrent, .read_many }) |mode| {
        for (reads_all) |reads| {
            var workload: Read(@TypeOf(journal)) = .{
                .gpa = gpa,
                .journal = &journal,
                .mode = mode,
                .reads = reads,
                .items = items,
            };
            try runner.run(benchmark_of(kind, mode, reads), &workload);
        }
    }
    destroyed = true;
    try journal.destroy();
}

fn Read(comptime J: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        journal: *J,
        mode: Mode,
        reads: u64,
        items: u64,
        positions: []u64 = &.{},
        out: []Item = &.{},

        pub fn setup(self: *Self) !void {
            assert(self.reads > 0 and self.items > 0);
            self.positions = try self.gpa.alloc(u64, self.reads);
            errdefer self.gpa.free(self.positions);
            self.out = try self.gpa.alloc(Item, self.reads);
        }

        pub fn iter(self: *Self) !u64 {
            // Each pass draws its positions from a fresh `test_rng`, as commonware's does.
            var rng = utils.rng.test_rng();
            for (self.positions) |*position| position.* = common.below(&rng, self.items);
            switch (self.mode) {
                .serial, .concurrent => {
                    for (self.positions) |position| {
                        // A pointer sink: by value, a small array gets one barrier per byte.
                        const item = try self.journal.read(position);
                        std.mem.doNotOptimizeAway(&item);
                    }
                    return self.positions.len;
                },
                .read_many => {
                    const sorted = common.sort_dedup(self.positions);
                    try self.journal.read_many(sorted, self.out[0..sorted.len]);
                    std.mem.doNotOptimizeAway(self.out[0..sorted.len]);
                    return sorted.len;
                },
            }
        }

        pub fn teardown(self: *Self) void {
            self.gpa.free(self.out);
            self.gpa.free(self.positions);
            // The runner sets up again for every sample.
            self.out = &.{};
            self.positions = &.{};
        }
    };
}
