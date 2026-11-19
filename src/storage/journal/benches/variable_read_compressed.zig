//! `journal::variable_read_compressed`: contiguous variable-journal reads of zstd level-3
//! items. In the uncached modes a two-page cache makes reads at sampled positions miss and
//! read their frames from blobs. Every sample uses the same items and positions.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const utils = @import("utils");
const common = @import("common.zig");

const items_per_section: u64 = 1_000;

const Mode = enum { read_many, read_many_uncached, read_uncached, replay };

pub fn run(runner: *bench.Runner) !void {
    try run_size(runner, 64);
    try run_size(runner, 1024);
    try run_size(runner, 16384);
}

fn run_size(runner: *bench.Runner, comptime size: usize) !void {
    // commonware smoke-tests up to 10,000 items; unoptimized builds take seconds to compress.
    const items_max = runner.inputs.pick(u64, 500, 10_000, 10_000);
    const items: u64 = @min(16 * 1024 * 1024 / size, items_max);
    for ([_]bool{ false, true }) |random| {
        for ([_]Mode{ .read_many, .read_many_uncached, .read_uncached, .replay }) |mode| {
            const benchmark = bench.Benchmark.init("journal::variable_read_compressed")
                .with_param("mode", mode)
                .with_param("items", items)
                .with_param("size", size)
                .with_param("random", random);
            var workload: Compressed(size) = .{
                .gpa = runner.allocator,
                .io = runner.io,
                .inputs = runner.inputs,
                .items = items,
                .random = random,
                .mode = mode,
            };
            try runner.run(benchmark, &workload);
        }
    }
}

fn Compressed(comptime size: usize) type {
    const J = common.VariableJournal(size);
    return struct {
        const Self = @This();

        gpa: Allocator,
        io: std.Io,
        inputs: bench.Inputs,
        items: u64,
        random: bool,
        mode: Mode,
        disk: common.Disk = undefined,
        cache_ref: common.CacheRef = undefined,
        journal: J = undefined,
        all: []u64 = &.{},
        sampled: []u64 = &.{},
        sorted: []u64 = &.{},
        out: [][size]u8 = &.{},

        pub fn setup(self: *Self) !void {
            try self.disk.init(self.io, self.gpa, "variable-read-compressed", self.inputs);
            errdefer self.disk.deinit();
            const uncached = self.mode == .read_many_uncached or self.mode == .read_uncached;
            const pages: u32 = if (uncached) 2 else common.page_cache_size;
            self.cache_ref = try .init(self.gpa, common.page_size, pages);
            errdefer self.cache_ref.deinit();
            self.journal = try J.init(self.gpa, self.disk.interface(), .{
                .partition = "variable_read_compressed",
                .items_per_section = items_per_section,
                .compression = 3,
                .codec_config = {},
                .cache_ref = &self.cache_ref,
                .write_buffer = common.write_buffer,
                .replay_buffer = common.replay_buffer,
            });
            errdefer self.journal.deinit();
            try self.populate();
        }

        fn populate(self: *Self) !void {
            var rng = utils.rng.test_rng();
            var bytes: [size]u8 = undefined;
            for (0..self.items) |index| {
                bytes = @splat(0xAB);
                if (self.random) {
                    rng.fill_bytes(&bytes);
                } else {
                    std.mem.writeInt(u64, bytes[0..8], index, .big);
                }
                _ = try self.journal.append(bytes);
            }
            try self.journal.sync();
            const count: usize = @intCast(self.items);
            self.all = try self.gpa.alloc(u64, count);
            self.sampled = try self.gpa.alloc(u64, count);
            self.sorted = try self.gpa.alloc(u64, count);
            self.out = try self.gpa.alloc([size]u8, count);
            for (self.all, 0..) |*position, index| position.* = index;
            for (self.sampled) |*position| position.* = common.below(&rng, self.items);
            // `read_many` takes strictly increasing positions: sort and deduplicate.
            @memcpy(self.sorted, self.sampled);
            self.sorted = common.sort_dedup(self.sorted);
            assert(self.journal.size() == self.items);
        }

        pub fn iter(self: *Self) !u64 {
            switch (self.mode) {
                .read_many => try self.journal.read_many(self.all, self.out),
                .read_many_uncached => {
                    try self.journal.read_many(self.sorted, self.out[0..self.sorted.len]);
                },
                .read_uncached => for (self.sampled) |position| {
                    std.mem.doNotOptimizeAway(try self.journal.read(position));
                },
                .replay => {
                    const bounds = self.journal.get_bounds();
                    var replay = try self.journal.replay_options(bounds, 65_536, .{});
                    defer replay.deinit();
                    assert(try common.drain(&replay) == self.items);
                },
            }
            std.mem.doNotOptimizeAway(self.out);
            return self.items;
        }

        pub fn teardown(self: *Self) !void {
            defer self.disk.deinit();
            defer self.cache_ref.deinit();
            self.gpa.free(self.out);
            // `sorted` is a prefix of its allocation.
            self.gpa.free(self.sorted.ptr[0..self.all.len]);
            self.gpa.free(self.sampled);
            self.gpa.free(self.all);
            self.out = &.{};
            self.sorted = &.{};
            self.sampled = &.{};
            self.all = &.{};
            try self.journal.destroy();
        }
    };
}
