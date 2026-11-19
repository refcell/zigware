//! `journal::variable_prepare_append`: variable-journal batch preparation (frame encoding,
//! optional compression, and freeing the batch) across record sizes and compressibility.
//! Repeated bytes with distinct item prefixes are highly compressible; random bytes are not.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const utils = @import("utils");
const common = @import("common.zig");

pub fn run(runner: *bench.Runner) !void {
    try run_size(runner, 64);
    try run_size(runner, 1024);
    // Unoptimized builds copy each 1 MiB record by value at every call of the encoding path
    // and overflow the stack, so the smoke run under `zig build test` skips this size.
    if (runner.inputs != .smoke) try run_size(runner, 1024 * 1024);
}

fn run_size(runner: *bench.Runner, comptime size: usize) !void {
    const gpa = runner.allocator;
    // Cap input payloads at 32 MiB: 32,768 records of 1 MiB would take 32 GiB.
    const items_max: usize = @min(32_768, 32 * 1024 * 1024 / size);
    // commonware smoke-tests 32,768 records too; unoptimized builds take seconds to compress.
    const counts_all = [_]usize{ 1, 32, 256, 1_024, 32_768 };
    const counts = runner.inputs.pick([]const usize, counts_all[0..4], &counts_all, &counts_all);
    for ([_]bool{ false, true }) |random| {
        var any = false;
        for (counts) |items| {
            if (items > items_max) continue;
            for ([_]?u8{ null, 3 }) |compression| {
                if (compression == null and random) continue;
                const benchmark = benchmark_of(size, items, compression, random);
                any = any or runner.matches(benchmark.name());
            }
        }
        if (!any) continue;
        const values = try gpa.alloc([size]u8, items_max);
        defer gpa.free(values);
        fill_values(size, values, random);
        for (counts) |items| {
            if (items > items_max) continue;
            for ([_]?u8{ null, 3 }) |compression| {
                // Fixed-size encoding copies the same bytes for either pattern, so one
                // uncompressed baseline covers both.
                if (compression == null and random) continue;
                var workload: Prepare(size) = .{
                    .gpa = gpa,
                    .io = runner.io,
                    .inputs = runner.inputs,
                    .values = values[0..items],
                    .compression = compression,
                };
                try runner.run(benchmark_of(size, items, compression, random), &workload);
            }
        }
    }
}

fn benchmark_of(size: usize, items: usize, compression: ?u8, random: bool) bench.Benchmark {
    const benchmark = bench.Benchmark.init("journal::variable_prepare_append")
        .with_param("items", items)
        .with_param("size", size);
    const with_level = if (compression) |level|
        benchmark.with_param("compression", level)
    else
        benchmark.with_param("compression", "none");
    return with_level.with_param("random", random);
}

/// commonware's values: `0xAB` bytes with the big-endian index first, or `test_rng` bytes.
fn fill_values(comptime size: usize, values: [][size]u8, random: bool) void {
    comptime assert(size >= 8);
    var rng = utils.rng.test_rng();
    for (values, 0..) |*value, index| {
        value.* = @splat(0xAB);
        if (random) {
            rng.fill_bytes(value);
        } else {
            std.mem.writeInt(u64, value[0..8], index, .big);
        }
    }
}

fn Prepare(comptime size: usize) type {
    const J = common.VariableJournal(size);
    return struct {
        const Self = @This();

        gpa: Allocator,
        io: std.Io,
        inputs: bench.Inputs,
        values: []const [size]u8,
        compression: ?u8,
        disk: common.Disk = undefined,
        cache_ref: common.CacheRef = undefined,
        journal: J = undefined,

        pub fn setup(self: *Self) !void {
            assert(self.values.len > 0);
            try self.disk.init(self.io, self.gpa, "variable-prepare-append", self.inputs);
            errdefer self.disk.deinit();
            self.cache_ref = try .init(self.gpa, common.page_size, 32);
            errdefer self.cache_ref.deinit();
            self.journal = try J.init(self.gpa, self.disk.interface(), .{
                .partition = "variable_prepare_append",
                .items_per_section = 1_000_000,
                .compression = self.compression,
                .codec_config = {},
                .cache_ref = &self.cache_ref,
                .write_buffer = common.write_buffer,
                .replay_buffer = common.replay_buffer,
            });
        }

        pub fn iter(self: *Self) !usize {
            const nested = [_][]const [size]u8{self.values};
            var prepared = try self.journal.prepare_append(&nested);
            defer prepared.deinit(self.gpa);
            assert(prepared.starts.len == self.values.len);
            return prepared.encoded.len;
        }

        pub fn teardown(self: *Self) !void {
            defer self.disk.deinit();
            defer self.cache_ref.deinit();
            try self.journal.destroy();
        }
    };
}
