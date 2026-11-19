//! `metadata::overwrite`: steady-state cost of persisting equal-size updates, which overwrite
//! the store in place. Cases with fewer than 256 keys fit in one 4,096-byte blob page and are
//! written whole: 255 keys (4,092 bytes) is the largest such store, 256 keys (4,108 bytes) is
//! just above it. Syncs complete synchronously, so `pipelined` runs `start_sync`, which
//! returns once the sync is durable, as commonware's awaited handle does.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const storage = @import("storage");
const common = @import("common.zig");

const Case = struct { keys: u64, modified: u64, pipelined: bool };

pub fn run(runner: *bench.Runner) !void {
    const small = [_]Case{
        .{ .keys = 1, .modified = 1, .pipelined = false },
        .{ .keys = 3, .modified = 1, .pipelined = false },
        .{ .keys = 3, .modified = 3, .pipelined = false },
        .{ .keys = 128, .modified = 1, .pipelined = false },
        .{ .keys = 128, .modified = 128, .pipelined = false },
        .{ .keys = 255, .modified = 1, .pipelined = false },
        .{ .keys = 255, .modified = 1, .pipelined = true },
        .{ .keys = 256, .modified = 1, .pipelined = false },
        .{ .keys = 1_024, .modified = 1, .pipelined = false },
        .{ .keys = 1_024, .modified = 128, .pipelined = false },
    };
    for (small) |case| try run_case(runner, 8, case);
    try run_case(runner, 2_048, .{ .keys = 1, .modified = 1, .pipelined = false });
    try run_case(runner, 8, .{ .keys = 3, .modified = 1, .pipelined = true });
}

fn run_case(runner: *bench.Runner, comptime size: usize, case: Case) !void {
    assert(case.modified <= case.keys);
    const benchmark = bench.Benchmark.init("metadata::overwrite")
        .with_param("keys", case.keys)
        .with_param("size", size)
        .with_param("modified", case.modified)
        .with_param("pipelined", case.pipelined);
    var workload: Overwrite(size) = .{
        .gpa = runner.allocator,
        .io = runner.io,
        .inputs = runner.inputs,
        .case = case,
    };
    try runner.run(benchmark, &workload);
}

fn Overwrite(comptime size: usize) type {
    const Store = storage.metadata.Metadata(u64, [size]u8);
    return struct {
        const Self = @This();

        gpa: Allocator,
        io: std.Io,
        inputs: bench.Inputs,
        case: Case,
        iteration: u64 = 0,
        disk: common.Disk = undefined,
        store: Store = undefined,

        /// Fill the store, then populate both copies before timing equal-size updates.
        pub fn setup(self: *Self) !void {
            try self.disk.init(self.io, self.gpa, "metadata-overwrite", self.inputs);
            errdefer self.disk.deinit();
            self.store = try Store.init(self.gpa, self.disk.interface(), .{
                .partition = "metadata_overwrite",
                .codec_config = {},
            });
            errdefer self.store.deinit();
            for (0..self.case.keys) |key| _ = try self.store.put(key, @splat(0));
            try self.store.sync();
            try self.store.sync();
            self.iteration = 0;
            assert(self.store.count() == self.case.keys);
        }

        pub fn before_iter(self: *Self) !void {
            const value: [size]u8 = @splat(@intCast(self.iteration % 251 + 1));
            self.iteration += 1;
            for (0..self.case.modified) |key| _ = try self.store.put(key, value);
            assert(self.store.count() == self.case.keys);
        }

        pub fn iter(self: *Self) !usize {
            if (self.case.pipelined) {
                try (try self.store.start_sync()).wait_release();
            } else {
                try self.store.sync();
            }
            return self.store.count();
        }

        pub fn teardown(self: *Self) !void {
            defer self.disk.deinit();
            try self.store.destroy();
        }
    };
}
