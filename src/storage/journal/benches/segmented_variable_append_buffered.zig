//! `journal::segmented_variable_append_buffered`: segmented variable-journal append CPU cost
//! while every record fits in the write buffer, so the timed appends perform no I/O.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const storage = @import("storage");
const common = @import("common.zig");

const segmented = storage.journal.segmented;

pub fn run(runner: *bench.Runner) !void {
    try run_size(runner, 32);
    try run_size(runner, 256);
}

fn run_size(runner: *bench.Runner, comptime size: usize) !void {
    const items: u64 = 320 * 1024 / size;
    const benchmark = bench.Benchmark.init("journal::segmented_variable_append_buffered")
        .with_param("items", items)
        .with_param("size", size);
    var workload: Buffered(size) = .{
        .gpa = runner.allocator,
        .io = runner.io,
        .inputs = runner.inputs,
        .items = items,
    };
    try runner.run(benchmark, &workload);
}

fn Buffered(comptime size: usize) type {
    const J = segmented.variable.Journal([size]u8);
    return struct {
        const Self = @This();
        const item: [size]u8 = @splat(0xAB);

        gpa: Allocator,
        io: std.Io,
        inputs: bench.Inputs,
        items: u64,
        disk: common.Disk = undefined,
        cache_ref: common.CacheRef = undefined,
        journal: ?J = null,

        pub fn setup(self: *Self) !void {
            assert(self.journal == null);
            try self.disk.init(self.io, self.gpa, "segmented-variable-append", self.inputs);
            errdefer self.disk.deinit();
            self.cache_ref = try .init(self.gpa, common.page_size, 32);
        }

        /// Open a fresh journal and create section 0 and its first tip page.
        pub fn before_iter(self: *Self) !void {
            try self.destroy();
            var recovery = try J.init(self.gpa, self.disk.interface(), .{
                .partition = "segmented_variable_append_buffered",
                .codec_config = {},
                .cache_ref = &self.cache_ref,
                .write_buffer = common.write_buffer,
                .replay_buffer = common.replay_buffer,
            });
            try recovery.drain();
            self.journal = try recovery.finish();
            const appended = try self.journal.?.append(0, item);
            assert(appended.offset == 0);
        }

        pub fn iter(self: *Self) !u64 {
            const journal = &self.journal.?;
            var last: u64 = 0;
            for (0..self.items) |_| last = (try journal.append(0, item)).offset;
            assert(last > 0);
            return last;
        }

        pub fn teardown(self: *Self) !void {
            defer self.disk.deinit();
            defer self.cache_ref.deinit();
            try self.destroy();
        }

        fn destroy(self: *Self) !void {
            var journal = self.journal orelse return;
            self.journal = null;
            try journal.destroy();
        }
    };
}
