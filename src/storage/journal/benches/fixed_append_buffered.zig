//! `journal::fixed_append_buffered`: append CPU cost while every record fits in the write
//! buffer, appending items one at a time or through `prepare_append`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const common = @import("common.zig");

pub fn run(runner: *bench.Runner) !void {
    try run_size(runner, 32);
    try run_size(runner, 256);
}

fn run_size(runner: *bench.Runner, comptime size: usize) !void {
    const items: u64 = 320 * 1024 / size;
    for ([_]bool{ false, true }) |prepared| {
        const benchmark = bench.Benchmark.init("journal::fixed_append_buffered")
            .with_param("items", items)
            .with_param("size", size)
            .with_param("prepared", prepared);
        var workload: Buffered(size) = .{
            .gpa = runner.allocator,
            .io = runner.io,
            .inputs = runner.inputs,
            .items = items,
            .prepared = prepared,
        };
        try runner.run(benchmark, &workload);
    }
}

fn Buffered(comptime size: usize) type {
    return struct {
        const Self = @This();
        const item: [size]u8 = @splat(0xAB);

        gpa: Allocator,
        io: std.Io,
        inputs: bench.Inputs,
        items: u64,
        prepared: bool,
        disk: common.Disk = undefined,
        cache_ref: common.CacheRef = undefined,
        journal: ?common.FixedJournal(size) = null,

        pub fn setup(self: *Self) !void {
            assert(self.journal == null);
            try self.disk.init(self.io, self.gpa, "fixed-append-buffered", self.inputs);
            errdefer self.disk.deinit();
            self.cache_ref = try .init(self.gpa, common.page_size, 32);
        }

        /// Open a fresh journal and warm the tip allocation. Neither this append nor the
        /// timed ones fill the tip or rotate the blob.
        pub fn before_iter(self: *Self) !void {
            try self.destroy();
            self.journal = try common.FixedJournal(size).init(self.gpa, self.disk.interface(), .{
                .partition = "fixed_append_buffered",
                .items_per_blob = 1_000_000,
                .cache_ref = &self.cache_ref,
                .write_buffer = common.write_buffer,
                .replay_buffer = common.replay_buffer,
            });
            assert(try self.journal.?.append(item) == 0);
        }

        pub fn iter(self: *Self) !u64 {
            const journal = &self.journal.?;
            for (0..self.items) |_| {
                if (self.prepared) {
                    const nested = [_][]const [size]u8{&.{item}};
                    var batch = try journal.prepare_append(&nested);
                    _ = try journal.append_prepared(&batch);
                } else {
                    _ = try journal.append(item);
                }
            }
            assert(journal.size() == self.items + 1);
            return journal.size();
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
