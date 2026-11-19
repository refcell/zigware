//! `buffer_paged::sync`: end-to-end cadence of `per_sync` appended records followed by one
//! durability barrier.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const common = @import("common.zig");

const record_size = 256;

pub fn run(runner: *bench.Runner) !void {
    for ([_]usize{ 1, 16 }) |per_sync| {
        for ([_]common.Backend{ .deterministic, .tokio }) |backend| {
            const benchmark = bench.Benchmark.init("buffer_paged::sync")
                .with_param("runner", backend)
                .with_param("per_sync", per_sync)
                .with_param("record_size", record_size)
                .with_param("write_buffer", common.write_buffer_size);
            var workload: Sync = .{
                .gpa = runner.allocator,
                .io = runner.io,
                .backend = backend,
                .per_sync = per_sync,
            };
            try runner.run(benchmark, &workload);
        }
    }
}

const Sync = struct {
    const data: [record_size]u8 = @splat(0xAB);

    gpa: Allocator,
    io: std.Io,
    backend: common.Backend,
    per_sync: usize,
    name: [64]u8 = undefined,
    name_len: usize = 0,
    store: common.Store = undefined,
    cache_ref: common.CacheRef = undefined,
    writer: common.Writer = undefined,

    /// Prepare the writer and cache outside the timed operation.
    pub fn setup(self: *Sync) !void {
        assert(self.per_sync > 0);
        const name = try std.fmt.bufPrint(&self.name, "sync_{t}_{d}", .{
            self.backend,
            self.per_sync,
        });
        self.name_len = name.len;
        try self.store.init(self.gpa, self.io, self.backend);
        errdefer self.store.deinit();
        self.cache_ref = try .init(self.gpa, common.page_size, common.cache_size);
        errdefer self.cache_ref.deinit();
        self.writer = try self.store.create_append(name, &self.cache_ref);
    }

    pub fn iter(self: *Sync) !u64 {
        const size_before = self.writer.size();
        for (0..self.per_sync) |_| _ = try self.writer.append(&data);
        try self.writer.sync();
        assert(self.writer.size() == size_before + self.per_sync * record_size);
        return self.writer.size();
    }

    pub fn teardown(self: *Sync) !void {
        defer self.store.deinit();
        defer self.cache_ref.deinit();
        try self.store.destroy_append(&self.writer, self.name[0..self.name_len]);
    }
};
