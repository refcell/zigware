//! `buffer_paged::append`: sequential appends of `chunk` bytes, each batch writing twice the
//! bytes the page cache holds.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const common = @import("common.zig");

pub fn run(runner: *bench.Runner) !void {
    for ([_]usize{ 64, 256, 1024, 4096 }) |chunk| {
        for ([_]common.Backend{ .deterministic, .tokio }) |backend| {
            const benchmark = bench.Benchmark.init("buffer_paged::append")
                .with_param("backend", backend)
                .with_param("chunk", chunk);
            var workload: Append = .{
                .gpa = runner.allocator,
                .io = runner.io,
                .backend = backend,
                .chunk = chunk,
                .cache_pages = cache_pages(runner.inputs),
            };
            try runner.run(benchmark, &workload);
        }
    }
}

/// commonware's 10,000 pages, or 100 for the unoptimized smoke run under `zig build test`.
pub fn cache_pages(inputs: bench.Inputs) u32 {
    return inputs.pick(u32, 100, common.cache_size, common.cache_size);
}

const Append = struct {
    gpa: Allocator,
    io: std.Io,
    backend: common.Backend,
    chunk: usize,
    cache_pages: u32,
    name: [64]u8 = undefined,
    name_len: usize = 0,
    data: []u8 = &.{},
    store: common.Store = undefined,
    cache_ref: common.CacheRef = undefined,
    writer: common.Writer = undefined,

    /// Prepare the writer and cache outside the timed operation.
    pub fn setup(self: *Append) !void {
        assert(self.chunk > 0 and self.chunk <= common.page_size * 2);
        const name = try std.fmt.bufPrint(&self.name, "append_seq_{t}_{d}", .{
            self.backend,
            self.chunk,
        });
        self.name_len = name.len;
        self.data = try self.gpa.alloc(u8, self.chunk);
        errdefer self.gpa.free(self.data);
        @memset(self.data, 0xAB);
        try self.store.init(self.gpa, self.io, self.backend);
        errdefer self.store.deinit();
        self.cache_ref = try .init(self.gpa, common.page_size, self.cache_pages);
        errdefer self.cache_ref.deinit();
        self.writer = try self.store.create_append(name, &self.cache_ref);
    }

    pub fn iter(self: *Append) !u64 {
        const bytes = @as(usize, self.cache_pages) * common.page_size;
        const appends = bytes / self.chunk * 2;
        const size_before = self.writer.size();
        for (0..appends) |_| _ = try self.writer.append(self.data);
        assert(self.writer.size() == size_before + appends * self.chunk);
        return self.writer.size();
    }

    pub fn teardown(self: *Append) !void {
        defer self.store.deinit();
        defer self.cache_ref.deinit();
        defer self.gpa.free(self.data);
        try self.store.destroy_append(&self.writer, self.name[0..self.name_len]);
    }
};
