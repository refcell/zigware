//! `buffer_paged::read`: reads of `size` bytes at random offsets of a blob that fits in the
//! page cache, so about one read in a hundred misses.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const utils = @import("utils");
const common = @import("common.zig");
const cache_pages = @import("append.zig").cache_pages;

pub fn run(runner: *bench.Runner) !void {
    for ([_]usize{ 64, 256, 1024, 4096 }) |read_size| {
        for ([_]common.Backend{ .deterministic, .tokio }) |backend| {
            const benchmark = bench.Benchmark.init("buffer_paged::read")
                .with_param("backend", backend)
                .with_param("size", read_size);
            var workload: Read = .{
                .gpa = runner.allocator,
                .io = runner.io,
                .backend = backend,
                .read_size = read_size,
                .total_pages = cache_pages(runner.inputs),
            };
            try runner.run(benchmark, &workload);
        }
    }
}

const Read = struct {
    gpa: Allocator,
    io: std.Io,
    backend: common.Backend,
    read_size: usize,
    /// Pages in the blob: as many as the cache holds.
    total_pages: u32,
    name: [64]u8 = undefined,
    name_len: usize = 0,
    buf: []u8 = &.{},
    rng: utils.rng.TestRng = undefined,
    store: common.Store = undefined,
    cache_ref: common.CacheRef = undefined,
    writer: common.Writer = undefined,

    fn total_size(self: *const Read) usize {
        return @as(usize, self.total_pages) * common.page_size;
    }

    /// Populate the blob, sync, and reopen it through a fresh writer.
    pub fn setup(self: *Read) !void {
        assert(self.read_size <= self.total_size());
        const name = try std.fmt.bufPrint(&self.name, "read_{t}_{d}", .{
            self.backend,
            self.read_size,
        });
        self.name_len = name.len;
        self.buf = try self.gpa.alloc(u8, self.read_size);
        errdefer self.gpa.free(self.buf);
        try self.store.init(self.gpa, self.io, self.backend);
        errdefer self.store.deinit();
        self.cache_ref = try .init(self.gpa, common.page_size, self.total_pages);
        errdefer self.cache_ref.deinit();
        {
            const data = try self.gpa.alloc(u8, self.total_size());
            defer self.gpa.free(data);
            @memset(data, 0xAB);
            var writer = try self.store.create_append(name, &self.cache_ref);
            defer writer.deinit();
            _ = try writer.append(data);
            try writer.sync();
        }
        self.writer = try self.store.create_append(name, &self.cache_ref);
        assert(self.writer.size() == self.total_size());
        self.rng = .init(42);
    }

    pub fn iter(self: *Read) !u64 {
        const offset_max = self.total_size() - self.read_size;
        for (0..@as(usize, self.total_pages) * 100) |_| {
            const offset = utils.rng.range_at_most(&self.rng, usize, 0, offset_max);
            try self.writer.read_into(self.buf, offset);
        }
        assert(self.buf[0] == 0xAB);
        return self.buf.len;
    }

    pub fn teardown(self: *Read) !void {
        defer self.store.deinit();
        defer self.cache_ref.deinit();
        defer self.gpa.free(self.buf);
        try self.store.destroy_append(&self.writer, self.name[0..self.name_len]);
    }
};
