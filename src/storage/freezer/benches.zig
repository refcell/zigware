//! Benchmarks of the freezer (commonware `storage/src/freezer/benches`), with commonware's
//! names and inputs: `get` (random and recent key lookups on a populated freezer), `put`
//! (appending random 128-byte values and syncing), and `restart` (reopening a populated
//! freezer from its checkpoint).
//!
//! Zigware's freezer is not shared between tasks, so commonware's `mode=concurrent` reads
//! (`try_join_all`) keep their name but read one after another.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const Disk = @import("../bench_support.zig").Disk;
const support = @import("../bench_support.zig");
const quick = support.quick;
const cases = support.cases;

const freezer = storage.freezer;
const metrics = runtime.telemetry.metrics;
const paged = runtime.buffer.paged;
const TestRng = utils.TestRng;

/// Bytes buffered before a blob write.
const WRITE_BUFFER: usize = 1024 * 1024;
/// Target size of each value section before a new one starts.
const VALUE_TARGET_SIZE: u64 = 100 * 1024 * 1024;
/// Initial size of the table.
const TABLE_INITIAL_SIZE: u32 = 65_536;
/// Items added to a table entry before a resize.
const TABLE_RESIZE_FREQUENCY: u8 = 4;
/// Items processed per chunk during a resize.
const TABLE_RESIZE_CHUNK_SIZE: u32 = 1024;
/// Replay buffer when scanning the table.
const TABLE_REPLAY_BUFFER: usize = 1024 * 1024;
/// Pages in the page cache.
const PAGE_CACHE_SIZE: usize = 10_000;

const Key = [64]u8;
const Val = [128]u8;
const Freezer = freezer.Freezer(Key, Val);

/// A freezer with the page cache and metrics registry it was opened with.
const Store = struct {
    cache: paged.CacheRef,
    registry: metrics.Registry,
    inner: Freezer,

    /// Opens (or, with no checkpoint, creates afresh) the freezer on `disk`, in place.
    fn open(self: *Store, gpa: Allocator, disk: *Disk, checkpoint: ?freezer.Checkpoint) !void {
        const page_size = paged.page_size(runtime.storage.blob_page_size);
        self.cache = try .init(gpa, page_size, PAGE_CACHE_SIZE);
        errdefer self.cache.deinit();
        self.registry = .init(gpa);
        errdefer self.registry.deinit();
        const scope = metrics.Scope.init(&self.registry).child("storage");
        self.inner = try .init(gpa, disk.storage(), scope, .{
            .key_partition = "freezer-bench-key",
            .key_write_buffer = WRITE_BUFFER,
            .key_cache_ref = &self.cache,
            .value_partition = "freezer-bench-value",
            .value_compression = null,
            .value_write_buffer = WRITE_BUFFER,
            .value_target_size = VALUE_TARGET_SIZE,
            .table_partition = "freezer-bench-table",
            .table_initial_size = TABLE_INITIAL_SIZE,
            .table_resize_frequency = TABLE_RESIZE_FREQUENCY,
            .table_resize_chunk_size = TABLE_RESIZE_CHUNK_SIZE,
            .table_replay_buffer = TABLE_REPLAY_BUFFER,
            .codec_config = {},
        }, checkpoint);
    }

    /// Closes the freezer, returning its checkpoint.
    fn close(self: *Store) !freezer.Checkpoint {
        defer self.registry.deinit();
        defer self.cache.deinit();
        return self.inner.close();
    }

    /// Removes the freezer's storage.
    fn destroy(self: *Store) !void {
        defer self.registry.deinit();
        defer self.cache.deinit();
        try self.inner.destroy();
    }
};

/// Puts `count` random key-value pairs and syncs once; records the keys if `keys` is given.
fn append_random(store: *Store, count: u64, keys: ?[]Key) !void {
    var rng = TestRng.init(42);
    for (0..count) |i| {
        var key: Key = undefined;
        var value: Val = undefined;
        rng.fill_bytes(&key);
        if (keys) |out| out[i] = key;
        rng.fill_bytes(&value);
        _ = try store.inner.put(key, value);
    }
    _ = try store.inner.sync();
}

/// A freezer filled with `items` pairs and closed on first use, so runs that filter out or
/// only list its benchmarks skip the fill.
const Fill = struct {
    gpa: Allocator,
    disk: *Disk,
    items: u64,
    /// Where the fill records its keys, if anywhere (sized `items`).
    keys: ?[]Key = null,
    checkpoint: ?freezer.Checkpoint = null,

    fn ensure(self: *Fill) !freezer.Checkpoint {
        if (self.checkpoint) |checkpoint| return checkpoint;
        var store: Store = undefined;
        try store.open(self.gpa, self.disk, null);
        errdefer store.destroy() catch {};
        try append_random(&store, self.items, self.keys);
        self.checkpoint = try store.close();
        return self.checkpoint.?;
    }
};

/// Reads keys chosen by `pattern` (in `setup`) from the filled freezer reopened there.
const GetWorkload = struct {
    fill: *Fill,
    pattern: []const u8,
    keys: []Key,
    store: Store = undefined,
    opened: bool = false,

    pub fn setup(self: *GetWorkload) !void {
        assert(!self.opened);
        const checkpoint = try self.fill.ensure();
        select_keys(self.pattern, self.fill.keys.?, self.keys);
        try self.store.open(self.fill.gpa, self.fill.disk, checkpoint);
        self.opened = true;
    }

    pub fn iter(self: *GetWorkload) !u64 {
        var sum: u64 = 0;
        for (self.keys) |*key| {
            const value = (try self.store.inner.get(.{ .key = key })) orelse unreachable;
            sum +%= value[0];
        }
        return sum;
    }

    pub fn teardown(self: *GetWorkload) void {
        if (!self.opened) return;
        self.opened = false;
        _ = self.store.close() catch |err| std.log.warn("freezer get bench: {t}", .{err});
    }
};

fn bench_get(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const items = runner.inputs.pick(u64, 10_000, 10_000, 250_000);
    const n_reads = runner.inputs.pick(
        []const usize,
        &.{1_000},
        &.{1_000},
        &.{ 1_000, 10_000, 50_000 },
    );
    const keys = try gpa.alloc(Key, @intCast(items));
    defer gpa.free(keys);
    const selected = try gpa.alloc(Key, n_reads[n_reads.len - 1]);
    defer gpa.free(selected);
    var disk: Disk = .init(runner);
    try disk.open(gpa, "freezer-bench-get");
    defer disk.close();
    var fill: Fill = .{ .gpa = gpa, .disk = &disk, .items = items, .keys = keys };
    const modes: []const []const u8 = &.{ "serial", "concurrent" };
    for ([_][]const u8{ "random", "recent" }) |pattern| {
        for (cases([]const u8, runner, modes, 1)) |mode| {
            for (n_reads) |reads| {
                var workload: GetWorkload = .{
                    .fill = &fill,
                    .pattern = pattern,
                    .keys = selected[0..@min(reads, keys.len)],
                };
                const benchmark = bench.Benchmark.init("freezer::get")
                    .with_param("pattern", pattern).with_param("mode", mode)
                    .with_param("items", items).with_param("reads", reads);
                try runner.run(benchmark, &workload);
            }
        }
    }
}

/// `random`: keys drawn with `TestRng::new(42)`; `recent`: the last keys added.
fn select_keys(pattern: []const u8, keys: []const Key, out: []Key) void {
    assert(out.len <= keys.len);
    if (std.mem.eql(u8, pattern, "recent")) {
        @memcpy(out, keys[keys.len - out.len ..]);
        return;
    }
    var rng = TestRng.init(42);
    for (out) |*key| key.* = keys[utils.rng.range_less_than(&rng, usize, 0, keys.len)];
}

/// Appends `items` pairs to a fresh freezer (opened untimed before each iteration), syncs,
/// then destroys it before the next.
const PutWorkload = struct {
    gpa: Allocator,
    disk: *Disk,
    items: u64,
    store: Store = undefined,
    opened: bool = false,

    pub fn before_iter(self: *PutWorkload) !void {
        try self.release();
        try self.store.open(self.gpa, self.disk, null);
        self.opened = true;
    }

    pub fn iter(self: *PutWorkload) !u64 {
        assert(self.opened);
        try append_random(&self.store, self.items, null);
        return self.items;
    }

    fn release(self: *PutWorkload) !void {
        if (!self.opened) return;
        self.opened = false;
        try self.store.destroy();
    }

    pub fn teardown(self: *PutWorkload) void {
        self.release() catch |err| std.log.warn("freezer put bench: {t}", .{err});
    }
};

fn bench_put(runner: *bench.Runner) !void {
    const sizes = runner.inputs.pick(
        []const u64,
        &.{10_000},
        &.{10_000},
        &.{ 10_000, 50_000, 100_000, 250_000 },
    );
    var disk: Disk = .init(runner);
    try disk.open(runner.allocator, "freezer-bench-put");
    defer disk.close();
    for (sizes) |items| {
        var workload: PutWorkload = .{ .gpa = runner.allocator, .disk = &disk, .items = items };
        const benchmark = bench.Benchmark.init("freezer::put").with_param("items", items);
        try runner.run(benchmark, &workload);
    }
}

/// Times reopening the filled freezer from its checkpoint; each reopened freezer closes
/// (untimed) before the next.
const RestartWorkload = struct {
    fill: *Fill,
    checkpoint: freezer.Checkpoint = undefined,
    store: Store = undefined,
    opened: bool = false,

    pub fn setup(self: *RestartWorkload) !void {
        self.checkpoint = try self.fill.ensure();
    }

    pub fn before_iter(self: *RestartWorkload) !void {
        if (!self.opened) return;
        self.opened = false;
        self.checkpoint = try self.store.close();
    }

    pub fn iter(self: *RestartWorkload) !void {
        assert(!self.opened);
        try self.store.open(self.fill.gpa, self.fill.disk, self.checkpoint);
        self.opened = true;
    }

    pub fn teardown(self: *RestartWorkload) void {
        self.before_iter() catch |err| std.log.warn("freezer restart bench: {t}", .{err});
    }
};

fn bench_restart(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick(
        []const u64,
        &.{10_000},
        &.{10_000},
        &.{ 10_000, 50_000, 100_000, 500_000 },
    );
    for (sizes) |items| {
        var disk: Disk = .init(runner);
        try disk.open(gpa, "freezer-bench-restart");
        defer disk.close();
        var fill: Fill = .{ .gpa = gpa, .disk = &disk, .items = items };
        var workload: RestartWorkload = .{ .fill = &fill };
        const benchmark = bench.Benchmark.init("freezer::restart").with_param("items", items);
        try runner.run(benchmark, &workload);
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_get(runner);
    try bench_put(runner);
    try bench_restart(runner);
}
