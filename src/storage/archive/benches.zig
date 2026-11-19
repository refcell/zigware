//! Benchmarks of the archives (commonware `storage/src/archive/benches`), with commonware's
//! names and inputs: `put` (appending random 64 KiB values and syncing), `get` (random lookups
//! by key and by index on a populated archive), and `restart` (reopening a populated archive),
//! for the prunable and immutable variants, with and without compression.
//!
//! Zigware's archives are not shared between tasks, so commonware's `mode=concurrent` reads
//! (`try_join_all`) keep their name but read one after another.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const codec = @import("codec");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const Disk = @import("../bench_disk.zig").Disk;

const archive = storage.archive;
const metrics = runtime.telemetry.metrics;
const paged = runtime.buffer.paged;
const TestRng = utils.TestRng;

/// Bytes buffered in a section before a blob write.
const WRITE_BUFFER: usize = 8 * 1024 * 1024;
/// Items per section (the granularity of pruning).
const ITEMS_PER_SECTION: u64 = 16_384;
/// Bytes buffered when replaying a blob.
const REPLAY_BUFFER: usize = 1024 * 1024;
/// Pages in the page cache (8,192 * 4 KiB = 32 MiB).
const PAGE_CACHE_SIZE: usize = 8_192;
/// Size of values in bytes (64 KiB, representative of block data).
const VALUE_SIZE: usize = 65536;

const Key = [64]u8;
const Val = []const u8;
const Prunable = archive.prunable.Archive(storage.translator.TwoCap, Key, Val);
const Immutable = archive.immutable.Archive(Key, Val);
const Identifier = archive.Identifier(Key);

const Variant = enum { prunable, immutable };

/// Either archive, with the page cache and metrics registry it was opened with.
const Archive = struct {
    cache: paged.CacheRef,
    registry: metrics.Registry,
    inner: union(Variant) { prunable: Prunable, immutable: Immutable },

    /// Opens (or creates) the archive of `variant` on `disk`, in place.
    fn open(
        self: *Archive,
        gpa: Allocator,
        disk: *Disk,
        variant: Variant,
        compression: ?u8,
    ) !void {
        const page_size = paged.page_size(runtime.storage.blob_page_size);
        self.cache = try .init(gpa, page_size, PAGE_CACHE_SIZE);
        errdefer self.cache.deinit();
        self.registry = .init(gpa);
        errdefer self.registry.deinit();
        const scope = metrics.Scope.init(&self.registry).child("storage");
        const backend = disk.storage();
        self.inner = switch (variant) {
            .prunable => .{ .prunable = try .init(gpa, backend, scope, .{
                .translator = .{},
                .metadata_partition = "archive-bench-metadata",
                .key_partition = "archive-bench-key",
                .key_cache_ref = &self.cache,
                .value_partition = "archive-bench-value",
                .compression = compression,
                .codec_config = .{ .range = .full() },
                .items_per_section = ITEMS_PER_SECTION,
                .key_write_buffer = WRITE_BUFFER,
                .value_write_buffer = WRITE_BUFFER,
                .replay_buffer = REPLAY_BUFFER,
            }) },
            .immutable => .{ .immutable = try .init(gpa, backend, scope, .{
                .metadata_partition = "archive-bench-metadata",
                .freezer_table_partition = "archive-bench-freezer-table",
                .freezer_table_initial_size = 131_072,
                .freezer_table_resize_frequency = 4,
                .freezer_table_resize_chunk_size = 1024,
                .freezer_key_partition = "archive-bench-freezer-key",
                .freezer_key_cache_ref = &self.cache,
                .freezer_value_partition = "archive-bench-freezer-value",
                .freezer_value_target_size = 128 * 1024 * 1024,
                .freezer_value_compression = compression,
                .ordinal_partition = "archive-bench-ordinal",
                .items_per_section = ITEMS_PER_SECTION,
                .freezer_key_write_buffer = WRITE_BUFFER,
                .freezer_value_write_buffer = WRITE_BUFFER,
                .ordinal_write_buffer = WRITE_BUFFER,
                .replay_buffer = REPLAY_BUFFER,
                .codec_config = .{ .range = .full() },
            }) },
        };
    }

    fn put(self: *Archive, index: u64, key: Key, value: Val) !void {
        switch (self.inner) {
            inline else => |*inner| try inner.put(index, key, value),
        }
    }

    /// Reads the value at `identifier`, which must exist, returning its length.
    fn get(self: *Archive, gpa: Allocator, identifier: Identifier) !usize {
        const value = switch (self.inner) {
            inline else => |*inner| try inner.get(identifier),
        } orelse unreachable; // Every benchmark reads a stored item.
        defer codec.free(Val, gpa, value);
        return value.len;
    }

    fn sync(self: *Archive) !void {
        switch (self.inner) {
            inline else => |*inner| try inner.sync(),
        }
    }

    /// Closes the archive (keeping its data), or removes its storage with `destroy`.
    fn close(self: *Archive, destroy: bool) !void {
        defer self.registry.deinit();
        defer self.cache.deinit();
        switch (self.inner) {
            inline else => |*inner| if (destroy) try inner.destroy() else inner.deinit(),
        }
    }
};

/// Appends `count` random (index, key, value) triples and syncs once; returns the keys if
/// `keys` is non-null (sized `count`).
fn append_random(gpa: Allocator, target: *Archive, count: u64, keys: ?[]Key) !void {
    const value = try gpa.alloc(u8, VALUE_SIZE);
    defer gpa.free(value);
    var rng = utils.test_rng();
    for (0..count) |i| {
        var key: Key = undefined;
        rng.fill_bytes(&key);
        if (keys) |out| out[i] = key;
        rng.fill_bytes(value);
        try target.put(i, key, value);
    }
    try target.sync();
}

fn comp_name(compression: ?u8) []const u8 {
    return if (compression) |level| switch (level) {
        3 => "3",
        else => unreachable, // Commonware benchmarks level 3 only.
    } else "off";
}

const variants = [_]Variant{ .prunable, .immutable };
const compressions = [_]?u8{ null, 3 };

/// Appends `items` triples to a fresh archive (opened untimed before each iteration), syncs,
/// then destroys it before the next.
const PutWorkload = struct {
    gpa: Allocator,
    disk: *Disk,
    variant: Variant,
    compression: ?u8,
    items: u64,
    target: Archive = undefined,
    opened: bool = false,

    pub fn before_iter(self: *PutWorkload) !void {
        try self.teardown_checked();
        try self.target.open(self.gpa, self.disk, self.variant, self.compression);
        self.opened = true;
    }

    pub fn iter(self: *PutWorkload) !u64 {
        assert(self.opened);
        try append_random(self.gpa, &self.target, self.items, null);
        return self.items;
    }

    fn teardown_checked(self: *PutWorkload) !void {
        if (!self.opened) return;
        self.opened = false;
        try self.target.close(true);
    }

    pub fn teardown(self: *PutWorkload) void {
        self.teardown_checked() catch |err| std.log.warn("archive put bench: {t}", .{err});
    }
};

fn bench_put(runner: *bench.Runner) !void {
    const sizes = runner.inputs.pick(
        []const u64,
        &.{1_000},
        &.{10_000},
        &.{ 10_000, 50_000, 100_000 },
    );
    var disk: Disk = .init(runner);
    try disk.open(runner.allocator, "archive-bench-put");
    defer disk.close();
    for (variants) |variant| {
        for (compressions) |compression| {
            for (sizes) |items| {
                const benchmark = bench.Benchmark.init("archive::put")
                    .with_param("variant", variant)
                    .with_param("items", items).with_param("comp", comp_name(compression));
                var workload: PutWorkload = .{
                    .gpa = runner.allocator,
                    .disk = &disk,
                    .variant = variant,
                    .compression = compression,
                    .items = items,
                };
                try runner.run(benchmark, &workload);
            }
        }
    }
}

/// Reads the selected keys or indices from an archive reopened in `setup`.
const GetWorkload = struct {
    gpa: Allocator,
    disk: *Disk,
    variant: Variant,
    compression: ?u8,
    keys: []const Key,
    indices: []const u64,
    target: Archive = undefined,
    opened: bool = false,

    pub fn setup(self: *GetWorkload) !void {
        assert(!self.opened);
        try self.target.open(self.gpa, self.disk, self.variant, self.compression);
        self.opened = true;
    }

    pub fn iter(self: *GetWorkload) !usize {
        var total: usize = 0;
        for (self.keys) |*key| total += try self.target.get(self.gpa, .{ .key = key });
        for (self.indices) |index| total += try self.target.get(self.gpa, .{ .index = index });
        assert(total == (self.keys.len + self.indices.len) * VALUE_SIZE);
        return total;
    }

    pub fn teardown(self: *GetWorkload) void {
        if (!self.opened) return;
        self.opened = false;
        self.target.close(false) catch |err| std.log.warn("archive get bench: {t}", .{err});
    }
};

/// Commonware draws reads with `TestRng::new(42)`, keys and indices alike.
fn select_reads(keys: []const Key, reads: usize, out_keys: []Key, out_indices: []u64) void {
    assert(out_keys.len == reads and out_indices.len == reads);
    var rng = TestRng.init(42);
    for (out_keys) |*key| key.* = keys[utils.rng.range_less_than(&rng, usize, 0, keys.len)];
    rng = TestRng.init(42);
    for (out_indices) |*index| index.* = utils.rng.range_less_than(&rng, u64, 0, keys.len);
}

fn bench_get(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const items = runner.inputs.pick(u64, 1_000, 10_000, 250_000);
    const n_reads = runner.inputs.pick(
        []const usize,
        &.{100},
        &.{1_000},
        &.{ 1_000, 10_000, 50_000 },
    );
    const keys = try gpa.alloc(Key, @intCast(items));
    defer gpa.free(keys);
    const max_reads = n_reads[n_reads.len - 1];
    const selected_keys = try gpa.alloc(Key, max_reads);
    defer gpa.free(selected_keys);
    const selected_indices = try gpa.alloc(u64, max_reads);
    defer gpa.free(selected_indices);
    for (variants) |variant| {
        for (compressions) |compression| {
            var disk: Disk = .init(runner);
            try disk.open(gpa, "archive-bench-get");
            defer disk.close();
            if (!runner.list) {
                // Setup: populate the archive once per variant and compression.
                var target: Archive = undefined;
                try target.open(gpa, &disk, variant, compression);
                errdefer target.close(true) catch {};
                try append_random(gpa, &target, items, keys);
                try target.close(false);
            }
            try bench_get_modes(runner, &disk, variant, compression, keys, .{
                .keys = selected_keys,
                .indices = selected_indices,
            }, n_reads);
        }
    }
}

const Selection = struct { keys: []Key, indices: []u64 };

fn bench_get_modes(
    runner: *bench.Runner,
    disk: *Disk,
    variant: Variant,
    compression: ?u8,
    keys: []const Key,
    selection: Selection,
    n_reads: []const usize,
) !void {
    for ([_][]const u8{ "serial", "concurrent" }) |mode| {
        for ([_][]const u8{ "key", "index" }) |pattern| {
            for (n_reads) |reads| {
                const by_key = std.mem.eql(u8, pattern, "key");
                if (!runner.list) {
                    const chosen = selection.keys[0..reads];
                    select_reads(keys, reads, chosen, selection.indices[0..reads]);
                }
                var workload: GetWorkload = .{
                    .gpa = runner.allocator,
                    .disk = disk,
                    .variant = variant,
                    .compression = compression,
                    .keys = if (by_key) selection.keys[0..reads] else &.{},
                    .indices = if (by_key) &.{} else selection.indices[0..reads],
                };
                const benchmark = bench.Benchmark.init("archive::get")
                    .with_param("variant", variant)
                    .with_param("mode", mode).with_param("pattern", pattern)
                    .with_param("comp", comp_name(compression)).with_param("items", keys.len)
                    .with_param("reads", reads);
                try runner.run(benchmark, &workload);
            }
        }
    }
}

/// Times reopening a populated archive; each reopened archive closes before the next.
const RestartWorkload = struct {
    gpa: Allocator,
    disk: *Disk,
    variant: Variant,
    compression: ?u8,
    target: Archive = undefined,
    opened: bool = false,

    pub fn before_iter(self: *RestartWorkload) !void {
        if (!self.opened) return;
        self.opened = false;
        try self.target.close(false);
    }

    pub fn iter(self: *RestartWorkload) !void {
        assert(!self.opened);
        try self.target.open(self.gpa, self.disk, self.variant, self.compression);
        self.opened = true;
    }

    pub fn teardown(self: *RestartWorkload) void {
        self.before_iter() catch |err| std.log.warn("archive restart bench: {t}", .{err});
    }
};

fn bench_restart(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick(
        []const u64,
        &.{1_000},
        &.{10_000},
        &.{ 10_000, 50_000, 100_000, 500_000 },
    );
    for (variants) |variant| {
        for (compressions) |compression| {
            for (sizes) |items| {
                var disk: Disk = .init(runner);
                try disk.open(gpa, "archive-bench-restart");
                defer disk.close();
                if (!runner.list) {
                    var target: Archive = undefined;
                    try target.open(gpa, &disk, variant, compression);
                    errdefer target.close(true) catch {};
                    try append_random(gpa, &target, items, null);
                    try target.close(false);
                }
                var workload: RestartWorkload = .{
                    .gpa = gpa,
                    .disk = &disk,
                    .variant = variant,
                    .compression = compression,
                };
                const benchmark = bench.Benchmark.init("archive::restart")
                    .with_param("variant", variant).with_param("items", items)
                    .with_param("comp", comp_name(compression));
                try runner.run(benchmark, &workload);
            }
        }
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_put(runner);
    try bench_get(runner);
    try bench_restart(runner);
}
