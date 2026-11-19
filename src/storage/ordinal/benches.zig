//! Benchmarks of the ordinal store (commonware `storage/src/ordinal/benches`), with
//! commonware's names and inputs: `get` (random lookups in a store of 250,000 records),
//! `put` (appending random 128-byte values to a fresh store and syncing once), and `restart`
//! (reopening a populated store from its committed bits).
//!
//! Zigware's ordinal store is not shared between tasks, so commonware's `mode=concurrent`
//! reads (`FuturesUnordered`) keep their name but read one after another, as the freezer's do.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const support = @import("../bench_support.zig");
const Disk = support.Disk;

const ordinal = storage.ordinal;
const metrics = runtime.telemetry.metrics;
const TestRng = utils.TestRng;

/// Bytes buffered before a blob write.
const WRITE_BUFFER: usize = 1024;
/// Bytes buffered when replaying.
const REPLAY_BUFFER: usize = 1024 * 1024;
const PARTITION = "ordinal-bench-partition";
const ITEMS_PER_BLOB: u64 = 10_000;

const Value = utils.sequence.FixedBytes(128);
const Ordinal = ordinal.Ordinal(Value);

/// An ordinal store with the metrics registry it was opened with.
const Store = struct {
    registry: metrics.Registry,
    inner: Ordinal,

    /// Opens (or, with no bits, creates afresh) the store on `disk`, in place.
    fn open(self: *Store, gpa: Allocator, disk: *Disk, bits: ?[]const ordinal.SectionBits) !void {
        self.registry = .init(gpa);
        errdefer self.registry.deinit();
        const scope = metrics.Scope.init(&self.registry).child("storage");
        self.inner = try .init(gpa, disk.storage(), scope, .{
            .partition = PARTITION,
            .items_per_blob = ITEMS_PER_BLOB,
            .write_buffer = WRITE_BUFFER,
            .replay_buffer = REPLAY_BUFFER,
        }, bits);
    }

    fn close(self: *Store) void {
        self.inner.deinit();
        self.registry.deinit();
    }

    fn destroy(self: *Store) !void {
        defer self.registry.deinit();
        try self.inner.destroy();
    }
};

/// Puts `count` sequential records with random values and syncs once (commonware's
/// `append_random`).
fn append_random(store: *Store, count: u64) !void {
    var rng = TestRng.init(0);
    var value: Value = undefined;
    for (0..count) |index| {
        rng.fill_bytes(&value.bytes);
        try store.inner.put(index, value);
    }
    try store.inner.sync();
}

/// A store filled with `items` records and closed on first use, with the bits that reopen
/// it, so runs that filter out or only list its benchmarks skip the fill.
const Fill = struct {
    gpa: Allocator,
    disk: *Disk,
    items: u64,
    bits: ?[]ordinal.SectionBits = null,

    fn ensure(self: *Fill) ![]const ordinal.SectionBits {
        if (self.bits) |bits| return bits;
        var store: Store = undefined;
        try store.open(self.gpa, self.disk, null);
        errdefer store.destroy() catch {};
        try append_random(&store, self.items);
        store.close();
        const indices = try self.gpa.alloc(u64, @intCast(self.items));
        defer self.gpa.free(indices);
        for (indices, 0..) |*index, value| index.* = value;
        self.bits = try ordinal.bits_for_indices(self.gpa, ITEMS_PER_BLOB, indices);
        return self.bits.?;
    }

    fn deinit(self: *Fill) void {
        if (self.bits) |bits| ordinal.free_bits(self.gpa, bits);
        self.bits = null;
    }
};

/// Reads indices drawn with `TestRng::new(42)` from the filled store, reopened in `setup`.
const GetWorkload = struct {
    fill: *Fill,
    indices: []u64,
    store: Store = undefined,
    opened: bool = false,

    pub fn setup(self: *GetWorkload) !void {
        assert(!self.opened);
        const bits = try self.fill.ensure();
        var rng = TestRng.init(42);
        for (self.indices) |*index| {
            index.* = utils.rng.range_less_than(&rng, u64, 0, self.fill.items);
        }
        try self.store.open(self.fill.gpa, self.fill.disk, bits);
        self.opened = true;
    }

    pub fn iter(self: *GetWorkload) !u64 {
        var sum: u64 = 0;
        for (self.indices) |index| {
            const value = (try self.store.inner.get(index)) orelse unreachable; // Filled.
            sum +%= value.bytes[0];
        }
        return sum;
    }

    pub fn teardown(self: *GetWorkload) void {
        if (!self.opened) return;
        self.opened = false;
        self.store.close();
    }
};

fn bench_get(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const items: u64 = if (support.quick(runner)) 10_000 else 250_000;
    const all_reads = [_]usize{ 1_000, 10_000, 50_000 };
    const reads_list = support.cases(usize, runner, &all_reads, 1);
    const indices = try gpa.alloc(u64, reads_list[reads_list.len - 1]);
    defer gpa.free(indices);
    var disk: Disk = .init(runner);
    try disk.open(gpa, "ordinal-bench-get");
    defer disk.close();
    var fill: Fill = .{ .gpa = gpa, .disk = &disk, .items = items };
    defer fill.deinit();
    const modes: []const []const u8 = &.{ "serial", "concurrent" };
    for (support.cases([]const u8, runner, modes, 1)) |mode| {
        for (reads_list) |reads| {
            var workload: GetWorkload = .{ .fill = &fill, .indices = indices[0..reads] };
            const benchmark = bench.Benchmark.init("ordinal::get").with_param("mode", mode)
                .with_param("reads", reads);
            try runner.run(benchmark, &workload);
        }
    }
}

/// Each iteration fills a fresh store and syncs; the store is destroyed before the next.
const PutWorkload = struct {
    gpa: Allocator,
    disk: *Disk,
    items: u64,
    store: Store = undefined,
    opened: bool = false,

    pub fn before_iter(self: *PutWorkload) !void {
        try self.discard();
        try self.store.open(self.gpa, self.disk, null);
        self.opened = true;
    }

    pub fn iter(self: *PutWorkload) !u64 {
        try append_random(&self.store, self.items);
        return self.items;
    }

    pub fn teardown(self: *PutWorkload) void {
        self.discard() catch |err| std.log.warn("ordinal put bench: {t}", .{err});
    }

    fn discard(self: *PutWorkload) !void {
        if (!self.opened) return;
        self.opened = false;
        try self.store.destroy();
    }
};

/// Each iteration reopens the filled store from its bits; the store closes untimed.
const RestartWorkload = struct {
    fill: *Fill,
    store: Store = undefined,
    opened: bool = false,

    pub fn before_iter(self: *RestartWorkload) !void {
        _ = try self.fill.ensure();
        self.close();
    }

    pub fn iter(self: *RestartWorkload) !u64 {
        try self.store.open(self.fill.gpa, self.fill.disk, self.fill.bits.?);
        self.opened = true;
        return self.fill.items;
    }

    pub fn teardown(self: *RestartWorkload) void {
        self.close();
    }

    fn close(self: *RestartWorkload) void {
        if (!self.opened) return;
        self.opened = false;
        self.store.close();
    }
};

fn bench_put_restart(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const put_items = [_]u64{ 10_000, 50_000, 100_000 };
    for (support.cases(u64, runner, &put_items, 1)) |items| {
        var disk: Disk = .init(runner);
        try disk.open(gpa, "ordinal-bench-put");
        defer disk.close();
        var workload: PutWorkload = .{ .gpa = gpa, .disk = &disk, .items = items };
        try runner.run(bench.Benchmark.init("ordinal::put").with_param("items", items), &workload);
    }
    const restart_items = [_]u64{ 10_000, 50_000, 100_000, 500_000 };
    for (support.cases(u64, runner, &restart_items, 1)) |items| {
        var disk: Disk = .init(runner);
        try disk.open(gpa, "ordinal-bench-restart");
        defer disk.close();
        var fill: Fill = .{ .gpa = gpa, .disk = &disk, .items = items };
        defer fill.deinit();
        var workload: RestartWorkload = .{ .fill = &fill };
        const benchmark = bench.Benchmark.init("ordinal::restart").with_param("items", items);
        try runner.run(benchmark, &workload);
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_get(runner);
    try bench_put_restart(runner);
}
