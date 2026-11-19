//! Metrics of the contiguous journals (commonware's `journal/contiguous/metrics.rs`).
//!
//! Fixed and variable journals register the same set. The duration histograms read the clock
//! of the `io` a journal's config names (commonware's context clock); without one they are
//! registered but never observe.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const metrics = @import("runtime").telemetry.metrics;

pub const Metrics = struct {
    /// Logical end position.
    size: metrics.Gauge,
    /// Oldest readable item position.
    pruning_boundary: metrics.Gauge,
    /// Readable items retained.
    retained: metrics.Gauge,
    /// Items in the blob containing the newest retained item.
    tail_items: metrics.Gauge,
    append_calls: metrics.Counter,
    append_many_calls: metrics.Counter,
    append_prepared_calls: metrics.Counter,
    read_calls: metrics.Counter,
    read_many_calls: metrics.Counter,
    /// Items read without a blob read.
    cache_hits: metrics.Counter,
    /// Items that fell back to a blob read in `read` and `read_many`.
    cache_misses: metrics.Counter,
    /// Items returned by `read`, `read_many`, and the sync probes.
    items_read: metrics.Counter,
    start_sync_calls: metrics.Counter,
    commit_calls: metrics.Counter,
    sync_calls: metrics.Counter,
    append_duration: metrics.Timed,
    append_many_duration: metrics.Timed,
    append_prepared_duration: metrics.Timed,
    /// Duration of single-item reads that miss the page cache.
    read_duration: metrics.Timed,
    read_many_duration: metrics.Timed,
    commit_duration: metrics.Timed,
    sync_duration: metrics.Timed,
    /// The clock of the duration timers.
    io: ?std.Io,

    const gauges = .{
        .{ "size", "Logical end position of the journal" },
        .{ "pruning_boundary", "Oldest readable item position" },
        .{ "retained", "Number of readable items retained" },
        .{ "tail_items", "Items in the blob containing the newest retained item" },
    };
    const counters = .{
        .{ "append_calls", "Number of single-item append calls" },
        .{ "append_many_calls", "Number of append-many calls" },
        .{ "append_prepared_calls", "Number of pre-encoded batch append calls" },
        .{ "read_calls", "Number of single-item read calls" },
        .{ "read_many_calls", "Number of non-empty batch read calls" },
        .{ "cache_hits", "Number of items served without a blob read" },
        .{ "cache_misses", "Number of items requiring a blob read" },
        .{
            "items_read",
            "Number of items returned by point reads, batch reads, and sync probes",
        },
        .{ "start_sync_calls", "Number of start_sync calls" },
        .{ "commit_calls", "Number of commit calls" },
        .{ "sync_calls", "Number of sync calls" },
    };
    const durations = .{
        .{ "append_duration", "Duration of single-item append calls" },
        .{ "append_many_duration", "Duration of append-many calls" },
        .{ "append_prepared_duration", "Duration of pre-encoded batch append calls" },
        .{ "read_duration", "Duration of single-item read calls that miss the page cache" },
        .{ "read_many_duration", "Duration of non-empty batch read calls" },
        .{ "commit_duration", "Duration of commit calls" },
        .{ "sync_duration", "Duration of full sync calls" },
    };

    /// A started duration timer, or none without a clock. `finish` observes it.
    pub const Span = struct {
        io: ?std.Io,
        timer: ?metrics.histogram.Timer,

        pub fn finish(span: Span) void {
            const timer = span.timer orelse return;
            timer.observe(span.io.?);
        }
    };

    /// Starts timing into the duration histogram `name`.
    pub fn time(self: *const Metrics, comptime name: []const u8) Span {
        comptime assert(std.mem.endsWith(u8, name, "_duration"));
        const io = self.io orelse return .{ .io = null, .timer = null };
        return .{ .io = io, .timer = @field(self, name).timer(io) };
    }

    /// Registers the set under `scope`, or records it unregistered without one.
    pub fn init(gpa: Allocator, scope: ?metrics.Scope, io: ?std.Io) Allocator.Error!Metrics {
        var result: Metrics = undefined;
        result.io = io;
        var registered: usize = 0;
        errdefer {
            inline for (gauges ++ counters ++ durations, 0..) |entry, index| {
                if (index < registered) @field(result, entry[0]).deinit();
            }
        }
        inline for (gauges) |entry| {
            @field(result, entry[0]) = if (scope) |s|
                try s.gauge(entry[0], entry[1])
            else
                try metrics.Gauge.detached(gpa, .{});
            registered += 1;
        }
        inline for (counters) |entry| {
            @field(result, entry[0]) = if (scope) |s|
                try s.counter(entry[0], entry[1])
            else
                try metrics.Counter.detached(gpa, .{});
            registered += 1;
        }
        inline for (durations) |entry| {
            @field(result, entry[0]) = if (scope) |s|
                try metrics.Timed.register(&s, entry[0], entry[1])
            else
                .init(try metrics.Histogram.detached(gpa, .init(&metrics.Buckets.local)));
            registered += 1;
        }
        assert(registered == gauges.len + counters.len + durations.len);
        return result;
    }

    pub fn deinit(self: *Metrics) void {
        inline for (gauges ++ counters ++ durations) |entry| @field(self, entry[0]).deinit();
        self.* = undefined;
    }

    /// Updates the state gauges from the current bounds. Like commonware's `try_set`, a value
    /// past `i64::MAX` (a journal reset near `u64::MAX`) leaves its gauge unchanged.
    pub fn update(self: *Metrics, size: u64, boundary: u64, items_per_blob: u64) void {
        assert(boundary <= size);
        assert(items_per_blob > 0);
        _ = self.size.metric().try_set(size) catch {};
        _ = self.pruning_boundary.metric().try_set(boundary) catch {};
        _ = self.retained.metric().try_set(size - boundary) catch {};
        const tail_items = if (size == boundary) 0 else blk: {
            const tail_start = (size - 1) / items_per_blob * items_per_blob;
            break :blk size - @max(boundary, tail_start);
        };
        _ = self.tail_items.metric().try_set(tail_items) catch {};
    }
};

test "tail_items counts the newest blob's readable items" {
    var set = try Metrics.init(std.testing.allocator, null, null);
    defer set.deinit();
    set.update(25, 0, 10);
    try std.testing.expectEqual(5, set.tail_items.metric().get());
    try std.testing.expectEqual(25, set.retained.metric().get());
    // A full tail blob counts all its items; a boundary inside it caps them.
    set.update(30, 23, 10);
    try std.testing.expectEqual(7, set.tail_items.metric().get());
    set.update(30, 30, 10);
    try std.testing.expectEqual(0, set.tail_items.metric().get());
}

test "variable journal metrics register with the offsets journal under its child" {
    const gpa = std.testing.allocator;
    const runtime = @import("runtime");
    const variable = @import("variable.zig");
    const Bytes = []const u8;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var memory = runtime.storage.memory.Storage.init(gpa);
    defer memory.deinit();
    var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 64, 4);
    defer cache_ref.deinit();
    var journal = try variable.Journal(Bytes).init(gpa, memory.storage(), .{
        .partition = "metrics",
        .items_per_section = 4,
        .codec_config = .{ .range = .full(), .item = {} },
        .cache_ref = &cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
        .metrics = metrics.Scope.init(&registry).child("journal"),
    });
    defer journal.deinit();
    for (0..10) |_| _ = try journal.append("item");
    try journal.sync();
    _ = try journal.prune(5);
    const item = try journal.read(6);
    gpa.free(item);
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    const expect = std.testing.expect;
    try expect(metrics.has_metric_value(text, "journal_size", "10"));
    try expect(metrics.has_metric_value(text, "journal_pruning_boundary", "4"));
    try expect(metrics.has_metric_value(text, "journal_retained", "6"));
    try expect(metrics.has_metric_value(text, "journal_tail_items", "2"));
    try expect(metrics.has_metric_value(text, "journal_append_calls_total", "10"));
    try expect(metrics.has_metric_value(text, "journal_read_calls_total", "1"));
    try expect(metrics.has_metric_value(text, "journal_items_read_total", "1"));
    try expect(metrics.has_metric_value(text, "journal_sync_calls_total", "1"));
    try expect(metrics.has_metric_value(text, "journal_offsets_size", "10"));
    // Data blobs [1, 2] remain after pruning blob 0; offsets blobs too.
    try expect(metrics.has_metric_value(text, "journal_data_tracked", "2"));
    try expect(metrics.has_metric_value(text, "journal_data_pruned_total", "1"));
    try expect(metrics.has_metric_value(text, "journal_offsets_blobs_tracked", "2"));
}

/// Reads `0..count` until one misses the page cache, reads that one, then reads it again from
/// the cache, and returns the registry's encoding.
fn read_one_miss(journal: anytype, registry: *metrics.Registry, count: u64) ![]u8 {
    const gpa = std.testing.allocator;
    var cold: ?u64 = null;
    for (0..count) |position| {
        if (journal.try_read_sync(position) == null) {
            cold = position;
            break;
        }
    }
    const position = cold.?; // The page cache cannot hold every page.
    // One read, as in commonware: under Clock2Q+ the missed page enters probation, where the
    // variable journal's next page read can evict it before a second read.
    _ = try journal.read(position);
    return registry.encode(gpa);
}

// Reads served from storage record a read_duration sample; cache hits do not
// (commonware's `test_fixed_journal_read_miss_timed` and `test_variable_journal_read_miss_timed`).
test "journal reads that miss the page cache are timed" {
    const gpa = std.testing.allocator;
    const runtime = @import("runtime");
    const fixed = @import("fixed.zig");
    const variable = @import("variable.zig");
    const Digest = @import("cryptography").sha256.Digest;
    inline for (.{ false, true }) |is_variable| {
        var registry = metrics.Registry.init(gpa);
        defer registry.deinit();
        var memory = runtime.storage.memory.Storage.init(gpa);
        defer memory.deinit();
        var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 64, 4);
        defer cache_ref.deinit();
        const scope = metrics.Scope.init(&registry).child("miss");
        var journal = if (is_variable)
            try variable.Journal(u64).init(gpa, memory.storage(), .{
                .partition = "miss",
                .items_per_section = 50,
                .codec_config = {},
                .cache_ref = &cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .metrics = scope,
                .io = std.testing.io,
            })
        else
            try fixed.Journal(Digest).init(gpa, memory.storage(), .{
                .partition = "miss",
                .items_per_blob = 2,
                .cache_ref = &cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .metrics = scope,
                .io = std.testing.io,
            });
        defer journal.deinit();
        const count: u64 = if (is_variable) 200 else 20;
        for (0..count) |i| {
            _ = try journal.append(if (is_variable) i else .{ .bytes = @splat(@intCast(i)) });
        }
        try journal.sync();
        const text = try read_one_miss(&journal, &registry, count);
        defer gpa.free(text);
        try std.testing.expect(metrics.has_metric_value(text, "miss_read_duration_count", "1"));
        try std.testing.expect(metrics.has_metric_value(text, "miss_sync_duration_count", "1"));
        const appends = std.fmt.comptimePrint("{d}", .{if (is_variable) 200 else 20});
        const append_count = "miss_append_duration_count";
        try std.testing.expect(metrics.has_metric_value(text, append_count, appends));
    }
}
